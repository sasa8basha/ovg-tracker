"""
routers/collector_v3.py — Collector v3 API (v4.3 — Fast IP Filter Integration)
"""
import json
import asyncio
import httpx
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from sqlalchemy import func, distinct
from sqlalchemy.orm import Session

from config import COLLECTOR_V3_ENABLED, MAX_SESSIONS_PER_IP_HOUR, GEO_LOOKUP_TIMEOUT
from database import get_db, SessionLocal
from models import SessionModel, VisitHeartbeatModel, VisitModel, CampaignModel
from schemas import HandshakePayload, HeartbeatPayload, FinalPayload
from utils import (
    get_client_ip,
    handshake_limiter,
    heartbeat_limiter,
    final_limiter,
    stats_cache,
    ip_cache,
)
from analysis import get_ip_info, parse_ua, extract_zone_id, safe_asn, safe_float
from collector.precheck import quick_precheck
from collector.filter_engine import evaluate_visit
from collector.decision import mode_from_block_threshold
from helpers import extract_zone_id_from_url

# ✅ استيراد الفلتر السريع
from collector.fast_ip_filter import check_ip_fast

router = APIRouter()


# =========================================================
# PopAds Macros — full extraction
# =========================================================
MACRO_ALIASES = {
    "bid":            ("bid",),
    "impression_id":  ("impressionid", "impid", "impression_id"),
    "website_id":     ("websiteid", "website_id"),
    "category_id":    ("categoryid", "category_id"),
    "category_name":  ("categoryname", "category_name"),
    "isp_id":         ("ispid", "isp_id"),
    "isp_name":       ("ispname", "isp_name", "isp"),
    "country":        ("country",),
    "quality":        ("quality",),
    "screen_res":     ("screenresolution", "screen_resolution"),
    "os_name":        ("osname", "os_name"),
    "browser_name":   ("browsername", "browser_name"),
    "form_factor":    ("formfactorname", "form_factor"),
    "device_name":    ("devicename", "device_name"),
    "campaign_id":    ("campaignid", "campaign_id"),
    "campaign_name":  ("campaignname", "campaign_name"),
    "os_id":          ("osid", "os_id"),
    "browser_id":     ("browserid", "browser_id"),
    "form_factor_id": ("formfactorid", "form_factor_id"),
    "device_id":      ("deviceid", "device_id"),
    "adblock":        ("adblock",),
    "ip":             ("ip",),
    "ipv6":           ("ipv6",),
    "ipv6or4":        ("ipv6or4",),
    "xforwardedfor":  ("xforwardedfor",),
    "useragent":      ("useragent", "ua"),
    "lang":           ("lang",),
}


def _extract_macros(tp: dict) -> dict:
    if not isinstance(tp, dict):
        return {
            "raw": {}, "known": {}, "bid": 0.0,
            "impression_id": None, "website_id": None,
            "quality": None, "adblock": False, "country": None,
        }

    lowered = {str(k).strip().lower(): v for k, v in tp.items() if v is not None and str(v) != ""}
    known = {}
    for canonical, aliases in MACRO_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                known[canonical] = lowered[alias]
                break

    def _to_float(v):
        try:
            return float(v)
        except (ValueError, TypeError):
            return 0.0

    def _to_int(v):
        try:
            return int(float(v))
        except (ValueError, TypeError):
            return None

    def _to_bool(v):
        return str(v).strip() in ("1", "true", "True", "yes", "YES")

    return {
        "raw": tp,
        "known": known,
        "bid": _to_float(known.get("bid")),
        "impression_id": str(known.get("impression_id") or "")[:100] or None,
        "website_id": str(known.get("website_id") or "")[:100] or None,
        "quality": _to_int(known.get("quality")),
        "adblock": _to_bool(known.get("adblock", "0")),
        "country": str(known.get("country") or "")[:10] or None,
    }


# =========================================================
# Zone extraction — Prioritize macros
# =========================================================
def _extract_zone_from_payload(url: str, tracking_params: dict, campaign) -> tuple:
    """Returns (zone_id, source)."""
    
    # 1) الأولوية القصوى: tracking_params (الماكروز اللي بوب ادس بيبعتها)
    try:
        tp = tracking_params or {}
        tp_lower = {str(k).lower().strip(): v for k, v in tp.items() if v}
        # بندور على websiteid الأول
        for key in ("websiteid", "website_id", "zoneid", "zone_id", "zone", "z", "zn", "zid"):
            if key in tp_lower and tp_lower[key]:
                _val = str(tp_lower[key]).strip()[:100]
                # تأكد إن الماكرو اتحول لرقم فعلاً ومش مجرد نص
                if _val and not _val.startswith("["): 
                    return _val, f"macro_{key}"
    except Exception:
        pass

    # 2) الـ URL
    try:
        _z = extract_zone_id_from_url(url or "")
        if _z:
            return _z, "url_helpers"
    except Exception:
        pass

    # 3) analysis.extract_zone_id
    try:
        _z = extract_zone_id(url or "")
        if _z and _z != "unknown":
            return _z, "url_analysis"
    except Exception:
        pass

    # 4) campaign default
    try:
        if campaign is not None and campaign.destination_zone_id:
            _val = str(campaign.destination_zone_id).strip()[:100]
            if _val:
                return _val, "campaign_default"
    except Exception:
        pass

    return "unknown", "none"


# =========================================================
# Sync IP info fetch — safe from threads
# =========================================================
def _fetch_ip_info_sync(ip: str, timeout: float = GEO_LOOKUP_TIMEOUT) -> dict:
    """Synchronous IP lookup. Safe from any thread. Uses cache first."""
    if not ip:
        return {
            "country": "Unknown", "country_code": "", "isp": "Unknown",
            "type": "Unknown", "asn": "Unknown", "security": {},
            "lat": 0.0, "lon": 0.0,
        }

    try:
        cached = ip_cache.get(ip)
        if cached is not None:
            return cached
    except Exception:
        pass

    try:
        r = httpx.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,as,proxy,hosting,lat,lon",
            timeout=timeout,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                is_proxy = bool(d.get("proxy"))
                is_hosting = bool(d.get("hosting"))
                out = {
                    "country": d.get("country", "Unknown"),
                    "country_code": str(d.get("countryCode") or "").upper()[:2],
                    "isp": d.get("isp", "Unknown"),
                    "type": "hosting" if is_hosting else "residential",
                    "asn": safe_asn(d.get("as")),
                    "security": {
                        "vpn": is_proxy or is_hosting,
                        "proxy": is_proxy,
                        "hosting": is_hosting,
                    },
                    "lat": safe_float(d.get("lat"), 0.0),
                    "lon": safe_float(d.get("lon"), 0.0),
                }
                try:
                    ip_cache.set(ip, out)
                except Exception:
                    pass
                return out
    except Exception as e:
        print(f"[ip_sync] fetch failed for {ip}: {e}")

    return {
        "country": "Unknown", "country_code": "", "isp": "Unknown",
        "type": "Unknown", "asn": "Unknown", "security": {},
        "lat": 0.0, "lon": 0.0,
    }


# =========================================================
# Small helpers
# =========================================================
def _validate_session_id(session_id: str) -> str:
    s = (session_id or "").strip()
    if not s or len(s) < 8 or len(s) > 64:
        raise HTTPException(400, "session_id غير صالح")
    return s


def _resolve_campaign(campaign_key: str, db: Session):
    if not campaign_key:
        return None
    return db.query(CampaignModel).filter(CampaignModel.campaign_key == campaign_key).first()


# =========================================================
# FINGERPRINT HASH
# =========================================================
def _compute_fp_hash(fp: dict, nav: dict) -> str:
    import hashlib
    parts = [
        str(fp.get("canvas_hash") or ""),
        str(fp.get("timezone") or ""),
        str(nav.get("language") or ""),
        str(nav.get("platform") or ""),
        str(fp.get("hardwareConcurrency") or ""),
        str(fp.get("deviceMemory") or ""),
        str((fp.get("webgl") or {}).get("renderer") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


# =========================================================
# FLOOD CHECK
# =========================================================
def _check_flood(ip: str, campaign_id: int, db: Session):
    cutoff = datetime.utcnow() - timedelta(hours=1)
    if db.query(SessionModel).filter(
        SessionModel.ip == ip,
        SessionModel.campaign_id == campaign_id,
        SessionModel.started_at >= cutoff,
    ).count() >= MAX_SESSIONS_PER_IP_HOUR:
        raise HTTPException(429, "محاولات كتير")


def _campaign_mode(campaign: CampaignModel) -> str:
    try:
        threshold = int(campaign.bot_block_threshold or 100)
    except (ValueError, TypeError):
        threshold = 100
    return mode_from_block_threshold(threshold)


# =========================================================
# HANDSHAKE — Includes Fast IP Filter
# =========================================================
@router.post("/collect/handshake")
async def collect_handshake(
    payload: HandshakePayload,
    request: Request,
    db: Session = Depends(get_db),
):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Collector disabled")

    client_ip = get_client_ip(request)

    # ⚡ Fast IP Filter (Zero-Latency) — يشتغل في أقل من 2ms
    if check_ip_fast(client_ip)["blocked"]:
        return {"ok": False, "hide": True, "reason": "FAST_FILTER_BLOCK", "duplicate": False}

    handshake_limiter.check(client_ip)
    session_id = _validate_session_id(payload.session_id)

    existing = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if existing:
        return {
            "ok": True,
            "session_id": existing.session_id,
            "server_time": int(datetime.utcnow().timestamp() * 1000),
            "duplicate": True,
            "hide": False,
        }

    campaign = _resolve_campaign(payload.campaign_key, db)
    if not campaign:
        raise HTTPException(400, "invalid_campaign_key")

    _check_flood(client_ip, campaign.id, db)

    try:
        threshold = int(campaign.bot_block_threshold or 100)
    except (ValueError, TypeError):
        threshold = 100
    precheck = quick_precheck(
        nav=payload.nav or {},
        fp=payload.fp or {},
        threshold=threshold,
    )

    try:
        ip_info = await get_ip_info(client_ip)
    except Exception:
        ip_info = {}
    if not isinstance(ip_info, dict):
        ip_info = {}

    ua = str((payload.nav or {}).get("ua") or "")
    cc = str(ip_info.get("country_code") or "").upper().strip()
    macros = _extract_macros(payload.tracking_params or {})
    click_id = payload.click_id or None

    blocked = precheck["action"] == "block"
    verdict = "invalid" if blocked else "pending"
    score = precheck["score"] if blocked else 0

    fp_hash = _compute_fp_hash(payload.fp or {}, payload.nav or {})

    session = SessionModel(
        session_id=session_id,
        user_id=campaign.user_id,
        campaign_id=campaign.id,
        ip=client_ip,
        country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
        user_agent=ua[:500],
        url=str(payload.url or "")[:2000],
        started_at=datetime.utcnow(),
        data_quality="pending",
        verdict=verdict,
        score=score,
        clock_drift_ms=0,
        consent_state=str(payload.consent_state or "unknown")[:20],
        visitor_fp_hash=fp_hash,
        meta={
            "precheck": {
                "score": precheck["score"],
                "reasons": precheck["reasons"],
                "action": precheck["action"],
            },
            "macros": macros.get("raw"),
            "macros_known": macros.get("known"),
            "click_id": click_id,
            "campaign_mode": _campaign_mode(campaign),
            "ip_info": ip_info,
            "nav_ua": ua[:500],
            "fp_brief": {
                "canvas_hash": str((payload.fp or {}).get("canvas_hash") or "")[:50],
                "timezone": str((payload.fp or {}).get("timezone") or "")[:50],
            },
        },
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    if blocked:
        return {
            "ok": False,
            "hide": True,
            "reason": precheck["reasons"][0] if precheck["reasons"] else "PRECHECK_BLOCK",
            "duplicate": False,
        }

    return {
        "ok": True,
        "session_id": session.session_id,
        "server_time": int(datetime.utcnow().timestamp() * 1000),
        "duplicate": False,
        "hide": False,
    }


# =========================================================
# HEARTBEAT
# =========================================================
@router.post("/collect/heartbeat")
async def collect_heartbeat(
    payload: HeartbeatPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Collector disabled")

    client_ip = get_client_ip(request)
    session_id = _validate_session_id(payload.session_id)
    heartbeat_limiter.check(f"{session_id}:{client_ip}")

    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(400, "session غير موجودة")

    existing = db.query(VisitHeartbeatModel).filter(
        VisitHeartbeatModel.session_id == session_id,
        VisitHeartbeatModel.seq == payload.seq,
    ).first()
    if existing:
        return {"ok": True, "duplicate": True}

    hb = VisitHeartbeatModel(
        session_id=session_id,
        seq=payload.seq,
        received_at=datetime.utcnow(),
        t_ms=max(0, int(payload.t_ms)),
        clicks=max(0, int(payload.clicks)),
        scrolls=max(0, int(payload.scrolls)),
        mousemoves=max(0, int(payload.mousemoves)),
        keydowns=max(0, int(payload.keydowns)),
        is_visible=bool(payload.is_visible),
        is_focused=bool(payload.is_focused),
    )
    db.add(hb)
    session.last_heartbeat_at = datetime.utcnow()
    session.total_heartbeats = (session.total_heartbeats or 0) + 1
    session.total_time_ms = max(session.total_time_ms or 0, payload.t_ms)
    db.commit()
    return {"ok": True, "duplicate": False}


# =========================================================
# FINAL PROCESSOR
# =========================================================
def _process_final_background(
    session_id: str,
    payload_dict: dict,
    client_ip: str,
    headers_dict: dict | None,
    http_version: str,
):
    db = SessionLocal()
    try:
        session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        if not session or session.visit_id:
            return

        payload = FinalPayload(**payload_dict)
        ua = str((payload.nav or {}).get("ua") or "")

        try:
            os_name, device, browser = parse_ua(ua)
        except Exception:
            os_name, device, browser = "Unknown", "Unknown", "Unknown"

        campaign = db.query(CampaignModel).get(session.campaign_id)

        zone_id, zone_source = _extract_zone_from_payload(
            payload.url or "",
            payload.tracking_params or {},
            campaign,
        )
        print(f"[ZONE] url={payload.url!r} zone={zone_id!r} source={zone_source}")

        ip_info = None
        try:
            if session.meta and isinstance(session.meta, dict):
                ip_info = session.meta.get("ip_info")
        except Exception:
            ip_info = None

        if not ip_info or not isinstance(ip_info, dict) or not ip_info.get("country_code"):
            ip_info = _fetch_ip_info_sync(client_ip)

        if not isinstance(ip_info, dict):
            ip_info = {}
        if "security" not in ip_info or not isinstance(ip_info.get("security"), dict):
            ip_info["security"] = {}
        if "country_code" not in ip_info:
            ip_info["country_code"] = session.country_code or ""

        recent_fp_count = 0
        same_ip_last_minute = 0
        same_canvas_ip_count = 0
        same_ip_canvas_count = 0
        try:
            cutoff_1m = datetime.utcnow() - timedelta(minutes=1)
            cutoff_1h = datetime.utcnow() - timedelta(hours=1)

            same_ip_last_minute = db.query(VisitModel).filter(
                VisitModel.campaign_id == session.campaign_id,
                VisitModel.ip == client_ip,
                VisitModel.timestamp > cutoff_1m,
            ).count()

            canvas_raw = str((payload.fingerprint or {}).get("canvas_hash") or "")
            if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
                canvas_key = canvas_raw[:32]
                recent_fp_count = db.query(VisitModel).filter(
                    VisitModel.campaign_id == session.campaign_id,
                    VisitModel.canvas_hash == canvas_key,
                    VisitModel.timestamp > cutoff_1m,
                ).count()
                same_canvas_ip_count = int(db.query(func.count(distinct(VisitModel.ip))).filter(
                    VisitModel.campaign_id == session.campaign_id,
                    VisitModel.canvas_hash == canvas_key,
                    VisitModel.timestamp > cutoff_1h,
                ).scalar() or 0)
                same_ip_canvas_count = int(db.query(func.count(distinct(VisitModel.canvas_hash))).filter(
                    VisitModel.campaign_id == session.campaign_id,
                    VisitModel.ip == client_ip,
                    VisitModel.timestamp > cutoff_1h,
                ).scalar() or 0)
        except Exception:
            pass

        heartbeats = db.query(VisitHeartbeatModel).filter(
            VisitHeartbeatModel.session_id == session_id,
        ).order_by(VisitHeartbeatModel.seq.asc()).all()

        heartbeats_list = [
            {
                "seq": hb.seq, "t_ms": hb.t_ms,
                "clicks": hb.clicks, "scrolls": hb.scrolls,
                "mousemoves": hb.mousemoves, "keydowns": hb.keydowns,
                "is_visible": bool(hb.is_visible),
            }
            for hb in heartbeats
        ]

        time_ms = max(int(payload.t_ms or 0), session.total_time_ms or 0)

        data = {
            "nav": payload.nav or {},
            "fingerprint": payload.fingerprint or {},
            "behavior": payload.behavior or {},
            "screen": payload.screen or {},
            "client_ip": client_ip,
            "_recent_fp_count": recent_fp_count,
            "_same_ip_last_minute": same_ip_last_minute,
            "_same_canvas_ip_count": same_canvas_ip_count,
            "_same_ip_canvas_count": same_ip_canvas_count,
            "_heartbeat_count": session.total_heartbeats or 0,
            "_session_duration_ms": time_ms,
            "_first_30s": payload.first_30s or {},
            "_milestones": payload.milestones or {},
            "_ad_events": payload.ad_events or [],
            "_clock_drift_ms": payload.clock_drift_ms or 0,
            "_honeypot_triggered": bool(payload.honeypot_triggered),
            "_data_quality": payload.data_quality or "full",
            "_headers": headers_dict,
            "_http_version": http_version,
            "_heartbeats_list": heartbeats_list,
            "_fp_hash": session.visitor_fp_hash,
            "_click_id": payload.click_id or None,
        }

        campaign_mode = _campaign_mode(campaign) if campaign else "balanced"

        try:
            result = evaluate_visit(data, ip_info, campaign_mode=campaign_mode)
        except Exception as e:
            print(f"[BG] engine failure: {e}")
            result = {
                "score": 50, "verdict": "suspicious", "confidence": 0.30,
                "bot_probability": 0.50, "evidence": [],
                "filter_reason": "ENGINE_ERROR", "data_quality": "partial",
                "reason": "engine_error", "reason_detail": str(e)[:200],
                "mode": campaign_mode, "decision": {}, "fusion": {},
                "signals": [], "data_quality_report": {},
                "contradiction_impossible": False, "fingerprint_strikes": 0,
            }

        macros = _extract_macros(payload.tracking_params or {})
        fp = payload.fingerprint or {}
        events = (payload.behavior or {}).get("events") or {}
        cc = str(ip_info.get("country_code") or "").upper().strip()
        visit_click_id = (payload.click_id or "").strip() or None

        full_payload = {
            "engine_version": "v4.2.2",
            "verdict": result.get("verdict"),
            "score": result.get("score"),
            "confidence": result.get("confidence"),
            "bot_probability": result.get("bot_probability"),
            "reason": result.get("reason"),
            "reason_detail": result.get("reason_detail"),
            "mode": result.get("mode"),
            "data_quality_report": result.get("data_quality_report"),
            "decision": result.get("decision"),
            "fusion": result.get("fusion"),
            "fingerprint_strikes": result.get("fingerprint_strikes"),
            "contradiction_impossible": result.get("contradiction_impossible"),
            "signals": result.get("signals"),
        }

        existing_visit = db.query(VisitModel).filter(VisitModel.session_id == session_id).first()

        if existing_visit:
            existing_visit.score = result.get("score", existing_visit.score)
            existing_visit.verdict = result.get("verdict", existing_visit.verdict)
            existing_visit.evidence = result.get("evidence", existing_visit.evidence)
            existing_visit.filter_reason = result.get("filter_reason")
            existing_visit.confidence = result.get("confidence")
            existing_visit.bot_probability = result.get("bot_probability")
            existing_visit.mode = result.get("mode")
            existing_visit.reason = result.get("reason")
            existing_visit.data_quality_report = result.get("data_quality_report")
            existing_visit.full_payload = full_payload
            existing_visit.time_on_page = time_ms
            existing_visit.clicks = int(events.get("clicks", 0) or 0)
            existing_visit.scrolls = int(events.get("scrolls", 0) or 0)
            existing_visit.behavioral = payload.behavior or None
            existing_visit.first_30s = payload.first_30s or None
            existing_visit.milestones = payload.milestones or None
            existing_visit.ad_events = payload.ad_events or None
            existing_visit.clock_drift_ms = payload.clock_drift_ms or 0
            existing_visit.is_honeypot_triggered = bool(payload.honeypot_triggered)
            existing_visit.data_quality = result.get("data_quality", "partial")
            if macros.get("raw"):
                merged = dict(existing_visit.popads_data or {})
                merged.update(macros["raw"])
                existing_visit.popads_data = merged
            if macros.get("bid") and not existing_visit.bid:
                existing_visit.bid = macros["bid"]
            if macros.get("impression_id") and not existing_visit.popads_impression_id:
                existing_visit.popads_impression_id = macros["impression_id"]
            if macros.get("website_id") and not existing_visit.popads_website_id:
                existing_visit.popads_website_id = macros["website_id"]
            if macros.get("quality") is not None and existing_visit.popads_quality is None:
                existing_visit.popads_quality = macros["quality"]
            if macros.get("country") and existing_visit.country in (None, "Unknown", "Local"):
                existing_visit.country = macros["country"]
            db.commit()

            session.visit_id = existing_visit.id
            session.verdict = existing_visit.verdict
            session.score = existing_visit.score
            session.confidence = existing_visit.confidence
            session.bot_probability = existing_visit.bot_probability
            session.data_quality = result.get("data_quality", "partial")
            session.ended_at = datetime.utcnow()
            db.commit()
            if session.user_id:
                stats_cache.invalidate(f"stats:user:{session.user_id}:all")
                stats_cache.invalidate(f"stats:campaign:{session.campaign_id}")
            return

        canvas_full = str(fp.get("canvas_hash", "") or "")
        canvas_stored = canvas_full[:32] if canvas_full and canvas_full not in ("blocked",) else "Unknown"

        visit = VisitModel(
            campaign_id=session.campaign_id,
            session_id=session_id,
            timestamp=datetime.utcnow(),
            ip=client_ip,
            user_agent=ua,
            zone_id=zone_id,
            click_id=visit_click_id,
            filter_reason=result.get("filter_reason"),
            confidence=result.get("confidence"),
            bot_probability=result.get("bot_probability"),
            mode=result.get("mode"),
            reason=result.get("reason"),
            data_quality_report=result.get("data_quality_report"),
            full_payload=full_payload,
            bid=macros.get("bid", 0.0),
            popads_impression_id=macros.get("impression_id"),
            popads_website_id=macros.get("website_id"),
            popads_quality=macros.get("quality"),
            popads_adblock=macros.get("adblock", False),
            popads_data=macros.get("raw"),
            score=result.get("score", 0),
            verdict=result.get("verdict", "suspicious"),
            evidence=result.get("evidence", []),
            os=os_name,
            device=device,
            browser=browser,
            country=macros.get("country") or ip_info.get("country", "Unknown"),
            country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
            isp=macros.get("known", {}).get("isp_name") or ip_info.get("isp", "Unknown"),
            asn=ip_info.get("asn", "Unknown"),
            is_vpn=bool(ip_info.get("security", {}).get("vpn")),
            timezone=str(fp.get("timezone", "Unknown"))[:50],
            canvas_hash=canvas_stored,
            data_quality=result.get("data_quality", "partial"),
            time_on_page=time_ms,
            clicks=int(events.get("clicks", 0) or 0),
            scrolls=int(events.get("scrolls", 0) or 0),
            counting_type="landing",
            first_30s=payload.first_30s or None,
            milestones=payload.milestones or None,
            ad_events=payload.ad_events or None,
            behavioral=payload.behavior or None,
            clock_drift_ms=payload.clock_drift_ms or 0,
            is_honeypot_triggered=bool(payload.honeypot_triggered),
            consent_state=payload.consent_state or "unknown",
        )

        try:
            db.add(visit)
            db.commit()
            db.refresh(visit)

            session.visit_id = visit.id
            session.verdict = visit.verdict
            session.score = visit.score
            session.confidence = visit.confidence
            session.bot_probability = visit.bot_probability
            session.data_quality = result.get("data_quality", "partial")
            session.ended_at = datetime.utcnow()
            db.commit()

            if session.user_id:
                stats_cache.invalidate(f"stats:user:{session.user_id}:all")
                stats_cache.invalidate(f"stats:campaign:{session.campaign_id}")
        except Exception as e:
            db.rollback()
            print(f"[BG] Failed to save visit: {e}")
    except Exception as e:
        print(f"[BG] Error: {e}")
    finally:
        db.close()


@router.post("/collect/final")
async def collect_final(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Collector disabled")

    client_ip = get_client_ip(request)

    try:
        raw_bytes = await request.body()
        payload_dict = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        payload = FinalPayload(**payload_dict)
    except Exception as e:
        raise HTTPException(400, f"Invalid payload: {e}")

    session_id = _validate_session_id(payload.session_id)
    final_limiter.check(f"{session_id}:{client_ip}")

    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session:
        raise HTTPException(400, "session غير موجودة")

    if session.visit_id:
        v = db.query(VisitModel).get(session.visit_id)
        if v:
            return {"ok": True, "visit_id": v.id, "duplicate": True}

    headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    http_version = str(request.scope.get("http_version", "1.1"))

    background_tasks.add_task(
        _process_final_background,
        session_id, payload_dict, client_ip, headers_dict, http_version,
    )
    return {"ok": True, "status": "processing", "duplicate": False}


# =========================================================
# STALE SESSION FINALIZER
# =========================================================
def _finalize_stale_session(session_id: str) -> bool:
    db_check = SessionLocal()
    try:
        session = db_check.query(SessionModel).filter(
            SessionModel.session_id == session_id,
        ).first()
        if not session or session.visit_id:
            return False

        client_ip = session.ip or ""
        url = session.url or ""
        user_agent = session.user_agent or ""
        consent = session.consent_state or "unknown"

        started_at = session.started_at or datetime.utcnow()
        age_sec = (datetime.utcnow() - started_at).total_seconds()

        heartbeats = db_check.query(VisitHeartbeatModel).filter(
            VisitHeartbeatModel.session_id == session_id,
        ).order_by(VisitHeartbeatModel.seq.asc()).all()

        hb_data = [
            {
                "clicks": hb.clicks or 0,
                "scrolls": hb.scrolls or 0,
                "mousemoves": hb.mousemoves or 0,
                "keydowns": hb.keydowns or 0,
                "t_ms": hb.t_ms or 0,
                "is_visible": bool(hb.is_visible),
                "is_focused": bool(hb.is_focused),
            }
            for hb in heartbeats
        ]

        meta_ua = ""
        meta_macros = {}
        try:
            if session.meta and isinstance(session.meta, dict):
                meta_ua = session.meta.get("nav_ua") or ""
                meta_macros = session.meta.get("macros") or {}
        except Exception:
            pass
    finally:
        db_check.close()

    # ---------- Path B: DEAD session (no heartbeats + aged 120s+) ----------
    if not hb_data and age_sec >= 120:
        try:
            db = SessionLocal()
            try:
                s = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
                if s and not s.visit_id:
                    campaign = db.query(CampaignModel).get(s.campaign_id)
                    zone_id, zone_source = _extract_zone_from_payload(url, meta_macros, campaign)

                    ip_info = None
                    try:
                        if s.meta and isinstance(s.meta, dict):
                            ip_info = s.meta.get("ip_info")
                    except Exception:
                        pass
                    if not ip_info:
                        ip_info = _fetch_ip_info_sync(client_ip)

                    cc = str(ip_info.get("country_code") or "").upper().strip()

                    visit = VisitModel(
                        campaign_id=s.campaign_id,
                        session_id=session_id,
                        timestamp=datetime.utcnow(),
                        ip=client_ip,
                        user_agent=user_agent,
                        zone_id=zone_id,
                        confidence=0.85,
                        bot_probability=0.85,
                        mode="balanced",
                        reason="stale_no_heartbeats",
                        data_quality="partial",
                        full_payload={
                            "engine_version": "v4.2.2-stale",
                            "verdict": "invalid",
                            "reason": "stale_no_heartbeats",
                            "reason_detail": f"No heartbeats and no final after {age_sec:.0f}s",
                        },
                        score=85,
                        verdict="invalid",
                        evidence=[{
                            "code": "STALE_NO_HEARTBEATS",
                            "severity": "critical",
                            "score": 85,
                            "detail": f"No heartbeat/final after {age_sec:.0f}s",
                        }],
                        country=ip_info.get("country", "Unknown"),
                        country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
                        time_on_page=int(age_sec * 1000),
                        counting_type="landing",
                        filter_reason="STALE_NO_HEARTBEATS",
                    )
                    db.add(visit)
                    db.commit()
                    db.refresh(visit)

                    s.visit_id = visit.id
                    s.verdict = visit.verdict
                    s.score = visit.score
                    s.confidence = visit.confidence
                    s.bot_probability = visit.bot_probability
                    s.data_quality = "partial"
                    s.ended_at = datetime.utcnow()
                    db.commit()
                    if s.user_id:
                        stats_cache.invalidate(f"stats:user:{s.user_id}:all")
                        stats_cache.invalidate(f"stats:campaign:{s.campaign_id}")
                    print(f"[STALE] dead session {session_id} -> invalid (no heartbeats)")
            finally:
                db.close()
        except Exception as e:
            print(f"[STALE] dead finalization failed for {session_id}: {e}")
        return True

    # ---------- Path A: has heartbeats ----------
    total_clicks = sum(h["clicks"] for h in hb_data)
    total_scrolls = sum(h["scrolls"] for h in hb_data)
    total_mousemoves = sum(h["mousemoves"] for h in hb_data)
    total_keydowns = sum(h["keydowns"] for h in hb_data)
    max_t_ms = max((h["t_ms"] for h in hb_data), default=0)

    payload_dict = {
        "v": 3,
        "session_id": session_id,
        "click_id": "",
        "campaign_key": "",
        "seq": 999,
        "t_ms": max_t_ms,
        "url": url,
        "webrtc_ip": "None",
        "nav": {"ua": user_agent or meta_ua},
        "fingerprint": {},
        "behavior": {
            "events": {
                "clicks": total_clicks,
                "scrolls": total_scrolls,
                "mousemove": total_mousemoves,
                "keydown": total_keydowns,
            },
            "total_time_ms": max_t_ms,
            "time_on_page_ms": max_t_ms,
            "mouse_points": [],
            "key_intervals": [],
        },
        "screen": {},
        "milestones": {},
        "first_30s": {},
        "ad_events": [],
        "honeypot_triggered": False,
        "clock_drift_ms": 0,
        "consent_state": consent,
        "data_quality": "partial",
        "tracking_params": meta_macros if isinstance(meta_macros, dict) else {},
    }

    _process_final_background(session_id, payload_dict, client_ip, None, "1.1")
    return True


async def stale_session_finalizer_loop():
    """Every 60s: finalize any PENDING session older than 120s."""
    while True:
        try:
            await asyncio.sleep(60)
            db = SessionLocal()
            try:
                cutoff = datetime.utcnow() - timedelta(seconds=120)
                stale = db.query(SessionModel).filter(
                    SessionModel.visit_id.is_(None),
                    SessionModel.started_at < cutoff,
                ).order_by(SessionModel.started_at.asc()).limit(50).all()
                session_ids = [s.session_id for s in stale]
            finally:
                db.close()

            if session_ids:
                print(f"[STALE] finalizing {len(session_ids)} stuck sessions")
                for sid in session_ids:
                    try:
                        _finalize_stale_session(sid)
                    except Exception as e:
                        print(f"[STALE] failed for {sid}: {e}")
        except Exception as e:
            print(f"[STALE] loop error: {e}")