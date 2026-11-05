"""
routers/collector_v3.py — Collector v3 (P2 — Idempotency & Speed + Fixes 1-4)
"""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from sqlalchemy import func, distinct
from sqlalchemy.orm import Session

from config import (
    COLLECTOR_V3_ENABLED, MAX_SESSIONS_PER_IP_HOUR,
)
from database import get_db, SessionLocal
from models import (
    SessionModel, VisitHeartbeatModel, VisitModel,
    SiteModel, CampaignModel,
)
from schemas import HandshakePayload, HeartbeatPayload, FinalPayload
from utils import (
    get_client_ip,
    handshake_limiter, heartbeat_limiter, final_limiter,
    stats_cache,
)
from analysis import get_ip_info, parse_ua, extract_zone_id
from collector.filter_engine import evaluate_visit
from helpers import extract_zone_id_from_url

router = APIRouter()


def _validate_session_id(session_id: str) -> str:
    s = (session_id or "").strip()
    if not s or len(s) < 8 or len(s) > 64:
        raise HTTPException(400, "session_id غير صالح")
    return s


def _resolve_target(site_key: str, campaign_key: str, db: Session):
    user_id = None
    site_id = None
    campaign_id = None

    if campaign_key:
        c = db.query(CampaignModel).filter(CampaignModel.campaign_key == campaign_key).first()
        if c:
            campaign_id = c.id
            user_id = c.user_id
            site_id = c.site_id

    if not campaign_id and site_key:
        c = db.query(CampaignModel).filter(CampaignModel.campaign_key == site_key).first()
        if c:
            campaign_id = c.id
            user_id = c.user_id
            site_id = c.site_id
        else:
            s = db.query(SiteModel).filter(SiteModel.site_key == site_key).first()
            if s:
                site_id = s.id
                user_id = s.user_id
                c2 = db.query(CampaignModel).filter(CampaignModel.site_id == s.id).first()
                if c2:
                    campaign_id = c2.id

    return user_id, site_id, campaign_id


def _extract_fp_brief(fp: dict) -> dict:
    if not isinstance(fp, dict): return {}
    return {
        "canvas": str(fp.get("canvas_hash") or "")[:20],
        "tz": str(fp.get("timezone") or "")[:50],
        "lang": str(fp.get("language") or "")[:10],
        "ua_short": str((fp.get("ua") or ""))[:100],
    }


def _compute_fp_hash(fp: dict) -> str:
    import hashlib
    parts = [
        str(fp.get("canvas_hash") or ""),
        str(fp.get("timezone") or ""),
        str(fp.get("language") or ""),
        str(fp.get("hardwareConcurrency") or ""),
        str(fp.get("deviceMemory") or ""),
        str((fp.get("webgl") or {}).get("renderer") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _check_flood(session_id: str, ip: str, db: Session):
    cutoff = datetime.utcnow() - timedelta(hours=1)
    count = db.query(SessionModel).filter(
        SessionModel.ip == ip, SessionModel.started_at >= cutoff,
    ).count()
    if count >= MAX_SESSIONS_PER_IP_HOUR:
        raise HTTPException(429, "محاولات كتير — جرب بعد شوية")


@router.post("/collect/handshake")
async def collect_handshake(payload: HandshakePayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Collector v3 disabled")

    client_ip = get_client_ip(request)
    handshake_limiter.check(client_ip)
    session_id = _validate_session_id(payload.session_id)

    existing = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if existing:
        return {"ok": True, "session_id": existing.session_id, "server_time": int(datetime.utcnow().timestamp() * 1000), "duplicate": True}

    _check_flood(session_id, client_ip, db)
    user_id, site_id, campaign_id = _resolve_target(payload.site_key, payload.campaign_key, db)

    try:
        ip_info = await get_ip_info(client_ip)
        if not isinstance(ip_info, dict): ip_info = {}
    except Exception:
        ip_info = {}

    ua = str((payload.nav or {}).get("ua") or "")
    cc = str(ip_info.get("country_code") or "").upper().strip()
    
    session = SessionModel(
        session_id=session_id, user_id=user_id, site_id=site_id, campaign_id=campaign_id,
        ip=client_ip, country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
        user_agent=ua[:500], url=str(payload.url or "")[:2000],
        started_at=datetime.utcnow(), data_quality="pending", clock_drift_ms=0,
        consent_state=str(payload.consent_state or "unknown")[:20],
        visitor_fp_hash=_compute_fp_hash(payload.fp or {}),
        meta={"fp_brief": _extract_fp_brief(payload.fp or {})},
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return {"ok": True, "session_id": session.session_id, "server_time": int(datetime.utcnow().timestamp() * 1000), "duplicate": False}


@router.post("/collect/heartbeat")
async def collect_heartbeat(payload: HeartbeatPayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Collector v3 disabled")
    client_ip = get_client_ip(request)
    session_id = _validate_session_id(payload.session_id)
    heartbeat_limiter.check(f"{session_id}:{client_ip}")

    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session: raise HTTPException(400, "session غير موجودة")

    existing = db.query(VisitHeartbeatModel).filter(VisitHeartbeatModel.session_id == session_id, VisitHeartbeatModel.seq == payload.seq).first()
    if existing: return {"ok": True, "duplicate": True}

    hb = VisitHeartbeatModel(
        session_id=session_id, seq=payload.seq, received_at=datetime.utcnow(), t_ms=max(0, int(payload.t_ms)),
        clicks=max(0, int(payload.clicks)), scrolls=max(0, int(payload.scrolls)),
        mousemoves=max(0, int(payload.mousemoves)), keydowns=max(0, int(payload.keydowns)),
        is_visible=bool(payload.is_visible), is_focused=bool(payload.is_focused),
    )
    db.add(hb)
    session.last_heartbeat_at = datetime.utcnow()
    session.total_heartbeats = (session.total_heartbeats or 0) + 1
    session.total_time_ms = max(session.total_time_ms or 0, payload.t_ms)
    db.commit()
    return {"ok": True, "duplicate": False}


def _process_final_background(session_id: str, payload_dict: dict, client_ip: str, headers_dict: dict, http_version: str):
    db = SessionLocal()
    try:
        session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        
        # حماية: لو الـ Interstitial سجل الزيارة خلاص، بلاش نسجل تاني
        if not session or session.visit_id:
            return 

        payload = FinalPayload(**payload_dict)
        ua = str((payload.nav or {}).get("ua") or "")
        
        try: os_name, device, browser = parse_ua(ua)
        except Exception: os_name, device, browser = "Unknown", "Unknown", "Unknown"

        zone_id = extract_zone_id(payload.url or "")
        if not zone_id or zone_id == "unknown":
            if session.campaign_id:
                c = db.query(CampaignModel).get(session.campaign_id)
                if c and c.destination_zone_id: zone_id = str(c.destination_zone_id).strip()[:100]
                elif c and c.destination_url: zone_id = extract_zone_id_from_url(c.destination_url) or "unknown"
        if not zone_id: zone_id = "unknown"

        # 🔴 إصلاح باج 3: جلب الـ IP Info في الخلفية (مش بيأثر على سرعة الرد)
        try:
            ip_info = __import__('asyncio').run(get_ip_info(client_ip)) # Run async in sync context
        except Exception:
            ip_info = {"country": "Unknown", "country_code": session.country_code, "isp": "Unknown", "asn": "", "security": {}, "lat": 0.0, "lon": 0.0}

        # 🔴 إصلاح باج 4: حساب تكرار الـ IP والبصمة
        recent_fp_count = 0; same_ip_last_minute = 0; same_canvas_ip_count = 0; same_ip_canvas_count = 0
        try:
            cutoff_1m = datetime.utcnow() - timedelta(minutes=1)
            cutoff_1h = datetime.utcnow() - timedelta(hours=1)
            same_ip_last_minute = db.query(VisitModel).filter(VisitModel.ip == client_ip, VisitModel.timestamp > cutoff_1m).count()
            
            canvas_raw = str((payload.fingerprint or {}).get("canvas_hash") or "")
            if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
                recent_fp_count = db.query(VisitModel).filter(VisitModel.canvas_hash == canvas_raw[:15] + "...", VisitModel.timestamp > cutoff_1m).count()
                same_canvas_ip_count = int(db.query(func.count(distinct(VisitModel.ip))).filter(VisitModel.canvas_hash == canvas_raw[:15] + "...", VisitModel.timestamp > cutoff_1h).scalar() or 0)
                same_ip_canvas_count = int(db.query(func.count(distinct(VisitModel.canvas_hash))).filter(VisitModel.ip == client_ip, VisitModel.timestamp > cutoff_1h).scalar() or 0)
        except Exception as e:
            print(f"[BG] Cross-visit fail: {e}")

        heartbeats = db.query(VisitHeartbeatModel).filter(VisitHeartbeatModel.session_id == session_id).order_by(VisitHeartbeatModel.seq.asc()).all()
        heartbeats_list = [{"seq": hb.seq, "t_ms": hb.t_ms, "clicks": hb.clicks, "scrolls": hb.scrolls, "mousemoves": hb.mousemoves, "keydowns": hb.keydowns} for hb in heartbeats]
        time_ms = max(int(payload.t_ms or 0), session.total_time_ms or 0)

        data = {
            "nav": payload.nav or {}, "fingerprint": payload.fingerprint or {}, "behavior": payload.behavior or {},
            "screen": payload.screen or {}, "webrtc_ip": payload.webrtc_ip or "None", "client_ip": client_ip,
            "_recent_fp_count": recent_fp_count, "_same_ip_last_minute": same_ip_last_minute,
            "_same_canvas_ip_count": same_canvas_ip_count, "_same_ip_canvas_count": same_ip_canvas_count,
            "_heartbeat_count": session.total_heartbeats or 0, "_session_duration_ms": time_ms,
            "_first_30s": payload.first_30s or {}, "_milestones": payload.milestones or {}, "_ad_events": payload.ad_events or [],
            "_clock_drift_ms": payload.clock_drift_ms or 0, "_honeypot_triggered": bool(payload.honeypot_triggered),
            "_data_quality": payload.data_quality or "full", "_headers": headers_dict, "_http_version": http_version,
            "_heartbeats_list": heartbeats_list, "_fp_hash": session.visitor_fp_hash,
        }

        try: result = evaluate_visit(data, ip_info)
        except Exception as e:
            result = {"score": 50, "verdict": "suspicious", "evidence": [], "filter_reason": "ENGINE_ERROR"}

        fp = payload.fingerprint or {}; behavior = payload.behavior or {}; events = behavior.get("events") or {}
        cc = str(ip_info.get("country_code") or "").upper().strip()

        visit = VisitModel(
            site_id=session.site_id, campaign_id=session.campaign_id, session_id=session_id, timestamp=datetime.utcnow(),
            ip=client_ip, user_agent=ua, zone_id=zone_id, click_id=payload.click_id or None, filter_reason=result.get("filter_reason"),
            score=result.get("score", 0), verdict=result.get("verdict", "suspicious"), evidence=result.get("evidence", []),
            os=os_name, device=device, browser=browser, country=ip_info.get("country", "Unknown"), country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
            isp=ip_info.get("isp", "Unknown"), timezone=str(fp.get("timezone", "Unknown"))[:50],
            canvas_hash=(str(fp.get("canvas_hash", ""))[:15] + "...") if fp.get("canvas_hash") else "Unknown",
            data_quality=payload.data_quality or "full", time_on_page=time_ms,
            clicks=int(events.get("clicks", 0) or 0), scrolls=int(events.get("scrolls", 0) or 0),
        )
        
        try:
            db.add(visit); db.commit(); db.refresh(visit)
            session.visit_id = visit.id; session.verdict = visit.verdict; session.score = visit.score
            session.ended_at = datetime.utcnow(); db.commit()
            if session.site_id: stats_cache.invalidate(f"stats:site:{session.site_id}")
            if session.user_id: stats_cache.invalidate(f"stats:user:{session.user_id}:all")
        except Exception as e:
            db.rollback()
            print(f"[BG] Failed to save visit: {e}")

    except Exception as e:
        print(f"[BG] Fatal error: {e}")
    finally:
        db.close()


@router.post("/collect/final")
async def collect_final(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Collector v3 disabled")
    client_ip = get_client_ip(request)

    try:
        raw_bytes = await request.body()
        payload_dict = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        payload = FinalPayload(**payload_dict) 
    except Exception as e: raise HTTPException(400, f"Invalid payload: {e}")

    session_id = _validate_session_id(payload.session_id)
    final_limiter.check(f"{session_id}:{client_ip}")

    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session: raise HTTPException(400, "session غير موجودة")

    if session.visit_id:
        v = db.query(VisitModel).get(session.visit_id)
        if v: return {"ok": True, "visit_id": v.id, "verdict": v.verdict, "score": v.score, "duplicate": True}

    headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    http_version = str(request.scope.get("http_version", "1.1"))

    background_tasks.add_task(_process_final_background, session_id, payload_dict, client_ip, headers_dict, http_version)
    return {"ok": True, "status": "processing", "duplicate": False}
