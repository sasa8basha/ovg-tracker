"""
routers/collector_v3.py — Collector v3 (Phase 1.1 + Fix 1.3.1)

Fix: /collect/final now accepts text/plain (from sendBeacon) and JSON (from fetch).
"""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import (
    COLLECTOR_V3_ENABLED, SESSION_ID_RE, MAX_SESSIONS_PER_IP_HOUR,
    DATA_QUALITY_FULL, DATA_QUALITY_PARTIAL, DATA_QUALITY_FAILED,
)
from database import get_db
from models import (
    SessionModel, VisitHeartbeatModel, VisitModel,
    SiteModel, CampaignModel, UserModel,
)
from schemas import HandshakePayload, HeartbeatPayload, FinalPayload
from utils import (
    get_client_ip,
    handshake_limiter, heartbeat_limiter, final_limiter,
    stats_cache, zone_evidence_cache,
)
from analysis import (
    get_ip_info, parse_ua, extract_zone_id, analyze_visit,
)
from collector.constants import (
    SIG_HONEYPOT_CLICK, SIG_HONEYPOT_FORM,
    SIG_CLOCK_DRIFT, SIG_SILENT_AFTER_INITIAL, SIG_HEARTBEAT_GAP,
)

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
        c = db.query(CampaignModel).filter(
            CampaignModel.campaign_key == campaign_key
        ).first()
        if c:
            campaign_id = c.id
            user_id = c.user_id
            site_id = c.site_id

    if not campaign_id and site_key:
        c = db.query(CampaignModel).filter(
            CampaignModel.campaign_key == site_key
        ).first()
        if c:
            campaign_id = c.id
            user_id = c.user_id
            site_id = c.site_id
        else:
            s = db.query(SiteModel).filter(SiteModel.site_key == site_key).first()
            if s:
                site_id = s.id
                user_id = s.user_id
                c2 = db.query(CampaignModel).filter(
                    CampaignModel.site_id == s.id
                ).first()
                if c2:
                    campaign_id = c2.id

    return user_id, site_id, campaign_id


def _extract_fp_brief(fp: dict) -> dict:
    if not isinstance(fp, dict):
        return {}
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
    s = "|".join(parts)
    return hashlib.sha256(s.encode()).hexdigest()[:32]


def _check_flood(session_id: str, ip: str, db: Session):
    cutoff = datetime.utcnow() - timedelta(hours=1)
    count = db.query(SessionModel).filter(
        SessionModel.ip == ip,
        SessionModel.started_at >= cutoff,
    ).count()
    if count >= MAX_SESSIONS_PER_IP_HOUR:
        raise HTTPException(429, "محاولات كتير — جرب بعد شوية")


@router.post("/collect/handshake")
async def collect_handshake(
    payload: HandshakePayload,
    request: Request,
    db: Session = Depends(get_db),
):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Collector v3 disabled")

    client_ip = get_client_ip(request)
    handshake_limiter.check(client_ip)

    session_id = _validate_session_id(payload.session_id)

    existing = db.query(SessionModel).filter(
        SessionModel.session_id == session_id
    ).first()
    if existing:
        return {
            "ok": True,
            "session_id": existing.session_id,
            "server_time": int(datetime.utcnow().timestamp() * 1000),
            "duplicate": True,
        }

    _check_flood(session_id, client_ip, db)

    user_id, site_id, campaign_id = _resolve_target(
        payload.site_key, payload.campaign_key, db,
    )

    try:
        ip_info = await get_ip_info(client_ip)
        if not isinstance(ip_info, dict):
            ip_info = {}
    except Exception:
        ip_info = {}

    ua = str((payload.nav or {}).get("ua") or "")
    cc = str(ip_info.get("country_code") or "").upper().strip()
    if cc in ("LO", "XX", ""):
        cc = None

    fp_hash = _compute_fp_hash(payload.fp or {})

    session = SessionModel(
        session_id=session_id,
        user_id=user_id,
        site_id=site_id,
        campaign_id=campaign_id,
        ip=client_ip,
        country_code=cc[:2] if cc else None,
        user_agent=ua[:500],
        url=str(payload.url or "")[:2000],
        started_at=datetime.utcnow(),
        data_quality="pending",
        clock_drift_ms=0,
        consent_state=str(payload.consent_state or "unknown")[:20],
        visitor_fp_hash=fp_hash,
        meta={"fp_brief": _extract_fp_brief(payload.fp or {})},
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    return {
        "ok": True,
        "session_id": session.session_id,
        "server_time": int(datetime.utcnow().timestamp() * 1000),
        "duplicate": False,
    }


@router.post("/collect/heartbeat")
async def collect_heartbeat(
    payload: HeartbeatPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Collector v3 disabled")

    client_ip = get_client_ip(request)
    session_id = _validate_session_id(payload.session_id)
    heartbeat_limiter.check(f"{session_id}:{client_ip}")

    session = db.query(SessionModel).filter(
        SessionModel.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(400, "session غير موجودة — handshake أولاً")

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


@router.post("/collect/final")
async def collect_final(
    request: Request,
    db: Session = Depends(get_db),
):
    """
    يقبل text/plain (من sendBeacon) أو application/json (من fetch).
    بيقرأ الـ body يدوياً ويحوله JSON.
    """
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Collector v3 disabled")

    client_ip = get_client_ip(request)

    # Read raw body
    try:
        raw_bytes = await request.body()
        if not raw_bytes:
            raise HTTPException(400, "Empty body")
        try:
            raw_str = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raw_str = raw_bytes.decode("utf-8", errors="replace")
        payload_dict = json.loads(raw_str)
        payload = FinalPayload(**payload_dict)
    except HTTPException:
        raise
    except Exception as e:
        print(f"[COLLECT_FINAL] payload parse failed: {e}")
        raise HTTPException(400, f"Invalid payload: {e}")

    session_id = _validate_session_id(payload.session_id)
    final_limiter.check(f"{session_id}:{client_ip}")

    session = db.query(SessionModel).filter(
        SessionModel.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(400, "session غير موجودة — handshake أولاً")

    if session.visit_id:
        v = db.query(VisitModel).get(session.visit_id)
        if v:
            return {
                "ok": True,
                "visit_id": v.id,
                "verdict": v.verdict,
                "score": v.score,
                "duplicate": True,
            }

    ua = str((payload.nav or {}).get("ua") or "")
    try:
        os_name, device, browser = parse_ua(ua)
    except Exception:
        os_name, device, browser = "Unknown", "Unknown", "Unknown"

    try:
        zone_id = extract_zone_id(payload.url)
    except Exception:
        zone_id = "unknown"

    try:
        ip_info = await get_ip_info(client_ip)
        if not isinstance(ip_info, dict):
            ip_info = {}
    except Exception:
        ip_info = {}

    canvas_raw = str((payload.fingerprint or {}).get("canvas_hash") or "")
    recent_fp_count = 0
    same_ip_last_minute = 0
    same_canvas_ip_count = 0
    same_ip_canvas_count = 0

    try:
        cutoff_1m = datetime.utcnow() - timedelta(minutes=1)
        cutoff_1h = datetime.utcnow() - timedelta(hours=1)

        same_ip_last_minute = db.query(VisitModel).filter(
            VisitModel.ip == client_ip,
            VisitModel.timestamp > cutoff_1m,
        ).count()

        if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
            canvas_stored = canvas_raw[:15] + "..."
            recent_fp_count = db.query(VisitModel).filter(
                VisitModel.canvas_hash == canvas_stored,
                VisitModel.timestamp > cutoff_1m,
            ).count()
            same_canvas_ip_count = int(
                db.query(func.count(func.distinct(VisitModel.ip))).filter(
                    VisitModel.canvas_hash == canvas_stored,
                    VisitModel.timestamp > cutoff_1h,
                ).scalar() or 0
            )
            same_ip_canvas_count = int(
                db.query(func.count(func.distinct(VisitModel.canvas_hash))).filter(
                    VisitModel.ip == client_ip,
                    VisitModel.timestamp > cutoff_1h,
                ).scalar() or 0
            )
    except Exception as e:
        print(f"[COLLECT_FINAL] cross-visit failed: {e}")

    data = {
        "nav": payload.nav or {},
        "fingerprint": payload.fingerprint or {},
        "behavior": payload.behavior or {},
        "screen": payload.screen or {},
        "webrtc_ip": payload.webrtc_ip or "None",
        "client_ip": client_ip,
        "_recent_fp_count": recent_fp_count,
        "_same_ip_last_minute": same_ip_last_minute,
        "_same_canvas_ip_count": same_canvas_ip_count,
        "_same_ip_canvas_count": same_ip_canvas_count,
    }

    try:
        result = analyze_visit(data, ip_info)
    except Exception as e:
        print(f"[COLLECT_FINAL] analyze_visit failed: {e}")
        result = {
            "score": 50,
            "verdict": "suspicious",
            "evidence": [{"code": "ANALYSIS_ERROR", "severity": "medium",
                          "score": 0, "detail": str(e)[:200]}],
            "raw_score": 50,
            "final_score": 50,
            "confidence": 0.0,
            "categories": {"critical": 0, "high": 0, "medium": 0,
                           "low": 0, "human": 0},
        }

    new_evidence = list(result.get("evidence", []))

    if payload.honeypot_triggered:
        new_evidence.append({
            "code": SIG_HONEYPOT_CLICK, "severity": "critical",
            "score": 100, "detail": "Honeypot triggered (from client)",
        })

    if abs(int(payload.clock_drift_ms or 0)) > 30000:
        new_evidence.append({
            "code": SIG_CLOCK_DRIFT, "severity": "medium",
            "score": 30,
            "detail": f"Clock drift: {int(payload.clock_drift_ms)}ms",
        })

    heartbeat_count = session.total_heartbeats or 0
    time_ms = max(int(payload.t_ms or 0), session.total_time_ms or 0)

    if heartbeat_count == 0 and time_ms < 5000:
        new_evidence.append({
            "code": SIG_SILENT_AFTER_INITIAL, "severity": "high",
            "score": 60, "detail": "No heartbeat after handshake (drive-by bot?)",
        })

    if heartbeat_count >= 2:
        hbs = db.query(VisitHeartbeatModel).filter(
            VisitHeartbeatModel.session_id == session_id
        ).order_by(VisitHeartbeatModel.seq.asc()).all()
        for i in range(1, len(hbs)):
            gap = (hbs[i].received_at - hbs[i-1].received_at).total_seconds()
            if gap > 60:
                new_evidence.append({
                    "code": SIG_HEARTBEAT_GAP, "severity": "low",
                    "score": 15,
                    "detail": f"Heartbeat gap: {gap:.1f}s",
                })
                break

    result["evidence"] = new_evidence

    fp = payload.fingerprint or {}
    behavior = payload.behavior or {}
    events = behavior.get("events") or {}

    cc = str(ip_info.get("country_code") or "").upper().strip()
    cc_stored = None if cc in ("LO", "XX", "") else cc[:2]

    canvas_stored = str(fp.get("canvas_hash", "Unknown"))
    if len(canvas_stored) >= 15 and canvas_stored not in ("blocked", "Unknown"):
        canvas_stored = canvas_stored[:15] + "..."

    dq = payload.data_quality or "full"
    if dq not in ("full", "partial", "failed"):
        dq = "partial"

    visit = VisitModel(
        site_id=session.site_id,
        campaign_id=session.campaign_id,
        session_id=session_id,
        timestamp=datetime.utcnow(),
        ip=client_ip,
        user_agent=ua,
        zone_id=zone_id,
        score=result.get("score", 0),
        verdict=result.get("verdict", "suspicious"),
        evidence=result.get("evidence", []),
        os=os_name,
        device=device,
        browser=browser,
        country=ip_info.get("country", "Unknown"),
        country_code=cc_stored,
        isp=ip_info.get("isp", "Unknown"),
        timezone=str(fp.get("timezone", "Unknown"))[:50],
        canvas_hash=canvas_stored,
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info.get("type", "unknown"),
        asn=str(ip_info.get("asn", ""))[:50],
        is_vpn=(ip_info.get("security", {}).get("vpn") is True
                or ip_info.get("type") == "hosting"),
        webrtc_ip=str(payload.webrtc_ip or "None")[:100],
        time_on_page=time_ms,
        clicks=int(events.get("clicks", 0) or 0),
        scrolls=int(events.get("scrolls", 0) or 0),
        latitude=float(ip_info.get("lat", 0.0) or 0.0),
        longitude=float(ip_info.get("lon", 0.0) or 0.0),
        data_quality=dq,
        is_honeypot_triggered=bool(payload.honeypot_triggered),
        clock_drift_ms=int(payload.clock_drift_ms or 0),
        consent_state=str(payload.consent_state or "unknown")[:20],
        first_30s=payload.first_30s if payload.first_30s else None,
        milestones=payload.milestones if payload.milestones else None,
        behavioral=behavior if behavior else None,
        ad_events=payload.ad_events if payload.ad_events else None,
        full_payload=payload.model_dump() if hasattr(payload, "model_dump") else None,
    )
    db.add(visit)
    db.commit()
    db.refresh(visit)

    session.visit_id = visit.id
    session.verdict = visit.verdict
    session.score = visit.score
    session.ended_at = datetime.utcnow()
    session.data_quality = dq
    session.total_time_ms = time_ms
    db.commit()

    if session.site_id:
        stats_cache.invalidate(f"stats:site:{session.site_id}")
    if session.user_id:
        stats_cache.invalidate(f"stats:user:{session.user_id}:all")
    zone_evidence_cache.invalidate_prefix("zone_ev:")

    return {
        "ok": True,
        "visit_id": visit.id,
        "verdict": visit.verdict,
        "score": visit.score,
        "duplicate": False,
      }
