"""
routers/collector_v3.py — Collector v3 (PopAds macros capture).
"""
import json
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from sqlalchemy import func, distinct
from sqlalchemy.orm import Session
from config import COLLECTOR_V3_ENABLED, MAX_SESSIONS_PER_IP_HOUR
from database import get_db, SessionLocal
from models import SessionModel, VisitHeartbeatModel, VisitModel, CampaignModel
from schemas import HandshakePayload, HeartbeatPayload, FinalPayload
from utils import get_client_ip, handshake_limiter, heartbeat_limiter, final_limiter, stats_cache
from analysis import get_ip_info, parse_ua, extract_zone_id
from collector.filter_engine import evaluate_visit
from helpers import extract_zone_id_from_url

router = APIRouter()

def _validate_session_id(session_id: str) -> str:
    s = (session_id or "").strip()
    if not s or len(s) < 8 or len(s) > 64: raise HTTPException(400, "session_id غير صالح")
    return s

def _resolve_campaign(campaign_key: str, db: Session):
    if not campaign_key: return None
    return db.query(CampaignModel).filter(CampaignModel.campaign_key == campaign_key).first()

def _compute_fp_hash(fp: dict) -> str:
    import hashlib
    parts = [str(fp.get("canvas_hash") or ""), str(fp.get("timezone") or ""), str(fp.get("language") or ""), str(fp.get("hardwareConcurrency") or ""), str(fp.get("deviceMemory") or ""), str((fp.get("webgl") or {}).get("renderer") or "")]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

def _check_flood(ip: str, db: Session):
    cutoff = datetime.utcnow() - timedelta(hours=1)
    if db.query(SessionModel).filter(SessionModel.ip == ip, SessionModel.started_at >= cutoff).count() >= MAX_SESSIONS_PER_IP_HOUR:
        raise HTTPException(429, "محاولات كتير")

def _parse_macros(tp: dict) -> dict:
    if not isinstance(tp, dict): return {}
    try: bid = float(tp.get("bid") or 0)
    except (ValueError, TypeError): bid = 0.0
    try: quality = int(tp.get("quality") or 0)
    except (ValueError, TypeError): quality = None
    adblock_raw = str(tp.get("adblock") or "0")
    return {
        "bid": bid,
        "impression_id": str(tp.get("impid") or tp.get("impressionid") or "")[:100] or None,
        "website_id": str(tp.get("websiteid") or tp.get("website_id") or "")[:100] or None,
        "quality": quality,
        "adblock": adblock_raw in ("1", "true", "True"),
        "raw": tp,
    }

@router.post("/collect/handshake")
async def collect_handshake(payload: HandshakePayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Collector disabled")
    client_ip = get_client_ip(request); handshake_limiter.check(client_ip)
    session_id = _validate_session_id(payload.session_id)

    existing = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if existing: return {"ok": True, "session_id": existing.session_id, "server_time": int(datetime.utcnow().timestamp() * 1000), "duplicate": True, "hide": False}

    campaign = _resolve_campaign(payload.campaign_key, db)
    if not campaign: raise HTTPException(400, "invalid_campaign_key")
    _check_flood(client_ip, db)

    try: ip_info = await get_ip_info(client_ip)
    except Exception: ip_info = {}
    if not isinstance(ip_info, dict): ip_info = {}

    ua = str((payload.nav or {}).get("ua") or "")
    cc = str(ip_info.get("country_code") or "").upper().strip()

    prelim_data = {
        "nav": payload.nav, "fingerprint": payload.fp, "behavior": {}, "screen": {},
        "_headers": {str(k).lower(): str(v) for k, v in request.headers.items()},
        "_http_version": str(request.scope.get("http_version", "1.1")),
        "_data_quality": "partial", "_heartbeat_count": 0, "_session_duration_ms": 0
    }
    prelim_result = evaluate_visit(prelim_data, ip_info)
    
    macros = _parse_macros(payload.tracking_params or {})

    session = SessionModel(
        session_id=session_id, user_id=campaign.user_id, campaign_id=campaign.id,
        ip=client_ip, country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
        user_agent=ua[:500], url=str(payload.url or "")[:2000],
        started_at=datetime.utcnow(), data_quality="pending", clock_drift_ms=0,
        consent_state=str(payload.consent_state or "unknown")[:20],
        visitor_fp_hash=_compute_fp_hash(payload.fp or {}),
        meta={"fp_brief": {}, "macros": macros.get("raw")},
    )
    db.add(session); db.commit(); db.refresh(session)

    if prelim_result["verdict"] == "invalid":
        return {"ok": False, "hide": True, "reason": prelim_result.get("filter_reason"), "duplicate": False}
    return {"ok": True, "session_id": session.session_id, "server_time": int(datetime.utcnow().timestamp() * 1000), "duplicate": False, "hide": False}

@router.post("/collect/heartbeat")
async def collect_heartbeat(payload: HeartbeatPayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Collector disabled")
    client_ip = get_client_ip(request); session_id = _validate_session_id(payload.session_id)
    heartbeat_limiter.check(f"{session_id}:{client_ip}")
    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session: raise HTTPException(400, "session غير موجودة")
    existing = db.query(VisitHeartbeatModel).filter(VisitHeartbeatModel.session_id == session_id, VisitHeartbeatModel.seq == payload.seq).first()
    if existing: return {"ok": True, "duplicate": True}
    hb = VisitHeartbeatModel(session_id=session_id, seq=payload.seq, received_at=datetime.utcnow(), t_ms=max(0, int(payload.t_ms)), clicks=max(0, int(payload.clicks)), scrolls=max(0, int(payload.scrolls)), mousemoves=max(0, int(payload.mousemoves)), keydowns=max(0, int(payload.keydowns)), is_visible=bool(payload.is_visible), is_focused=bool(payload.is_focused))
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
        if not session or session.visit_id: return
        payload = FinalPayload(**payload_dict)
        ua = str((payload.nav or {}).get("ua") or "")
        try: os_name, device, browser = parse_ua(ua)
        except Exception: os_name, device, browser = "Unknown", "Unknown", "Unknown"
        zone_id = extract_zone_id(payload.url or "")
        if not zone_id or zone_id == "unknown":
            c = db.query(CampaignModel).get(session.campaign_id)
            if c and c.destination_zone_id: zone_id = str(c.destination_zone_id).strip()[:100]
        if not zone_id: zone_id = "unknown"
        try: ip_info = __import__('asyncio').run(get_ip_info(client_ip))
        except Exception: ip_info = {"country": "Unknown", "country_code": session.country_code, "isp": "Unknown", "asn": "", "security": {}}
        
        recent_fp_count = 0; same_ip_last_minute = 0; same_canvas_ip_count = 0; same_ip_canvas_count = 0
        try:
            cutoff_1m = datetime.utcnow() - timedelta(minutes=1); cutoff_1h = datetime.utcnow() - timedelta(hours=1)
            same_ip_last_minute = db.query(VisitModel).filter(VisitModel.ip == client_ip, VisitModel.timestamp > cutoff_1m).count()
            canvas_raw = str((payload.fingerprint or {}).get("canvas_hash") or "")
            if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
                recent_fp_count = db.query(VisitModel).filter(VisitModel.canvas_hash == canvas_raw[:15] + "...", VisitModel.timestamp > cutoff_1m).count()
                same_canvas_ip_count = int(db.query(func.count(distinct(VisitModel.ip))).filter(VisitModel.canvas_hash == canvas_raw[:15] + "...", VisitModel.timestamp > cutoff_1h).scalar() or 0)
        except Exception: pass
        heartbeats = db.query(VisitHeartbeatModel).filter(VisitHeartbeatModel.session_id == session_id).order_by(VisitHeartbeatModel.seq.asc()).all()
        heartbeats_list = [{"seq": hb.seq, "t_ms": hb.t_ms, "clicks": hb.clicks, "scrolls": hb.scrolls, "mousemoves": hb.mousemoves, "keydowns": hb.keydowns} for hb in heartbeats]
        time_ms = max(int(payload.t_ms or 0), session.total_time_ms or 0)
        data = {
            "nav": payload.nav or {}, "fingerprint": payload.fingerprint or {}, "behavior": payload.behavior or {}, "screen": payload.screen or {},
            "client_ip": client_ip, "_recent_fp_count": recent_fp_count, "_same_ip_last_minute": same_ip_last_minute,
            "_same_canvas_ip_count": same_canvas_ip_count, "_same_ip_canvas_count": same_ip_canvas_count,
            "_heartbeat_count": session.total_heartbeats or 0, "_session_duration_ms": time_ms,
            "_first_30s": {}, "_milestones": {}, "_ad_events": [], "_clock_drift_ms": 0, "_honeypot_triggered": bool(payload.honeypot_triggered),
            "_data_quality": payload.data_quality or "full", "_headers": headers_dict, "_http_version": http_version,
            "_heartbeats_list": heartbeats_list, "_fp_hash": session.visitor_fp_hash,
        }
        try: result = evaluate_visit(data, ip_info)
        except Exception: result = {"score": 50, "verdict": "suspicious", "evidence": [], "filter_reason": "ENGINE_ERROR"}

        macros = _parse_macros(payload.tracking_params or {})
        fp = payload.fingerprint or {}; events = payload.behavior.get("events") if payload.behavior else {}
        cc = str(ip_info.get("country_code") or "").upper().strip()

        visit = VisitModel(
            campaign_id=session.campaign_id, session_id=session_id, timestamp=datetime.utcnow(),
            ip=client_ip, user_agent=ua, zone_id=zone_id, click_id=payload.click_id or None, filter_reason=result.get("filter_reason"),
            bid=macros.get("bid", 0.0),
            popads_impression_id=macros.get("impression_id"),
            popads_website_id=macros.get("website_id"),
            popads_quality=macros.get("quality"),
            popads_adblock=macros.get("adblock", False),
            popads_data=macros.get("raw"),
            score=result.get("score", 0), verdict=result.get("verdict", "suspicious"), evidence=result.get("evidence", []),
            os=os_name, device=device, browser=browser, country=ip_info.get("country", "Unknown"), country_code=cc[:2] if cc in ("LO", "XX", "") else cc,
            isp=ip_info.get("isp", "Unknown"), timezone=str(fp.get("timezone", "Unknown"))[:50],
            canvas_hash=(str(fp.get("canvas_hash", ""))[:15] + "...") if fp.get("canvas_hash") else "Unknown",
            data_quality=payload.data_quality or "full", time_on_page=time_ms,
            clicks=int((events or {}).get("clicks", 0) or 0), scrolls=int((events or {}).get("scrolls", 0) or 0),
            counting_type="landing"
        )
        try:
            db.add(visit); db.commit(); db.refresh(visit)
            session.visit_id = visit.id; session.verdict = visit.verdict; session.score = visit.score
            session.ended_at = datetime.utcnow(); db.commit()
            if session.user_id: stats_cache.invalidate(f"stats:user:{session.user_id}:all")
        except Exception as e: db.rollback(); print(f"[BG] Failed: {e}")
    except Exception as e: print(f"[BG] Error: {e}")
    finally: db.close()

@router.post("/collect/final")
async def collect_final(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Collector disabled")
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
        if v: return {"ok": True, "visit_id": v.id, "duplicate": True}
    headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    http_version = str(request.scope.get("http_version", "1.1"))
    background_tasks.add_task(_process_final_background, session_id, payload_dict, client_ip, headers_dict, http_version)
    return {"ok": True, "status": "processing", "duplicate": False}
