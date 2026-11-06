"""
routers/interstitial.py — Interstitial + Precheck (Direct Link Visit Logging)
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from config import COLLECTOR_V3_ENABLED
from database import get_db
from models import CampaignModel, SessionModel, VisitModel
from schemas import InterstitialPrecheckPayload, InterstitialLogPayload
from utils import get_client_ip, handshake_limiter, safe_origin, stats_cache
from collector.precheck import quick_precheck
from collector.interstitial_template import INTERSTITIAL_HTML
from collector.header_analyzer import analyze_headers
from collector.fingerprint_cache import get_strikes as fp_get_strikes
from analysis import parse_ua
from helpers import extract_zone_id_from_url

router = APIRouter()

def _compute_fp_hash(nav, fp):
    import hashlib
    parts = [str((fp or {}).get("canvas_hash") or ""), str((fp or {}).get("timezone") or ""), str((nav or {}).get("language") or ""), str((fp or {}).get("hardwareConcurrency") or ""), str((fp or {}).get("deviceMemory") or ""), str(((fp or {}).get("webgl") or {}).get("renderer") or "")]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

@router.get("/go/{campaign_key}", response_class=HTMLResponse)
async def serve_interstitial(campaign_key: str, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Not Found")
    c = db.query(CampaignModel).filter(CampaignModel.campaign_key == campaign_key).first()
    if not c or c.status != "active" or c.type == "landing" or not c.destination_url or len(c.destination_url) < 10: raise HTTPException(404, "Not Found")

    origin = safe_origin(request)
    html = INTERSTITIAL_HTML.replace("__CAMPAIGN_KEY__", c.campaign_key).replace("__DEST_URL__", c.destination_url).replace("__PRECHECK_URL__", f"{origin}/api/interstitial/precheck").replace("__LOG_URL__", f"{origin}/api/interstitial/log")
    return HTMLResponse(content=html, status_code=200, headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "X-Robots-Tag": "noindex, nofollow"})

@router.post("/api/interstitial/precheck")
async def precheck(payload: InterstitialPrecheckPayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Not Found")
    client_ip = get_client_ip(request)
    try: handshake_limiter.check(f"isc:{client_ip}")
    except HTTPException: return {"action": "redirect", "url": None, "score": 0, "reasons": ["RATE_LIMITED"]}

    session_id = (payload.session_id or "").strip()
    if not session_id or len(session_id) < 8 or len(session_id) > 64: raise HTTPException(400, "session_id غير صالح")

    c = db.query(CampaignModel).filter(CampaignModel.campaign_key == payload.campaign_key).first()
    if not c: raise HTTPException(404, "campaign not found")
    if c.status != "active": return {"action": "block", "url": None, "score": 100, "reasons": ["CAMPAIGN_PAUSED"]}

    result = quick_precheck(nav=payload.nav or {}, fp=payload.fp or {}, threshold=int(c.bot_block_threshold or 100))
    extra_score = 0; extra_reasons = []

    try: headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    except Exception: headers_dict = {}
    http_version = str(request.scope.get("http_version", "1.1"))
    ua = str((payload.nav or {}).get("ua") or "")
    
    try:
        header_sigs = analyze_headers(headers_dict, ua, http_version)
        for sig in header_sigs: extra_score += int(sig.get("score", 0) or 0); extra_reasons.append(sig.get("code"))
    except Exception as e: print(f"[INTERSTITIAL] header analysis failed: {e}")

    fp_hash = _compute_fp_hash(payload.nav or {}, payload.fp or {})
    try:
        stats = fp_get_strikes(fp_hash)
        strikes = int(stats.get("strikes") or 0)
        if strikes >= 5: extra_score += 85; extra_reasons.append("FINGERPRINT_KNOWN_BAD")
        elif strikes >= 3: extra_score += 55; extra_reasons.append("FINGERPRINT_SUSPICIOUS")
    except Exception as e: print(f"[INTERSTITIAL] cache lookup failed: {e}")

    total_score = min(150, result["score"] + extra_score)
    should_block = total_score >= int(c.bot_block_threshold or 100) or result["action"] == "block"
    final_result = {"action": "block" if should_block else "redirect", "score": total_score, "reasons": (result["reasons"] + extra_reasons)[:15], "threshold": int(c.bot_block_threshold or 100)}

    try:
        existing_session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
        if not existing_session:
            os_name, device, browser = parse_ua(ua) if ua else ("Unknown", "Unknown", "Unknown")
            zone_id = c.destination_zone_id or extract_zone_id_from_url(c.destination_url) or "unknown"
            
            session = SessionModel(
                session_id=session_id, campaign_id=c.id, user_id=c.user_id, site_id=c.site_id,
                ip=client_ip, user_agent=ua[:500], url=(payload.url or "")[:2000], started_at=datetime.utcnow(),
                data_quality="partial", consent_state="unknown", meta={"interstitial": True, "precheck_score": total_score, "precheck_reasons": final_result["reasons"][:10], "precheck_threshold": final_result["threshold"]},
            )
            db.add(session)
            
            # 🔴 Fix: Log the Visit immediately for Direct Links
            is_blocked = final_result["action"] == "block"
            verdict = "invalid" if is_blocked else "valid"
            score = 100 if is_blocked else 0
            
            visit = VisitModel(
                site_id=c.site_id, campaign_id=c.id, session_id=session_id,
                timestamp=datetime.utcnow(), ip=client_ip, user_agent=ua,
                zone_id=zone_id, score=score, verdict=verdict,
                evidence=[{"code": "INTERSTITIAL_PRECHECK", "severity": "critical" if is_blocked else "low", "score": score, "detail": "Direct Link"}],
                os=os_name, device=device, browser=browser,
                country="Unknown", country_code=None, isp="Unknown", asn="",
                data_quality="partial", filter_reason="INTERSTITIAL_BLOCK" if is_blocked else None
            )
            db.add(visit)
            db.commit()
            db.refresh(visit)
            
            session.visit_id = visit.id
            session.verdict = visit.verdict
            session.score = visit.score
            session.ended_at = datetime.utcnow()
            db.commit()
            
            if c.user_id: stats_cache.invalidate(f"stats:user:{c.user_id}:all")
            if c.site_id: stats_cache.invalidate(f"stats:site:{c.site_id}")
            
    except Exception as e:
        print(f"[INTERSTITIAL] save failed: {e}"); db.rollback()

    if final_result["action"] == "block": return {"action": "block", "url": None, "score": final_result["score"], "reasons": final_result["reasons"]}
    return {"action": "redirect", "url": c.destination_url, "score": final_result["score"], "reasons": final_result["reasons"]}

@router.post("/api/interstitial/log")
async def log_interstitial(payload: InterstitialLogPayload, request: Request, db: Session = Depends(get_db)):
    try:
        s = db.query(SessionModel).filter(SessionModel.session_id == payload.session_id).first()
        if not s: return {"ok": True}
        m = dict(s.meta) if isinstance(s.meta, dict) else {}
        m.update({"interstitial_decision": payload.decision, "interstitial_score": payload.score, "interstitial_reasons": payload.reasons[:10], "interstitial_at": datetime.utcnow().isoformat()})
        s.meta = m; db.commit()
    except Exception: db.rollback()
    return {"ok": True}
