"""
routers/interstitial.py — Interstitial Precheck (Direct Links + Macros).
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from config import COLLECTOR_V3_ENABLED
from database import get_db
from models import CampaignModel, SessionModel, VisitModel
from schemas import InterstitialPrecheckPayload
from utils import get_client_ip, handshake_limiter, safe_origin, stats_cache
from collector.precheck import quick_precheck
from collector.interstitial_template import INTERSTITIAL_HTML
from collector.header_analyzer import analyze_headers
from helpers import extract_zone_id_from_url

router = APIRouter()

def _parse_macros(tp: dict) -> dict:
    """Parse PopAds tracking params."""
    if not isinstance(tp, dict): return {}
    try:
        bid = float(tp.get("bid") or 0)
    except (ValueError, TypeError):
        bid = 0.0
    try:
        quality = int(tp.get("quality") or 0)
    except (ValueError, TypeError):
        quality = None
    adblock_raw = str(tp.get("adblock") or "0")
    return {
        "bid": bid,
        "impression_id": str(tp.get("impid") or tp.get("impressionid") or "")[:100] or None,
        "website_id": str(tp.get("websiteid") or tp.get("website_id") or "")[:100] or None,
        "quality": quality,
        "adblock": adblock_raw in ("1", "true", "True"),
        "raw": tp,
    }

@router.get("/go/{campaign_key}", response_class=HTMLResponse)
async def serve_interstitial(campaign_key: str, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Not Found")
    c = db.query(CampaignModel).filter(CampaignModel.campaign_key == campaign_key).first()
    if not c or c.status != "active" or not c.destination_url:
        return HTMLResponse("<html><body>Not Found</body></html>", status_code=404)
    origin = safe_origin(request)
    html = INTERSTITIAL_HTML.replace("__CAMPAIGN_KEY__", c.campaign_key).replace("__DEST_URL__", c.destination_url).replace("__PRECHECK_URL__", f"{origin}/api/interstitial/precheck")
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store"})

@router.post("/api/interstitial/precheck")
async def precheck(payload: InterstitialPrecheckPayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED: raise HTTPException(404, "Not Found")
    client_ip = get_client_ip(request)
    try: handshake_limiter.check(f"isc:{client_ip}")
    except HTTPException: return {"action": "redirect", "url": None, "score": 0, "reasons": ["RATE_LIMITED"]}

    c = db.query(CampaignModel).filter(CampaignModel.campaign_key == payload.campaign_key).first()
    if not c or c.status != "active": return {"action": "block", "url": None, "score": 100, "reasons": ["CAMPAIGN_INACTIVE"]}

    result = quick_precheck(nav=payload.nav or {}, fp=payload.fp or {}, threshold=int(c.bot_block_threshold or 100))
    headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    http_version = str(request.scope.get("http_version", "1.1"))
    ua = str((payload.nav or {}).get("ua") or "")
    extra_score = 0; extra_reasons = []
    try:
        for sig in analyze_headers(headers_dict, ua, http_version):
            extra_score += int(sig.get("score", 0) or 0); extra_reasons.append(sig.get("code"))
    except Exception: pass

    total_score = min(150, result["score"] + extra_score)
    should_block = total_score >= int(c.bot_block_threshold or 100) or result["action"] == "block"
    is_blocked = should_block

    # 🔴 Parse PopAds macros
    macros = _parse_macros(payload.tracking_params or {})

    existing = db.query(SessionModel).filter(SessionModel.session_id == payload.session_id).first()
    if not existing:
        zone_id = c.destination_zone_id or extract_zone_id_from_url(c.destination_url) or "unknown"
        verdict = "invalid" if is_blocked else "valid"
        score = 100 if is_blocked else 0
        visit = VisitModel(
            campaign_id=c.id, session_id=payload.session_id, timestamp=datetime.utcnow(),
            ip=client_ip, user_agent=ua, zone_id=zone_id,
            bid=macros.get("bid", 0.0),
            popads_impression_id=macros.get("impression_id"),
            popads_website_id=macros.get("website_id"),
            popads_quality=macros.get("quality"),
            popads_adblock=macros.get("adblock", False),
            popads_data=macros.get("raw"),
            score=score, verdict=verdict,
            evidence=[{"code": "INTERSTITIAL_PRECHECK", "severity": "critical" if is_blocked else "low", "score": score, "detail": "Direct Link"}],
            country=str(payload.nav.get("country") or "Unknown")[:100] if payload.nav else "Unknown",
            data_quality="partial", filter_reason="INTERSTITIAL_BLOCK" if is_blocked else None,
            counting_type="direct_link"
        )
        db.add(visit)
        session = SessionModel(
            session_id=payload.session_id, campaign_id=c.id, user_id=c.user_id,
            ip=client_ip, user_agent=ua[:500], started_at=datetime.utcnow(),
            data_quality="partial", verdict=verdict, score=score,
            meta={"direct_link": True, "precheck_score": total_score, "macros": macros.get("raw")}
        )
        db.add(session)
        db.commit()
        db.refresh(visit)
        session.visit_id = visit.id
        session.ended_at = datetime.utcnow()
        db.commit()
        if c.user_id: stats_cache.invalidate(f"stats:user:{c.user_id}:all")

    if is_blocked:
        return {"action": "block", "url": None, "score": total_score, "reasons": (result["reasons"] + extra_reasons)}
    return {"action": "redirect", "url": c.destination_url, "score": total_score, "reasons": []}
