"""
routers/interstitial.py — Interstitial + Precheck (Phase 1.3 + Fix 2.1)

Fix:
  - Verdict: passed precheck = 'valid' (not 'suspicious')
  - Zone ID: use campaign.destination_zone_id or extract from destination_url
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from config import COLLECTOR_V3_ENABLED
from database import get_db
from models import CampaignModel, SessionModel, VisitModel
from schemas import InterstitialPrecheckPayload, InterstitialLogPayload
from utils import get_client_ip, handshake_limiter, safe_origin
from collector.precheck import quick_precheck
from collector.interstitial_template import INTERSTITIAL_HTML
from analysis import parse_ua, extract_zone_id
from helpers import extract_zone_id_from_url

router = APIRouter()


@router.get("/go/{campaign_key}", response_class=HTMLResponse)
async def serve_interstitial(campaign_key: str, request: Request,
                             db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Not Found")

    c = db.query(CampaignModel).filter(
        CampaignModel.campaign_key == campaign_key,
    ).first()

    if not c:
        raise HTTPException(404, "Not Found")

    if c.status != "active":
        blank = """<!DOCTYPE html><html><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Unavailable</title>
        <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;
        justify-content:center;height:100vh;margin:0;background:#f8f9fa;color:#6c757d;font-size:14px}
        </style></head><body>This page is temporarily unavailable.</body></html>"""
        return HTMLResponse(content=blank, status_code=200)

    if c.type == "landing":
        raise HTTPException(404, "Not Found")

    if not c.destination_url or len(c.destination_url) < 10:
        raise HTTPException(404, "Not Found")

    origin = safe_origin(request)

    html = (
        INTERSTITIAL_HTML
        .replace("__CAMPAIGN_KEY__", c.campaign_key)
        .replace("__DEST_URL__", c.destination_url)
        .replace("__PRECHECK_URL__", f"{origin}/api/interstitial/precheck")
        .replace("__LOG_URL__", f"{origin}/api/interstitial/log")
    )

    return HTMLResponse(
        content=html,
        status_code=200,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "X-Robots-Tag": "noindex, nofollow",
        },
    )


@router.post("/api/interstitial/precheck")
async def precheck(
    payload: InterstitialPrecheckPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Not Found")

    client_ip = get_client_ip(request)
    try:
        handshake_limiter.check(f"isc:{client_ip}")
    except HTTPException:
        return {
            "action": "redirect",
            "url": None,
            "score": 0,
            "reasons": ["RATE_LIMITED"],
        }

    session_id = (payload.session_id or "").strip()
    if not session_id or len(session_id) < 8 or len(session_id) > 64:
        raise HTTPException(400, "session_id غير صالح")

    c = db.query(CampaignModel).filter(
        CampaignModel.campaign_key == payload.campaign_key,
    ).first()
    if not c:
        raise HTTPException(404, "campaign not found")

    if c.status != "active":
        return {
            "action": "block",
            "url": None,
            "score": 100,
            "reasons": ["CAMPAIGN_PAUSED"],
        }

    result = quick_precheck(
        nav=payload.nav or {},
        fp=payload.fp or {},
        threshold=int(c.bot_block_threshold or 100),
    )

    try:
        _save_precheck(db, c, session_id, client_ip, payload, result)
    except Exception as e:
        print(f"[INTERSTITIAL] save failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass

    if result["action"] == "block":
        return {
            "action": "block",
            "url": None,
            "score": result["score"],
            "reasons": result["reasons"],
        }
    return {
        "action": "redirect",
        "url": c.destination_url,
        "score": result["score"],
        "reasons": result["reasons"],
    }


@router.post("/api/interstitial/log")
async def log_interstitial(
    payload: InterstitialLogPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        s = db.query(SessionModel).filter(
            SessionModel.session_id == payload.session_id
        ).first()
        if not s:
            return {"ok": True}

        if not s.meta:
            s.meta = {}
        try:
            m = dict(s.meta) if isinstance(s.meta, dict) else {}
        except Exception:
            m = {}

        m["interstitial_decision"] = payload.decision
        m["interstitial_score"] = payload.score
        m["interstitial_reasons"] = payload.reasons[:10]
        m["interstitial_at"] = datetime.utcnow().isoformat()
        s.meta = m
        db.commit()
    except Exception as e:
        print(f"[INTERSTITIAL_LOG] failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass

    return {"ok": True}


def _save_precheck(db, campaign, session_id, client_ip, payload, result):
    """Save session + visit. Zone id from campaign (reliable)."""
    existing = db.query(SessionModel).filter(
        SessionModel.session_id == session_id,
    ).first()
    if existing:
        return

    ua = str((payload.nav or {}).get("ua") or "")
    try:
        os_name, device, browser = parse_ua(ua)
    except Exception:
        os_name, device, browser = "Unknown", "Unknown", "Unknown"

    # zone_id from campaign.destination_zone_id (most reliable)
    zone_id = ""
    if campaign.destination_zone_id:
        zone_id = str(campaign.destination_zone_id).strip()[:100]
    if not zone_id and campaign.destination_url:
        zone_id = extract_zone_id_from_url(campaign.destination_url)
    if not zone_id:
        zone_id = extract_zone_id(payload.url or "")

    # Verdict: blocked → invalid, passed → valid
    is_blocked = (result["action"] == "block")
    verdict = "invalid" if is_blocked else "valid"
    score = 100 if is_blocked else 0

    evidence = []
    for reason in result["reasons"]:
        evidence.append({
            "code": reason,
            "severity": "critical" if is_blocked else "medium",
            "score": 100 if is_blocked else 0,
            "detail": "Interstitial precheck",
        })

    session = SessionModel(
        session_id=session_id,
        campaign_id=campaign.id,
        user_id=campaign.user_id,
        site_id=campaign.site_id,
        ip=client_ip,
        user_agent=ua[:500],
        url=(payload.url or "")[:2000],
        started_at=datetime.utcnow(),
        data_quality="partial",
        consent_state="unknown",
        meta={
            "interstitial": True,
            "precheck_score": result["score"],
            "precheck_reasons": result["reasons"][:10],
            "precheck_threshold": result["threshold"],
        },
    )
    db.add(session)

    visit = VisitModel(
        site_id=campaign.site_id,
        campaign_id=campaign.id,
        session_id=session_id,
        timestamp=datetime.utcnow(),
        ip=client_ip,
        user_agent=ua,
        zone_id=zone_id or "unknown",
        score=score,
        verdict=verdict,
        evidence=evidence,
        os=os_name,
        device=device,
        browser=browser,
        country="Unknown",
        country_code=None,
        isp="Unknown",
        asn="",
        is_vpn=False,
        connection_type="unknown",
        latitude=0.0,
        longitude=0.0,
        data_quality="partial",
        is_honeypot_triggered=False,
        full_payload={
            "type": "interstitial",
            "precheck_score": result["score"],
            "precheck_reasons": result["reasons"],
            "nav_brief": {
                "ua_len": len(ua),
                "webdriver": (payload.nav or {}).get("webdriver"),
                "language": (payload.nav or {}).get("language"),
            },
        },
    )
    db.add(visit)
    db.commit()
    db.refresh(visit)

    session.visit_id = visit.id
    session.verdict = visit.verdict
    session.score = visit.score
    session.ended_at = datetime.utcnow()
    session.data_quality = "partial"
    db.commit()
