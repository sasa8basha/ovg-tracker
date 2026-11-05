"""
routers/interstitial.py — Interstitial + Precheck (Phase 1.3)

Routes:
  GET  /go/{campaign_key}          → interstitial HTML
  POST /api/interstitial/precheck  → fast decision + save session/visit
  POST /api/interstitial/log       → final log (decision made)

الفكرة:
  1. الزائر يدخل /go/{key}
  2. الصفحة تجمع بصمة سريعة (<100ms)
  3. POST precheck → تحليل سريع + حفظ session + visit
  4. Response: redirect URL أو block
  5. JS يعمل redirect أو يفضل ثابت
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
from collector.constants import CODE_TO_SOURCE
from analysis import get_ip_info, parse_ua

router = APIRouter()


# =========================================================
# 1) Serve interstitial page
# =========================================================
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

    # لو الحملة مش نشطة → serve بلانك (مفيش redirect)
    if c.status != "active":
        blank = """<!DOCTYPE html><html><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Unavailable</title>
        <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;
        justify-content:center;height:100vh;margin:0;background:#f8f9fa;color:#6c757d;font-size:14px}
        </style></head><body>This page is temporarily unavailable.</body></html>"""
        return HTMLResponse(content=blank, status_code=200)

    # لو direct/hybrid بس — landing pages عندها tracker code عادي
    if c.type == "landing":
        raise HTTPException(404, "Not Found")

    # لو مفيش destination_url → مش valid direct
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


# =========================================================
# 2) Precheck — fast decision
# =========================================================
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
        # rate limit hit — redirect عشان ما نخسرش الزيارة
        return {
            "action": "redirect",
            "url": None,
            "score": 0,
            "reasons": ["RATE_LIMITED"],
        }

    # Validate session id
    session_id = (payload.session_id or "").strip()
    if not session_id or len(session_id) < 8 or len(session_id) > 64:
        raise HTTPException(400, "session_id غير صالح")

    # Lookup campaign
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

    # Run fast precheck
    result = quick_precheck(
        nav=payload.nav or {},
        fp=payload.fp or {},
        threshold=int(c.bot_block_threshold or 100),
    )

    # Save session + visit (don't block response on failure)
    try:
        _save_precheck(db, c, session_id, client_ip, payload, result)
    except Exception as e:
        print(f"[INTERSTITIAL] save failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass

    # Build response
    if result["action"] == "block":
        return {
            "action": "block",
            "url": None,
            "score": result["score"],
            "reasons": result["reasons"],
        }
    else:
        return {
            "action": "redirect",
            "url": c.destination_url,
            "score": result["score"],
            "reasons": result["reasons"],
        }


# =========================================================
# 3) Log — decision was made, log it
# =========================================================
@router.post("/api/interstitial/log")
async def log_interstitial(
    payload: InterstitialLogPayload,
    request: Request,
    db: Session = Depends(get_db),
):
    """Logs the decision for audit. Fire-and-forget — no strict validation."""
    try:
        s = db.query(SessionModel).filter(
            SessionModel.session_id == payload.session_id
        ).first()
        if not s:
            return {"ok": True}

        # Update session with decision (if not already set)
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


# =========================================================
# HELPERS
# =========================================================
def _save_precheck(db, campaign, session_id, client_ip, payload, result):
    """Save session + minimal visit."""
    # Check if session already exists (idempotent)
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

    # Sync geo — best effort (may return Unknown quickly)
    country = "Unknown"
    country_code = None
    isp = "Unknown"
    asn = ""
    is_vpn = False
    connection_type = "unknown"
    lat = lon = 0.0

    # (best-effort — لا ننتظر الـ geo لو بطئ)
    try:
        # We DON'T await this to keep precheck fast (< 100ms).
        # Skip geo for now — can be filled by later analysis.
        pass
    except Exception:
        pass

    # Save session
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

    # Save visit (minimal, immediate)
    verdict = "invalid" if result["action"] == "block" else "suspicious"
    # "suspicious" مش "valid" — عشان البيانات ناقصة (interstitial)
    # التحليل الكامل ممكن يغيرها لو جالها final
    score = result["score"] if result["action"] == "block" else 25

    evidence = []
    for reason in result["reasons"]:
        evidence.append({
            "code": reason,
            "severity": "critical" if result["action"] == "block" else "medium",
            "score": 100 if result["action"] == "block" else 0,
            "detail": "Interstitial precheck",
        })

    visit = VisitModel(
        site_id=campaign.site_id,
        campaign_id=campaign.id,
        session_id=session_id,
        timestamp=datetime.utcnow(),
        ip=client_ip,
        user_agent=ua,
        zone_id=campaign.destination_zone_id or "unknown",
        score=score,
        verdict=verdict,
        evidence=evidence,
        os=os_name,
        device=device,
        browser=browser,
        country=country,
        country_code=country_code,
        isp=isp,
        asn=asn,
        is_vpn=is_vpn,
        connection_type=connection_type,
        latitude=lat,
        longitude=lon,
        data_quality="partial",
        is_honeypot_triggered=("HONEYPOT_CLICK" in result["reasons"]
                               or "HONEYPOT_FORM_FILL" in result["reasons"]),
        first_30s=None,
        milestones=None,
        behavioral=None,
        ad_events=None,
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

    # Link visit to session
    session.visit_id = visit.id
    session.verdict = visit.verdict
    session.score = visit.score
    session.ended_at = datetime.utcnow()
    session.data_quality = "partial"
    db.commit()
