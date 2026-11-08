"""
routers/interstitial.py — Interstitial Precheck (Direct Links + Macros) v4.3

CRITICAL FIXES:
    - Zone extraction: URL params FIRST → campaign default (not the other way)
    - Verdict: computed from precheck score, NOT left as "pending" forever
    - IP velocity: same IP > 10 visits in 10 min → +30 score
    - Fingerprint reuse: same canvas hash > 10 visits in 10 min → +40 score
    - Confidence + bot_probability stored on the visit
"""
import asyncio
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func
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


# =========================================================
# PopAds Macros
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
        return {"raw": {}, "known": {}, "bid": 0.0,
                "impression_id": None, "website_id": None,
                "quality": None, "adblock": False, "country": None}

    lowered = {str(k).strip().lower(): v for k, v in tp.items() if v is not None and str(v) != ""}
    known = {}
    for canonical, aliases in MACRO_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                known[canonical] = lowered[alias]
                break

    def _to_float(v):
        try: return float(v)
        except (ValueError, TypeError): return 0.0

    def _to_int(v):
        try: return int(float(v))
        except (ValueError, TypeError): return None

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
# Zone extraction — URL params FIRST
# =========================================================
def _extract_zone(payload_url: str, tracking_params: dict, campaign) -> tuple:
    """Returns (zone_id, source). Priority: tracking_params > url > campaign default."""
    # 1) tracking_params
    try:
        tp = tracking_params or {}
        tp_lower = {str(k).lower().strip(): v for k, v in tp.items() if v}
        for key in ("zoneid", "zone_id", "zone", "z", "zn", "zid"):
            if key in tp_lower and tp_lower[key]:
                val = str(tp_lower[key]).strip()[:100]
                if val:
                    return val, "tracking_params"
    except Exception:
        pass

    # 2) URL query/path
    try:
        _z = extract_zone_id_from_url(payload_url or "")
        if _z:
            return _z, "url"
    except Exception:
        pass

    # 3) Campaign default (last resort)
    try:
        if campaign is not None and campaign.destination_zone_id:
            val = str(campaign.destination_zone_id).strip()[:100]
            if val:
                return val, "campaign_default"
    except Exception:
        pass

    return "unknown", "none"


# =========================================================
# Cross-visit signals
# =========================================================
def _compute_cross_visit_signals(db: Session, client_ip: str, canvas_hash: str) -> dict:
    """Count recent visits by IP and by canvas hash."""
    cutoff_10m = datetime.utcnow() - timedelta(minutes=10)

    ip_visits = 0
    try:
        ip_visits = db.query(func.count(VisitModel.id)).filter(
            VisitModel.ip == client_ip,
            VisitModel.timestamp > cutoff_10m,
        ).scalar() or 0
    except Exception:
        pass

    fp_visits = 0
    if canvas_hash and len(canvas_hash) >= 15:
        canvas_key = canvas_hash[:15] + "..."
        try:
            fp_visits = db.query(func.count(VisitModel.id)).filter(
                VisitModel.canvas_hash == canvas_key,
                VisitModel.timestamp > cutoff_10m,
            ).scalar() or 0
        except Exception:
            pass

    return {
        "ip_visits_10m": int(ip_visits),
        "fp_visits_10m": int(fp_visits),
    }


# =========================================================
# INTERSTITIAL PAGE
# =========================================================
@router.get("/go/{campaign_key}", response_class=HTMLResponse)
async def serve_interstitial(campaign_key: str, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Not Found")
    c = db.query(CampaignModel).filter(CampaignModel.campaign_key == campaign_key).first()
    if not c or c.status != "active" or not c.destination_url:
        return HTMLResponse("<html><body>Not Found</body></html>", status_code=404)
    origin = safe_origin(request)
    html = INTERSTITIAL_HTML.replace("__CAMPAIGN_KEY__", c.campaign_key)\
                            .replace("__DEST_URL__", c.destination_url)\
                            .replace("__PRECHECK_URL__", f"{origin}/api/interstitial/precheck")
    return HTMLResponse(content=html, headers={"Cache-Control": "no-store"})


# =========================================================
# PRECHECK — now returns a REAL verdict, not pending
# =========================================================
@router.post("/api/interstitial/precheck")
async def precheck(payload: InterstitialPrecheckPayload, request: Request, db: Session = Depends(get_db)):
    if not COLLECTOR_V3_ENABLED:
        raise HTTPException(404, "Not Found")
    client_ip = get_client_ip(request)
    try:
        handshake_limiter.check(f"isc:{client_ip}")
    except HTTPException:
        return {"action": "redirect", "url": None, "score": 0, "reasons": ["RATE_LIMITED"]}

    c = db.query(CampaignModel).filter(CampaignModel.campaign_key == payload.campaign_key).first()
    if not c or c.status != "active":
        return {"action": "block", "url": None, "score": 100, "reasons": ["CAMPAIGN_INACTIVE"]}

    # ---- Base precheck ----
    result = quick_precheck(nav=payload.nav or {}, fp=payload.fp or {}, threshold=int(c.bot_block_threshold or 100))

    headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    http_version = str(request.scope.get("http_version", "1.1"))
    ua = str((payload.nav or {}).get("ua") or "")

    # ---- Header signals ----
    extra_score = 0
    extra_reasons = []
    try:
        for sig in analyze_headers(headers_dict, ua, http_version):
            extra_score += int(sig.get("score", 0) or 0)
            extra_reasons.append(sig.get("code"))
    except Exception:
        pass

    # ---- Cross-visit signals (IP velocity + FP reuse) ----
    canvas_raw = str((payload.fp or {}).get("canvas_hash", "") or "")
    cross = _compute_cross_visit_signals(db, client_ip, canvas_raw)

    velocity_score = 0
    velocity_reasons = []

    if cross["ip_visits_10m"] >= 20:
        velocity_score += 40
        velocity_reasons.append(f"IP_VELOCITY_EXTREME({cross['ip_visits_10m']})")
    elif cross["ip_visits_10m"] >= 10:
        velocity_score += 25
        velocity_reasons.append(f"IP_VELOCITY_HIGH({cross['ip_visits_10m']})")
    elif cross["ip_visits_10m"] >= 5:
        velocity_score += 10
        velocity_reasons.append(f"IP_VELOCITY_MED({cross['ip_visits_10m']})")

    if cross["fp_visits_10m"] >= 30:
        velocity_score += 45
        velocity_reasons.append(f"FP_REUSE_EXTREME({cross['fp_visits_10m']})")
    elif cross["fp_visits_10m"] >= 15:
        velocity_score += 30
        velocity_reasons.append(f"FP_REUSE_HIGH({cross['fp_visits_10m']})")
    elif cross["fp_visits_10m"] >= 7:
        velocity_score += 15
        velocity_reasons.append(f"FP_REUSE_MED({cross['fp_visits_10m']})")

    # ---- Total score ----
    total_score = min(150, int(result["score"]) + int(extra_score) + int(velocity_score))

    threshold = int(c.bot_block_threshold or 100)
    is_blocked = total_score >= threshold or result["action"] == "block"

    # ---- Zone ----
    zone_id, zone_source = _extract_zone(payload.url or "", payload.tracking_params or {}, c)
    print(f"[INTERSTITIAL] url={payload.url!r} zone={zone_id!r} ({zone_source}) score={total_score} ip_visits={cross['ip_visits_10m']} fp_visits={cross['fp_visits_10m']}", flush=True)

    # ---- Verdict: computed, NOT pending ----
    if is_blocked:
        verdict = "invalid"
        confidence = 0.90
        bot_probability = min(1.0, total_score / 100.0)
        reason = "interstitial_precheck_block"
        filter_reason = "INTERSTITIAL_BLOCK"
    elif total_score >= 40:
        verdict = "suspicious"
        confidence = 0.60
        bot_probability = min(1.0, total_score / 100.0)
        reason = "interstitial_precheck_suspicious"
        filter_reason = None
    else:
        verdict = "valid"
        confidence = 0.70
        bot_probability = max(0.0, total_score / 100.0)
        reason = "interstitial_precheck_clean"
        filter_reason = None

    # ---- Save visit ----
    macros = _extract_macros(payload.tracking_params or {})
    existing_session = db.query(SessionModel).filter(SessionModel.session_id == payload.session_id).first()

    if not existing_session:
        click_id = payload.session_id

        evidence_list = [{
            "code": "INTERSTITIAL_PRECHECK",
            "severity": "critical" if is_blocked else ("high" if verdict == "suspicious" else "low"),
            "score": total_score,
            "detail": f"Direct link · precheck={result['score']} header={extra_score} velocity={velocity_score}",
        }]
        for code in (result.get("reasons") or []):
            evidence_list.append({"code": code, "severity": "critical", "score": 100, "detail": "precheck"})
        for code in extra_reasons:
            evidence_list.append({"code": code, "severity": "high", "score": 60, "detail": "header"})
        for code in velocity_reasons:
            evidence_list.append({"code": code, "severity": "high", "score": 40, "detail": "cross_visit"})

        visit = VisitModel(
            campaign_id=c.id,
            session_id=payload.session_id,
            click_id=click_id,
            timestamp=datetime.utcnow(),
            ip=client_ip,
            user_agent=ua,
            zone_id=zone_id,
            bid=macros.get("bid", 0.0),
            popads_impression_id=macros.get("impression_id"),
            popads_website_id=macros.get("website_id"),
            popads_quality=macros.get("quality"),
            popads_adblock=macros.get("adblock", False),
            popads_data=macros.get("raw"),
            score=total_score,
            verdict=verdict,
            confidence=confidence,
            bot_probability=bot_probability,
            mode="direct",
            reason=reason,
            evidence=evidence_list,
            filter_reason=filter_reason,
            country=macros.get("country") or "Unknown",
            data_quality="partial",
            counting_type="direct_link",
            canvas_hash=(canvas_raw[:15] + "...") if canvas_raw else "Unknown",
        )
        db.add(visit)

        session = SessionModel(
            session_id=payload.session_id,
            campaign_id=c.id,
            user_id=c.user_id,
            ip=client_ip,
            user_agent=ua[:500],
            started_at=datetime.utcnow(),
            data_quality="partial",
            verdict=verdict,
            score=total_score,
            confidence=confidence,
            bot_probability=bot_probability,
            meta={
                "direct_link": True,
                "precheck_score": int(result["score"]),
                "header_score": int(extra_score),
                "velocity_score": int(velocity_score),
                "ip_visits_10m": cross["ip_visits_10m"],
                "fp_visits_10m": cross["fp_visits_10m"],
                "macros": macros.get("raw"),
                "click_id": click_id,
                "zone_source": zone_source,
            },
        )
        db.add(session)
        db.commit()
        db.refresh(visit)

        session.visit_id = visit.id
        session.ended_at = datetime.utcnow()
        db.commit()

        if c.user_id:
            stats_cache.invalidate(f"stats:user:{c.user_id}:all")
            stats_cache.invalidate(f"stats:campaign:{c.id}")

    if is_blocked:
        return {"action": "block", "url": None, "score": total_score,
                "reasons": (result["reasons"] or []) + extra_reasons + velocity_reasons}

    return {"action": "redirect", "url": c.destination_url, "score": total_score, "reasons": []}