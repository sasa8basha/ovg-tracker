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


# =========================================================
# PopAds Macros (from official docs)
# =========================================================
# كل ماكرو ممكن يجي بأكتر من اسم. بنحاول نغطي الكل.
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
    # XML feeds only — بس نستقبلها لو جاية
    "ip":             ("ip",),
    "ipv6":           ("ipv6",),
    "ipv6or4":        ("ipv6or4",),
    "xforwardedfor":  ("xforwardedfor",),
    "useragent":      ("useragent", "ua"),
    "lang":           ("lang",),
    "sec_ch_ua":              ("sec-ch-ua", "secchua"),
    "sec_ch_ua_arch":         ("sec-ch-ua-arch", "secchuaarch"),
    "sec_ch_ua_bitness":      ("sec-ch-ua-bitness", "secchuabitness"),
    "sec_ch_ua_model":        ("sec-ch-ua-model", "secchuamodel"),
    "sec_ch_ua_platform":     ("sec-ch-ua-platform", "secchuaplatform"),
    "sec_ch_ua_platform_ver": ("sec-ch-ua-platform-version", "secchuaplatformversion"),
    "sec_ch_ua_full_version": ("sec-ch-ua-full-version", "secchuafullversion"),
    "sec_ch_ua_mobile":       ("sec-ch-ua-mobile", "secchuamobile"),
}


def _extract_macros(tp: dict) -> dict:
    """
    يستخرج كل الماكروز المعروفة + يحفظ الـ raw (كل حاجة جاية).
    """
    if not isinstance(tp, dict):
        return {"raw": {}, "known": {}}

    # نسخة lowercase من المفاتيح عشان نقدر نقارن بسهولة
    lowered = {str(k).strip().lower(): v for k, v in tp.items() if v is not None and str(v) != ""}

    known = {}
    for canonical, aliases in MACRO_ALIASES.items():
        for alias in aliases:
            if alias in lowered:
                known[canonical] = lowered[alias]
                break

    # 🔴 دالة مساعدة عشان نحوّل بأمان
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
        # كل حاجة جاية (raw) — ده اللي بيتحفظ في JSON
        "raw": tp,
        # الحقول الأساسية اللي بتتحط في أعمدة DB مخصصة
        "bid":           _to_float(known.get("bid")),
        "impression_id": str(known.get("impression_id") or "")[:100] or None,
        "website_id":    str(known.get("website_id") or "")[:100] or None,
        "quality":       _to_int(known.get("quality")),
        "adblock":       _to_bool(known.get("adblock", "0")),
        "country":       str(known.get("country") or "")[:10] or None,
        # الباقي بيضل في raw — منه نستخرج للعرض لاحقاً
        "known": known,
    }


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

    result = quick_precheck(nav=payload.nav or {}, fp=payload.fp or {}, threshold=int(c.bot_block_threshold or 100))
    headers_dict = {str(k).lower(): str(v) for k, v in request.headers.items()}
    http_version = str(request.scope.get("http_version", "1.1"))
    ua = str((payload.nav or {}).get("ua") or "")

    extra_score = 0
    extra_reasons = []
    try:
        for sig in analyze_headers(headers_dict, ua, http_version):
            extra_score += int(sig.get("score", 0) or 0)
            extra_reasons.append(sig.get("code"))
    except Exception:
        pass

    total_score = min(150, result["score"] + extra_score)
    should_block = total_score >= int(c.bot_block_threshold or 100) or result["action"] == "block"
    is_blocked = should_block

    # 🔴 نستخرج كل الماكروز
    macros = _extract_macros(payload.tracking_params or {})

    existing = db.query(SessionModel).filter(SessionModel.session_id == payload.session_id).first()
    if not existing:
        zone_id = c.destination_zone_id or extract_zone_id_from_url(c.destination_url) or "unknown"

        # لو محظور = invalid، غير كده = pending (لسه ما شفناش Adsterra)
        verdict = "invalid" if is_blocked else "pending"
        score = 100 if is_blocked else 0

        # click_id = session_id عشان يطابق Adsterra postback
        click_id = payload.session_id

        visit = VisitModel(
            campaign_id=c.id,
            session_id=payload.session_id,
            click_id=click_id,                       # 🔴 ده اللي Adsterra هترجعه
            timestamp=datetime.utcnow(),
            ip=client_ip,
            user_agent=ua,
            zone_id=zone_id,
            bid=macros.get("bid", 0.0),
            popads_impression_id=macros.get("impression_id"),
            popads_website_id=macros.get("website_id"),
            popads_quality=macros.get("quality"),
            popads_adblock=macros.get("adblock", False),
            popads_data=macros.get("raw"),           # 🔴 كل الماكروز
            score=score,
            verdict=verdict,
            evidence=[{"code": "INTERSTITIAL_PRECHECK", "severity": "critical" if is_blocked else "low",
                       "score": score, "detail": "Direct Link"}],
            country=macros.get("country") or (payload.nav.get("country") if payload.nav else "Unknown"),
            data_quality="partial",
            filter_reason="INTERSTITIAL_BLOCK" if is_blocked else None,
            counting_type="direct_link",
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
            score=score,
            meta={
                "direct_link": True,
                "precheck_score": total_score,
                "macros": macros.get("raw"),
                "click_id": click_id,
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
                "reasons": (result["reasons"] + extra_reasons)}

    return {"action": "redirect", "url": c.destination_url, "score": total_score, "reasons": []}
