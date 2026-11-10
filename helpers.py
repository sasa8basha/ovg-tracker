"""
helpers.py — Shared helper functions.
"""
import re
from collections import OrderedDict
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import UserModel, VisitModel, CampaignModel


def verify_campaign_access(campaign_id: int | None, user: UserModel, db: Session) -> CampaignModel | None:
    """
    Verify that campaign_id belongs to the current user.
    Returns the CampaignModel if valid, None if campaign_id is None.
    Raises HTTPException(404) if the campaign does not exist or is not owned by the user.
    Prevents cross-user data leaks when campaign_id is supplied as a query parameter.
    """
    if campaign_id is None:
        return None
    c = db.query(CampaignModel).filter(
        CampaignModel.id == campaign_id,
        CampaignModel.user_id == user.id,
    ).first()
    if not c:
        raise HTTPException(status_code=404, detail="الحملة مش موجودة")
    return c


# =========================================================
# POPADS URL MACROS — 17 macros
# =========================================================
POPADS_URL_MACROS = OrderedDict([
    ("websiteid",        ("[WEBSITEID]",        "ID of the source website")),
    ("categoryid",       ("[CATEGORYID]",       "ID of the source category")),
    ("categoryname",     ("[CATEGORYNAME]",     "Name of the source category")),
    ("ispid",            ("[ISPID]",            "ISP ID")),
    ("ispname",          ("[ISPNAME]",          "ISP name")),
    ("country",          ("[COUNTRY]",          "Country of the visitor")),
    ("quality",          ("[QUALITY]",          "Website quality (1-10)")),
    ("bid",              ("[BID]",              "Price of the impression")),
    ("screenresolution", ("[SCREENRESOLUTION]", "Screen resolution")),
    ("osname",           ("[OSNAME]",           "OS name")),
    ("browsername",      ("[BROWSERNAME]",      "Browser name")),
    ("formfactorname",   ("[FORMFACTORNAME]",   "Form factor (Smartphone/Tablet)")),
    ("devicename",       ("[DEVICENAME]",       "Device name")),
    ("campaignid",       ("[CAMPAIGNID]",       "PopAds campaign ID")),
    ("campaignname",     ("[CAMPAIGNNAME]",     "PopAds campaign name")),
    ("impressionid",     ("[IMPRESSIONID]",     "Unique impression ID")),
    ("adblock",          ("[ADBLOCK]",          "1 = AdBlock detected, 0 = no")),
])


def build_tracking_url(campaign: CampaignModel, origin: str) -> str:
    """
    Build the traffic URL user should paste into their traffic source (PopAds).
    Includes all 17 PopAds macros as placeholders.

    - Direct: `{origin}/go/{campaign_key}?macros...` (redirects to Adsterra)
    - Landing: `{landing_url}?macros...` (user's LP receives macros)
    """
    if not campaign:
        return ""
    origin = (origin or "").rstrip("/")

    if campaign.type == "direct":
        base = f"{origin}/go/{campaign.campaign_key}"
    elif campaign.type == "landing":
        base = (campaign.landing_url or "").strip()
        if not base:
            return ""
    elif campaign.type == "hybrid":
        base = (campaign.landing_url or "").strip() or f"{origin}/go/{campaign.campaign_key}"
    else:
        return ""

    sep = "&" if "?" in base else "?"
    parts = [f"{key}={macro}" for key, (macro, _desc) in POPADS_URL_MACROS.items()]
    # H-19: landing/hybrid CTAs to Adsterra must carry sub_id for revenue sync
    param = getattr(campaign, "adsterra_tracking_param", None) or "sub_id"
    if campaign.type in ("landing", "hybrid") and not any(p.startswith(f"{param}=") for p in parts):
        parts.append(f"{param}=[CLICKID]")
    return base + sep + "&".join(parts)


# =========================================================
# MACRO EXTRACTION (shared by interstitial + collector_v3)
# =========================================================
MACRO_ALIASES = {  # L-26: canonical; collector_v3 keeps a copy — prefer import long-term
    "bid":              ("bid",),
    "sub_id":           ("sub_id", "subid", "clickid", "click_id"),  # H-19
    "impression_id":    ("impressionid", "impid", "impression_id"),
    "website_id":       ("websiteid", "website_id"),
    "category_id":      ("categoryid", "category_id"),
    "category_name":    ("categoryname", "category_name"),
    "isp_id":           ("ispid", "isp_id"),
    "isp_name":         ("ispname", "isp_name", "isp"),
    "country":          ("country",),
    "quality":          ("quality",),
    "screen_res":       ("screenresolution", "screen_resolution"),
    "os_name":          ("osname", "os_name"),
    "browser_name":     ("browsername", "browser_name"),
    "form_factor":      ("formfactorname", "form_factor"),
    "device_name":      ("devicename", "device_name"),
    "campaign_id":      ("campaignid", "campaign_id"),
    "campaign_name":    ("campaignname", "campaign_name"),
    "os_id":            ("osid", "os_id"),
    "browser_id":       ("browserid", "browser_id"),
    "form_factor_id":   ("formfactorid", "form_factor_id"),
    "device_id":        ("deviceid", "device_id"),
    "adblock":          ("adblock",),
    "ip":               ("ip",),
    "ipv6":             ("ipv6",),
    "ipv6or4":          ("ipv6or4",),
    "xforwardedfor":    ("xforwardedfor",),
    "useragent":        ("useragent", "ua"),
    "lang":             ("lang",),
}


def extract_macros(tp: dict) -> dict:
    """Extract PopAds macros from tracking_params."""
    if not isinstance(tp, dict):
        return {
            "raw": {}, "known": {}, "bid": 0.0,
            "impression_id": None, "website_id": None,
            "quality": None, "adblock": False, "country": None,
        }

    lowered = {
        str(k).strip().lower(): v
        for k, v in tp.items()
        if v is not None and str(v) != "" and not str(v).startswith("[")
    }

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
# CSV / DATE / FILE HELPERS
# =========================================================
def csv_safe(val):
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


def _country_key(country_code, country_name):
    # L-09: collapse Local/LO/XX into one bucket
    code = (country_code or "").strip().upper()
    name = (country_name or "").strip()
    if code in ("LO", "XX", "") or name.lower() in ("local", "unknown", ""):
        return "LOCAL"
    if code:
        return code
    return name or "Unknown"


def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(str(s).strip(), "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def _apply_date_filter(q, from_date, to_date):
    fd = _parse_date(from_date)
    td = _parse_date(to_date)
    if fd:
        q = q.filter(VisitModel.timestamp >= fd)
    if td:
        q = q.filter(VisitModel.timestamp < (td + timedelta(days=1)))
    return q


def _safe_filename(base, *parts):
    s = "_".join([base] + [str(p) for p in parts if p])
    s = re.sub(r"[^a-zA-Z0-9_.-]", "_", s)[:100]
    return (s or "export") + ".csv"


def _resolve_user_campaign(campaign_key_or_id, user: UserModel, db: Session) -> CampaignModel:
    if not campaign_key_or_id:
        raise HTTPException(400, "campaign مطلوب")
    q = db.query(CampaignModel).filter(CampaignModel.user_id == user.id)
    if isinstance(campaign_key_or_id, int):
        q = q.filter(CampaignModel.id == campaign_key_or_id)
    else:
        key = str(campaign_key_or_id).strip()
        if key.isdigit():
            q = q.filter(CampaignModel.id == int(key))
        else:
            q = q.filter(CampaignModel.campaign_key == key)
    c = q.first()
    if not c:
        raise HTTPException(404, "الحملة مش موجودة أو مش بتاعتك")
    return c


# =========================================================
# ZONE EXTRACTION
# =========================================================
def extract_zone_id_from_url(url: str) -> str:
    if not url or url == "unknown":
        return ""
    try:
        parsed = urlparse(url)
    except Exception:
        return ""
    try:
        for k, v in parse_qs(parsed.query or "").items():
            kl = (k or "").lower().strip()
            if kl in ("zoneid", "zone_id", "zone", "z"):
                if v and v[0]:
                    val = str(v[0]).strip()
                    if val and len(val) <= 100:
                        return val
    except Exception:
        pass
    try:
        parts = [p for p in (parsed.path or "").split("/") if p]
        for i, p in enumerate(parts):
            pl = (p or "").lower().strip()
            if pl in ("zone", "z", "zoneid") and i + 1 < len(parts):
                nxt = parts[i + 1]
                if nxt and len(nxt) <= 100:
                    return nxt
    except Exception:
        pass
    try:
        parts = [p for p in (parsed.path or "").split("/") if p]
        if parts:
            first = parts[0]
            if first.isdigit() and 4 <= len(first) <= 10:
                return first
    except Exception:
        pass
    return ""


def extract_zone_id(url: str) -> str:
    result = extract_zone_id_from_url(url)
    return result if result else "unknown"