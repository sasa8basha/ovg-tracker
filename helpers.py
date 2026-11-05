"""
helpers.py — Shared helper functions.

Contains:
  - CSV safety, date parsing, filename sanitization
  - CPM P&L math (used by reports router)
  - Zone scoring & lifecycle
  - Shared DB resolution helper
  - Campaign resolution (v3 — Phase 0.5)
  - Zone ID extraction from URLs (improved in v3 Phase 2.1)
"""
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import SiteModel, UserModel, VisitModel, CampaignModel


# =========================================================
# GENERAL HELPERS
# =========================================================
def csv_safe(val):
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


def _country_key(country_code, country_name):
    code = (country_code or "").strip().upper()
    if code and code not in ("LO", "XX"):
        return code
    return (country_name or "Unknown").strip() or "Unknown"


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


def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key:
        raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(
        SiteModel.site_key == site_key,
        SiteModel.user_id == user.id,
    ).first()
    if not s:
        raise HTTPException(404, "الموقع مش موجود أو مش بتاعك")
    return s


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
# ZONE ID EXTRACTION (v3 Phase 2.1 — improved)
# =========================================================
def extract_zone_id_from_url(url: str) -> str:
    """
    استخراج zone_id من URL بعدة طرق.
    يقبل:
      - ?zoneId=10245, ?zone_id=10245, ?zone=10245, ?z=10245
      - /zone/10245 or /z/10245 or /zoneid/10245
      - /10245/ (path يبدأ برقم كبير — adsterra direct)
    """
    if not url or url == "unknown":
        return ""

    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    # 1) Query params
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

    # 2) Path patterns: /zone/12345 or /z/12345
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

    # 3) Adsterra direct link pattern: first path segment is a number
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
    """Legacy wrapper — يرجع 'unknown' لو مفيش نتيجة."""
    result = extract_zone_id_from_url(url)
    return result if result else "unknown"


# =========================================================
# CPM P&L HELPERS
# =========================================================
_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])


def _extract_source(zone_id: str) -> str:
    if not zone_id or zone_id == "unknown":
        return "unknown"
    z = str(zone_id)
    for sep in ("_", "-", ":"):
        if sep in z:
            head = z.split(sep, 1)[0].strip().lower()
            if head:
                return head
    return "unknown"


def _compute_pl(total: int, valid: int, wasted: int,
                buy_cpm: float, sell_cpm: float) -> dict:
    """
    P&L الحقيقي:
      - cost = كل الزيارات (بوت + valid + suspicious) × buy_cpm
      - revenue = valid × sell_cpm (بوت blocked = مفيش impression = مفيش revenue)
      - profit = revenue - cost
    """
    effective = max(0, valid - wasted)
    cost = round(total * buy_cpm / 1000.0, 4)
    revenue = round(effective * sell_cpm / 1000.0, 4)
    profit = round(revenue - cost, 4)
    roi = round((profit / cost * 100.0), 2) if cost > 0 else 0.0
    effective_ratio = round(effective / total * 100.0, 2) if total > 0 else 0.0
    needed_ratio = round((buy_cpm / sell_cpm) * 100.0, 2) if sell_cpm > 0 else 100.0
    return {
        "cost": cost,
        "revenue": revenue,
        "profit": profit,
        "roi": roi,
        "effective_ratio": effective_ratio,
        "needed_ratio": needed_ratio,
        "is_profitable": profit >= 0,
    }


def _compute_zone_score(profit: float, roi: float, bot_rate: float,
                        wasted_rate: float, total: int) -> dict:
    if roi >= 50:
        profit_score = 100.0
    elif roi >= 0:
        profit_score = 50.0 + (roi / 50.0) * 50.0
    elif roi >= -30:
        profit_score = 50.0 + (roi / 30.0) * 50.0
    else:
        profit_score = 0.0

    safety_bots = max(0.0, 100.0 - bot_rate * 2.0)
    safety_wasted = max(0.0, 100.0 - wasted_rate * 1.67)
    safety_score = safety_bots * 0.70 + safety_wasted * 0.30

    volume_score = min(100.0, total / 50.0)

    if total >= 1000:
        stability_score = 100.0
    elif total >= 200:
        stability_score = 40.0 + ((total - 200) / 800.0) * 60.0
    else:
        stability_score = 0.0

    composite = (
        profit_score * 0.40
        + safety_score * 0.35
        + volume_score * 0.15
        + stability_score * 0.10
    )

    if composite >= 85:
        grade = "S"
    elif composite >= 70:
        grade = "A"
    elif composite >= 50:
        grade = "B"
    elif composite >= 30:
        grade = "C"
    elif composite >= 10:
        grade = "D"
    else:
        grade = "F"

    return {
        "profit_score": round(profit_score, 1),
        "safety_score": round(safety_score, 1),
        "volume_score": round(volume_score, 1),
        "stability_score": round(stability_score, 1),
        "composite": round(composite, 1),
        "grade": grade,
    }


def _compute_zone_lifecycle(total: int, grade: str, roi: float) -> str:
    if total < 200:
        return "learning"
    if total < 1000:
        return "testing"
    if grade in ("S", "A", "B") and roi >= 0:
        return "scaling"
    if grade in ("D", "F") or roi < -20:
        return "kill"
    return "declining"


def _is_wasted_visit(evidence) -> bool:
    if not isinstance(evidence, list):
        return False
    for e in evidence:
        if isinstance(e, dict) and e.get("code") in _WASTED_CODES:
            return True
    return False
