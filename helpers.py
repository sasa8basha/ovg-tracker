"""
helpers.py — Shared helper functions.

Contains:
  - CSV safety, date parsing, filename sanitization
  - CPM P&L math (used by reports router)
  - Zone scoring & lifecycle
  - Shared DB resolution helper
"""
import re
from datetime import datetime, timedelta
from fastapi import HTTPException
from sqlalchemy.orm import Session

from models import SiteModel, UserModel


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


# =========================================================
# CPM P&L HELPERS (Phase 3A)
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
