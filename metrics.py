"""
metrics.py — P4: Single Source of Truth for all financial and performance metrics.
"""
from typing import Any

_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])

def extract_source(zone_id: str) -> str:
    if not zone_id or zone_id == "unknown":
        return "unknown"
    z = str(zone_id)
    for sep in ("_", "-", ":"):
        if sep in z:
            head = z.split(sep, 1)[0].strip().lower()
            if head:
                return head
    return "unknown"

def is_wasted_visit(evidence: Any) -> bool:
    if not isinstance(evidence, list):
        return False
    for e in evidence:
        if isinstance(e, dict) and e.get("code") in _WASTED_CODES:
            return True
    return False

def compute_pl(total: int, valid: int, wasted: int, buy_cpm: float, sell_cpm: float) -> dict:
    """
    حساب الربح والخسارة الموحد.
    cost = كل الزيارات × buy_cpm
    revenue = (valid - wasted) × sell_cpm
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

def compute_zone_score(profit: float, roi: float, bot_rate: float, wasted_rate: float, total: int) -> dict:
    """
    حساب درجة تقييم الزون (Grade) الموحد.
    """
    if roi >= 50: profit_score = 100.0
    elif roi >= 0: profit_score = 50.0 + (roi / 50.0) * 50.0
    elif roi >= -30: profit_score = 50.0 + (roi / 30.0) * 50.0
    else: profit_score = 0.0

    safety_bots = max(0.0, 100.0 - bot_rate * 2.0)
    safety_wasted = max(0.0, 100.0 - wasted_rate * 1.67)
    safety_score = safety_bots * 0.70 + safety_wasted * 0.30

    volume_score = min(100.0, total / 50.0)

    if total >= 1000: stability_score = 100.0
    elif total >= 200: stability_score = 40.0 + ((total - 200) / 800.0) * 60.0
    else: stability_score = 0.0

    composite = (profit_score * 0.40 + safety_score * 0.35 + volume_score * 0.15 + stability_score * 0.10)

    if composite >= 85: grade = "S"
    elif composite >= 70: grade = "A"
    elif composite >= 50: grade = "B"
    elif composite >= 30: grade = "C"
    elif composite >= 10: grade = "D"
    else: grade = "F"

    return {
        "profit_score": round(profit_score, 1),
        "safety_score": round(safety_score, 1),
        "volume_score": round(volume_score, 1),
        "stability_score": round(stability_score, 1),
        "composite": round(composite, 1),
        "grade": grade,
    }

def compute_zone_lifecycle(total: int, grade: str, roi: float) -> str:
    if total < 200: return "learning"
    if total < 1000: return "testing"
    if grade in ("S", "A", "B") and roi >= 0: return "scaling"
    if grade in ("D", "F") or roi < -20: return "kill"
    return "declining"
