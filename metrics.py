"""
metrics.py — Single Source of Truth for all financial and performance metrics.
"""
from typing import Any

_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])

# BID-integrity thresholds
BID_COVERAGE_WARN = 0.90   # 90%+ coverage = "partial" (acceptable with warning)
BID_COVERAGE_CRIT = 0.70   # <70% coverage = "partial_warn" (severe)


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
    """
    Detect a 'wasted' impression from the evidence list.

    Handles three shapes safely:
      - dict with code (orchestrator + legacy)
      - plain string (legacy v1)
      - None / invalid → False
    """
    if not isinstance(evidence, list):
        return False
    for e in evidence:
        if isinstance(e, dict):
            code = e.get("code")
            if code and str(code).upper() in _WASTED_CODES:
                return True
        elif isinstance(e, str):
            if e.upper() in _WASTED_CODES:
                return True
    return False


def compute_cost_integrity(visits_data: list) -> dict:
    """
    Analyze the integrity of cost data (BID from PopAds macros).

    Returns a structured report so the UI can warn the user when
    profit is being calculated on incomplete cost data.
    """
    if not visits_data:
        return {
            "total_visits": 0,
            "visits_with_bid": 0,
            "visits_without_bid": 0,
            "bid_coverage_pct": 0.0,
            "integrity": "unknown",
            "message": "No visits in this dataset.",
        }

    total = len(visits_data)
    with_bid = 0
    for v in visits_data:
        try:
            bid = float(v.get("bid") or 0)
        except (ValueError, TypeError):
            bid = 0.0
        if bid > 0:
            with_bid += 1

    without_bid = total - with_bid
    coverage = round((with_bid / total) * 100.0, 2) if total > 0 else 0.0

    if without_bid == 0:
        integrity = "exact"
        message = "All visits have a BID. Cost and profit are exact."
    elif (with_bid / total) >= BID_COVERAGE_WARN:
        integrity = "partial"
        message = (
            f"Cost calculated from {coverage}% of visits. "
            f"{without_bid} visit(s) have no BID — cost may be slightly underestimated."
        )
    else:
        integrity = "partial_warn"
        message = (
            f"Only {coverage}% of visits have a BID. "
            f"Cost and profit are SIGNIFICANTLY UNDERESTIMATED. "
            f"{without_bid} of {total} visits have no cost data."
        )

    return {
        "total_visits": total,
        "visits_with_bid": with_bid,
        "visits_without_bid": without_bid,
        "bid_coverage_pct": coverage,
        "integrity": integrity,
        "message": message,
    }


def compute_pl(total: int, valid: int, wasted: int, buy_cpm: float, sell_cpm: float) -> dict:
    """
    Estimate P&L from CPMs (used when per-visit BID/revenue unavailable).

    When `sell_cpm` is zero or missing, we DO NOT claim "needs 100% efficiency".
    We return a clearly flagged "no_revenue" result so the UI can tell the user
    to configure sell CPM.
    """
    effective = max(0, valid - wasted)
    cost = round(total * buy_cpm / 1000.0, 4)

    # Guard: no sell revenue → cannot compute breakeven
    if sell_cpm is None or float(sell_cpm) <= 0:
        return {
            "cost": cost,
            "revenue": 0.0,
            "profit": round(-cost, 4),
            "roi": -100.0 if cost > 0 else 0.0,
            "effective_ratio": round(effective / total * 100.0, 2) if total > 0 else 0.0,
            "needed_ratio": None,
            "is_profitable": False,
            "source": "cpm",
            "error": "no_sell_revenue",
            "message": "Sell CPM is zero or missing — profit cannot be estimated. Configure sell CPM in Settings.",
        }

    revenue = round(effective * sell_cpm / 1000.0, 4)
    profit = round(revenue - cost, 4)
    roi = round((profit / cost * 100.0), 2) if cost > 0 else 0.0
    effective_ratio = round(effective / total * 100.0, 2) if total > 0 else 0.0
    needed_ratio = round((buy_cpm / sell_cpm) * 100.0, 2)

    return {
        "cost": cost,
        "revenue": revenue,
        "profit": profit,
        "roi": roi,
        "effective_ratio": effective_ratio,
        "needed_ratio": needed_ratio,
        "is_profitable": profit >= 0,
        "source": "cpm",
        "error": None,
        "message": None,
    }


def compute_pl_exact(visits_data: list) -> dict:
    """
    Compute P&L from real BID (PopAds) + revenue (Adsterra) per visit.

    Visits with bid==0 contribute ZERO to cost (they would otherwise
    inflate profit artificially). The returned `integrity` block tells
    the caller how trustworthy the result is.
    """
    total_cost = 0.0
    total_revenue = 0.0
    valid_visits = 0
    invalid_visits = 0
    bot_cost_wasted = 0.0

    for v in visits_data:
        try:
            bid = float(v.get("bid") or 0)
        except (ValueError, TypeError):
            bid = 0.0
        try:
            rev = float(v.get("revenue") or 0)
        except (ValueError, TypeError):
            rev = 0.0

        if bid > 0:
            total_cost += bid
        total_revenue += rev

        if v.get("verdict") == "valid":
            valid_visits += 1
        elif v.get("verdict") == "invalid":
            invalid_visits += 1
            if bid > 0:
                bot_cost_wasted += bid

    profit = round(total_revenue - total_cost, 4)
    roi = round((profit / total_cost * 100.0), 2) if total_cost > 0 else 0.0

    integrity = compute_cost_integrity(visits_data)

    return {
        "cost": round(total_cost, 4),
        "revenue": round(total_revenue, 4),
        "profit": profit,
        "roi": roi,
        "valid_visits": valid_visits,
        "invalid_visits": invalid_visits,
        "bot_cost_wasted": round(bot_cost_wasted, 4),
        "is_profitable": profit >= 0,
        "source": "exact",
        "integrity": integrity,
        "error": None,
        "message": None if integrity["integrity"] == "exact" else integrity["message"],
    }


def compute_zone_score(profit: float, roi: float, bot_rate: float, wasted_rate: float, total: int) -> dict:
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


def compute_zone_lifecycle(total: int, grade: str, roi: float) -> str:
    if total < 200:
        return "learning"
    if total < 1000:
        return "testing"
    if grade in ("S", "A", "B") and roi >= 0:
        return "scaling"
    if grade in ("D", "F") or roi < -20:
        return "kill"
    return "declining"