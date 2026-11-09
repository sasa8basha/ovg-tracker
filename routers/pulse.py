"""
routers/pulse.py — Single-call endpoint for the "Money Pulse" widget.

Replaces 4 separate `/api/visits` calls that used to fire every 30s
from shell.js (≈4,800 req/hour). This endpoint does ONE aggregation
over the user's campaigns and returns every window the widget needs.

Returns per-window:
    {
        "visits": int,
        "valid": int,
        "invalid": int,
        "cost": float,          # sum of BID
        "revenue": float,       # sum of Adsterra revenue
        "profit": float,
        "source": "exact" | "cpm" | "unknown",
        "integrity": {...},     # from metrics.compute_cost_integrity
    }
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, VisitModel, CampaignModel
from auth import current_user
from metrics import compute_cost_integrity

router = APIRouter()


def _window_aggregate(campaign_ids, start, end, db, buy_cpm, sell_cpm):
    """
    Aggregate a single time window.

    Returns a dict with totals, cost, revenue, profit, source, integrity.
    """
    if not campaign_ids:
        return _empty_window()

    row = db.query(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
        func.sum(VisitModel.bid).label("cost"),
        func.sum(VisitModel.revenue).label("revenue"),
        func.sum(case((VisitModel.bid > 0, 1), else_=0)).label("with_bid"),
    ).filter(
        VisitModel.campaign_id.in_(campaign_ids),
        VisitModel.timestamp >= start,
        VisitModel.timestamp < end,
    ).first()

    total = int(row.total or 0)
    valid = int(row.valid or 0)
    invalid = int(row.invalid or 0)
    suspicious = int(row.suspicious or 0)
    cost = round(float(row.cost or 0), 4)
    revenue = round(float(row.revenue or 0), 4)
    with_bid = int(row.with_bid or 0)
    without_bid = total - with_bid

    if total == 0:
        return _empty_window()

    # Integrity block
    integrity = _integrity_block(total, with_bid, without_bid)

    # Decide source
    if without_bid == 0:
        source = "exact"
        profit = round(revenue - cost, 4)
    elif cost > 0:
        # Some BID but not all — still "exact" but with a warning
        source = "exact_partial"
        profit = round(revenue - cost, 4)
    else:
        # No BID at all — fall back to CPM estimation
        source = "cpm"
        effective = max(0, valid)
        revenue = round(effective * sell_cpm / 1000.0, 4)
        cost = round(total * buy_cpm / 1000.0, 4)
        profit = round(revenue - cost, 4)

    return {
        "visits": total,
        "valid": valid,
        "invalid": invalid,
        "suspicious": suspicious,
        "cost": cost,
        "revenue": revenue,
        "profit": profit,
        "source": source,
        "integrity": integrity,
    }


def _empty_window() -> dict:
    return {
        "visits": 0,
        "valid": 0,
        "invalid": 0,
        "suspicious": 0,
        "cost": 0.0,
        "revenue": 0.0,
        "profit": 0.0,
        "source": "unknown",
        "integrity": {
            "total_visits": 0,
            "visits_with_bid": 0,
            "visits_without_bid": 0,
            "bid_coverage_pct": 0.0,
            "integrity": "unknown",
            "message": "No visits in this window.",
        },
    }


def _integrity_block(total: int, with_bid: int, without_bid: int) -> dict:
    """Aggregate-level integrity block (no raw visits needed)."""
    if total <= 0:
        return {
            "total_visits": 0,
            "visits_with_bid": 0,
            "visits_without_bid": 0,
            "bid_coverage_pct": 0.0,
            "integrity": "unknown",
            "message": "No visits in this window.",
        }
    coverage = round((with_bid / total) * 100.0, 2)
    if without_bid == 0:
        integrity = "exact"
        message = "All visits have a BID."
    elif (with_bid / total) >= 0.90:
        integrity = "partial"
        message = f"Cost from {coverage}% of visits. {without_bid} missing BID."
    else:
        integrity = "partial_warn"
        message = f"Only {coverage}% of visits have BID. Cost underestimated."
    return {
        "total_visits": total,
        "visits_with_bid": with_bid,
        "visits_without_bid": without_bid,
        "bid_coverage_pct": coverage,
        "integrity": integrity,
        "message": message,
    }


@router.get("/stats/pulse")
def stats_pulse(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    Single-call endpoint for the Money Pulse widget.

    Windows:
        today       — [start_of_today, now)
        yesterday   — [start_of_yesterday, start_of_today)
        week        — [start_of_today - 7d, now)
        week_prev   — [start_of_today - 14d, start_of_today - 7d)
    """
    now = datetime.utcnow()
    start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_yesterday = start_today - timedelta(days=1)
    start_week = start_today - timedelta(days=7)
    start_prev_week = start_today - timedelta(days=14)

    campaign_ids = [
        r.id for r in db.query(CampaignModel.id).filter(
            CampaignModel.user_id == user.id
        ).all()
    ]

    buy_cpm = float(user.cpm_buy or 1.0)
    sell_cpm = float(user.cpm_sell or 1.5)

    return {
        "today": _window_aggregate(campaign_ids, start_today, now, db, buy_cpm, sell_cpm),
        "yesterday": _window_aggregate(campaign_ids, start_yesterday, start_today, db, buy_cpm, sell_cpm),
        "week": _window_aggregate(campaign_ids, start_week, now, db, buy_cpm, sell_cpm),
        "week_prev": _window_aggregate(campaign_ids, start_prev_week, start_week, db, buy_cpm, sell_cpm),
        "computed_at": now.isoformat(),
        "cpm_config": {"buy": buy_cpm, "sell": sell_cpm},
    }