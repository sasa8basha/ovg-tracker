"""
routers/reports.py — Zone reports, smart P&L, countries, tech, map,
and specific Proof/Refund reports.
"""
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, and_, not_
from sqlalchemy.orm import Session
from database import get_db
from models import UserModel, VisitModel, CampaignModel
from auth import current_user
from helpers import _apply_date_filter, _country_key, verify_campaign_access
from metrics import (
    extract_source,
    compute_pl,
    compute_cost_integrity,
    compute_zone_score,
    compute_zone_lifecycle,
    is_wasted_visit,
)

router = APIRouter()

# Hard cap on rows analyzed in the smart report.
# We fetch LIMIT + 1 to detect overflow without a separate COUNT query.
SMART_REPORT_ROW_LIMIT = 100_000


# =========================================================
# ZONE AGGREGATE
# =========================================================
@router.get("/reports/zones")
def get_zone_reports(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    inv = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    sus = func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0))
    val = func.sum(case((VisitModel.verdict == "valid", 1), else_=0))
    q = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label("total"),
        val.label("valid"),
        inv.label("invalid"),
        sus.label("suspicious"),
    )
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.zone_id).all()

    report = []
    for z in rows:
        if not z.zone_id or z.zone_id == "unknown":
            continue
        total = int(z.total or 0)
        invalid = int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = (
            "?" if total < 10
            else "A" if rate < 5
            else "B" if rate < 15
            else "C" if rate < 30
            else "F"
        )
        report.append({
            "zone": z.zone_id,
            "total": total,
            "valid": int(z.valid or 0),
            "invalid": invalid,
            "suspicious": int(z.suspicious or 0),
            "bot_rate": rate,
            "grade": grade,
            "min_sample_met": total >= 10,
        })
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report


# =========================================================
# SMART REPORT (P&L per zone) — truncated detection + integrity
# =========================================================
@router.get("/reports/smart")
def smart_report(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    verify_campaign_access(campaign_id, user, db)
    buy_cpm = float(user.cpm_buy or 1.0)
    sell_cpm = float(user.cpm_sell or 1.5)

    q = db.query(
        VisitModel.zone_id,
        VisitModel.verdict,
        VisitModel.evidence,
        VisitModel.bid,
        VisitModel.revenue,
    )
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    # H-20: deterministic sample (newest first) when truncating
    q = q.order_by(VisitModel.timestamp.desc())

    # ---- Fetch LIMIT+1 to detect overflow ----
    raw_rows = q.limit(SMART_REPORT_ROW_LIMIT + 1).all()
    truncated = len(raw_rows) > SMART_REPORT_ROW_LIMIT
    rows = raw_rows[:SMART_REPORT_ROW_LIMIT] if truncated else raw_rows

    # ---- Per-zone accumulation ----
    zones = {}
    total_all = 0
    valid_all = 0
    invalid_all = 0
    suspicious_all = 0
    wasted_all = 0
    total_cost = 0.0
    total_revenue = 0.0
    visits_with_bid = 0
    visits_without_bid = 0

    for row in rows:
        total_all += 1
        zid = row.zone_id or "unknown"

        try:
            bid = float(row.bid or 0)
        except (ValueError, TypeError):
            bid = 0.0
        try:
            rev = float(row.revenue or 0)
        except (ValueError, TypeError):
            rev = 0.0

        if bid > 0:
            visits_with_bid += 1
            total_cost += bid
        else:
            visits_without_bid += 1
        total_revenue += rev

        if zid not in zones:
            zones[zid] = {
                "total": 0, "valid": 0, "invalid": 0, "suspicious": 0, "wasted": 0,
                "cost": 0.0, "revenue": 0.0,
                "visits_with_bid": 0, "visits_without_bid": 0,
            }
        z = zones[zid]
        z["total"] += 1
        z["cost"] += bid
        z["revenue"] += rev
        if bid > 0:
            z["visits_with_bid"] += 1
        else:
            z["visits_without_bid"] += 1

        verdict = row.verdict or "unknown"
        if verdict == "valid":
            z["valid"] += 1
            valid_all += 1
            if is_wasted_visit(row.evidence):
                z["wasted"] += 1
                wasted_all += 1
        elif verdict == "invalid":
            z["invalid"] += 1
            invalid_all += 1
        elif verdict == "suspicious":
            z["suspicious"] += 1
            suspicious_all += 1

    # ---- Summary P&L ----
    # C-07 FIX: only claim "exact" when every visit has a bid; otherwise partial.
    if total_cost > 0 and visits_without_bid == 0:
        summary_pl = {
            "cost": round(total_cost, 4),
            "revenue": round(total_revenue, 4),
            "profit": round(total_revenue - total_cost, 4),
            "roi": round((total_revenue - total_cost) / total_cost * 100, 2) if total_cost > 0 else 0,
            "is_profitable": total_revenue >= total_cost,
            "source": "exact",
        }
    elif total_cost > 0:
        summary_pl = {
            "cost": round(total_cost, 4),
            "revenue": round(total_revenue, 4),
            "profit": round(total_revenue - total_cost, 4),
            "roi": round((total_revenue - total_cost) / total_cost * 100, 2) if total_cost > 0 else 0,
            "is_profitable": total_revenue >= total_cost,
            "source": "exact_partial",
        }
    else:
        summary_pl = compute_pl(total_all, valid_all, wasted_all, buy_cpm, sell_cpm)
        summary_pl["source"] = "cpm"

    # ---- Integrity block ----
    integrity = _build_integrity(
        total=total_all,
        with_bid=visits_with_bid,
        without_bid=visits_without_bid,
    )

    summary = {
        "total": total_all,
        "valid": valid_all,
        "invalid": invalid_all,
        "suspicious": suspicious_all,
        "wasted": wasted_all,
        "bot_rate": round(invalid_all / total_all * 100.0, 2) if total_all > 0 else 0.0,
        "wasted_rate": round(wasted_all / total_all * 100.0, 2) if total_all > 0 else 0.0,
        "pl": summary_pl,
        "integrity": integrity,
    }

    # ---- Per-zone P&L ----
    result_zones = []
    for zid, z in zones.items():
        if zid == "unknown":
            continue
        total = z["total"]
        bot_rate = round(z["invalid"] / total * 100.0, 2) if total > 0 else 0.0
        wasted_rate = round(z["wasted"] / total * 100.0, 2) if total > 0 else 0.0

        if z["cost"] > 0 and z.get("visits_without_bid", 0) == 0:
            pl = {
                "cost": round(z["cost"], 4),
                "revenue": round(z["revenue"], 4),
                "profit": round(z["revenue"] - z["cost"], 4),
                "roi": round((z["revenue"] - z["cost"]) / z["cost"] * 100, 2) if z["cost"] > 0 else 0,
                "is_profitable": z["revenue"] >= z["cost"],
                "source": "exact",
            }
        elif z["cost"] > 0:
            pl = {
                "cost": round(z["cost"], 4),
                "revenue": round(z["revenue"], 4),
                "profit": round(z["revenue"] - z["cost"], 4),
                "roi": round((z["revenue"] - z["cost"]) / z["cost"] * 100, 2) if z["cost"] > 0 else 0,
                "is_profitable": z["revenue"] >= z["cost"],
                "source": "exact_partial",  # C-07 per-zone
            }
        else:
            pl = compute_pl(total, z["valid"], z["wasted"], buy_cpm, sell_cpm)
            pl["source"] = "cpm"

        zone_integrity = _build_integrity(
            total=total,
            with_bid=z["visits_with_bid"],
            without_bid=z["visits_without_bid"],
        )

        score = compute_zone_score(pl["profit"], pl["roi"], bot_rate, wasted_rate, total)
        lifecycle = compute_zone_lifecycle(total, score["grade"], pl["roi"])
        result_zones.append({
            "zone": zid,
            "source": extract_source(zid),
            "total": total,
            "valid": z["valid"],
            "invalid": z["invalid"],
            "suspicious": z["suspicious"],
            "wasted": z["wasted"],
            "bot_rate": bot_rate,
            "wasted_rate": wasted_rate,
            "pl": pl,
            "score": score,
            "lifecycle": lifecycle,
            "min_sample_met": total >= 200,
            "integrity": zone_integrity["integrity"],
        })

    result_zones.sort(key=lambda x: x["pl"]["profit"], reverse=True)

    return {
        "summary": summary,
        "zones": result_zones,
        "generated_at": datetime.utcnow().isoformat(),
        "truncated": truncated,
        "truncated_at": SMART_REPORT_ROW_LIMIT if truncated else None,
        "warnings": _build_warnings(truncated, integrity, summary_pl),
    }


# =========================================================
# POPADS REFUND REPORT
# =========================================================
@router.get("/reports/popads-refund")
def popads_refund_report(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Report of money spent on bots from PopAds — for refund requests."""
    verify_campaign_access(campaign_id, user, db)  # M-36/C-01
    q = db.query(
        VisitModel.popads_website_id,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("bot_visits"),
        func.sum(VisitModel.bid).label("total_cost"),
        func.sum(case((VisitModel.verdict == "invalid", VisitModel.bid), else_=0.0)).label("wasted_cost"),
    ).filter(
        VisitModel.popads_website_id.isnot(None),
        VisitModel.popads_website_id != "",
    )

    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)

    rows = q.group_by(VisitModel.popads_website_id).all()

    report = []
    for r in rows:
        total = int(r.total or 0)
        bots = int(r.bot_visits or 0)
        if bots == 0:
            continue

        bot_rate = round(bots / total * 100, 2) if total > 0 else 0
        report.append({
            "website_id": r.popads_website_id,
            "total_visits": total,
            "bot_visits": bots,
            "bot_rate": bot_rate,
            "total_cost": round(float(r.total_cost or 0), 6),
            "wasted_cost": round(float(r.wasted_cost or 0), 6),
        })

    report.sort(key=lambda x: x["wasted_cost"], reverse=True)

    total_wasted = sum(x["wasted_cost"] for x in report)
    total_bots = sum(x["bot_visits"] for x in report)
    # If any suspicious website has 0 cost, BID was missing — the refund
    # number is only as good as the cost data we have.
    has_bid_gaps = any(
        x["total_cost"] == 0 and x["bot_visits"] > 0 for x in report
    )

    return {
        "summary": {
            "total_wasted_amount": round(total_wasted, 6),
            "total_bot_visits": total_bots,
            "suspicious_websites_count": len(report),
            "has_bid_gaps": has_bid_gaps,
            "note": (
                "Some suspicious websites have no BID data — wasted cost is "
                "underestimated. Configure BID capture before submitting the refund."
                if has_bid_gaps else None
            ),
        },
        "websites": report,
        "generated_at": datetime.utcnow().isoformat(),
    }


# =========================================================
# ADSTERRA PROOF REPORT
# =========================================================
@router.get("/reports/adsterra-proof")
def adsterra_proof_report(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    Traffic-quality proof to show an Adsterra manager.
    M-35: pending/other bucket is labeled pending_or_other (not unknown).
    """
    verify_campaign_access(campaign_id, user, db)
    q = db.query(VisitModel).select_from(VisitModel)
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)

    total = q.count()
    if total == 0:
        return {"error": "No data"}

    valid = q.filter(VisitModel.verdict == "valid").count()
    invalid = q.filter(VisitModel.verdict == "invalid").count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()
    # 🔑 Include unknown so the buckets sum to total
    unknown = total - valid - invalid - suspicious

    human_quality = q.filter(VisitModel.evidence.like('%HUMAN%')).count()
    total_revenue = q.with_entities(func.sum(VisitModel.revenue)).scalar() or 0.0

    return {
        "summary": {
            "total_visits": total,
            "valid_visits": valid,
            "blocked_bots": invalid,
            "suspicious_visits": suspicious,
            "pending_or_other_visits": unknown,  # M-35
            "unknown_visits": unknown,  # backward compat
            "human_traffic_rate": round(valid / total * 100, 2) if total > 0 else 0,
            "bot_block_rate": round(invalid / total * 100, 2) if total > 0 else 0,
            "unknown_rate": round(unknown / total * 100, 2) if total > 0 else 0,
            "total_revenue": round(float(total_revenue), 4),
            "human_quality_events": human_quality,
        },
        "generated_at": datetime.utcnow().isoformat(),
    }


# =========================================================
# COUNTRIES REPORT
# =========================================================
@router.get("/reports/countries")
def report_countries(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    verify_campaign_access(campaign_id, user, db)
    q = db.query(
        VisitModel.country_code,
        VisitModel.country,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    )
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.country_code, VisitModel.country).all()
    cmap = {}
    for r in rows:
        k = _country_key(r.country_code, r.country)
        if k not in cmap:
            cmap[k] = {
                "code": r.country_code or None,
                "name": r.country or "Unknown",
                "total": 0, "valid": 0, "invalid": 0, "suspicious": 0,
            }
        cmap[k]["total"] += int(r.total or 0)
        cmap[k]["valid"] += int(r.valid or 0)
        cmap[k]["invalid"] += int(r.invalid or 0)
        cmap[k]["suspicious"] += int(r.suspicious or 0)
    result = list(cmap.values())
    for c in result:
        c["bot_rate"] = round(c["invalid"] / c["total"] * 100, 1) if c["total"] else 0.0
    result.sort(key=lambda x: x["total"], reverse=True)
    return result[:30]  # M-38: was 15


# =========================================================
# TECH REPORT
# =========================================================
@router.get("/reports/tech")
def report_tech(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    def _q(col):
        q = db.query(col, VisitModel.verdict, func.count(VisitModel.id).label("count"))
        if campaign_id:
            q = q.filter(VisitModel.campaign_id == campaign_id)
        else:
            q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
        q = _apply_date_filter(q, from_date, to_date)
        return q.group_by(col, VisitModel.verdict).all()

    def _agg(rows, attr):
        m = {}
        for r in rows:
            n = getattr(r, attr, None) or "Unknown"
            if n not in m:
                m[n] = {"name": n, "total": 0, "valid": 0, "invalid": 0, "suspicious": 0}
            m[n][r.verdict] = int(r.count or 0)
            m[n]["total"] += int(r.count or 0)
        return sorted(m.values(), key=lambda x: x["total"], reverse=True)

    return {
        "devices": _agg(_q(VisitModel.device), "device"),
        "browsers": _agg(_q(VisitModel.browser), "browser"),
    }


# =========================================================
# MAP DATA
# =========================================================
@router.get("/map/visits")
def map_visits(
    campaign_id: int = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    verify_campaign_access(campaign_id, user, db)
    q = db.query(VisitModel)
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    visits = (
        q.filter(not_(and_(VisitModel.latitude == 0.0, VisitModel.longitude == 0.0)))
        .order_by(VisitModel.id.desc())
        .limit(1000)
        .all()
    )
    return [
        {
            "id": v.id,
            "lat": v.latitude,
            "lng": v.longitude,
            "verdict": v.verdict,
            "country": v.country,
            "ip": v.ip,
        }
        for v in visits
    ]


# =========================================================
# INTERNAL HELPERS
# =========================================================
def _build_integrity(total: int, with_bid: int, without_bid: int) -> dict:
    """
    Build a cost-integrity block (without needing the raw visits list).
    Mirrors `metrics.compute_cost_integrity` but for aggregate counts.
    """
    if total <= 0:
        return {
            "total_visits": 0,
            "visits_with_bid": 0,
            "visits_without_bid": 0,
            "bid_coverage_pct": 0.0,
            "integrity": "unknown",
            "message": "No visits in this dataset.",
        }

    coverage = round((with_bid / total) * 100.0, 2)

    if without_bid == 0:
        integrity = "exact"
        message = "All visits have a BID. Cost and profit are exact."
    elif (with_bid / total) >= 0.90:
        integrity = "partial"
        message = (
            f"Cost calculated from {coverage}% of visits. "
            f"{without_bid} visit(s) have no BID."
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


def _build_warnings(truncated: bool, integrity: dict, pl: dict) -> list:
    """
    User-facing warnings about the report's reliability.
    Empty list → everything is trustworthy.
    """
    warnings = []

    if truncated:
        warnings.append({
            "code": "TRUNCATED",
            "severity": "high",
            "message": (
                f"Only the first {SMART_REPORT_ROW_LIMIT:,} visits were analyzed. "
                f"Narrow the date range for accurate results."
            ),
        })

    if integrity.get("integrity") == "partial_warn":
        warnings.append({
            "code": "LOW_BID_COVERAGE",
            "severity": "high",
            "message": integrity.get("message", "BID coverage is low — cost is underestimated."),
        })
    elif integrity.get("integrity") == "partial":
        warnings.append({
            "code": "PARTIAL_BID_COVERAGE",
            "severity": "medium",
            "message": integrity.get("message", "Some visits are missing BID data."),
        })
    elif integrity.get("integrity") == "unknown":
        warnings.append({
            "code": "NO_BID",
            "severity": "medium",
            "message": integrity.get("message", "No BID data — using CPM estimation."),
        })

    if pl.get("error") == "no_sell_revenue":
        warnings.append({
            "code": "NO_SELL_CPM",
            "severity": "high",
            "message": pl.get("message", "Sell CPM is zero — profit cannot be estimated."),
        })

    return warnings