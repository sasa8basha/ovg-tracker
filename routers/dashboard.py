"""
routers/dashboard.py — Dashboard Overview (v1.0)
Single-call endpoint for the new Dashboard V2.

Replaces 15+ separate API calls with one request that returns:
    - 4 KPIs with deltas + sparklines
    - Revenue vs Cost chart series
    - Today at a glance
    - Top/Worst campaigns
    - Top zones
    - Active alerts
    - Data integrity warnings
"""
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, VisitModel, CampaignModel, SessionModel
from auth import current_user
from metrics import is_wasted_visit, _WASTED_CODES


router = APIRouter()


# =========================================================
# HELPERS
# =========================================================
def _safe_div(a, b, default=0.0):
    try:
        if b == 0:
            return default
        return float(a) / float(b)
    except (ValueError, TypeError, ZeroDivisionError):
        return default


def _pct_change(current, previous):
    """Percentage change from previous → current. Cap extreme swings (M-39)."""
    try:
        c = float(current)
        p = float(previous)
    except (ValueError, TypeError):
        return 0.0
    if abs(p) < 0.001:
        return 100.0 if abs(c) > 0.001 else 0.0
    pct = ((c - p) / abs(p)) * 100
    return round(max(-999.0, min(999.0, pct)), 2)


def _is_wasted_evidence(evidence):  # M-40/M-47: thin wrapper over shared _WASTED_CODES
    """Check evidence list for wasted codes."""
    if not isinstance(evidence, list):
        return False
    for e in evidence:
        code = None
        if isinstance(e, dict):
            code = e.get("code")
        elif isinstance(e, str):
            code = e
        if code and str(code).upper() in _WASTED_CODES:
            return True
    return False


def _integrity_block(total, with_bid, without_bid):
    """Cost integrity — how many visits actually had a BID."""
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
        message = "All visits have a BID. Cost and profit are exact."
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


def _sparkline_from_daily(daily_map, keys):
    """
    Build a sparkline array of length N from the daily aggregates.
    Missing days → 0. Sorted by date ascending.
    """
    if not daily_map:
        return [0.0] * len(keys)
    return [round(float(daily_map.get(k, 0.0)), 4) for k in keys]


# =========================================================
# MAIN ENDPOINT
# =========================================================
@router.get("/overview")
def dashboard_overview(
    period: str = Query("7d"),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    Single-call dashboard payload. Supports period=7d|30d|90d.
    """
    days = {"7d": 7, "30d": 30, "90d": 90}.get(period, 7)
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    period_start = today_start - timedelta(days=days - 1)
    prev_period_start = period_start - timedelta(days=days)
    prev_period_end = period_start

    campaign_ids = [
        r.id for r in db.query(CampaignModel.id).filter(
            CampaignModel.user_id == user.id
        ).all()
    ]

    # ---------------------------------------------------------
    # EMPTY STATE — no campaigns
    # ---------------------------------------------------------
    if not campaign_ids:
        return _empty_dashboard(period, days)

    # ---------------------------------------------------------
    # 1) AGGREGATE VISITS (current + previous)
    # ---------------------------------------------------------
    def _fetch(start, end):
        # H-04 FIX: stream via yield_per WITHOUT list() materialization
        q = db.query(
            VisitModel.campaign_id,
            VisitModel.timestamp,
            VisitModel.verdict,
            VisitModel.bid,
            VisitModel.revenue,
            VisitModel.evidence,
            VisitModel.zone_id,
            VisitModel.impressions,
        ).filter(
            VisitModel.campaign_id.in_(campaign_ids),
            VisitModel.timestamp >= start,
            VisitModel.timestamp < end,
        ).execution_options(stream_results=True).yield_per(1000)
        return q

    current_rows = _fetch(period_start, now)
    previous_rows = _fetch(prev_period_start, prev_period_end)
    today_rows = _fetch(today_start, now)

    # ---------------------------------------------------------
    # 2) AGGREGATE HELPER
    # ---------------------------------------------------------
    def _aggregate(rows):
        """Returns totals + daily buckets."""
        total = 0
        valid = 0
        invalid = 0
        suspicious = 0
        wasted = 0
        cost = 0.0
        revenue = 0.0
        impressions = 0
        with_bid = 0
        without_bid = 0
        daily = defaultdict(lambda: {"cost": 0.0, "revenue": 0.0, "profit": 0.0, "wasted": 0, "visits": 0, "valid": 0, "invalid": 0})
        by_zone = defaultdict(lambda: {"total": 0, "valid": 0, "invalid": 0, "suspicious": 0, "cost": 0.0, "revenue": 0.0, "visits_with_bid": 0, "visits_without_bid": 0})
        by_campaign = defaultdict(lambda: {"total": 0, "valid": 0, "invalid": 0, "suspicious": 0, "cost": 0.0, "revenue": 0.0, "visits_with_bid": 0, "visits_without_bid": 0, "zones": {}})  # M-43

        for r in rows:
            total += 1
            try:
                bid = float(r.bid or 0)
            except (ValueError, TypeError):
                bid = 0.0
            try:
                rev = float(r.revenue or 0)
            except (ValueError, TypeError):
                rev = 0.0
            cost += bid
            revenue += rev
            impressions += int(r.impressions or 0)

            if bid > 0:
                with_bid += 1
            else:
                without_bid += 1

            day_key = r.timestamp.strftime("%Y-%m-%d") if r.timestamp else "unknown"
            daily[day_key]["visits"] += 1
            daily[day_key]["cost"] += bid
            daily[day_key]["revenue"] += rev

            verdict = (r.verdict or "").lower()
            if verdict == "valid":
                valid += 1
                daily[day_key]["valid"] += 1
                if _is_wasted_evidence(r.evidence):
                    wasted += 1
                    daily[day_key]["wasted"] += 1
            elif verdict == "invalid":
                invalid += 1
                daily[day_key]["invalid"] += 1
            elif verdict == "suspicious":
                suspicious += 1

            # by_zone
            zid = r.zone_id or "unknown"
            z = by_zone[zid]
            z["total"] += 1
            z["cost"] += bid
            z["revenue"] += rev
            if bid > 0: z["visits_with_bid"] += 1
            else: z["visits_without_bid"] += 1
            if verdict == "valid": z["valid"] += 1
            elif verdict == "invalid": z["invalid"] += 1
            elif verdict == "suspicious": z["suspicious"] += 1

            # by_campaign
            cid = r.campaign_id
            c = by_campaign[cid]
            c["total"] += 1
            c["cost"] += bid
            c["revenue"] += rev
            if bid > 0: c["visits_with_bid"] += 1
            else: c["visits_without_bid"] += 1
            if verdict == "valid": c["valid"] += 1
            elif verdict == "invalid": c["invalid"] += 1
            elif verdict == "suspicious": c["suspicious"] += 1
            # M-43: fill per-campaign zone breakdown
            cz = c["zones"].setdefault(zid, {"total": 0, "invalid": 0})
            cz["total"] += 1
            if verdict == "invalid":
                cz["invalid"] += 1

        return {
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "suspicious": suspicious,
            "wasted": wasted,
            "cost": round(cost, 4),
            "revenue": round(revenue, 4),
            "profit": round(revenue - cost, 4),
            "impressions": impressions,
            "with_bid": with_bid,
            "without_bid": without_bid,
            "daily": dict(daily),
            "by_zone": dict(by_zone),
            "by_campaign": dict(by_campaign),
        }

    cur = _aggregate(current_rows)
    prev = _aggregate(previous_rows)
    today = _aggregate(today_rows)

    # ---------------------------------------------------------
    # 3) PERIOD DATE KEYS (for sparklines + chart series)
    # ---------------------------------------------------------
    period_dates = []
    for i in range(days):
        d = period_start + timedelta(days=i)
        period_dates.append(d.strftime("%Y-%m-%d"))

    # ---------------------------------------------------------
    # 4) BUILD 4 KPI CARDS
    # ---------------------------------------------------------
    cur_integrity = _integrity_block(cur["total"], cur["with_bid"], cur["without_bid"])

    kpis = [
        {
            "id": "cost",
            "label": "التكلفة",
            "label_en": "Spend",
            "value": cur["cost"],
            "prev_value": prev["cost"],
            "delta_pct": _pct_change(cur["cost"], prev["cost"]),
            "format": "money",
            "color": "var(--neo-danger)",
            "sparkline": _sparkline_from_daily(
                {k: v["cost"] for k, v in cur["daily"].items()},
                period_dates,
            ),
            "integrity": cur_integrity if cur["total"] > 0 else None,
        },
        {
            "id": "wasted",
            "label": "المهدور",
            "label_en": "Wasted",
            "value": cur["wasted"],
            "prev_value": prev["wasted"],
            "delta_pct": _pct_change(cur["wasted"], prev["wasted"]),
            "format": "int",
            "color": "var(--neo-warning)",
            "sparkline": _sparkline_from_daily(
                {k: v["wasted"] for k, v in cur["daily"].items()},
                period_dates,
            ),
            "integrity": None,
        },
        {
            "id": "revenue",
            "label": "الإيراد",
            "label_en": "Revenue",
            "value": cur["revenue"],
            "prev_value": prev["revenue"],
            "delta_pct": _pct_change(cur["revenue"], prev["revenue"]),
            "format": "money",
            "color": "var(--neo-success)",
            "sparkline": _sparkline_from_daily(
                {k: v["revenue"] for k, v in cur["daily"].items()},
                period_dates,
            ),
            "integrity": None,
        },
        {
            "id": "profit",
            "label": "الربح",
            "label_en": "Profit",
            "value": cur["profit"],
            "prev_value": prev["profit"],
            "delta_pct": _pct_change(cur["profit"], prev["profit"]),
            "format": "money_signed",
            "color": "var(--neo-info)" if cur["profit"] >= 0 else "var(--neo-danger)",
            "sparkline": _sparkline_from_daily(
                {k: v["revenue"] - v["cost"] for k, v in cur["daily"].items()},
                period_dates,
            ),
            "integrity": cur_integrity if cur["total"] > 0 else None,
        },
    ]

    # ---------------------------------------------------------
    # 5) CHART SERIES — Revenue vs Cost over period
    # ---------------------------------------------------------
    chart_series = []
    for dk in period_dates:
        day = cur["daily"].get(dk, {"cost": 0.0, "revenue": 0.0})
        chart_series.append({
            "date": dk,
            "cost": round(day.get("cost", 0.0), 4),
            "revenue": round(day.get("revenue", 0.0), 4),
            "profit": round(day.get("revenue", 0.0) - day.get("cost", 0.0), 4),
        })

    # ---------------------------------------------------------
    # 6) TODAY AT A GLANCE
    # ---------------------------------------------------------
    today_valid_pct = round(_safe_div(today["valid"], today["total"], 0) * 100, 1)
    today_bot_pct = round(_safe_div(today["invalid"], today["total"], 0) * 100, 1)
    today_cpm = round(_safe_div(today["revenue"], today["impressions"], 0) * 1000, 4) if today["impressions"] > 0 else round(_safe_div(today["revenue"], today["valid"], 0) * 1000, 4)

    # Top zone today
    today_top_zone = None
    if today["by_zone"]:
        zones_sorted = sorted(
            [(k, v) for k, v in today["by_zone"].items() if k != "unknown"],
            key=lambda kv: kv[1]["total"],
            reverse=True,
        )
        if zones_sorted:
            today_top_zone = {"zone": zones_sorted[0][0], "visits": zones_sorted[0][1]["total"]}

    today_glance = {
        "visits": today["total"],
        "valid_pct": today_valid_pct,
        "bot_pct": today_bot_pct,
        "cpm": today_cpm,
        "top_zone": today_top_zone,
        "profit": today["profit"],
    }

    # ---------------------------------------------------------
    # 7) TOP / WORST CAMPAIGNS
    # ---------------------------------------------------------
    campaign_lookup = {
        c.id: c for c in db.query(CampaignModel).filter(
            CampaignModel.id.in_(campaign_ids)
        ).all()
    }

    campaign_stats = []
    for cid, data in cur["by_campaign"].items():
        c = campaign_lookup.get(cid)
        if not c:
            continue
        profit = round(data["revenue"] - data["cost"], 4)
        integrity = _integrity_block(data["total"], data["visits_with_bid"], data["visits_without_bid"])
        campaign_stats.append({
            "id": cid,
            "name": c.name,
            "type": c.type,
            "status": c.status,
            "traffic_source": c.traffic_source_slug,
            "destination": c.destination_slug,
            "visits": data["total"],
            "valid": data["valid"],
            "invalid": data["invalid"],
            "profit": profit,
            "revenue": round(data["revenue"], 4),
            "cost": round(data["cost"], 4),
            "integrity": integrity["integrity"],
            "bid_coverage": integrity["bid_coverage_pct"],
        })

    profitable = sorted(
        [c for c in campaign_stats if c["profit"] > 0.01 and c["visits"] > 0],
        key=lambda x: x["profit"],
        reverse=True,
    )[:5]

    losing = sorted(
        [c for c in campaign_stats if c["profit"] < -0.01 and c["visits"] > 0],
        key=lambda x: x["profit"],
    )[:5]

    # ---------------------------------------------------------
    # 8) TOP ZONES
    # ---------------------------------------------------------
    zone_stats = []
    for zid, data in cur["by_zone"].items():
        if zid == "unknown" or data["total"] < 5:
            continue
        profit = round(data["revenue"] - data["cost"], 4)
        bot_rate = round(_safe_div(data["invalid"], data["total"], 0) * 100, 1)
        # Grade
        if data["total"] < 10:
            grade = "?"
        elif bot_rate < 5:
            grade = "A"
        elif bot_rate < 15:
            grade = "B"
        elif bot_rate < 30:
            grade = "C"
        else:
            grade = "F"
        zone_stats.append({
            "zone": zid,
            "visits": data["total"],
            "valid": data["valid"],
            "bot_rate": bot_rate,
            "profit": profit,
            "grade": grade,
        })

    top_zones = sorted(zone_stats, key=lambda x: x["profit"], reverse=True)[:5]

    # ---------------------------------------------------------
    # 9) ALERTS
    # ---------------------------------------------------------
    alerts = []

    # Bot wave
    if today_bot_pct >= 30 and today["total"] >= 20:
        alerts.append({
            "id": "bot_wave",
            "severity": "critical",
            "icon": "🚨",
            "title": "ارتفاع حاد في البوتات",
            "message": f"{today_bot_pct}% بوت اليوم ({today['invalid']} من {today['total']})",
            "action_label": "راجع الزيارات",
            "action_href": "/visits?verdict=invalid",
        })
    elif today_bot_pct >= 15 and today["total"] >= 20:
        alerts.append({
            "id": "bot_spike",
            "severity": "warn",
            "icon": "⚠️",
            "title": "ارتفاع في البوتات",
            "message": f"{today_bot_pct}% بوت اليوم",
            "action_label": "راجع",
            "action_href": "/zone-analytics",
        })

    # BID coverage
    if cur_integrity["integrity"] == "partial_warn":
        alerts.append({
            "id": "low_bid_coverage",
            "severity": "warn",
            "icon": "💸",
            "title": "تغطية BID منخفضة",
            "message": f"فقط {cur_integrity['bid_coverage_pct']}% من الزيارات فيها BID — التكلفة والربح أقل من الحقيقة",
            "action_label": "راجع الحملات",
            "action_href": "/campaigns",
        })

    # Adsterra sync check
    # M-42: revenue>0 alone misses campaigns with legit zero revenue; also check any revenue field set
    last_sync = db.query(func.max(VisitModel.timestamp)).filter(
        VisitModel.campaign_id.in_(campaign_ids),
        VisitModel.revenue.isnot(None),
    ).scalar()
    if last_sync:
        sync_age_h = (now - last_sync).total_seconds() / 3600
        if sync_age_h > 24:
            alerts.append({
                "id": "sync_stale",
                "severity": "critical",
                "icon": "🔄",
                "title": "مزامنة Adsterra متوقفة",
                "message": f"آخر تحديث من {int(sync_age_h)} ساعة — راجع الـ API key",
                "action_label": "راجع الإعدادات",
                "action_href": "/system-health",
            })
    elif campaign_ids:
        # no revenue field ever set → likely never synced
        alerts.append({
            "id": "sync_never",
            "severity": "warn",
            "icon": "🔄",
            "title": "لا توجد مزامنة Adsterra",
            "message": "لم يُسجَّل revenue لأي زيارة — راجع الـ API key أو انتظر أول sync",
            "action_label": "راجع الإعدادات",
            "action_href": "/system-health",
        })

    # Losing campaigns
    if losing and abs(losing[0]["profit"]) > 5:
        alerts.append({
            "id": "losing_campaign",
            "severity": "warn",
            "icon": "📉",
            "title": "حملة بتخسر",
            "message": f"{losing[0]['name']} — خسارة {abs(losing[0]['profit']):.2f}$",
            "action_label": "افتح الحملة",
            "action_href": f"/campaigns/{losing[0]['id']}",
        })

    # ---------------------------------------------------------
    # 10) RETURN
    # ---------------------------------------------------------
    return {
        "period": period,
        "days": days,
        "period_start": period_start.isoformat(),
        "period_end": now.isoformat(),
        "generated_at": now.isoformat(),

        "kpis": kpis,
        "chart_series": chart_series,
        "today_glance": today_glance,

        "top_campaigns": profitable,
        "worst_campaigns": losing,
        "top_zones": top_zones,

        "alerts": alerts,
        "integrity": cur_integrity,
        "summary": {
            "total_visits": cur["total"],
            "valid_visits": cur["valid"],
            "invalid_visits": cur["invalid"],
            "suspicious_visits": cur["suspicious"],
            "wasted_visits": cur["wasted"],
            "total_cost": cur["cost"],
            "total_revenue": cur["revenue"],
            "total_profit": cur["profit"],
            "bot_rate": round(_safe_div(cur["invalid"], cur["total"], 0) * 100, 1),
        },
    }


def _empty_dashboard(period, days):
    """Return a properly-shaped empty payload when no campaigns exist."""
    return {
        "period": period,
        "days": days,
        "generated_at": datetime.utcnow().isoformat(),
        "kpis": [
            {"id": "cost", "label": "التكلفة", "label_en": "Spend", "value": 0, "prev_value": 0, "delta_pct": 0, "format": "money", "color": "var(--neo-danger)", "sparkline": [0]*days, "integrity": None},
            {"id": "wasted", "label": "المهدور", "label_en": "Wasted", "value": 0, "prev_value": 0, "delta_pct": 0, "format": "int", "color": "var(--neo-warning)", "sparkline": [0]*days, "integrity": None},
            {"id": "revenue", "label": "الإيراد", "label_en": "Revenue", "value": 0, "prev_value": 0, "delta_pct": 0, "format": "money", "color": "var(--neo-success)", "sparkline": [0]*days, "integrity": None},
            {"id": "profit", "label": "الربح", "label_en": "Profit", "value": 0, "prev_value": 0, "delta_pct": 0, "format": "money_signed", "color": "var(--neo-info)", "sparkline": [0]*days, "integrity": None},
        ],
        "chart_series": [{"date": "", "cost": 0, "revenue": 0, "profit": 0}],
        "today_glance": {"visits": 0, "valid_pct": 0, "bot_pct": 0, "cpm": 0, "top_zone": None, "profit": 0},
        "top_campaigns": [],
        "worst_campaigns": [],
        "top_zones": [],
        "alerts": [],
        "integrity": {"integrity": "unknown", "message": "No campaigns yet."},
        "summary": {"total_visits": 0, "valid_visits": 0, "invalid_visits": 0, "suspicious_visits": 0, "wasted_visits": 0, "total_cost": 0, "total_revenue": 0, "total_profit": 0, "bot_rate": 0},
    }