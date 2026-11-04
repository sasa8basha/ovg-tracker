"""
routers/data_quality.py — Data completeness monitoring.
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, SiteModel, VisitModel
from auth import current_user
from helpers import _resolve_user_site, _apply_date_filter

router = APIRouter()


def _get_completeness_checks():
    canvas_invalid_values = ["", "Unknown", "Unknown...", "blocked", "blocked...", "Mock", "Mock..."]
    asn_invalid_values = ["", "Unknown", "N/A"]
    country_invalid_values = ["", "Unknown", "Local"]
    timezone_invalid_values = ["", "Unknown"]
    isp_invalid_values = ["", "Unknown"]
    hardware_invalid_values = ["", "Unknown", "0 cores / 0 GB"]
    webrtc_invalid_values = ["", "Unknown"]

    return [
        ("canvas_hash", lambda q: q.filter(
            VisitModel.canvas_hash.isnot(None),
            VisitModel.canvas_hash.notin_(canvas_invalid_values),
        ).count(), 20),
        ("asn", lambda q: q.filter(
            VisitModel.asn.isnot(None),
            VisitModel.asn.notin_(asn_invalid_values),
        ).count(), 15),
        ("country", lambda q: q.filter(
            VisitModel.country.isnot(None),
            VisitModel.country.notin_(country_invalid_values),
        ).count(), 15),
        ("timezone", lambda q: q.filter(
            VisitModel.timezone.isnot(None),
            VisitModel.timezone.notin_(timezone_invalid_values),
        ).count(), 10),
        ("isp", lambda q: q.filter(
            VisitModel.isp.isnot(None),
            VisitModel.isp.notin_(isp_invalid_values),
        ).count(), 10),
        ("hardware", lambda q: q.filter(
            VisitModel.hardware.isnot(None),
            VisitModel.hardware.notin_(hardware_invalid_values),
        ).count(), 10),
        ("webrtc_ip", lambda q: q.filter(
            VisitModel.webrtc_ip.isnot(None),
            VisitModel.webrtc_ip.notin_(webrtc_invalid_values),
        ).count(), 10),
        ("evidence", lambda q: q.filter(VisitModel.evidence.isnot(None)).count(), 10),
    ]


def _score_label(score):
    if score >= 95:
        return "excellent"
    if score >= 85:
        return "good"
    if score >= 70:
        return "fair"
    if score >= 50:
        return "poor"
    return "critical"


@router.get("/data-quality/overview")
def data_quality_overview(
    site: str = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    q = _apply_date_filter(q, from_date, to_date)

    total = q.count()
    if total == 0:
        return {"total": 0, "fields": [], "score": 0.0,
                "score_label": "critical", "note": "no_data"}

    fields = []
    weighted_sum = 0.0
    weight_total = 0

    for field_name, count_fn, weight in _get_completeness_checks():
        try:
            valid = count_fn(q)
            if valid > total:
                valid = total
            if valid < 0:
                valid = 0
            invalid = total - valid
            completeness = round(valid / total * 100, 2) if total > 0 else 0.0
            fields.append({
                "field": field_name, "valid": valid, "invalid": invalid,
                "total": total, "completeness": completeness,
                "weight": weight, "reliable": total >= 30,
            })
            weighted_sum += completeness * weight
            weight_total += weight
        except Exception as e:
            print(f"[DQ] field '{field_name}' failed: {e}")
            fields.append({
                "field": field_name,
                "valid": None, "invalid": None, "total": total,
                "completeness": None, "weight": weight,
                "reliable": False, "error": True,
            })

    overall = round(weighted_sum / weight_total, 2) if weight_total > 0 else 0.0

    return {
        "total": total, "fields": fields, "score": overall,
        "score_label": _score_label(overall), "note": "ok",
    }


@router.get("/data-quality/timeline")
def data_quality_timeline(
    site: str = Query(None),
    days: int = Query(30, ge=1, le=90),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(days=days)
    day_col = func.date(VisitModel.timestamp).label("day")

    canvas_ok_expr = case(
        (VisitModel.canvas_hash.isnot(None)
         & VisitModel.canvas_hash.notin_(["", "Unknown", "Unknown...", "blocked", "blocked...", "Mock", "Mock..."]), 1),
        else_=0,
    )
    asn_ok_expr = case(
        (VisitModel.asn.isnot(None) & VisitModel.asn.notin_(["", "Unknown", "N/A"]), 1),
        else_=0,
    )

    q = db.query(
        day_col,
        func.count(VisitModel.id).label("total"),
        func.sum(canvas_ok_expr).label("canvas_ok"),
        func.sum(asn_ok_expr).label("asn_ok"),
    )
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    q = q.filter(VisitModel.timestamp >= cutoff)
    q = q.group_by(day_col).order_by(day_col)
    rows = q.all()

    timeline = []
    for r in rows:
        t = int(r.total or 0)
        if t == 0:
            continue
        timeline.append({
            "day": str(r.day),
            "total": t,
            "canvas_completeness": round(int(r.canvas_ok or 0) / t * 100, 1),
            "asn_completeness": round(int(r.asn_ok or 0) / t * 100, 1),
        })
    return {"timeline": timeline, "days": days}


@router.get("/data-quality/collector-rate")
def data_quality_collector_rate(
    site: str = Query(None),
    hours: int = Query(24, ge=1, le=168),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    baseline_cutoff = datetime.utcnow() - timedelta(days=7)
    hour_col = func.strftime("%Y-%m-%d %H:00", VisitModel.timestamp)

    q = db.query(hour_col.label("hour"), func.count(VisitModel.id).label("count"))
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    q = q.filter(VisitModel.timestamp >= cutoff)
    q = q.group_by(hour_col).order_by(hour_col)
    rows = q.all()
    series = [{"hour": str(r.hour), "count": int(r.count)} for r in rows]

    bq = db.query(func.count(VisitModel.id))
    if site:
        bq = bq.filter(VisitModel.site_id == _resolve_user_site(site, user, db).id)
    else:
        bq = bq.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    total_7d = bq.filter(VisitModel.timestamp >= baseline_cutoff).scalar() or 0
    baseline_per_hour = round(total_7d / (7 * 24), 2) if total_7d else 0.0

    last_hour_count = series[-1]["count"] if series else 0
    health = "ok"
    if baseline_per_hour > 0:
        if last_hour_count < baseline_per_hour * 0.5:
            health = "critical"
        elif last_hour_count < baseline_per_hour * 0.8:
            health = "degraded"

    return {
        "series": series,
        "baseline_per_hour": baseline_per_hour,
        "last_hour_count": last_hour_count,
        "health": health,
        "hours": hours,
  }
