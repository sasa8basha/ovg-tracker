"""
routers/zones_analytics.py — Zone Time-Series + Anomaly Detection.
"""
from datetime import datetime, timedelta
from statistics import mean, pstdev
from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session
from database import get_db
from models import UserModel, VisitModel, CampaignModel
from auth import current_user

router = APIRouter()

def _daily_series(db, campaign_id, zone_id, days=14):
    cutoff = datetime.utcnow() - timedelta(days=days)
    day_col = func.date(VisitModel.timestamp).label("day")
    q = db.query(day_col, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).filter(VisitModel.timestamp >= cutoff)
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    if zone_id: q = q.filter(VisitModel.zone_id == zone_id)
    q = q.group_by(day_col).order_by(day_col)
    rows = q.all()
    series = []
    for r in rows:
        total = int(r.total or 0)
        if total == 0: continue
        invalid = int(r.invalid or 0)
        series.append({"day": str(r.day), "total": total, "invalid": invalid, "bot_rate": round(invalid / total * 100, 2)})
    return series

def _compute_baseline(daily_series, exclude_last_days=1):
    if not daily_series: return None
    usable = daily_series[:-exclude_last_days] if exclude_last_days > 0 else daily_series
    usable = [d for d in usable if d["total"] >= 5]
    if len(usable) < 3: return None
    rates = [d["bot_rate"] for d in usable]; total_visits = sum(d["total"] for d in usable)
    if total_visits < 100: return None
    m = mean(rates); std = pstdev(rates) if len(rates) > 1 else 0.0
    return {"mean": round(m, 2), "std": round(std, 2), "sample_days": len(usable), "sample_visits": total_visits}

def _compute_current(db, campaign_id, zone_id, hours=1):
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).filter(VisitModel.timestamp >= cutoff)
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    if zone_id: q = q.filter(VisitModel.zone_id == zone_id)
    r = q.first()
    if not r: return None
    total = int(r.total or 0)
    if total < 20: return None
    invalid = int(r.invalid or 0)
    return {"total": total, "invalid": invalid, "bot_rate": round(invalid / total * 100, 2), "hours": hours}

def _compute_trend(daily_series):
    if len(daily_series) < 5: return {"slope": 0.0, "direction": "unknown", "confidence": "low"}
    n = len(daily_series); xs = list(range(n)); ys = [d["bot_rate"] for d in daily_series]
    x_mean = mean(xs); y_mean = mean(ys)
    num = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys)); den = sum((x - x_mean) ** 2 for x in xs)
    if den == 0: return {"slope": 0.0, "direction": "stable", "confidence": "low"}
    slope = num / den; direction = "stable"
    if slope > 0.5: direction = "rising"
    elif slope < -0.5: direction = "falling"
    return {"slope": round(slope, 2), "direction": direction, "confidence": "high" if n >= 10 else "medium" if n >= 7 else "low"}

def _compute_anomaly(baseline, current):
    if not baseline or not current: return None
    std = baseline["std"]
    if std < 1.0: std = 1.0
    z = (current["bot_rate"] - baseline["mean"]) / std
    severity = None
    if z >= 3.0: severity = "critical"
    elif z >= 2.5: severity = "high"
    elif z >= 2.0: severity = "medium"
    elif z <= -3.0: severity = "critical_drop"
    elif z <= -2.5: severity = "high_drop"
    elif z <= -2.0: severity = "medium_drop"
    return {"z_score": round(z, 2), "severity": severity, "direction": "spike" if z > 0 else "drop"}

@router.get("/zones/analytics")
def zones_analytics(campaign_id: int = Query(None), days: int = Query(14, ge=7, le=90), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(days=days)
    q = db.query(VisitModel.zone_id, func.count(VisitModel.id).label("n"))
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = q.filter(VisitModel.timestamp >= cutoff, VisitModel.zone_id.isnot(None), VisitModel.zone_id != "unknown").group_by(VisitModel.zone_id).having(func.count(VisitModel.id) >= 20)
    zones_list = q.all()
    
    zones = []; anomalies = []
    for z in zones_list:
        zone_id = z.zone_id
        series = _daily_series(db, campaign_id, zone_id, days)
        baseline = _compute_baseline(series); trend = _compute_trend(series)
        current = _compute_current(db, campaign_id, zone_id, hours=1)
        anomaly = _compute_anomaly(baseline, current) if baseline and current else None
        zones.append({"zone": zone_id, "series": series, "baseline": baseline, "trend": trend, "current": current, "anomaly": anomaly, "insufficient_data": not baseline})
        if anomaly and anomaly["severity"] and anomaly["severity"] not in ("medium_drop",):
            anomalies.append({"zone": zone_id, "anomaly": anomaly, "baseline_mean": baseline["mean"], "current_rate": current["bot_rate"], "current_visits": current["total"]})
    
    sev_order = {"critical": 0, "high": 1, "medium": 2, "critical_drop": 3, "high_drop": 4, "medium_drop": 5}
    zones.sort(key=lambda z: (sev_order.get(z["anomaly"]["severity"] if z["anomaly"] else None, 99), -abs(z["trend"]["slope"])))
    return {"zones": zones, "anomalies": anomalies, "days": days, "generated_at": datetime.utcnow().isoformat()}

@router.get("/zones/{zone}/time-series")
def zone_time_series(zone: str, campaign_id: int = Query(None), days: int = Query(14, ge=7, le=90), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    if not campaign_id:
        c_check = db.query(CampaignModel).filter(CampaignModel.user_id == user.id).first()
        if not c_check: return {"zone": zone, "series": [], "baseline": None, "trend": None, "current": None, "anomaly": None}
    series = _daily_series(db, campaign_id, zone, days)
    return {"zone": zone, "series": series, "baseline": _compute_baseline(series), "trend": _compute_trend(series), "current": _compute_current(db, campaign_id, zone, hours=1), "anomaly": None}

@router.get("/zones/anomalies")
def zones_anomalies(campaign_id: int = Query(None), hours: int = Query(24, ge=1, le=168), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    result = zones_analytics(campaign_id=campaign_id, days=14, user=user, db=db)
    return {"anomalies": result["anomalies"], "generated_at": result["generated_at"], "hours": hours}
