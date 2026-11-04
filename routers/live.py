"""
routers/live.py — Live Monitor API.

Endpoints:
  GET /api/live/feed    — new visits since last_id (polling, 2s)
  GET /api/live/stats   — today totals + last-minute rate
  GET /api/live/alerts  — active alerts (computed on the fly)
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, SiteModel, VisitModel
from auth import current_user
from helpers import _resolve_user_site

router = APIRouter()


@router.get("/live/feed")
def live_feed(
    site: str = Query(None),
    since_id: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=50),
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
    if since_id > 0:
        q = q.filter(VisitModel.id > since_id)

    visits = q.order_by(VisitModel.id.desc()).limit(limit).all()

    items = []
    for v in visits:
        items.append({
            "id": v.id,
            "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
            "ip": v.ip,
            "zone": v.zone_id,
            "verdict": v.verdict,
            "score": v.score,
            "country": v.country,
            "country_code": v.country_code,
            "browser": v.browser,
            "device": v.device,
        })

    latest_id = max([v.id for v in visits], default=since_id)

    return {
        "items": items,
        "latest_id": latest_id,
        "count": len(items),
    }


@router.get("/live/stats")
def live_stats(
    site: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    minute_ago = now - timedelta(minutes=1)
    hour_ago = now - timedelta(hours=1)

    def _base():
        q = db.query(VisitModel)
        if site:
            s = _resolve_user_site(site, user, db)
            q = q.filter(VisitModel.site_id == s.id)
        else:
            q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
                SiteModel.user_id == user.id
            )
        return q

    today_agg = _base().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
    ).filter(VisitModel.timestamp >= today_start).one()

    today_total = int(today_agg.total or 0)
    today_invalid = int(today_agg.invalid or 0)
    today_valid = int(today_agg.valid or 0)
    today_bot_rate = round(today_invalid / today_total * 100, 1) if today_total > 0 else 0.0

    last_min = _base().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
    ).filter(VisitModel.timestamp >= minute_ago).one()

    last_min_total = int(last_min.total or 0)
    last_min_invalid = int(last_min.invalid or 0)

    last_hour = _base().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
    ).filter(VisitModel.timestamp >= hour_ago).one()

    last_hour_total = int(last_hour.total or 0)
    last_hour_invalid = int(last_hour.invalid or 0)

    return {
        "today": {
            "total": today_total,
            "valid": today_valid,
            "invalid": today_invalid,
            "bot_rate": today_bot_rate,
        },
        "last_minute": {
            "total": last_min_total,
            "invalid": last_min_invalid,
        },
        "last_hour": {
            "total": last_hour_total,
            "invalid": last_hour_invalid,
        },
        "computed_at": now.isoformat(),
    }


@router.get("/live/alerts")
def live_alerts(
    site: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    alerts = []
    now = datetime.utcnow()

    def _base():
        q = db.query(VisitModel)
        if site:
            s = _resolve_user_site(site, user, db)
            q = q.filter(VisitModel.site_id == s.id)
        else:
            q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
                SiteModel.user_id == user.id
            )
        return q

    # Bot wave in last 5 minutes (most urgent)
    five_min_ago = now - timedelta(minutes=5)
    recent_agg = _base().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
    ).filter(VisitModel.timestamp >= five_min_ago).one()

    recent_total = int(recent_agg.total or 0)
    recent_invalid = int(recent_agg.invalid or 0)

    if recent_invalid >= 5:
        alerts.append({
            "id": "bot_wave_now",
            "severity": "critical",
            "icon": "🔥",
            "title": "هجوم بوتات الآن",
            "message": f"{recent_invalid} بوت في آخر 5 دقايق (من {recent_total} زيارة)",
            "action_label": "شوف الزيارات",
            "action_href": ("/visits?verdict=invalid" + (f"&site={site}" if site else "")),
        })

    # Bot spike in last hour
    hour_ago = now - timedelta(hours=1)
    hour_agg = _base().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
    ).filter(VisitModel.timestamp >= hour_ago).one()

    hour_total = int(hour_agg.total or 0)
    hour_invalid = int(hour_agg.invalid or 0)

    if hour_total >= 20:
        hour_bot_rate = (hour_invalid / hour_total) * 100
        if hour_bot_rate >= 50:
            alerts.append({
                "id": "bot_spike_high",
                "severity": "critical",
                "icon": "🚨",
                "title": "ارتفاع حاد في البوتات",
                "message": f"{hour_bot_rate:.0f}% بوت في آخر ساعة ({hour_invalid} من {hour_total})",
                "action_label": "راجع",
                "action_href": ("/smart-reports" + (f"?site={site}" if site else "")),
            })
        elif hour_bot_rate >= 30:
            alerts.append({
                "id": "bot_spike_medium",
                "severity": "high",
                "icon": "⚠️",
                "title": "ارتفاع في البوتات",
                "message": f"{hour_bot_rate:.0f}% بوت في آخر ساعة",
                "action_label": "راجع",
                "action_href": ("/zone-analytics" + (f"?site={site}" if site else "")),
            })

    # Traffic death (sudden drop)
    hour_before_agg = _base().with_entities(
        func.count(VisitModel.id).label("total"),
    ).filter(
        VisitModel.timestamp >= (hour_ago - timedelta(hours=1)),
        VisitModel.timestamp < hour_ago,
    ).one()
    hour_before_total = int(hour_before_agg.total or 0)

    if hour_before_total >= 20 and hour_total < (hour_before_total * 0.3):
        alerts.append({
            "id": "traffic_death",
            "severity": "high",
            "icon": "📉",
            "title": "هبوط مفاجئ في الترافيك",
            "message": f"الزيارات نزلت من {hour_before_total} لـ {hour_total} في آخر ساعة",
            "action_label": "راجع",
            "action_href": ("/radar" + (f"?site={site}" if site else "")),
        })

    return {"alerts": alerts, "count": len(alerts), "computed_at": now.isoformat()}
