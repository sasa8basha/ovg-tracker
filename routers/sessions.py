"""
routers/sessions.py — Session Analytics (Phase 1.4)

Endpoints:
  GET /api/sessions              — list with filters + pagination
  GET /api/sessions/{session_id} — detail + heartbeats timeline
  GET /api/sessions/compare/stats — v2 vs v3 comparison

بيستخدم SessionModel, VisitHeartbeatModel, VisitModel.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import (
    UserModel, SiteModel, VisitModel,
    SessionModel, VisitHeartbeatModel, CampaignModel,
)
from auth import current_user
from helpers import _resolve_user_site

router = APIRouter()


# =========================================================
# HELPERS
# =========================================================
def _parse_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(str(s).strip(), "%Y-%m-%d")
    except (ValueError, TypeError):
        return None


def _human_duration(ms):
    if ms is None or ms <= 0:
        return None
    s = int(ms / 1000)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


# =========================================================
# LIST
# =========================================================
@router.get("")
def list_sessions(
    site: str = Query(None),
    campaign_id: int = Query(None),
    data_quality: str = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(SessionModel).filter(SessionModel.user_id == user.id)

    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(SessionModel.site_id == s.id)
    if campaign_id:
        q = q.filter(SessionModel.campaign_id == campaign_id)
    if data_quality:
        q = q.filter(SessionModel.data_quality == data_quality)

    fd = _parse_date(from_date)
    if fd:
        q = q.filter(SessionModel.started_at >= fd)
    td = _parse_date(to_date)
    if td:
        q = q.filter(SessionModel.started_at < (td + timedelta(days=1)))

    total = q.count()
    sessions = q.order_by(SessionModel.started_at.desc()).offset(
        (page - 1) * per_page
    ).limit(per_page).all()

    if not sessions:
        return {
            "items": [], "total": total,
            "page": page, "per_page": per_page, "pages": 0,
        }

    session_ids = [s.session_id for s in sessions]

    # Heartbeats count (single query)
    hb_rows = db.query(
        VisitHeartbeatModel.session_id,
        func.count(VisitHeartbeatModel.id).label("n"),
    ).filter(
        VisitHeartbeatModel.session_id.in_(session_ids),
    ).group_by(VisitHeartbeatModel.session_id).all()
    hb_counts = {r.session_id: int(r.n or 0) for r in hb_rows}

    # Visit info (single query)
    visit_rows = db.query(
        VisitModel.session_id,
        VisitModel.verdict,
        VisitModel.score,
        VisitModel.time_on_page,
        VisitModel.country,
        VisitModel.country_code,
        VisitModel.device,
        VisitModel.browser,
        VisitModel.os,
    ).filter(
        VisitModel.session_id.in_(session_ids),
    ).all()
    visit_info = {}
    for v in visit_rows:
        visit_info[v.session_id] = {
            "verdict": v.verdict,
            "score": v.score,
            "time_on_page": v.time_on_page,
            "country": v.country,
            "country_code": v.country_code,
            "device": v.device,
            "browser": v.browser,
            "os": v.os,
        }

    items = []
    for s in sessions:
        v = visit_info.get(s.session_id, {})
        duration_ms = None
        if s.ended_at and s.started_at:
            duration_ms = int((s.ended_at - s.started_at).total_seconds() * 1000)
        elif s.total_time_ms:
            duration_ms = s.total_time_ms
        elif s.started_at:
            duration_ms = int((datetime.utcnow() - s.started_at).total_seconds() * 1000)

        items.append({
            "session_id": s.session_id,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            "duration_ms": duration_ms,
            "duration_human": _human_duration(duration_ms),
            "heartbeats": hb_counts.get(s.session_id, 0),
            "data_quality": s.data_quality or "unknown",
            "verdict": v.get("verdict") or s.verdict,
            "score": v.get("score") if v.get("score") is not None else s.score,
            "country": v.get("country") or "",
            "country_code": v.get("country_code") or s.country_code,
            "device": v.get("device") or "",
            "browser": v.get("browser") or "",
            "os": v.get("os") or "",
            "ip": s.ip,
            "campaign_id": s.campaign_id,
            "site_id": s.site_id,
            "has_visit": s.visit_id is not None,
        })

    pages = (total + per_page - 1) // per_page if total else 0
    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


# =========================================================
# DETAIL
# =========================================================
@router.get("/{session_id}")
def get_session_detail(
    session_id: str,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    s = db.query(SessionModel).filter(
        SessionModel.session_id == session_id,
        SessionModel.user_id == user.id,
    ).first()
    if not s:
        raise HTTPException(404, "Session not found")

    hbs = db.query(VisitHeartbeatModel).filter(
        VisitHeartbeatModel.session_id == session_id,
    ).order_by(VisitHeartbeatModel.seq.asc()).all()

    heartbeat_items = []
    prev_t = 0
    for hb in hbs:
        gap_ms = None
        if prev_t and hb.t_ms and hb.t_ms > prev_t:
            gap_ms = hb.t_ms - prev_t
        heartbeat_items.append({
            "seq": hb.seq,
            "received_at": hb.received_at.isoformat() if hb.received_at else None,
            "t_ms": hb.t_ms,
            "t_human": _human_duration(hb.t_ms),
            "gap_ms": gap_ms,
            "clicks": hb.clicks,
            "scrolls": hb.scrolls,
            "mousemoves": hb.mousemoves,
            "keydowns": hb.keydowns,
            "is_visible": bool(hb.is_visible),
            "is_focused": bool(hb.is_focused),
        })
        if hb.t_ms:
            prev_t = hb.t_ms

    visit = None
    if s.visit_id:
        v = db.query(VisitModel).get(s.visit_id)
        if v:
            visit = {
                "id": v.id,
                "verdict": v.verdict,
                "score": v.score,
                "time_on_page": v.time_on_page,
                "time_on_page_human": _human_duration(v.time_on_page),
                "clicks": v.clicks,
                "scrolls": v.scrolls,
                "country": v.country,
                "country_code": v.country_code,
                "os": v.os,
                "device": v.device,
                "browser": v.browser,
                "isp": v.isp,
                "asn": v.asn,
                "is_vpn": bool(v.is_vpn),
                "timezone": v.timezone,
                "canvas_hash": v.canvas_hash,
                "hardware": v.hardware,
                "behavioral": v.behavioral,
                "milestones": v.milestones,
                "first_30s": v.first_30s,
                "ad_events": v.ad_events,
                "evidence": v.evidence,
                "data_quality": v.data_quality,
                "is_honeypot_triggered": bool(v.is_honeypot_triggered),
                "clock_drift_ms": v.clock_drift_ms,
                "consent_state": v.consent_state,
            }

    duration_ms = None
    if s.ended_at and s.started_at:
        duration_ms = int((s.ended_at - s.started_at).total_seconds() * 1000)
    elif s.total_time_ms:
        duration_ms = s.total_time_ms

    return {
        "session_id": s.session_id,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "ended_at": s.ended_at.isoformat() if s.ended_at else None,
        "last_heartbeat_at": s.last_heartbeat_at.isoformat() if s.last_heartbeat_at else None,
        "duration_ms": duration_ms,
        "duration_human": _human_duration(duration_ms),
        "total_heartbeats": s.total_heartbeats or 0,
        "total_time_ms": s.total_time_ms or 0,
        "ip": s.ip,
        "country_code": s.country_code,
        "user_agent": s.user_agent,
        "url": s.url,
        "data_quality": s.data_quality,
        "consent_state": s.consent_state,
        "clock_drift_ms": s.clock_drift_ms,
        "is_honeypot_triggered": bool(s.is_honeypot_triggered),
        "visitor_fp_hash": s.visitor_fp_hash,
        "campaign_id": s.campaign_id,
        "site_id": s.site_id,
        "verdict": s.verdict,
        "score": s.score,
        "meta": s.meta,
        "heartbeats": heartbeat_items,
        "visit": visit,
    }


# =========================================================
# COMPARE (v2 vs v3)
# =========================================================
@router.get("/compare/stats")
def compare_stats(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    site_ids = [r.id for r in db.query(SiteModel.id).filter(
        SiteModel.user_id == user.id
    ).all()]

    if not site_ids:
        return {
            "groups": [],
            "v2_fixed_2000ms_ratio": None,
            "has_v2_data": False,
            "has_v3_data": False,
            "diagnostic": "no_data",
            "recommendation": "أضف موقع وركّب كود التتبع الأول.",
        }

    rows = db.query(
        VisitModel.data_quality,
        func.count(VisitModel.id).label("n"),
        func.avg(VisitModel.time_on_page).label("avg_time"),
        func.min(VisitModel.time_on_page).label("min_time"),
        func.max(VisitModel.time_on_page).label("max_time"),
    ).filter(
        VisitModel.site_id.in_(site_ids),
    ).group_by(VisitModel.data_quality).all()

    groups = []
    v2_count = 0
    v3_count = 0
    for r in rows:
        dq = r.data_quality or "unknown"
        n = int(r.n or 0)
        if dq == "legacy":
            v2_count = n
        elif dq in ("full", "partial"):
            v3_count += n

        groups.append({
            "data_quality": dq,
            "count": n,
            "avg_time_ms": round(float(r.avg_time or 0)),
            "avg_time_human": _human_duration(float(r.avg_time or 0)),
            "min_time_ms": int(r.min_time or 0),
            "max_time_ms": int(r.max_time or 0),
        })

    # نسبة v2 اللي عندها 2000ms بالظبط
    v2_fixed_ratio = None
    if v2_count > 0:
        exactly_2000 = db.query(func.count(VisitModel.id)).filter(
            VisitModel.site_id.in_(site_ids),
            VisitModel.data_quality == "legacy",
            VisitModel.time_on_page == 2000,
        ).scalar() or 0
        v2_fixed_ratio = round(exactly_2000 / v2_count * 100, 1)

    # Diagnostic
    diagnostic = "insufficient"
    recommendation = ""
    if v3_count == 0 and v2_count == 0:
        diagnostic = "no_data"
        recommendation = "مفيش زيارات لسه. ركّب الكود واختبر."
    elif v3_count == 0:
        diagnostic = "v2_only"
        recommendation = "كل الزيارات legacy (v2). ركّب كود v3 الجديد عشان تبدأ تحصل على بيانات حقيقية."
    elif v2_count == 0:
        diagnostic = "v3_only"
        recommendation = "ممتاز — كل الزيارات بقت v3. البيانات موثوقة."
    else:
        diagnostic = "mixed"
        if v2_fixed_ratio is not None and v2_fixed_ratio >= 80:
            recommendation = (
                f"مؤكد: {v2_fixed_ratio}% من زيارات v2 على 2000ms بالظبط (الباج). "
                "زيارات v3 بتظهر أوقات متنوعة — الإصلاح شغال."
            )
        else:
            recommendation = "فيه خليط بين v2 و v3. راقب النسبة خلال الأيام الجاية."

    return {
        "groups": groups,
        "v2_fixed_2000ms_ratio": v2_fixed_ratio,
        "has_v2_data": v2_count > 0,
        "has_v3_data": v3_count > 0,
        "v2_count": v2_count,
        "v3_count": v3_count,
        "diagnostic": diagnostic,
        "recommendation": recommendation,
    }


# =========================================================
# QUICK STATS
# =========================================================
@router.get("/overview/stats")
def overview_stats(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    site_ids = [r.id for r in db.query(SiteModel.id).filter(
        SiteModel.user_id == user.id
    ).all()]

    if not site_ids:
        return {
            "sessions_total": 0,
            "sessions_24h": 0,
            "sessions_active": 0,
            "visits_total": 0,
            "heartbeats_total": 0,
        }

    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    cutoff_active = datetime.utcnow() - timedelta(minutes=5)

    sessions_total = db.query(func.count(SessionModel.id)).filter(
        SessionModel.user_id == user.id
    ).scalar() or 0

    sessions_24h = db.query(func.count(SessionModel.id)).filter(
        SessionModel.user_id == user.id,
        SessionModel.started_at >= cutoff_24h,
    ).scalar() or 0

    sessions_active = db.query(func.count(SessionModel.id)).filter(
        SessionModel.user_id == user.id,
        SessionModel.ended_at.is_(None),
        SessionModel.started_at >= cutoff_active,
    ).scalar() or 0

    visits_total = db.query(func.count(VisitModel.id)).filter(
        VisitModel.site_id.in_(site_ids),
        VisitModel.session_id.isnot(None),
    ).scalar() or 0

    heartbeats_total = db.query(func.count(VisitHeartbeatModel.id)).join(
        SessionModel, SessionModel.session_id == VisitHeartbeatModel.session_id,
    ).filter(
        SessionModel.user_id == user.id,
    ).scalar() or 0

    return {
        "sessions_total": int(sessions_total),
        "sessions_24h": int(sessions_24h),
        "sessions_active": int(sessions_active),
        "visits_total": int(visits_total),
        "heartbeats_total": int(heartbeats_total),
}
