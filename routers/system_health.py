"""
routers/system_health.py — System health dashboard backend.

Reports the status of every background worker and infrastructure
component WITHOUT modifying the workers themselves. Derived from DB
state + in-process cache introspection.

Endpoints:
    GET /api/system/health                — aggregated snapshot
    GET /api/system/feeds                 — reputation feeds detail
    GET /api/system/fingerprint-cache     — in-memory cache stats
    GET /api/system/interstitial-stats    — direct-link PoW stats
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import (
    UserModel,
    VisitModel,
    SessionModel,
    IPIntelligence,
    IPReputationCache,
)
from auth import current_user


router = APIRouter()


# =========================================================
# HELPERS
# =========================================================
def _iso(dt):
    return dt.isoformat() if dt else None


def _age_hours(last, now):
    if not last:
        return None
    return round((now - last).total_seconds() / 3600, 1)


def _worker_status_emoji(status):
    return {
        "ok": "✅",
        "warn": "⚠️",
        "critical": "🚨",
        "unknown": "❓",
    }.get(status, "❓")


# =========================================================
# MAIN HEALTH SNAPSHOT
# =========================================================
@router.get("/system/health")
def system_health(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    Aggregated health snapshot for the System Health page.

    Each worker's health is inferred from DB state (no worker-side
    tracking needed). This means the worker doesn't need to be modified.
    """
    now = datetime.utcnow()
    cutoff_1h = now - timedelta(hours=1)
    cutoff_6h = now - timedelta(hours=6)
    cutoff_24h = now - timedelta(hours=24)

    # -----------------------------------------------------
    # 1) Adsterra Sync — آخر مرة اتحدّث فيها revenue
    # -----------------------------------------------------
    adsterra_last = db.query(func.max(VisitModel.timestamp)).filter(
        VisitModel.revenue > 0,
    ).scalar()
    adsterra_last_age_h = _age_hours(adsterra_last, now)
    adsterra_recent_updates = db.query(func.count(VisitModel.id)).filter(
        VisitModel.timestamp >= cutoff_1h,
        VisitModel.revenue > 0,
    ).scalar() or 0

    if adsterra_last_age_h is None:
        adsterra_status = "unknown"
    elif adsterra_last_age_h <= 6:
        adsterra_status = "ok"
    elif adsterra_last_age_h <= 24:
        adsterra_status = "warn"
    else:
        adsterra_status = "critical"

    # -----------------------------------------------------
    # 2) Stale Finalizer — sessions معلقة
    # -----------------------------------------------------
    stale_sessions = db.query(func.count(SessionModel.id)).filter(
        SessionModel.visit_id.is_(None),
        SessionModel.started_at < (now - timedelta(seconds=120)),
    ).scalar() or 0
    pending_sessions = db.query(func.count(SessionModel.id)).filter(
        SessionModel.visit_id.is_(None),
    ).scalar() or 0

    if stale_sessions < 50:
        stale_status = "ok"
    elif stale_sessions < 200:
        stale_status = "warn"
    else:
        stale_status = "critical"

    # -----------------------------------------------------
    # 3) IP Intel Worker — IPs غير مصنّفة
    # -----------------------------------------------------
    subq = db.query(IPIntelligence.ip_address).subquery()
    pending_ips = db.query(func.count(func.distinct(VisitModel.ip))).filter(
        VisitModel.ip.isnot(None),
        VisitModel.ip.notin_(subq),
    ).scalar() or 0
    classified_total = db.query(func.count(IPIntelligence.id)).scalar() or 0

    if pending_ips < 500:
        ip_intel_status = "ok"
    elif pending_ips < 2000:
        ip_intel_status = "warn"
    else:
        ip_intel_status = "critical"

    # -----------------------------------------------------
    # 4) Reputation Loader — feeds
    # -----------------------------------------------------
    feeds_rows = db.query(IPReputationCache).all()
    feeds = []
    all_ok = True
    for f in feeds_rows:
        age_h = _age_hours(f.last_updated, now)
        # Daily refresh + 12h grace = 36h
        feed_status = "ok" if age_h is not None and age_h <= 36 else "stale"
        if feed_status != "ok":
            all_ok = False
        feeds.append({
            "name": f.source_name,
            "record_count": int(f.record_count or 0),
            "last_updated": _iso(f.last_updated),
            "age_hours": age_h,
            "status": feed_status,
        })

    if not feeds:
        reputation_status = "unknown"
    elif all_ok:
        reputation_status = "ok"
    else:
        reputation_status = "warn"

    # -----------------------------------------------------
    # 5) Fingerprint Cache — in-process
    # -----------------------------------------------------
    try:
        from collector.fingerprint_cache import cache_size
        fp_cache_size = int(cache_size())
    except Exception:
        fp_cache_size = 0

    # -----------------------------------------------------
    # 6) Interstitial — direct-link stats
    # -----------------------------------------------------
    direct_total = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
    ).scalar() or 0
    direct_blocked = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
        VisitModel.verdict == "invalid",
    ).scalar() or 0
    direct_valid = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
        VisitModel.verdict == "valid",
    ).scalar() or 0
    direct_recent = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
        VisitModel.timestamp >= cutoff_24h,
    ).scalar() or 0

    block_rate = round((direct_blocked / direct_total) * 100, 1) if direct_total > 0 else 0.0

    # -----------------------------------------------------
    # 7) Overall status = worst of workers
    # -----------------------------------------------------
    worker_statuses = [
        adsterra_status, stale_status, ip_intel_status,
        reputation_status, "ok", "ok",
    ]
    priority = {"ok": 0, "unknown": 1, "warn": 2, "critical": 3}
    overall = max(worker_statuses, key=lambda s: priority.get(s, 0))

    return {
        "generated_at": now.isoformat(),
        "overall_status": overall,
        "workers": {
            "adsterra_sync": {
                "name": "Adsterra Sync",
                "name_ar": "مزامنة Adsterra",
                "interval": "5 min",
                "status": adsterra_status,
                "emoji": _worker_status_emoji(adsterra_status),
                "last_run": _iso(adsterra_last),
                "age_hours": adsterra_last_age_h,
                "recent_updates": int(adsterra_recent_updates),
                "metrics": [
                    {"label": "زيارات بـ revenue (1h)", "value": int(adsterra_recent_updates)},
                    {"label": "آخر تحديث", "value": f"{adsterra_last_age_h}h" if adsterra_last_age_h is not None else "—"},
                ],
            },
            "stale_finalizer": {
                "name": "Stale Finalizer",
                "name_ar": "إنهاء الجلسات المعلقة",
                "interval": "60s",
                "status": stale_status,
                "emoji": _worker_status_emoji(stale_status),
                "pending_sessions": int(pending_sessions),
                "stale_sessions": int(stale_sessions),
                "metrics": [
                    {"label": "Sessions معلقة", "value": int(pending_sessions)},
                    {"label": "Stale (120s+)", "value": int(stale_sessions)},
                ],
            },
            "ip_intel_worker": {
                "name": "IP Intel Worker",
                "name_ar": "تصنيف IPs",
                "interval": "30s",
                "status": ip_intel_status,
                "emoji": _worker_status_emoji(ip_intel_status),
                "classified_total": int(classified_total),
                "pending_ips": int(pending_ips),
                "metrics": [
                    {"label": "IPs مصنّفة", "value": int(classified_total)},
                    {"label": "في الـ queue", "value": int(pending_ips)},
                ],
            },
            "reputation_loader": {
                "name": "Reputation Loader",
                "name_ar": "تحميل قوائم السمعة",
                "interval": "24h",
                "status": reputation_status,
                "emoji": _worker_status_emoji(reputation_status),
                "feeds": feeds,
                "metrics": [
                    {"label": "Feeds", "value": len(feeds)},
                    {"label": "Healthy", "value": sum(1 for f in feeds if f["status"] == "ok")},
                ],
            },
            "fingerprint_cache": {
                "name": "Fingerprint Cache",
                "name_ar": "ذاكرة البصمات",
                "interval": "in-memory",
                "status": "ok",
                "emoji": "✅",
                "cached_fingerprints": fp_cache_size,
                "metrics": [
                    {"label": "بصمات مخزنة", "value": fp_cache_size},
                    {"label": "الحد الأقصى", "value": 100000},
                ],
            },
            "interstitial": {
                "name": "Interstitial / PoW",
                "name_ar": "بوابة الـ Direct Links",
                "interval": "on-demand",
                "status": "ok",
                "emoji": "✅",
                "direct_total": int(direct_total),
                "direct_blocked": int(direct_blocked),
                "direct_valid": int(direct_valid),
                "direct_recent_24h": int(direct_recent),
                "block_rate": block_rate,
                "metrics": [
                    {"label": "Direct visits", "value": int(direct_total)},
                    {"label": "Blocked", "value": int(direct_blocked)},
                    {"label": "Block rate", "value": f"{block_rate}%"},
                ],
            },
        },
    }


# =========================================================
# DETAILED FEEDS
# =========================================================
@router.get("/system/feeds")
def system_feeds(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Detailed reputation feed status (for expandable detail view)."""
    now = datetime.utcnow()
    feeds_rows = db.query(IPReputationCache).all()
    result = []
    for f in feeds_rows:
        age_h = _age_hours(f.last_updated, now)
        result.append({
            "name": f.source_name,
            "record_count": int(f.record_count or 0),
            "last_updated": _iso(f.last_updated),
            "age_hours": age_h,
            "status": "ok" if age_h is not None and age_h <= 36 else "stale",
        })
    return {"feeds": result, "generated_at": now.isoformat()}


# =========================================================
# FINGERPRINT CACHE
# =========================================================
@router.get("/system/fingerprint-cache")
def system_fingerprint_cache(user: UserModel = Depends(current_user)):
    """Fingerprint cache stats."""
    try:
        from collector.fingerprint_cache import cache_size
        return {"size": int(cache_size()), "max_size": 100000, "error": None}
    except Exception as e:
        return {"size": 0, "max_size": 100000, "error": str(e)[:200]}


# =========================================================
# INTERSTITIAL STATS
# =========================================================
@router.get("/system/interstitial-stats")
def system_interstitial_stats(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Interstitial challenge statistics."""
    total = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
    ).scalar() or 0
    blocked = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
        VisitModel.verdict == "invalid",
    ).scalar() or 0
    valid = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
        VisitModel.verdict == "valid",
    ).scalar() or 0
    suspicious = db.query(func.count(VisitModel.id)).filter(
        VisitModel.counting_type == "direct_link",
        VisitModel.verdict == "suspicious",
    ).scalar() or 0

    return {
        "total": int(total),
        "valid": int(valid),
        "invalid": int(blocked),
        "suspicious": int(suspicious),
        "block_rate": round(blocked / max(1, total) * 100, 1) if total > 0 else 0.0,
    }
