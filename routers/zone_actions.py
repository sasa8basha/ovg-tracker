"""
routers/zone_actions.py — Zone Actions (v8)

Endpoints:
  POST   /api/zones/{zone_id}/action                 — apply action (blacklist/pause/scale/resume)
  DELETE /api/zones/{zone_id}/action/{action_id}     — undo action
  GET    /api/zones/{zone_id}/actions                — history for a zone
  GET    /api/zones/actions/active                   — active actions per zone
  GET    /api/zones/actions/attention-count          — count of items needing attention (for sidebar badge)
  GET    /api/zones/actions/recent                   — recent actions (for dashboard feed)
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, SiteModel, VisitModel, ZoneActionModel
from auth import current_user

router = APIRouter()

VALID_ACTIONS = frozenset(["blacklist", "pause", "scale", "resume"])


class ZoneActionIn(BaseModel):
    action: str = Field(pattern=r"^(blacklist|pause|scale|resume)$")
    reason: str = ""
    metadata: dict = Field(default_factory=dict)


def _site_ids_for(user_id: int, db: Session):
    rows = db.query(SiteModel.id).filter(SiteModel.user_id == user_id).all()
    return [r.id for r in rows]


@router.post("/zones/{zone_id}/action")
def apply_action(
    zone_id: str,
    payload: ZoneActionIn,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    zone_id = (zone_id or "").strip()
    if not zone_id or zone_id == "unknown" or len(zone_id) > 100:
        raise HTTPException(400, "zone_id غير صالح")

    if payload.action not in VALID_ACTIONS:
        raise HTTPException(400, "action غير صالح")

    # metadata validation
    meta = payload.metadata or {}
    if payload.action == "scale":
        pct = meta.get("percent", 30)
        try:
            pct = int(pct)
        except (ValueError, TypeError):
            pct = 30
        pct = max(10, min(200, pct))
        meta["percent"] = pct
    elif payload.action == "pause":
        hours = meta.get("hours", 24)
        try:
            hours = int(hours)
        except (ValueError, TypeError):
            hours = 24
        hours = max(1, min(168, hours))
        meta["hours"] = hours

    row = ZoneActionModel(
        user_id=user.id,
        zone_id=zone_id,
        action=payload.action,
        reason=(payload.reason or "")[:200],
        metadata_json=meta,
        timestamp=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {
        "ok": True,
        "id": row.id,
        "zone_id": row.zone_id,
        "action": row.action,
        "metadata": meta,
        "timestamp": row.timestamp.isoformat(),
    }


@router.delete("/zones/{zone_id}/action/{action_id}")
def undo_action(
    zone_id: str,
    action_id: int,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = db.query(ZoneActionModel).filter(
        ZoneActionModel.id == action_id,
        ZoneActionModel.user_id == user.id,
        ZoneActionModel.zone_id == zone_id,
        ZoneActionModel.reverted_at.is_(None),
    ).first()

    if not row:
        raise HTTPException(404, "الإجراء غير موجود أو تم التراجع عنه")

    # Only allow undo within 10 minutes (safety)
    if (datetime.utcnow() - row.timestamp) > timedelta(minutes=10):
        raise HTTPException(400, "انتهت مدة التراجع (10 دقائق)")

    row.reverted_at = datetime.utcnow()
    db.commit()

    return {"ok": True, "id": row.id, "reverted_at": row.reverted_at.isoformat()}


@router.get("/zones/{zone_id}/actions")
def get_zone_actions(
    zone_id: str,
    limit: int = Query(20, ge=1, le=100),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ZoneActionModel).filter(
        ZoneActionModel.user_id == user.id,
        ZoneActionModel.zone_id == zone_id,
    ).order_by(ZoneActionModel.timestamp.desc()).limit(limit).all()

    return {
        "zone_id": zone_id,
        "count": len(rows),
        "actions": [
            {
                "id": r.id,
                "action": r.action,
                "reason": r.reason,
                "metadata": r.metadata_json or {},
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "reverted_at": r.reverted_at.isoformat() if r.reverted_at else None,
            }
            for r in rows
        ],
    }


@router.get("/zones/actions/active")
def get_active_actions(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """آخر إجراء نشط لكل زون (لو مش مترجع عنه)."""
    rows = db.query(ZoneActionModel).filter(
        ZoneActionModel.user_id == user.id,
        ZoneActionModel.reverted_at.is_(None),
    ).order_by(ZoneActionModel.timestamp.desc()).all()

    # Keep last per zone
    per_zone = {}
    for r in rows:
        if r.zone_id not in per_zone:
            per_zone[r.zone_id] = r

    return {
        "zones": [
            {
                "zone_id": r.zone_id,
                "action": r.action,
                "reason": r.reason,
                "metadata": r.metadata_json or {},
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
            for r in per_zone.values()
        ],
    }


@router.get("/zones/actions/recent")
def get_recent_actions(
    limit: int = Query(10, ge=1, le=50),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    rows = db.query(ZoneActionModel).filter(
        ZoneActionModel.user_id == user.id,
    ).order_by(ZoneActionModel.timestamp.desc()).limit(limit).all()

    return {
        "actions": [
            {
                "id": r.id,
                "zone_id": r.zone_id,
                "action": r.action,
                "reason": r.reason,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "reverted_at": r.reverted_at.isoformat() if r.reverted_at else None,
            }
            for r in rows
        ],
    }


@router.get("/zones/actions/attention-count")
def attention_count(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    عدد الحاجات اللي محتاجة انتباه.
    - labeling: visits 40-80 score, no ground truth
    - bad_zones: zones في آخر 24 ساعة بـ bot_rate > 40% (تقدير سريع)
    """
    site_ids = _site_ids_for(user.id, db)
    if not site_ids:
        return {"labeling": 0, "bad_zones": 0, "total": 0}

    labeling = db.query(VisitModel).filter(
        VisitModel.site_id.in_(site_ids),
        VisitModel.ground_truth.is_(None),
        VisitModel.score >= 40,
        VisitModel.score <= 80,
    ).count()

    # Bad zones quick count (last 24h, bot_rate > 40% with >= 20 visits)
    cutoff = datetime.utcnow() - timedelta(hours=24)
    zone_stats = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label("total"),
        func.sum(func.cast(VisitModel.verdict == "invalid", Integer)).label("invalid"),
    ).filter(
        VisitModel.site_id.in_(site_ids),
        VisitModel.timestamp >= cutoff,
        VisitModel.zone_id.isnot(None),
        VisitModel.zone_id != "unknown",
    ).group_by(VisitModel.zone_id).all()

    bad_zones = 0
    for z in zone_stats:
        total = int(z.total or 0)
        invalid = int(z.invalid or 0)
        if total >= 20 and (invalid / total) > 0.4:
            bad_zones += 1

    return {
        "labeling": labeling,
        "bad_zones": bad_zones,
        "total": labeling + bad_zones,
        "computed_at": datetime.utcnow().isoformat(),
    }


# Import for the cast above
from sqlalchemy import Integer  # noqa: E402
