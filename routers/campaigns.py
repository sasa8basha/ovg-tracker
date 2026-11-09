"""
routers/campaigns.py — Campaign CRUD + tracking URL generation.
"""
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, VisitModel, CampaignModel, TrafficSource, Destination
from schemas import CampaignCreateIn, CampaignUpdateIn
from auth import current_user
from utils import stats_cache, safe_origin
from metrics import compute_pl
from helpers import build_tracking_url

router = APIRouter()
MAX_CAMPAIGNS_PER_USER = 100


def _new_campaign_key() -> str:
    return secrets.token_hex(16)


def _resolve_campaign(campaign_id: int, user: UserModel, db: Session) -> CampaignModel:
    c = db.query(CampaignModel).filter(
        CampaignModel.id == campaign_id,
        CampaignModel.user_id == user.id,
    ).first()
    if not c:
        raise HTTPException(404, "الحملة مش موجودة")
    return c


def _validate_traffic_source(slug: str, db: Session):
    if not slug:
        return "custom"
    if not db.query(TrafficSource).filter(TrafficSource.slug == slug).first():
        raise HTTPException(400, f"مصدر غير معروف: {slug}")
    return slug


def _validate_destination(slug: str, db: Session):
    if not slug:
        return "custom"
    if not db.query(Destination).filter(Destination.slug == slug).first():
        raise HTTPException(400, f"وجهة غير معروفة: {slug}")
    return slug


def _campaign_payload(c: CampaignModel, origin: str) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "type": c.type,
        "traffic_source_slug": c.traffic_source_slug,
        "traffic_source_campaign_id": c.traffic_source_campaign_id,
        "buy_cpm": float(c.buy_cpm or 0),
        "destination_slug": c.destination_slug,
        "destination_url": c.destination_url,
        "destination_zone_id": c.destination_zone_id,
        "landing_url": c.landing_url or "",
        "sell_cpm": float(c.sell_cpm or 0),
        "campaign_key": c.campaign_key,
        "redirect_delay_ms": c.redirect_delay_ms,
        "bot_block_threshold": c.bot_block_threshold,
        "daily_budget": float(c.daily_budget or 0) if c.daily_budget else None,
        "status": c.status,
        "notes": c.notes,
        "adsterra_api_key_set": bool(c.adsterra_api_key),
        "adsterra_tracking_param": c.adsterra_tracking_param or "sub_id",
        "tracking_url": build_tracking_url(c, origin),
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


@router.get("")
def list_campaigns(
    request: Request,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    origin = safe_origin(request)
    campaigns = db.query(CampaignModel).filter(
        CampaignModel.user_id == user.id
    ).order_by(CampaignModel.created_at.desc()).all()
    if not campaigns:
        return []

    ids = [c.id for c in campaigns]
    stats_rows = db.query(
        VisitModel.campaign_id,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
        func.sum(VisitModel.bid).label("total_cost"),
        func.sum(VisitModel.revenue).label("total_revenue"),
    ).filter(VisitModel.campaign_id.in_(ids)).group_by(VisitModel.campaign_id).all()

    smap = {r.campaign_id: r for r in stats_rows}
    out = []
    for c in campaigns:
        st = smap.get(c.id)
        total = int(st.total or 0) if st else 0
        valid = int(st.valid or 0) if st else 0
        invalid = int(st.invalid or 0) if st else 0
        suspicious = int(st.suspicious or 0) if st else 0
        total_cost = float(st.total_cost or 0) if st else 0.0
        total_revenue = float(st.total_revenue or 0) if st else 0.0
        if total_cost > 0:
            pl = {
                "cost": round(total_cost, 4),
                "revenue": round(total_revenue, 4),
                "profit": round(total_revenue - total_cost, 4),
                "roi": round((total_revenue - total_cost) / total_cost * 100, 2) if total_cost > 0 else 0,
                "is_profitable": total_revenue >= total_cost,
                "source": "exact",
            }
        else:
            pl = compute_pl(total, valid, 0, float(c.buy_cpm or 0), float(c.sell_cpm or 0))
            pl["source"] = "cpm"
        base = _campaign_payload(c, origin)
        base["stats"] = {
            "total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious,
            "bot_rate": round(invalid / total * 100, 2) if total > 0 else 0.0,
            "pl": pl,
        }
        out.append(base)
    return out


@router.post("")
def create_campaign(
    payload: CampaignCreateIn,
    request: Request,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    if db.query(CampaignModel).filter(CampaignModel.user_id == user.id).count() >= MAX_CAMPAIGNS_PER_USER:
        raise HTTPException(400, "وصلت للحد الأقصى")
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(400, "اسم الحملة مطلوب")
    if payload.type not in ("landing", "direct", "hybrid"):
        raise HTTPException(400, "نوع غير صالح")

    source_slug = _validate_traffic_source(payload.traffic_source_slug, db)
    dest_slug = _validate_destination(payload.destination_slug, db)

    if payload.type in ("direct", "hybrid") and not (payload.destination_url or "").strip():
        raise HTTPException(400, "حملات Direct محتاجة destination_url")

    landing_url = (payload.landing_url or "").strip()
    if payload.type == "landing" and not landing_url:
        raise HTTPException(400, "حملات Landing محتاجة landing_url")

    c = CampaignModel(
        user_id=user.id,
        name=name[:200],
        type=payload.type,
        traffic_source_slug=source_slug,
        traffic_source_campaign_id=(payload.traffic_source_campaign_id or "")[:100],
        buy_cpm=float(payload.buy_cpm),
        destination_slug=dest_slug,
        destination_url=(payload.destination_url or "")[:1000],
        destination_zone_id=(payload.destination_zone_id or "")[:100],
        landing_url=landing_url[:1000],
        sell_cpm=float(payload.sell_cpm),
        campaign_key=_new_campaign_key(),
        redirect_delay_ms=int(payload.redirect_delay_ms),
        bot_block_threshold=int(payload.bot_block_threshold),
        daily_budget=float(payload.daily_budget) if payload.daily_budget > 0 else None,
        adsterra_api_key=(payload.adsterra_api_key or "")[:255] or None,
        adsterra_tracking_param=(payload.adsterra_tracking_param or "sub_id")[:50],
        status="active",
        notes=(payload.notes or "")[:1000],
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    origin = safe_origin(request)
    return _campaign_payload(c, origin)


@router.get("/{campaign_id}")
def get_campaign(
    campaign_id: int,
    request: Request,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    origin = safe_origin(request)
    agg = db.query(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
        func.sum(VisitModel.bid).label("cost"),
        func.sum(VisitModel.revenue).label("rev"),
    ).filter(VisitModel.campaign_id == c.id).one()
    total = int(agg.total or 0)
    valid = int(agg.valid or 0)
    invalid = int(agg.invalid or 0)
    suspicious = int(agg.suspicious or 0)
    total_cost = float(agg.cost or 0)
    total_rev = float(agg.rev or 0)
    if total_cost > 0:
        pl = {
            "cost": round(total_cost, 4),
            "revenue": round(total_rev, 4),
            "profit": round(total_rev - total_cost, 4),
            "roi": round((total_rev - total_cost) / total_cost * 100, 2) if total_cost > 0 else 0,
            "is_profitable": total_rev >= total_cost,
            "source": "exact",
        }
    else:
        pl = compute_pl(total, valid, 0, float(c.buy_cpm or 0), float(c.sell_cpm or 0))
        pl["source"] = "cpm"

    base = _campaign_payload(c, origin)
    base["stats"] = {
        "total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious,
        "bot_rate": round(invalid / total * 100, 2) if total > 0 else 0.0,
        "pl": pl,
    }
    return base


@router.patch("/{campaign_id}")
def update_campaign(
    campaign_id: int,
    payload: CampaignUpdateIn,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    if payload.name:
        c.name = payload.name.strip()[:200]
    if payload.traffic_source_slug:
        c.traffic_source_slug = _validate_traffic_source(payload.traffic_source_slug, db)
    if payload.buy_cpm >= 0:
        c.buy_cpm = float(payload.buy_cpm)
    if payload.destination_slug:
        c.destination_slug = _validate_destination(payload.destination_slug, db)
    if payload.destination_url is not None:
        c.destination_url = (payload.destination_url or "")[:1000]
    if payload.destination_zone_id is not None:
        c.destination_zone_id = (payload.destination_zone_id or "")[:100]
    if payload.landing_url is not None:
        c.landing_url = (payload.landing_url or "")[:1000]
    if payload.sell_cpm >= 0:
        c.sell_cpm = float(payload.sell_cpm)
    if payload.redirect_delay_ms > 0:
        c.redirect_delay_ms = int(payload.redirect_delay_ms)
    if payload.bot_block_threshold >= 0:
        c.bot_block_threshold = int(payload.bot_block_threshold)
    if payload.daily_budget >= 0:
        c.daily_budget = float(payload.daily_budget) if payload.daily_budget > 0 else None
    if payload.status:
        if payload.status not in ("active", "paused", "archived"):
            raise HTTPException(400, "status غير صالح")
        c.status = payload.status
    if payload.notes is not None:
        c.notes = (payload.notes or "")[:1000]
    if payload.adsterra_api_key is not None:
        c.adsterra_api_key = (payload.adsterra_api_key or "")[:255] or None
    if payload.adsterra_tracking_param:
        c.adsterra_tracking_param = payload.adsterra_tracking_param[:50]
    db.commit()
    db.refresh(c)
    stats_cache.invalidate(f"stats:user:{user.id}:all")
    return {"ok": True, "id": c.id}


@router.delete("/{campaign_id}")
def delete_campaign(
    campaign_id: int,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    db.query(VisitModel).filter(VisitModel.campaign_id == c.id).delete(synchronize_session=False)
    db.delete(c)
    db.commit()
    stats_cache.invalidate(f"stats:user:{user.id}:all")
    return {"ok": True}


@router.post("/{campaign_id}/rotate-key")
def rotate_campaign_key(
    campaign_id: int,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    c.campaign_key = _new_campaign_key()
    db.commit()
    return {"campaign_key": c.campaign_key}