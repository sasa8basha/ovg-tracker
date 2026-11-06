"""
routers/campaigns.py — Campaign CRUD + Stats.
"""
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, VisitModel, CampaignModel, TrafficSource, Destination
from schemas import CampaignCreateIn, CampaignUpdateIn
from auth import current_user
from utils import stats_cache
from metrics import compute_pl

router = APIRouter()
MAX_CAMPAIGNS_PER_USER = 100

def _new_campaign_key() -> str:
    return secrets.token_hex(16)

def _compute_mini_stats(campaign_id: int, db: Session) -> dict:
    row = db.query(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    ).filter(VisitModel.campaign_id == campaign_id).one()

    total = int(row.total or 0); valid = int(row.valid or 0); invalid = int(row.invalid or 0); suspicious = int(row.suspicious or 0)
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "bot_rate": round(invalid / total * 100, 2) if total > 0 else 0.0}

def _resolve_campaign(campaign_id: int, user: UserModel, db: Session) -> CampaignModel:
    c = db.query(CampaignModel).filter(CampaignModel.id == campaign_id, CampaignModel.user_id == user.id).first()
    if not c: raise HTTPException(404, "الحملة مش موجودة أو مش بتاعتك")
    return c

def _validate_traffic_source(slug: str, db: Session):
    if not slug: return "custom"
    row = db.query(TrafficSource).filter(TrafficSource.slug == slug).first()
    if not row: raise HTTPException(400, f"مصدر الترافيك غير معروف: {slug}")
    return slug

def _validate_destination(slug: str, db: Session):
    if not slug: return "custom"
    row = db.query(Destination).filter(Destination.slug == slug).first()
    if not row: raise HTTPException(400, f"الوجهة غير معروفة: {slug}")
    return slug

@router.get("")
def list_campaigns(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    campaigns = db.query(CampaignModel).filter(CampaignModel.user_id == user.id).order_by(CampaignModel.created_at.desc()).all()
    if not campaigns: return []
    
    ids = [c.id for c in campaigns]
    stats_rows = db.query(
        VisitModel.campaign_id, func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    ).filter(VisitModel.campaign_id.in_(ids)).group_by(VisitModel.campaign_id).all()
    smap = {r.campaign_id: r for r in stats_rows}

    out = []
    for c in campaigns:
        st = smap.get(c.id)
        total = int(st.total or 0) if st else 0
        valid = int(st.valid or 0) if st else 0
        invalid = int(st.invalid or 0) if st else 0
        suspicious = int(st.suspicious or 0) if st else 0
        pl = compute_pl(total, valid, 0, float(c.buy_cpm or 0), float(c.sell_cpm or 0))
        out.append({
            "id": c.id, "name": c.name, "type": c.type, "traffic_source_slug": c.traffic_source_slug, "destination_slug": c.destination_slug,
            "destination_zone_id": c.destination_zone_id, "buy_cpm": float(c.buy_cpm or 0), "sell_cpm": float(c.sell_cpm or 0),
            "campaign_key": c.campaign_key, "status": c.status, "daily_budget": float(c.daily_budget or 0) if c.daily_budget else None,
            "stats": {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "bot_rate": round(invalid / total * 100, 2) if total > 0 else 0.0, "pl": pl},
            "created_at": c.created_at.isoformat() if c.created_at else None, "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        })
    return out

@router.post("")
def create_campaign(payload: CampaignCreateIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    count = db.query(CampaignModel).filter(CampaignModel.user_id == user.id).count()
    if count >= MAX_CAMPAIGNS_PER_USER: raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_CAMPAIGNS_PER_USER} حملة)")
    name = (payload.name or "").strip()
    if not name: raise HTTPException(400, "اسم الحملة مطلوب")
    if payload.type not in ("landing", "direct", "hybrid"): raise HTTPException(400, "نوع الحملة غير صالح")

    source_slug = _validate_traffic_source(payload.traffic_source_slug, db)
    dest_slug = _validate_destination(payload.destination_slug, db)

    if payload.type in ("direct", "hybrid") and not payload.destination_url.strip(): raise HTTPException(400, "حملات direct/hybrid لازم يكون لها destination_url")

    campaign_key = _new_campaign_key()
    c = CampaignModel(
        user_id=user.id, name=name[:200], type=payload.type, traffic_source_slug=source_slug,
        traffic_source_campaign_id=(payload.traffic_source_campaign_id or "")[:100], buy_cpm=float(payload.buy_cpm),
        destination_slug=dest_slug, destination_url=(payload.destination_url or "")[:1000], destination_zone_id=(payload.destination_zone_id or "")[:100],
        sell_cpm=float(payload.sell_cpm), campaign_key=campaign_key, redirect_delay_ms=int(payload.redirect_delay_ms),
        bot_block_threshold=int(payload.bot_block_threshold), daily_budget=float(payload.daily_budget) if payload.daily_budget > 0 else None,
        status="active", notes=(payload.notes or "")[:1000],
    )
    db.add(c); db.commit(); db.refresh(c)
    return {"id": c.id, "name": c.name, "type": c.type, "campaign_key": c.campaign_key, "status": c.status, "created_at": c.created_at.isoformat() if c.created_at else None}

@router.get("/{campaign_id}")
def get_campaign(campaign_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    c = _resolve_campaign(campaign_id, user, db)
    mini = _compute_mini_stats(c.id, db)
    pl = compute_pl(mini["total"], mini["valid"], 0, float(c.buy_cpm or 0), float(c.sell_cpm or 0))
    return {
        "id": c.id, "name": c.name, "type": c.type, "traffic_source_slug": c.traffic_source_slug, "traffic_source_campaign_id": c.traffic_source_campaign_id,
        "buy_cpm": float(c.buy_cpm or 0), "destination_slug": c.destination_slug, "destination_url": c.destination_url, "destination_zone_id": c.destination_zone_id,
        "sell_cpm": float(c.sell_cpm or 0), "campaign_key": c.campaign_key, "redirect_delay_ms": c.redirect_delay_ms, "bot_block_threshold": c.bot_block_threshold,
        "daily_budget": float(c.daily_budget or 0) if c.daily_budget else None, "status": c.status, "notes": c.notes, "stats": {**mini, "pl": pl},
        "created_at": c.created_at.isoformat() if c.created_at else None, "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }

@router.patch("/{campaign_id}")
def update_campaign(campaign_id: int, payload: CampaignUpdateIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    c = _resolve_campaign(campaign_id, user, db)
    if payload.name: c.name = payload.name.strip()[:200]
    if payload.traffic_source_slug: c.traffic_source_slug = _validate_traffic_source(payload.traffic_source_slug, db)
    if payload.traffic_source_campaign_id is not None: c.traffic_source_campaign_id = payload.traffic_source_campaign_id[:100]
    if payload.buy_cpm >= 0: c.buy_cpm = float(payload.buy_cpm)
    if payload.destination_slug: c.destination_slug = _validate_destination(payload.destination_slug, db)
    if payload.destination_url is not None: c.destination_url = (payload.destination_url or "")[:1000]
    if payload.destination_zone_id is not None: c.destination_zone_id = (payload.destination_zone_id or "")[:100]
    if payload.sell_cpm >= 0: c.sell_cpm = float(payload.sell_cpm)
    if payload.redirect_delay_ms > 0: c.redirect_delay_ms = int(payload.redirect_delay_ms)
    if payload.bot_block_threshold >= 0: c.bot_block_threshold = int(payload.bot_block_threshold)
    if payload.daily_budget >= 0: c.daily_budget = float(payload.daily_budget) if payload.daily_budget > 0 else None
    if payload.status:
        if payload.status not in ("active", "paused", "archived"): raise HTTPException(400, "status غير صالح")
        c.status = payload.status
    if payload.notes is not None: c.notes = (payload.notes or "")[:1000]
    db.commit(); db.refresh(c); stats_cache.invalidate(f"stats:user:{user.id}:all")
    return {"ok": True, "id": c.id}

@router.delete("/{campaign_id}")
def delete_campaign(campaign_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    c = _resolve_campaign(campaign_id, user, db)
    db.query(VisitModel).filter(VisitModel.campaign_id == c.id).delete(synchronize_session=False)
    db.delete(c); db.commit(); stats_cache.invalidate(f"stats:user:{user.id}:all")
    return {"ok": True}

@router.post("/{campaign_id}/rotate-key")
def rotate_campaign_key(campaign_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    c = _resolve_campaign(campaign_id, user, db)
    c.campaign_key = _new_campaign_key(); db.commit()
    return {"campaign_key": c.campaign_key}

@router.get("/{campaign_id}/stats")
def campaign_stats(campaign_id: int, from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    c = _resolve_campaign(campaign_id, user, db)
    q = db.query(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    ).filter(VisitModel.campaign_id == c.id)
    
    if from_date:
        try: fd = datetime.strptime(from_date, "%Y-%m-%d"); q = q.filter(VisitModel.timestamp >= fd)
        except ValueError: pass
    if to_date:
        try: td = datetime.strptime(to_date, "%Y-%m-%d") + timedelta(days=1); q = q.filter(VisitModel.timestamp < td)
        except ValueError: pass

    row = q.one(); total = int(row.total or 0); valid = int(row.valid or 0); invalid = int(row.invalid or 0); suspicious = int(row.suspicious or 0)
    pl = compute_pl(total, valid, 0, float(c.buy_cpm or 0), float(c.sell_cpm or 0))
    return {"campaign_id": c.id, "campaign_name": c.name, "period": {"from": from_date, "to": to_date}, "total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "bot_rate": round(invalid / total * 100, 2) if total > 0 else 0.0, "pl": pl}
