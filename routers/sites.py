"""
routers/sites.py — Sites CRUD routes.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from config import MAX_SITES_PER_USER
from database import get_db
from models import UserModel, SiteModel, VisitModel
from schemas import SiteIn
from auth import current_user
from analysis import new_site_key
from helpers import _resolve_user_site
from utils import stats_cache, zone_evidence_cache

router = APIRouter()


@router.get("")
def list_sites(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    sites = db.query(SiteModel).filter(
        SiteModel.user_id == user.id
    ).order_by(SiteModel.created_at.desc()).all()
    if not sites:
        return []
    ids = [s.id for s in sites]
    stats = db.query(
        VisitModel.site_id,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.max(VisitModel.timestamp).label("last"),
    ).filter(VisitModel.site_id.in_(ids)).group_by(VisitModel.site_id).all()
    smap = {r.site_id: r for r in stats}
    out = []
    for s in sites:
        st = smap.get(s.id)
        out.append({
            "id": s.id, "name": s.name, "domain": s.domain, "site_key": s.site_key,
            "total": int(st.total or 0) if st else 0,
            "valid": int(st.valid or 0) if st else 0,
            "invalid": int(st.invalid or 0) if st else 0,
            "last_visit": st.last.isoformat() if st and st.last else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return out


@router.post("")
def create_site(payload: SiteIn, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    count = db.query(SiteModel).filter(SiteModel.user_id == user.id).count()
    if count >= MAX_SITES_PER_USER:
        raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_SITES_PER_USER} موقع)")
    name = payload.name.strip()
    domain = payload.domain.strip()
    if not name:
        raise HTTPException(400, "اسم الموقع مطلوب")
    if len(name) > 100:
        raise HTTPException(400, "اسم الموقع طويل جداً")
    site = SiteModel(user_id=user.id, name=name, domain=domain, site_key=new_site_key())
    db.add(site); db.commit(); db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}


@router.patch("/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(
        SiteModel.id == site_id, SiteModel.user_id == user.id
    ).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    site.name = payload.name.strip()
    site.domain = payload.domain.strip()[:253]
    db.commit()
    return {"ok": True}


@router.delete("/{site_id}")
def delete_site(site_id: int, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(
        SiteModel.id == site_id, SiteModel.user_id == user.id
    ).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    stats_cache.invalidate(f"stats:site:{site.id}")
    stats_cache.invalidate(f"stats:user:{user.id}:all")
    zone_evidence_cache.invalidate_prefix("zone_ev:")
    db.query(VisitModel).filter(VisitModel.site_id == site.id).delete()
    db.delete(site); db.commit()
    return {"ok": True}


@router.post("/{site_id}/rotate-key")
def rotate_key(site_id: int, user: UserModel = Depends(current_user),
               db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(
        SiteModel.id == site_id, SiteModel.user_id == user.id
    ).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    stats_cache.invalidate(f"stats:site:{site.id}")
    site.site_key = new_site_key()
    db.commit()
    return {"site_key": site.site_key}
