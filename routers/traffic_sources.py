"""
routers/traffic_sources.py — Traffic sources (Phase 0.5).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, TrafficSource
from schemas import TrafficSourceIn
from auth import current_user

router = APIRouter()


@router.get("")
def list_sources(user: UserModel = Depends(current_user),
                 db: Session = Depends(get_db)):
    rows = db.query(TrafficSource).order_by(
        TrafficSource.is_builtin.desc(),
        TrafficSource.name.asc(),
    ).all()
    return [
        {
            "id": r.id,
            "slug": r.slug,
            "name": r.name,
            "default_cpm": float(r.default_cpm or 0),
            "notes": r.notes,
            "is_builtin": bool(r.is_builtin),
        }
        for r in rows
    ]


@router.post("")
def create_source(payload: TrafficSourceIn,
                  user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    slug = (payload.slug or "").strip().lower()
    if not slug or not slug.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "الـ slug لازم يكون حروف إنجليزية وأرقام و - أو _ فقط")

    if db.query(TrafficSource).filter(TrafficSource.slug == slug).first():
        raise HTTPException(400, "الـ slug مستخدم بالفعل")

    row = TrafficSource(
        slug=slug,
        name=(payload.name or "").strip()[:100],
        default_cpm=float(payload.default_cpm),
        notes=(payload.notes or "")[:500],
        is_builtin=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {
        "id": row.id,
        "slug": row.slug,
        "name": row.name,
        "default_cpm": float(row.default_cpm or 0),
        "is_builtin": False,
                   }
