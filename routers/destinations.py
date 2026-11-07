"""
routers/destinations.py — Destinations (Phase 0.5).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, Destination
from schemas import DestinationIn
from auth import current_user

router = APIRouter()


@router.get("")
def list_destinations(user: UserModel = Depends(current_user),
                      db: Session = Depends(get_db)):
    rows = db.query(Destination).order_by(
        Destination.is_builtin.desc(),
        Destination.name.asc(),
    ).all()
    return [
        {
            "id": r.id,
            "slug": r.slug,
            "name": r.name,
            "postback_supported": bool(r.postback_supported),
            "notes": r.notes,
            "is_builtin": bool(r.is_builtin),
        }
        for r in rows
    ]


@router.post("")
def create_destination(payload: DestinationIn,
                       user: UserModel = Depends(current_user),
                       db: Session = Depends(get_db)):
    slug = (payload.slug or "").strip().lower()
    if not slug or not slug.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "الـ slug لازم يكون حروف إنجليزية وأرقام و - أو _ فقط")

    if db.query(Destination).filter(Destination.slug == slug).first():
        raise HTTPException(400, "الـ slug مستخدم بالفعل")

    row = Destination(
        slug=slug,
        name=(payload.name or "").strip()[:100],
        postback_supported=bool(payload.postback_supported),
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
        "postback_supported": bool(row.postback_supported),
        "is_builtin": False,
                        }
