"""
routers/pages.py — HTML pages + debug/diagnostic endpoints.
"""
import os
import random
from fastapi import APIRouter, Depends, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from config import (
    DASHBOARD_KEY, SESSION_COOKIE, SESSION_TTL, ENV,
)
from database import get_db
from models import UserModel, SiteModel, VisitModel
from auth import _optional_user, current_user, make_token, consume_email_verification_token
from helpers import _resolve_user_site
from utils import stats_cache, zone_evidence_cache

router = APIRouter()


def read_template(name):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base_dir, "templates", name), "r", encoding="utf-8") as f:
        return f.read()


@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(read_template("login.html"))


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, key: str = None, db: Session = Depends(get_db)):
    if key and DASHBOARD_KEY and key == DASHBOARD_KEY:
        first = db.query(UserModel).first()
        if first:
            resp = RedirectResponse("/dashboard", status_code=302)
            resp.set_cookie(SESSION_COOKIE, make_token(first), httponly=True,
                            samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("dashboard.html"))


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("settings.html"))


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(read_template("forgot_password.html"))


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse("/forgot-password", status_code=302)


@router.get("/verify-email", response_class=HTMLResponse)
def verify_email_page(token: str = "", db: Session = Depends(get_db)):
    if not token:
        return RedirectResponse("/dashboard?verify=invalid", status_code=302)
    user = consume_email_verification_token(token, db)
    if user:
        return RedirectResponse("/dashboard?verify=ok", status_code=302)
    return RedirectResponse("/dashboard?verify=invalid", status_code=302)


@router.get("/visits", response_class=HTMLResponse)
def all_visits_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("visits.html"))


@router.get("/visits/{visit_id}", response_class=HTMLResponse)
def visit_detail_page(request: Request, visit_id: int, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("visit_detail.html"))


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("reports.html"))


@router.get("/smart-reports", response_class=HTMLResponse)
def smart_reports_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("smart_reports.html"))


# =========================================================
# DEBUG / DIAGNOSTIC / MOCK
# =========================================================
@router.get("/api/_debug/stats")
def debug_stats(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    total_visits = db.query(VisitModel).count()
    user_visits = db.query(VisitModel).join(
        SiteModel, VisitModel.site_id == SiteModel.id
    ).filter(SiteModel.user_id == user.id).count()
    orphan_visits = db.query(VisitModel).filter(VisitModel.site_id == None).count()

    sites = db.query(SiteModel).filter(SiteModel.user_id == user.id).all()
    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(15).all()

    return {
        "total_visits_db": total_visits,
        "user_visits_db": user_visits,
        "orphan_visits_db": orphan_visits,
        "user_sites": [
            {"id": s.id, "name": s.name, "key_prefix": (s.site_key or "")[:8]}
            for s in sites
        ],
        "recent_visits": [
            {"id": v.id, "site_id": v.site_id,
             "ts": v.timestamp.isoformat() if v.timestamp else None,
             "verdict": v.verdict, "score": v.score}
            for v in recent
        ],
    }


@router.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    if ENV != "dev":
        raise HTTPException(404, "Not Found")
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    countries = [
        ("Egypt", "EG", 30.0444, 31.2357),
        ("United States", "US", 37.7749, -122.4194),
        ("India", "IN", 20.5937, 78.9629),
        ("United Kingdom", "GB", 51.5074, -0.1278),
    ]
    for _ in range(50):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid"
              else random.randint(70, 100) if v == "invalid"
              else random.randint(40, 69))
        cn, cc, clat, clon = random.choice(countries)
        db.add(VisitModel(
            site_id=s.id, ip="127.0.0.1", user_agent="Mock",
            zone_id=random.choice(zones), score=sc, verdict=v,
            evidence=["Mock Data"], country=cn, country_code=cc,
            isp="Mock ISP", connection_type="residential",
            time_on_page=random.randint(1000, 15000),
            clicks=random.randint(0, 5), scrolls=random.randint(0, 10),
            latitude=clat + random.uniform(-2, 2),
            longitude=clon + random.uniform(-2, 2),
        ))
    db.commit()
    stats_cache.invalidate(f"stats:site:{s.id}")
    stats_cache.invalidate(f"stats:user:{user.id}:all")
    zone_evidence_cache.invalidate_prefix("zone_ev:")
    return {"status": "ok"}


@router.get("/health")
def health():
    return {"status": "ok", "version": "5.1"}
