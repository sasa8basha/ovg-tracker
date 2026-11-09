"""
routers/pages.py — HTML pages
"""
import os
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from config import DASHBOARD_KEY, SESSION_COOKIE, SESSION_TTL
from database import get_db
from models import UserModel
from auth import _optional_user, make_token, consume_email_verification_token

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
            resp.set_cookie(SESSION_COOKIE, make_token(first), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
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


@router.get("/campaigns", response_class=HTMLResponse)
def campaigns_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("campaigns.html"))


@router.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
def campaign_detail_page(request: Request, campaign_id: int, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("campaign_detail.html"))


@router.get("/sessions", response_class=HTMLResponse)
def sessions_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("sessions.html"))


@router.get("/sessions/{session_id}", response_class=HTMLResponse)
def session_detail_page(request: Request, session_id: str, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("session_detail.html"))


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


@router.get("/ip-lists", response_class=HTMLResponse)
def ip_lists_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("ip_intel.html"))


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


@router.get("/popads-report", response_class=HTMLResponse)
def popads_report_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("popads_report.html"))


@router.get("/adsterra-report", response_class=HTMLResponse)
def adsterra_report_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("adsterra_report.html"))


@router.get("/labeling", response_class=HTMLResponse)
def labeling_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("labeling.html"))


@router.get("/data-quality", response_class=HTMLResponse)
def data_quality_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("data_quality.html"))


@router.get("/zone-analytics", response_class=HTMLResponse)
def zone_analytics_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("zone_analytics.html"))


@router.get("/radar", response_class=HTMLResponse)
def radar_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("radar.html"))


@router.get("/tracker", response_class=HTMLResponse)
def tracker_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("tracker.html"))


@router.get("/live", response_class=HTMLResponse)
def live_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("live.html"))


# =========================================================
# Phase 2 — Reveal the Buried
# =========================================================
@router.get("/audit-log", response_class=HTMLResponse)
def audit_log_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("audit_log.html"))


@router.get("/system-health", response_class=HTMLResponse)
def system_health_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("system_health.html"))


@router.get("/404", response_class=HTMLResponse)
def page_404():
    html = "<html><head><title>404 Not Found</title></head><body style='background:#fff;color:#000;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'><h1>404 Not Found</h1></body></html>"
    return HTMLResponse(content=html, status_code=404)


@router.get("/health")
def health():
    return {"status": "ok", "version": "9.7"}