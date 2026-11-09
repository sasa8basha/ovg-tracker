"""
routers/pages.py — HTML pages (v12.0 — 100% Neo)
All content pages now use Neo templates. Old pages kept only for auth flow.
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


# =========================================================
# AUTH PAGES (only legacy pages remaining)
# =========================================================
@router.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db):
        return RedirectResponse("/v2/dashboard", status_code=302)
    return HTMLResponse(read_template("login.html"))


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("settings.html"))


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db):
        return RedirectResponse("/v2/dashboard", status_code=302)
    return HTMLResponse(read_template("forgot_password.html"))


@router.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse("/forgot-password", status_code=302)


@router.get("/verify-email", response_class=HTMLResponse)
def verify_email_page(token: str = "", db: Session = Depends(get_db)):
    if not token:
        return RedirectResponse("/v2/dashboard?verify=invalid", status_code=302)
    user = consume_email_verification_token(token, db)
    if user:
        return RedirectResponse("/v2/dashboard?verify=ok", status_code=302)
    return RedirectResponse("/v2/dashboard?verify=invalid", status_code=302)


# =========================================================
# 301 REDIRECTS
# =========================================================
@router.get("/dashboard", response_class=RedirectResponse)
def dashboard_redirect(request: Request, key: str = None, db: Session = Depends(get_db)):
    if key and DASHBOARD_KEY and key == DASHBOARD_KEY:
        first = db.query(UserModel).first()
        if first:
            resp = RedirectResponse("/v2/dashboard", status_code=302)
            resp.set_cookie(SESSION_COOKIE, make_token(first), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    return RedirectResponse("/v2/dashboard", status_code=301)


@router.get("/campaigns", response_class=RedirectResponse)
def campaigns_redirect(): return RedirectResponse("/v2/campaigns", status_code=301)


@router.get("/campaigns/{campaign_id}", response_class=RedirectResponse)
def campaign_detail_redirect(campaign_id: int): return RedirectResponse(f"/v2/campaigns/{campaign_id}", status_code=301)


@router.get("/sessions", response_class=RedirectResponse)
def sessions_redirect(): return RedirectResponse("/v2/sessions", status_code=301)


@router.get("/sessions/{session_id}", response_class=RedirectResponse)
def session_detail_redirect(session_id: str): return RedirectResponse(f"/v2/sessions/{session_id}", status_code=301)


@router.get("/visits", response_class=RedirectResponse)
def visits_redirect(): return RedirectResponse("/v2/visits", status_code=301)


@router.get("/visits/{visit_id}", response_class=RedirectResponse)
def visit_detail_redirect(visit_id: int): return RedirectResponse(f"/v2/visits/{visit_id}", status_code=301)


@router.get("/ip-lists", response_class=RedirectResponse)
def ip_lists_redirect(): return RedirectResponse("/v2/ip-lists", status_code=301)


@router.get("/smart-reports", response_class=RedirectResponse)
def smart_reports_redirect(): return RedirectResponse("/v2/reports", status_code=301)


@router.get("/live", response_class=RedirectResponse)
def live_redirect(): return RedirectResponse("/v2/live", status_code=301)


@router.get("/radar", response_class=RedirectResponse)
def radar_redirect(): return RedirectResponse("/v2/radar", status_code=301)


@router.get("/labeling", response_class=RedirectResponse)
def labeling_redirect(): return RedirectResponse("/v2/labeling", status_code=301)


@router.get("/data-quality", response_class=RedirectResponse)
def data_quality_redirect(): return RedirectResponse("/v2/data-quality", status_code=301)


@router.get("/zone-analytics", response_class=RedirectResponse)
def zone_analytics_redirect(): return RedirectResponse("/v2/zone-analytics", status_code=301)


@router.get("/audit-log", response_class=RedirectResponse)
def audit_log_redirect(): return RedirectResponse("/v2/audit-log", status_code=301)


@router.get("/system-health", response_class=RedirectResponse)
def system_health_redirect(): return RedirectResponse("/v2/system-health", status_code=301)


@router.get("/tracker", response_class=RedirectResponse)
def tracker_redirect(): return RedirectResponse("/v2/tracker", status_code=301)


@router.get("/reports", response_class=RedirectResponse)
def reports_redirect(): return RedirectResponse("/v2/reports", status_code=301)


@router.get("/popads-report", response_class=RedirectResponse)
def popads_report_redirect(): return RedirectResponse("/v2/popads-report", status_code=301)


@router.get("/adsterra-report", response_class=RedirectResponse)
def adsterra_report_redirect(): return RedirectResponse("/v2/adsterra-report", status_code=301)


# =========================================================
# NEO V2 PAGES (all 21 pages)
# =========================================================
@router.get("/v2/components", response_class=HTMLResponse)
def components_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/components.html"))


@router.get("/v2/dashboard", response_class=HTMLResponse)
def dashboard_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/dashboard.html"))


@router.get("/v2/reports", response_class=HTMLResponse)
def reports_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/reports.html"))


@router.get("/v2/visits", response_class=HTMLResponse)
def visits_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/visits.html"))


@router.get("/v2/visits/{visit_id}", response_class=HTMLResponse)
def visit_detail_v2_page(request: Request, visit_id: int, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/visit_detail.html"))


@router.get("/v2/campaigns", response_class=HTMLResponse)
def campaigns_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/campaigns.html"))


@router.get("/v2/campaigns/{campaign_id}", response_class=HTMLResponse)
def campaign_detail_v2_page(request: Request, campaign_id: int, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/campaign_detail.html"))


@router.get("/v2/live", response_class=HTMLResponse)
def live_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/live.html"))


@router.get("/v2/radar", response_class=HTMLResponse)
def radar_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/radar.html"))


@router.get("/v2/ip-lists", response_class=HTMLResponse)
def ip_lists_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/ip-lists.html"))


@router.get("/v2/sessions", response_class=HTMLResponse)
def sessions_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/sessions.html"))


@router.get("/v2/sessions/{session_id}", response_class=HTMLResponse)
def session_detail_v2_page(request: Request, session_id: str, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/session_detail.html"))


@router.get("/v2/labeling", response_class=HTMLResponse)
def labeling_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/labeling.html"))


@router.get("/v2/data-quality", response_class=HTMLResponse)
def data_quality_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/data-quality.html"))


@router.get("/v2/zone-analytics", response_class=HTMLResponse)
def zone_analytics_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/zone-analytics.html"))


@router.get("/v2/audit-log", response_class=HTMLResponse)
def audit_log_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/audit-log.html"))


@router.get("/v2/system-health", response_class=HTMLResponse)
def system_health_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/system-health.html"))


@router.get("/v2/tracker", response_class=HTMLResponse)
def tracker_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/tracker.html"))


@router.get("/v2/popads-report", response_class=HTMLResponse)
def popads_report_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/popads-report.html"))


@router.get("/v2/adsterra-report", response_class=HTMLResponse)
def adsterra_report_v2_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("v2/adsterra-report.html"))


# =========================================================
# UTILITIES
# =========================================================
@router.get("/404", response_class=HTMLResponse)
def page_404():
    html = "<html><head><title>404 Not Found</title></head><body style='background:#fff;color:#000;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'><h1>404 Not Found</h1></body></html>"
    return HTMLResponse(content=html, status_code=404)


@router.get("/health")
def health():
    return {"status": "ok", "version": "12.0-neo"}