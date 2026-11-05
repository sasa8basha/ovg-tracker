"""
main.py — OVG Tracker entry point.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import ALLOWED_ORIGINS
from database import engine, Base, run_migrations
from auth import bootstrap_admin
from routers import (
    auth as auth_router,
    settings as settings_router,
    sites as sites_router,
    tracker as tracker_router,
    stats as stats_router,
    reports as reports_router,
    labeling as labeling_router,
    data_quality as data_quality_router,
    zones_analytics as zones_analytics_router,
    radar as radar_router,
    zone_actions as zone_actions_router,
    live as live_router,
    pages as pages_router,
    campaigns as campaigns_router,
    traffic_sources as traffic_sources_router,
    destinations as destinations_router,
    collector_v3 as collector_v3_router,
)

# =========================================================
# SAFE CREATE ALL
# =========================================================
# create_all() ممكن يفشل لو الـ DB موجودة أصلاً وفيها index شبه الجديد
# (زي ix_visits_data_quality اللي اتعمل من migration سابق)
# الحل: نلفها بـ try/except، ولو فشلت نجرب ننشئ كل جدول على حدة
def _safe_create_all():
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        print("✅ create_all: OK")
        return
    except Exception as e:
        print(f"⚠️ create_all partial failure: {e}")
        print("   → Falling back to per-table creation...")

    # Fallback: ننشئ كل جدول على حدة، لو واحد فشل مش بنوقف الباقي
    for tbl in Base.metadata.sorted_tables:
        try:
            tbl.create(bind=engine, checkfirst=True)
        except Exception as ex:
            print(f"   ⚠️ table '{tbl.name}' skipped: {ex}")


_safe_create_all()
run_migrations()
bootstrap_admin()

app = FastAPI(title="OVG Tracker", version="5.8")
app.mount("/static", StaticFiles(directory="static"), name="static")

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(settings_router.router, prefix="/api/settings", tags=["settings"])
app.include_router(sites_router.router, prefix="/api/sites", tags=["sites"])
app.include_router(campaigns_router.router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(traffic_sources_router.router, prefix="/api/traffic-sources", tags=["traffic-sources"])
app.include_router(destinations_router.router, prefix="/api/destinations", tags=["destinations"])
app.include_router(collector_v3_router.router, prefix="/api", tags=["collector-v3"])
app.include_router(tracker_router.router, prefix="/api", tags=["tracker"])
app.include_router(stats_router.router, prefix="/api", tags=["stats"])
app.include_router(reports_router.router, prefix="/api", tags=["reports"])
app.include_router(labeling_router.router, prefix="/api", tags=["labeling"])
app.include_router(data_quality_router.router, prefix="/api", tags=["data-quality"])
app.include_router(zones_analytics_router.router, prefix="/api", tags=["zones-analytics"])
app.include_router(radar_router.router, prefix="/api", tags=["radar"])
app.include_router(zone_actions_router.router, prefix="/api", tags=["zone-actions"])
app.include_router(live_router.router, prefix="/api", tags=["live"])
app.include_router(pages_router.router, tags=["pages"])
