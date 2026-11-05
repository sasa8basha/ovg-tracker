"""
main.py — OVG Tracker entry point.

P0 hardening:
  - No wildcard CORS.
  - Config validation happens on import (fail-fast).
  - Startup banner shows ENV + CORS mode clearly.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from config import ALLOWED_ORIGINS, ENV, DEBUG
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
    interstitial as interstitial_router,
    sessions as sessions_router,
)


# =========================================================
# DB INIT
# =========================================================
Base.metadata.create_all(bind=engine)
run_migrations()
bootstrap_admin()


# =========================================================
# APP
# =========================================================
app = FastAPI(
    title="OVG Tracker",
    version="5.9",
    docs_url="/docs" if DEBUG else None,
    redoc_url="/redoc" if DEBUG else None,
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# =========================================================
# CORS (P0 — NO WILDCARD)
# =========================================================
# ALLOWED_ORIGINS is validated in config.py and can never be ["*"].
# Any request from an unlisted origin is rejected by CORSMiddleware.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# =========================================================
# ROUTERS
# =========================================================
app.include_router(auth_router.router,                 prefix="/api/auth",            tags=["auth"])
app.include_router(settings_router.router,             prefix="/api/settings",        tags=["settings"])
app.include_router(sites_router.router,                prefix="/api/sites",           tags=["sites"])
app.include_router(campaigns_router.router,            prefix="/api/campaigns",       tags=["campaigns"])
app.include_router(traffic_sources_router.router,      prefix="/api/traffic-sources", tags=["traffic-sources"])
app.include_router(destinations_router.router,         prefix="/api/destinations",    tags=["destinations"])
app.include_router(collector_v3_router.router,         prefix="/api",                 tags=["collector-v3"])
app.include_router(interstitial_router.router,                                        tags=["interstitial"])
app.include_router(tracker_router.router,              prefix="/api",                 tags=["tracker"])
app.include_router(stats_router.router,                prefix="/api",                 tags=["stats"])
app.include_router(reports_router.router,              prefix="/api",                 tags=["reports"])
app.include_router(labeling_router.router,             prefix="/api",                 tags=["labeling"])
app.include_router(data_quality_router.router,         prefix="/api",                 tags=["data-quality"])
app.include_router(zones_analytics_router.router,      prefix="/api",                 tags=["zones-analytics"])
app.include_router(radar_router.router,                prefix="/api",                 tags=["radar"])
app.include_router(zone_actions_router.router,         prefix="/api",                 tags=["zone-actions"])
app.include_router(live_router.router,                 prefix="/api",                 tags=["live"])
app.include_router(sessions_router.router,             prefix="/api/sessions",        tags=["sessions"])
app.include_router(pages_router.router,                                               tags=["pages"])


# =========================================================
# STARTUP BANNER
# =========================================================
@app.on_event("startup")
async def _startup_banner():
    print("=" * 60)
    print(f"  OVG Tracker v5.9 — ENV={ENV}  DEBUG={DEBUG}")
    print(f"  CORS origins: {ALLOWED_ORIGINS}")
    print("  Security posture: P0-hardened (no wildcards, secrets from .env)")
    print("=" * 60)
