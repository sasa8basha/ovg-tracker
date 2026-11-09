"""
main.py — OVG Tracker entry point (v10.0-neo)
"""
import asyncio
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from config import ALLOWED_ORIGINS, ENV, DEBUG
from database import engine, Base, run_data_seeding_and_backfills, apply_safe_migrations
from auth import bootstrap_admin
from adsterra_sync import sync_adsterra_loop
from ip_reputation_loader import reputation_loader_loop
from ip_intelligence import intelligence_worker_loop
from routers.collector_v3 import stale_session_finalizer_loop

from routers import (
    auth as auth_router, settings as settings_router,
    tracker as tracker_router, stats as stats_router, reports as reports_router,
    labeling as labeling_router, data_quality as data_quality_router,
    zones_analytics as zones_analytics_router, radar as radar_router,
    zone_actions as zone_actions_router, live as live_router,
    pages as pages_router, campaigns as campaigns_router,
    traffic_sources as traffic_sources_router, destinations as destinations_router,
    collector_v3 as collector_v3_router, interstitial as interstitial_router,
    sessions as sessions_router, adsterra as adsterra_router,
    ip_intel as ip_intel_router,
)

# Phase 1 — single-call Money Pulse
from routers import pulse as pulse_router
# Phase 2 — System Health dashboard
from routers import system_health as system_health_router

apply_safe_migrations()
Base.metadata.create_all(bind=engine)
run_data_seeding_and_backfills()
bootstrap_admin()

app = FastAPI(title="OVG Tracker", version="10.0-neo", docs_url="/docs" if DEBUG else None)

# GZip
app.add_middleware(GZipMiddleware, minimum_size=500)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def cache_control_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    elif path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
    return response


@app.middleware("http")
async def tracker_cors_middleware(request: Request, call_next):
    if request.url.path.startswith(("/api/track", "/api/collect", "/api/interstitial")):
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                },
            )
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response
    return await call_next(request)


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(sync_adsterra_loop())
    asyncio.create_task(stale_session_finalizer_loop())
    asyncio.create_task(reputation_loader_loop())
    asyncio.create_task(intelligence_worker_loop())
    print("=" * 60)
    print(f"  OVG Tracker v10.0-neo — ENV={ENV}  DEBUG={DEBUG}")
    print("  Adsterra Sync:       running (every 5 min)")
    print("  Stale Finalizer:     running (every 60s)")
    print("  Reputation Loader:   running (immediate + every 24h)")
    print("  IP Intel Worker:     running (every 30s)")
    print("  Design System:       Neo v1.0 (available at /v2/components)")
    print("=" * 60)


app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(settings_router.router, prefix="/api/settings", tags=["settings"])
app.include_router(campaigns_router.router, prefix="/api/campaigns", tags=["campaigns"])
app.include_router(traffic_sources_router.router, prefix="/api/traffic-sources", tags=["traffic-sources"])
app.include_router(destinations_router.router, prefix="/api/destinations", tags=["destinations"])
app.include_router(adsterra_router.router, prefix="/api/adsterra", tags=["adsterra"])
app.include_router(collector_v3_router.router, prefix="/api", tags=["collector-v3"])
app.include_router(interstitial_router.router, tags=["interstitial"])
app.include_router(tracker_router.router, prefix="/api", tags=["tracker"])
app.include_router(stats_router.router, prefix="/api", tags=["stats"])
app.include_router(pulse_router.router, prefix="/api", tags=["pulse"])
app.include_router(system_health_router.router, prefix="/api", tags=["system-health"])
app.include_router(reports_router.router, prefix="/api", tags=["reports"])
app.include_router(labeling_router.router, prefix="/api", tags=["labeling"])
app.include_router(data_quality_router.router, prefix="/api", tags=["data-quality"])
app.include_router(zones_analytics_router.router, prefix="/api", tags=["zones-analytics"])
app.include_router(radar_router.router, prefix="/api", tags=["radar"])
app.include_router(zone_actions_router.router, prefix="/api", tags=["zone-actions"])
app.include_router(live_router.router, prefix="/api", tags=["live"])
app.include_router(sessions_router.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(ip_intel_router.router, prefix="/api/ip-intel", tags=["ip-intel"])
app.include_router(pages_router.router, tags=["pages"])