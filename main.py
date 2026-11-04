"""
main.py — OVG Tracker entry point.

This file ONLY:
  1. Creates the FastAPI app
  2. Configures CORS + static files
  3. Runs DB init (create_all + migrations + bootstrap)
  4. Includes all routers

Business logic lives in routers/*.py
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
    pages as pages_router,
)

# =========================================================
# INIT
# =========================================================
Base.metadata.create_all(bind=engine)
run_migrations()
bootstrap_admin()

app = FastAPI(title="OVG Tracker", version="5.1")
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS
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

# =========================================================
# ROUTERS
# =========================================================
app.include_router(auth_router.router, prefix="/api/auth", tags=["auth"])
app.include_router(settings_router.router, prefix="/api/settings", tags=["settings"])
app.include_router(sites_router.router, prefix="/api/sites", tags=["sites"])
app.include_router(tracker_router.router, prefix="/api", tags=["tracker"])
app.include_router(stats_router.router, prefix="/api", tags=["stats"])
app.include_router(reports_router.router, prefix="/api", tags=["reports"])
app.include_router(pages_router.router, tags=["pages"])
