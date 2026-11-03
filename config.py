import os
import re
import secrets

# =========================================================
# CONFIG
# =========================================================
DATABASE_URL       = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
ENV                = os.getenv("OVG_ENV", "prod").lower().strip()

DASHBOARD_KEY      = "sasa"
SECRET             = "a3f8b2e1c9d4f7a6b5c8e2d1f4a7b9c3e6d8f1a4b7c9e2d5f8a1b3c6d9e2f4a7"
ADMIN_USER         = ""
ADMIN_PASS         = ""
PUBLIC_URL         = os.getenv("OVG_PUBLIC_URL", "https://ovg-tracker.de1.netrun.io")
ALLOWED_ORIGINS    = ["*"]
TRACK_RATE_PER_MIN = 120
GEO_LOOKUP_TIMEOUT = 3.0
GEO_CACHE_TTL      = 86400
GEO_CACHE_MAX      = 50000
MAX_SITES_PER_USER = 20
SESSION_COOKIE     = "ovg_session"
SESSION_TTL        = 86400 * 7

# =========================================================
# EMAIL (Phase 5 — Auth System)
# =========================================================
# provider: "console" (dev) | "smtp" (production) | "resend" (modern API)
EMAIL_PROVIDER   = os.getenv("OVG_EMAIL_PROVIDER", "console").lower().strip()
EMAIL_FROM       = os.getenv("OVG_EMAIL_FROM", "noreply@ovg-tracker.de1.netrun.io")
EMAIL_FROM_NAME  = os.getenv("OVG_EMAIL_FROM_NAME", "OVG Tracker")

# SMTP (لو اخترت smtp)
SMTP_HOST        = os.getenv("OVG_SMTP_HOST", "")
SMTP_PORT        = int(os.getenv("OVG_SMTP_PORT", "587"))
SMTP_USER        = os.getenv("OVG_SMTP_USER", "")
SMTP_PASS        = os.getenv("OVG_SMTP_PASS", "")
SMTP_USE_TLS     = os.getenv("OVG_SMTP_USE_TLS", "true").lower() == "true"

# Resend (لو اخترت resend)
RESEND_API_KEY   = os.getenv("OVG_RESEND_API_KEY", "")

# Token TTLs
RESET_TOKEN_TTL  = int(os.getenv("OVG_RESET_TOKEN_TTL", "3600"))     # 1 ساعة
VERIFY_TOKEN_TTL = int(os.getenv("OVG_VERIFY_TOKEN_TTL", "86400"))   # 24 ساعة

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE  = re.compile(r"^[a-f0-9]{16}$")
EMAIL_RE    = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
