import os
import re
import secrets

# =========================================================
# CONFIG (Hardcoded for Netrun)
# =========================================================
DATABASE_URL       = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
ENV                = os.getenv("OVG_ENV", "prod").lower().strip()  # "dev" enables mock-data
DASHBOARD_KEY      = "sasa"
SECRET             = "a3f8b2e1c9d4f7a6b5c8e2d1f4a7b9c3e6d8f1a4b7c9e2d5f8a1b3c6d9e2f4a7"
ADMIN_USER         = ""
ADMIN_PASS         = ""
PUBLIC_URL         = "https://ovg-tracker.de1.netrun.io"
ALLOWED_ORIGINS    = ["*"]
TRACK_RATE_PER_MIN = 120
GEO_LOOKUP_TIMEOUT = 3.0
GEO_CACHE_TTL      = 86400
GEO_CACHE_MAX      = 50000
MAX_SITES_PER_USER = 20
SESSION_COOKIE     = "ovg_session"
SESSION_TTL        = 86400 * 7

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE  = re.compile(r"^[a-f0-9]{16}$")
