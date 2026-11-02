from dotenv import load_dotenv
load_dotenv()  # لو غيرت اسم الملف لـ .env
# أو لو سايبه ovg.txt اكتب: load_dotenv("ovg.txt")
import os
import re
import secrets

# =========================================================
# CONFIG
# =========================================================
DATABASE_URL       = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
DASHBOARD_KEY      = os.getenv("OVG_DASHBOARD_KEY", "")
SECRET             = os.getenv("OVG_SECRET", secrets.token_hex(32))
ADMIN_USER         = os.getenv("OVG_ADMIN_USER", "")
ADMIN_PASS         = os.getenv("OVG_ADMIN_PASS", "")
PUBLIC_URL         = os.getenv("OVG_PUBLIC_URL", "").rstrip("/")
ALLOWED_ORIGINS    = [o.strip() for o in os.getenv("OVG_ORIGINS", "*").split(",") if o.strip()]
TRACK_RATE_PER_MIN = int(os.getenv("OVG_TRACK_RATE", "120"))
GEO_LOOKUP_TIMEOUT = float(os.getenv("OVG_GEO_TIMEOUT", "3.0"))
GEO_CACHE_TTL      = int(os.getenv("OVG_GEO_TTL", "86400"))
GEO_CACHE_MAX      = int(os.getenv("OVG_GEO_MAX", "50000"))
MAX_SITES_PER_USER = int(os.getenv("OVG_MAX_SITES", "20"))
SESSION_COOKIE     = "ovg_session"
SESSION_TTL        = 86400 * 7  # 7 days

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE  = re.compile(r"^[a-f0-9]{16}$")
