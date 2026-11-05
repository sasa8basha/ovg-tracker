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
EMAIL_PROVIDER   = os.getenv("OVG_EMAIL_PROVIDER", "console").lower().strip()
EMAIL_FROM       = os.getenv("OVG_EMAIL_FROM", "noreply@ovg-tracker.de1.netrun.io")
EMAIL_FROM_NAME  = os.getenv("OVG_EMAIL_FROM_NAME", "OVG Tracker")

SMTP_HOST        = os.getenv("OVG_SMTP_HOST", "")
SMTP_PORT        = int(os.getenv("OVG_SMTP_PORT", "587"))
SMTP_USER        = os.getenv("OVG_SMTP_USER", "")
SMTP_PASS        = os.getenv("OVG_SMTP_PASS", "")
SMTP_USE_TLS     = os.getenv("OVG_SMTP_USE_TLS", "true").lower() == "true"

RESEND_API_KEY   = os.getenv("OVG_RESEND_API_KEY", "")

RESET_TOKEN_TTL  = int(os.getenv("OVG_RESET_TOKEN_TTL", "3600"))
VERIFY_TOKEN_TTL = int(os.getenv("OVG_VERIFY_TOKEN_TTL", "86400"))

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE  = re.compile(r"^[a-f0-9]{16}$")
EMAIL_RE    = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# =========================================================
# v3 — Collector (Phase 1.1)
# =========================================================
# التفاعل بين المتصفح والسيرفر
COLLECTOR_V3_ENABLED     = os.getenv("OVG_COLLECTOR_V3", "true").lower() == "true"
HANDSHAKE_TIMEOUT_MS     = 300     # أقصى وقت للـ handshake قبل ما نطيح
HEARTBEAT_INTERVAL_MS    = 10000   # كل 10 ثواني (مع jitter في الـ JS)
FINAL_BEACON_TIMEOUT_MS  = 2000    # أقصى وقت للـ sendBeacon

# Rate limits (per minute)
HANDSHAKE_RATE_PER_MIN   = 60      # IP واحد ممكن يعمل 60 handshake في الدقيقة
HEARTBEAT_RATE_PER_MIN   = 20      # كل session ممكن تبعت 20 heartbeat في الدقيقة (احتياطي)
FINAL_RATE_PER_MIN       = 10      # كل session ممكن تبعت 10 finals في الدقيقة (احتياطي)

# Session limits
MAX_SESSIONS_PER_IP_HOUR = 200     # حماية من flood
SESSION_ID_LEN           = 36      # UUID v4 string length
SESSION_ID_RE            = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")

# Interstitial defaults
DEFAULT_REDIRECT_DELAY_MS = 500
DEFAULT_BLOCK_THRESHOLD   = 90
INTERSTITIAL_MAX_WAIT_MS  = 1500   # لو الـ precheck اتأخر أكتر من كده، redirect anyway

# Data quality
DATA_QUALITY_FULL    = "full"      # final وصل + كل الحقول
DATA_QUALITY_PARTIAL = "partial"   # final وصل بس ناقص حقول
DATA_QUALITY_FAILED  = "failed"    # مفيش final، بس heartbeats
DATA_QUALITY_LEGACY  = "legacy"    # زيارة قديمة قبل v3
DATA_QUALITY_UNKNOWN = "unknown"
