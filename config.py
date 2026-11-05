"""
config.py — Central configuration (Pydantic Settings based).

Reads all configuration from environment variables / .env file.
Fails fast on startup if any critical value is missing or invalid.

Backward compatible: module-level names (SECRET, DASHBOARD_KEY, ...)
are still exported so existing `from config import SECRET` keeps working.

Supports both plain names (SECRET, DATABASE_URL) and legacy OVG_* prefixes.
"""

import re

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# =========================================================
# KNOWN-COMPROMISED VALUES (reject on startup)
# =========================================================
_LEAKED_SECRETS = {
    "a3f8b2e1c9d4f7a6b5c8e2d1f4a7b9c3e6d8f1a4b7c9e2d5f8a1b3c6d9e2f4a7",
    "CHANGE_ME_generate_with_secrets_token_urlsafe_64",
    "change-me",
    "changeme",
    "secret",
    "your-secret-key",
}
_LEAKED_DASHBOARD_KEYS = {"sasa"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---------- Environment ----------
    ENV: str = Field(
        default="prod",
        validation_alias=AliasChoices("ENV", "OVG_ENV"),
    )
    DEBUG: bool = Field(default=False)

    # ---------- Security ----------
    SECRET: str = Field(
        ...,
        min_length=32,
        validation_alias=AliasChoices("SECRET", "OVG_SECRET"),
        description="Strong random secret for signing sessions/tokens.",
    )
    DASHBOARD_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("DASHBOARD_KEY", "OVG_DASHBOARD_KEY"),
    )

    # ---------- Admin ----------
    ADMIN_USER: str = Field(default="")
    ADMIN_PASS: str = Field(default="")

    # ---------- Public ----------
    PUBLIC_URL: str = Field(
        default="https://ovg-tracker.de1.netrun.io",
        validation_alias=AliasChoices("PUBLIC_URL", "OVG_PUBLIC_URL"),
    )

    # ---------- CORS ----------
    ALLOWED_ORIGINS: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("ALLOWED_ORIGINS", "OVG_ORIGINS"),
    )

    # ---------- Database ----------
    DATABASE_URL: str = Field(
        default="sqlite:///./ovg.db",
        validation_alias=AliasChoices("DATABASE_URL", "OVG_DB_URL"),
    )

    # ---------- Tracking / Rate ----------
    TRACK_RATE_PER_MIN: int = Field(
        default=120,
        validation_alias=AliasChoices("TRACK_RATE_PER_MIN", "OVG_TRACK_RATE"),
    )
    GEO_LOOKUP_TIMEOUT: float = Field(default=3.0)
    GEO_CACHE_TTL: int = Field(default=86400)
    GEO_CACHE_MAX: int = Field(default=50000)
    MAX_SITES_PER_USER: int = Field(default=20)

    # ---------- Sessions ----------
    SESSION_COOKIE: str = Field(default="ovg_session")
    SESSION_TTL: int = Field(default=86400 * 7, ge=60)

    # ---------- Auth Tokens ----------
    RESET_TOKEN_TTL: int = Field(
        default=3600,
        validation_alias=AliasChoices("RESET_TOKEN_TTL", "OVG_RESET_TOKEN_TTL"),
    )
    VERIFY_TOKEN_TTL: int = Field(
        default=86400,
        validation_alias=AliasChoices("VERIFY_TOKEN_TTL", "OVG_VERIFY_TOKEN_TTL"),
    )

    # ---------- Email ----------
    EMAIL_PROVIDER: str = Field(
        default="console",
        validation_alias=AliasChoices("EMAIL_PROVIDER", "OVG_EMAIL_PROVIDER"),
    )
    EMAIL_FROM: str = Field(
        default="noreply@ovg-tracker.de1.netrun.io",
        validation_alias=AliasChoices("EMAIL_FROM", "OVG_EMAIL_FROM"),
    )
    EMAIL_FROM_NAME: str = Field(
        default="OVG Tracker",
        validation_alias=AliasChoices("EMAIL_FROM_NAME", "OVG_EMAIL_FROM_NAME"),
    )
    SMTP_HOST: str = Field(
        default="",
        validation_alias=AliasChoices("SMTP_HOST", "OVG_SMTP_HOST"),
    )
    SMTP_PORT: int = Field(
        default=587,
        validation_alias=AliasChoices("SMTP_PORT", "OVG_SMTP_PORT"),
    )
    SMTP_USER: str = Field(
        default="",
        validation_alias=AliasChoices("SMTP_USER", "OVG_SMTP_USER"),
    )
    SMTP_PASS: str = Field(
        default="",
        validation_alias=AliasChoices("SMTP_PASS", "OVG_SMTP_PASS"),
    )
    SMTP_USE_TLS: bool = Field(
        default=True,
        validation_alias=AliasChoices("SMTP_USE_TLS", "OVG_SMTP_USE_TLS"),
    )
    RESEND_API_KEY: str = Field(
        default="",
        validation_alias=AliasChoices("RESEND_API_KEY", "OVG_RESEND_API_KEY"),
    )

    # ---------- Collector v3 ----------
    COLLECTOR_V3_ENABLED: bool = Field(
        default=True,
        validation_alias=AliasChoices("COLLECTOR_V3_ENABLED", "OVG_COLLECTOR_V3"),
    )
    HANDSHAKE_TIMEOUT_MS: int = Field(default=300)
    HEARTBEAT_INTERVAL_MS: int = Field(default=10000)
    FINAL_BEACON_TIMEOUT_MS: int = Field(default=2000)
    HANDSHAKE_RATE_PER_MIN: int = Field(default=60)
    HEARTBEAT_RATE_PER_MIN: int = Field(default=20)
    FINAL_RATE_PER_MIN: int = Field(default=10)
    MAX_SESSIONS_PER_IP_HOUR: int = Field(default=200)
    SESSION_ID_LEN: int = Field(default=36)

    # ---------- Interstitial ----------
    DEFAULT_REDIRECT_DELAY_MS: int = Field(default=500)
    DEFAULT_BLOCK_THRESHOLD: int = Field(default=90)
    INTERSTITIAL_MAX_WAIT_MS: int = Field(default=1500)

    # ---------- Filter / Decision ----------
    BOT_RISK_THRESHOLD: int = Field(default=60, ge=0, le=100)

    # ---------- Redis ----------
    REDIS_URL: str = Field(default="redis://localhost:6379/0")

    # =========================================================
    # VALIDATORS
    # =========================================================
    @field_validator("SECRET")
    @classmethod
    def _validate_secret(cls, v: str) -> str:
        if v.strip().lower() in {x.lower() for x in _LEAKED_SECRETS}:
            raise ValueError(
                "SECRET matches a known-compromised value and MUST be rotated.\n"
                "Generate a new one with:\n"
                "  python -c \"import secrets; print(secrets.token_urlsafe(64))\""
            )
        return v

    @field_validator("DASHBOARD_KEY")
    @classmethod
    def _validate_dashboard_key(cls, v: str) -> str:
        if not v:
            return ""
        if v in _LEAKED_DASHBOARD_KEYS or len(v) < 16:
            raise ValueError(
                "DASHBOARD_KEY is too weak or known-compromised. "
                "Either leave it empty (recommended) or set a strong value (>=16 chars)."
            )
        return v

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v or []

    @field_validator("ALLOWED_ORIGINS")
    @classmethod
    def _no_wildcard_cors(cls, v: list[str]) -> list[str]:
        if "*" in v:
            raise ValueError(
                "ALLOWED_ORIGINS must NOT contain '*'. "
                "List explicit trusted origins separated by commas."
            )
        if not v:
            raise ValueError(
                "ALLOWED_ORIGINS must be set to at least one origin (e.g. http://localhost:8000)."
            )
        return v

    @model_validator(mode="after")
    def _post_checks(self):
        # Warn if DEBUG on in production
        if self.ENV == "prod" and self.DEBUG:
            import warnings
            warnings.warn("DEBUG=True in production — disable it.", RuntimeWarning)
        return self


# =========================================================
# SINGLETON
# =========================================================
settings = Settings()


# =========================================================
# REGEX (module-level, unchanged API)
# =========================================================
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE = re.compile(r"^[a-f0-9]{16}$")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
SESSION_ID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)


# =========================================================
# DATA QUALITY CONSTANTS
# =========================================================
DATA_QUALITY_FULL = "full"
DATA_QUALITY_PARTIAL = "partial"
DATA_QUALITY_FAILED = "failed"
DATA_QUALITY_LEGACY = "legacy"
DATA_QUALITY_UNKNOWN = "unknown"


# =========================================================
# BACKWARD-COMPAT EXPORTS
# Existing `from config import X` continues to work.
# =========================================================
DATABASE_URL = settings.DATABASE_URL
ENV = settings.ENV
DEBUG = settings.DEBUG

DASHBOARD_KEY = settings.DASHBOARD_KEY
SECRET = settings.SECRET
ADMIN_USER = settings.ADMIN_USER
ADMIN_PASS = settings.ADMIN_PASS
PUBLIC_URL = settings.PUBLIC_URL
ALLOWED_ORIGINS = settings.ALLOWED_ORIGINS

TRACK_RATE_PER_MIN = settings.TRACK_RATE_PER_MIN
GEO_LOOKUP_TIMEOUT = settings.GEO_LOOKUP_TIMEOUT
GEO_CACHE_TTL = settings.GEO_CACHE_TTL
GEO_CACHE_MAX = settings.GEO_CACHE_MAX
MAX_SITES_PER_USER = settings.MAX_SITES_PER_USER

SESSION_COOKIE = settings.SESSION_COOKIE
SESSION_TTL = settings.SESSION_TTL

EMAIL_PROVIDER = settings.EMAIL_PROVIDER
EMAIL_FROM = settings.EMAIL_FROM
EMAIL_FROM_NAME = settings.EMAIL_FROM_NAME
SMTP_HOST = settings.SMTP_HOST
SMTP_PORT = settings.SMTP_PORT
SMTP_USER = settings.SMTP_USER
SMTP_PASS = settings.SMTP_PASS
SMTP_USE_TLS = settings.SMTP_USE_TLS
RESEND_API_KEY = settings.RESEND_API_KEY

RESET_TOKEN_TTL = settings.RESET_TOKEN_TTL
VERIFY_TOKEN_TTL = settings.VERIFY_TOKEN_TTL

COLLECTOR_V3_ENABLED = settings.COLLECTOR_V3_ENABLED
HANDSHAKE_TIMEOUT_MS = settings.HANDSHAKE_TIMEOUT_MS
HEARTBEAT_INTERVAL_MS = settings.HEARTBEAT_INTERVAL_MS
FINAL_BEACON_TIMEOUT_MS = settings.FINAL_BEACON_TIMEOUT_MS
HANDSHAKE_RATE_PER_MIN = settings.HANDSHAKE_RATE_PER_MIN
HEARTBEAT_RATE_PER_MIN = settings.HEARTBEAT_RATE_PER_MIN
FINAL_RATE_PER_MIN = settings.FINAL_RATE_PER_MIN
MAX_SESSIONS_PER_IP_HOUR = settings.MAX_SESSIONS_PER_IP_HOUR
SESSION_ID_LEN = settings.SESSION_ID_LEN

DEFAULT_REDIRECT_DELAY_MS = settings.DEFAULT_REDIRECT_DELAY_MS
DEFAULT_BLOCK_THRESHOLD = settings.DEFAULT_BLOCK_THRESHOLD
INTERSTITIAL_MAX_WAIT_MS = settings.INTERSTITIAL_MAX_WAIT_MS

BOT_RISK_THRESHOLD = settings.BOT_RISK_THRESHOLD
REDIS_URL = settings.REDIS_URL
