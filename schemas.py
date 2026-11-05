"""
schemas.py — Pydantic models for OVG Tracker.
"""
from pydantic import BaseModel, Field


class AuthIn(BaseModel):
    username: str
    password: str
    email: str = ""


class ForgotPasswordIn(BaseModel):
    email: str


class ResetPasswordIn(BaseModel):
    email: str
    otp: str
    new_password: str


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class ProfileUpdateIn(BaseModel):
    username: str = ""
    email: str = ""


class DeleteAccountIn(BaseModel):
    password: str
    confirm: str


class SiteIn(BaseModel):
    name: str
    domain: str = ""


class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    webrtc_ip: str = "None"
    site_key: str = ""


class CPMSettingsIn(BaseModel):
    cpm_buy: float = Field(ge=0.0, le=100.0)
    cpm_sell: float = Field(ge=0.0, le=100.0)


class GroundTruthIn(BaseModel):
    label: str = Field(pattern=r"^(human|bot)$")


# =========================================================
# v3 — Campaign Foundation (Phase 0.5)
# =========================================================
class CampaignCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    type: str = Field(pattern=r"^(landing|direct|hybrid)$")

    traffic_source_slug: str = Field(default="custom", max_length=50)
    traffic_source_campaign_id: str = Field(default="", max_length=100)
    buy_cpm: float = Field(default=0.0, ge=0.0, le=100.0)

    destination_slug: str = Field(default="custom", max_length=50)
    destination_url: str = Field(default="", max_length=1000)
    destination_zone_id: str = Field(default="", max_length=100)
    sell_cpm: float = Field(default=0.0, ge=0.0, le=100.0)

    site_id: int = Field(default=0)  # 0 = مفيش site مرتبط (للـ direct)
    redirect_delay_ms: int = Field(default=500, ge=100, le=2000)
    bot_block_threshold: int = Field(default=100, ge=0, le=100)
    daily_budget: float = Field(default=0.0, ge=0.0, le=100000.0)
    notes: str = Field(default="", max_length=1000)


class CampaignUpdateIn(BaseModel):
    name: str = Field(default="", max_length=200)
    traffic_source_slug: str = Field(default="", max_length=50)
    traffic_source_campaign_id: str = Field(default="", max_length=100)
    buy_cpm: float = Field(default=-1.0, ge=-1.0, le=100.0)
    destination_slug: str = Field(default="", max_length=50)
    destination_url: str = Field(default="", max_length=1000)
    destination_zone_id: str = Field(default="", max_length=100)
    sell_cpm: float = Field(default=-1.0, ge=-1.0, le=100.0)
    redirect_delay_ms: int = Field(default=0, ge=0, le=2000)
    bot_block_threshold: int = Field(default=-1, ge=-1, le=100)
    daily_budget: float = Field(default=-1.0, ge=-1.0, le=100000.0)
    status: str = Field(default="", max_length=20)  # active | paused | archived
    notes: str = Field(default="", max_length=1000)


class TrafficSourceIn(BaseModel):
    slug: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=100)
    default_cpm: float = Field(default=0.0, ge=0.0, le=100.0)
    notes: str = Field(default="", max_length=500)


class DestinationIn(BaseModel):
    slug: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=100)
    postback_supported: bool = Field(default=False)
    notes: str = Field(default="", max_length=500)
