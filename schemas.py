from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

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

class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    webrtc_ip: str = "None"
    site_key: str = "" # Legacy, will be treated as campaign_key

class CPMSettingsIn(BaseModel):
    cpm_buy: float = Field(ge=0.0, le=100.0)
    cpm_sell: float = Field(ge=0.0, le=100.0)

class GroundTruthIn(BaseModel):
    label: str = Field(pattern=r"^(human|bot)$")

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
    status: str = Field(default="", max_length=20)
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

class HandshakePayload(BaseModel):
    v: int = Field(default=3)
    session_id: str = Field(min_length=8, max_length=64)
    click_id: str = Field(default="", max_length=64) 
    campaign_key: str = Field(default="", max_length=100) # Now required
    url: str = Field(default="", max_length=2000)
    t_ms: int = Field(default=0, ge=0)
    nav: Dict[str, Any] = Field(default_factory=dict)
    fp: Dict[str, Any] = Field(default_factory=dict)
    consent_state: str = Field(default="unknown", max_length=20)

class HeartbeatPayload(BaseModel):
    v: int = Field(default=3)
    session_id: str = Field(min_length=8, max_length=64)
    seq: int = Field(ge=1, le=10000)
    t_ms: int = Field(ge=0)
    clicks: int = Field(default=0, ge=0)
    scrolls: int = Field(default=0, ge=0)
    mousemoves: int = Field(default=0, ge=0)
    keydowns: int = Field(default=0, ge=0)
    is_visible: bool = Field(default=True)
    is_focused: bool = Field(default=True)

class AdEventPayload(BaseModel):
    event: str = Field(max_length=50)
    zone_id: str = Field(default="", max_length=100)
    t_ms: int = Field(default=0, ge=0)
    viewport_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    duration_ms: int = Field(default=0, ge=0)
    is_trusted: Optional[bool] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

class FinalPayload(BaseModel):
    v: int = Field(default=3)
    session_id: str = Field(min_length=8, max_length=64)
    click_id: str = Field(default="", max_length=64) 
    campaign_key: str = Field(default="", max_length=100) # Required
    seq: int = Field(default=999, ge=0, le=10000)
    t_ms: int = Field(default=0, ge=0)
    url: str = Field(default="", max_length=2000)
    webrtc_ip: str = Field(default="None", max_length=100)
    nav: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: Dict[str, Any] = Field(default_factory=dict)
    behavior: Dict[str, Any] = Field(default_factory=dict)
    screen: Dict[str, Any] = Field(default_factory=dict)
    milestones: Dict[str, Any] = Field(default_factory=dict)
    first_30s: Dict[str, Any] = Field(default_factory=dict)
    ad_events: List[Dict[str, Any]] = Field(default_factory=list)
    honeypot_triggered: bool = Field(default=False)
    clock_drift_ms: int = Field(default=0)
    consent_state: str = Field(default="unknown", max_length=20)
    data_quality: str = Field(default="full", max_length=20)

class InterstitialPrecheckPayload(BaseModel):
    v: int = Field(default=3)
    session_id: str = Field(min_length=8, max_length=64)
    campaign_key: str = Field(min_length=1, max_length=100)
    t_ms: int = Field(default=0, ge=0)
    url: str = Field(default="", max_length=2000)
    nav: Dict[str, Any] = Field(default_factory=dict)
    fp: Dict[str, Any] = Field(default_factory=dict)

class InterstitialLogPayload(BaseModel):
    v: int = Field(default=3)
    session_id: str = Field(min_length=8, max_length=64)
    campaign_key: str = Field(default="", max_length=100)
    decision: str = Field(default="", max_length=20)
    score: int = Field(default=0, ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)
    t_ms: int = Field(default=0, ge=0)
    url: str = Field(default="", max_length=2000)
