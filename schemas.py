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
