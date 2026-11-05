from datetime import datetime
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Float
)
from sqlalchemy.orm import relationship
from database import Base


class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    email = Column(String(255), unique=True, nullable=True, index=True)
    email_verified = Column(Boolean, default=False, nullable=False)
    token_version = Column(Integer, default=1, nullable=False)
    cpm_buy = Column(Float, default=1.0, server_default="1.0", nullable=False)
    cpm_sell = Column(Float, default=1.5, server_default="1.5", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    sites = relationship("SiteModel", back_populates="user", cascade="all, delete-orphan")
    campaigns = relationship("CampaignModel", back_populates="user", cascade="all, delete-orphan")


class SiteModel(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    name = Column(String, nullable=False)
    domain = Column(String, default="")
    site_key = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("UserModel", back_populates="sites")


# =========================================================
# v3 — Campaign Foundation (Phase 0.5)
# =========================================================
class TrafficSource(Base):
    """
    مصدر الترافيك (PopAds, Propeller, Galaksion, custom).
    Built-in sources بتتعمل seed تلقائياً.
    """
    __tablename__ = "traffic_sources"
    id = Column(Integer, primary_key=True)
    slug = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    default_cpm = Column(Float, default=0.0)
    notes = Column(String(500), default="")
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Destination(Base):
    """
    وجهة الترافيك (Adsterra, Monetag, KDM, custom).
    """
    __tablename__ = "destinations"
    id = Column(Integer, primary_key=True)
    slug = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    postback_supported = Column(Boolean, default=False)
    notes = Column(String(500), default="")
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class CampaignModel(Base):
    """
    الحملة — القلب الحقيقي للنظام.

    - landing: صفحة هبوط (site موجود) + إعلان (destination)
    - direct: traffic → interstitial (/go/{key}) → destination URL
    - hybrid: landing + redirect out
    """
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    name = Column(String(200), nullable=False)
    type = Column(String(20), nullable=False, default="landing", index=True)
    # landing | direct | hybrid

    traffic_source_slug = Column(String(50), default="custom", index=True)
    traffic_source_campaign_id = Column(String(100), default="")  # ID في PopAds مثلاً
    buy_cpm = Column(Float, default=0.0, nullable=False)

    destination_slug = Column(String(50), default="custom", index=True)
    destination_url = Column(String(1000), default="")
    destination_zone_id = Column(String(100), default="")
    sell_cpm = Column(Float, default=0.0, nullable=False)

    site_id = Column(Integer, ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True)
    campaign_key = Column(String(32), unique=True, index=True, nullable=False)

    redirect_delay_ms = Column(Integer, default=500, nullable=False)
    bot_block_threshold = Column(Integer, default=100, nullable=False)
    daily_budget = Column(Float, nullable=True)

    status = Column(String(20), default="active", nullable=False, index=True)
    # active | paused | archived

    notes = Column(String(1000), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("UserModel", back_populates="campaigns")
    site = relationship("SiteModel")

    __table_args__ = (
        Index("ix_campaigns_user_status", "user_id", "status"),
        Index("ix_campaigns_user_type", "user_id", "type"),
    )


class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True, nullable=True)
    campaign_id = Column(Integer, index=True, nullable=True)  # v3 — nullable for backward compat
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip = Column(String, index=True)
    user_agent = Column(String)
    zone_id = Column(String, index=True)
    score = Column(Integer)
    verdict = Column(String, index=True)
    evidence = Column(JSON)
    os = Column(String, default="Unknown")
    device = Column(String, default="Unknown")
    browser = Column(String, default="Unknown")
    country = Column(String, default="Unknown")
    country_code = Column(String(2), nullable=True, index=True)
    isp = Column(String, default="Unknown")
    timezone = Column(String, default="Unknown")
    canvas_hash = Column(String, default="Unknown")
    hardware = Column(String, default="Unknown")
    connection_type = Column(String, default="Unknown")
    asn = Column(String, default="Unknown")
    is_vpn = Column(Boolean, default=False)
    webrtc_ip = Column(String, default="None")
    time_on_page = Column(Integer, default=0)
    clicks = Column(Integer, default=0)
    scrolls = Column(Integer, default=0)
    latitude = Column(Float, default=0.0)
    longitude = Column(Float, default=0.0)
    ground_truth = Column(String(10), nullable=True, index=True)
    ground_truth_at = Column(DateTime, nullable=True)
    ground_truth_by = Column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_visits_site_zone_verdict", "site_id", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
        Index("ix_visits_gt_verdict", "ground_truth", "verdict"),
        Index("ix_visits_campaign_timestamp", "campaign_id", "timestamp"),
    )


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    ip = Column(String(45), default="")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class EmailVerificationToken(Base):
    __tablename__ = "email_verification_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class BanRiskSnapshot(Base):
    __tablename__ = "ban_risk_snapshots"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    score = Column(Integer, nullable=True)
    level = Column(String(20), nullable=False, default="unknown")
    total_24h = Column(Integer, default=0)
    bot_rate = Column(Float, default=0.0)
    wasted_rate = Column(Float, default=0.0)
    human_quality = Column(Float, default=0.0)
    zone_diversity = Column(Integer, default=0)
    source_diversity = Column(Integer, default=0)
    factors = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_ban_risk_user_time", "user_id", "timestamp"),
    )


class ZoneActionModel(Base):
    __tablename__ = "zone_actions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    zone_id = Column(String, index=True, nullable=False)
    action = Column(String(20), nullable=False)
    reason = Column(String(200), default="")
    metadata_json = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    reverted_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_zone_actions_user_zone", "user_id", "zone_id"),
        Index("ix_zone_actions_user_time", "user_id", "timestamp"),
        Index("ix_zone_actions_user_active", "user_id", "action", "reverted_at"),
    )
