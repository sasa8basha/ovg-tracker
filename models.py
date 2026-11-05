from datetime import datetime
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Float, Text
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
    __tablename__ = "traffic_sources"
    id = Column(Integer, primary_key=True)
    slug = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    default_cpm = Column(Float, default=0.0)
    notes = Column(String(500), default="")
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Destination(Base):
    __tablename__ = "destinations"
    id = Column(Integer, primary_key=True)
    slug = Column(String(50), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    postback_supported = Column(Boolean, default=False)
    notes = Column(String(500), default="")
    is_builtin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class CampaignModel(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)

    name = Column(String(200), nullable=False)
    type = Column(String(20), nullable=False, default="landing", index=True)
    # landing | direct | hybrid

    traffic_source_slug = Column(String(50), default="custom", index=True)
    traffic_source_campaign_id = Column(String(100), default="")
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


# =========================================================
# v3 — Session (Phase 1.1)
# =========================================================
class SessionModel(Base):
    """
    كل session = زيارة واحدة (من handshake لـ final/انتهاء).
    بنستخدمها عشان:
      - نربط الـ heartbeats ببعضها
      - نعرف لو الزيارة اتقفلت فجأة
      - نمنع تكرار الزيارات
    """
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), unique=True, index=True, nullable=False)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="SET NULL"), index=True, nullable=True)
    site_id = Column(Integer, ForeignKey("sites.id", ondelete="SET NULL"), index=True, nullable=True)

    ip = Column(String(45), index=True)
    country_code = Column(String(2), nullable=True, index=True)
    user_agent = Column(String(500), default="")
    url = Column(String(2000), default="")

    started_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    last_heartbeat_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)

    total_heartbeats = Column(Integer, default=0, nullable=False)
    total_time_ms = Column(Integer, default=0, nullable=False)

    # بيتملى لما الـ final ييجي
    visit_id = Column(Integer, ForeignKey("visits.id", ondelete="SET NULL"), nullable=True, index=True)
    verdict = Column(String(20), nullable=True, index=True)
    score = Column(Integer, nullable=True)

    data_quality = Column(String(20), default="pending", nullable=False, index=True)
    # pending | full | partial | failed | legacy | unknown

    clock_drift_ms = Column(Integer, default=0)
    is_honeypot_triggered = Column(Boolean, default=False)
    consent_state = Column(String(20), default="unknown")
    # granted | denied | unknown

    visitor_fp_hash = Column(String(64), nullable=True, index=True)
    meta = Column(JSON, nullable=True)
    # {nav_brief, fp_brief, ...}

    __table_args__ = (
        Index("ix_sessions_ip_started", "ip", "started_at"),
        Index("ix_sessions_campaign_started", "campaign_id", "started_at"),
        Index("ix_sessions_user_started", "user_id", "started_at"),
    )


# =========================================================
# v3 — Heartbeats (Phase 1.1)
# =========================================================
class VisitHeartbeatModel(Base):
    """
    كل heartbeat = نقطة زمنية بتقول 'لسه هنا'.
    بنستخدمها عشان:
      - نعرف الزيارة قعدت قد إيه فعلاً (لو الـ final ماجاش)
      - نشوف نمط التفاعل عبر الزمن
    """
    __tablename__ = "visit_heartbeats"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), index=True, nullable=False)
    seq = Column(Integer, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

    t_ms = Column(Integer, default=0, nullable=False)
    # الوقت الداخلي من بداية الزيارة (client-side)

    clicks = Column(Integer, default=0)
    scrolls = Column(Integer, default=0)
    mousemoves = Column(Integer, default=0)
    keydowns = Column(Integer, default=0)

    is_visible = Column(Boolean, default=True)
    is_focused = Column(Boolean, default=True)

    meta = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_heartbeats_session_seq", "session_id", "seq"),
        Index("ix_heartbeats_session_time", "session_id", "received_at"),
    )


# =========================================================
# Visits (extended for v3)
# =========================================================
class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True, nullable=True)
    campaign_id = Column(Integer, index=True, nullable=True)
    session_id = Column(String(36), nullable=True, index=True)  # v3
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

    # ===== v3 fields =====
    data_quality = Column(String(20), nullable=True, index=True)
    # full | partial | failed | legacy | unknown

    is_honeypot_triggered = Column(Boolean, default=False)
    clock_drift_ms = Column(Integer, default=0)
    consent_state = Column(String(20), default="unknown")

    # حقول JSONB (في SQLite بيبقوا JSON عادي)
    first_30s = Column(JSON, nullable=True)
    # {scroll_depth_30s, interaction_count_30s, mouse_distance_30s, ...}

    milestones = Column(JSON, nullable=True)
    # {t_first_paint, t_first_ad_visible_50, ...}

    behavioral = Column(JSON, nullable=True)
    # {scroll_depth_pct, mouse_velocity_median, ...} — 40+ حقل

    ad_events = Column(JSON, nullable=True)
    # [{zone_id, viewport_pct, duration_ms, event, ...}]

    full_payload = Column(JSON, nullable=True)
    # الـ payload الكامل (للdebug والـ replay)

    __table_args__ = (
        Index("ix_visits_site_zone_verdict", "site_id", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
        Index("ix_visits_gt_verdict", "ground_truth", "verdict"),
        Index("ix_visits_campaign_timestamp", "campaign_id", "timestamp"),
        Index("ix_visits_session", "session_id"),
        Index("ix_visits_data_quality", "data_quality"),
    )


# =========================================================
# Auth tokens
# =========================================================
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


# =========================================================
# v8 — Ban Risk Snapshots
# =========================================================
class BanRiskSnapshot(Base):
    __tablename__ = "ban_risk_snapshots"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
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


# =========================================================
# v8 — Zone Actions
# =========================================================
class ZoneActionModel(Base):
    __tablename__ = "zone_actions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
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
