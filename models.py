from datetime import datetime
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Float
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
    campaigns = relationship("CampaignModel", back_populates="user", cascade="all, delete-orphan")


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
    traffic_source_slug = Column(String(50), default="custom", index=True)
    traffic_source_campaign_id = Column(String(100), default="")
    buy_cpm = Column(Float, default=0.0, nullable=False)
    destination_slug = Column(String(50), default="custom", index=True)
    destination_url = Column(String(1000), default="")
    destination_zone_id = Column(String(100), default="")
    landing_url = Column(String(1000), default="")
    sell_cpm = Column(Float, default=0.0, nullable=False)
    adsterra_api_key = Column(String(255), nullable=True)
    adsterra_tracking_param = Column(String(50), default="sub_id")
    campaign_key = Column(String(32), unique=True, index=True, nullable=False)
    redirect_delay_ms = Column(Integer, default=500, nullable=False)
    bot_block_threshold = Column(Integer, default=100, nullable=False)
    daily_budget = Column(Float, nullable=True)
    status = Column(String(20), default="active", nullable=False, index=True)
    notes = Column(String(1000), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("UserModel", back_populates="campaigns")

    __table_args__ = (
        Index("ix_campaigns_user_status", "user_id", "status"),
        Index("ix_campaigns_user_type", "user_id", "type"),
    )


class SessionModel(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="SET NULL"), index=True, nullable=True)
    ip = Column(String(45), index=True)
    country_code = Column(String(2), nullable=True, index=True)
    user_agent = Column(String(500), default="")
    url = Column(String(2000), default="")
    started_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    last_heartbeat_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)
    total_heartbeats = Column(Integer, default=0, nullable=False)
    total_time_ms = Column(Integer, default=0, nullable=False)
    visit_id = Column(Integer, ForeignKey("visits.id", ondelete="SET NULL"), nullable=True, index=True)
    verdict = Column(String(20), nullable=True, index=True)
    score = Column(Integer, nullable=True)
    confidence = Column(Float, nullable=True)
    bot_probability = Column(Float, nullable=True)
    data_quality = Column(String(20), default="pending", nullable=False, index=True)
    clock_drift_ms = Column(Integer, default=0)
    is_honeypot_triggered = Column(Boolean, default=False)
    consent_state = Column(String(20), default="unknown")
    visitor_fp_hash = Column(String(64), nullable=True, index=True)
    meta = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_sessions_ip_started", "ip", "started_at"),
        Index("ix_sessions_campaign_started", "campaign_id", "started_at"),
        Index("ix_sessions_user_started", "user_id", "started_at"),
        Index("ix_sessions_pending", "visit_id", "started_at"),
    )


class VisitHeartbeatModel(Base):
    __tablename__ = "visit_heartbeats"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), index=True, nullable=False)
    seq = Column(Integer, nullable=False)
    received_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    t_ms = Column(Integer, default=0, nullable=False)
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


class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="CASCADE"), index=True, nullable=False)
    session_id = Column(String(36), nullable=True, index=True)

    click_id = Column(String(36), unique=True, index=True, nullable=True)
    filter_reason = Column(String(100), nullable=True, index=True)

    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    ip = Column(String, index=True)
    user_agent = Column(String)
    zone_id = Column(String, index=True)
    score = Column(Integer)
    verdict = Column(String, index=True)
    evidence = Column(JSON)

    confidence = Column(Float, nullable=True, index=True)
    bot_probability = Column(Float, nullable=True, index=True)
    mode = Column(String(20), nullable=True, index=True)
    reason = Column(String(100), nullable=True, index=True)
    data_quality_report = Column(JSON, nullable=True)
    full_payload = Column(JSON, nullable=True)

    impressions = Column(Integer, default=0)
    revenue = Column(Float, default=0.0)

    bid = Column(Float, default=0.0)
    popads_impression_id = Column(String(100), nullable=True, index=True)
    popads_website_id = Column(String(100), nullable=True, index=True)
    popads_quality = Column(Integer, nullable=True)
    popads_adblock = Column(Boolean, default=False)
    popads_data = Column(JSON, nullable=True)

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

    data_quality = Column(String(20), nullable=True)
    counting_type = Column(String(20), nullable=True)
    is_honeypot_triggered = Column(Boolean, default=False)
    clock_drift_ms = Column(Integer, default=0)
    consent_state = Column(String(20), default="unknown")
    first_30s = Column(JSON, nullable=True)
    milestones = Column(JSON, nullable=True)
    behavioral = Column(JSON, nullable=True)
    ad_events = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_visits_campaign_zone_verdict", "campaign_id", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
        Index("ix_visits_gt_verdict", "ground_truth", "verdict"),
        Index("ix_visits_campaign_timestamp", "campaign_id", "timestamp"),
        Index("ix_visits_session", "session_id"),
        Index("ix_visits_data_quality", "data_quality"),
        Index("ix_visits_counting_type", "counting_type"),
        Index("ix_visits_website_time", "popads_website_id", "timestamp"),
        Index("ix_visits_bot_prob_ts", "bot_probability", "timestamp"),
        Index("ix_visits_confidence_ts", "confidence", "timestamp"),
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

    __table_args__ = (Index("ix_ban_risk_user_time", "user_id", "timestamp"),)


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


class DecisionAuditModel(Base):
    __tablename__ = "decision_audit"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    decision_type = Column(String(50), nullable=False, index=True)
    target_id = Column(String(100), nullable=True, index=True)
    reason = Column(String(200), nullable=False)
    risk_score = Column(Integer, default=0)
    inputs_json = Column(JSON, nullable=True)
    actor = Column(String(100), default="system")
    __table_args__ = (Index("ix_audit_type_time", "decision_type", "timestamp"), Index("ix_audit_target", "target_id"))


class IPIntelligence(Base):
    __tablename__ = "ip_intelligence"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)
    asn = Column(String(50), nullable=True, index=True)
    asn_description = Column(String(200), nullable=True)
    country = Column(String(2), nullable=True, index=True)
    isp = Column(String(200), nullable=True)
    classification = Column(String(20), nullable=True, index=True)
    risk_score = Column(Integer, default=0, index=True)
    reasons = Column(JSON, nullable=True)
    last_checked = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    tcp_rtt_ms = Column(Float, nullable=True)
    ws_echo_ms = Column(Float, nullable=True)
    rtt_gap_ms = Column(Float, nullable=True)


class IPReputationCache(Base):
    __tablename__ = "ip_reputation_cache"
    id = Column(Integer, primary_key=True, index=True)
    source_name = Column(String(100), unique=True, index=True, nullable=False)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    record_count = Column(Integer, default=0)
    data = Column(JSON, nullable=True)