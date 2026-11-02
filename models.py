from datetime import datetime
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String
)
from sqlalchemy.orm import relationship
from database import Base

# =========================================================
# MODELS
# =========================================================
class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    sites = relationship("SiteModel", back_populates="user", cascade="all, delete-orphan")

class SiteModel(Base):
    __tablename__ = "sites"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    name = Column(String, nullable=False)
    domain = Column(String, default="")
    site_key = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("UserModel", back_populates="sites")

class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True, nullable=True)
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
    isp = Column(String, default="Unknown")
    timezone = Column(String, default="Unknown")
    canvas_hash = Column(String, default="Unknown")
    hardware = Column(String, default="Unknown")
    connection_type = Column(String, default="Unknown")
    asn = Column(String, default="Unknown")
    is_vpn = Column(Boolean, default=False)
    webrtc_ip = Column(String, default="None")
    
    # الأعمدة الجديدة للتحليل العميق
    time_on_page = Column(Integer, default=0) # بالملي ثانية
    clicks = Column(Integer, default=0)
    scrolls = Column(Integer, default=0)

    __table_args__ = (
        Index("ix_visits_site_zone_verdict", "site_id", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
    )
