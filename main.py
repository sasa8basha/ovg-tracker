"""
OVG Tracker — Version 5.0.0 (Phase 1: Core Experience)
Production-ready · No external auth libs · CSRF-safe · XSS-safe
Phase 1: Design System + Advanced Visits + Core Reports + Visit Detail
"""
import hashlib
import hmac
import ipaddress
import json
import math
import os
import random
import re
import secrets
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
)
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer,
    String, and_, asc, case, create_engine, desc, func, inspect, or_, text
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

# =========================================================
# CONFIG
# =========================================================
APP_VERSION        = "5.0.0"
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

# =========================================================
# DB & MODELS
# =========================================================
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


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
    breakdown = Column(JSON)
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
    language = Column(String, default="Unknown")
    do_not_track = Column(Boolean, default=False)
    referrer = Column(String, default="")
    page_url = Column(String, default="")
    tags = Column(JSON, default=list)
    note = Column(String, default="")
    is_whitelisted = Column(Boolean, default=False)
    is_blacklisted = Column(Boolean, default=False)

    __table_args__ = (
        Index("ix_visits_site_zone_verdict", "site_id", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
        Index("ix_visits_site_timestamp", "site_id", "timestamp"),
        Index("ix_visits_canvas", "canvas_hash"),
        Index("ix_visits_country", "country"),
    )


class SegmentModel(Base):
    __tablename__ = "segments"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    site_id = Column(Integer, ForeignKey("sites.id"), index=True, nullable=True)
    name = Column(String, nullable=False)
    filters = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# =========================================================
# DB MIGRATIONS (add new columns to existing tables)
# =========================================================
def _migrate_visits_table():
    """Add new columns to existing visits table (SQLite/Postgres compatible)."""
    try:
        insp = inspect(engine)
        if not insp.has_table("visits"):
            return
        existing = {c["name"] for c in insp.get_columns("visits")}
        dialect = engine.dialect.name
        bool_def = "0" if dialect == "sqlite" else "FALSE"
        new_cols = [
            ("breakdown", "JSON"),
            ("language", "VARCHAR DEFAULT 'Unknown'"),
            ("do_not_track", f"BOOLEAN DEFAULT {bool_def}"),
            ("referrer", "VARCHAR DEFAULT ''"),
            ("page_url", "VARCHAR DEFAULT ''"),
            ("tags", "JSON"),
            ("note", "VARCHAR DEFAULT ''"),
            ("is_whitelisted", f"BOOLEAN DEFAULT {bool_def}"),
            ("is_blacklisted", f"BOOLEAN DEFAULT {bool_def}"),
        ]
        with engine.connect() as conn:
            for name, col_def in new_cols:
                if name in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE visits ADD COLUMN {name} {col_def}"))
                    conn.commit()
                    print(f"✅ Migrated column: visits.{name}")
                except Exception as e:
                    print(f"⚠️ Migration skip visits.{name}: {e}")
    except Exception as e:
        print(f"⚠️ Migration error: {e}")


_migrate_visits_table()


# =========================================================
# AUTH HELPERS
# =========================================================
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return hmac.compare_digest(calc, h)
    except Exception:
        return False


def make_token(user_id: int) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = f"{user_id}.{exp}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(token: str):
    try:
        user_id, exp, sig = token.rsplit(".", 2)
        payload = f"{user_id}.{exp}"
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return None
        if int(exp) < time.time():
            return None
        return int(user_id)
    except Exception:
        return None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _optional_user(request: Request, db: Session):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        uid = verify_token(token)
        if uid:
            u = db.query(UserModel).get(uid)
            if u:
                return u
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if DASHBOARD_KEY and key == DASHBOARD_KEY:
        return db.query(UserModel).first()
    return None


def current_user(request: Request, db: Session = Depends(get_db)) -> UserModel:
    user = _optional_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def bootstrap_admin():
    if not ADMIN_USER or not ADMIN_PASS:
        return
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == ADMIN_USER).first():
            return
        db.add(UserModel(username=ADMIN_USER, password_hash=hash_password(ADMIN_PASS)))
        db.commit()
        print(f"✅ Bootstrapped admin user: {ADMIN_USER}")
    finally:
        db.close()


bootstrap_admin()


# =========================================================
# APP
# =========================================================
app = FastAPI(title="OVG Tracker", version=APP_VERSION)

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                       allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])

# =========================================================
# UTILITIES
# =========================================================
class TTLCache:
    def __init__(self, maxsize: int = 10000, ttl: int = 3600):
        self.maxsize, self.ttl = maxsize, ttl
        self._data = OrderedDict()

    def get(self, key):
        e = self._data.get(key)
        if e is None:
            return None
        v, ts = e
        if time.time() - ts > self.ttl:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return v

    def set(self, key, val):
        self._data[key] = (val, time.time())
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)


class WindowRateLimiter:
    def __init__(self, max_req=120, window=60, maxsize=100000):
        self.max_req, self.window, self.maxsize = max_req, window, maxsize
        self._d = OrderedDict()

    def check(self, key: str):
        now = time.time()
        e = self._d.get(key)
        if e is None or now - e[1] > self.window:
            self._d[key] = (1, now)
            self._d.move_to_end(key)
        else:
            self._d[key] = (e[0] + 1, e[1])
            self._d.move_to_end(key)
        while len(self._d) > self.maxsize:
            self._d.popitem(last=False)
        if self._d[key][0] > self.max_req:
            raise HTTPException(status_code=429, detail="محاولات كتير — جرب بعد شوية",
                                headers={"Retry-After": str(self.window)})


ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)
signup_limiter = WindowRateLimiter(max_req=5, window=300)
login_limiter = WindowRateLimiter(max_req=15, window=300)


def _is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip")
    if cf and cf.strip():
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for p in parts:
            if not _is_private_ip(p):
                return p
        if parts:
            return parts[0]
    xri = request.headers.get("x-real-ip")
    if xri and xri.strip():
        return xri.strip()
    return request.client.host if request.client else "0.0.0.0"


def safe_origin(request: Request) -> str:
    origin = PUBLIC_URL
    if not origin:
        try:
            origin = str(request.base_url).rstrip("/")
        except Exception:
            origin = "https://ovg-tracker.de1.netrun.io"
    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        origin = "https://ovg-tracker.de1.netrun.io"
    for ch in ("'", '"', "<", ">", "`", "\\", "\n", "\r", "\t"):
        origin = origin.replace(ch, "")
    return origin.rstrip("/")


async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {"country": "Local", "isp": "Local ISP", "type": "residential",
                "asn": "N/A", "security": {}}
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,isp,as,proxy,hosting",
                timeout=GEO_LOOKUP_TIMEOUT,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    is_vpn = bool(d.get("proxy") or d.get("hosting"))
                    out = {
                        "country": d.get("country", "Unknown"),
                        "isp": d.get("isp", "Unknown"),
                        "type": "hosting" if is_vpn else "residential",
                        "asn": (d.get("as") or "Unknown").split()[0] if d.get("as") else "Unknown",
                        "security": {"vpn": is_vpn},
                    }
                    ip_cache.set(ip, out)
                    return out
    except Exception:
        pass
    return {"country": "Unknown", "isp": "Unknown", "type": "Unknown",
            "asn": "Unknown", "security": {}}


def parse_ua(ua: str):
    u = (ua or "").lower()
    device = "Mobile" if "mobi" in u else "Tablet" if ("tablet" in u or "ipad" in u) else "Desktop"
    if "windows nt" in u:
        os_name = "Windows"
    elif "mac os" in u or "macintosh" in u:
        os_name = "macOS"
    elif "android" in u:
        os_name = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u:
        os_name = "iOS"
    elif "linux" in u:
        os_name = "Linux"
    else:
        os_name = "Unknown"
    if "opr/" in u or "opera" in u:
        browser = "Opera"
    elif "edg/" in u or "edge/" in u:
        browser = "Edge"
    elif "chrome" in u and "chromium" not in u:
        browser = "Chrome"
    elif "firefox" in u:
        browser = "Firefox"
    elif "safari" in u and "chrome" not in u:
        browser = "Safari"
    else:
        browser = "Unknown"
    return os_name, device, browser


def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v:
                return v[0]
    except Exception:
        pass
    return "unknown"


def new_site_key() -> str:
    return secrets.token_hex(8)


# =========================================================
# ANALYSIS ENGINE (with detailed breakdown)
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    breakdown = []
    nav = data.get("nav") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    ua = str(nav.get("ua") or "").lower()
    sec = ip_info.get("security", {})

    def add(rule, weight, category):
        breakdown.append({"rule": rule, "weight": weight, "category": category})

    # --- Automation signals ---
    if nav.get("webdriver") is True:
        add("WebDriver Flag", 80, "automation")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        add("Suspicious User-Agent", 90, "automation")

    # --- OS / Platform mismatch ---
    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        add("OS Mismatch (Windows UA vs Platform)", 50, "mismatch")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        add("OS Mismatch (Mac UA vs Platform)", 50, "mismatch")

    # --- Network signals ---
    if sec.get("vpn") is True:
        add("VPN/Proxy Detected", 70, "network")
    if str(ip_info.get("type", "")).lower() == "hosting":
        add("Datacenter/Hosting IP", 80, "network")

    # --- WebRTC leak ---
    webrtc = data.get("webrtc_ip")
    if webrtc and webrtc != "None" and not _is_private_ip(webrtc) and webrtc != data.get("client_ip"):
        add(f"WebRTC Leak (Real IP: {webrtc})", 90, "network")

    # --- Fingerprint signals ---
    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        add("Missing Canvas FP", 60, "fingerprint")
    try:
        cores = int(fp.get("hardwareConcurrency") or 0)
    except Exception:
        cores = 0
    if cores <= 1:
        add(f"Low CPU ({cores} cores)", 40, "fingerprint")

    # --- Timezone mismatch ---
    tz = str(fp.get("timezone") or "").lower()
    country = ip_info.get("country", "Unknown")
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        add("UTC/Unknown Timezone", 30, "mismatch")
    elif country not in ("Unknown", "Local"):
        cmap = {
            "Egypt": ["cairo", "africa"],
            "United States": ["america/"],
            "US": ["america/"],
            "United Kingdom": ["london", "europe/london"],
            "UK": ["london", "europe/london"],
            "Saudi Arabia": ["riyadh", "asia/riyadh"],
            "SA": ["riyadh", "asia/riyadh"],
            "Italy": ["rome", "europe/rome"],
            "Germany": ["berlin", "europe/berlin"],
            "France": ["paris", "europe/paris"],
            "India": ["kolkata", "asia/kolkata"],
        }
        if country in cmap and not any(t in tz for t in cmap[country]):
            add(f"Timezone Mismatch (IP: {country} vs TZ: {tz})", 60, "mismatch")

    # --- Behavior signals ---
    try:
        t_on_page = int(behavior.get("time_on_page_ms") or 0)
    except Exception:
        t_on_page = 0
    if t_on_page < 1500:
        add("Left too fast (< 1.5s)", 40, "behavior")
    try:
        mv = float(behavior.get("mouse_variance") or 0)
    except Exception:
        mv = 0.0
    if events.get("mousemove", 0) > 10 and mv < 1.5:
        add("Robotic Mouse (low variance)", 50, "behavior")
    if t_on_page > 3000 and events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        add("No Interaction (Zombie Session)", 30, "behavior")

    # --- Virtual renderer ---
    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        add("Virtual WebGL Renderer", 60, "fingerprint")

    raw_score = sum(b["weight"] for b in breakdown)
    score = min(150, raw_score)
    verdict = "invalid" if score >= 80 else "suspicious" if score >= 40 else "valid"
    return {
        "score": score,
        "raw_score": raw_score,
        "verdict": verdict,
        "evidence": [b["rule"] for b in breakdown],
        "breakdown": breakdown,
    }


# =========================================================
# SCHEMAS
# =========================================================
class AuthIn(BaseModel):
    username: str
    password: str


class SiteIn(BaseModel):
    name: str
    domain: str = ""


class TrackPayload(BaseModel):
    url: str
    page_url: str = ""
    referrer: str = ""
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    webrtc_ip: str = "None"
    site_key: str = ""


class VisitUpdateIn(BaseModel):
    verdict: Optional[str] = None
    note: Optional[str] = None
    tags: Optional[List[str]] = None


class BulkActionIn(BaseModel):
    ids: List[int]
    action: str  # mark_valid | mark_invalid | delete | add_tag
    tag: Optional[str] = None
    site: Optional[str] = None


class SegmentIn(BaseModel):
    name: str
    filters: dict
    site: Optional[str] = None

# =========================================================
# AUTH ROUTES
# =========================================================
@app.post("/api/auth/signup")
def signup(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    signup_limiter.check(client_ip)

    username = payload.username.strip()
    password = payload.password

    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم لازم 3-32 حرف (حروف إنجليزي، أرقام، _ . -)")
    if len(password) < 6:
        raise HTTPException(400, "كلمة المرور لازم 6 حروف على الأقل")
    if len(password) > 128:
        raise HTTPException(400, "كلمة المرور طويلة جداً")
    if db.query(UserModel).filter(UserModel.username == username).first():
        raise HTTPException(400, "اسم المستخدم ده مستخدم بالفعل، جرب اسم تاني")

    u = UserModel(username=username, password_hash=hash_password(password))
    db.add(u)
    db.commit()
    db.refresh(u)

    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}


@app.post("/api/auth/login")
def login(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    login_limiter.check(client_ip)

    u = db.query(UserModel).filter(UserModel.username == payload.username.strip()).first()
    if not u or not verify_password(payload.password, u.password_hash):
        raise HTTPException(401, "اسم المستخدم أو كلمة المرور غلط")

    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True,
                        samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}


@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user: UserModel = Depends(current_user)):
    return {"id": user.id, "username": user.username}


# =========================================================
# SITES ROUTES
# =========================================================
@app.get("/api/sites")
def list_sites(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    sites = (db.query(SiteModel)
             .filter(SiteModel.user_id == user.id)
             .order_by(SiteModel.created_at.desc()).all())
    if not sites:
        return []
    ids = [s.id for s in sites]

    stats = db.query(
        VisitModel.site_id,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.max(VisitModel.timestamp).label("last"),
    ).filter(VisitModel.site_id.in_(ids)).group_by(VisitModel.site_id).all()
    smap = {r.site_id: r for r in stats}

    out = []
    for s in sites:
        st = smap.get(s.id)
        out.append({
            "id": s.id, "name": s.name, "domain": s.domain, "site_key": s.site_key,
            "total": int(st.total or 0) if st else 0,
            "valid": int(st.valid or 0) if st else 0,
            "invalid": int(st.invalid or 0) if st else 0,
            "last_visit": st.last.isoformat() if st and st.last else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return out


@app.post("/api/sites")
def create_site(payload: SiteIn, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    count = db.query(SiteModel).filter(SiteModel.user_id == user.id).count()
    if count >= MAX_SITES_PER_USER:
        raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_SITES_PER_USER} موقع)")
    name = payload.name.strip()
    domain = payload.domain.strip()
    if not name:
        raise HTTPException(400, "اسم الموقع مطلوب")
    if len(name) > 100:
        raise HTTPException(400, "اسم الموقع طويل جداً (أقصى 100 حرف)")
    if len(domain) > 253:
        raise HTTPException(400, "الدومين طويل جداً")

    site = SiteModel(user_id=user.id, name=name, domain=domain, site_key=new_site_key())
    db.add(site)
    db.commit()
    db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}


@app.patch("/api/sites/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id,
                                      SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "اسم الموقع مطلوب")
    if len(name) > 100:
        raise HTTPException(400, "اسم الموقع طويل جداً")
    site.name = name
    site.domain = payload.domain.strip()[:253]
    db.commit()
    return {"ok": True}


@app.delete("/api/sites/{site_id}")
def delete_site(site_id: int, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id,
                                      SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    db.query(VisitModel).filter(VisitModel.site_id == site.id).delete()
    db.delete(site)
    db.commit()
    return {"ok": True}


@app.post("/api/sites/{site_id}/rotate-key")
def rotate_key(site_id: int, user: UserModel = Depends(current_user),
               db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id,
                                      SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    site.site_key = new_site_key()
    db.commit()
    return {"site_key": site.site_key}


def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key:
        raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key,
                                   SiteModel.user_id == user.id).first()
    if not s:
        raise HTTPException(404, "الموقع مش موجود أو مش بتاعك")
    return s


# =========================================================
# TRACKER CODE TEMPLATE (Inline JS — Phase 1 enhanced)
# =========================================================
TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  var SITE_KEY = '__OVG_SITE_KEY__';
  var ENDPOINT = '__OVG_ENDPOINT__';
  var SEND_DELAY_MS = 4000;
  var WEBRTC_TIMEOUT = 1500;

  var startTime = Date.now();
  var mousemoves = 0, touchstarts = 0;
  var mouseX = [], mouseY = [];
  var sent = false;

  document.addEventListener('mousemove', function (e) {
    mousemoves++;
    mouseX.push(e.clientX); mouseY.push(e.clientY);
    if (mouseX.length > 200) { mouseX.shift(); mouseY.shift(); }
  }, { passive: true });

  document.addEventListener('touchstart', function () { touchstarts++; }, { passive: true });

  function variance(arr) {
    if (arr.length < 2) return 0;
    var m = 0, i;
    for (i = 0; i < arr.length; i++) m += arr[i];
    m = m / arr.length;
    var s = 0;
    for (i = 0; i < arr.length; i++) { var d = arr[i] - m; s += d * d; }
    return s / arr.length;
  }

  function isPrivateIP(ip) {
    if (!ip) return true;
    if (ip.indexOf('.') !== -1) {
      var p = ip.split('.').map(Number);
      return p[0] === 10 ||
             (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
             (p[0] === 192 && p[1] === 168) ||
             p[0] === 127 ||
             (p[0] === 169 && p[1] === 254);
    }
    return ip === '::1' || ip.indexOf('fe80') === 0 ||
           ip.indexOf('fc') === 0 || ip.indexOf('fd') === 0;
  }

  function getWebRTCIP() {
    return new Promise(function (resolve) {
      var done = false;
      function finish(ip) { if (!done) { done = true; resolve(ip); } }
      try {
        if (!window.RTCPeerConnection) return finish('None');
        var pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        var ips = new Set();
        try { pc.createDataChannel('ovg'); } catch (e) {}
        pc.onicecandidate = function (e) {
          if (!e.candidate) return;
          var m = e.candidate.candidate.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
          if (m && !isPrivateIP(m[1])) ips.add(m[1]);
        };
        pc.createOffer()
          .then(function (o) { return pc.setLocalDescription(o); })
          .catch(function () {});
        setTimeout(function () {
          try { pc.close(); } catch (e) {}
          finish(ips.size ? Array.from(ips).join(',') : 'None');
        }, WEBRTC_TIMEOUT);
      } catch (e) { finish('None'); }
    });
  }

  function getCanvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 220; c.height = 40;
      var ctx = c.getContext('2d');
      if (!ctx) return 'blocked';
      ctx.textBaseline = 'top'; ctx.font = '15px Arial';
      ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
      ctx.fillStyle = '#069'; ctx.fillText('OVG-FP-123', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('OVG-FP-123', 4, 17);
      var data = c.toDataURL();
      var h = 5381;
      for (var i = 0; i < data.length; i++) h = ((h << 5) + h + data.charCodeAt(i)) | 0;
      return 'fp_' + Math.abs(h).toString(16);
    } catch (e) { return 'blocked'; }
  }

  function getWebGL() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { renderer: 'blocked', vendor: 'blocked' };
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return { renderer: 'Unknown', vendor: 'Unknown' };
      return {
        renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'),
        vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown')
      };
    } catch (e) { return { renderer: 'blocked', vendor: 'blocked' }; }
  }

  function getTimezone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; }
    catch (e) { return 'Unknown'; }
  }

  function buildPayload(webrtc) {
    return {
      url: location.href,
      page_url: location.pathname + location.search,
      referrer: document.referrer || '',
      site_key: SITE_KEY,
      nav: {
        ua: navigator.userAgent,
        platform: navigator.platform || '',
        webdriver: navigator.webdriver === true,
        language: navigator.language || 'Unknown',
        doNotTrack: navigator.doNotTrack === '1' || window.doNotTrack === '1'
      },
      fingerprint: {
        timezone: getTimezone(),
        canvas_hash: getCanvasHash(),
        hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
        deviceMemory: Number(navigator.deviceMemory) || 0,
        webgl: getWebGL()
      },
      behavior: {
        time_on_page_ms: Date.now() - startTime,
        mouse_variance: variance(mouseX) + variance(mouseY),
        events: { mousemove: mousemoves, touchstart: touchstarts }
      },
      screen: {
        width: screen.width, height: screen.height,
        availWidth: screen.availWidth, availHeight: screen.availHeight,
        colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1
      },
      webrtc_ip: webrtc || 'None'
    };
  }

  function send() {
    if (sent) return;
    sent = true;
    getWebRTCIP().then(function (ip) {
      var body = JSON.stringify(buildPayload(ip));
      fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true
      }).catch(function (err) {
        try { console.error('[OVG Tracker] Send failed:', err); } catch (e) {}
      });
    });
  }

  setTimeout(send, SEND_DELAY_MS);
  window.addEventListener('beforeunload', function () { send(); });
})();
</script>"""


def _json_escape(s: str) -> str:
    return json.dumps(s)


@app.get("/api/sites/{site_id}/tracker-code")
def get_tracker_code(site_id: int, request: Request,
                     user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id,
                                      SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    if not HEX_KEY_RE.match(site.site_key or ""):
        site.site_key = new_site_key()
        db.commit()

    origin = safe_origin(request)
    endpoint = f"{origin}/api/track"

    code = (TRACKER_CODE_TEMPLATE
            .replace("__OVG_SITE_KEY__", site.site_key)
            .replace("__OVG_ENDPOINT__", endpoint))

    return Response(
        content='{"code":' + _json_escape(code) + '}',
        media_type="application/json",
        headers={"Cache-Control": "no-store, max-age=0"},
    )

# =========================================================
# TRACK ENDPOINT
# =========================================================
@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    track_limiter.check(client_ip)
    zone_id = extract_zone_id(payload.url)
    ua = (payload.nav or {}).get("ua") or ""
    os_name, device, browser = parse_ua(ua)
    ip_info = await get_ip_info(client_ip)

    site_id = None
    if payload.site_key:
        s = db.query(SiteModel).filter(SiteModel.site_key == payload.site_key).first()
        if s:
            site_id = s.id

    try:
        data = payload.model_dump()
    except AttributeError:
        data = payload.dict()
    data["client_ip"] = client_ip
    result = analyze_visit(data, ip_info)
    fp = data.get("fingerprint") or {}
    nav = data.get("nav") or {}

    visit = VisitModel(
        site_id=site_id,
        ip=client_ip,
        user_agent=ua,
        zone_id=zone_id,
        score=result["score"],
        verdict=result["verdict"],
        evidence=result["evidence"],
        breakdown=result["breakdown"],
        os=os_name,
        device=device,
        browser=browser,
        country=ip_info["country"],
        isp=ip_info["isp"],
        timezone=fp.get("timezone", "Unknown"),
        canvas_hash=(str(fp.get("canvas_hash", "Unknown"))[:15] + "...") if fp.get("canvas_hash") else "Unknown",
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"],
        asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"),
        webrtc_ip=payload.webrtc_ip,
        language=str(nav.get("language", "Unknown"))[:20],
        do_not_track=bool(nav.get("doNotTrack", False)),
        referrer=str(payload.referrer or "")[:500],
        page_url=str(payload.page_url or "")[:500],
        tags=[],
    )
    try:
        db.add(visit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "DB write failed")
    return {"status": "success"}


# =========================================================
# VISITS API — LIST / DETAIL / EXPORT / BULK / UPDATE
# =========================================================
ALLOWED_SORT_FIELDS = {
    "timestamp": VisitModel.timestamp,
    "score": VisitModel.score,
    "country": VisitModel.country,
    "zone": VisitModel.zone_id,
    "device": VisitModel.device,
    "browser": VisitModel.browser,
    "os": VisitModel.os,
    "asn": VisitModel.asn,
    "isp": VisitModel.isp,
    "verdict": VisitModel.verdict,
    "ip": VisitModel.ip,
}

ALLOWED_GROUP_FIELDS = {
    "country": VisitModel.country,
    "zone": VisitModel.zone_id,
    "verdict": VisitModel.verdict,
    "device": VisitModel.device,
    "browser": VisitModel.browser,
    "os": VisitModel.os,
    "asn": VisitModel.asn,
    "isp": VisitModel.isp,
}


def _apply_visits_filters(q, params: dict, user: UserModel, db: Session):
    """Apply filters from request query params to a query object."""
    site = params.get("site")
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    def _multi(name):
        v = params.get(name)
        if not v:
            return None
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return list(v)

    countries = _multi("country")
    if countries:
        q = q.filter(VisitModel.country.in_(countries))

    zones = _multi("zone")
    if zones:
        q = q.filter(VisitModel.zone_id.in_(zones))

    verdicts = _multi("verdict")
    if verdicts:
        q = q.filter(VisitModel.verdict.in_(verdicts))

    devices = _multi("device")
    if devices:
        q = q.filter(VisitModel.device.in_(devices))

    browsers = _multi("browser")
    if browsers:
        q = q.filter(VisitModel.browser.in_(browsers))

    oses = _multi("os")
    if oses:
        q = q.filter(VisitModel.os.in_(oses))

    isps = _multi("isp")
    if isps:
        q = q.filter(VisitModel.isp.in_(isps))

    asns = _multi("asn")
    if asns:
        q = q.filter(VisitModel.asn.in_(asns))

    ip = params.get("ip")
    if ip:
        q = q.filter(VisitModel.ip.like(f"%{ip}%"))

    score_min = params.get("score_min")
    if score_min not in (None, ""):
        try:
            q = q.filter(VisitModel.score >= int(score_min))
        except (ValueError, TypeError):
            pass

    score_max = params.get("score_max")
    if score_max not in (None, ""):
        try:
            q = q.filter(VisitModel.score <= int(score_max))
        except (ValueError, TypeError):
            pass

    date_from = params.get("date_from")
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from.replace("Z", ""))
            q = q.filter(VisitModel.timestamp >= dt)
        except Exception:
            pass

    date_to = params.get("date_to")
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to.replace("Z", ""))
            q = q.filter(VisitModel.timestamp <= dt)
        except Exception:
            pass

    webrtc = params.get("webrtc")
    if webrtc == "leak":
        q = q.filter(and_(VisitModel.webrtc_ip != "None", VisitModel.webrtc_ip != ""))
    elif webrtc == "none":
        q = q.filter(or_(VisitModel.webrtc_ip == "None", VisitModel.webrtc_ip == ""))

    vpn = params.get("vpn")
    if vpn in ("true", "1", True):
        q = q.filter(VisitModel.is_vpn == True)  # noqa: E712
    elif vpn in ("false", "0", False):
        q = q.filter(VisitModel.is_vpn == False)  # noqa: E712

    return q


def _visit_to_dict(v: VisitModel) -> dict:
    return {
        "id": v.id,
        "timestamp": v.timestamp.isoformat() if v.timestamp else None,
        "ip": v.ip,
        "zone": v.zone_id,
        "verdict": v.verdict,
        "score": v.score,
        "country": v.country,
        "isp": v.isp,
        "asn": v.asn,
        "device": v.device,
        "browser": v.browser,
        "os": v.os,
        "timezone": v.timezone,
        "canvas_hash": v.canvas_hash,
        "hardware": v.hardware,
        "connection_type": v.connection_type,
        "is_vpn": v.is_vpn,
        "webrtc": v.webrtc_ip,
        "language": v.language,
        "do_not_track": v.do_not_track,
        "referrer": v.referrer,
        "page_url": v.page_url,
        "evidence": v.evidence or [],
        "breakdown": v.breakdown or [],
        "tags": v.tags or [],
        "note": v.note or "",
        "is_whitelisted": v.is_whitelisted,
        "is_blacklisted": v.is_blacklisted,
        "user_agent": v.user_agent,
    }


@app.get("/api/visits")
def list_visits(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=200),
    sort_by: str = Query("timestamp"),
    sort_dir: str = Query("desc"),
    group_by: str = Query("", alias="groupBy"),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    params = dict(request.query_params)
    q = _apply_visits_filters(db.query(VisitModel), params, user, db)

    total = q.count()

    # Sorting
    sort_col = ALLOWED_SORT_FIELDS.get(sort_by, VisitModel.timestamp)
    order_fn = desc if (sort_dir or "").lower() == "desc" else asc
    q = q.order_by(order_fn(sort_col), desc(VisitModel.id))

    offset = (page - 1) * per_page
    rows = q.offset(offset).limit(per_page).all()
    items = [_visit_to_dict(v) for v in rows]

    # Optional grouping of the returned chunk
    groups = None
    if group_by and group_by in ALLOWED_GROUP_FIELDS:
        gcol = ALLOWED_GROUP_FIELDS[group_by]
        gq = _apply_visits_filters(db.query(gcol, func.count(VisitModel.id)), params, user, db)
        gq = gq.group_by(gcol).order_by(desc(func.count(VisitModel.id))).limit(30)
        groups = [{"key": str(k or "Unknown"), "count": int(c or 0)} for k, c in gq.all()]

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, math.ceil(total / per_page)),
        "groups": groups,
    }


@app.get("/api/visits/export")
def export_visits(
    request: Request,
    format: str = Query("csv"),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    params = dict(request.query_params)
    q = _apply_visits_filters(db.query(VisitModel), params, user, db)
    q = q.order_by(desc(VisitModel.timestamp)).limit(50000)
    rows = q.all()
    items = [_visit_to_dict(v) for v in rows]

    if format == "json":
        return Response(
            content=json.dumps(items, ensure_ascii=False),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="visits.json"'},
        )

    # CSV
    cols = [
        "id", "timestamp", "ip", "zone", "verdict", "score", "country",
        "isp", "asn", "device", "browser", "os", "timezone", "connection_type",
        "is_vpn", "webrtc", "language", "page_url", "referrer", "tags", "note",
    ]

    def _esc_csv(x) -> str:
        s = str(x if x is not None else "")
        if any(c in s for c in (",", '"', "\n", "\r")):
            s = '"' + s.replace('"', '""') + '"'
        return s

    lines = [",".join(cols)]
    for it in items:
        row = []
        for c in cols:
            val = it.get(c)
            if isinstance(val, list):
                val = ";".join(str(x) for x in val)
            row.append(_esc_csv(val))
        lines.append(",".join(row))

    csv_data = "\n".join(lines)
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="visits.csv"'},
    )


@app.get("/api/visits/{visit_id}")
def get_visit(visit_id: int, user: UserModel = Depends(current_user),
              db: Session = Depends(get_db)):
    v = db.query(VisitModel).filter(VisitModel.id == visit_id).first()
    if not v:
        raise HTTPException(404, "الزيارة مش موجودة")
    # Ownership check
    if v.site_id is None:
        raise HTTPException(403, "زيارة غير مرتبطة بموقع")
    site = db.query(SiteModel).filter(SiteModel.id == v.site_id,
                                      SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(403, "مش بتاعتك")

    out = _visit_to_dict(v)
    out["site"] = {"id": site.id, "name": site.name, "site_key": site.site_key}

    # Similar visits
    def _count(q):
        try:
            return q.count()
        except Exception:
            return 0

    same_ip_q = db.query(VisitModel).filter(
        VisitModel.site_id == site.id, VisitModel.ip == v.ip, VisitModel.id != v.id
    )
    same_fp_q = db.query(VisitModel).filter(
        VisitModel.site_id == site.id, VisitModel.canvas_hash == v.canvas_hash,
        VisitModel.id != v.id
    ) if v.canvas_hash and v.canvas_hash != "Unknown" else None
    same_asn_q = db.query(VisitModel).filter(
        VisitModel.site_id == site.id, VisitModel.asn == v.asn,
        VisitModel.id != v.id
    ) if v.asn and v.asn != "Unknown" else None

    out["similar"] = {
        "same_ip": _count(same_ip_q),
        "same_fp": _count(same_fp_q) if same_fp_q is not None else 0,
        "same_asn": _count(same_asn_q) if same_asn_q is not None else 0,
    }
    return out


@app.patch("/api/visits/{visit_id}")
def update_visit(visit_id: int, payload: VisitUpdateIn,
                 user: UserModel = Depends(current_user),
                 db: Session = Depends(get_db)):
    v = db.query(VisitModel).filter(VisitModel.id == visit_id).first()
    if not v or v.site_id is None:
        raise HTTPException(404, "الزيارة مش موجودة")
    site = db.query(SiteModel).filter(SiteModel.id == v.site_id,
                                      SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(403, "مش بتاعتك")

    if payload.verdict in ("valid", "suspicious", "invalid"):
        v.verdict = payload.verdict
        if payload.verdict == "valid":
            v.score = 0
        elif payload.verdict == "invalid":
            v.score = 150
    if payload.note is not None:
        v.note = payload.note[:1000]
    if payload.tags is not None:
        v.tags = [str(t)[:32] for t in payload.tags[:10]]
    db.commit()
    return {"ok": True, "visit": _visit_to_dict(v)}


@app.post("/api/visits/bulk")
def bulk_visits(payload: BulkActionIn, user: UserModel = Depends(current_user),
                db: Session = Depends(get_db)):
    if not payload.ids:
        raise HTTPException(400, "مفيش زيارات محددة")
    if len(payload.ids) > 1000:
        raise HTTPException(400, "حد أقصى 1000 زيارة في المرة")

    allowed_sites = [x.id for x in db.query(SiteModel.id).filter(
        SiteModel.user_id == user.id).all()]
    if not allowed_sites:
        raise HTTPException(403, "مفيش مواقع")

    q = db.query(VisitModel).filter(
        VisitModel.id.in_(payload.ids), VisitModel.site_id.in_(allowed_sites)
    )
    rows = q.all()
    if not rows:
        raise HTTPException(404, "مفيش زيارات مطابقة")

    action = payload.action
    if action == "delete":
        for v in rows:
            db.delete(v)
    elif action == "mark_valid":
        for v in rows:
            v.verdict = "valid"
            v.score = 0
            v.is_whitelisted = True
    elif action == "mark_invalid":
        for v in rows:
            v.verdict = "invalid"
            v.score = 150
            v.is_blacklisted = True
    elif action == "add_tag":
        tag = (payload.tag or "").strip()[:32]
        if not tag:
            raise HTTPException(400, "tag مطلوب")
        for v in rows:
            tags = list(v.tags or [])
            if tag not in tags:
                tags.append(tag)
            v.tags = tags[:10]
    else:
        raise HTTPException(400, "action غير معروف")

    db.commit()
    return {"ok": True, "affected": len(rows)}


# =========================================================
# SEGMENTS (saved filters)
# =========================================================
@app.get("/api/segments")
def list_segments(site: str = Query(None),
                  user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    q = db.query(SegmentModel).filter(SegmentModel.user_id == user.id)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(or_(SegmentModel.site_id == s.id, SegmentModel.site_id.is_(None)))
    else:
        q = q.filter(SegmentModel.site_id.is_(None))
    rows = q.order_by(desc(SegmentModel.created_at)).all()
    return [{
        "id": r.id, "name": r.name, "filters": r.filters,
        "site_id": r.site_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows]


@app.post("/api/segments")
def create_segment(payload: SegmentIn, user: UserModel = Depends(current_user),
                   db: Session = Depends(get_db)):
    name = (payload.name or "").strip()
    if not name or len(name) > 60:
        raise HTTPException(400, "اسم الـ Segment مطلوب (أقصى 60 حرف)")
    site_id = None
    if payload.site:
        s = _resolve_user_site(payload.site, user, db)
        site_id = s.id
    seg = SegmentModel(user_id=user.id, site_id=site_id, name=name, filters=payload.filters or {})
    db.add(seg)
    db.commit()
    db.refresh(seg)
    return {"id": seg.id, "name": seg.name}


@app.delete("/api/segments/{seg_id}")
def delete_segment(seg_id: int, user: UserModel = Depends(current_user),
                   db: Session = Depends(get_db)):
    seg = db.query(SegmentModel).filter(SegmentModel.id == seg_id,
                                        SegmentModel.user_id == user.id).first()
    if not seg:
        raise HTTPException(404, "Segment مش موجود")
    db.delete(seg)
    db.commit()
    return {"ok": True}

# =========================================================
# STATS (KPI cards + live feed)
# =========================================================
def _user_site_ids(user: UserModel, db: Session) -> List[int]:
    return [x.id for x in db.query(SiteModel.id).filter(
        SiteModel.user_id == user.id).all()]


def _site_filter(q, site: str, user: UserModel, db: Session):
    if site:
        s = _resolve_user_site(site, user, db)
        return q.filter(VisitModel.site_id == s.id)
    ids = _user_site_ids(user, db)
    return q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)


@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user),
              db: Session = Depends(get_db)):
    q = _site_filter(db.query(VisitModel), site, user, db)

    total = q.count()
    valid = q.filter(VisitModel.verdict == "valid").count()
    invalid = q.filter(VisitModel.verdict == "invalid").count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()

    # Today vs Yesterday
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)

    today_total = q.filter(VisitModel.timestamp >= today_start).count()
    yesterday_total = q.filter(and_(
        VisitModel.timestamp >= yesterday_start,
        VisitModel.timestamp < today_start
    )).count()

    today_bots = q.filter(and_(
        VisitModel.timestamp >= today_start,
        VisitModel.verdict == "invalid"
    )).count()
    yesterday_bots = q.filter(and_(
        VisitModel.timestamp >= yesterday_start,
        VisitModel.timestamp < today_start,
        VisitModel.verdict == "invalid"
    )).count()

    today_quality = round((today_total - today_bots) / today_total * 100, 1) if today_total else 0.0
    yesterday_quality = round(
        (yesterday_total - yesterday_bots) / yesterday_total * 100, 1
    ) if yesterday_total else 0.0

    # Live indicator: any visit in last 5 minutes
    five_min_ago = now - timedelta(minutes=5)
    live_count = q.filter(VisitModel.timestamp >= five_min_ago).count()

    recent = q.order_by(desc(VisitModel.id)).limit(15).all()
    recent_visits = [{
        "id": v.id,
        "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id,
        "verdict": v.verdict,
        "country": v.country,
        "score": v.score,
        "evidence": v.evidence or [],
        "timezone": v.timezone,
        "hardware": v.hardware,
        "conn_type": v.connection_type,
        "asn": v.asn,
        "is_vpn": v.is_vpn,
        "webrtc": v.webrtc_ip,
    } for v in recent]

    return {
        "total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious,
        "today": {
            "total": today_total,
            "bots": today_bots,
            "quality": today_quality,
            "delta_total": _pct_delta(today_total, yesterday_total),
            "delta_bots": _pct_delta(today_bots, yesterday_bots),
            "delta_quality": round(today_quality - yesterday_quality, 1),
        },
        "live_count": live_count,
        "recent": recent_visits,
    }


def _pct_delta(a: int, b: int) -> float:
    if b == 0:
        return 0.0 if a == 0 else 100.0
    return round((a - b) / b * 100, 1)


# =========================================================
# SPARKLINES (7-day trend per KPI)
# =========================================================
@app.get("/api/stats/sparkline")
def sparkline(site: str = Query(None), user: UserModel = Depends(current_user),
              db: Session = Depends(get_db)):
    now = datetime.utcnow()
    end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    start = end - timedelta(days=7)

    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.filter(VisitModel.timestamp >= start, VisitModel.timestamp < end)
    rows = q.all()

    days = [start.date() + timedelta(days=i) for i in range(7)]
    labels = [d.strftime("%m-%d") for d in days]
    total_by_day = {d: 0 for d in days}
    bots_by_day = {d: 0 for d in days}

    for v in rows:
        if not v.timestamp:
            continue
        d = v.timestamp.date()
        if d in total_by_day:
            total_by_day[d] += 1
            if v.verdict == "invalid":
                bots_by_day[d] += 1

    totals = [total_by_day[d] for d in days]
    bots = [bots_by_day[d] for d in days]
    quality = [
        round((totals[i] - bots[i]) / totals[i] * 100, 1) if totals[i] else 0.0
        for i in range(7)
    ]

    return {"labels": labels, "totals": totals, "bots": bots, "quality": quality}


# =========================================================
# INSIGHTS (smart bullet points)
# =========================================================
@app.get("/api/insights")
def insights(site: str = Query(None), user: UserModel = Depends(current_user),
             db: Session = Depends(get_db)):
    out = []
    now = datetime.utcnow()
    one_hour_ago = now - timedelta(hours=1)
    ten_min_ago = now - timedelta(minutes=10)
    seven_days_ago = now - timedelta(days=7)

    base = _site_filter(db.query(VisitModel), site, user, db)
    site_id_for_links = None
    if site:
        try:
            s = _resolve_user_site(site, user, db)
            site_id_for_links = s.site_key
        except Exception:
            pass

    # Top country by quality (last 7 days)
    country_rows = (base
                    .filter(VisitModel.timestamp >= seven_days_ago)
                    .group_by(VisitModel.country)
                    .with_entities(
                        VisitModel.country,
                        func.count(VisitModel.id).label("total"),
                        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("bots")
                    )
                    .having(func.count(VisitModel.id) >= 5)
                    .all())
    if country_rows:
        scored = []
        for c, total, bots in country_rows:
            quality = round((total - (bots or 0)) / total * 100, 1) if total else 0
            scored.append((c, total, bots or 0, quality))
        scored.sort(key=lambda x: x[3], reverse=True)
        best = scored[0]
        worst = scored[-1]
        if best[3] >= 90:
            out.append({
                "type": "positive",
                "text": f"أعلى جودة ترافيك من {best[0]} ({best[3]}%) في آخر 7 أيام.",
            })
        if worst[3] < 60 and worst[1] >= 5:
            out.append({
                "type": "warning",
                "text": f"أقل جودة ترافيك من {worst[0]} ({worst[3]}%) — راجع مصادره.",
            })

    # Bot spike in last hour vs 24h average
    last_hour_bots = base.filter(and_(
        VisitModel.timestamp >= one_hour_ago,
        VisitModel.verdict == "invalid"
    )).count()
    twenty_four_ago = now - timedelta(hours=24)
    last_24_bots = base.filter(and_(
        VisitModel.timestamp >= twenty_four_ago,
        VisitModel.verdict == "invalid"
    )).count()
    hourly_avg = last_24_bots / 24.0
    if hourly_avg > 0 and last_hour_bots >= hourly_avg * 2.5 and last_hour_bots >= 5:
        out.append({
            "type": "critical",
            "text": f"⚠️ زيادة {int((last_hour_bots / hourly_avg - 1) * 100)}% في البوتات في آخر ساعة ({last_hour_bots} زيارة).",
        })

    # Repeated fingerprint burst (last 10 min)
    dup = (base
           .filter(VisitModel.timestamp >= ten_min_ago)
           .filter(VisitModel.canvas_hash != "Unknown")
           .filter(VisitModel.canvas_hash.isnot(None))
           .group_by(VisitModel.canvas_hash)
           .with_entities(VisitModel.canvas_hash, func.count(VisitModel.id).label("c"))
           .having(func.count(VisitModel.id) >= 10)
           .order_by(desc(func.count(VisitModel.id)))
           .first())
    if dup:
        out.append({
            "type": "critical",
            "text": f"🧬 بصمة واحدة ({dup[0][:12]}...) ظهرت في {dup[1]} زيارة في آخر 10 دقايق — في الغالب شبكة بوتات.",
        })

    # Timezone mismatch country
    tz_mismatch = base.filter(and_(
        VisitModel.timestamp >= seven_days_ago,
        VisitModel.timezone.in_(["UTC", "Etc/UTC", "Unknown", ""])
    )).count()
    if tz_mismatch >= 10:
        out.append({
            "type": "warning",
            "text": f"⏰ {tz_mismatch} زيارة بدون Timezone واضح — مؤشر على أدوات أتمتة.",
        })

    if not out:
        out.append({
            "type": "positive",
            "text": "✅ كل حاجة تمام — مفيش شذوذ في آخر 7 أيام.",
        })
    return out


# =========================================================
# TREND (24h / 7d / 30d for line chart)
# =========================================================
@app.get("/api/reports/trend")
def report_trend(range: str = Query("7d", alias="range"),
                 site: str = Query(None),
                 user: UserModel = Depends(current_user),
                 db: Session = Depends(get_db)):
    now = datetime.utcnow()
    if range == "24h":
        start = now - timedelta(hours=24)
        buckets = 24
        step = timedelta(hours=1)
        fmt = "%H:00"
    elif range == "30d":
        start = (now - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
        buckets = 30
        step = timedelta(days=1)
        fmt = "%m-%d"
    else:  # 7d
        start = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        buckets = 7
        step = timedelta(days=1)
        fmt = "%m-%d"

    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.filter(VisitModel.timestamp >= start)
    rows = q.all()

    labels = [(start + step * i).strftime(fmt) for i in range(buckets)]
    totals = [0] * buckets
    bots = [0] * buckets

    for v in rows:
        if not v.timestamp:
            continue
        idx = int((v.timestamp - start) / step)
        if 0 <= idx < buckets:
            totals[idx] += 1
            if v.verdict == "invalid":
                bots[idx] += 1

    return {"labels": labels, "totals": totals, "bots": bots}


# =========================================================
# ZONES REPORT (with trend)
# =========================================================
@app.get("/api/reports/zones")
def report_zones(site: str = Query(None), user: UserModel = Depends(current_user),
                 db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    valid_expr = func.sum(case((VisitModel.verdict == "valid", 1), else_=0))
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.with_entities(
        VisitModel.zone_id,
        func.count(VisitModel.id).label("total"),
        invalid_expr.label("invalid"),
        valid_expr.label("valid"),
    ).group_by(VisitModel.zone_id)
    rows = q.all()

    report = []
    for z in rows:
        total = int(z.total or 0)
        invalid = int(z.invalid or 0)
        valid = int(z.valid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = "A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F"
        report.append({
            "zone": z.zone_id,
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "bot_rate": rate,
            "grade": grade,
        })
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report


# =========================================================
# COUNTRY REPORT
# =========================================================
@app.get("/api/reports/countries")
def report_countries(site: str = Query(None), user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    valid_expr = func.sum(case((VisitModel.verdict == "valid", 1), else_=0))
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.with_entities(
        VisitModel.country,
        func.count(VisitModel.id).label("total"),
        invalid_expr.label("invalid"),
        valid_expr.label("valid"),
    ).group_by(VisitModel.country)
    rows = q.all()
    out = []
    for r in rows:
        total = int(r.total or 0)
        invalid = int(r.invalid or 0)
        valid = int(r.valid or 0)
        out.append({
            "country": r.country or "Unknown",
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "quality": round(valid / total * 100, 1) if total else 0,
        })
    out.sort(key=lambda x: x["total"], reverse=True)
    return out


# =========================================================
# DEVICES / BROWSERS / OS
# =========================================================
def _grouped_report(column, site: str, user: UserModel, db: Session):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.with_entities(
        column.label("k"),
        func.count(VisitModel.id).label("total"),
        invalid_expr.label("invalid"),
    ).group_by(column)
    rows = q.all()
    out = []
    for r in rows:
        total = int(r.total or 0)
        invalid = int(r.invalid or 0)
        out.append({
            "key": r.k or "Unknown",
            "total": total,
            "invalid": invalid,
            "quality": round((total - invalid) / total * 100, 1) if total else 0,
        })
    out.sort(key=lambda x: x["total"], reverse=True)
    return out


@app.get("/api/reports/devices")
def report_devices(site: str = Query(None), user: UserModel = Depends(current_user),
                   db: Session = Depends(get_db)):
    return _grouped_report(VisitModel.device, site, user, db)


@app.get("/api/reports/browsers")
def report_browsers(site: str = Query(None), user: UserModel = Depends(current_user),
                    db: Session = Depends(get_db)):
    return _grouped_report(VisitModel.browser, site, user, db)


@app.get("/api/reports/os")
def report_os(site: str = Query(None), user: UserModel = Depends(current_user),
              db: Session = Depends(get_db)):
    return _grouped_report(VisitModel.os, site, user, db)


# =========================================================
# FINGERPRINTS REPORT
# =========================================================
@app.get("/api/reports/fingerprints")
def report_fingerprints(site: str = Query(None), user: UserModel = Depends(current_user),
                        db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.filter(VisitModel.canvas_hash != "Unknown").filter(VisitModel.canvas_hash.isnot(None))
    q = q.with_entities(
        VisitModel.canvas_hash,
        func.count(VisitModel.id).label("total"),
        func.count(func.distinct(VisitModel.ip)).label("unique_ips"),
        invalid_expr.label("invalid"),
    ).group_by(VisitModel.canvas_hash).having(func.count(VisitModel.id) > 1)
    rows = q.order_by(desc(func.count(VisitModel.id))).limit(100).all()

    out = []
    for r in rows:
        total = int(r.total or 0)
        ips = int(r.unique_ips or 0)
        invalid = int(r.invalid or 0)
        risk = "high" if ips >= 5 else "medium" if ips >= 2 else "low"
        out.append({
            "canvas_hash": r.canvas_hash,
            "total": total,
            "unique_ips": ips,
            "invalid": invalid,
            "risk": risk,
        })
    return out


# =========================================================
# REPEATED IPs REPORT
# =========================================================
@app.get("/api/reports/ips")
def report_ips(site: str = Query(None), user: UserModel = Depends(current_user),
               db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.with_entities(
        VisitModel.ip,
        func.count(VisitModel.id).label("total"),
        func.count(func.distinct(VisitModel.canvas_hash)).label("unique_fps"),
        invalid_expr.label("invalid"),
        VisitModel.country,
        VisitModel.asn,
    ).group_by(VisitModel.ip).having(func.count(VisitModel.id) > 1)
    rows = q.order_by(desc(func.count(VisitModel.id))).limit(100).all()
    return [{
        "ip": r.ip,
        "total": int(r.total or 0),
        "unique_fps": int(r.unique_fps or 0),
        "invalid": int(r.invalid or 0),
        "country": r.country or "Unknown",
        "asn": r.asn or "Unknown",
    } for r in rows]


# =========================================================
# ASN REPORT
# =========================================================
@app.get("/api/reports/asn")
def report_asn(site: str = Query(None), user: UserModel = Depends(current_user),
               db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.with_entities(
        VisitModel.asn,
        func.count(VisitModel.id).label("total"),
        invalid_expr.label("invalid"),
        func.count(func.distinct(VisitModel.isp)).label("isps"),
    ).group_by(VisitModel.asn).having(func.count(VisitModel.id) > 1)
    rows = q.order_by(desc(func.count(VisitModel.id))).limit(30).all()
    out = []
    for r in rows:
        total = int(r.total or 0)
        invalid = int(r.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0
        out.append({
            "asn": r.asn or "Unknown",
            "total": total,
            "invalid": invalid,
            "bot_rate": rate,
            "isps": int(r.isps or 0),
        })
    return out


# =========================================================
# TIMEZONES REPORT
# =========================================================
@app.get("/api/reports/timezones")
def report_timezones(site: str = Query(None), user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.with_entities(
        VisitModel.timezone,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
    ).group_by(VisitModel.timezone)
    rows = q.order_by(desc(func.count(VisitModel.id))).limit(50).all()
    return [{
        "timezone": r.timezone or "Unknown",
        "total": int(r.total or 0),
        "invalid": int(r.invalid or 0),
    } for r in rows]


# =========================================================
# WEBRTC LEAKS REPORT
# =========================================================
@app.get("/api/reports/webrtc")
def report_webrtc(site: str = Query(None), user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.filter(and_(
        VisitModel.webrtc_ip != "None",
        VisitModel.webrtc_ip != "",
        VisitModel.webrtc_ip.isnot(None),
    ))
    rows = q.order_by(desc(VisitModel.timestamp)).limit(500).all()
    return [{
        "id": r.id,
        "ip": r.ip,
        "webrtc": r.webrtc_ip,
        "country": r.country,
        "verdict": r.verdict,
        "time": r.timestamp.isoformat() if r.timestamp else None,
    } for r in rows]


# =========================================================
# VPN REPORT
# =========================================================
@app.get("/api/reports/vpn")
def report_vpn(site: str = Query(None), user: UserModel = Depends(current_user),
               db: Session = Depends(get_db)):
    q = _site_filter(db.query(VisitModel), site, user, db)
    total = q.count()
    vpn = q.filter(VisitModel.is_vpn == True).count()  # noqa: E712
    hosting = q.filter(VisitModel.connection_type == "hosting").count()
    return {
        "total": total,
        "vpn": vpn,
        "hosting": hosting,
        "vpn_rate": round(vpn / total * 100, 1) if total else 0,
        "hosting_rate": round(hosting / total * 100, 1) if total else 0,
    }


# =========================================================
# HOURLY HEATMAP (7×24)
# =========================================================
@app.get("/api/reports/hourly")
def report_hourly(site: str = Query(None), user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    now = datetime.utcnow()
    start = (now - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.filter(VisitModel.timestamp >= start)
    rows = q.all()

    grid = [[0] * 24 for _ in range(7)]
    bot_grid = [[0] * 24 for _ in range(7)]

    for v in rows:
        if not v.timestamp:
            continue
        dow = v.timestamp.weekday()  # Monday=0
        hr = v.timestamp.hour
        grid[dow][hr] += 1
        if v.verdict == "invalid":
            bot_grid[dow][hr] += 1

    days_ar = ["الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت", "الأحد"]
    return {
        "days": days_ar,
        "hours": list(range(24)),
        "grid": grid,
        "bot_grid": bot_grid,
    }


# =========================================================
# ANOMALIES (days with high bot rate)
# =========================================================
@app.get("/api/reports/anomalies")
def report_anomalies(site: str = Query(None), user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    now = datetime.utcnow()
    start = (now - timedelta(days=29)).replace(hour=0, minute=0, second=0, microsecond=0)
    q = _site_filter(db.query(VisitModel), site, user, db)
    q = q.filter(VisitModel.timestamp >= start)
    rows = q.all()

    by_day = defaultdict(lambda: {"total": 0, "invalid": 0})
    for v in rows:
        if not v.timestamp:
            continue
        d = v.timestamp.date().isoformat()
        by_day[d]["total"] += 1
        if v.verdict == "invalid":
            by_day[d]["invalid"] += 1

    if not by_day:
        return {"average_rate": 0.0, "days": []}

    rates = [(v["invalid"] / v["total"] * 100) if v["total"] else 0
             for v in by_day.values()]
    avg = sum(rates) / len(rates) if rates else 0.0

    out = []
    for d, v in sorted(by_day.items()):
        rate = round((v["invalid"] / v["total"] * 100), 1) if v["total"] else 0
        if rate >= avg * 1.5 and rate >= 20:
            out.append({
                "date": d,
                "total": v["total"],
                "invalid": v["invalid"],
                "rate": rate,
                "avg_rate": round(avg, 1),
            })
    return {"average_rate": round(avg, 1), "days": out}


# =========================================================
# MOCK DATA (for testing)
# =========================================================
@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    countries = ["Egypt", "US", "UK", "India", "Germany", "France", "SA"]
    devices = ["Desktop", "Mobile", "Tablet"]
    browsers = ["Chrome", "Safari", "Firefox", "Edge"]
    oses = ["Windows", "macOS", "iOS", "Android", "Linux"]
    now = datetime.utcnow()

    for i in range(120):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid" else
              random.randint(70, 150) if v == "invalid" else random.randint(40, 69))
        ts = now - timedelta(minutes=random.randint(0, 60 * 24 * 7))
        db.add(VisitModel(
            site_id=s.id, ip=f"41.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            user_agent="Mock", zone_id=random.choice(zones), score=sc, verdict=v,
            evidence=["Mock Data"], breakdown=[],
            country=random.choice(countries), isp="Mock ISP",
            device=random.choice(devices), browser=random.choice(browsers),
            os=random.choice(oses),
            canvas_hash="fp_" + secrets.token_hex(6),
            connection_type=random.choice(["residential", "hosting"]),
            asn="AS" + str(random.randint(1000, 99999)),
            is_vpn=random.random() < 0.2,
            timestamp=ts,
        ))
    db.commit()
    return {"status": "ok", "created": 120}


# =========================================================
# HEALTH & DEBUG
# =========================================================
@app.get("/health")
def health():
    return {"status": "ok", "version": APP_VERSION}


@app.get("/debug/site/{site_key}")
def debug_site(site_key: str, db: Session = Depends(get_db)):
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key).first()
    if not s:
        return {
            "exists": False,
            "error": "❌ الـ site_key ده مش موجود في الداتابيز",
            "received_key": site_key,
            "total_sites_in_db": db.query(func.count(SiteModel.id)).scalar(),
        }
    visits = db.query(func.count(VisitModel.id)).filter(VisitModel.site_id == s.id).scalar() or 0
    return {
        "exists": True,
        "site_name": s.name,
        "domain": s.domain,
        "site_key": s.site_key,
        "visits_count": visits,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


# =========================================================
# LEGACY TRACKER.JS
# =========================================================
TRACKER_JS = r"""
(function() {
  try {
    var script = document.currentScript;
    var SITE_KEY = script ? (script.getAttribute('data-site') || '') : '';
    var ORIGIN = script && script.src ? new URL(script.src).origin : '';
    var ENDPOINT = ORIGIN + '/api/track';
    var SEND_DELAY_MS = 4000;
    var WEBRTC_TIMEOUT = 1500;
    var startTime = Date.now();
    var mousemoves = 0, touchstarts = 0;
    var mouseX = [], mouseY = [];
    var sent = false;

    document.addEventListener('mousemove', function(e) {
      mousemoves++;
      mouseX.push(e.clientX); mouseY.push(e.clientY);
      if (mouseX.length > 200) { mouseX.shift(); mouseY.shift(); }
    }, { passive: true });
    document.addEventListener('touchstart', function() { touchstarts++; }, { passive: true });

    function variance(arr) {
      if (arr.length < 2) return 0;
      var m = arr.reduce(function(a,b){return a+b;},0) / arr.length;
      return arr.reduce(function(a,b){return a + (b-m)*(b-m);},0) / arr.length;
    }
    function isPrivateIP(ip) {
      if (!ip) return true;
      if (ip.indexOf('.') !== -1) {
        var p = ip.split('.').map(Number);
        return p[0]===10 || (p[0]===172 && p[1]>=16 && p[1]<=31) ||
               (p[0]===192 && p[1]===168) || p[0]===127 ||
               (p[0]===169 && p[1]===254);
      }
      return ip==='::1' || ip.indexOf('fe80')===0 || ip.indexOf('fc')===0 || ip.indexOf('fd')===0;
    }
    function getWebRTCIP() {
      return new Promise(function(resolve) {
        var done = false;
        function finish(ip) { if (!done) { done = true; resolve(ip); } }
        try {
          if (!window.RTCPeerConnection) return finish('None');
          var pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
          var ips = new Set();
          try { pc.createDataChannel('ovg'); } catch(e) {}
          pc.onicecandidate = function(e) {
            if (!e.candidate) return;
            var m = e.candidate.candidate.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
            if (m && !isPrivateIP(m[1])) ips.add(m[1]);
          };
          pc.createOffer().then(function(o){ return pc.setLocalDescription(o); }).catch(function(){});
          setTimeout(function() {
            try { pc.close(); } catch(e){}
            finish(ips.size ? Array.from(ips).join(',') : 'None');
          }, WEBRTC_TIMEOUT);
        } catch(e) { finish('None'); }
      });
    }
    function getCanvasHash() {
      try {
        var c = document.createElement('canvas');
        c.width = 220; c.height = 40;
        var ctx = c.getContext('2d');
        if (!ctx) return 'blocked';
        ctx.textBaseline = 'top'; ctx.font = '15px Arial';
        ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
        ctx.fillStyle = '#069'; ctx.fillText('OVG-FP-123', 2, 15);
        ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('OVG-FP-123', 4, 17);
        var data = c.toDataURL();
        var h = 5381;
        for (var i = 0; i < data.length; i++) h = ((h << 5) + h + data.charCodeAt(i)) | 0;
        return 'fp_' + Math.abs(h).toString(16);
      } catch(e) { return 'blocked'; }
    }
    function getWebGL() {
      try {
        var c = document.createElement('canvas');
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (!gl) return { renderer: 'blocked', vendor: 'blocked' };
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (!ext) return { renderer: 'Unknown', vendor: 'Unknown' };
        return {
          renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'),
          vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown')
        };
      } catch(e) { return { renderer: 'blocked', vendor: 'blocked' }; }
    }
    function getTimezone() {
      try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; }
      catch(e) { return 'Unknown'; }
    }
    function buildPayload(webrtc) {
      return {
        url: location.href,
        page_url: location.pathname + location.search,
        referrer: document.referrer || '',
        site_key: SITE_KEY,
        nav: {
          ua: navigator.userAgent,
          platform: navigator.platform || '',
          webdriver: navigator.webdriver === true,
          language: navigator.language || 'Unknown',
          doNotTrack: navigator.doNotTrack === '1' || window.doNotTrack === '1'
        },
        fingerprint: {
          timezone: getTimezone(),
          canvas_hash: getCanvasHash(),
          hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
          deviceMemory: Number(navigator.deviceMemory) || 0,
          webgl: getWebGL()
        },
        behavior: {
          time_on_page_ms: Date.now() - startTime,
          mouse_variance: variance(mouseX) + variance(mouseY),
          events: { mousemove: mousemoves, touchstart: touchstarts }
        },
        screen: {
          width: screen.width, height: screen.height,
          availWidth: screen.availWidth, availHeight: screen.availHeight,
          colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1
        },
        webrtc_ip: webrtc || 'None'
      };
    }
    function send() {
      if (sent) return; sent = true;
      getWebRTCIP().then(function(ip) {
        var body = JSON.stringify(buildPayload(ip));
        fetch(ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: body,
          keepalive: true
        }).catch(function(err){ try { console.error('[OVG Tracker] Send failed:', err); } catch(e){} });
      });
    }
    setTimeout(send, SEND_DELAY_MS);
    window.addEventListener('beforeunload', function() { send(); });
  } catch(e) {}
})();
"""


@app.get("/tracker.js")
def tracker_js():
    return Response(content=TRACKER_JS, media_type="application/javascript",
                    headers={"Cache-Control": "public, max-age=3600"})

# =========================================================
# DESIGN SYSTEM (shared CSS + JS injected into every page)
# =========================================================
DESIGN_SYSTEM_CSS = r"""
:root {
  --ovg-primary: #6366F1;
  --ovg-primary-2: #8B5CF6;
  --ovg-valid: #10B981;
  --ovg-suspicious: #F59E0B;
  --ovg-invalid: #F43F5E;
  --ovg-critical: #DC2626;
  --ovg-bg: #F8FAFC;
  --ovg-bg-elev: #FFFFFF;
  --ovg-card: #FFFFFF;
  --ovg-border: #E2E8F0;
  --ovg-text: #0F172A;
  --ovg-text-muted: #475569;
  --ovg-text-dim: #94A3B8;
  --ovg-shadow-sm: 0 1px 3px rgba(15,23,42,.06), 0 1px 2px rgba(15,23,42,.04);
  --ovg-shadow-md: 0 4px 12px rgba(15,23,42,.08);
  --ovg-shadow-lg: 0 20px 40px -12px rgba(99,102,241,.25);
  --ovg-radius: 16px;
  --ovg-radius-sm: 12px;
  --ovg-font: 'Cairo', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  --ovg-mono: 'JetBrains Mono', 'SF Mono', Menlo, Consolas, monospace;
}
html.dark {
  --ovg-bg: #0F172A;
  --ovg-bg-elev: #1E293B;
  --ovg-card: #1E293B;
  --ovg-border: #334155;
  --ovg-text: #F1F5F9;
  --ovg-text-muted: #CBD5E1;
  --ovg-text-dim: #64748B;
  --ovg-shadow-sm: 0 1px 3px rgba(0,0,0,.3);
  --ovg-shadow-md: 0 4px 12px rgba(0,0,0,.4);
  --ovg-shadow-lg: 0 20px 40px -12px rgba(99,102,241,.4);
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--ovg-bg);
  color: var(--ovg-text);
  font-family: var(--ovg-font);
  font-size: 14px;
  line-height: 1.5;
  transition: background .2s, color .2s;
}
h1,h2,h3,h4 { margin: 0; font-family: var(--ovg-font); font-weight: 700; }
h1 { font-size: 28px; }
h2 { font-size: 20px; }
h3 { font-size: 16px; font-weight: 600; }
p { margin: 0; }
a { color: var(--ovg-primary); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre { font-family: var(--ovg-mono); }

/* Ambient background */
.ovg-ambient {
  position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden;
}
.ovg-ambient::before, .ovg-ambient::after {
  content: ''; position: absolute; border-radius: 50%; filter: blur(80px);
  opacity: .25; animation: ovgFloat 22s ease-in-out infinite;
}
.ovg-ambient::before {
  width: 520px; height: 520px;
  background: radial-gradient(circle, var(--ovg-primary), transparent 70%);
  top: -120px; right: -120px;
}
.ovg-ambient::after {
  width: 420px; height: 420px;
  background: radial-gradient(circle, var(--ovg-primary-2), transparent 70%);
  bottom: -120px; left: -120px; animation-delay: -10s;
}
@keyframes ovgFloat {
  0%,100% { transform: translate(0,0) scale(1); }
  50% { transform: translate(40px,30px) scale(1.1); }
}

/* Buttons */
.ovg-btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  padding: 10px 18px; border-radius: 12px; border: none;
  font-family: inherit; font-weight: 700; font-size: 14px;
  cursor: pointer; transition: all .15s ease;
  text-decoration: none !important;
}
.ovg-btn:focus-visible { outline: none; box-shadow: 0 0 0 4px rgba(99,102,241,.35); }
.ovg-btn:disabled { opacity: .55; cursor: not-allowed; transform: none !important; }
.ovg-btn-primary {
  background: linear-gradient(135deg, #6366F1, #8B5CF6);
  color: #fff; box-shadow: 0 10px 25px -5px rgba(99,102,241,.5);
}
.ovg-btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 15px 30px -5px rgba(99,102,241,.6); }
.ovg-btn-secondary {
  background: var(--ovg-card); color: var(--ovg-text);
  border: 1.5px solid var(--ovg-border);
}
.ovg-btn-secondary:hover:not(:disabled) { border-color: var(--ovg-primary); color: var(--ovg-primary); }
.ovg-btn-ghost { background: transparent; color: var(--ovg-text-muted); }
.ovg-btn-ghost:hover:not(:disabled) { background: rgba(99,102,241,.08); color: var(--ovg-primary); }
.ovg-btn-danger { background: var(--ovg-invalid); color: #fff; }
.ovg-btn-danger:hover:not(:disabled) { background: #dc2626; }
.ovg-btn-sm { padding: 6px 12px; font-size: 12px; border-radius: 8px; }

/* Inputs */
.ovg-input, .ovg-select {
  width: 100%; padding: 10px 14px; border-radius: 12px;
  border: 1.5px solid var(--ovg-border);
  background: var(--ovg-card); color: var(--ovg-text);
  font-family: inherit; font-size: 14px;
  transition: border-color .15s, box-shadow .15s;
}
.ovg-input:focus, .ovg-select:focus {
  outline: none; border-color: var(--ovg-primary);
  box-shadow: 0 0 0 4px rgba(99,102,241,.15);
}
.ovg-input::placeholder { color: var(--ovg-text-dim); }

/* Cards */
.ovg-card {
  background: var(--ovg-card); border-radius: var(--ovg-radius);
  border: 1px solid var(--ovg-border);
  box-shadow: var(--ovg-shadow-sm);
  transition: transform .2s ease, box-shadow .2s ease;
}
.ovg-card-hover:hover { transform: translateY(-3px); box-shadow: var(--ovg-shadow-lg); }
.ovg-card-pad { padding: 20px; }

/* Badges */
.ovg-badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 3px 10px; border-radius: 999px;
  font-size: 11px; font-weight: 700; text-transform: capitalize;
}
.ovg-badge-valid { background: rgba(16,185,129,.12); color: #047857; }
.ovg-badge-suspicious { background: rgba(245,158,11,.14); color: #B45309; }
.ovg-badge-invalid { background: rgba(244,63,94,.14); color: #BE123C; }
.ovg-badge-critical { background: rgba(220,38,38,.15); color: #991B1B; animation: ovgPulse 1.6s infinite; }
.ovg-badge-info { background: rgba(99,102,241,.14); color: #4338CA; }
html.dark .ovg-badge-valid { color: #34D399; }
html.dark .ovg-badge-suspicious { color: #FBBF24; }
html.dark .ovg-badge-invalid { color: #FB7185; }
html.dark .ovg-badge-info { color: #A5B4FC; }

/* Live Pulse */
.ovg-pulse {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  background: var(--ovg-valid); position: relative;
}
.ovg-pulse::after {
  content: ''; position: absolute; inset: -4px; border-radius: 50%;
  background: var(--ovg-valid); opacity: .4;
  animation: ovgPulse 1.6s infinite;
}
@keyframes ovgPulse {
  0% { transform: scale(1); opacity: .4; }
  70% { transform: scale(2); opacity: 0; }
  100% { transform: scale(1); opacity: 0; }
}

/* Skeleton */
.ovg-skeleton {
  background: linear-gradient(90deg,
    rgba(148,163,184,.1) 25%,
    rgba(148,163,184,.25) 50%,
    rgba(148,163,184,.1) 75%);
  background-size: 200% 100%;
  animation: ovgSkeleton 1.4s linear infinite;
  border-radius: 8px;
  min-height: 16px;
}
@keyframes ovgSkeleton {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}

/* Fade-in-up with stagger via inline --i */
.ovg-fade-up {
  animation: ovgFadeUp .5s ease-out both;
  animation-delay: calc(var(--i, 0) * 50ms);
}
@keyframes ovgFadeUp {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Toasts */
.ovg-toasts {
  position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
  display: flex; flex-direction: column; gap: 8px;
  z-index: 10000; pointer-events: none; align-items: center;
}
.ovg-toast {
  background: #0F172A; color: #F1F5F9;
  padding: 12px 22px; border-radius: 12px;
  box-shadow: var(--ovg-shadow-md); font-weight: 600; font-size: 13px;
  opacity: 0; transform: translateY(20px);
  animation: ovgToastIn .25s ease forwards;
  pointer-events: auto;
  display: flex; align-items: center; gap: 8px;
}
.ovg-toast.out { animation: ovgToastOut .25s ease forwards; }
.ovg-toast.success { background: #065F46; color: #ECFDF5; }
.ovg-toast.error { background: #7F1D1D; color: #FEE2E2; }
.ovg-toast.warning { background: #78350F; color: #FEF3C7; }
@keyframes ovgToastIn { to { opacity: 1; transform: translateY(0); } }
@keyframes ovgToastOut { to { opacity: 0; transform: translateY(20px); } }

/* Modal */
.ovg-modal-bg {
  position: fixed; inset: 0; z-index: 9999;
  background: rgba(15,23,42,.55);
  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  display: none; align-items: center; justify-content: center;
  padding: 16px; animation: ovgFadeIn .2s ease;
}
.ovg-modal-bg.open { display: flex; }
.ovg-modal {
  background: var(--ovg-card); border-radius: 24px;
  max-width: 100%; max-height: 92vh; overflow-y: auto;
  box-shadow: 0 25px 60px -15px rgba(0,0,0,.35);
  padding: 24px; animation: ovgModalIn .25s ease;
}
@keyframes ovgFadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes ovgModalIn {
  from { opacity: 0; transform: scale(.95) translateY(10px); }
  to { opacity: 1; transform: scale(1) translateY(0); }
}

/* Table */
.ovg-table {
  width: 100%; border-collapse: collapse; font-size: 13px;
}
.ovg-table th, .ovg-table td {
  text-align: right; padding: 12px 14px;
  border-bottom: 1px solid var(--ovg-border);
}
.ovg-table thead th {
  background: var(--ovg-bg); color: var(--ovg-text-dim);
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .3px; position: sticky; top: 0; z-index: 2;
}
.ovg-table tbody tr:hover { background: rgba(99,102,241,.04); }
.ovg-table tr.row-valid { background: rgba(16,185,129,.04); }
.ovg-table tr.row-suspicious { background: rgba(245,158,11,.05); }
.ovg-table tr.row-invalid { background: rgba(244,63,94,.05); }

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(148,163,184,.4); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: rgba(148,163,184,.6); }

/* Tooltip */
.ovg-tooltip { position: relative; }
.ovg-tooltip::after {
  content: attr(data-tip); position: absolute; bottom: calc(100% + 6px);
  left: 50%; transform: translateX(-50%);
  background: #0F172A; color: #fff; padding: 6px 10px; border-radius: 8px;
  font-size: 11px; white-space: nowrap; pointer-events: none;
  opacity: 0; transition: opacity .15s; z-index: 100;
}
.ovg-tooltip:hover::after { opacity: 1; }

/* Utility */
.ovg-flex { display: flex; }
.ovg-flex-col { flex-direction: column; }
.ovg-items-center { align-items: center; }
.ovg-justify-between { justify-content: space-between; }
.ovg-gap-2 { gap: 8px; }
.ovg-gap-4 { gap: 16px; }
.ovg-text-muted { color: var(--ovg-text-muted); }
.ovg-text-dim { color: var(--ovg-text-dim); }
.ovg-mono { font-family: var(--ovg-mono); font-variant-numeric: tabular-nums; }
.ovg-grad-text {
  background: linear-gradient(135deg, #6366F1, #8B5CF6, #3B82F6);
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent; color: transparent;
}
"""


DESIGN_SYSTEM_JS = r"""
(function() {
  "use strict";

  // ---------- Theme ----------
  window.ovgTheme = {
    get: function() { return localStorage.getItem('ovg-theme') || 'light'; },
    set: function(mode) {
      localStorage.setItem('ovg-theme', mode);
      document.documentElement.classList.toggle('dark', mode === 'dark');
      document.dispatchEvent(new CustomEvent('ovg:theme', { detail: mode }));
    },
    toggle: function() {
      this.set(this.get() === 'dark' ? 'light' : 'dark');
    },
    init: function() {
      var m = this.get();
      if (m === 'dark') document.documentElement.classList.add('dark');
    }
  };
  ovgTheme.init();

  // ---------- Toasts ----------
  window.ovgToast = function(msg, type) {
    type = type || 'info';
    var host = document.querySelector('.ovg-toasts');
    if (!host) {
      host = document.createElement('div');
      host.className = 'ovg-toasts';
      document.body.appendChild(host);
    }
    var el = document.createElement('div');
    el.className = 'ovg-toast ' + type;
    var icons = { success: '✓', error: '✗', warning: '⚠️', info: 'ℹ️' };
    el.innerHTML = '<span>' + (icons[type] || '') + '</span><span>' +
      String(msg).replace(/[&<>"']/g, function(c) {
        return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
      }) + '</span>';
    host.appendChild(el);
    setTimeout(function() {
      el.classList.add('out');
      setTimeout(function() { el.remove(); }, 260);
    }, 3000);
  };

  // ---------- Count-up ----------
  window.ovgCountUp = function(el, target, duration) {
    duration = duration || 800;
    target = Number(target) || 0;
    var start = 0, startT = null;
    function step(ts) {
      if (!startT) startT = ts;
      var p = Math.min(1, (ts - startT) / duration);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.floor(start + (target - start) * eased).toLocaleString('en-US');
      if (p < 1) requestAnimationFrame(step);
      else el.textContent = target.toLocaleString('en-US');
    }
    requestAnimationFrame(step);
  };

  // ---------- Modal helper ----------
  window.ovgOpenModal = function(id) {
    var el = document.getElementById(id);
    if (el) el.classList.add('open');
  };
  window.ovgCloseModal = function(id) {
    var el = document.getElementById(id);
    if (el) el.classList.remove('open');
  };
  document.addEventListener('click', function(e) {
    if (e.target.classList && e.target.classList.contains('ovg-modal-bg')) {
      e.target.classList.remove('open');
    }
  });

  // ---------- Copy button ----------
  window.ovgCopy = function(text, btnEl) {
    navigator.clipboard.writeText(text).then(function() {
      ovgToast('تم النسخ ✓', 'success');
      if (btnEl && btnEl.tagName === 'BUTTON') {
        var orig = btnEl.textContent;
        btnEl.textContent = '✓ تم النسخ';
        btnEl.disabled = true;
        setTimeout(function() { btnEl.textContent = orig; btnEl.disabled = false; }, 1500);
      }
    }).catch(function() { ovgToast('فشل النسخ', 'error'); });
  };

  // ---------- Escape ----------
  window.ovgEsc = function(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
    });
  };

  // ---------- Tab switch helper ----------
  window.ovgTabs = function(hostSel, activeId) {
    var host = document.querySelector(hostSel);
    if (!host) return;
    var btns = host.querySelectorAll('[data-tab]');
    btns.forEach(function(b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === activeId);
    });
  };

  // ---------- Time ago ----------
  window.ovgTimeAgo = function(date) {
    var s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (s < 60) return 'قبل لحظات';
    if (s < 3600) return 'قبل ' + Math.floor(s / 60) + ' دقيقة';
    if (s < 86400) return 'قبل ' + Math.floor(s / 3600) + ' ساعة';
    return 'قبل ' + Math.floor(s / 86400) + ' يوم';
  };

})();
"""

# =========================================================
# LOGIN PAGE
# =========================================================
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OVG · تسجيل الدخول</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script>(function(){try{if(localStorage.getItem('ovg-theme')==='dark')document.documentElement.classList.add('dark');}catch(e){}})();</script>
<style>
:root {
  --ovg-primary: #6366F1; --ovg-primary-2: #8B5CF6;
  --ovg-bg: #F8FAFC; --ovg-card: #FFFFFF;
  --ovg-border: #E2E8F0; --ovg-text: #0F172A;
  --ovg-text-muted: #475569; --ovg-text-dim: #94A3B8;
  --ovg-font: 'Cairo', sans-serif;
}
html.dark {
  --ovg-bg: #0F172A; --ovg-card: #1E293B;
  --ovg-border: #334155; --ovg-text: #F1F5F9;
  --ovg-text-muted: #CBD5E1; --ovg-text-dim: #64748B;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--ovg-bg); color: var(--ovg-text);
  font-family: var(--ovg-font); min-height: 100vh;
  transition: background .2s, color .2s;
}
.ovg-ambient { position: fixed; inset: 0; pointer-events: none; overflow: hidden; z-index: 0; }
.ovg-ambient::before, .ovg-ambient::after {
  content: ''; position: absolute; border-radius: 50%;
  filter: blur(80px); opacity: .28;
  animation: ovgFloat 22s ease-in-out infinite;
}
.ovg-ambient::before {
  width: 520px; height: 520px;
  background: radial-gradient(circle, var(--ovg-primary), transparent 70%);
  top: -120px; right: -120px;
}
.ovg-ambient::after {
  width: 420px; height: 420px;
  background: radial-gradient(circle, var(--ovg-primary-2), transparent 70%);
  bottom: -120px; left: -120px; animation-delay: -10s;
}
@keyframes ovgFloat {
  0%,100% { transform: translate(0,0) scale(1); }
  50% { transform: translate(40px,30px) scale(1.1); }
}
.login-wrap {
  position: relative; z-index: 1; min-height: 100vh;
  display: flex; align-items: center; justify-content: center;
  padding: 16px;
}
.login-card {
  width: 100%; max-width: 440px;
  background: var(--ovg-card); border-radius: 24px;
  box-shadow: 0 25px 60px -15px rgba(0,0,0,.25);
  padding: 40px;
  animation: ovgFadeUp .55s cubic-bezier(.2,.9,.3,1) both;
}
@keyframes ovgFadeUp {
  from { opacity: 0; transform: translateY(14px); }
  to { opacity: 1; transform: translateY(0); }
}
.logo-badge {
  width: 76px; height: 76px; border-radius: 22px;
  background: linear-gradient(135deg, #6366F1, #8B5CF6);
  display: flex; align-items: center; justify-content: center;
  font-size: 38px; margin: 0 auto 20px;
  box-shadow: 0 15px 35px -8px rgba(99,102,241,.55);
  animation: ovgPulseLogo 3s ease-in-out infinite;
}
@keyframes ovgPulseLogo {
  0%,100% { transform: scale(1); }
  50% { transform: scale(1.04); }
}
.brand-title {
  font-size: 24px; font-weight: 800; text-align: center;
  margin-bottom: 4px;
  background: linear-gradient(135deg, #6366F1, #8B5CF6, #3B82F6);
  -webkit-background-clip: text; background-clip: text;
  -webkit-text-fill-color: transparent;
}
.brand-sub {
  text-align: center; color: var(--ovg-text-muted);
  font-size: 13px; margin-bottom: 28px;
}
.tabs {
  display: flex; gap: 6px; background: var(--ovg-bg);
  padding: 6px; border-radius: 14px; margin-bottom: 24px;
}
.tab {
  flex: 1; padding: 10px; border-radius: 10px;
  border: none; background: transparent;
  font-family: inherit; font-weight: 700; font-size: 13px;
  color: var(--ovg-text-muted); cursor: pointer;
  transition: all .18s;
}
.tab.active {
  background: var(--ovg-card); color: var(--ovg-primary);
  box-shadow: 0 2px 8px rgba(99,102,241,.18);
}
.field { margin-bottom: 16px; }
.field label {
  display: block; font-size: 12px; font-weight: 700;
  color: var(--ovg-text-muted); margin-bottom: 6px;
}
.input {
  width: 100%; padding: 12px 16px; border-radius: 12px;
  border: 1.5px solid var(--ovg-border);
  background: var(--ovg-card); color: var(--ovg-text);
  font-family: inherit; font-size: 14px;
  transition: border-color .15s, box-shadow .15s;
}
.input:focus {
  outline: none; border-color: var(--ovg-primary);
  box-shadow: 0 0 0 4px rgba(99,102,241,.15);
}
.btn {
  width: 100%; padding: 13px; border: none; border-radius: 12px;
  background: linear-gradient(135deg, #6366F1, #8B5CF6);
  color: #fff; font-family: inherit; font-weight: 700;
  font-size: 14px; cursor: pointer; transition: all .15s;
  box-shadow: 0 10px 25px -5px rgba(99,102,241,.5);
  margin-top: 8px;
}
.btn:hover:not(:disabled) { transform: translateY(-1px); }
.btn:disabled { opacity: .6; cursor: not-allowed; }
.err {
  display: none; background: rgba(244,63,94,.08);
  color: #BE123C; font-size: 13px; font-weight: 600;
  padding: 10px; border-radius: 10px;
  text-align: center; margin-top: 12px;
}
.err.show { display: block; animation: ovgFadeUp .2s; }
html.dark .err { color: #FB7185; }
.hint {
  display: none; color: var(--ovg-text-dim);
  font-size: 11px; margin-top: 4px;
}
.hint.show { display: block; }
.theme-toggle {
  position: fixed; top: 20px; left: 20px;
  width: 44px; height: 44px; border-radius: 12px;
  border: 1.5px solid var(--ovg-border);
  background: var(--ovg-card); cursor: pointer;
  font-size: 20px; display: flex; align-items: center; justify-content: center;
  transition: all .15s; z-index: 100;
}
.theme-toggle:hover { border-color: var(--ovg-primary); transform: scale(1.05); }
.footer-note {
  text-align: center; color: var(--ovg-text-dim);
  font-size: 11px; margin-top: 28px;
}
</style>
</head>
<body>
<div class="ovg-ambient"></div>
<button class="theme-toggle" id="themeBtn" onclick="toggleTheme()" title="تبديل الوضع">🌙</button>

<div class="login-wrap">
  <div class="login-card">
    <div class="logo-badge">🛡️</div>
    <div class="brand-title">OVG Tracker</div>
    <div class="brand-sub">منصة تتبع الترافيك ومنع البوتات · v5.0</div>

    <div class="tabs">
      <button class="tab active" id="tab-login" onclick="switchMode('login')">تسجيل دخول</button>
      <button class="tab" id="tab-signup" onclick="switchMode('signup')">إنشاء حساب</button>
    </div>

    <form id="authForm" autocomplete="on">
      <div class="field">
        <label>اسم المستخدم</label>
        <input class="input" name="username" placeholder="مثال: ahmed" autocomplete="username" required minlength="3" maxlength="32" pattern="[a-zA-Z0-9_.\-]{3,32}">
        <div class="hint" id="hintUser">3-32 حرف إنجليزي، أرقام، _ . -</div>
      </div>
      <div class="field">
        <label>كلمة المرور</label>
        <input class="input" name="password" type="password" placeholder="••••••••" autocomplete="current-password" required minlength="6">
      </div>
      <div class="field" id="confirmField" style="display:none;">
        <label>تأكيد كلمة المرور</label>
        <input class="input" name="confirm" type="password" placeholder="••••••••" autocomplete="new-password">
      </div>
      <button type="submit" class="btn" id="submitBtn">تسجيل الدخول</button>
      <div class="err" id="errBox"></div>
    </form>

    <div class="footer-note">© OVG Analytics · v5.0.0 Phase 1</div>
  </div>
</div>

<script>
  function toggleTheme() {
    var isDark = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('ovg-theme', isDark ? 'dark' : 'light'); } catch(e){}
    document.getElementById('themeBtn').textContent = isDark ? '☀️' : '🌙';
  }
  (function initTheme() {
    try {
      if (localStorage.getItem('ovg-theme') === 'dark') {
        document.documentElement.classList.add('dark');
        document.getElementById('themeBtn').textContent = '☀️';
      }
    } catch(e){}
  })();

  var MODE = 'login';
  function switchMode(m) {
    MODE = m;
    document.getElementById('tab-login').classList.toggle('active', m === 'login');
    document.getElementById('tab-signup').classList.toggle('active', m === 'signup');
    document.getElementById('confirmField').style.display = m === 'signup' ? 'block' : 'none';
    document.getElementById('hintUser').classList.toggle('show', m === 'signup');
    document.getElementById('submitBtn').textContent = m === 'signup' ? 'إنشاء حساب' : 'تسجيل الدخول';
    document.getElementById('errBox').classList.remove('show');
  }

  document.getElementById('authForm').addEventListener('submit', async function(ev) {
    ev.preventDefault();
    var btn = document.getElementById('submitBtn');
    var err = document.getElementById('errBox');
    var fd = new FormData(ev.target);
    var username = (fd.get('username') || '').trim();
    var password = fd.get('password') || '';
    if (MODE === 'signup' && password !== fd.get('confirm')) {
      err.textContent = 'كلمتا المرور غير متطابقتين';
      err.classList.add('show');
      return;
    }
    btn.disabled = true;
    var orig = btn.textContent;
    btn.textContent = 'جاري...';
    err.classList.remove('show');
    var url = MODE === 'signup' ? '/api/auth/signup' : '/api/auth/login';
    try {
      var r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
      });
      var d = await r.json().catch(function() { return {}; });
      if (r.ok) { window.location.href = '/dashboard'; return; }
      err.textContent = d.detail || 'فشل العملية';
      err.classList.add('show');
    } catch (e) {
      err.textContent = 'خطأ في الاتصال بالسيرفر';
      err.classList.add('show');
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });
</script>
</body>
</html>"""

# =========================================================
# DASHBOARD HTML — PART 1/7: HEAD + STYLES + SHELL
# =========================================================
DASHBOARD_HTML_PART1 = (
r"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OVG · لوحة التحكم</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script>(function(){try{if(localStorage.getItem('ovg-theme')==='dark')document.documentElement.classList.add('dark');}catch(e){}})();</script>
<style>""" + DESIGN_SYSTEM_CSS + r"""

/* ===== Dashboard shell ===== */
body { padding: 0; }
.app-shell { display: flex; min-height: 100vh; position: relative; }

/* ===== Sidebar ===== */
.sidebar {
  width: 280px; background: var(--ovg-card);
  border-left: 1px solid var(--ovg-border);
  display: flex; flex-direction: column;
  position: fixed; right: 0; top: 0; bottom: 0;
  z-index: 40; transition: transform .28s cubic-bezier(.2,.9,.3,1);
}
.sidebar-header {
  padding: 20px; border-bottom: 1px solid var(--ovg-border);
  display: flex; align-items: center; gap: 12px;
}
.sidebar-logo {
  width: 42px; height: 42px; border-radius: 12px;
  background: linear-gradient(135deg, #6366F1, #8B5CF6);
  display: flex; align-items: center; justify-content: center;
  color: #fff; font-weight: 800; font-size: 20px;
  box-shadow: 0 8px 20px -5px rgba(99,102,241,.55);
}
.sidebar-title { font-weight: 800; font-size: 15px; line-height: 1.2; color: var(--ovg-text); }
.sidebar-version { font-size: 9px; color: var(--ovg-text-dim); font-weight: 700; letter-spacing: 1px; margin-top: 2px; }
.sidebar-body {
  flex: 1; overflow-y: auto; padding: 12px;
  display: flex; flex-direction: column; gap: 18px;
}
.nav-section-label {
  font-size: 10px; font-weight: 800; color: var(--ovg-text-dim);
  text-transform: uppercase; letter-spacing: 1.2px;
  padding: 6px 12px; margin-bottom: 4px;
}
.nav-btn {
  width: 100%; display: flex; align-items: center; gap: 12px;
  padding: 10px 14px; border-radius: 12px; border: none;
  background: transparent; color: var(--ovg-text-muted);
  font-family: inherit; font-size: 13px; font-weight: 600;
  text-align: right; cursor: pointer; transition: all .15s;
  margin-bottom: 2px;
}
.nav-btn:hover { background: rgba(99,102,241,.06); color: var(--ovg-primary); }
.nav-btn.active { background: rgba(99,102,241,.1); color: var(--ovg-primary); font-weight: 700; }
.nav-btn .nav-icon { font-size: 18px; width: 22px; text-align: center; }
.sidebar-footer { padding: 12px; border-top: 1px solid var(--ovg-border); }
.user-card {
  display: flex; align-items: center; gap: 10px;
  padding: 10px; border-radius: 12px; background: var(--ovg-bg);
}
.user-avatar {
  width: 38px; height: 38px; border-radius: 50%;
  background: linear-gradient(135deg, #6366F1, #8B5CF6);
  display: flex; align-items: center; justify-content: center;
  color: #fff; font-weight: 800; font-size: 15px; flex-shrink: 0;
}
.user-info { flex: 1; min-width: 0; }
.user-name {
  font-weight: 700; font-size: 13px; color: var(--ovg-text);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.user-status { font-size: 10px; color: var(--ovg-text-dim); }
.logout-btn {
  width: 100%; margin-top: 8px; padding: 8px;
  border-radius: 10px; border: none; background: transparent;
  color: #BE123C; font-family: inherit; font-size: 12px;
  font-weight: 700; cursor: pointer; text-align: right;
  transition: background .15s;
}
html.dark .logout-btn { color: #FB7185; }
.logout-btn:hover { background: rgba(244,63,94,.08); }

/* ===== Main area ===== */
.main-area {
  flex: 1; margin-right: 280px;
  display: flex; flex-direction: column; min-height: 100vh;
}
.topbar {
  height: 64px; background: var(--ovg-card);
  border-bottom: 1px solid var(--ovg-border);
  display: flex; align-items: center;
  padding: 0 24px; gap: 16px;
  position: sticky; top: 0; z-index: 30;
  backdrop-filter: blur(10px);
}
.breadcrumbs {
  display: flex; align-items: center; gap: 6px;
  font-size: 13px; color: var(--ovg-text-muted);
  flex: 1; min-width: 0;
}
.breadcrumbs a { color: var(--ovg-text-muted); text-decoration: none; }
.breadcrumbs a:hover { color: var(--ovg-primary); }
.breadcrumbs .sep { color: var(--ovg-text-dim); }
.breadcrumbs .current { color: var(--ovg-text); font-weight: 700; }
.topbar-search { flex: 0 0 320px; position: relative; }
.topbar-search input {
  width: 100%; padding: 9px 14px 9px 36px;
  border-radius: 10px; border: 1px solid var(--ovg-border);
  background: var(--ovg-bg); color: var(--ovg-text);
  font-family: inherit; font-size: 13px; cursor: pointer;
}
.topbar-search input:focus { outline: none; border-color: var(--ovg-primary); }
.topbar-search .kbd {
  position: absolute; left: 8px; top: 50%; transform: translateY(-50%);
  font-size: 10px; padding: 2px 6px; border-radius: 5px;
  background: var(--ovg-card); border: 1px solid var(--ovg-border);
  color: var(--ovg-text-dim); font-family: var(--ovg-mono); pointer-events: none;
}
.topbar-search .search-icon {
  position: absolute; right: 12px; top: 50%;
  transform: translateY(-50%); color: var(--ovg-text-dim); pointer-events: none;
}
.topbar-btn {
  width: 38px; height: 38px; border-radius: 10px;
  border: 1px solid var(--ovg-border); background: var(--ovg-card);
  cursor: pointer; display: flex; align-items: center; justify-content: center;
  font-size: 16px; transition: all .15s; flex-shrink: 0;
}
.topbar-btn:hover { border-color: var(--ovg-primary); background: rgba(99,102,241,.05); }
.user-avatar-btn {
  width: 38px; height: 38px; border-radius: 50%; border: 2px solid transparent;
  background: linear-gradient(135deg, #6366F1, #8B5CF6);
  color: #fff; font-weight: 800; font-size: 14px; cursor: pointer;
  transition: all .15s; display: flex; align-items: center; justify-content: center;
}
.user-avatar-btn:hover { box-shadow: 0 0 0 3px rgba(99,102,241,.25); }
.user-dropdown {
  position: absolute; top: calc(100% + 8px); left: 0;
  background: var(--ovg-card); border: 1px solid var(--ovg-border);
  border-radius: 14px; box-shadow: 0 12px 40px -8px rgba(0,0,0,.2);
  padding: 8px; min-width: 200px; display: none; z-index: 100;
  animation: ovgFadeUp .2s ease-out;
}
.user-dropdown.open { display: block; }
.user-dropdown button {
  width: 100%; text-align: right; padding: 10px 12px;
  border: none; background: transparent; color: var(--ovg-text);
  font-family: inherit; font-size: 13px; border-radius: 8px;
  cursor: pointer; display: flex; align-items: center; gap: 10px;
}
.user-dropdown button:hover { background: var(--ovg-bg); }
.user-dropdown hr { border: none; border-top: 1px solid var(--ovg-border); margin: 6px 0; }

/* ===== Views ===== */
.views-container { padding: 24px; flex: 1; }
@media (min-width: 1024px) { .views-container { padding: 32px; } }
.view { display: none; }
.view.active { display: block; animation: ovgFadeUp .4s cubic-bezier(.2,.9,.3,1); }

/* ===== Mobile nav ===== */
.mobile-nav { display: none; position: fixed; bottom: 0; left: 0; right: 0; height: 62px; background: var(--ovg-card); border-top: 1px solid var(--ovg-border); z-index: 45; padding: 0 8px; }
.mobile-nav-inner { display: flex; height: 100%; justify-content: space-around; align-items: center; }
.mobile-nav button {
  flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px;
  border: none; background: transparent; color: var(--ovg-text-muted);
  font-family: inherit; font-size: 10px; font-weight: 600;
  cursor: pointer; padding: 6px; border-radius: 8px;
}
.mobile-nav button .m-icon { font-size: 18px; }
.mobile-nav button.active { color: var(--ovg-primary); }
.mobile-menu-btn { display: none; }
@media (max-width: 900px) {
  .sidebar { transform: translateX(100%); }
  .sidebar.open { transform: translateX(0); }
  .main-area { margin-right: 0; padding-bottom: 62px; }
  .mobile-nav { display: block; }
  .topbar-search { display: none; }
  .breadcrumbs { display: none; }
  .topbar { padding: 0 16px; }
  .mobile-menu-btn { display: flex; }
  .views-container { padding: 16px; }
}

/* ===== Page utilities ===== */
.page-header {
  display: flex; justify-content: space-between;
  align-items: flex-start; gap: 16px;
  margin-bottom: 24px; flex-wrap: wrap;
}
.page-title { font-size: 26px; font-weight: 800; }
.page-subtitle { color: var(--ovg-text-muted); font-size: 13px; margin-top: 2px; }
.filter-bar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
.filter-chip {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 12px; background: rgba(99,102,241,.1);
  color: var(--ovg-primary); border-radius: 999px;
  font-size: 12px; font-weight: 700;
}
.filter-chip button {
  border: none; background: transparent; color: inherit;
  cursor: pointer; padding: 0; font-size: 14px; line-height: 1;
}
.kpi-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px; margin-bottom: 24px;
}
.kpi-card {
  padding: 20px; background: var(--ovg-card);
  border: 1px solid var(--ovg-border); border-radius: 16px;
  position: relative; overflow: hidden;
  transition: transform .2s, box-shadow .2s;
}
.kpi-card:hover { transform: translateY(-3px); box-shadow: var(--ovg-shadow-lg); }
.kpi-label {
  font-size: 11px; font-weight: 700; color: var(--ovg-text-dim);
  text-transform: uppercase; letter-spacing: .5px; margin-bottom: 6px;
}
.kpi-value {
  font-size: 30px; font-weight: 800;
  font-variant-numeric: tabular-nums; font-family: var(--ovg-mono);
  color: var(--ovg-text);
}
.kpi-delta { font-size: 11px; font-weight: 700; margin-top: 4px; display: inline-flex; align-items: center; gap: 3px; }
.kpi-delta.up { color: #059669; }
.kpi-delta.down { color: #DC2626; }
.kpi-delta.neutral { color: var(--ovg-text-dim); }
.kpi-sparkline { margin-top: 12px; height: 40px; }

/* ===== Command palette ===== */
.cmd-bg {
  position: fixed; inset: 0;
  background: rgba(15,23,42,.6); backdrop-filter: blur(8px);
  z-index: 10000; display: none;
  align-items: flex-start; justify-content: center;
  padding-top: 15vh;
}
.cmd-bg.open { display: flex; animation: ovgFadeIn .15s ease; }
.cmd-box {
  width: 100%; max-width: 580px;
  background: var(--ovg-card); border-radius: 18px;
  box-shadow: 0 25px 60px -15px rgba(0,0,0,.5);
  overflow: hidden; animation: ovgModalIn .2s ease;
}
.cmd-input-wrap {
  display: flex; align-items: center;
  padding: 16px 20px; border-bottom: 1px solid var(--ovg-border); gap: 12px;
}
.cmd-input-wrap input {
  flex: 1; border: none; background: transparent;
  font-family: inherit; font-size: 16px; color: var(--ovg-text); outline: none;
}
.cmd-results { max-height: 60vh; overflow-y: auto; padding: 8px; }
.cmd-item {
  padding: 12px 16px; border-radius: 10px; cursor: pointer;
  display: flex; align-items: center; gap: 12px; font-size: 14px;
  color: var(--ovg-text);
}
.cmd-item:hover, .cmd-item.active { background: var(--ovg-bg); }
.cmd-item .cmd-icon { font-size: 18px; width: 24px; text-align: center; }
.cmd-item .cmd-label { flex: 1; }
.cmd-item .cmd-hint { font-size: 11px; color: var(--ovg-text-dim); }
.cmd-empty { padding: 40px 20px; text-align: center; color: var(--ovg-text-dim); font-size: 13px; }

/* ===== Data table shared ===== */
.dt-wrap {
  background: var(--ovg-card); border-radius: 16px;
  border: 1px solid var(--ovg-border); overflow: hidden;
}
.dt-scroll { overflow-x: auto; overflow-y: auto; max-height: 70vh; }
.dt-scroll .ovg-table th, .dt-scroll .ovg-table td { white-space: nowrap; }
.dt-toolbar {
  padding: 14px 18px; border-bottom: 1px solid var(--ovg-border);
  display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
}
.dt-toolbar input, .dt-toolbar select {
  padding: 8px 12px; border-radius: 10px; border: 1px solid var(--ovg-border);
  background: var(--ovg-card); color: var(--ovg-text);
  font-family: inherit; font-size: 12px;
}
.dt-toolbar input:focus, .dt-toolbar select:focus {
  outline: none; border-color: var(--ovg-primary);
}
.dt-empty { padding: 60px 20px; text-align: center; color: var(--ovg-text-dim); font-size: 14px; }
.dt-empty .icon { font-size: 48px; margin-bottom: 12px; }

/* ===== Pagination ===== */
.pager { display: flex; justify-content: center; align-items: center; gap: 8px; padding: 16px; }
.pager button {
  padding: 8px 14px; border-radius: 10px;
  border: 1px solid var(--ovg-border); background: var(--ovg-card);
  color: var(--ovg-text); font-family: inherit; font-size: 12px;
  font-weight: 700; cursor: pointer; transition: all .15s;
}
.pager button:hover:not(:disabled) { border-color: var(--ovg-primary); color: var(--ovg-primary); }
.pager button:disabled { opacity: .4; cursor: not-allowed; }
.pager .pg-info { font-size: 12px; color: var(--ovg-text-muted); font-weight: 600; }

/* ===== Reports tabs ===== */
.reports-tabs {
  display: flex; gap: 4px; overflow-x: auto;
  border-bottom: 1px solid var(--ovg-border);
  margin-bottom: 20px; padding-bottom: 2px;
}
.reports-tab {
  padding: 10px 16px; border: none; background: transparent;
  color: var(--ovg-text-muted); font-family: inherit;
  font-size: 13px; font-weight: 700; cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: all .15s; white-space: nowrap;
}
.reports-tab:hover { color: var(--ovg-text); }
.reports-tab.active { color: var(--ovg-primary); border-bottom-color: var(--ovg-primary); }

/* ===== Country / Zone bars ===== */
.bar-row { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid var(--ovg-border); }
.bar-row:last-child { border-bottom: none; }
.bar-label { font-size: 12px; font-weight: 600; min-width: 110px; color: var(--ovg-text); }
.bar-track { flex: 1; height: 8px; background: var(--ovg-bg); border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; transition: width .4s ease; }
.bar-val { font-size: 11px; font-weight: 700; font-family: var(--ovg-mono); color: var(--ovg-text-muted); min-width: 52px; text-align: left; }

/* ===== Heatmap ===== */
.heat-wrap { overflow-x: auto; }
.heat-grid {
  display: grid;
  grid-template-columns: 80px repeat(24, 1fr);
  gap: 3px; min-width: 720px;
}
.heat-cell {
  aspect-ratio: 1; border-radius: 3px;
  transition: transform .15s;
  min-width: 20px;
}
.heat-cell:hover { transform: scale(1.15); }
.heat-head { font-size: 10px; color: var(--ovg-text-dim); text-align: center; font-weight: 700; }
.heat-day { font-size: 11px; color: var(--ovg-text-muted); font-weight: 600; padding: 4px 0; }
</style>
</head>
<body>
<div class="ovg-ambient"></div>

<div class="app-shell">

<!-- ============ SIDEBAR ============ -->
<aside class="sidebar" id="sidebar">
  <div class="sidebar-header">
    <div class="sidebar-logo">O</div>
    <div>
      <div class="sidebar-title">OVG Tracker</div>
      <div class="sidebar-version">V5.0.0 · PHASE 1</div>
    </div>
  </div>

  <div class="sidebar-body">
    <div>
      <div class="nav-section-label">مساحة العمل</div>
      <button class="nav-btn active" data-nav="sites" onclick="navTo('sites')">
        <span class="nav-icon">📊</span><span>المواقع</span>
      </button>
      <button class="nav-btn" data-nav="overview" onclick="navTo('overview')" id="navOverview" style="display:none;">
        <span class="nav-icon">🏠</span><span>النظرة العامة</span>
      </button>
    </div>

    <div id="analysisSection" style="display:none;">
      <div class="nav-section-label">التحليل</div>
      <button class="nav-btn" data-nav="visits" onclick="navTo('visits')">
        <span class="nav-icon">📋</span><span>كل الزيارات</span>
      </button>
      <button class="nav-btn" data-nav="reports" onclick="navTo('reports')">
        <span class="nav-icon">📈</span><span>التقارير</span>
      </button>
    </div>

    <div id="toolsSection" style="display:none;">
      <div class="nav-section-label">الأدوات</div>
      <button class="nav-btn" data-nav="tracker" onclick="navTo('tracker')">
        <span class="nav-icon">🔧</span><span>كود التتبع</span>
      </button>
      <button class="nav-btn" data-nav="settings" onclick="navTo('settings')">
        <span class="nav-icon">⚙️</span><span>الإعدادات</span>
      </button>
    </div>
  </div>

  <div class="sidebar-footer">
    <div class="user-card">
      <div class="user-avatar" id="userAvatar">?</div>
      <div class="user-info">
        <div class="user-name" id="userName">...</div>
        <div class="user-status">مسجل دخول</div>
      </div>
    </div>
    <button class="logout-btn" onclick="doLogout()">← تسجيل الخروج</button>
  </div>
</aside>

<!-- ============ MAIN ============ -->
<main class="main-area">

<header class="topbar">
  <button class="topbar-btn mobile-menu-btn" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
  <nav class="breadcrumbs" id="breadcrumbs">
    <a href="/dashboard" onclick="event.preventDefault(); navTo('sites');">OVG</a>
    <span class="sep">/</span>
    <span class="current" id="crumbCurrent">المواقع</span>
  </nav>
  <div class="topbar-search" onclick="openCmdPalette()">
    <span class="search-icon">🔍</span>
    <input readonly placeholder="بحث سريع..." id="topSearchTrigger">
    <span class="kbd">⌘K</span>
  </div>
  <button class="topbar-btn" id="themeBtn" onclick="toggleTheme()" title="الوضع الليلي">🌙</button>
  <div style="position:relative;">
    <button class="user-avatar-btn" onclick="toggleUserMenu(event)" id="userAvatarBtn">?</button>
    <div class="user-dropdown" id="userDropdown">
      <button onclick="event.stopPropagation(); ovgToast('قريباً في Phase 2', 'info'); closeUserMenu();">⚙️ الإعدادات</button>
      <button onclick="event.stopPropagation(); ovgToast('قريباً في Phase 2', 'info'); closeUserMenu();">📖 المساعدة</button>
      <hr>
      <button onclick="event.stopPropagation(); doLogout();" style="color:#BE123C;">← تسجيل الخروج</button>
    </div>
  </div>
</header>

<div class="views-container" id="viewsContainer">
"""
)

# =========================================================
# DASHBOARD HTML — PART 2/7: SITES + OVERVIEW VIEWS
# =========================================================
DASHBOARD_HTML_PART2 = (
r"""
<!-- ============ VIEW: SITES ============ -->
<div class="view active" id="view-sites">
  <div class="page-header">
    <div>
      <h1 class="page-title ovg-grad-text">مواقعي</h1>
      <p class="page-subtitle">أدر كل مواقعك من مكان واحد · <span id="siteLimit">0/20</span></p>
    </div>
    <button class="ovg-btn ovg-btn-primary" onclick="openSiteModal()">
      <span style="font-size:18px;line-height:1;">+</span> موقع جديد
    </button>
  </div>
  <div id="sitesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"></div>
</div>

<!-- ============ VIEW: OVERVIEW ============ -->
<div class="view" id="view-overview">

  <!-- Site context -->
  <div class="page-header">
    <div>
      <h1 class="page-title" id="overviewSiteName">—</h1>
      <p class="page-subtitle" id="overviewSiteDomain">—</p>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="switchSiteModal()">
        🔀 تبديل الموقع
      </button>
      <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="runMock()">
        🧪 بيانات تجريبية
      </button>
    </div>
  </div>

  <!-- At a Glance Bar -->
  <div class="ovg-card ovg-card-pad ovg-fade-up" style="margin-bottom:20px;">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;">
      <div style="display:flex;align-items:center;gap:10px;">
        <div>
          <div class="kpi-label">إجمالي اليوم</div>
          <div style="font-size:22px;font-weight:800;font-variant-numeric:tabular-nums;font-family:var(--ovg-mono);color:var(--ovg-text);" id="glanceTotal">0</div>
        </div>
        <div style="margin-left:auto;text-align:left;">
          <span class="kpi-delta neutral" id="glanceTotalDelta">—</span>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        <div>
          <div class="kpi-label">بوتات اليوم</div>
          <div style="font-size:22px;font-weight:800;font-variant-numeric:tabular-nums;font-family:var(--ovg-mono);color:#F43F5E;" id="glanceBots">0</div>
        </div>
        <div style="margin-left:auto;text-align:left;">
          <span class="kpi-delta neutral" id="glanceBotsDelta">—</span>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        <div>
          <div class="kpi-label">الجودة</div>
          <div style="font-size:22px;font-weight:800;font-variant-numeric:tabular-nums;font-family:var(--ovg-mono);color:#10B981;" id="glanceQuality">0%</div>
        </div>
        <div style="margin-left:auto;text-align:left;">
          <span class="kpi-delta neutral" id="glanceQualityDelta">—</span>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        <div class="ovg-pulse" id="livePulse" style="display:none;"></div>
        <div>
          <div class="kpi-label">مباشر</div>
          <div style="font-size:14px;font-weight:700;color:var(--ovg-text);" id="glanceLive">0 نشط الآن</div>
        </div>
      </div>
    </div>
  </div>

  <!-- KPI Cards with Sparklines -->
  <div class="kpi-grid" id="kpiGrid">
    <div class="kpi-card ovg-fade-up" style="--i:0;">
      <div class="kpi-label">إجمالي الزيارات</div>
      <div class="kpi-value" id="kpi-total" data-count="0">0</div>
      <div class="kpi-delta neutral" id="kpi-total-delta"></div>
      <div class="kpi-sparkline"><canvas id="sparkTotal"></canvas></div>
    </div>
    <div class="kpi-card ovg-fade-up" style="--i:1;">
      <div class="kpi-label" style="color:#059669;">زيارات صالحة</div>
      <div class="kpi-value" id="kpi-valid" style="color:#059669;" data-count="0">0</div>
      <div class="kpi-delta neutral"></div>
      <div class="kpi-sparkline"><canvas id="sparkValid"></canvas></div>
    </div>
    <div class="kpi-card ovg-fade-up" style="--i:2;">
      <div class="kpi-label" style="color:#E11D48;">بوتات</div>
      <div class="kpi-value" id="kpi-invalid" style="color:#E11D48;" data-count="0">0</div>
      <div class="kpi-delta neutral"></div>
      <div class="kpi-sparkline"><canvas id="sparkBots"></canvas></div>
    </div>
    <div class="kpi-card ovg-fade-up" style="--i:3;">
      <div class="kpi-label" style="color:#D97706;">مشبوهة</div>
      <div class="kpi-value" id="kpi-suspicious" style="color:#D97706;" data-count="0">0</div>
      <div class="kpi-delta neutral"></div>
      <div class="kpi-sparkline"><canvas id="sparkQuality"></canvas></div>
    </div>
  </div>

  <!-- Trend + Live Feed -->
  <div style="display:grid;grid-template-columns:1fr;gap:20px;margin-bottom:20px;">
    <div class="ovg-card ovg-card-pad ovg-fade-up" style="--i:4;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
        <h3>اتجاه الزيارات</h3>
        <div style="display:flex;gap:4px;background:var(--ovg-bg);padding:4px;border-radius:10px;" id="trendTabs">
          <button onclick="loadTrend('24h')" data-range="24h" class="ovg-btn ovg-btn-ghost ovg-btn-sm">24 ساعة</button>
          <button onclick="loadTrend('7d')" data-range="7d" class="ovg-btn ovg-btn-ghost ovg-btn-sm" style="background:var(--ovg-card);color:var(--ovg-primary);font-weight:700;">7 أيام</button>
          <button onclick="loadTrend('30d')" data-range="30d" class="ovg-btn ovg-btn-ghost ovg-btn-sm">30 يوم</button>
        </div>
      </div>
      <div style="height:280px;"><canvas id="trendChart"></canvas></div>
    </div>
  </div>

  <!-- Live Feed + Insights -->
  <div style="display:grid;grid-template-columns:1fr;gap:20px;" id="feedAndInsights">
    <div class="ovg-card ovg-fade-up" style="--i:5;overflow:hidden;">
      <div style="padding:16px 20px;border-bottom:1px solid var(--ovg-border);display:flex;justify-content:space-between;align-items:center;">
        <h3>أحدث الزيارات</h3>
        <div style="display:flex;align-items:center;gap:8px;font-size:11px;color:#10B981;font-weight:700;">
          <div class="ovg-pulse"></div> مباشر
        </div>
      </div>
      <div id="liveFeed" style="max-height:380px;overflow-y:auto;"></div>
      <div style="padding:12px 20px;border-top:1px solid var(--ovg-border);text-align:center;">
        <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="navTo('visits')">عرض كل الزيارات ←</button>
      </div>
    </div>

    <div class="ovg-card ovg-card-pad ovg-fade-up" style="--i:6;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
        <span style="font-size:20px;">💡</span>
        <h3>توصيات ذكية</h3>
      </div>
      <div id="insightsBox" style="display:flex;flex-direction:column;gap:10px;">
        <div class="ovg-skeleton" style="height:50px;"></div>
        <div class="ovg-skeleton" style="height:50px;"></div>
      </div>
    </div>
  </div>
</div>
"""
)

# =========================================================
# DASHBOARD HTML — PART 3/7: VISITS VIEW
# =========================================================
DASHBOARD_HTML_PART3 = (
r"""
<!-- ============ VIEW: VISITS ============ -->
<div class="view" id="view-visits">
  <div class="page-header">
    <div>
      <h1 class="page-title">كل الزيارات</h1>
      <p class="page-subtitle" id="visitsSubtitle">تصفح وفلتر كل الزيارات</p>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="reloadVisits()">🔄 تحديث</button>
      <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="exportVisits('csv')">⬇️ CSV</button>
      <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="exportVisits('json')">⬇️ JSON</button>
    </div>
  </div>

  <!-- Quick Filters -->
  <div class="filter-bar">
    <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="quickFilter('all')">الكل</button>
    <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="quickFilter('valid')" style="color:#059669;">🟢 صالح فقط</button>
    <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="quickFilter('invalid')" style="color:#E11D48;">🔴 بوتات فقط</button>
    <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="quickFilter('suspicious')" style="color:#D97706;">⚠️ مشبوهة</button>
    <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="quickFilter('highrisk')" style="color:#DC2626;font-weight:700;">🔥 عالي المخاطر</button>
    <span style="flex:1;"></span>
    <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="openFilterModal()">+ فلتر متقدم</button>
    <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="saveAsSegment()">💾 حفظ Segment</button>
  </div>

  <!-- Active filter chips -->
  <div id="activeFilters" style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;"></div>

  <!-- Data table -->
  <div class="dt-wrap">
    <div class="dt-toolbar">
      <input type="text" placeholder="بحث IP / ASN / Zone..." id="visitSearch" onkeydown="if(event.key==='Enter')applySearchFilter()" style="min-width:240px;">
      <select id="visitSortBy" onchange="reloadVisits()">
        <option value="timestamp">الأحدث</option>
        <option value="score">الدرجة</option>
        <option value="country">الدولة</option>
        <option value="zone">الزون</option>
        <option value="ip">IP</option>
      </select>
      <select id="visitSortDir" onchange="reloadVisits()">
        <option value="desc">تنازلي</option>
        <option value="asc">تصاعدي</option>
      </select>
      <select id="visitGroupBy" onchange="reloadVisits()">
        <option value="">بدون تجميع</option>
        <option value="country">حسب الدولة</option>
        <option value="zone">حسب الزون</option>
        <option value="verdict">حسب الحكم</option>
        <option value="device">حسب الجهاز</option>
        <option value="browser">حسب المتصفح</option>
        <option value="asn">حسب ASN</option>
      </select>
      <span style="flex:1;"></span>
      <span class="ovg-text-dim" style="font-size:12px;" id="visitsCount">—</span>
    </div>

    <!-- Bulk actions bar -->
    <div id="bulkBar" style="display:none;padding:10px 18px;background:rgba(99,102,241,.06);border-bottom:1px solid var(--ovg-border);display:none;align-items:center;gap:8px;">
      <span style="font-size:12px;font-weight:700;color:var(--ovg-primary);"><span id="bulkCount">0</span> محددة</span>
      <button class="ovg-btn ovg-btn-sm ovg-btn-secondary" onclick="bulkAction('mark_valid')">✓ تعليم كصالح</button>
      <button class="ovg-btn ovg-btn-sm ovg-btn-secondary" onclick="bulkAction('mark_invalid')">✗ تعليم كبوت</button>
      <button class="ovg-btn ovg-btn-sm ovg-btn-secondary" onclick="bulkAction('add_tag')">🏷️ إضافة Tag</button>
      <button class="ovg-btn ovg-btn-sm ovg-btn-danger" onclick="bulkAction('delete')">🗑️ حذف</button>
      <button class="ovg-btn ovg-btn-sm ovg-btn-ghost" onclick="clearSelection()">إلغاء</button>
    </div>

    <div class="dt-scroll" id="visitsScroll">
      <table class="ovg-table" id="visitsTable">
        <thead>
          <tr>
            <th style="width:32px;"><input type="checkbox" id="checkAll" onchange="toggleAllRows()"></th>
            <th>الوقت</th>
            <th>IP</th>
            <th>الزون</th>
            <th>الدولة</th>
            <th>الجهاز</th>
            <th>المتصفح</th>
            <th>ASN</th>
            <th>Score</th>
            <th>الحكم</th>
            <th style="width:60px;"></th>
          </tr>
        </thead>
        <tbody id="visitsTbody">
          <tr><td colspan="11" class="dt-empty">جاري التحميل...</td></tr>
        </tbody>
      </table>
    </div>

    <div class="pager" id="visitsPager"></div>
  </div>
</div>
"""
)

# =========================================================
# DASHBOARD HTML — PART 4/7: REPORTS VIEW
# =========================================================
DASHBOARD_HTML_PART4 = (
r"""
<!-- ============ VIEW: REPORTS ============ -->
<div class="view" id="view-reports">
  <div class="page-header">
    <div>
      <h1 class="page-title">التقارير</h1>
      <p class="page-subtitle">تحليل شامل لجودة الترافيك</p>
    </div>
  </div>

  <div class="reports-tabs" id="reportsTabs">
    <button class="reports-tab active" data-tab="zones" onclick="switchReport('zones')">🎯 الزونات</button>
    <button class="reports-tab" data-tab="countries" onclick="switchReport('countries')">🌍 الدول</button>
    <button class="reports-tab" data-tab="devices" onclick="switchReport('devices')">💻 الأجهزة</button>
    <button class="reports-tab" data-tab="browsers" onclick="switchReport('browsers')">🌐 المتصفحات</button>
    <button class="reports-tab" data-tab="os" onclick="switchReport('os')">🖥️ الأنظمة</button>
    <button class="reports-tab" data-tab="fingerprints" onclick="switchReport('fingerprints')">🧬 البصمات</button>
    <button class="reports-tab" data-tab="ips" onclick="switchReport('ips')">🔗 IPs</button>
    <button class="reports-tab" data-tab="asn" onclick="switchReport('asn')">📡 ASN</button>
    <button class="reports-tab" data-tab="timezones" onclick="switchReport('timezones')">⏰ التوقيت</button>
    <button class="reports-tab" data-tab="webrtc" onclick="switchReport('webrtc')">🛡️ WebRTC</button>
    <button class="reports-tab" data-tab="vpn" onclick="switchReport('vpn')">🔒 VPN</button>
    <button class="reports-tab" data-tab="hourly" onclick="switchReport('hourly')">🔥 الساعات</button>
    <button class="reports-tab" data-tab="anomalies" onclick="switchReport('anomalies')">⚠️ الشذوذ</button>
  </div>

  <div id="reportBody">
    <div class="ovg-skeleton" style="height:300px;border-radius:16px;"></div>
  </div>
</div>
"""
)

# =========================================================
# DASHBOARD HTML — PART 5/7: TRACKER + SETTINGS + MODALS
# =========================================================
DASHBOARD_HTML_PART5 = (
r"""
<!-- ============ VIEW: TRACKER ============ -->
<div class="view" id="view-tracker">
  <div class="page-header">
    <div>
      <h1 class="page-title">كود التتبع</h1>
      <p class="page-subtitle">انسخ الكود وحطه في موقعك داخل &lt;head&gt; أو قبل &lt;/body&gt;</p>
    </div>
  </div>

  <div class="ovg-card ovg-card-pad" style="margin-bottom:16px;">
    <label class="kpi-label" style="display:block;margin-bottom:6px;">Site Key</label>
    <div style="display:flex;gap:8px;">
      <input class="ovg-input" id="siteKeyInput" readonly style="font-family:var(--ovg-mono);font-size:12px;">
      <button class="ovg-btn ovg-btn-secondary" onclick="ovgCopy(document.getElementById('siteKeyInput').value, this)">نسخ</button>
    </div>
    <p style="font-size:11px;color:var(--ovg-text-dim);margin-top:6px;">المفتاح مدمج جوه الكود تحت — مش محتاج تحطه يدوياً</p>
  </div>

  <div class="ovg-card" style="padding:20px;background:#0F172A;border:none;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <label style="font-size:11px;font-weight:700;color:#94A3B8;">الكود الكامل (جاهز للنسخ)</label>
      <button class="ovg-btn ovg-btn-sm" style="background:#334155;color:#F1F5F9;" onclick="ovgCopy(document.getElementById('embedCode').textContent, this)">نسخ الكود</button>
    </div>
    <pre id="embedCode" style="color:#34D399;font-size:11px;font-family:var(--ovg-mono);overflow-x:auto;white-space:pre-wrap;line-height:1.6;margin:0;max-height:400px;overflow-y:auto;">جاري التحميل...</pre>
  </div>

  <div style="margin-top:16px;padding:14px 16px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:12px;font-size:12px;color:#92400E;">
    <p style="font-weight:700;margin-bottom:4px;">⚠️ ملاحظة مهمة</p>
    <p style="line-height:1.6;">لازم تضيف <code style="background:rgba(245,158,11,.2);padding:2px 6px;border-radius:4px;">?zoneId=XXX</code> في روابط صفحات موقعك عشان الزون يظهر في التقارير.</p>
  </div>
</div>

<!-- ============ VIEW: SETTINGS ============ -->
<div class="view" id="view-settings">
  <div class="page-header">
    <div>
      <h1 class="page-title">الإعدادات</h1>
      <p class="page-subtitle">إدارة بيانات الموقع والمفتاح</p>
    </div>
  </div>

  <div class="ovg-card ovg-card-pad" style="max-width:600px;margin-bottom:16px;">
    <h3 style="margin-bottom:14px;">بيانات الموقع</h3>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div>
        <label class="kpi-label" style="display:block;margin-bottom:4px;">اسم الموقع</label>
        <input class="ovg-input" id="editName" placeholder="اسم الموقع">
      </div>
      <div>
        <label class="kpi-label" style="display:block;margin-bottom:4px;">الدومين (اختياري)</label>
        <input class="ovg-input" id="editDomain" placeholder="example.com">
      </div>
      <div>
        <button class="ovg-btn ovg-btn-primary" onclick="saveSiteSettings()">حفظ التعديلات</button>
      </div>
    </div>
  </div>

  <div class="ovg-card ovg-card-pad" style="max-width:600px;margin-bottom:16px;">
    <h3 style="margin-bottom:6px;">تجديد المفتاح</h3>
    <p style="font-size:12px;color:var(--ovg-text-muted);margin-bottom:12px;">لو المفتاح اتسرّب، اعمله rotate. الكود القديم هيبطّل يشتغل فوراً.</p>
    <button class="ovg-btn ovg-btn-secondary" onclick="rotateSiteKey()">🔄 تجديد المفتاح</button>
  </div>

  <div class="ovg-card ovg-card-pad" style="max-width:600px;border-color:rgba(244,63,94,.3);background:rgba(244,63,94,.03);">
    <h3 style="color:#BE123C;margin-bottom:6px;">منطقة الخطر</h3>
    <p style="font-size:12px;color:#BE123C;opacity:.8;margin-bottom:12px;">حذف الموقع هيمسح كل البيانات المرتبطة بيه نهائياً</p>
    <button class="ovg-btn ovg-btn-danger" onclick="deleteCurrentSite()">حذف الموقع نهائياً</button>
  </div>
</div>
"""
)

# =========================================================
# DASHBOARD HTML — PART 6/7: MODALS + COMMAND PALETTE
# =========================================================
DASHBOARD_HTML_PART6 = (
r"""
</div><!-- /views-container -->
</main>
</div><!-- /app-shell -->

<!-- ============ MOBILE NAV ============ -->
<nav class="mobile-nav">
  <div class="mobile-nav-inner">
    <button data-nav="sites" onclick="navTo('sites')"><span class="m-icon">📊</span>المواقع</button>
    <button data-nav="overview" onclick="navTo('overview')"><span class="m-icon">🏠</span>نظرة</button>
    <button data-nav="visits" onclick="navTo('visits')"><span class="m-icon">📋</span>الزيارات</button>
    <button data-nav="reports" onclick="navTo('reports')"><span class="m-icon">📈</span>تقارير</button>
    <button data-nav="settings" onclick="navTo('settings')"><span class="m-icon">⚙️</span>إعدادات</button>
  </div>
</nav>

<!-- ============ MODAL: SITE CREATE ============ -->
<div class="ovg-modal-bg" id="siteModal">
  <div class="ovg-modal" style="max-width:440px;width:100%;">
    <h3 style="margin-bottom:4px;">موقع جديد</h3>
    <p style="color:var(--ovg-text-muted);font-size:12px;margin-bottom:20px;">أضف موقع وابدأ تتبع الزيارات</p>
    <form id="siteForm" onsubmit="submitSiteForm(event)">
      <div style="margin-bottom:14px;">
        <label class="kpi-label" style="display:block;margin-bottom:4px;">اسم الموقع *</label>
        <input class="ovg-input" id="newName" required maxlength="100" placeholder="مثال: متجر الأناقة">
      </div>
      <div style="margin-bottom:20px;">
        <label class="kpi-label" style="display:block;margin-bottom:4px;">الدومين (اختياري)</label>
        <input class="ovg-input" id="newDomain" maxlength="253" placeholder="shop.example.com">
      </div>
      <div style="display:flex;gap:8px;">
        <button type="button" class="ovg-btn ovg-btn-secondary" style="flex:1;" onclick="ovgCloseModal('siteModal')">إلغاء</button>
        <button type="submit" class="ovg-btn ovg-btn-primary" style="flex:1;" id="createSiteBtn">إنشاء</button>
      </div>
    </form>
  </div>
</div>

<!-- ============ MODAL: SITE CREATED (show tracker code) ============ -->
<div class="ovg-modal-bg" id="createdModal">
  <div class="ovg-modal" style="max-width:720px;width:100%;">
    <div style="text-align:center;margin-bottom:20px;">
      <div style="width:64px;height:64px;border-radius:50%;background:rgba(16,185,129,.15);display:flex;align-items:center;justify-content:center;font-size:32px;margin:0 auto 12px;">✅</div>
      <h3>تم إنشاء الموقع بنجاح!</h3>
      <p style="color:var(--ovg-text-muted);font-size:13px;margin-top:4px;">الموقع <span id="createdSiteName" style="color:var(--ovg-primary);font-weight:700;"></span> جاهز للتتبع</p>
    </div>
    <div style="margin-bottom:12px;">
      <label class="kpi-label" style="display:block;margin-bottom:4px;">Site Key</label>
      <div style="display:flex;gap:6px;">
        <input class="ovg-input" id="createdKey" readonly style="font-family:var(--ovg-mono);font-size:12px;">
        <button class="ovg-btn ovg-btn-secondary ovg-btn-sm" onclick="ovgCopy(document.getElementById('createdKey').value, this)">نسخ</button>
      </div>
    </div>
    <div style="margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <label class="kpi-label">كود التتبع الكامل</label>
        <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="ovgCopy(document.getElementById('createdCode').textContent, this)">نسخ الكود</button>
      </div>
      <pre id="createdCode" style="background:#0F172A;color:#34D399;font-size:11px;padding:14px;border-radius:12px;overflow:auto;max-height:240px;font-family:var(--ovg-mono);margin:0;">جاري التحميل...</pre>
    </div>
    <div style="padding:12px 14px;background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.3);border-radius:10px;font-size:11px;color:#92400E;line-height:1.6;margin-bottom:16px;">
      ⚠️ لازم تضيف <code style="background:rgba(245,158,11,.2);padding:2px 6px;border-radius:4px;">?zoneId=XXX</code> في روابط صفحات موقعك عشان الزون يظهر في التقارير.
    </div>
    <div style="display:flex;gap:8px;">
      <button class="ovg-btn ovg-btn-secondary" style="flex:1;" onclick="closeCreatedModal()">+ إضافة موقع آخر</button>
      <button class="ovg-btn ovg-btn-primary" style="flex:1;" onclick="goToCreatedDashboard()">روح للداشبورد ←</button>
    </div>
  </div>
</div>

<!-- ============ MODAL: ADVANCED FILTER ============ -->
<div class="ovg-modal-bg" id="filterModal">
  <div class="ovg-modal" style="max-width:560px;width:100%;">
    <h3 style="margin-bottom:4px;">فلتر متقدم</h3>
    <p style="color:var(--ovg-text-muted);font-size:12px;margin-bottom:18px;">كل الشروط متصلة بـ AND</p>
    <div id="filterConditions" style="display:flex;flex-direction:column;gap:8px;margin-bottom:12px;"></div>
    <button class="ovg-btn ovg-btn-ghost ovg-btn-sm" onclick="addFilterCondition()">+ إضافة شرط</button>
    <div style="display:flex;gap:8px;margin-top:18px;">
      <button class="ovg-btn ovg-btn-secondary" style="flex:1;" onclick="clearAdvancedFilters()">مسح الكل</button>
      <button class="ovg-btn ovg-btn-primary" style="flex:1;" onclick="applyAdvancedFilters()">تطبيق</button>
    </div>
  </div>
</div>

<!-- ============ MODAL: SAVE SEGMENT ============ -->
<div class="ovg-modal-bg" id="segmentModal">
  <div class="ovg-modal" style="max-width:400px;width:100%;">
    <h3 style="margin-bottom:16px;">حفظ كـ Segment</h3>
    <input class="ovg-input" id="segmentName" placeholder="اسم الـ Segment" maxlength="60" style="margin-bottom:14px;">
    <div style="display:flex;gap:8px;">
      <button class="ovg-btn ovg-btn-secondary" style="flex:1;" onclick="ovgCloseModal('segmentModal')">إلغاء</button>
      <button class="ovg-btn ovg-btn-primary" style="flex:1;" onclick="saveSegment()">حفظ</button>
    </div>
  </div>
</div>

<!-- ============ MODAL: SITE SWITCHER ============ -->
<div class="ovg-modal-bg" id="siteSwitchModal">
  <div class="ovg-modal" style="max-width:440px;width:100%;">
    <h3 style="margin-bottom:16px;">تبديل الموقع</h3>
    <div id="siteSwitchList" style="display:flex;flex-direction:column;gap:6px;max-height:400px;overflow-y:auto;"></div>
    <button class="ovg-btn ovg-btn-secondary" style="width:100%;margin-top:14px;" onclick="ovgCloseModal('siteSwitchModal')">إلغاء</button>
  </div>
</div>

<!-- ============ COMMAND PALETTE ============ -->
<div class="cmd-bg" id="cmdPalette">
  <div class="cmd-box">
    <div class="cmd-input-wrap">
      <span style="font-size:18px;color:var(--ovg-text-dim);">🔍</span>
      <input id="cmdInput" placeholder="ابحث عن زيارة، موقع، أو أمر..." oninput="cmdSearch(this.value)" onkeydown="cmdKeydown(event)" autocomplete="off">
      <span style="font-size:10px;padding:3px 7px;border-radius:5px;background:var(--ovg-bg);border:1px solid var(--ovg-border);color:var(--ovg-text-dim);font-family:var(--ovg-mono);">ESC</span>
    </div>
    <div class="cmd-results" id="cmdResults">
      <div class="cmd-empty">اكتب حاجة للبحث...</div>
    </div>
  </div>
</div>

<!-- ============ TOASTS ============ -->
<div class="ovg-toasts"></div>
"""
)

# =========================================================
# DASHBOARD HTML — PART 7/7: SHARED JS
# =========================================================
DASHBOARD_HTML_JS = (
DESIGN_SYSTEM_JS + r"""

// =========================================================
// APP STATE
// =========================================================
const state = {
  user: null,
  sites: [],
  currentSite: null,
  view: 'sites',
  trendChart: null,
  sparkCharts: {},
  visits: {
    page: 1,
    per_page: 50,
    sort_by: 'timestamp',
    sort_dir: 'desc',
    group_by: '',
    search: '',
    quick: 'all',
    filters: {},
    selected: new Set(),
    total: 0,
    pages: 1,
    data: [],
  },
  currentReport: 'zones',
  commands: [],
  cmdActiveIdx: 0,
  cmdResults: [],
};

const MAX_SITES = 20;
const REPORT_LABELS = {
  zones: 'الزونات', countries: 'الدول', devices: 'الأجهزة',
  browsers: 'المتصفحات', os: 'الأنظمة', fingerprints: 'البصمات',
  ips: 'الـ IPs', asn: 'ASN', timezones: 'التوقيت',
  webrtc: 'WebRTC', vpn: 'VPN', hourly: 'الساعات', anomalies: 'الشذوذ',
};

// =========================================================
// API HELPER
// =========================================================
async function api(path, opts) {
  opts = opts || {};
  try {
    const r = await fetch(path, {
      method: opts.method || 'GET',
      headers: Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {}),
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail || ('HTTP ' + r.status));
    return data;
  } catch (e) {
    throw e;
  }
}

// =========================================================
// THEME
// =========================================================
function toggleTheme() {
  ovgTheme.toggle();
  document.getElementById('themeBtn').textContent =
    ovgTheme.get() === 'dark' ? '☀️' : '🌙';
}
(function initThemeBtn() {
  var btn = document.getElementById('themeBtn');
  if (btn) btn.textContent = ovgTheme.get() === 'dark' ? '☀️' : '🌙';
})();

// =========================================================
// USER MENU
// =========================================================
function toggleUserMenu(e) {
  e.stopPropagation();
  document.getElementById('userDropdown').classList.toggle('open');
}
function closeUserMenu() {
  document.getElementById('userDropdown').classList.remove('open');
}
document.addEventListener('click', function (e) {
  if (!e.target.closest('#userAvatarBtn') && !e.target.closest('#userDropdown')) {
    closeUserMenu();
  }
});

// =========================================================
// NAVIGATION
// =========================================================
function navTo(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const el = document.getElementById('view-' + view);
  if (el) el.classList.add('active');

  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.nav === view);
  });
  document.querySelectorAll('.mobile-nav button').forEach(b => {
    b.classList.toggle('active', b.dataset.nav === view);
  });

  const crumbMap = {
    sites: 'المواقع', overview: 'النظرة العامة', visits: 'كل الزيارات',
    reports: 'التقارير', tracker: 'كود التتبع', settings: 'الإعدادات',
  };
  document.getElementById('crumbCurrent').textContent = crumbMap[view] || view;

  if (view === 'sites') renderSites();
  if (view === 'overview') loadOverview();
  if (view === 'visits') reloadVisits();
  if (view === 'reports') switchReport(state.currentReport);
  if (view === 'tracker') renderTracker();
  if (view === 'settings') renderSettings();

  // Close mobile sidebar
  document.getElementById('sidebar').classList.remove('open');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showSiteSections(show) {
  const ids = ['navOverview', 'analysisSection', 'toolsSection'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = show ? '' : 'none';
  });
}

// =========================================================
// INIT
// =========================================================
async function init() {
  try {
    const me = await api('/api/auth/me');
    state.user = me;
    document.getElementById('userName').textContent = me.username;
    document.getElementById('userAvatar').textContent =
      me.username.charAt(0).toUpperCase();
    document.getElementById('userAvatarBtn').textContent =
      me.username.charAt(0).toUpperCase();
  } catch (e) {
    window.location.href = '/';
    return;
  }
  await loadSites();
  const params = new URLSearchParams(window.location.search);
  const siteKey = params.get('site');
  if (siteKey) {
    const s = state.sites.find(x => x.site_key === siteKey);
    if (s) { selectSite(s, false); return; }
  }
  navTo('sites');
  if (state.sites.length === 0) {
    setTimeout(openSiteModal, 400);
  }
}

// =========================================================
// SITES
// =========================================================
async function loadSites() {
  try {
    state.sites = await api('/api/sites');
    document.getElementById('siteLimit').textContent =
      state.sites.length + '/' + MAX_SITES;
  } catch (e) {
    ovgToast('فشل تحميل المواقع', 'error');
  }
}

function renderSites() {
  const grid = document.getElementById('sitesGrid');
  if (!state.sites.length) {
    grid.innerHTML =
      '<div class="ovg-card ovg-card-pad" style="grid-column:1/-1;text-align:center;padding:60px 20px;">' +
        '<div style="font-size:56px;margin-bottom:12px;">🌐</div>' +
        '<h3 style="margin-bottom:6px;">مفيش مواقع لسه</h3>' +
        '<p style="color:var(--ovg-text-muted);font-size:13px;margin-bottom:20px;">أضف أول موقع ليك وابدأ تبعت الزيارات</p>' +
        '<button class="ovg-btn ovg-btn-primary" onclick="openSiteModal()">+ أضف موقعك الأول</button>' +
      '</div>';
    return;
  }
  grid.innerHTML = state.sites.map((s, i) => {
    const total = s.total || 0;
    const valid = s.valid || 0;
    const invalid = s.invalid || 0;
    const quality = total > 0 ? Math.round((valid / total) * 100) : 0;
    const qColor = quality >= 80 ? '#059669' : quality >= 50 ? '#D97706' : '#E11D48';
    const last = s.last_visit ? ovgTimeAgo(s.last_visit) : 'لا يوجد نشاط';
    return (
      '<div class="ovg-card ovg-card-hover ovg-fade-up" style="--i:' + i + ';padding:18px;cursor:pointer;" onclick="openSite(\'' + s.site_key + '\')">' +
        '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;">' +
          '<div style="min-width:0;flex:1;">' +
            '<h3 style="font-size:16px;font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + ovgEsc(s.name) + '</h3>' +
            '<p style="font-size:11px;color:var(--ovg-text-dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + ovgEsc(s.domain || 'بدون دومين') + '</p>' +
          '</div>' +
          '<div style="width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,rgba(99,102,241,.1),rgba(139,92,246,.1));display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;">🌐</div>' +
        '</div>' +
        '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:4px;padding:10px 0;border-top:1px solid var(--ovg-border);border-bottom:1px solid var(--ovg-border);margin-bottom:10px;">' +
          '<div style="text-align:center;"><div style="font-size:10px;color:var(--ovg-text-dim);font-weight:700;">إجمالي</div><div style="font-size:16px;font-weight:800;font-variant-numeric:tabular-nums;font-family:var(--ovg-mono);">' + total + '</div></div>' +
          '<div style="text-align:center;"><div style="font-size:10px;color:var(--ovg-text-dim);font-weight:700;">صالح</div><div style="font-size:16px;font-weight:800;color:#059669;font-variant-numeric:tabular-nums;font-family:var(--ovg-mono);">' + valid + '</div></div>' +
          '<div style="text-align:center;"><div style="font-size:10px;color:var(--ovg-text-dim);font-weight:700;">بوتات</div><div style="font-size:16px;font-weight:800;color:#E11D48;font-variant-numeric:tabular-nums;font-family:var(--ovg-mono);">' + invalid + '</div></div>' +
        '</div>' +
        '<div style="display:flex;justify-content:space-between;font-size:11px;">' +
          '<span style="color:var(--ovg-text-dim);">' + last + '</span>' +
          '<span style="color:' + qColor + ';font-weight:800;">' + quality + '% جودة</span>' +
        '</div>' +
      '</div>'
    );
  }).join('');
}

function openSite(key) {
  const s = state.sites.find(x => x.site_key === key);
  if (!s) return;
  selectSite(s, true);
}

function selectSite(site, push) {
  state.currentSite = site;
  showSiteSections(true);
  if (push) {
    history.pushState({}, '', '/dashboard?site=' + site.site_key);
  }
  document.getElementById('overviewSiteName').textContent = site.name;
  document.getElementById('overviewSiteDomain').textContent = site.domain || 'بدون دومين';
  navTo('overview');
}

function openSiteModal() {
  document.getElementById('newName').value = '';
  document.getElementById('newDomain').value = '';
  ovgOpenModal('siteModal');
  setTimeout(() => document.getElementById('newName').focus(), 60);
}

async function submitSiteForm(e) {
  e.preventDefault();
  const name = document.getElementById('newName').value.trim();
  const domain = document.getElementById('newDomain').value.trim();
  if (!name) return;
  const btn = document.getElementById('createSiteBtn');
  btn.disabled = true; btn.textContent = 'جاري...';
  try {
    const d = await api('/api/sites', { method: 'POST', body: { name, domain } });
    ovgCloseModal('siteModal');
    await loadSites();
    showCreatedModal(d);
  } catch (err) {
    ovgToast(err.message || 'فشل الإنشاء', 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'إنشاء';
  }
}

async function showCreatedModal(site) {
  document.getElementById('createdSiteName').textContent = site.name;
  document.getElementById('createdKey').value = site.site_key;
  document.getElementById('createdCode').textContent = 'جاري التحميل...';
  ovgOpenModal('createdModal');
  window._justCreatedKey = site.site_key;
  try {
    const d = await api('/api/sites/' + site.id + '/tracker-code');
    document.getElementById('createdCode').textContent = d.code || 'فشل';
  } catch (e) {
    document.getElementById('createdCode').textContent = 'فشل تحميل الكود';
  }
}

function closeCreatedModal() {
  ovgCloseModal('createdModal');
  window._justCreatedKey = null;
  setTimeout(openSiteModal, 200);
}

function goToCreatedDashboard() {
  ovgCloseModal('createdModal');
  const key = window._justCreatedKey;
  window._justCreatedKey = null;
  if (key) {
    const s = state.sites.find(x => x.site_key === key);
    if (s) { selectSite(s, true); return; }
  }
  navTo('sites');
}

// =========================================================
// SETTINGS
// =========================================================
function renderSettings() {
  if (!state.currentSite) return;
  document.getElementById('editName').value = state.currentSite.name;
  document.getElementById('editDomain').value = state.currentSite.domain || '';
}

async function saveSiteSettings() {
  if (!state.currentSite) return;
  const name = document.getElementById('editName').value.trim();
  const domain = document.getElementById('editDomain').value.trim();
  if (!name) { ovgToast('اسم الموقع مطلوب', 'warning'); return; }
  try {
    await api('/api/sites/' + state.currentSite.id, {
      method: 'PATCH', body: { name, domain },
    });
    ovgToast('تم الحفظ ✓', 'success');
    await loadSites();
    state.currentSite = state.sites.find(s => s.id === state.currentSite.id);
    renderSettings();
  } catch (e) { ovgToast(e.message || 'فشل الحفظ', 'error'); }
}

async function rotateSiteKey() {
  if (!state.currentSite) return;
  if (!confirm('تجديد المفتاح هيبطّل الكود القديم. متأكد؟')) return;
  try {
    await api('/api/sites/' + state.currentSite.id + '/rotate-key', { method: 'POST' });
    ovgToast('تم تجديد المفتاح', 'success');
    await loadSites();
    state.currentSite = state.sites.find(s => s.id === state.currentSite.id);
    renderTracker(); renderSettings();
  } catch (e) { ovgToast(e.message || 'فشل التجديد', 'error'); }
}

async function deleteCurrentSite() {
  if (!state.currentSite) return;
  if (!confirm('حذف "' + state.currentSite.name + '" نهائياً؟')) return;
  try {
    await api('/api/sites/' + state.currentSite.id, { method: 'DELETE' });
    ovgToast('تم الحذف', 'success');
    state.currentSite = null;
    showSiteSections(false);
    await loadSites();
    navTo('sites');
  } catch (e) { ovgToast(e.message || 'فشل الحذف', 'error'); }
}

// =========================================================
// TRACKER
// =========================================================
async function renderTracker() {
  if (!state.currentSite) return;
  document.getElementById('siteKeyInput').value = state.currentSite.site_key;
  document.getElementById('embedCode').textContent = 'جاري التحميل...';
  try {
    const d = await api('/api/sites/' + state.currentSite.id + '/tracker-code');
    document.getElementById('embedCode').textContent = d.code || 'فشل';
  } catch (e) {
    document.getElementById('embedCode').textContent = 'فشل تحميل الكود';
  }
}

// =========================================================
// LOGOUT
// =========================================================
async function doLogout() {
  try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) {}
  window.location.href = '/';
}
"""
)

# =========================================================
# DASHBOARD HTML — PART 8/7: APP LOGIC JS
# =========================================================
DASHBOARD_HTML_JS_LOGIC = (
r"""
// =========================================================
// OVERVIEW
// =========================================================
async function loadOverview() {
  if (!state.currentSite) return;
  const key = state.currentSite.site_key;
  document.getElementById('overviewSiteName').textContent = state.currentSite.name;
  document.getElementById('overviewSiteDomain').textContent = state.currentSite.domain || 'بدون دومين';

  try {
    const d = await api('/api/stats?site=' + key);
    // KPIs with count-up
    ovgCountUp(document.getElementById('kpi-total'), d.total);
    ovgCountUp(document.getElementById('kpi-valid'), d.valid);
    ovgCountUp(document.getElementById('kpi-invalid'), d.invalid);
    ovgCountUp(document.getElementById('kpi-suspicious'), d.suspicious);

    // Glance
    document.getElementById('glanceTotal').textContent = d.today.total;
    document.getElementById('glanceBots').textContent = d.today.bots;
    document.getElementById('glanceQuality').textContent = d.today.quality + '%';

    const deltaEl = (id, val, invert) => {
      const el = document.getElementById(id);
      if (!el) return;
      const up = val > 0, down = val < 0, eq = val === 0;
      el.className = 'kpi-delta ' + (eq ? 'neutral' : ((up !== !!invert) ? 'up' : 'down'));
      el.textContent = eq ? '= نفس أمس' : ((up ? '↑ ' : '↓ ') + Math.abs(val) + '%');
    };
    deltaEl('glanceTotalDelta', d.today.delta_total, false);
    deltaEl('glanceBotsDelta', d.today.delta_bots, true);
    deltaEl('glanceQualityDelta', d.today.delta_quality, false);

    // Live
    const pulse = document.getElementById('livePulse');
    const liveEl = document.getElementById('glanceLive');
    if (d.live_count > 0) {
      pulse.style.display = 'inline-block';
      liveEl.textContent = d.live_count + ' نشط الآن';
      liveEl.style.color = '#059669';
    } else {
      pulse.style.display = 'none';
      liveEl.textContent = 'لا يوجد نشاط حديث';
      liveEl.style.color = 'var(--ovg-text-dim)';
    }

    renderLiveFeed(d.recent || []);
    loadSparklines();
    loadTrend('7d');
    loadInsights();
  } catch (e) {
    ovgToast('فشل تحميل الإحصائيات', 'error');
  }
}

function renderLiveFeed(visits) {
  const feed = document.getElementById('liveFeed');
  if (!visits.length) {
    feed.innerHTML =
      '<div class="dt-empty"><div class="icon">📭</div>' +
      '<div>مفيش زيارات لسه — ركّب كود التتبع عشان تبدأ</div></div>';
    return;
  }
  feed.innerHTML = visits.map((v, i) => {
    const dot = v.verdict === 'valid' ? '#10B981' :
                v.verdict === 'invalid' ? '#F43F5E' : '#F59E0B';
    const badge = v.verdict === 'valid' ? 'ovg-badge-valid' :
                  v.verdict === 'invalid' ? 'ovg-badge-invalid' : 'ovg-badge-suspicious';
    return (
      '<div class="ovg-fade-up" style="--i:' + i + ';display:flex;align-items:center;gap:10px;padding:10px 20px;border-bottom:1px solid var(--ovg-border);cursor:pointer;transition:background .15s;" onmouseover="this.style.background=\'var(--ovg-bg)\'" onmouseout="this.style.background=\'\'" onclick="window.location.href=\'/visits/' + v.id + '\'">' +
        '<div style="width:8px;height:8px;border-radius:50%;background:' + dot + ';flex-shrink:0;"></div>' +
        '<div style="font-family:var(--ovg-mono);font-size:11px;color:var(--ovg-text-dim);min-width:56px;">' + ovgEsc(v.time) + '</div>' +
        '<div style="flex:1;font-size:12px;font-weight:600;">' + ovgEsc(v.country) + ' · ' + ovgEsc(v.zone) + '</div>' +
        '<div style="font-family:var(--ovg-mono);font-size:12px;color:' + (v.score >= 80 ? '#E11D48' : v.score >= 40 ? '#D97706' : '#059669') + ';font-weight:700;">' + v.score + '</div>' +
        '<span class="ovg-badge ' + badge + '">' + v.verdict + '</span>' +
      '</div>'
    );
  }).join('');
}

async function loadInsights() {
  const box = document.getElementById('insightsBox');
  try {
    const d = await api('/api/insights?site=' + state.currentSite.site_key);
    if (!d.length) { box.innerHTML = '<p class="ovg-text-dim" style="font-size:13px;">لا توجد توصيات حالياً</p>'; return; }
    const icons = { positive: '✅', warning: '⚠️', critical: '🚨', info: 'ℹ️' };
    const bg = { positive: 'rgba(16,185,129,.08)', warning: 'rgba(245,158,11,.08)', critical: 'rgba(244,63,94,.08)', info: 'rgba(99,102,241,.06)' };
    box.innerHTML = d.map((x, i) =>
      '<div class="ovg-fade-up" style="--i:' + i + ';display:flex;gap:10px;padding:10px 12px;background:' + (bg[x.type] || bg.info) + ';border-radius:10px;font-size:12px;line-height:1.6;">' +
        '<span style="font-size:16px;flex-shrink:0;">' + (icons[x.type] || '') + '</span>' +
        '<span>' + ovgEsc(x.text) + '</span>' +
      '</div>'
    ).join('');
  } catch (e) {
    box.innerHTML = '<p class="ovg-text-dim" style="font-size:13px;">تعذر تحميل التوصيات</p>';
  }
}

async function loadSparklines() {
  try {
    const d = await api('/api/stats/sparkline?site=' + state.currentSite.site_key);
    const mk = (id, data, color) => {
      const ctx = document.getElementById(id);
      if (!ctx) return;
      if (state.sparkCharts[id]) state.sparkCharts[id].destroy();
      state.sparkCharts[id] = new Chart(ctx, {
        type: 'line',
        data: { labels: d.labels, datasets: [{ data: data, borderColor: color, backgroundColor: color + '22', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 }] },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false }, tooltip: { enabled: false } },
          scales: { x: { display: false }, y: { display: false } },
        },
      });
    };
    mk('sparkTotal', d.totals, '#6366F1');
    mk('sparkValid', d.totals.map((t, i) => t - d.bots[i]), '#10B981');
    mk('sparkBots', d.bots, '#F43F5E');
    mk('sparkQuality', d.quality, '#F59E0B');
  } catch (e) {}
}

async function loadTrend(range) {
  document.querySelectorAll('#trendTabs button').forEach(b => {
    const isActive = b.dataset.range === range;
    b.style.background = isActive ? 'var(--ovg-card)' : 'transparent';
    b.style.color = isActive ? 'var(--ovg-primary)' : 'var(--ovg-text-muted)';
    b.style.fontWeight = isActive ? '700' : '600';
  });
  try {
    const d = await api('/api/reports/trend?range=' + range + '&site=' + state.currentSite.site_key);
    if (state.trendChart) state.trendChart.destroy();
    state.trendChart = new Chart(document.getElementById('trendChart'), {
      type: 'line',
      data: {
        labels: d.labels,
        datasets: [
          { label: 'إجمالي', data: d.totals, borderColor: '#6366F1', backgroundColor: 'rgba(99,102,241,.1)', fill: true, tension: 0.35, borderWidth: 2.5, pointRadius: 3, pointHoverRadius: 5 },
          { label: 'بوتات', data: d.bots, borderColor: '#F43F5E', backgroundColor: 'rgba(244,63,94,.08)', fill: true, tension: 0.35, borderWidth: 2.5, pointRadius: 3, pointHoverRadius: 5 },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, font: { size: 11, family: 'Cairo' } } },
          tooltip: { mode: 'index', intersect: false },
        },
        scales: {
          x: { grid: { display: false }, ticks: { font: { family: 'Cairo', size: 10 }, color: '#94A3B8' } },
          y: { grid: { color: 'rgba(148,163,184,.1)' }, beginAtZero: true, ticks: { font: { family: 'Cairo', size: 10 }, color: '#94A3B8' } },
        },
      },
    });
  } catch (e) {}
}

async function runMock() {
  if (!state.currentSite) return;
  try {
    await api('/api/mock-data?site=' + state.currentSite.site_key, { method: 'POST' });
    ovgToast('تم توليد 120 زيارة تجريبية', 'success');
    loadOverview();
  } catch (e) { ovgToast('فشل التوليد', 'error'); }
}

// =========================================================
// VISITS — filters + table
// =========================================================
function buildVisitsQuery() {
  const v = state.visits;
  const params = new URLSearchParams();
  params.set('page', v.page);
  params.set('per_page', v.per_page);
  params.set('sort_by', v.sort_by);
  params.set('sort_dir', v.sort_dir);
  if (v.group_by) params.set('groupBy', v.group_by);
  if (state.currentSite) params.set('site', state.currentSite.site_key);
  if (v.search) params.set('ip', v.search);
  if (v.quick === 'valid' || v.quick === 'invalid' || v.quick === 'suspicious') {
    params.set('verdict', v.quick);
  } else if (v.quick === 'highrisk') {
    params.set('score_min', '80');
  }
  Object.entries(v.filters || {}).forEach(([k, val]) => {
    if (val !== '' && val != null) params.set(k, val);
  });
  return params.toString();
}

async function reloadVisits() {
  const v = state.visits;
  v.sort_by = document.getElementById('visitSortBy').value;
  v.sort_dir = document.getElementById('visitSortDir').value;
  v.group_by = document.getElementById('visitGroupBy').value;
  const tbody = document.getElementById('visitsTbody');
  tbody.innerHTML = '<tr><td colspan="11" class="dt-empty"><div class="ovg-skeleton" style="height:22px;margin:4px 0;"></div><div class="ovg-skeleton" style="height:22px;margin:4px 0;"></div></td></tr>';
  try {
    const d = await api('/api/visits?' + buildVisitsQuery());
    v.total = d.total; v.pages = d.pages; v.data = d.items;
    document.getElementById('visitsCount').textContent = d.total + ' زيارة';
    renderVisitsTable(d.items);
    renderVisitsPager();
    renderActiveFilters();
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="11" class="dt-empty">فشل التحميل: ' + ovgEsc(e.message) + '</td></tr>';
  }
}

function renderVisitsTable(items) {
  const tbody = document.getElementById('visitsTbody');
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="11" class="dt-empty"><div class="icon">📭</div>مفيش زيارات مطابقة</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(v => {
    const checked = state.visits.selected.has(v.id) ? 'checked' : '';
    const rowCls = 'row-' + v.verdict;
    const badge = 'ovg-badge-' + v.verdict;
    const scColor = v.score >= 80 ? '#E11D48' : v.score >= 40 ? '#D97706' : '#059669';
    const time = v.timestamp ? new Date(v.timestamp).toLocaleString('en-GB', { hour12: false }) : '—';
    return (
      '<tr class="' + rowCls + '">' +
        '<td><input type="checkbox" ' + checked + ' onchange="toggleRowSelect(' + v.id + ', this.checked)"></td>' +
        '<td style="font-family:var(--ovg-mono);font-size:11px;">' + time + '</td>' +
        '<td style="font-family:var(--ovg-mono);font-size:11px;">' + ovgEsc(v.ip) + '</td>' +
        '<td>' + ovgEsc(v.zone) + '</td>' +
        '<td>' + ovgEsc(v.country) + '</td>' +
        '<td>' + ovgEsc(v.device) + '</td>' +
        '<td>' + ovgEsc(v.browser) + '</td>' +
        '<td style="font-family:var(--ovg-mono);font-size:11px;">' + ovgEsc(v.asn) + '</td>' +
        '<td style="font-family:var(--ovg-mono);font-weight:700;color:' + scColor + ';">' + v.score + '</td>' +
        '<td><span class="ovg-badge ' + badge + '">' + v.verdict + '</span></td>' +
        '<td><a href="/visits/' + v.id + '" class="ovg-btn ovg-btn-ghost ovg-btn-sm" style="padding:4px 8px;">عرض</a></td>' +
      '</tr>'
    );
  }).join('');
  document.getElementById('checkAll').checked = items.every(v => state.visits.selected.has(v.id));
  updateBulkBar();
}

function renderVisitsPager() {
  const v = state.visits;
  const p = document.getElementById('visitsPager');
  p.innerHTML =
    '<button ' + (v.page <= 1 ? 'disabled' : '') + ' onclick="changePage(' + (v.page - 1) + ')">→ السابق</button>' +
    '<span class="pg-info">صفحة ' + v.page + ' من ' + v.pages + '</span>' +
    '<button ' + (v.page >= v.pages ? 'disabled' : '') + ' onclick="changePage(' + (v.page + 1) + ')">التالي ←</button>';
}

function changePage(p) {
  if (p < 1 || p > state.visits.pages) return;
  state.visits.page = p;
  reloadVisits();
}

function quickFilter(kind) {
  state.visits.quick = kind;
  state.visits.page = 1;
  reloadVisits();
}

function applySearchFilter() {
  state.visits.search = document.getElementById('visitSearch').value.trim();
  state.visits.page = 1;
  reloadVisits();
}

function toggleRowSelect(id, checked) {
  if (checked) state.visits.selected.add(id);
  else state.visits.selected.delete(id);
  updateBulkBar();
}

function toggleAllRows() {
  const checked = document.getElementById('checkAll').checked;
  if (checked) state.visits.data.forEach(v => state.visits.selected.add(v.id));
  else state.visits.selected.clear();
  reloadVisits();
}

function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  const n = state.visits.selected.size;
  bar.style.display = n > 0 ? 'flex' : 'none';
  document.getElementById('bulkCount').textContent = n;
}

function clearSelection() {
  state.visits.selected.clear();
  reloadVisits();
}

async function bulkAction(action) {
  const ids = Array.from(state.visits.selected);
  if (!ids.length) return;
  const payload = { ids, action };
  if (action === 'add_tag') {
    const tag = prompt('اسم الـ Tag:');
    if (!tag) return;
    payload.tag = tag.trim();
  }
  if (action === 'delete' && !confirm('حذف ' + ids.length + ' زيارة نهائياً؟')) return;
  try {
    await api('/api/visits/bulk', { method: 'POST', body: payload });
    ovgToast('تم ' + ids.length + ' زيارة', 'success');
    state.visits.selected.clear();
    reloadVisits();
  } catch (e) { ovgToast(e.message || 'فشل', 'error'); }
}

function exportVisits(fmt) {
  const q = buildVisitsQuery().replace(/page=\d+&?/, '').replace(/per_page=\d+&?/, '');
  window.open('/api/visits/export?format=' + fmt + '&' + q, '_blank');
}

// =========================================================
// ADVANCED FILTERS
// =========================================================
function openFilterModal() {
  const conds = document.getElementById('filterConditions');
  conds.innerHTML = '';
  addFilterCondition();
  ovgOpenModal('filterModal');
}

function addFilterCondition() {
  const conds = document.getElementById('filterConditions');
  const row = document.createElement('div');
  row.style.cssText = 'display:grid;grid-template-columns:1fr 1fr 1.2fr;gap:6px;align-items:center;';
  row.innerHTML =
    '<select class="ovg-input fld" style="padding:8px;font-size:12px;">' +
      '<option value="country">الدولة</option><option value="zone">الزون</option>' +
      '<option value="verdict">الحكم</option><option value="device">الجهاز</option>' +
      '<option value="browser">المتصفح</option><option value="os">النظام</option>' +
      '<option value="asn">ASN</option><option value="isp">ISP</option>' +
      '<option value="score_min">Score ≥</option><option value="score_max">Score ≤</option>' +
    '</select>' +
    '<select class="ovg-input op" style="padding:8px;font-size:12px;">' +
      '<option value="eq">يساوي</option><option value="neq">لا يساوي</option>' +
    '</select>' +
    '<input class="ovg-input val" style="padding:8px;font-size:12px;" placeholder="القيمة">';
  conds.appendChild(row);
}

function clearAdvancedFilters() {
  state.visits.filters = {};
  state.visits.page = 1;
  ovgCloseModal('filterModal');
  reloadVisits();
}

function applyAdvancedFilters() {
  const rows = document.querySelectorAll('#filterConditions > div');
  const filters = {};
  rows.forEach(r => {
    const fld = r.querySelector('.fld').value;
    const val = r.querySelector('.val').value.trim();
    if (val) filters[fld] = val;
  });
  state.visits.filters = filters;
  state.visits.page = 1;
  ovgCloseModal('filterModal');
  reloadVisits();
}

function renderActiveFilters() {
  const host = document.getElementById('activeFilters');
  const chips = [];
  const v = state.visits;
  if (v.search) chips.push({ k: 'search', label: 'IP: ' + v.search });
  if (v.quick !== 'all') chips.push({ k: 'quick', label: 'Quick: ' + v.quick });
  Object.entries(v.filters || {}).forEach(([k, val]) => {
    chips.push({ k: 'f_' + k, label: k + ': ' + val });
  });
  host.innerHTML = chips.map(c =>
    '<span class="filter-chip">' + ovgEsc(c.label) +
      '<button onclick="removeFilterChip(\'' + c.k + '\')">×</button></span>'
  ).join('');
}

function removeFilterChip(key) {
  if (key === 'search') state.visits.search = '';
  else if (key === 'quick') state.visits.quick = 'all';
  else if (key.startsWith('f_')) delete state.visits.filters[key.slice(2)];
  state.visits.page = 1;
  reloadVisits();
}

function saveAsSegment() {
  document.getElementById('segmentName').value = '';
  ovgOpenModal('segmentModal');
}

async function saveSegment() {
  const name = document.getElementById('segmentName').value.trim();
  if (!name) return;
  try {
    await api('/api/segments', {
      method: 'POST',
      body: { name, filters: state.visits.filters, site: state.currentSite.site_key },
    });
    ovgToast('تم حفظ الـ Segment', 'success');
    ovgCloseModal('segmentModal');
  } catch (e) { ovgToast(e.message || 'فشل', 'error'); }
}

// =========================================================
// REPORTS
// =========================================================
function switchReport(kind) {
  state.currentReport = kind;
  document.querySelectorAll('#reportsTabs .reports-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === kind);
  });
  loadReport(kind);
}

async function loadReport(kind) {
  const body = document.getElementById('reportBody');
  body.innerHTML = '<div class="ovg-skeleton" style="height:300px;border-radius:16px;"></div>';
  if (!state.currentSite) {
    body.innerHTML = '<div class="dt-empty">اختر موقع أولاً</div>';
    return;
  }
  try {
    if (kind === 'hourly') return renderHourlyReport(await api('/api/reports/hourly?site=' + state.currentSite.site_key));
    if (kind === 'vpn') return renderVpnReport(await api('/api/reports/vpn?site=' + state.currentSite.site_key));
    if (kind === 'anomalies') return renderAnomaliesReport(await api('/api/reports/anomalies?site=' + state.currentSite.site_key));
    if (kind === 'webrtc') return renderWebrtcReport(await api('/api/reports/webrtc?site=' + state.currentSite.site_key));
    if (kind === 'fingerprints') return renderFingerprintsReport(await api('/api/reports/fingerprints?site=' + state.currentSite.site_key));
    if (kind === 'ips') return renderIpsReport(await api('/api/reports/ips?site=' + state.currentSite.site_key));
    if (kind === 'asn') return renderAsnReport(await api('/api/reports/asn?site=' + state.currentSite.site_key));
    if (kind === 'zones') return renderZonesReport(await api('/api/reports/zones?site=' + state.currentSite.site_key));
    if (kind === 'timezones') return renderTimezonesReport(await api('/api/reports/timezones?site=' + state.currentSite.site_key));
    if (kind === 'countries') return renderCountriesReport(await api('/api/reports/countries?site=' + state.currentSite.site_key));
    return renderSimpleReport(kind, await api('/api/reports/' + kind + '?site=' + state.currentSite.site_key));
  } catch (e) {
    body.innerHTML = '<div class="dt-empty">فشل تحميل التقرير: ' + ovgEsc(e.message) + '</div>';
  }
}
// =========================================================
// SITE SWITCHER MODAL
// =========================================================
function switchSiteModal() {
  const list = document.getElementById('siteSwitchList');
  if (!list) return;
  list.innerHTML = state.sites.map(s =>
    '<button class="ovg-btn ovg-btn-secondary" style="width:100%;text-align:right;justify-content:space-between;' +
    (state.currentSite && state.currentSite.id === s.id ? 'border-color:var(--ovg-primary);color:var(--ovg-primary);' : '') +
    '" onclick="pickSite(\'' + s.site_key + '\')">' +
      '<span style="flex:1;text-align:right;">' + ovgEsc(s.name) + '</span>' +
      '<span style="font-size:11px;opacity:.7;">' + (s.total || 0) + ' زيارة</span>' +
    '</button>'
  ).join('') || '<div class="dt-empty">لا توجد مواقع</div>';
  ovgOpenModal('siteSwitchModal');
}
function pickSite(key) {
  ovgCloseModal('siteSwitchModal');
  openSite(key);
}

// =========================================================
// REPORT RENDERERS
// =========================================================
function _reportTable(headers, rows) {
  const body = document.getElementById('reportBody');
  if (!rows.length) {
    body.innerHTML = '<div class="dt-empty"><div class="icon">📭</div>لا توجد بيانات</div>';
    return;
  }
  body.innerHTML =
    '<div class="dt-wrap"><div class="dt-scroll"><table class="ovg-table"><thead><tr>' +
    headers.map(h => '<th>' + h + '</th>').join('') +
    '</tr></thead><tbody>' +
    rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div></div>';
}

function _reportBars(data, valKey, labelKey, extraFn) {
  const body = document.getElementById('reportBody');
  if (!data.length) {
    body.innerHTML = '<div class="dt-empty"><div class="icon">📭</div>لا توجد بيانات</div>';
    return;
  }
  const max = Math.max.apply(null, data.map(d => d[valKey] || 0).concat([1]));
  body.innerHTML = '<div class="ovg-card ovg-card-pad">' +
    data.map(d => {
      const pct = ((d[valKey] || 0) / max * 100).toFixed(1);
      const color = (d.quality || 0) >= 80 ? '#10B981' : (d.quality || 0) >= 50 ? '#F59E0B' : '#F43F5E';
      return '<div class="bar-row">' +
        '<div class="bar-label">' + ovgEsc(String(d[labelKey] || 'Unknown')) + '</div>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:linear-gradient(90deg,' + color + ',' + color + 'aa);"></div></div>' +
        '<div class="bar-val">' + (extraFn ? extraFn(d) : d[valKey]) + '</div>' +
      '</div>';
    }).join('') + '</div>';
}

function renderZonesReport(data) {
  _reportTable(
    ['Zone ID', 'الإجمالي', 'صالح', 'بوت', 'نسبة البوت', 'التقييم'],
    data.map(z => [
      '<strong>' + ovgEsc(z.zone) + '</strong>',
      z.total,
      '<span style="color:#059669;font-weight:700;">' + z.valid + '</span>',
      '<span style="color:#E11D48;font-weight:700;">' + z.invalid + '</span>',
      '<span style="font-weight:800;color:' + (z.bot_rate > 30 ? '#E11D48' : z.bot_rate > 15 ? '#D97706' : '#059669') + ';">' + z.bot_rate + '%</span>',
      '<span class="ovg-badge ovg-badge-' + (z.grade === 'A' ? 'valid' : z.grade === 'F' ? 'invalid' : 'suspicious') + '">' + z.grade + '</span>',
    ])
  );
}

function renderCountriesReport(data) {
  _reportBars(data, 'total', 'country', d => d.total + ' · ' + d.quality + '%');
}

function renderSimpleReport(kind, data) {
  _reportBars(data, 'total', 'key', d => d.total + ' · ' + d.quality + '%');
}

function renderTimezonesReport(data) {
  _reportTable(
    ['Timezone', 'الإجمالي', 'بوت'],
    data.map(t => [
      ovgEsc(t.timezone),
      t.total,
      '<span style="color:#E11D48;font-weight:700;">' + t.invalid + '</span>',
    ])
  );
}

function renderFingerprintsReport(data) {
  if (!data.length) {
    document.getElementById('reportBody').innerHTML = '<div class="dt-empty"><div class="icon">🧬</div>لا توجد بصمات مكررة</div>';
    return;
  }
  _reportTable(
    ['Canvas Hash', 'الإجمالي', 'IPs فريدة', 'بوت', 'الخطورة'],
    data.map(f => [
      '<code style="font-family:var(--ovg-mono);font-size:11px;">' + ovgEsc(f.canvas_hash) + '</code>',
      f.total,
      f.unique_ips,
      '<span style="color:#E11D48;font-weight:700;">' + f.invalid + '</span>',
      '<span class="ovg-badge ' + (f.risk === 'high' ? 'ovg-badge-invalid' : f.risk === 'medium' ? 'ovg-badge-suspicious' : 'ovg-badge-info') + '">' + f.risk + '</span>',
    ])
  );
}

function renderIpsReport(data) {
  if (!data.length) {
    document.getElementById('reportBody').innerHTML = '<div class="dt-empty"><div class="icon">🔗</div>لا توجد IPs مكررة</div>';
    return;
  }
  _reportTable(
    ['IP', 'الدولة', 'ASN', 'الإجمالي', 'بصمات فريدة', 'بوت'],
    data.map(ip => [
      '<code style="font-family:var(--ovg-mono);font-size:11px;">' + ovgEsc(ip.ip) + '</code>',
      ovgEsc(ip.country),
      ovgEsc(ip.asn),
      ip.total,
      ip.unique_fps,
      '<span style="color:#E11D48;font-weight:700;">' + ip.invalid + '</span>',
    ])
  );
}

function renderAsnReport(data) {
  _reportTable(
    ['ASN', 'الإجمالي', 'بوت', 'نسبة البوت', 'ISPs'],
    data.map(a => [
      '<strong>' + ovgEsc(a.asn) + '</strong>',
      a.total,
      '<span style="color:#E11D48;font-weight:700;">' + a.invalid + '</span>',
      '<span style="font-weight:800;color:' + (a.bot_rate > 50 ? '#E11D48' : a.bot_rate > 20 ? '#D97706' : '#059669') + ';">' + a.bot_rate + '%</span>',
      a.isps,
    ])
  );
}

function renderWebrtcReport(data) {
  if (!data.length) {
    document.getElementById('reportBody').innerHTML = '<div class="dt-empty"><div class="icon">🛡️</div>لا توجد تسريبات WebRTC</div>';
    return;
  }
  _reportTable(
    ['الوقت', 'IP الظاهر', 'WebRTC IP', 'الدولة', 'الحكم', ''],
    data.slice(0, 200).map(w => [
      w.time ? new Date(w.time).toLocaleString('en-GB', { hour12: false }) : '—',
      '<code style="font-family:var(--ovg-mono);font-size:11px;">' + ovgEsc(w.ip) + '</code>',
      '<code style="font-family:var(--ovg-mono);font-size:11px;color:#E11D48;">' + ovgEsc(w.webrtc) + '</code>',
      ovgEsc(w.country),
      '<span class="ovg-badge ovg-badge-' + w.verdict + '">' + w.verdict + '</span>',
      '<a href="/visits/' + w.id + '" class="ovg-btn ovg-btn-ghost ovg-btn-sm">عرض</a>',
    ])
  );
}

function renderVpnReport(data) {
  const body = document.getElementById('reportBody');
  body.innerHTML =
    '<div class="kpi-grid">' +
      '<div class="kpi-card"><div class="kpi-label">إجمالي الزيارات</div><div class="kpi-value">' + data.total + '</div></div>' +
      '<div class="kpi-card"><div class="kpi-label" style="color:#E11D48;">VPN/Proxy</div><div class="kpi-value" style="color:#E11D48;">' + data.vpn + '</div><div class="kpi-delta down">' + data.vpn_rate + '% من الإجمالي</div></div>' +
      '<div class="kpi-card"><div class="kpi-label" style="color:#D97706;">Datacenter</div><div class="kpi-value" style="color:#D97706;">' + data.hosting + '</div><div class="kpi-delta down">' + data.hosting_rate + '% من الإجمالي</div></div>' +
    '</div>';
}

function renderHourlyReport(data) {
  const body = document.getElementById('reportBody');
  const flat = [];
  for (var d = 0; d < data.grid.length; d++) for (var h = 0; h < 24; h++) flat.push(data.grid[d][h]);
  const max = Math.max.apply(null, flat.concat([1]));
  let html = '<div class="ovg-card ovg-card-pad"><h3 style="margin-bottom:12px;">خريطة حرارية — 7 أيام × 24 ساعة</h3>';
  html += '<div class="heat-wrap"><div class="heat-grid">';
  html += '<div></div>';
  for (let h = 0; h < 24; h++) html += '<div class="heat-head">' + h + '</div>';
  for (let d = 0; d < 7; d++) {
    html += '<div class="heat-day">' + ovgEsc(data.days[d]) + '</div>';
    for (let h = 0; h < 24; h++) {
      const val = data.grid[d][h];
      const intensity = val / max;
      const color = intensity === 0 ? 'var(--ovg-bg)' : 'rgba(99,102,241,' + (0.15 + intensity * 0.85) + ')';
      html += '<div class="heat-cell" style="background:' + color + ';" title="' + data.days[d] + ' ' + h + ':00 → ' + val + ' زيارة"></div>';
    }
  }
  html += '</div></div></div>';
  body.innerHTML = html;
}

function renderAnomaliesReport(data) {
  const body = document.getElementById('reportBody');
  if (!data.days.length) {
    body.innerHTML = '<div class="ovg-card ovg-card-pad"><h3 style="margin-bottom:8px;">✅ لا توجد أيام شاذة</h3><p class="ovg-text-muted" style="font-size:13px;">متوسط نسبة البوتات: ' + data.average_rate + '%</p></div>';
    return;
  }
  let html = '<div class="ovg-card ovg-card-pad" style="margin-bottom:16px;"><strong>متوسط نسبة البوتات:</strong> ' + data.average_rate + '%</div>';
  html += '<div class="dt-wrap"><div class="dt-scroll"><table class="ovg-table"><thead><tr>';
  html += '<th>التاريخ</th><th>الإجمالي</th><th>بوت</th><th>النسبة</th><th>المتوسط</th></tr></thead><tbody>';
  for (let i = 0; i < data.days.length; i++) {
    const d = data.days[i];
    html += '<tr>' +
      '<td>' + ovgEsc(d.date) + '</td>' +
      '<td>' + d.total + '</td>' +
      '<td style="color:#E11D48;font-weight:700;">' + d.invalid + '</td>' +
      '<td style="font-weight:800;color:#E11D48;">' + d.rate + '%</td>' +
      '<td class="ovg-text-dim">' + d.avg_rate + '%</td>' +
    '</tr>';
  }
  html += '</tbody></table></div></div>';
  body.innerHTML = html;
}

// =========================================================
// COMMAND PALETTE
// =========================================================
// =========================================================
// COMMAND PALETTE
// =========================================================
function openCmdPalette() {
  document.getElementById('cmdPalette').classList.add('open');
  const inp = document.getElementById('cmdInput');
  inp.value = '';
  setTimeout(() => inp.focus(), 50);
  cmdSearch('');
}
function closeCmdPalette() {
  document.getElementById('cmdPalette').classList.remove('open');
}
document.addEventListener('keydown', function (e) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    openCmdPalette();
  }
  if (e.key === 'Escape') { closeCmdPalette(); ovgCloseModal('siteModal'); ovgCloseModal('createdModal'); ovgCloseModal('filterModal'); ovgCloseModal('segmentModal'); ovgCloseModal('siteSwitchModal'); }
});
document.getElementById('cmdPalette').addEventListener('click', function (e) {
  if (e.target === this) closeCmdPalette();
});

const CMD_COMMANDS = [
  { icon: '📊', label: 'المواقع', action: () => navTo('sites') },
  { icon: '🏠', label: 'النظرة العامة', action: () => navTo('overview') },
  { icon: '📋', label: 'كل الزيارات', action: () => navTo('visits') },
  { icon: '📈', label: 'التقارير', action: () => navTo('reports') },
  { icon: '🔧', label: 'كود التتبع', action: () => navTo('tracker') },
  { icon: '⚙️', label: 'الإعدادات', action: () => navTo('settings') },
  { icon: '🌙', label: 'تبديل الوضع الليلي', action: () => toggleTheme() },
  { icon: '←', label: 'تسجيل الخروج', action: () => doLogout() },
];

function cmdSearch(q) {
  q = (q || '').toLowerCase().trim();
  const matched = CMD_COMMANDS.filter(c => c.label.toLowerCase().includes(q));
  state.cmdResults = matched;
  state.cmdActiveIdx = 0;
  const box = document.getElementById('cmdResults');
  if (!matched.length) {
    box.innerHTML = '<div class="cmd-empty">لا توجد نتائج</div>';
    return;
  }
  box.innerHTML = matched.map((c, i) =>
    '<div class="cmd-item' + (i === 0 ? ' active' : '') + '" data-idx="' + i + '" onclick="runCmd(' + i + ')">' +
      '<span class="cmd-icon">' + c.icon + '</span>' +
      '<span class="cmd-label">' + ovgEsc(c.label) + '</span>' +
    '</div>'
  ).join('');
}

function cmdKeydown(e) {
  const items = document.querySelectorAll('#cmdResults .cmd-item');
  if (!items.length) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    state.cmdActiveIdx = (state.cmdActiveIdx + 1) % items.length;
    items.forEach((x, i) => x.classList.toggle('active', i === state.cmdActiveIdx));
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    state.cmdActiveIdx = (state.cmdActiveIdx - 1 + items.length) % items.length;
    items.forEach((x, i) => x.classList.toggle('active', i === state.cmdActiveIdx));
  } else if (e.key === 'Enter') {
    e.preventDefault();
    runCmd(state.cmdActiveIdx);
  }
}

function runCmd(idx) {
  const c = state.cmdResults[idx];
  if (!c) return;
  closeCmdPalette();
  c.action();
}

// =========================================================
// POLLING (live)
// =========================================================
setInterval(() => {
  if (state.view === 'overview' && state.currentSite) loadOverview();
}, 15000);

// =========================================================
// BOOT
// =========================================================
init();
</script>
</body>
</html>
"""
)

# =========================================================
# ASSEMBLY
# =========================================================
DASHBOARD_HTML = (
    DASHBOARD_HTML_PART1 + DASHBOARD_HTML_PART2 +
    DASHBOARD_HTML_PART3 + DASHBOARD_HTML_PART4 +
    DASHBOARD_HTML_PART5 + DASHBOARD_HTML_PART6 +
    DASHBOARD_HTML_JS + DASHBOARD_HTML_JS_LOGIC
)

# =========================================================
# VISIT DETAIL PAGE (/visits/{id})
# =========================================================
VISIT_DETAIL_HTML = (
r"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OVG · تفاصيل الزيارة</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<script>(function(){try{if(localStorage.getItem('ovg-theme')==='dark')document.documentElement.classList.add('dark');}catch(e){}})();</script>
<style>""" + DESIGN_SYSTEM_CSS + r"""

body { padding: 0; }
.detail-wrap { max-width: 1200px; margin: 0 auto; padding: 24px; position: relative; z-index: 1; }
.detail-topbar {
  display: flex; justify-content: space-between; align-items: center;
  gap: 12px; margin-bottom: 24px; flex-wrap: wrap;
}
.back-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 8px 14px; border-radius: 10px;
  border: 1px solid var(--ovg-border); background: var(--ovg-card);
  color: var(--ovg-text); font-family: inherit; font-size: 13px;
  font-weight: 700; cursor: pointer; transition: all .15s;
}
.back-btn:hover { border-color: var(--ovg-primary); color: var(--ovg-primary); }
.detail-grid { display: grid; grid-template-columns: 1fr; gap: 20px; }
@media (min-width: 1024px) {
  .detail-grid { grid-template-columns: 1.5fr 1fr; }
}
.summary-card {
  background: var(--ovg-card); border: 1px solid var(--ovg-border);
  border-radius: 20px; padding: 24px;
  display: flex; gap: 24px; align-items: center;
  margin-bottom: 20px;
}
.score-ring {
  width: 100px; height: 100px; position: relative; flex-shrink: 0;
}
.score-ring svg { transform: rotate(-90deg); }
.score-ring .score-text {
  position: absolute; inset: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.score-ring .score-num {
  font-size: 28px; font-weight: 800;
  font-family: var(--ovg-mono); font-variant-numeric: tabular-nums;
}
.score-ring .score-lbl {
  font-size: 9px; color: var(--ovg-text-dim); font-weight: 700;
  text-transform: uppercase;
}
.summary-info { flex: 1; min-width: 0; }
.summary-ip {
  font-family: var(--ovg-mono); font-size: 24px;
  font-weight: 800; color: var(--ovg-text);
  margin-bottom: 6px; word-break: break-all;
}
.summary-meta { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }

.section-card {
  background: var(--ovg-card); border: 1px solid var(--ovg-border);
  border-radius: 16px; padding: 20px; margin-bottom: 16px;
}
.section-title {
  font-size: 14px; font-weight: 800; margin-bottom: 14px;
  display: flex; align-items: center; gap: 8px;
}
.breakdown-list { display: flex; flex-direction: column; gap: 6px; }
.breakdown-item {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px; border-radius: 10px;
  background: var(--ovg-bg); font-size: 12px;
}
.breakdown-item .rule-icon { font-size: 16px; flex-shrink: 0; }
.breakdown-item .rule-text { flex: 1; font-weight: 600; }
.breakdown-item .rule-weight {
  font-family: var(--ovg-mono); font-weight: 700;
  color: var(--ovg-invalid); font-size: 13px;
}
.breakdown-total {
  margin-top: 12px; padding: 12px;
  background: rgba(99,102,241,.06); border-radius: 10px;
  display: flex; justify-content: space-between; align-items: center;
  font-weight: 800;
}
.breakdown-total .total-val {
  font-family: var(--ovg-mono); font-size: 18px; color: var(--ovg-primary);
}

.kv-list { display: flex; flex-direction: column; gap: 8px; }
.kv-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 8px 0; border-bottom: 1px dashed var(--ovg-border); font-size: 13px;
}
.kv-row:last-child { border-bottom: none; }
.kv-key { color: var(--ovg-text-muted); font-weight: 600; }
.kv-val {
  font-family: var(--ovg-mono); color: var(--ovg-text);
  font-weight: 700; text-align: left; word-break: break-word;
  max-width: 60%;
}

.action-btns { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.action-btn {
  padding: 10px 12px; border-radius: 10px; border: none;
  font-family: inherit; font-size: 12px; font-weight: 700;
  cursor: pointer; transition: all .15s;
  display: flex; align-items: center; justify-content: center; gap: 6px;
}
.action-btn.valid { background: rgba(16,185,129,.12); color: #047857; }
.action-btn.valid:hover { background: rgba(16,185,129,.2); }
.action-btn.invalid { background: rgba(244,63,94,.12); color: #BE123C; }
.action-btn.invalid:hover { background: rgba(244,63,94,.2); }
.action-btn.neutral {
  background: var(--ovg-bg); color: var(--ovg-text); border: 1px solid var(--ovg-border);
}
.action-btn.neutral:hover { border-color: var(--ovg-primary); color: var(--ovg-primary); }

.note-area {
  width: 100%; min-height: 70px; padding: 10px;
  border-radius: 10px; border: 1px solid var(--ovg-border);
  background: var(--ovg-bg); color: var(--ovg-text);
  font-family: inherit; font-size: 12px; resize: vertical;
}
.note-area:focus { outline: none; border-color: var(--ovg-primary); }

.tag-chip {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 4px 10px; border-radius: 999px;
  background: rgba(99,102,241,.12); color: var(--ovg-primary);
  font-size: 11px; font-weight: 700;
}
.similar-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 10px 12px; border-radius: 10px; background: var(--ovg-bg);
  font-size: 12px; margin-bottom: 6px;
}
.similar-item .num {
  font-family: var(--ovg-mono); font-weight: 800;
  color: var(--ovg-primary); font-size: 15px;
}
.loading-center {
  text-align: center; padding: 80px 20px;
  color: var(--ovg-text-muted);
}
</style>
</head>
<body>
<div class="ovg-ambient"></div>
<div class="detail-wrap">
  <div class="detail-topbar">
    <button class="back-btn" onclick="history.length>1?history.back():location.href='/dashboard'">
      <span>←</span> رجوع
    </button>
    <div style="display:flex;gap:8px;">
      <button class="back-btn" onclick="copyShareLink()">🔗 نسخ الرابط</button>
      <button class="back-btn" onclick="toggleTheme()" id="themeBtn">🌙</button>
    </div>
  </div>

  <div id="detailBody">
    <div class="loading-center">
      <div class="ovg-skeleton" style="height:100px;border-radius:16px;margin-bottom:16px;max-width:500px;margin-left:auto;margin-right:auto;"></div>
      <div class="ovg-skeleton" style="height:200px;border-radius:16px;max-width:800px;margin:0 auto;"></div>
    </div>
  </div>
</div>

<div class="ovg-toasts"></div>

<script>
var VISIT_ID = window.location.pathname.split('/').pop();

function toggleTheme() {
  var isDark = document.documentElement.classList.toggle('dark');
  try { localStorage.setItem('ovg-theme', isDark ? 'dark' : 'light'); } catch(e){}
  document.getElementById('themeBtn').textContent = isDark ? '☀️' : '🌙';
}
(function() {
  if (document.documentElement.classList.contains('dark')) {
    document.getElementById('themeBtn').textContent = '☀️';
  }
})();

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
    return { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c];
  });
}

async function loadDetail() {
  try {
    var r = await fetch('/api/visits/' + VISIT_ID);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    var v = await r.json();
    renderDetail(v);
  } catch (e) {
    document.getElementById('detailBody').innerHTML =
      '<div class="loading-center" style="color:#BE123C;">❌ الزيارة غير موجودة أو مش بتاعتك</div>';
  }
}

function renderDetail(v) {
  var verdictColor = v.verdict === 'valid' ? '#10B981' :
                     v.verdict === 'invalid' ? '#F43F5E' : '#F59E0B';
  var scorePct = Math.min(100, (v.score / 150) * 100);
  var circumference = 2 * Math.PI * 42;
  var dashOffset = circumference * (1 - scorePct / 100);

  var breakdownHtml = '';
  var bd = v.breakdown || [];
  if (bd.length) {
    breakdownHtml = '<div class="breakdown-list">' +
      bd.map(function(b) {
        return '<div class="breakdown-item">' +
          '<span class="rule-icon">⚠️</span>' +
          '<span class="rule-text">' + esc(b.rule) + '</span>' +
          '<span class="rule-weight">+' + b.weight + '</span>' +
        '</div>';
      }).join('') +
    '</div>';
  } else {
    breakdownHtml = '<p style="font-size:13px;color:#059669;text-align:center;padding:20px;">✅ لا توجد مؤشرات خطر — زيارة سليمة تماماً</p>';
  }

  var tagsHtml = (v.tags || []).map(function(t) {
    return '<span class="tag-chip">🏷️ ' + esc(t) + '</span>';
  }).join(' ') || '<span class="ovg-text-dim" style="font-size:12px;">لا توجد tags</span>';

  var html =
    // Summary
    '<div class="summary-card ovg-fade-up">' +
      '<div class="score-ring">' +
        '<svg width="100" height="100" viewBox="0 0 100 100">' +
          '<circle cx="50" cy="50" r="42" fill="none" stroke="rgba(148,163,184,.2)" stroke-width="8"/>' +
          '<circle cx="50" cy="50" r="42" fill="none" stroke="' + verdictColor + '" stroke-width="8" stroke-linecap="round" stroke-dasharray="' + circumference + '" stroke-dashoffset="' + dashOffset + '" style="transition:stroke-dashoffset .8s ease;"/>' +
        '</svg>' +
        '<div class="score-text">' +
          '<div class="score-num" style="color:' + verdictColor + ';">' + v.score + '</div>' +
          '<div class="score-lbl">SCORE</div>' +
        '</div>' +
      '</div>' +
      '<div class="summary-info">' +
        '<div class="summary-ip">' + esc(v.ip) + '</div>' +
        '<div class="summary-meta">' +
          '<span class="ovg-badge ovg-badge-' + v.verdict + '">' + esc(v.verdict) + '</span>' +
          '<span style="font-size:12px;color:var(--ovg-text-muted);">🌍 ' + esc(v.country) + '</span>' +
          '<span style="font-size:12px;color:var(--ovg-text-muted);">🎯 ' + esc(v.zone) + '</span>' +
          '<span style="font-size:12px;color:var(--ovg-text-muted);">🕒 ' + (v.timestamp ? new Date(v.timestamp).toLocaleString('en-GB', {hour12:false}) : '—') + '</span>' +
        '</div>' +
        '<div style="margin-top:12px;">' + tagsHtml + '</div>' +
      '</div>' +
    '</div>' +

    '<div class="detail-grid">' +
      // LEFT COLUMN
      '<div>' +
        // Risk Breakdown
        '<div class="section-card ovg-fade-up" style="--i:1;">' +
          '<div class="section-title">🔍 تفصيل المخاطر</div>' +
          breakdownHtml +
          '<div class="breakdown-total">' +
            '<span>المجموع (بحد أقصى 150)</span>' +
            '<span class="total-val">' + v.score + '</span>' +
          '</div>' +
        '</div>' +

        // Note
        '<div class="section-card ovg-fade-up" style="--i:2;">' +
          '<div class="section-title">📝 ملاحظة شخصية</div>' +
          '<textarea class="note-area" id="noteInput" placeholder="أضف ملاحظة على الزيارة...">' + esc(v.note || '') + '</textarea>' +
          '<button class="ovg-btn ovg-btn-primary ovg-btn-sm" style="margin-top:8px;" onclick="saveNote()">💾 حفظ الملاحظة</button>' +
        '</div>' +

        // User Agent
        '<div class="section-card ovg-fade-up" style="--i:3;">' +
          '<div class="section-title">🧾 User Agent</div>' +
          '<pre style="font-family:var(--ovg-mono);font-size:11px;background:var(--ovg-bg);padding:12px;border-radius:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:var(--ovg-text-muted);margin:0;">' + esc(v.user_agent || '—') + '</pre>' +
        '</div>' +
      '</div>' +

      // RIGHT COLUMN
      '<div>' +
        // Actions
        '<div class="section-card ovg-fade-up" style="--i:1;">' +
          '<div class="section-title">⚡ إجراءات سريعة</div>' +
          '<div class="action-btns">' +
            '<button class="action-btn valid" onclick="setVerdict(\'valid\')">✓ تعليم كصالح</button>' +
            '<button class="action-btn invalid" onclick="setVerdict(\'invalid\')">✗ تعليم كبوت</button>' +
            '<button class="action-btn neutral" onclick="addTagPrompt()">🏷️ إضافة Tag</button>' +
            '<button class="action-btn neutral" onclick="copyIp()">📋 نسخ IP</button>' +
          '</div>' +
        '</div>' +

        // Identity
        '<div class="section-card ovg-fade-up" style="--i:2;">' +
          '<div class="section-title">🧬 البصمة</div>' +
          '<div class="kv-list">' +
            '<div class="kv-row"><span class="kv-key">Canvas Hash</span><span class="kv-val">' + esc(v.canvas_hash) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">Timezone</span><span class="kv-val">' + esc(v.timezone) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">Hardware</span><span class="kv-val">' + esc(v.hardware) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">Language</span><span class="kv-val">' + esc(v.language) + '</span></div>' +
          '</div>' +
        '</div>' +

        // Network
        '<div class="section-card ovg-fade-up" style="--i:3;">' +
          '<div class="section-title">🌐 الشبكة</div>' +
          '<div class="kv-list">' +
            '<div class="kv-row"><span class="kv-key">ISP</span><span class="kv-val">' + esc(v.isp) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">ASN</span><span class="kv-val">' + esc(v.asn) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">Connection</span><span class="kv-val">' + esc(v.connection_type) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">VPN/Proxy</span><span class="kv-val" style="color:' + (v.is_vpn ? '#E11D48' : '#059669') + ';">' + (v.is_vpn ? 'YES' : 'NO') + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">WebRTC</span><span class="kv-val">' + esc(v.webrtc || 'None') + '</span></div>' +
          '</div>' +
        '</div>' +

        // Device
        '<div class="section-card ovg-fade-up" style="--i:4;">' +
          '<div class="section-title">💻 الجهاز</div>' +
          '<div class="kv-list">' +
            '<div class="kv-row"><span class="kv-key">OS</span><span class="kv-val">' + esc(v.os) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">Browser</span><span class="kv-val">' + esc(v.browser) + '</span></div>' +
            '<div class="kv-row"><span class="kv-key">Device</span><span class="kv-val">' + esc(v.device) + '</span></div>' +
          '</div>' +
        '</div>' +

        // Similar
        '<div class="section-card ovg-fade-up" style="--i:5;">' +
          '<div class="section-title">🔗 زيارات مشابهة</div>' +
          '<div class="similar-item"><span>من نفس الـ IP</span><span class="num">' + (v.similar?.same_ip || 0) + '</span></div>' +
          '<div class="similar-item"><span>بنفس البصمة</span><span class="num">' + (v.similar?.same_fp || 0) + '</span></div>' +
          '<div class="similar-item"><span>من نفس الـ ASN</span><span class="num">' + (v.similar?.same_asn || 0) + '</span></div>' +
        '</div>' +
      '</div>' +
    '</div>';

  document.getElementById('detailBody').innerHTML = html;
}

async function setVerdict(verdict) {
  try {
    var r = await fetch('/api/visits/' + VISIT_ID, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict: verdict })
    });
    if (r.ok) {
      ovgToast('تم التحديث ✓', 'success');
      loadDetail();
    } else {
      ovgToast('فشل', 'error');
    }
  } catch (e) { ovgToast('خطأ في الاتصال', 'error'); }
}

async function saveNote() {
  var note = document.getElementById('noteInput').value.trim();
  try {
    var r = await fetch('/api/visits/' + VISIT_ID, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: note })
    });
    if (r.ok) ovgToast('تم حفظ الملاحظة ✓', 'success');
    else ovgToast('فشل', 'error');
  } catch (e) { ovgToast('خطأ', 'error'); }
}

async function addTagPrompt() {
  var tag = prompt('اسم الـ Tag:');
  if (!tag) return;
  try {
    var r = await fetch('/api/visits/' + VISIT_ID);
    if (!r.ok) return;
    var v = await r.json();
    var tags = (v.tags || []).concat([tag.trim()]);
    var r2 = await fetch('/api/visits/' + VISIT_ID, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: tags })
    });
    if (r2.ok) { ovgToast('تمت الإضافة ✓', 'success'); loadDetail(); }
  } catch (e) { ovgToast('فشل', 'error'); }
}

function copyIp() {
  var ipEl = document.querySelector('.summary-ip');
  if (ipEl) {
    navigator.clipboard.writeText(ipEl.textContent.trim()).then(function() {
      ovgToast('تم نسخ IP ✓', 'success');
    });
  }
}

function copyShareLink() {
  navigator.clipboard.writeText(window.location.href).then(function() {
    ovgToast('تم نسخ الرابط ✓', 'success');
  }).catch(function() { ovgToast('فشل النسخ', 'error'); });
}

function ovgToast(msg, type) {
  type = type || 'info';
  var host = document.querySelector('.ovg-toasts');
  if (!host) return;
  var el = document.createElement('div');
  el.className = 'ovg-toast ' + type;
  var icons = { success: '✓', error: '✗', warning: '⚠️', info: 'ℹ️' };
  el.innerHTML = '<span>' + (icons[type] || '') + '</span><span>' + esc(msg) + '</span>';
  host.appendChild(el);
  setTimeout(function() {
    el.classList.add('out');
    setTimeout(function() { el.remove(); }, 260);
  }, 3000);
}

loadDetail();
</script>
</body>
</html>"""
)

# =========================================================
# HTML ROUTES
# =========================================================
@app.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(LOGIN_HTML)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, key: str = None, db: Session = Depends(get_db)):
    if key and DASHBOARD_KEY and key == DASHBOARD_KEY:
        first = db.query(UserModel).first()
        if first:
            resp = RedirectResponse("/dashboard", status_code=302)
            resp.set_cookie(SESSION_COOKIE, make_token(first.id), httponly=True,
                            samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/visits/{visit_id}", response_class=HTMLResponse)
def visit_detail_page(visit_id: int, request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    v = db.query(VisitModel).filter(VisitModel.id == visit_id).first()
    if not v:
        return HTMLResponse(
            "<html><body style='font-family:sans-serif;text-align:center;padding:80px;'>"
            "<h2>404 — الزيارة مش موجودة</h2>"
            "<a href='/dashboard' style='color:#6366F1;'>← رجوع للداشبورد</a>"
            "</body></html>",
            status_code=404,
        )
    return HTMLResponse(VISIT_DETAIL_HTML)


# =========================================================
# ERROR HANDLERS
# =========================================================
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return HTMLResponse(
        "<html><body style='font-family:sans-serif;text-align:center;padding:80px;background:#F8FAFC;'>"
        "<h1 style='color:#6366F1;font-size:64px;margin:0;'>404</h1>"
        "<p style='color:#475569;font-size:16px;'>الصفحة غير موجودة</p>"
        "<a href='/dashboard' style='color:#6366F1;font-weight:bold;'>← رجوع للداشبورد</a>"
        "</body></html>",
        status_code=404,
    )


# =========================================================
# STARTUP BANNER (printed at import)
# =========================================================
if __name__ != "__main__":
    try:
        print("=" * 62)
        print(f"🛡️  OVG Tracker  ·  v{APP_VERSION}  ·  Phase 1")
        print(f"    Database : {DATABASE_URL}")
        print(f"    Sites    : {MAX_SITES_PER_USER} max per user")
        print(f"    Tracker  : {'URL set' if PUBLIC_URL else 'auto-detected from request'}")
        print("    Endpoints:")
        print("      /               → Login / Signup")
        print("      /dashboard      → Main dashboard")
        print("      /visits/{id}    → Visit detail page")
        print("      /api/*          → REST API")
        print("      /health         → Health check")
        print("      /docs           → API docs (FastAPI auto)")
        print("=" * 62)
    except Exception:
        pass


# =========================================================
# LOCAL DEV ENTRYPOINT
# =========================================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)