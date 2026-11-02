"""
OVG Tracker — Session 4.0.0 (Ultimate Edition: GeoIP + Advanced Reports + Honeypot)
Production-ready · No external auth libs · CSRF-safe · XSS-safe
"""
import hashlib
import hmac
import ipaddress
import os
import random
import re
import secrets
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

import httpx
import maxminddb
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String,
    case, create_engine, func,
)
from sqlalchemy.orm import Session, declarative_base, relationship, sessionmaker

# =========================================================
# CONFIG
# =========================================================
DATABASE_URL       = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
DASHBOARD_KEY      = os.getenv("OVG_DASHBOARD_KEY", "")
SECRET             = os.getenv("OVG_SECRET", secrets.token_hex(32))
ADMIN_USER         = os.getenv("OVG_ADMIN_USER", "")
ADMIN_PASS         = os.getenv("OVG_ADMIN_PASS", "")
PUBLIC_URL         = os.getenv("OVG_PUBLIC_URL", "").rstrip("/")
ALLOWED_ORIGINS    = [o.strip() for o in os.getenv("OVG_ORIGINS", "*").split(",") if o.strip()]
TRACK_RATE_PER_MIN = int(os.getenv("OVG_TRACK_RATE", "120"))
MAX_SITES_PER_USER = int(os.getenv("OVG_MAX_SITES", "20"))
SESSION_COOKIE     = "ovg_session"
SESSION_TTL        = 86400 * 7  # 7 days

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE  = re.compile(r"^[a-f0-9]{16}$")

# =========================================================
# GEOIP (MaxMind GeoLite2)
# =========================================================
_geoip_dir    = os.getenv("OVG_GEOIP_DIR", "/code")
_city_db_path = os.path.join(_geoip_dir, "GeoLite2-City.mmdb")
_asn_db_path  = os.path.join(_geoip_dir, "GeoLite2-ASN.mmdb")

city_reader = None
asn_reader  = None
try:
    if os.path.exists(_city_db_path):
        city_reader = maxminddb.open_database(_city_db_path)
        print(f"✅ Loaded GeoIP City DB")
    if os.path.exists(_asn_db_path):
        asn_reader = maxminddb.open_database(_asn_db_path)
        print(f"✅ Loaded GeoIP ASN DB")
except Exception as e:
    print(f"⚠️ Failed to load GeoIP databases: {e}")

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
    os = Column(String, default="Unknown")
    device = Column(String, default="Unknown")
    browser = Column(String, default="Unknown")
    country = Column(String, default="Unknown")
    isp = Column(String, default="Unknown")
    timezone = Column(String, default="Unknown")
    canvas_hash = Column(String, default="Unknown", index=True)
    hardware = Column(String, default="Unknown")
    connection_type = Column(String, default="Unknown")
    asn = Column(String, default="Unknown")
    is_vpn = Column(Boolean, default=False)
    webrtc_ip = Column(String, default="None")
    converted = Column(Boolean, default=False)
    conversion_value = Column(Float, default=0.0)

    __table_args__ = (
        Index("ix_visits_site_zone_verdict", "site_id", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
    )

Base.metadata.create_all(bind=engine)

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
app = FastAPI(title="OVG Tracker", version="4.0.0")

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
        if e is None: return None
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
            raise HTTPException(status_code=429, detail="محاولات كتير — جرب بعد شوية")

track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)
signup_limiter = WindowRateLimiter(max_req=10, window=300)
login_limiter = WindowRateLimiter(max_req=15, window=300)

def _is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False

def get_client_ip(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip")
    if cf and cf.strip(): return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for p in parts:
            if not _is_private_ip(p): return p
        if parts: return parts[0]
    xri = request.headers.get("x-real-ip")
    if xri and xri.strip(): return xri.strip()
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
        return {"country": "Local", "isp": "Local ISP", "type": "residential", "asn": "N/A", "security": {}}
    if city_reader is None:
        return {"country": "Unknown", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}}
    try:
        city = city_reader.get(ip) or {}
        asn  = (asn_reader.get(ip) if asn_reader else None) or {}
        country = (city.get("country", {}).get("names", {}).get("en") or "Unknown")
        asn_num = asn.get("autonomous_system_number")
        org     = asn.get("autonomous_system_organization") or "Unknown"
        dc_keywords = ("amazon", "aws", "google", "gcp", "digitalocean", "ovh", "hetzner", "linode", "vultr", "azure", "microsoft", "cloudflare", "oracle", "contabo", "choopa", "leaseweb", "m247", "hostinger", "godaddy", "namecheap", "scaleway", "alibaba", "tencent", "netcup", "upcloud")
        is_hosting = any(k in org.lower() for k in dc_keywords)
        return {
            "country": country,
            "isp": org,
            "type": "hosting" if is_hosting else "residential",
            "asn": f"AS{asn_num}" if asn_num else "Unknown",
            "security": {"vpn": is_hosting},
        }
    except Exception:
        return {"country": "Unknown", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}}

def parse_ua(ua: str):
    u = (ua or "").lower()
    device = "Mobile" if "mobi" in u else "Tablet" if ("tablet" in u or "ipad" in u) else "Desktop"
    if "windows nt" in u: os_name = "Windows"
    elif "mac os" in u or "macintosh" in u: os_name = "macOS"
    elif "android" in u: os_name = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u: os_name = "iOS"
    elif "linux" in u: os_name = "Linux"
    else: os_name = "Unknown"
    if "edg/" in u or "edge/" in u: browser = "Edge"
    elif "chrome" in u and "chromium" not in u: browser = "Chrome"
    elif "firefox" in u: browser = "Firefox"
    elif "safari" in u and "chrome" not in u: browser = "Safari"
    else: browser = "Unknown"
    return os_name, device, browser

def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v: return v[0]
    except Exception: pass
    return "unknown"

def new_site_key() -> str: return secrets.token_hex(8)

# =========================================================
# ANALYSIS ENGINE (with Honeypot)
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    score = 0
    evidence = []
    nav = data.get("nav") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    ua = str(nav.get("ua") or "").lower()
    sec = ip_info.get("security", {})

    # 1. Honeypot Check
    if data.get("_hp_filled") is True:
        score += 150
        evidence.append("🚨 Honeypot Triggered (Bot filled hidden field)")

    if nav.get("webdriver") is True:
        score += 80; evidence.append("WebDriver Flag")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90; evidence.append("Suspicious User-Agent")

    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        score += 50; evidence.append("OS Mismatch (Win)")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        score += 50; evidence.append("OS Mismatch (Mac)")

    if sec.get("vpn") is True:
        score += 70; evidence.append("VPN/Proxy Detected")
    if str(ip_info.get("type", "")).lower() == "hosting":
        score += 80; evidence.append("Datacenter/Hosting IP")

    webrtc = data.get("webrtc_ip")
    if webrtc and webrtc != "None" and not _is_private_ip(webrtc) and webrtc != data.get("client_ip"):
        score += 90; evidence.append(f"WebRTC Leak (Real IP: {webrtc})")

    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        score += 60; evidence.append("Missing Canvas FP")
    
    try: cores = int(fp.get("hardwareConcurrency") or 0)
    except: cores = 0
    if cores <= 1: score += 40; evidence.append(f"Low CPU ({cores})")

    tz = str(fp.get("timezone") or "").lower()
    country = ip_info.get("country", "Unknown")
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        score += 30; evidence.append("UTC/Unknown Timezone")
    elif country not in ("Unknown", "Local"):
        cmap = {"Egypt": ["cairo", "africa"], "US": ["america/"], "UK": ["london", "europe/london"], "SA": ["riyadh", "asia/riyadh"], "Italy": ["rome", "europe/rome"]}
        if country in cmap and not any(t in tz for t in cmap[country]):
            score += 60; evidence.append(f"Timezone Mismatch (IP:{country} vs TZ:{tz})")

    try: t_on_page = int(behavior.get("time_on_page_ms") or 0)
    except: t_on_page = 0
    if t_on_page < 1500: score += 40; evidence.append("Left too fast")
    try: mv = float(behavior.get("mouse_variance") or 0)
    except: mv = 0.0
    if events.get("mousemove", 0) > 10 and mv < 1.5:
        score += 50; evidence.append("Robotic Mouse")
    if t_on_page > 3000 and events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30; evidence.append("No Interaction (Zombie)")

    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        score += 60; evidence.append("Virtual Renderer")

    score = min(150, score)
    verdict = "invalid" if score >= 80 else "suspicious" if score >= 40 else "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

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
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    webrtc_ip: str = "None"
    site_key: str = ""
    _hp_filled: bool = False

# =========================================================
# AUTH ROUTES
# =========================================================
@app.post("/api/auth/signup")
def signup(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    signup_limiter.check(client_ip)
    username = payload.username.strip()
    password = payload.password
    if not USERNAME_RE.match(username): raise HTTPException(400, "اسم المستخدم غير صالح")
    if len(password) < 6: raise HTTPException(400, "كلمة المرور قصيرة")
    if db.query(UserModel).filter(UserModel.username == username).first(): raise HTTPException(400, "الاسم مستخدم")
    u = UserModel(username=username, password_hash=hash_password(password))
    db.add(u); db.commit(); db.refresh(u)
    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/login")
def login(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    login_limiter.check(client_ip)
    u = db.query(UserModel).filter(UserModel.username == payload.username.strip()).first()
    if not u or not verify_password(payload.password, u.password_hash): raise HTTPException(401, "بيانات خاطئة")
    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
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
    sites = db.query(SiteModel).filter(SiteModel.user_id == user.id).order_by(SiteModel.created_at.desc()).all()
    if not sites: return []
    ids = [s.id for s in sites]
    stats = db.query(
        VisitModel.site_id, func.count(VisitModel.id).label("total"),
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
            "total": int(st.total or 0) if st else 0, "valid": int(st.valid or 0) if st else 0,
            "invalid": int(st.invalid or 0) if st else 0,
            "last_visit": st.last.isoformat() if st and st.last else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        })
    return out

@app.post("/api/sites")
def create_site(payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    count = db.query(SiteModel).filter(SiteModel.user_id == user.id).count()
    if count >= MAX_SITES_PER_USER: raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_SITES_PER_USER})")
    name = payload.name.strip()
    if not name: raise HTTPException(400, "اسم الموقع مطلوب")
    site = SiteModel(user_id=user.id, name=name, domain=payload.domain.strip()[:253], site_key=new_site_key())
    db.add(site); db.commit(); db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}

@app.patch("/api/sites/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    site.name = payload.name.strip()[:100]
    site.domain = payload.domain.strip()[:253]
    db.commit()
    return {"ok": True}

@app.delete("/api/sites/{site_id}")
def delete_site(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    db.query(VisitModel).filter(VisitModel.site_id == site.id).delete()
    db.delete(site); db.commit()
    return {"ok": True}

@app.post("/api/sites/{site_id}/rotate-key")
def rotate_key(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    site.site_key = new_site_key(); db.commit()
    return {"site_key": site.site_key}

def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key: raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key, SiteModel.user_id == user.id).first()
    if not s: raise HTTPException(404, "الموقع غير موجود")
    return s

def _scoped_query(db, user, site_key):
    if site_key:
        s = _resolve_user_site(site_key, user, db)
        return db.query(VisitModel).filter(VisitModel.site_id == s.id)
    ids = [r.id for r in db.query(SiteModel.id).filter(SiteModel.user_id == user.id)]
    return db.query(VisitModel).filter(VisitModel.site_id.in_(ids)) if ids else db.query(VisitModel).filter(False)

def _visit_to_dict(v: VisitModel):
    return {
        "id": v.id, "time": v.timestamp.isoformat() + "Z" if v.timestamp else None,
        "zone": v.zone_id, "verdict": v.verdict, "score": v.score, "ip": v.ip,
        "country": v.country, "isp": v.isp, "asn": v.asn, "os": v.os, "device": v.device,
        "browser": v.browser, "timezone": v.timezone, "hardware": v.hardware,
        "conn_type": v.connection_type, "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip,
        "canvas": v.canvas_hash, "evidence": v.evidence or [],
    }

# =========================================================
# TRACKER CODE TEMPLATE (With Honeypot)
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
  var hpFilled = false;

  // 🕵️ Honeypot: حقل وهمي مخفي
  function setupHoneypot() {
    var hp = document.createElement('input');
    hp.type = 'text';
    hp.name = 'email_confirm';
    hp.id = 'ovg_hp_field';
    hp.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;';
    hp.autocomplete = 'off';
    document.body.appendChild(hp);
    
    // لو البوت ملأ الحقل ده، هنعرف
    setInterval(function() {
      if (hp.value && hp.value.length > 0) {
        hpFilled = true;
      }
    }, 1000);
  }
  
  if (document.body) setupHoneypot();
  else document.addEventListener('DOMContentLoaded', setupHoneypot);

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
      return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || p[0] === 127 || (p[0] === 169 && p[1] === 254);
    }
    return ip === '::1' || ip.indexOf('fe80') === 0 || ip.indexOf('fc') === 0 || ip.indexOf('fd') === 0;
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
        pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () {});
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
      site_key: SITE_KEY,
      _hp_filled: hpFilled,
      nav: {
        ua: navigator.userAgent,
        platform: navigator.platform || '',
        webdriver: navigator.webdriver === true
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
      }).catch(function (err) { console.error('[OVG Tracker] Send failed:', err); });
    });
  }

  setTimeout(send, SEND_DELAY_MS);
  window.addEventListener('beforeunload', function () { send(); });
})();
</script>"""

@app.get("/api/sites/{site_id}/tracker-code")
def get_tracker_code(site_id: int, request: Request, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    if not HEX_KEY_RE.match(site.site_key or ""):
        site.site_key = new_site_key(); db.commit()
    origin = safe_origin(request)
    endpoint = f"{origin}/api/track"
    code = (TRACKER_CODE_TEMPLATE.replace("__OVG_SITE_KEY__", site.site_key).replace("__OVG_ENDPOINT__", endpoint))
    return Response(content='{"code":' + _json_escape(code) + '}', media_type="application/json", headers={"Cache-Control": "no-store"})

def _json_escape(s: str) -> str:
    import json as _json
    return _json.dumps(s)

# =========================================================
# TRACK
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
        if s: site_id = s.id

    try: data = payload.model_dump()
    except AttributeError: data = payload.dict()
    
    data["client_ip"] = client_ip
    result = analyze_visit(data, ip_info)
    fp = data.get("fingerprint") or {}

    visit = VisitModel(
        site_id=site_id, ip=client_ip, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"],
        os=os_name, device=device, browser=browser,
        country=ip_info["country"], isp=ip_info["isp"],
        timezone=fp.get("timezone", "Unknown"),
        canvas_hash=str(fp.get("canvas_hash", "Unknown"))[:64],
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"], asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"),
        webrtc_ip=payload.webrtc_ip,
    )
    try:
        db.add(visit); db.commit()
    except Exception:
        db.rollback(); raise HTTPException(500, "DB write failed")
    return {"status": "success"}

# =========================================================
# STATS & ADVANCED VISITS
# =========================================================
@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    total = q.count()
    valid = q.filter(VisitModel.verdict == "valid").count()
    invalid = q.filter(VisitModel.verdict == "invalid").count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()
    recent = q.order_by(VisitModel.id.desc()).limit(15).all()
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": [_visit_to_dict(v) for v in recent]}

@app.get("/api/visits")
def list_visits(
    page: int = Query(1, ge=1), per_page: int = Query(50, ge=10, le=200),
    site: str = Query(None), verdict: str = Query(None), zone: str = Query(None),
    country: str = Query(None), device: str = Query(None), browser: str = Query(None),
    search: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    query = _scoped_query(db, user, site)
    if verdict: query = query.filter(VisitModel.verdict == verdict)
    if zone: query = query.filter(VisitModel.zone_id == zone)
    if country: query = query.filter(VisitModel.country == country)
    if device: query = query.filter(VisitModel.device == device)
    if browser: query = query.filter(VisitModel.browser == browser)
    if search:
        query = query.filter((VisitModel.ip.contains(search)) | (VisitModel.isp.contains(search)) | (VisitModel.asn.contains(search)))
    if from_date: query = query.filter(VisitModel.timestamp >= datetime.fromisoformat(from_date))
    if to_date: query = query.filter(VisitModel.timestamp <= datetime.fromisoformat(to_date + "T23:59:59"))

    total = query.count()
    items = query.order_by(VisitModel.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return {"total": total, "page": page, "pages": (total + per_page - 1) // per_page, "items": [_visit_to_dict(v) for v in items]}

# =========================================================
# REPORTS ENGINE
# =========================================================
@app.get("/api/reports/countries")
def rep_countries(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    rows = q.with_entities(VisitModel.country, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).group_by(VisitModel.country).order_by(func.count(VisitModel.id).desc()).all()
    return [{"label": r.country, "total": r.total, "invalid": int(r.invalid or 0)} for r in rows]

@app.get("/api/reports/devices")
def rep_devices(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    os_rows = q.with_entities(VisitModel.os, func.count(VisitModel.id)).group_by(VisitModel.os).all()
    br_rows = q.with_entities(VisitModel.browser, func.count(VisitModel.id)).group_by(VisitModel.browser).all()
    dev_rows = q.with_entities(VisitModel.device, func.count(VisitModel.id)).group_by(VisitModel.device).all()
    return {
        "os": [{"label": r[0], "count": r[1]} for r in os_rows],
        "browser": [{"label": r[0], "count": r[1]} for r in br_rows],
        "device": [{"label": r[0], "count": r[1]} for r in dev_rows]
    }

@app.get("/api/reports/fingerprints")
def rep_fingerprints(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    rows = q.with_entities(VisitModel.canvas_hash, func.count(VisitModel.id).label("total"), func.count(func.distinct(VisitModel.ip)).label("unique_ips")).filter(VisitModel.canvas_hash != "Unknown").group_by(VisitModel.canvas_hash).having(func.count(VisitModel.id) > 1).order_by(func.count(VisitModel.id).desc()).limit(50).all()
    return [{"fp": r.canvas_hash, "visits": r.total, "unique_ips": r.unique_ips, "suspicious": r.unique_ips > (r.total * 0.8)} for r in rows]

@app.get("/api/reports/hourly")
def rep_hourly(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    hour_expr = func.strftime("%H", VisitModel.timestamp) if "sqlite" in DATABASE_URL else func.extract("hour", VisitModel.timestamp)
    rows = q.with_entities(hour_expr.label("hour"), func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).group_by("hour").all()
    return {int(r.hour): {"total": r.total, "invalid": int(r.invalid or 0)} for r in rows}

@app.get("/api/reports/ips")
def rep_ips(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    rows = q.with_entities(VisitModel.ip, func.count(VisitModel.id).label("total"), func.max(VisitModel.verdict).label("max_verdict")).group_by(VisitModel.ip).having(func.count(VisitModel.id) > 2).order_by(func.count(VisitModel.id).desc()).limit(50).all()
    return [{"ip": r.ip, "visits": r.total, "verdict": r.max_verdict} for r in rows]

@app.get("/api/reports/asn")
def rep_asn(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    rows = q.with_entities(VisitModel.asn, VisitModel.isp, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).group_by(VisitModel.asn, VisitModel.isp).order_by(func.count(VisitModel.id).desc()).limit(30).all()
    return [{"asn": r.asn, "isp": r.isp, "total": r.total, "invalid": int(r.invalid or 0)} for r in rows]

@app.get("/api/reports/trend")
def rep_trend(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    since = datetime.utcnow() - timedelta(days=30)
    day_expr = func.strftime("%Y-%m-%d", VisitModel.timestamp) if "sqlite" in DATABASE_URL else func.date(VisitModel.timestamp)
    rows = q.filter(VisitModel.timestamp >= since).with_entities(day_expr.label("day"), func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).group_by("day").order_by("day").all()
    return [{"day": r.day, "total": r.total, "invalid": int(r.invalid or 0)} for r in rows]

@app.get("/api/reports/zones")
def rep_zones(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = _scoped_query(db, user, site)
    rows = q.with_entities(VisitModel.zone_id, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid")).group_by(VisitModel.zone_id).all()
    report = [{"zone": r.zone_id, "total": r.total, "bot_rate": round(int(r.invalid or 0)/r.total*100, 1) if r.total else 0} for r in rows]
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    for _ in range(50):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid" else random.randint(70, 100) if v == "invalid" else random.randint(40, 69))
        db.add(VisitModel(site_id=s.id, ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones), score=sc, verdict=v, evidence=["Mock Data"], country="US", isp="Mock ISP", connection_type="residential"))
    db.commit()
    return {"status": "ok"}

# =========================================================
# HEALTH & DEBUG
# =========================================================
@app.get("/health")
def health(): return {"status": "ok", "version": app.version}

@app.get("/debug/site/{site_key}")
def debug_site(site_key: str, db: Session = Depends(get_db)):
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key).first()
    if not s: return {"exists": False}
    return {"exists": True, "site_name": s.name}

# =========================================================
# LOGIN PAGE
# =========================================================
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG · تسجيل الدخول</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    body{font-family:'Cairo',sans-serif}
    .bg-mesh{background:radial-gradient(at 20% 20%, rgba(99,102,241,.45) 0px, transparent 50%),radial-gradient(at 80% 80%, rgba(168,85,247,.4) 0px, transparent 50%),radial-gradient(at 50% 50%, rgba(59,130,246,.3) 0px, transparent 50%),#0f172a;}
    .card{background:rgba(255,255,255,.98);backdrop-filter:blur(30px)}
    .input{width:100%;padding:12px 16px;border:1.5px solid #e2e8f0;border-radius:12px;font-size:15px;transition:.15s;background:#fff}
    .input:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 4px rgba(99,102,241,.12)}
    .btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;padding:13px;border-radius:12px;font-weight:700;width:100%;transition:.15s;box-shadow:0 10px 25px -5px rgba(99,102,241,.5)}
    .tab{padding:10px;border-radius:10px;font-weight:700;font-size:14px;transition:.15s;color:#64748b;flex:1;background:transparent;border:none;cursor:pointer}
    .tab.active{background:#eef2ff;color:#4f46e5}
  </style>
</head>
<body class="bg-mesh min-h-screen flex items-center justify-center p-4">
  <div class="card w-full max-w-md rounded-3xl shadow-2xl p-8 md:p-10">
    <div class="text-center mb-6">
      <div class="w-20 h-20 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-indigo-500/40"><span class="text-4xl">🛡️</span></div>
      <h1 class="text-2xl font-extrabold text-slate-900">OVG Tracker</h1>
    </div>
    <div class="flex gap-2 mb-6 bg-slate-50 p-1 rounded-xl">
      <button type="button" id="tab-login" class="tab active" onclick="switchTab('login')">تسجيل دخول</button>
      <button type="button" id="tab-signup" class="tab" onclick="switchTab('signup')">إنشاء حساب</button>
    </div>
    <form id="authForm" class="space-y-4" autocomplete="on">
      <div><input name="username" class="input" placeholder="اسم المستخدم" required minlength="3"></div>
      <div><input name="password" type="password" class="input" placeholder="كلمة المرور" required minlength="6"></div>
      <div id="confirmWrap" class="hidden"><input name="confirm" type="password" class="input" placeholder="تأكيد كلمة المرور"></div>
      <button type="submit" id="submitBtn" class="btn">تسجيل الدخول</button>
      <p id="error" class="hidden text-rose-600 text-sm text-center font-semibold bg-rose-50 py-2.5 rounded-lg"></p>
    </form>
  </div>
  <script>
    let MODE = 'login';
    function switchTab(m) {
      MODE = m;
      document.getElementById('tab-login').classList.toggle('active', m === 'login');
      document.getElementById('tab-signup').classList.toggle('active', m === 'signup');
      document.getElementById('confirmWrap').classList.toggle('hidden', m !== 'signup');
      document.getElementById('submitBtn').textContent = m === 'signup' ? 'إنشاء حساب' : 'تسجيل الدخول';
      document.getElementById('error').classList.add('hidden');
    }
    document.getElementById('authForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submitBtn'), err = document.getElementById('error');
      btn.disabled = true; err.classList.add('hidden'); const orig = btn.textContent; btn.textContent = 'جاري...';
      const fd = new FormData(e.target), body = { username: fd.get('username').trim(), password: fd.get('password') };
      if (MODE === 'signup' && body.password !== fd.get('confirm')) { err.textContent = 'كلمتا المرور غير متطابقتين'; err.classList.remove('hidden'); btn.disabled = false; btn.textContent = orig; return; }
      try {
        const r = await fetch(MODE === 'signup' ? '/api/auth/signup' : '/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        const d = await r.json().catch(()=>({}));
        if (r.ok) { location.href = '/dashboard'; return; }
        err.textContent = d.detail || 'فشل العملية'; err.classList.remove('hidden');
      } catch(e) { err.textContent = 'خطأ في الاتصال'; err.classList.remove('hidden'); } finally { btn.disabled = false; btn.textContent = orig; }
    });
  </script>
</body>
</html>
"""

# =========================================================
# MAIN DASHBOARD (With Reports & Advanced Filters)
# =========================================================
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG · لوحة التحكم</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    body{font-family:'Cairo',sans-serif;background:#f8fafc;color:#1e293b}
    ::-webkit-scrollbar{width:6px;height:6px} ::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}
    .site-card{transition:all .2s ease} .site-card:hover{transform:translateY(-3px);box-shadow:0 20px 40px -12px rgba(99,102,241,.25)}
    .nav-btn.active{background:#eef2ff;color:#4f46e5;font-weight:700}
    .modal-bg{background:rgba(15,23,42,.6);backdrop-filter:blur(6px)}
    .toast{animation:slideUp .3s ease} @keyframes slideUp{from{transform:translate(-50%,20px);opacity:0}to{transform:translate(-50%,0);opacity:1}}
    .tab-btn{padding:10px 20px;border-radius:10px;font-weight:700;font-size:14px;transition:.15s;color:#64748b;background:transparent;border:none;cursor:pointer;white-space:nowrap}
    .tab-btn.active{background:#eef2ff;color:#4f46e5}
  </style>
</head>
<body class="min-h-screen">

<aside class="fixed right-0 top-0 h-screen w-72 bg-white border-l border-slate-200 flex flex-col z-40">
  <div class="p-6 border-b border-slate-100">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center text-white font-extrabold shadow-md">O</div>
      <div><h1 class="font-extrabold text-slate-900 leading-tight">OVG Tracker</h1><p class="text-[11px] text-slate-400 font-semibold">ULTIMATE · V4.0</p></div>
    </div>
  </div>
  <div id="siteContext" class="p-3 border-b border-slate-100 hidden relative">
    <button onclick="toggleSiteMenu(event)" class="w-full flex items-center justify-between p-3 bg-slate-50 hover:bg-slate-100 rounded-xl transition">
      <div class="flex items-center gap-2 min-w-0"><span class="text-lg">🌐</span><span id="currentSiteName" class="font-semibold text-sm text-slate-700 truncate">...</span></div>
      <span class="text-slate-400 text-xs">▼</span>
    </button>
    <div id="siteMenu" class="hidden absolute right-3 left-3 top-full mt-1 bg-white rounded-xl shadow-2xl border border-slate-100 py-2 z-50 max-h-80 overflow-y-auto"></div>
  </div>
  <nav class="flex-1 p-3 space-y-1 overflow-y-auto">
    <button onclick="navTo('sites')" data-nav="sites" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">📊</span> المواقع</button>
    <div id="siteNav" class="hidden space-y-1 pt-1">
      <button onclick="navTo('overview')" data-nav="overview" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">🏠</span> نظرة عامة</button>
      <button onclick="navTo('visits')" data-nav="visits" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">📋</span> كل الزيارات</button>
      <button onclick="navTo('reports')" data-nav="reports" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">📈</span> التقارير المتقدمة</button>
      <button onclick="navTo('tracker')" data-nav="tracker" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">🔧</span> كود التتبع</button>
      <button onclick="navTo('settings')" data-nav="settings" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">⚙️</span> الإعدادات</button>
    </div>
  </nav>
  <div class="p-3 border-t border-slate-100">
    <button onclick="doLogout()" class="w-full text-right px-3 py-2 text-sm text-rose-600 hover:bg-rose-50 rounded-lg font-semibold transition">← تسجيل الخروج</button>
  </div>
</aside>

<main class="mr-72 min-h-screen">
  <div class="p-6 md:p-8 max-w-7xl mx-auto">

    <!-- SITES VIEW -->
    <div id="view-sites" class="view">
      <div class="flex justify-between items-center mb-6">
        <div><h1 class="text-2xl font-extrabold text-slate-900">مواقعي</h1><p class="text-slate-500 text-sm">أدر كل مواقعك من مكان واحد</p></div>
        <button onclick="openSiteModal()" class="bg-indigo-600 text-white px-5 py-2.5 rounded-xl font-bold text-sm shadow-lg">+ موقع جديد</button>
      </div>
      <div id="sitesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"></div>
    </div>

    <!-- OVERVIEW VIEW -->
    <div id="view-overview" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">نظرة عامة</h1>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white p-5 rounded-2xl border border-slate-100"><p class="text-slate-500 text-xs font-bold">إجمالي الزيارات</p><p id="kpi-total" class="text-3xl font-extrabold text-slate-900">0</p></div>
        <div class="bg-white p-5 rounded-2xl border-r-4 border-r-emerald-500"><p class="text-slate-500 text-xs font-bold">صالحة</p><p id="kpi-valid" class="text-3xl font-extrabold text-emerald-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl border-r-4 border-r-rose-500"><p class="text-slate-500 text-xs font-bold">بوتات</p><p id="kpi-invalid" class="text-3xl font-extrabold text-rose-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl border-r-4 border-r-amber-500"><p class="text-slate-500 text-xs font-bold">مشبوهة</p><p id="kpi-suspicious" class="text-3xl font-extrabold text-amber-500">0</p></div>
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-2xl border border-slate-100"><h2 class="text-sm font-bold mb-4">نسبة جودة الترافيك</h2><div class="h-56 flex justify-center"><canvas id="qualityChart"></canvas></div></div>
        <div class="bg-white rounded-2xl border border-slate-100 col-span-1 lg:col-span-2 overflow-hidden">
          <div class="p-5 border-b flex justify-between"><h2 class="text-sm font-bold">أحدث الزيارات</h2></div>
          <div class="overflow-x-auto"><table class="w-full text-sm text-right"><thead class="bg-slate-50 text-[11px] text-slate-400"><tr><th class="px-2 py-3">الوقت</th><th class="px-2 py-3">الزون</th><th class="px-2 py-3">الدولة</th><th class="px-2 py-3">Score</th><th class="px-2 py-3">الحكم</th></tr></thead><tbody id="live-table"></tbody></table></div>
        </div>
      </div>
    </div>

    <!-- ALL VISITS VIEW (ADVANCED) -->
    <div id="view-visits" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">كل الزيارات</h1>
      
      <!-- Filter Bar -->
      <div class="bg-white p-4 rounded-2xl shadow-sm border border-slate-100 mb-6 grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <div><label class="text-[10px] font-bold text-slate-500">الدولة</label><input id="f-country" class="w-full border rounded-lg px-2 py-1.5 text-xs focus:border-indigo-500 outline-none" placeholder="Egypt"></div>
        <div><label class="text-[10px] font-bold text-slate-500">الزون</label><input id="f-zone" class="w-full border rounded-lg px-2 py-1.5 text-xs focus:border-indigo-500 outline-none" placeholder="10245"></div>
        <div><label class="text-[10px] font-bold text-slate-500">الحكم</label><select id="f-verdict" class="w-full border rounded-lg px-2 py-1.5 text-xs outline-none"><option value="">الكل</option><option value="valid">Valid</option><option value="invalid">Invalid</option><option value="suspicious">Suspicious</option></select></div>
        <div><label class="text-[10px] font-bold text-slate-500">الجهاز</label><select id="f-device" class="w-full border rounded-lg px-2 py-1.5 text-xs outline-none"><option value="">الكل</option><option value="Desktop">Desktop</option><option value="Mobile">Mobile</option><option value="Tablet">Tablet</option></select></div>
        <div><label class="text-[10px] font-bold text-slate-500">المتصفح</label><input id="f-browser" class="w-full border rounded-lg px-2 py-1.5 text-xs outline-none" placeholder="Chrome"></div>
        <div><label class="text-[10px] font-bold text-slate-500">من تاريخ</label><input type="date" id="f-from" class="w-full border rounded-lg px-2 py-1.5 text-xs outline-none"></div>
        <div><label class="text-[10px] font-bold text-slate-500">إلى تاريخ</label><input type="date" id="f-to" class="w-full border rounded-lg px-2 py-1.5 text-xs outline-none"></div>
        <div class="flex items-end gap-2">
          <button onclick="loadVisits(1)" class="bg-indigo-600 text-white w-full py-1.5 rounded-lg text-xs font-bold">بحث</button>
          <button onclick="resetVisitFilters()" class="bg-slate-100 text-slate-600 w-full py-1.5 rounded-lg text-xs font-bold">مسح</button>
        </div>
      </div>

      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden mb-4">
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-right">
            <thead class="bg-slate-50 text-[11px] text-slate-400"><tr><th class="px-4 py-3 text-center">الوقت</th><th class="px-4 py-3">IP</th><th class="px-4 py-3">الدولة</th><th class="px-4 py-3">الزون</th><th class="px-4 py-3 text-center">الجهاز</th><th class="px-4 py-3 text-center">الحكم</th><th class="px-4 py-3 text-center">تفاصيل</th></tr></thead>
            <tbody id="visits-table-body" class="divide-y divide-slate-100"></tbody>
          </table>
        </div>
      </div>
      <div class="flex justify-between items-center bg-white p-4 rounded-2xl border border-slate-100">
        <button id="btn-prev" onclick="changePage(-1)" class="px-4 py-2 bg-slate-100 rounded-lg text-sm font-bold disabled:opacity-50">السابق</button>
        <span id="page-info" class="text-sm font-semibold">صفحة 1</span>
        <button id="btn-next" onclick="changePage(1)" class="px-4 py-2 bg-slate-100 rounded-lg text-sm font-bold disabled:opacity-50">التالي</button>
      </div>
    </div>

    <!-- REPORTS VIEW -->
    <div id="view-reports" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">التقارير المتقدمة</h1>
      
      <!-- Tabs -->
      <div class="flex gap-2 mb-6 overflow-x-auto pb-2">
        <button onclick="switchRepTab('countries')" id="tab-rep-countries" class="tab-btn active">🌍 الدول</button>
        <button onclick="switchRepTab('devices')" id="tab-rep-devices" class="tab-btn">📱 الأجهزة والمتصفحات</button>
        <button onclick="switchRepTab('fps')" id="tab-rep-fps" class="tab-btn">🧬 البصمات المتكررة</button>
        <button onclick="switchRepTab('ips')" id="tab-rep-ips" class="tab-btn">🔁 الـ IPs المتكررة</button>
        <button onclick="switchRepTab('asn')" id="tab-rep-asn" class="tab-btn">🏢 الشبكات (ASN)</button>
        <button onclick="switchRepTab('hourly')" id="tab-rep-hourly" class="tab-btn">⏰ ساعات النشاط</button>
        <button onclick="switchRepTab('trend')" id="tab-rep-trend" class="tab-btn">📈 الترند (30 يوم)</button>
      </div>

      <!-- Content -->
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 p-6">
        <div id="rep-countries" class="rep-content"><table class="w-full text-sm text-right"><thead class="bg-slate-50 text-[11px] text-slate-400"><tr><th class="px-4 py-3">الدولة</th><th class="px-4 py-3">إجمالي</th><th class="px-4 py-3">بوتات</th><th class="px-4 py-3">نسبة البوتات</th></tr></thead><tbody id="tb-countries"></tbody></table></div>
        <div id="rep-devices" class="rep-content hidden"><div class="grid grid-cols-1 md:grid-cols-3 gap-6"><div><h3 class="text-sm font-bold mb-4 text-center">نظام التشغيل</h3><canvas id="chart-os"></canvas></div><div><h3 class="text-sm font-bold mb-4 text-center">المتصفح</h3><canvas id="chart-browser"></canvas></div><div><h3 class="text-sm font-bold mb-4 text-center">الجهاز</h3><canvas id="chart-device"></canvas></div></div></div>
        <div id="rep-fps" class="rep-content hidden"><table class="w-full text-sm text-right"><thead class="bg-slate-50 text-[11px] text-slate-400"><tr><th class="px-4 py-3">البصمة</th><th class="px-4 py-3">مرات الدخول</th><th class="px-4 py-3">IPs مختلفة</th><th class="px-4 py-3 text-rose-600">شبهة؟</th></tr></thead><tbody id="tb-fps"></tbody></table></div>
        <div id="rep-ips" class="rep-content hidden"><table class="w-full text-sm text-right"><thead class="bg-slate-50 text-[11px] text-slate-400"><tr><th class="px-4 py-3">IP</th><th class="px-4 py-3">مرات الدخول</th><th class="px-4 py-3">أسوأ حكم</th></tr></thead><tbody id="tb-ips"></tbody></table></div>
        <div id="rep-asn" class="rep-content hidden"><table class="w-full text-sm text-right"><thead class="bg-slate-50 text-[11px] text-slate-400"><tr><th class="px-4 py-3">ASN</th><th class="px-4 py-3">الشبكة</th><th class="px-4 py-3">إجمالي</th><th class="px-4 py-3">بوتات</th></tr></thead><tbody id="tb-asn"></tbody></table></div>
        <div id="rep-hourly" class="rep-content hidden"><div class="h-80"><canvas id="chart-hourly"></canvas></div></div>
        <div id="rep-trend" class="rep-content hidden"><div class="h-80"><canvas id="chart-trend"></canvas></div></div>
      </div>
    </div>

    <!-- TRACKER & SETTINGS VIEWS (Same as before) -->
    <div id="view-tracker" class="view hidden">
      <h1 class="text-2xl font-extrabold mb-2">كود التتبع</h1>
      <div class="bg-slate-900 rounded-2xl p-6"><pre id="embedCode" class="text-emerald-400 text-xs overflow-x-auto whitespace-pre-wrap">جاري التحميل...</pre></div>
    </div>
    <div id="view-settings" class="view hidden">
      <h1 class="text-2xl font-extrabold mb-6">إعدادات الموقع</h1>
      <div class="bg-white rounded-2xl p-6 max-w-xl mb-5 border border-slate-100">
        <input id="editName" class="w-full border rounded-xl px-4 py-2 mb-3" placeholder="اسم الموقع">
        <input id="editDomain" class="w-full border rounded-xl px-4 py-2 mb-3" placeholder="الدومين">
        <button onclick="saveSiteSettings()" class="bg-indigo-600 text-white px-5 py-2 rounded-xl font-bold">حفظ</button>
      </div>
    </div>

  </div>
</main>

<!-- Modals & Toast (Same as before) -->
<div id="siteModal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4"><div class="bg-white rounded-3xl p-8 max-w-md w-full"><h3 class="text-lg font-bold mb-4">موقع جديد</h3><form id="siteForm"><input id="newName" required class="w-full border rounded-xl px-4 py-2 mb-3" placeholder="الاسم"><input id="newDomain" class="w-full border rounded-xl px-4 py-2 mb-4" placeholder="الدومين (اختياري)"><div class="flex gap-2"><button type="button" onclick="closeSiteModal()" class="flex-1 bg-slate-100 py-2 rounded-xl">إلغاء</button><button type="submit" class="flex-1 bg-indigo-600 text-white py-2 rounded-xl">إنشاء</button></div></form></div></div>
<div id="details-modal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4"><div class="bg-white rounded-3xl p-8 max-w-md w-full"><h3 class="text-lg font-bold text-indigo-700 mb-4">التفاصيل</h3><div id="modal-content" class="text-sm space-y-2 mb-6 max-h-96 overflow-y-auto"></div><button onclick="closeDetails()" class="w-full bg-slate-800 text-white py-2 rounded-xl">إغلاق</button></div></div>
<div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 hidden bg-slate-900 text-white px-6 py-3 rounded-xl font-semibold text-sm shadow-2xl z-[100] toast"></div>

<script>
const state = { user: null, sites: [], currentSite: null, view: 'sites', chart: null, visitsData: {} };

async function init() {
  const me = await fetch('/api/auth/me').then(r => r.ok ? r.json() : null).catch(() => null);
  if (!me) { location.href = '/'; return; }
  state.user = me; await loadSites();
  const siteKey = new URL(location.href).searchParams.get('site');
  if (siteKey) { const s = state.sites.find(x => x.site_key === siteKey); if (s) { selectSite(s, false); return; } }
  navTo('sites');
}

async function loadSites() {
  const r = await fetch('/api/sites'); state.sites = await r.json(); renderSites(); renderSiteMenu();
}
function renderSites() {
  const grid = document.getElementById('sitesGrid');
  if (!state.sites.length) { grid.innerHTML = `<div class="col-span-full text-center py-10 text-slate-400">لا توجد مواقع. أضف موقعك الأول.</div>`; return; }
  grid.innerHTML = state.sites.map(s => `
    <div class="site-card bg-white rounded-2xl p-5 border cursor-pointer" onclick="openSite('${s.site_key}')">
      <h3 class="font-bold text-lg">${esc(s.name)}</h3>
      <p class="text-slate-400 text-xs mb-3">${esc(s.domain || 'بدون دومين')}</p>
      <div class="grid grid-cols-3 gap-1 text-center py-2 border-y mb-3"><div><p class="text-[10px]">إجمالي</p><p class="font-bold">${s.total}</p></div><div><p class="text-[10px]">صالح</p><p class="font-bold text-emerald-600">${s.valid}</p></div><div><p class="text-[10px]">بوتات</p><p class="font-bold text-rose-600">${s.invalid}</p></div></div>
    </div>`).join('');
}
function renderSiteMenu() {
  document.getElementById('siteMenu').innerHTML = state.sites.map(s => `<button onclick="openSite('${s.site_key}')" class="w-full text-right px-3 py-2 hover:bg-slate-50 text-sm ${state.currentSite?.id === s.id ? 'bg-indigo-50 font-bold' : ''}">${esc(s.name)}</button>`).join('');
}
function toggleSiteMenu(e) { e.stopPropagation(); document.getElementById('siteMenu').classList.toggle('hidden'); }
document.addEventListener('click', e => { const m = document.getElementById('siteMenu'); if (m && !m.classList.contains('hidden') && !e.target.closest('#siteContext')) m.classList.add('hidden'); });
function openSite(key) { const s = state.sites.find(x => x.site_key === key); if (s) selectSite(s, true); }
function selectSite(site, push) {
  state.currentSite = site; document.getElementById('currentSiteName').textContent = site.name;
  document.getElementById('siteContext').classList.remove('hidden'); document.getElementById('siteNav').classList.remove('hidden');
  if (push) history.pushState({}, '', '/dashboard?site=' + site.site_key);
  renderSiteMenu(); navTo('overview');
}
function navTo(view) {
  state.view = view; document.querySelectorAll('.view').forEach(v => v.classList.add('hidden')); document.getElementById('view-' + view).classList.remove('hidden');
  document.querySelectorAll('.nav-btn').forEach(b => { b.classList.remove('active'); if (b.dataset.nav === view) b.classList.add('active'); });
  if (view === 'sites') loadSites();
  if (view === 'overview') loadOverview();
  if (view === 'visits') loadVisits(1);
  if (view === 'reports') switchRepTab('countries');
  if (view === 'tracker') renderTracker();
  if (view === 'settings') renderSettings();
}

async function loadOverview() {
  if (!state.currentSite) return;
  const r = await fetch('/api/stats?site=' + state.currentSite.site_key); const d = await r.json();
  document.getElementById('kpi-total').textContent = d.total; document.getElementById('kpi-valid').textContent = d.valid; document.getElementById('kpi-invalid').textContent = d.invalid; document.getElementById('kpi-suspicious').textContent = d.suspicious;
  const tb = document.getElementById('live-table');
  tb.innerHTML = d.recent.map(v => `<tr class="hover:bg-slate-50"><td class="px-2 py-2 text-xs">${v.time.split('T')[1].slice(0,8)}</td><td class="px-2 py-2 text-xs font-bold">${esc(v.zone)}</td><td class="px-2 py-2 text-xs">${esc(v.country)}</td><td class="px-2 py-2 text-xs font-bold ${v.score>80?'text-rose-600':'text-emerald-600'}">${v.score}</td><td class="px-2 py-2 text-xs"><span class="px-2 py-1 rounded bg-slate-100 font-bold">${v.verdict}</span></td></tr>`).join('');
  if (state.chart) state.chart.destroy();
  state.chart = new Chart(document.getElementById('qualityChart'), { type: 'doughnut', data: { labels: ['Valid', 'Invalid', 'Suspicious'], datasets: [{ data: [d.valid, d.invalid, d.suspicious], backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'] }] }, options: { cutout: '75%' } });
}

let currentPage = 1;
function resetVisitFilters() { document.getElementById('f-country').value=''; document.getElementById('f-zone').value=''; document.getElementById('f-verdict').value=''; document.getElementById('f-device').value=''; document.getElementById('f-browser').value=''; document.getElementById('f-from').value=''; document.getElementById('f-to').value=''; loadVisits(1); }
async function loadVisits(page = 1) {
  currentPage = page;
  let url = `/api/visits?page=${page}&site=${state.currentSite.site_key}`;
  const c = document.getElementById('f-country').value.trim(); if (c) url += `&country=${encodeURIComponent(c)}`;
  const z = document.getElementById('f-zone').value.trim(); if (z) url += `&zone=${encodeURIComponent(z)}`;
  const v = document.getElementById('f-verdict').value; if (v) url += `&verdict=${v}`;
  const d = document.getElementById('f-device').value; if (d) url += `&device=${d}`;
  const b = document.getElementById('f-browser').value.trim(); if (b) url += `&browser=${encodeURIComponent(b)}`;
  const f = document.getElementById('f-from').value; if (f) url += `&from_date=${f}`;
  const t = document.getElementById('f-to').value; if (t) url += `&to_date=${t}`;
  
  const tbody = document.getElementById('visits-table-body'); tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4">جاري التحميل...</td></tr>';
  const r = await fetch(url); const data = await r.json();
  document.getElementById('page-info').textContent = `صفحة ${data.page} من ${data.pages || 1} (إجمالي ${data.total})`;
  document.getElementById('btn-prev').disabled = data.page <= 1; document.getElementById('btn-next').disabled = data.page >= data.pages;
  if (!data.items.length) { tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4">لا توجد نتائج</td></tr>'; return; }
  
  tbody.innerHTML = data.items.map(v => {
    state.visitsData[v.id] = v;
    const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700' : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700';
    return `<tr class="hover:bg-slate-50"><td class="px-4 py-2 text-xs text-slate-500 text-center" dir="ltr">${v.time.replace('T',' ').slice(0,16)}</td><td class="px-4 py-2 font-mono text-xs" dir="ltr">${v.ip}</td><td class="px-4 py-2 text-xs">${esc(v.country)}</td><td class="px-4 py-2 text-xs font-bold">${esc(v.zone)}</td><td class="px-4 py-2 text-xs text-center">${esc(v.device)}<br><span class="text-[10px] text-slate-400">${esc(v.browser)}</span></td><td class="px-4 py-2 text-center"><span class="${badge} px-2 py-1 rounded text-[10px] font-bold">${v.verdict}</span></td><td class="px-4 py-2 text-center"><button onclick="showDetails(${v.id})" class="text-indigo-600 text-xs font-bold hover:underline">عرض</button></td></tr>`;
  }).join('');
}
function changePage(step) { loadVisits(currentPage + step); }

function showDetails(id) {
  const v = state.visitsData[id]; if (!v) return;
  document.getElementById('modal-content').innerHTML = `<p><b>IP:</b> <span dir="ltr">${v.ip}</span></p><p><b>ISP:</b> ${v.isp}</p><p><b>ASN:</b> ${v.asn}</p><p><b>Timezone:</b> ${v.timezone}</p><p><b>Hardware:</b> ${v.hardware}</p><p><b>WebRTC:</b> <span dir="ltr">${v.webrtc}</span></p><hr><ul class="list-disc pr-5 text-rose-600">${v.evidence.map(e=>`<li>${esc(e)}</li>`).join('') || '<li class="text-emerald-600">سليم</li>'}</ul>`;
  document.getElementById('details-modal').classList.remove('hidden'); document.getElementById('details-modal').classList.add('flex');
}
function closeDetails() { document.getElementById('details-modal').classList.add('hidden'); document.getElementById('details-modal').classList.remove('flex'); }

let currentRepTab = 'countries';
function switchRepTab(tab) {
  currentRepTab = tab;
  document.querySelectorAll('.rep-content').forEach(e => e.classList.add('hidden')); document.getElementById('rep-' + tab).classList.remove('hidden');
  document.querySelectorAll('.tab-btn').forEach(b => { b.classList.remove('active'); if (b.id === 'tab-rep-' + tab) b.classList.add('active'); });
  if (tab === 'countries') loadRepCountries();
  if (tab === 'devices') loadRepDevices();
  if (tab === 'fps') loadRepFps();
  if (tab === 'ips') loadRepIps();
  if (tab === 'asn') loadRepAsn();
  if (tab === 'hourly') loadRepHourly();
  if (tab === 'trend') loadRepTrend();
}

async function loadRepCountries() {
  const r = await fetch('/api/reports/countries?site=' + state.currentSite.site_key); const d = await r.json();
  document.getElementById('tb-countries').innerHTML = d.map(x => `<tr><td class="px-4 py-2 text-xs font-bold">${esc(x.label)}</td><td class="px-4 py-2 text-xs">${x.total}</td><td class="px-4 py-2 text-xs text-rose-600">${x.invalid}</td><td class="px-4 py-2 text-xs font-bold">${x.total>0 ? (x.invalid/x.total*100).toFixed(1) : 0}%</td></tr>`).join('') || '<tr><td colspan="4" class="text-center py-4">لا بيانات</td></tr>';
}
async function loadRepDevices() {
  const r = await fetch('/api/reports/devices?site=' + state.currentSite.site_key); const d = await r.json();
  const makeChart = (id, labels, data) => { new Chart(document.getElementById(id), { type: 'pie', data: { labels: labels, datasets: [{ data: data, backgroundColor: ['#6366f1', '#10b981', '#f59e0b', '#f43f5e', '#8b5cf6'] }] } }); };
  makeChart('chart-os', d.os.map(x=>x.label), d.os.map(x=>x.count)); makeChart('chart-browser', d.browser.map(x=>x.label), d.browser.map(x=>x.count)); makeChart('chart-device', d.device.map(x=>x.label), d.device.map(x=>x.count));
}
async function loadRepFps() {
  const r = await fetch('/api/reports/fingerprints?site=' + state.currentSite.site_key); const d = await r.json();
  document.getElementById('tb-fps').innerHTML = d.map(x => `<tr><td class="px-4 py-2 text-xs font-mono" dir="ltr">${x.fp}</td><td class="px-4 py-2 text-xs font-bold">${x.visits}</td><td class="px-4 py-2 text-xs">${x.unique_ips}</td><td class="px-4 py-2 text-xs font-bold ${x.suspicious?'text-rose-600':'text-emerald-600'}">${x.suspicious?'نعم (شبكة بوتات)':'لا'}</td></tr>`).join('') || '<tr><td colspan="4" class="text-center py-4">لا بصمات متكررة</td></tr>';
}
async function loadRepIps() {
  const r = await fetch('/api/reports/ips?site=' + state.currentSite.site_key); const d = await r.json();
  document.getElementById('tb-ips').innerHTML = d.map(x => `<tr><td class="px-4 py-2 text-xs font-mono" dir="ltr">${x.ip}</td><td class="px-4 py-2 text-xs font-bold">${x.visits}</td><td class="px-4 py-2 text-xs"><span class="px-2 py-1 rounded bg-slate-100">${x.verdict}</span></td></tr>`).join('') || '<tr><td colspan="3" class="text-center py-4">لا بيانات</td></tr>';
}
async function loadRepAsn() {
  const r = await fetch('/api/reports/asn?site=' + state.currentSite.site_key); const d = await r.json();
  document.getElementById('tb-asn').innerHTML = d.map(x => `<tr><td class="px-4 py-2 text-xs font-bold">${x.asn}</td><td class="px-4 py-2 text-xs">${esc(x.isp)}</td><td class="px-4 py-2 text-xs">${x.total}</td><td class="px-4 py-2 text-xs text-rose-600 font-bold">${x.invalid}</td></tr>`).join('') || '<tr><td colspan="4" class="text-center py-4">لا بيانات</td></tr>';
}
async function loadRepHourly() {
  const r = await fetch('/api/reports/hourly?site=' + state.currentSite.site_key); const d = await r.json();
  const labels = Array.from({length: 24}, (_, i) => i + ':00');
  const data = Array.from({length: 24}, (_, i) => d[i] ? d[i].total : 0);
  new Chart(document.getElementById('chart-hourly'), { type: 'bar', data: { labels: labels, datasets: [{ label: 'الزيارات', data: data, backgroundColor: '#6366f1' }] } });
}
async function loadRepTrend() {
  const r = await fetch('/api/reports/trend?site=' + state.currentSite.site_key); const d = await r.json();
  new Chart(document.getElementById('chart-trend'), { type: 'line', data: { labels: d.map(x=>x.day), datasets: [{ label: 'إجمالي', data: d.map(x=>x.total), borderColor: '#6366f1', tension: 0.3 }, { label: 'بوتات', data: d.map(x=>x.invalid), borderColor: '#f43f5e', tension: 0.3 }] } });
}

function openSiteModal() { document.getElementById('siteModal').classList.remove('hidden'); document.getElementById('siteModal').classList.add('flex'); }
function closeSiteModal() { document.getElementById('siteModal').classList.add('hidden'); document.getElementById('siteModal').classList.remove('flex'); }
document.getElementById('siteForm').addEventListener('submit', async (e) => {
  e.preventDefault(); const r = await fetch('/api/sites', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name: document.getElementById('newName').value, domain: document.getElementById('newDomain').value }) });
  if (r.ok) { closeSiteModal(); await loadSites(); } else toast('فشل الإنشاء');
});

async function renderTracker() { const r = await fetch('/api/sites/' + state.currentSite.id + '/tracker-code'); const d = await r.json(); document.getElementById('embedCode').textContent = d.code; }
function renderSettings() { document.getElementById('editName').value = state.currentSite.name; document.getElementById('editDomain').value = state.currentSite.domain || ''; }
async function saveSiteSettings() { await fetch('/api/sites/' + state.currentSite.id, { method: 'PATCH', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name: document.getElementById('editName').value, domain: document.getElementById('editDomain').value }) }); toast('تم الحفظ'); }

function esc(s) { return String(s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function toast(msg) { const el = document.getElementById('toast'); el.textContent = msg; el.classList.remove('hidden'); clearTimeout(el._t); el._t = setTimeout(() => el.classList.add('hidden'), 2500); }
async function doLogout() { await fetch('/api/auth/logout', { method: 'POST' }); location.href = '/'; }

init();
</script>
</body>
</html>
"""

# =========================================================
# ROUTES: HTML
# =========================================================
@app.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db): return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, key: str = None, db: Session = Depends(get_db)):
    if key and DASHBOARD_KEY and key == DASHBOARD_KEY:
        first = db.query(UserModel).first()
        if first:
            resp = RedirectResponse("/dashboard", status_code=302)
            resp.set_cookie(SESSION_COOKIE, make_token(first.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(DASHBOARD_HTML)