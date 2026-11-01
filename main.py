"""
OVG Tracker — Session 3.2 (Security Hardened)
Fixed: XSS in dashboard, XSS in DASHBOARD_KEY, HTTP MITM, XFF trust,
       WebRTC IP validation, mock-data exposure.
"""
import ipaddress
import json
import os
import random
import time
from collections import OrderedDict
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Index, Integer, String,
    case, create_engine, func,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# اختياري — لو عايز MaxMind محلي (أسرع وأأمن)
try:
    import geoip2.database
    _GEOIP_AVAILABLE = True
except ImportError:
    _GEOIP_AVAILABLE = False

# =========================================================
# CONFIG
# =========================================================
DATABASE_URL       = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
DASHBOARD_KEY      = os.getenv("OVG_DASHBOARD_KEY", "")
ALLOWED_ORIGINS    = [o.strip() for o in os.getenv("OVG_ORIGINS", "*").split(",") if o.strip()]
TRACK_RATE_PER_MIN = int(os.getenv("OVG_TRACK_RATE", "120"))
GEO_LOOKUP_TIMEOUT = float(os.getenv("OVG_GEO_TIMEOUT", "3.0"))
GEO_CACHE_TTL      = int(os.getenv("OVG_GEO_TTL", "86400"))
GEO_CACHE_MAX      = int(os.getenv("OVG_GEO_MAX", "50000"))

# 🔒 FIX #4: قائمة الـ proxies الموثوقة — فاضية يعني مفيش هيدر forwarding بيتصدق
# مثال: OVG_TRUSTED_PROXIES="127.0.0.1,10.0.0.5,172.18.0.2"
TRUSTED_PROXIES = {
    ip.strip() for ip in os.getenv("OVG_TRUSTED_PROXIES", "").split(",") if ip.strip()
}

# 🔒 FIX #6: mock-data معطّل افتراضياً
ENABLE_MOCK = os.getenv("OVG_ENABLE_MOCK", "false").lower() in ("1", "true", "yes")

# 🔒 FIX #3: MaxMind DB (اختياري) + proxycheck.io key (اختياري)
GEOIP_DB_PATH = os.getenv("OVG_GEOIP_DB", "./GeoLite2-City.mmdb")
PROXYCHECK_KEY = os.getenv("OVG_PROXYCHECK_KEY", "").strip()

# =========================================================
# DB & MODELS
# =========================================================
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class VisitModel(Base):
    __tablename__ = "visits"
    id = Column(Integer, primary_key=True, index=True)
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

    __table_args__ = (
        Index("ix_visits_zone_verdict", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
    )

Base.metadata.create_all(bind=engine)

# =========================================================
# APP & MIDDLEWARE
# =========================================================
app = FastAPI(title="OVG Tracker", version="3.2.0")

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                       allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])

# 🎁 Defense-in-depth لثغرات XSS — لو حصل نسيان في مكان، المتصفح يحمي
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# =========================================================
# HELPERS
# =========================================================
class TTLCache:
    def __init__(self, maxsize: int = 10000, ttl: int = 3600):
        self.maxsize, self.ttl = maxsize, ttl
        self._data = OrderedDict()
    def get(self, key):
        entry = self._data.get(key)
        if entry is None: return None
        val, ts = entry
        if time.time() - ts > self.ttl:
            del self._data[key]; return None
        self._data.move_to_end(key); return val
    def set(self, key, val):
        self._data[key] = (val, time.time()); self._data.move_to_end(key)
        while len(self._data) > self.maxsize: self._data.popitem(last=False)

class WindowRateLimiter:
    def __init__(self, max_req=120, window=60, maxsize=100000):
        self.max_req, self.window, self.maxsize = max_req, window, maxsize
        self._d = OrderedDict()
    def check(self, key: str):
        now = time.time()
        entry = self._d.get(key)
        if entry is None or now - entry[1] > self.window:
            self._d[key] = (1, now); self._d.move_to_end(key)
        else:
            self._d[key] = (entry[0] + 1, entry[1]); self._d.move_to_end(key)
        while len(self._d) > self.maxsize: self._d.popitem(last=False)
        if self._d[key][0] > self.max_req:
            raise HTTPException(status_code=429, detail="Too many requests",
                                headers={"Retry-After": str(self.window)})

ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False

# 🔒 FIX #5: بوابة تحقق لأي IP جاي من العميل قبل ما يدخل الداتابيز
def _validate_ip_or_none(v) -> str:
    if not v:
        return "None"
    v = str(v).strip()
    if v == "None":
        return "None"
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        return "None"

# 🔒 FIX #4: ما بنثقش في هيدرات forwarding إلا لو الطلب جاي من proxy موثوق
def _is_trusted_proxy(host: str) -> bool:
    return host in TRUSTED_PROXIES

def get_client_ip(request: Request) -> str:
    client_host = request.client.host if request.client else "0.0.0.0"

    # مفيش proxy موثوق؟ استخدم الـ socket IP مباشرة (آمن)
    if not _is_trusted_proxy(client_host):
        return client_host

    cf = (request.headers.get("cf-connecting-ip") or "").strip()
    if cf:
        try:
            ipaddress.ip_address(cf)
            return cf
        except ValueError:
            pass

    xff = request.headers.get("x-forwarded-for") or ""
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    for p in reversed(parts):
        try:
            ipaddress.ip_address(p)
            if not _is_private_ip(p):
                return p
        except ValueError:
            continue

    xri = (request.headers.get("x-real-ip") or "").strip()
    if xri:
        try:
            ipaddress.ip_address(xri)
            return xri
        except ValueError:
            pass

    return client_host

def verify_dashboard_key(request: Request):
    if not DASHBOARD_KEY:
        # 🔒 FIX #2 (مساعد): fail-closed — مفيش key مظبوط يعني API مقفول
        raise HTTPException(status_code=403, detail="Dashboard disabled")
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if key != DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

# 🔒 FIX #3: Geo lookup آمن — MaxMind محلي (preferred) → ipwho.is HTTPS → proxycheck.io
_geo_reader = None
_geo_reader_loaded = False

def _get_geo_reader():
    global _geo_reader, _geo_reader_loaded
    if _geo_reader_loaded:
        return _geo_reader
    _geo_reader_loaded = True
    if _GEOIP_AVAILABLE and os.path.exists(GEOIP_DB_PATH):
        try:
            _geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception:
            _geo_reader = None
    return _geo_reader

_HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "azure", "microsoft", "digitalocean",
    "linode", "ovh", "hetzner", "vultr", "contabo", "oracle",
    "alibaba", "cloud", "server", "hosting", "datacenter",
)

async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {"country": "Local", "isp": "Local ISP", "type": "residential",
                "asn": "N/A", "security": {"vpn": False}}

    cached = ip_cache.get(ip)
    if cached is not None:
        return cached

    result = {
        "country": "Unknown",
        "isp": "Unknown",
        "type": "Unknown",
        "asn": "Unknown",
        "security": {"vpn": False},
    }

    # 1) MaxMind محلي — أسرع وأأمن (مفيش إنترنت، مفيش MITM)
    reader = _get_geo_reader()
    if reader is not None:
        try:
            r = reader.city(ip)
            result["country"] = r.country.name or "Unknown"
            result["isp"] = r.traits.autonomous_system_organization or "Unknown"
            if r.traits.autonomous_system_number:
                result["asn"] = f"AS{r.traits.autonomous_system_number}"
            org_lower = (result["isp"] or "").lower()
            result["type"] = "hosting" if any(k in org_lower for k in _HOSTING_KEYWORDS) else "residential"
        except Exception:
            pass

    # 2) ipwho.is fallback (HTTPS، مجاني، مش محتاج key)
    if result["country"] == "Unknown":
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(f"https://ipwho.is/{ip}", timeout=GEO_LOOKUP_TIMEOUT)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("success"):
                        result["country"] = data.get("country") or "Unknown"
                        conn = data.get("connection") or {}
                        result["isp"] = conn.get("isp") or "Unknown"
                        if conn.get("asn"):
                            result["asn"] = f"AS{conn['asn']}"
                        result["type"] = "residential"
        except Exception:
            pass

    # 3) proxycheck.io للكشف عن VPN/Proxy (اختياري — لو في key)
    if PROXYCHECK_KEY:
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(
                    f"https://proxycheck.io/v2/{ip}",
                    params={"key": PROXYCHECK_KEY, "vpn": 1, "asn": 1},
                    timeout=GEO_LOOKUP_TIMEOUT,
                )
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "ok":
                        entry = data.get(ip) or {}
                        if str(entry.get("proxy", "no")).lower() == "yes":
                            result["security"]["vpn"] = True
                            result["type"] = "hosting"
        except Exception:
            pass

    ip_cache.set(ip, result)
    return result

def parse_ua(ua: str):
    ua_l = (ua or "").lower()
    device = "Mobile" if "mobi" in ua_l else "Tablet" if ("tablet" in ua_l or "ipad" in ua_l) else "Desktop"
    if "windows nt" in ua_l: os_name = "Windows"
    elif "mac os" in ua_l or "macintosh" in ua_l: os_name = "macOS"
    elif "android" in ua_l: os_name = "Android"
    elif "iphone" in ua_l or "ipad" in ua_l or "ios" in ua_l: os_name = "iOS"
    elif "linux" in ua_l: os_name = "Linux"
    else: os_name = "Unknown"

    if "edg/" in ua_l or "edge/" in ua_l: browser = "Edge"
    elif "chrome" in ua_l and "chromium" not in ua_l: browser = "Chrome"
    elif "firefox" in ua_l: browser = "Firefox"
    elif "safari" in ua_l and "chrome" not in ua_l: browser = "Safari"
    else: browser = "Unknown"
    return os_name, device, browser

def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v:
                # 🔒 قص القيمة عشان ما تتحولش لـ vector لمهاجمة الـ DB أو الـ dashboard
                return str(v[0])[:64]
    except Exception:
        pass
    return "unknown"

# =========================================================
# 🧠 THE SMART ANALYSIS ENGINE (Session 3.2)
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

    # 1. Automation Check
    if nav.get("webdriver") is True:
        score += 80; evidence.append("WebDriver Flag")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90; evidence.append("Suspicious User-Agent")

    # 2. OS Mismatch
    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        score += 50; evidence.append("OS Mismatch (Win)")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        score += 50; evidence.append("OS Mismatch (Mac)")

    # 3. Network Security
    if sec.get("vpn") is True:
        score += 70; evidence.append("VPN/Proxy Detected")

    conn_type = str(ip_info.get("type", "")).lower()
    if conn_type == "hosting":
        score += 80; evidence.append("Datacenter/Hosting IP")

    # 4. WebRTC Leak Check — 🔒 FIX #5: نتحقق من الـ IP قبل استخدامه
    webrtc = _validate_ip_or_none(data.get("webrtc_ip"))
    client_ip = data.get("client_ip")
    if webrtc != "None" and not _is_private_ip(webrtc):
        if webrtc != client_ip:
            score += 90; evidence.append(f"WebRTC Leak (Real IP: {webrtc})")

    # 5. Fingerprinting
    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        score += 60; evidence.append("Missing Canvas FP")
    try:
        cores = int(fp.get("hardwareConcurrency") or 0)
    except (TypeError, ValueError):
        cores = 0
    if cores <= 1:
        score += 40; evidence.append(f"Low CPU ({cores})")

    # 6. Timezone Mismatch
    tz = str(fp.get("timezone") or "").lower()
    country = ip_info.get("country", "Unknown")
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        score += 30; evidence.append("UTC/Unknown Timezone")
    elif country not in ("Unknown", "Local"):
        country_map = {
            "Egypt": ["cairo", "africa"],
            "US": ["america/new_york", "america/chicago", "america/los_angeles", "america/denver"],
            "United States": ["america/new_york", "america/chicago", "america/los_angeles", "america/denver"],
            "UK": ["london", "europe/london"],
            "United Kingdom": ["london", "europe/london"],
            "SA": ["riyadh", "asia/riyadh"],
            "Saudi Arabia": ["riyadh", "asia/riyadh"],
            "Italy": ["rome", "europe/rome"],
        }
        if country in country_map and not any(t in tz for t in country_map[country]):
            score += 60; evidence.append(f"Timezone Mismatch (IP:{country} vs TZ:{tz})")

    # 7. Behavior
    try:
        t_on_page = int(behavior.get("time_on_page_ms") or 0)
    except (TypeError, ValueError):
        t_on_page = 0
    if t_on_page < 1500:
        score += 40; evidence.append("Left too fast")
    try:
        mouse_var = float(behavior.get("mouse_variance") or 0)
    except (TypeError, ValueError):
        mouse_var = 0.0
    if events.get("mousemove", 0) > 10 and mouse_var < 1.5:
        score += 50; evidence.append("Robotic Mouse")
    if t_on_page > 3000 and events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30; evidence.append("No Interaction (Zombie)")

    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        score += 60; evidence.append("Virtual Renderer")

    score = min(150, score)
    if score >= 80: verdict = "invalid"
    elif score >= 40: verdict = "suspicious"
    else: verdict = "valid"

    return {"score": score, "verdict": verdict, "evidence": evidence}

class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    webrtc_ip: str = "None"

@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    track_limiter.check(client_ip)
    zone_id = extract_zone_id(payload.url)
    ua = (payload.nav or {}).get("ua") or ""
    os_name, device, browser = parse_ua(ua)

    ip_info = await get_ip_info(client_ip)

    try:
        data = payload.model_dump()
    except AttributeError:
        data = payload.dict()
    data["client_ip"] = client_ip

    result = analyze_visit(data, ip_info)

    fp = data.get("fingerprint") or {}

    # 🔒 FIX #5: التحقق من webrtc_ip قبل الحفظ
    safe_webrtc = _validate_ip_or_none(payload.webrtc_ip)

    visit = VisitModel(
        ip=client_ip, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"],
        evidence=result["evidence"], os=os_name, device=device, browser=browser,
        country=ip_info["country"], isp=ip_info["isp"],
        timezone=str(fp.get("timezone", "Unknown"))[:64],
        canvas_hash=str(fp.get("canvas_hash", "Unknown"))[:15] + "...",
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"], asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"),
        webrtc_ip=safe_webrtc,
    )
    try:
        db.add(visit); db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="DB write failed")
    return {"status": "success"}

@app.get("/api/stats", dependencies=[Depends(verify_dashboard_key)])
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(VisitModel.id)).scalar() or 0
    valid = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "valid").scalar() or 0
    invalid = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "invalid").scalar() or 0
    suspicious = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "suspicious").scalar() or 0

    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id,
        "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country,
        "score": v.score, "evidence": v.evidence,
        "timezone": v.timezone, "hardware": v.hardware,
        "conn_type": v.connection_type, "asn": v.asn,
        "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip,
    } for v in recent]
    return {"total": total, "valid": valid, "invalid": invalid,
            "suspicious": suspicious, "recent": recent_visits}

@app.get("/api/reports/zones", dependencies=[Depends(verify_dashboard_key)])
def get_zone_reports(db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    rows = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label("total"),
        invalid_expr.label("invalid"),
    ).group_by(VisitModel.zone_id).all()
    report = []
    for z in rows:
        total, invalid = int(z.total or 0), int(z.invalid or 0)
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0.0
        grade = "A" if bot_rate < 5 else "B" if bot_rate < 15 else "C" if bot_rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": bot_rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

# 🔒 FIX #6: mock-data مقفول إلا لو OVG_ENABLE_MOCK=true — وبردو محتاج dashboard key
@app.post("/api/mock-data", dependencies=[Depends(verify_dashboard_key)])
def generate_mock(db: Session = Depends(get_db)):
    if not ENABLE_MOCK:
        # camouflage — العميل ما يعرفش إن الإندبوينت موجود
        raise HTTPException(status_code=404, detail="Not found")
    zones = ["10245", "88321", "55410", "99120"]
    for _ in range(50):
        verdict = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        score = (random.randint(0, 30) if verdict == "valid"
                 else random.randint(70, 100) if verdict == "invalid"
                 else random.randint(40, 69))
        db.add(VisitModel(
            ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones),
            score=score, verdict=verdict, evidence=["Mock Data"],
            country="US", isp="Mock ISP", connection_type="residential",
        ))
    db.commit()
    return {"status": "ok"}

# =========================================================
# DASHBOARD V3.2 — XSS-Safe
# =========================================================
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG Analytics V3.2</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
  <style>body { font-family: 'Cairo', sans-serif; background-color: #f8fafc; color: #1e293b; }</style>
</head>
<body class="flex h-screen overflow-hidden">
  <aside class="w-64 bg-white border-l border-slate-200 hidden md:flex flex-col shadow-sm">
    <div class="p-6 text-2xl font-bold text-indigo-600 border-b border-slate-100">OVG V3.2 🛡️</div>
    <nav class="flex-1 p-4 space-y-2">
      <button onclick="switchPage('dashboard')" class="w-full text-right px-4 py-3 rounded-xl bg-indigo-50 text-indigo-700 font-bold transition">لوحة التحكم</button>
      <button onclick="switchPage('zones')" class="w-full text-right px-4 py-3 rounded-xl text-slate-500 hover:bg-slate-50 hover:text-slate-800 font-semibold transition">تقارير الزونات</button>
    </nav>
  </aside>

  <main class="flex-1 overflow-y-auto p-4 md:p-8">
    <div id="page-dashboard" class="block">
      <h1 class="text-2xl font-bold mb-6 text-slate-800">نظرة عامة</h1>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100"><p class="text-slate-500 text-sm font-semibold mb-1">إجمالي الزيارات</p><p id="kpi-total" class="text-3xl font-bold text-slate-800">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-emerald-500"><p class="text-slate-500 text-sm font-semibold mb-1">زيارات صالحة</p><p id="kpi-valid" class="text-3xl font-bold text-emerald-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-rose-500"><p class="text-slate-500 text-sm font-semibold mb-1">بوتات (Invalid)</p><p id="kpi-invalid" class="text-3xl font-bold text-rose-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-amber-500"><p class="text-slate-500 text-sm font-semibold mb-1">مشبوهة</p><p id="kpi-suspicious" class="text-3xl font-bold text-amber-500">0</p></div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 col-span-1"><h2 class="text-sm font-bold text-slate-700 mb-4">نسبة جودة الترافيك</h2><div class="relative h-48 flex justify-center"><canvas id="qualityChart"></canvas></div></div>
        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 col-span-1 md:col-span-2 overflow-hidden">
          <div class="p-5 border-b border-slate-100 flex justify-between items-center"><h2 class="text-sm font-bold text-slate-700">أحدث الزيارات (Live)</h2><span class="text-xs text-indigo-500 bg-indigo-50 px-2 py-1 rounded">V3.2</span></div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-right">
              <thead class="text-xs text-slate-400 bg-slate-50">
                <tr>
                  <th class="px-2 py-3 text-center">الوقت</th>
                  <th class="px-2 py-3">الزون</th>
                  <th class="px-2 py-3 text-center">الدولة/الشبكة</th>
                  <th class="px-2 py-3 text-center">Score</th>
                  <th class="px-2 py-3 text-center">الحكم</th>
                  <th class="px-2 py-3 text-center">تفاصيل</th>
                </tr>
              </thead>
              <tbody id="live-table" class="divide-y divide-slate-100"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    <div id="page-zones" class="hidden">
      <h1 class="text-2xl font-bold mb-6 text-slate-800">تقارير الزونات</h1>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
        <table class="w-full text-sm text-right">
          <thead class="bg-slate-50 text-slate-400 text-xs"><tr><th class="px-5 py-4">Zone ID</th><th class="px-5 py-4">الزيارات</th><th class="px-5 py-4">نسبة البوتات</th><th class="px-5 py-4">التقييم</th></tr></thead>
          <tbody id="zones-table" class="divide-y divide-slate-100"></tbody>
        </table>
      </div>
    </div>
  </main>

  <div id="details-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50">
      <div class="bg-white rounded-2xl p-6 w-11/12 md:w-1/2 shadow-2xl">
          <h3 class="text-lg font-bold mb-4 text-indigo-700">تفاصيل التحليل (Evidence)</h3>
          <div id="modal-content" class="space-y-2 text-sm text-slate-600 mb-6"></div>
          <button onclick="closeModal()" class="w-full bg-slate-800 text-white py-2 rounded-xl">إغلاق</button>
      </div>
  </div>

  <script>
    // 🔒 FIX #2: المفتاح جاي JSON-encoded من السيرفر — مضمون الهروب
    const KEY = __DASHBOARD_KEY__;
    const Q = KEY ? ("?key=" + encodeURIComponent(KEY)) : "";
    let chartInstance = null;

    // 🔒 FIX #1: esc() لتنقية أي نص قبل وضعه في HTML
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[c]));

    window.visitsData = window.visitsData || {};

    function switchPage(page) {
      document.getElementById('page-dashboard').classList.add('hidden');
      document.getElementById('page-zones').classList.add('hidden');
      document.getElementById('page-' + page).classList.remove('hidden');
      if (page === 'zones') loadZones();
    }

    // 🔒 FIX #1: showDetails بيبني DOM بأمان عبر textContent — لا حقن ممكن
    function showDetails(v) {
      const modal = document.getElementById('details-modal');
      const content = document.getElementById('modal-content');
      content.replaceChildren();

      const addRow = (label, value, cls) => {
        const p = document.createElement('p');
        const b = document.createElement('strong');
        b.textContent = label + ': ';
        p.appendChild(b);
        const s = document.createElement('span');
        s.textContent = (value === null || value === undefined) ? '—' : String(value);
        if (cls) s.className = cls;
        p.appendChild(s);
        content.appendChild(p);
      };

      addRow('Score', v.score, 'text-rose-600 font-bold');
      addRow('Timezone', v.timezone);
      addRow('Hardware', v.hardware);
      addRow('Connection', v.conn_type + ' (ASN: ' + v.asn + ')');
      addRow('VPN/Proxy', v.is_vpn ? 'YES' : 'NO',
             v.is_vpn ? 'text-rose-600 font-bold' : 'text-emerald-600');
      addRow('WebRTC Leak', v.webrtc && v.webrtc !== 'None' ? v.webrtc : 'None');

      if (Array.isArray(v.evidence) && v.evidence.length) {
        const hr = document.createElement('hr'); hr.className = 'my-2'; content.appendChild(hr);
        const ul = document.createElement('ul');
        ul.className = 'list-disc pl-5 space-y-1';
        v.evidence.forEach(t => {
          const li = document.createElement('li');
          li.textContent = String(t);
          ul.appendChild(li);
        });
        content.appendChild(ul);
      } else {
        const p = document.createElement('p');
        p.className = 'text-emerald-600';
        p.textContent = 'زيارة سليمة.';
        content.appendChild(p);
      }

      modal.classList.remove('hidden');
      modal.classList.add('flex');
    }

    function closeModal() {
      document.getElementById('details-modal').classList.add('hidden');
      document.getElementById('details-modal').classList.remove('flex');
    }

    async function loadData() {
      const res = await fetch('/api/stats' + Q); if (!res.ok) return;
      const data = await res.json();
      document.getElementById('kpi-total').innerText = data.total;
      document.getElementById('kpi-valid').innerText = data.valid;
      document.getElementById('kpi-invalid').innerText = data.invalid;
      document.getElementById('kpi-suspicious').innerText = data.suspicious;

      const tbody = document.getElementById('live-table');
      tbody.innerHTML = '';

      // 🔒 FIX #1: كل القيم بتمر على esc() قبل الحقن
      data.recent.forEach(v => {
        const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700'
                    : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700'
                    : 'bg-amber-100 text-amber-700';
        const scoreColor = v.score > 80 ? 'text-rose-600 font-bold'
                         : v.score > 40 ? 'text-amber-600 font-bold'
                         : 'text-emerald-600';

        let netIcon = v.conn_type === 'hosting' ? '🚨 DataCenter' : '🏠 Home';
        if (v.is_vpn) netIcon = '🛡️ VPN';
        if (v.conn_type === 'Unknown') netIcon = '❓ Unknown';
        const netColor = (v.is_vpn || v.conn_type === 'hosting')
          ? 'text-rose-500 font-bold' : 'text-slate-500';

        window.visitsData[v.id] = v;

        tbody.insertAdjacentHTML('beforeend', `
          <tr class="hover:bg-slate-50 transition">
            <td class="px-2 py-3 text-slate-500 text-xs text-center">${esc(v.time)}</td>
            <td class="px-2 py-3 font-semibold text-xs">${esc(v.zone)}</td>
            <td class="px-2 py-3 text-xs text-center">
               <div>${esc(v.country)}</div>
               <div class="${netColor}" style="font-size:10px;">${esc(netIcon)}</div>
            </td>
            <td class="px-2 py-3 ${scoreColor} text-center">${esc(v.score)}</td>
            <td class="px-2 py-3 text-center"><span class="${badge} px-2 py-1 rounded-md text-xs font-bold">${esc(v.verdict)}</span></td>
            <td class="px-2 py-3 text-center">
              <button data-id="${Number(v.id)}" class="details-btn text-indigo-600 hover:underline text-xs">عرض</button>
            </td>
          </tr>`);
      });

      if (chartInstance) chartInstance.destroy();
      chartInstance = new Chart(document.getElementById('qualityChart').getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['Valid', 'Invalid', 'Suspicious'],
          datasets: [{
            data: [data.valid, data.invalid, data.suspicious],
            backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'],
            borderWidth: 0
          }]
        },
        options: {
          cutout: '75%',
          plugins: { legend: { position: 'bottom',
            labels: { usePointStyle: true, boxWidth: 8, font: { size: 11 } } } }
        }
      });
    }

    // 🔒 FIX #1: event delegation بدل inline onclick — لا حقن ممكن
    document.getElementById('live-table').addEventListener('click', (e) => {
      const btn = e.target.closest('.details-btn');
      if (!btn) return;
      const id = Number(btn.dataset.id);
      const visit = window.visitsData[id];
      if (visit) showDetails(visit);
    });

    async function loadZones() {
      const res = await fetch('/api/reports/zones' + Q); if (!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('zones-table');
      tbody.innerHTML = '';
      data.forEach(z => {
        const gradeColor = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700'
                         : z.grade === 'F' ? 'bg-rose-100 text-rose-700'
                         : 'bg-slate-100 text-slate-700';
        // 🔒 FIX #1: esc() على z.zone (قادمة من URL، خطرة)
        tbody.insertAdjacentHTML('beforeend', `
          <tr class="hover:bg-slate-50 transition">
            <td class="px-5 py-4 font-bold text-slate-700">${esc(z.zone)}</td>
            <td class="px-5 py-4 text-slate-600">${esc(z.total)}</td>
            <td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${esc(z.bot_rate)}%</span></td>
            <td class="px-5 py-4"><span class="${gradeColor} px-3 py-1 rounded-lg text-xs font-bold">${esc(z.grade)}</span></td>
          </tr>`);
      });
    }

    loadData();
    setInterval(loadData, 15000);
  </script>
</body>
</html>
"""

# 🔒 FIX #2: fail-closed + JSON-encode للمفتاح
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(key: str = Query(None)):
    if not DASHBOARD_KEY:
        return HTMLResponse(
            content="<h2>Dashboard disabled — set OVG_DASHBOARD_KEY</h2>",
            status_code=403,
        )
    if key != DASHBOARD_KEY:
        return HTMLResponse(content="<h2>Unauthorized</h2>", status_code=401)

    # json.dumps يضمن الهروب الكامل داخل سياق JS string — لا XSS ممكن
    return DASHBOARD_HTML.replace("__DASHBOARD_KEY__", json.dumps(key))