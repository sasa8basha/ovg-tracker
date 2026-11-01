"""
OVG Tracker — Session 4.0 (38 Bot Traps + Advanced Detection)
==============================================================
- 38 فخ متقدم لكشف ZAAMA TURBO وأي بوت متطور
- تحليل تناسق الإشارات (Consistency Analysis)
- Composite rules + trap diversity detection
"""
import ipaddress
import os
import random
import time
import json
from collections import OrderedDict
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Index, Integer, String,
    create_engine, func, case,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ============ CONFIG ============
DATABASE_URL     = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
DASHBOARD_KEY    = os.getenv("OVG_DASHBOARD_KEY", "")
ALLOWED_ORIGINS  = [o.strip() for o in os.getenv("OVG_ORIGINS", "*").split(",") if o.strip()]
TRACK_RATE_PER_MIN = int(os.getenv("OVG_TRACK_RATE", "120"))

# ============ DB ============
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
    trap_count = Column(Integer, default=0)
    fired_traps = Column(JSON, default=list)
    __table_args__ = (
        Index("ix_visits_zone_verdict", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
    )

Base.metadata.create_all(bind=engine)

app = FastAPI(title="OVG Tracker", version="4.0.0")
if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ============ CACHE & RATE LIMIT ============
class TTLCache:
    def __init__(self, maxsize=10000, ttl=3600):
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
    def check(self, key):
        now = time.time()
        entry = self._d.get(key)
        if entry is None or now - entry[1] > self.window:
            self._d[key] = (1, now); self._d.move_to_end(key)
        else:
            self._d[key] = (entry[0] + 1, entry[1]); self._d.move_to_end(key)
        while len(self._d) > self.maxsize: self._d.popitem(last=False)
        if self._d[key][0] > self.max_req:
            raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": str(self.window)})

ip_cache = TTLCache(maxsize=50000, ttl=86400)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)

# ============ HELPERS ============
def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
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

def verify_dashboard_key(request: Request):
    if not DASHBOARD_KEY: return
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if key != DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

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
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v: return v[0]
    except Exception: pass
    return "unknown"

async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {"country": "Local", "isp": "Local ISP", "type": "residential", "asn": "N/A", "security": {}}
    cached = ip_cache.get(ip)
    if cached is not None: return cached
    try:
        import httpx
        async with httpx.AsyncClient() as client:
            res = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,as,proxy,hosting", timeout=3.0)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    is_proxy = data.get("proxy", False)
                    is_hosting = data.get("hosting", False)
                    result = {
                        "country": data.get("country", "Unknown"),
                        "isp": data.get("isp", "Unknown"),
                        "type": "hosting" if (is_proxy or is_hosting) else "residential",
                        "asn": data.get("as", "Unknown").split()[0] if data.get("as") else "Unknown",
                        "security": {"vpn": is_proxy},
                    }
                    ip_cache.set(ip, result); return result
    except Exception: pass
    return {"country": "Unknown", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}}

# ============ 38 TRAPS CONFIG ============
TRAP_WEIGHTS = {
    "T01": 100, "T02": 100, "T03": 100, "T08": 100, "T11": 100,
    "T12": 100, "T16": 100, "T28": 100, "T23": 100,
    "T04": 80, "T05": 80, "T09": 80, "T10": 80, "T18": 80, "T29": 80,
    "T06": 70, "T07": 70, "T17": 70, "T19": 70, "T22": 70,
    "T24": 70, "T30": 70,
    "T13": 60, "T20": 60, "T21": 60, "T35": 60, "T38": 60,
    "T15": 50, "T14": 40, "T25": 40, "T33": 40, "T34": 40,
    "T26": 30, "T27": 30, "T32": 30, "T36": 30, "T37": 30,
    "T31": 20,
}

TRAP_LABELS = {
    "T01": "Worker UA Mismatch", "T02": "Worker Cores Mismatch",
    "T03": "Worker Platform Mismatch", "T04": "Worker Memory Mismatch",
    "T05": "SharedWorker Blocked", "T06": "ServiceWorker Failed",
    "T07": "MessageChannel Blocked", "T08": "Reflect.ownKeys Leak",
    "T09": "Symbol Leak", "T10": "Proxy toString Tampered",
    "T11": "CDP Runtime Detected", "T12": "Automation Stack Trace",
    "T13": "chrome.runtime Missing", "T14": "chrome.csi on Modern Chrome",
    "T15": "prepareStackTrace Tampered", "T16": "Canvas Inconsistency",
    "T17": "Virtual Renderer Detected", "T18": "ImageData/DataURL Mismatch",
    "T19": "measureText Inconsistent", "T20": "WebGL Extensions Mismatch",
    "T21": "OffscreenCanvas Noise", "T22": "SVG Non-deterministic",
    "T23": "getTimezoneOffset Too Slow", "T24": "performance.now Drift",
    "T25": "Intl.DateTimeFormat Too Slow", "T26": "Canvas Timing Anomalous",
    "T27": "rAF Timing Jitter", "T28": "hidden/hasFocus Mismatch",
    "T29": "visibilitychange Faked", "T30": "WebRTC Candidates Leaked",
    "T31": "WebTransport Unusual", "T32": "navigator.connection Inconsistent",
    "T33": "MediaDevices Empty (VM)", "T34": "Battery API Impossible",
    "T35": "Plugins/MimeTypes Mismatch", "T36": "Permissions Inconsistent",
    "T37": "BroadcastChannel Unsynced", "T38": "Speech Voices Empty",
}

CRITICAL_TRAPS = {"T01","T02","T03","T08","T11","T12","T16","T23","T28"}

# ============ ANALYSIS ENGINE v4.0 ============
def analyze_visit(data: dict, ip_info: dict) -> dict:
    score = 0
    evidence = []
    fired_traps = []
    trap_count = 0

    nav = data.get("nav") or {}
    screen = data.get("screen") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    ua = str(nav.get("ua") or "").lower()
    sec = ip_info.get("security", {})

    # Base rules
    if nav.get("webdriver") is True:
        score += 80; evidence.append("WebDriver Flag")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget", "phantom", "bot")):
        score += 90; evidence.append("Suspicious User-Agent")

    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        score += 50; evidence.append("OS Mismatch (Win)")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        score += 50; evidence.append("OS Mismatch (Mac)")

    if sec.get("vpn") is True:
        score += 70; evidence.append("VPN/Proxy Detected")
    conn_type = str(ip_info.get("type", "")).lower()
    if conn_type == "hosting":
        score += 80; evidence.append("Datacenter/Hosting IP")

    webrtc = data.get("webrtc_ip")
    client_ip = data.get("client_ip")
    if webrtc and webrtc != "None" and not _is_private_ip(webrtc):
        if webrtc != client_ip:
            score += 90; evidence.append(f"WebRTC Leak (Real IP: {webrtc})")

    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        score += 60; evidence.append("Missing Canvas FP")
    cores = int(fp.get("hardwareConcurrency") or 0)
    if cores <= 1:
        score += 40; evidence.append(f"Low CPU ({cores})")

    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        score += 30; evidence.append("UTC/Unknown Timezone")

    t_on_page = int(behavior.get("time_on_page_ms") or 0)
    if t_on_page < 800:
        score += 40; evidence.append("Left too fast")
    mouse_var = float(behavior.get("mouse_variance") or 0)
    if events.get("mousemove", 0) > 10 and mouse_var < 1.5:
        score += 50; evidence.append("Robotic Mouse")
    if t_on_page > 3000 and events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30; evidence.append("No Interaction (Zombie)")

    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        score += 60; evidence.append("Virtual Renderer")

    # ===== 38 Traps =====
    traps = fp.get("traps") or {}
    if isinstance(traps, dict):
        for trap_id, trap_data in traps.items():
            if not trap_data: continue
            if isinstance(trap_data, dict):
                fired = bool(trap_data.get("fired"))
                detail = str(trap_data.get("detail", ""))[:120]
            else:
                fired = bool(trap_data)
                detail = ""
            if fired:
                trap_count += 1
                fired_traps.append(trap_id)
                weight = TRAP_WEIGHTS.get(trap_id, 30)
                score += weight
                label = TRAP_LABELS.get(trap_id, trap_id)
                ev = f"[{trap_id}] {label}"
                if detail:
                    ev += f" — {detail}"
                evidence.append(ev)

    # Composite rules
    if CRITICAL_TRAPS & set(fired_traps):
        score = max(score, 100)
    if trap_count >= 3:
        score = max(score, 90)
    if trap_count >= 5:
        score = min(150, score + 20)

    score = min(150, score)
    if score >= 80:
        verdict = "invalid"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "valid"

    return {
        "score": score,
        "verdict": verdict,
        "evidence": evidence,
        "trap_count": trap_count,
        "fired_traps": fired_traps,
    }

# ============ PAYLOAD MODEL ============
class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}
    webrtc_ip: str = "None"

@app.get("/health")
def health(): return {"status": "ok", "version": app.version}

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

    visit = VisitModel(
        ip=client_ip, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"],
        evidence=result["evidence"], os=os_name, device=device, browser=browser,
        country=ip_info["country"], isp=ip_info["isp"],
        timezone=fp.get("timezone", "Unknown"),
        canvas_hash=str(fp.get("canvas_hash", "Unknown"))[:40],
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"], asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"),
        webrtc_ip=payload.webrtc_ip,
        trap_count=result["trap_count"],
        fired_traps=result["fired_traps"],
    )
    try:
        db.add(visit); db.commit()
    except Exception:
        db.rollback(); raise HTTPException(status_code=500, detail="DB write failed")
    return {"status": "success", "verdict": result["verdict"], "trap_count": result["trap_count"]}

# =================================================================
# CONTINUATION — Stats, Zones, Dashboard, Main
# (الصق ده بعد الجزء الأول مباشرة في نفس الملف main.py)
# =================================================================

@app.get("/api/stats", dependencies=[Depends(verify_dashboard_key)])
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(VisitModel.id)).scalar() or 0
    valid = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "valid").scalar() or 0
    invalid = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "invalid").scalar() or 0
    suspicious = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "suspicious").scalar() or 0
    trapped = db.query(func.count(VisitModel.id)).filter(VisitModel.trap_count > 0).scalar() or 0

    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(20).all()
    recent_visits = [{
        "id": v.id,
        "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country,
        "score": v.score, "evidence": v.evidence,
        "timezone": v.timezone, "hardware": v.hardware,
        "conn_type": v.connection_type, "asn": v.asn,
        "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip,
        "trap_count": v.trap_count or 0,
        "fired_traps": v.fired_traps or [],
    } for v in recent]
    return {"total": total, "valid": valid, "invalid": invalid,
            "suspicious": suspicious, "trapped": trapped, "recent": recent_visits}

@app.get("/api/reports/zones", dependencies=[Depends(verify_dashboard_key)])
def get_zone_reports(db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    trapped_expr = func.sum(case((VisitModel.trap_count > 0, 1), else_=0))
    rows = db.query(
        VisitModel.zone_id,
        func.count(VisitModel.id).label("total"),
        invalid_expr.label("invalid"),
        trapped_expr.label("trapped"),
    ).group_by(VisitModel.zone_id).all()
    report = []
    for z in rows:
        total = int(z.total or 0)
        invalid = int(z.invalid or 0)
        trapped = int(z.trapped or 0)
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0.0
        trap_rate = round((trapped / total) * 100, 1) if total > 0 else 0.0
        grade = "A" if bot_rate < 5 else "B" if bot_rate < 15 else "C" if bot_rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": bot_rate,
                       "trap_rate": trap_rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

@app.post("/api/mock-data", dependencies=[Depends(verify_dashboard_key)])
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410", "99120"]
    for _ in range(50):
        verdict = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        score = random.randint(0, 30) if verdict == "valid" else (random.randint(70, 100) if verdict == "invalid" else random.randint(40, 69))
        db.add(VisitModel(
            ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones),
            score=score, verdict=verdict, evidence=["Mock Data"],
            country="US", isp="Mock ISP", connection_type="residential",
            trap_count=random.randint(0, 5) if verdict != "valid" else 0,
        ))
    db.commit()
    return {"status": "ok"}

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG Tracker V4.0 — 38 Traps</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
  <style>body{font-family:'Cairo',sans-serif;background:#f8fafc;color:#1e293b}</style>
</head>
<body class="flex h-screen overflow-hidden">
  <aside class="w-64 bg-white border-l border-slate-200 hidden md:flex flex-col shadow-sm">
    <div class="p-6 text-xl font-bold text-indigo-600 border-b border-slate-100">OVG V4.0 🛡️<span class="block text-xs text-slate-400 font-normal mt-1">38 Bot Traps</span></div>
    <nav class="flex-1 p-4 space-y-2">
      <button onclick="switchPage('dashboard')" class="w-full text-right px-4 py-3 rounded-xl bg-indigo-50 text-indigo-700 font-bold">لوحة التحكم</button>
      <button onclick="switchPage('zones')" class="w-full text-right px-4 py-3 rounded-xl text-slate-500 hover:bg-slate-50 font-semibold">تقارير الزونات</button>
    </nav>
  </aside>
  <main class="flex-1 overflow-y-auto p-4 md:p-8">
    <div id="page-dashboard" class="block">
      <h1 class="text-2xl font-bold mb-6">نظرة عامة — كشف البوتات المتقدم</h1>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
        <div class="bg-white p-5 rounded-2xl shadow-sm border"><p class="text-slate-500 text-xs">إجمالي</p><p id="kpi-total" class="text-3xl font-bold">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-r-4 border-r-emerald-500"><p class="text-slate-500 text-xs">صالحة</p><p id="kpi-valid" class="text-3xl font-bold text-emerald-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-r-4 border-r-rose-500"><p class="text-slate-500 text-xs">بوتات</p><p id="kpi-invalid" class="text-3xl font-bold text-rose-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-r-4 border-r-amber-500"><p class="text-slate-500 text-xs">مشبوهة</p><p id="kpi-suspicious" class="text-3xl font-bold text-amber-500">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-r-4 border-r-violet-500"><p class="text-slate-500 text-xs">فُعّلت فخاخ</p><p id="kpi-trapped" class="text-3xl font-bold text-violet-600">0</p></div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-2xl shadow-sm border">
          <h2 class="text-sm font-bold mb-4">جودة الترافيك</h2>
          <div class="relative h-48 flex justify-center"><canvas id="qualityChart"></canvas></div>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border md:col-span-2 overflow-hidden">
          <div class="p-5 border-b flex justify-between items-center"><h2 class="text-sm font-bold">أحدث الزيارات</h2><span class="text-xs text-indigo-500 bg-indigo-50 px-2 py-1 rounded">V4.0 · 38 Traps</span></div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-right">
              <thead class="text-xs text-slate-400 bg-slate-50"><tr>
                <th class="px-2 py-3">الوقت</th><th class="px-2 py-3">الزون</th>
                <th class="px-2 py-3">الدولة</th><th class="px-2 py-3">Score</th>
                <th class="px-2 py-3">Traps</th><th class="px-2 py-3">الحكم</th><th class="px-2 py-3">تفاصيل</th>
              </tr></thead>
              <tbody id="live-table" class="divide-y divide-slate-100"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    <div id="page-zones" class="hidden">
      <h1 class="text-2xl font-bold mb-6">تقارير الزونات</h1>
      <div class="bg-white rounded-2xl shadow-sm border overflow-hidden">
        <table class="w-full text-sm text-right">
          <thead class="bg-slate-50 text-slate-400 text-xs"><tr>
            <th class="px-5 py-4">Zone</th><th class="px-5 py-4">الزيارات</th>
            <th class="px-5 py-4">% بوتات</th><th class="px-5 py-4">% فخاخ</th><th class="px-5 py-4">التقييم</th>
          </tr></thead>
          <tbody id="zones-table" class="divide-y divide-slate-100"></tbody>
        </table>
      </div>
    </div>
  </main>
  <div id="details-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50 p-4">
    <div class="bg-white rounded-2xl p-6 w-11/12 md:w-2/3 max-h-[90vh] overflow-y-auto shadow-2xl">
      <h3 class="text-lg font-bold mb-4 text-indigo-700">تفاصيل التحليل الكامل</h3>
      <div id="modal-content" class="space-y-2 text-sm text-slate-600 mb-6"></div>
      <button onclick="closeModal()" class="w-full bg-slate-800 text-white py-2 rounded-xl">إغلاق</button>
    </div>
  </div>
  <script>
    const KEY = "__DASHBOARD_KEY__";
    const Q = KEY ? ("?key=" + encodeURIComponent(KEY)) : "";
    let chartInstance = null;
    window.visitsData = {};

    function switchPage(page){
      document.getElementById('page-dashboard').classList.add('hidden');
      document.getElementById('page-zones').classList.add('hidden');
      document.getElementById('page-'+page).classList.remove('hidden');
      if(page==='zones') loadZones();
    }
    function escapeHtml(s){
      if(s===null||s===undefined) return '';
      return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function showDetails(v){
      const modal = document.getElementById('details-modal');
      const content = document.getElementById('modal-content');
      let html = `<div class="grid grid-cols-2 gap-3 mb-4">
        <div><strong>Score:</strong> <span class="text-rose-600 font-bold text-lg">${v.score}</span></div>
        <div><strong>Traps Fired:</strong> <span class="text-violet-600 font-bold text-lg">${v.trap_count || 0}</span></div>
        <div><strong>TZ:</strong> ${escapeHtml(v.timezone)}</div>
        <div><strong>HW:</strong> ${escapeHtml(v.hardware)}</div>
        <div><strong>Conn:</strong> ${escapeHtml(v.conn_type)}</div>
        <div><strong>ASN:</strong> ${escapeHtml(v.asn)}</div>
        <div><strong>VPN:</strong> <span class="${v.is_vpn ? 'text-rose-600 font-bold' : 'text-emerald-600'}">${v.is_vpn ? 'YES' : 'NO'}</span></div>
        <div><strong>WebRTC:</strong> ${escapeHtml(v.webrtc)}</div>
      </div><hr class="my-3"><h4 class="font-bold mb-2">Evidence (${(v.evidence || []).length})</h4>`;
      if(v.evidence && v.evidence.length > 0){
        html += '<ul class="list-disc pl-5 space-y-1.5 max-h-96 overflow-y-auto">' +
          v.evidence.map(e => `<li class="text-xs">${escapeHtml(e)}</li>`).join('') + '</ul>';
      } else {
        html += `<p class="text-emerald-600">زيارة سليمة — لم تُفعل أي فخ.</p>`;
      }
      content.innerHTML = html;
      modal.classList.remove('hidden'); modal.classList.add('flex');
    }
    function closeModal(){
      document.getElementById('details-modal').classList.add('hidden');
      document.getElementById('details-modal').classList.remove('flex');
    }
    async function loadData(){
      const res = await fetch('/api/stats' + Q); if(!res.ok) return;
      const data = await res.json();
      document.getElementById('kpi-total').innerText = data.total;
      document.getElementById('kpi-valid').innerText = data.valid;
      document.getElementById('kpi-invalid').innerText = data.invalid;
      document.getElementById('kpi-suspicious').innerText = data.suspicious;
      document.getElementById('kpi-trapped').innerText = data.trapped || 0;
      const tbody = document.getElementById('live-table'); tbody.innerHTML = '';
      data.recent.forEach(v => {
        window.visitsData[v.id] = v;
        const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700'
                    : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700'
                    : 'bg-amber-100 text-amber-700';
        const scoreColor = v.score > 80 ? 'text-rose-600 font-bold'
                        : v.score > 40 ? 'text-amber-600 font-bold' : 'text-emerald-600';
        let netIcon = v.conn_type === 'hosting' ? '🚨 DC' : '🏠';
        if (v.is_vpn) netIcon = '🛡️ VPN';
        const netColor = (v.is_vpn || v.conn_type === 'hosting') ? 'text-rose-500 font-bold' : 'text-slate-500';
        const trapCount = v.trap_count || 0;
        const trapBadge = trapCount > 0
          ? `<span class="bg-violet-100 text-violet-700 px-2 py-0.5 rounded text-xs font-bold">${trapCount}</span>`
          : '<span class="text-slate-300 text-xs">0</span>';
        tbody.innerHTML += `<tr class="hover:bg-slate-50">
          <td class="px-2 py-3 text-xs text-center text-slate-500">${escapeHtml(v.time)}</td>
          <td class="px-2 py-3 font-semibold text-xs">${escapeHtml(v.zone)}</td>
          <td class="px-2 py-3 text-xs text-center"><div>${escapeHtml(v.country)}</div><div class="${netColor}" style="font-size:10px">${netIcon}</div></td>
          <td class="px-2 py-3 ${scoreColor} text-center">${v.score}</td>
          <td class="px-2 py-3 text-center">${trapBadge}</td>
          <td class="px-2 py-3 text-center"><span class="${badge} px-2 py-1 rounded-md text-xs font-bold">${v.verdict}</span></td>
          <td class="px-2 py-3 text-center"><button data-id="${v.id}" class="view-btn text-indigo-600 hover:underline text-xs">عرض</button></td>
        </tr>`;
      });
      tbody.querySelectorAll('.view-btn').forEach(btn => {
        btn.addEventListener('click', () => showDetails(window.visitsData[btn.dataset.id]));
      });
      if (chartInstance) chartInstance.destroy();
      chartInstance = new Chart(document.getElementById('qualityChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Valid','Invalid','Suspicious'],
          datasets: [{ data: [data.valid, data.invalid, data.suspicious],
            backgroundColor: ['#10b981','#f43f5e','#f59e0b'], borderWidth: 0 }] },
        options: { cutout:'75%', plugins:{ legend:{ position:'bottom', labels:{ usePointStyle:true, boxWidth:8, font:{size:11} } } } }
      });
    }
    async function loadZones(){
      const res = await fetch('/api/reports/zones' + Q); if(!res.ok) return;
      const data = await res.json();
      const tbody = document.getElementById('zones-table'); tbody.innerHTML = '';
      data.forEach(z => {
        const gradeColor = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700'
                        : z.grade === 'F' ? 'bg-rose-100 text-rose-700'
                        : 'bg-slate-100 text-slate-700';
        tbody.innerHTML += `<tr class="hover:bg-slate-50">
          <td class="px-5 py-4 font-bold">${escapeHtml(z.zone)}</td>
          <td class="px-5 py-4">${z.total}</td>
          <td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${z.bot_rate}%</span></td>
          <td class="px-5 py-4"><span class="${z.trap_rate > 30 ? 'text-violet-600 font-bold' : 'text-slate-600'}">${z.trap_rate || 0}%</span></td>
          <td class="px-5 py-4"><span class="${gradeColor} px-3 py-1 rounded-lg text-xs font-bold">${z.grade}</span></td>
        </tr>`;
      });
    }
    loadData(); setInterval(loadData, 15000);
  </script>
</body>
</html>
"""

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(key: str = Query(None)):
    if DASHBOARD_KEY and key != DASHBOARD_KEY:
        return HTMLResponse(content="<h2>Unauthorized</h2>", status_code=401)
    safe_key = (key or "").replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\u003c")
    return DASHBOARD_HTML.replace("__DASHBOARD_KEY__", safe_key)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))