"""
OVG Tracker — Session 2 (Advanced Detection & Fingerprinting)
"""
import ipaddress
import os
import random
import time
from collections import OrderedDict
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import (
    JSON, Column, DateTime, Index, Integer, String,
    case, create_engine, func,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# =========================================================
# CONFIG
# =========================================================
DATABASE_URL         = os.getenv("OVG_DB_URL", "sqlite:///./ovg.db")
DASHBOARD_KEY        = os.getenv("OVG_DASHBOARD_KEY", "") 
ALLOWED_ORIGINS      = [o.strip() for o in os.getenv("OVG_ORIGINS", "*").split(",") if o.strip()]
TRACK_RATE_PER_MIN   = int(os.getenv("OVG_TRACK_RATE", "120"))
GEO_LOOKUP_TIMEOUT   = float(os.getenv("OVG_GEO_TIMEOUT", "2.0"))
GEO_CACHE_TTL        = int(os.getenv("OVG_GEO_TTL", "86400"))
GEO_CACHE_MAX        = int(os.getenv("OVG_GEO_MAX", "50000"))

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
    timezone = Column(String, default="Unknown")      # جديد
    canvas_hash = Column(String, default="Unknown")   # جديد
    hardware = Column(String, default="Unknown")      # جديد

    __table_args__ = (
        Index("ix_visits_zone_verdict", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
    )

Base.metadata.create_all(bind=engine)

# =========================================================
# APP & MIDDLEWARE
# =========================================================
app = FastAPI(title="OVG Tracker", version="2.0.0")

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# =========================================================
# HELPERS (Cache, Rate Limiter, IP, UA)
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
            raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": str(self.window)})

ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError: return False

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
    if key != DASHBOARD_KEY: raise HTTPException(status_code=401, detail="Unauthorized")

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip): return ("Local", "Local ISP")
    cached = ip_cache.get(ip)
    if cached is not None: return cached
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"https://ipwho.is/{ip}", timeout=GEO_LOOKUP_TIMEOUT)
            if res.status_code == 200:
                data = res.json()
                if data.get("success") is True:
                    result = (data.get("country", "Unknown"), (data.get("connection") or {}).get("isp", "Unknown"))
                    ip_cache.set(ip, result)
                    return result
    except Exception: pass
    return ("Unknown", "Unknown")

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
            if k.lower() == "zoneid" and v: return v[0]
    except Exception: pass
    return "unknown"

# =========================================================
# 🧠 THE SMART ANALYSIS ENGINE (Session 2 Core)
# =========================================================
def analyze_visit(data: dict, country: str) -> dict:
    score = 0
    evidence = []
    
    nav = data.get("nav") or {}
    screen = data.get("screen") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    ua = str(nav.get("ua") or "").lower()

    # 1. Headless / Automation Check
    if nav.get("webdriver") is True: 
        score += 80; evidence.append("WebDriver Flag")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90; evidence.append("Suspicious User-Agent")

    # 2. OS Mismatch Check
    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        score += 50; evidence.append("OS Mismatch (Win)")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        score += 50; evidence.append("OS Mismatch (Mac)")

    # 3. Advanced Fingerprinting (Canvas & Audio)
    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        score += 60; evidence.append("Missing Canvas Fingerprint")
    
    # 4. Hardware Check (Virtual Machines usually have 1-2 cores)
    cores = int(fp.get("hardwareConcurrency") or 0)
    mem = int(fp.get("deviceMemory") or 0)
    if cores <= 1:
        score += 40; evidence.append(f"Low CPU Cores ({cores})")
    if mem == 0 and "mobi" not in ua: # 0 means unsupported or hidden VM
        score += 30; evidence.append("Hidden Device Memory")

    # 5. Timezone vs Country Check (VPN / Proxy Detection)
    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        score += 30; evidence.append("UTC/Unknown Timezone")
    elif country != "Unknown" and country != "Local":
        # Heuristic: If country is US but TZ is Egypt/Africa, it's a proxy.
        country_map = {
            "Egypt": ["cairo", "africa"], "US": ["america/new_york", "america/chicago", "america/los_angeles", "america/denver"],
            "UK": ["london", "europe/london"], "SA": ["riyadh", "asia/riyadh"]
        }
        if country in country_map:
            if not any(t in tz for t in country_map[country]):
                score += 60; evidence.append(f"Timezone Mismatch (IP:{country} vs TZ:{tz})")

    # 6. Behavioral Analysis
    t_on_page = int(behavior.get("time_on_page_ms") or 0)
    if t_on_page < 1500: 
        score += 40; evidence.append("Left too fast (<1.5s)")
    
    # Mouse Variance (0 means straight line/robotic, higher is human)
    mouse_var = float(behavior.get("mouse_variance") or 0)
    if events.get("mousemove", 0) > 10 and mouse_var < 1.5:
        score += 50; evidence.append("Robotic Mouse Movement")
    
    if t_on_page > 3000 and events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30; evidence.append("No Interaction (Zombie)")

    # 7. WebGL Renderer (Virtual Machines)
    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen", "microsoft basic render")):
        score += 60; evidence.append("Virtual Renderer")

    # Final Verdict
    score = min(150, score) # Raised cap to 150 for better accuracy
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

@app.get("/health")
def health(): return {"status": "ok", "version": app.version}

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    track_limiter.check(ip)
    zone_id = extract_zone_id(payload.url)
    ua = (payload.nav or {}).get("ua") or ""
    os_name, device, browser = parse_ua(ua)
    country, isp = await get_ip_info(ip)
    
    try: data = payload.model_dump()
    except AttributeError: data = payload.dict()

    # تحليل ذكي مع تمرير الدولة للكشف عن الـ VPN
    result = analyze_visit(data, country)

    fp = data.get("fingerprint") or {}
    tz = fp.get("timezone", "Unknown")
    canvas = str(fp.get("canvas_hash", "Unknown"))[:15] + "..." # Shorten for DB
    hw = f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB"

    visit = VisitModel(
        ip=ip, user_agent=ua, zone_id=zone_id, score=result["score"], verdict=result["verdict"],
        evidence=result["evidence"], os=os_name, device=device, browser=browser,
        country=country, isp=isp, timezone=tz, canvas_hash=canvas, hardware=hw
    )
    try:
        db.add(visit); db.commit()
    except Exception:
        db.rollback(); raise HTTPException(status_code=500, detail="DB write failed")
    return {"status": "success"}

@app.get("/api/stats", dependencies=[Depends(verify_dashboard_key)])
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(VisitModel.id)).scalar() or 0
    valid = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "valid").scalar() or 0
    invalid = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "invalid").scalar() or 0
    suspicious = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "suspicious").scalar() or 0

    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country, "score": v.score,
        "evidence": v.evidence, "timezone": v.timezone, "hardware": v.hardware
    } for v in recent]
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

@app.get("/api/reports/zones", dependencies=[Depends(verify_dashboard_key)])
def get_zone_reports(db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    rows = db.query(VisitModel.zone_id, func.count(VisitModel.id).label("total"), invalid_expr.label("invalid")).group_by(VisitModel.zone_id).all()
    report = []
    for z in rows:
        total, invalid = int(z.total or 0), int(z.invalid or 0)
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0.0
        grade = "A" if bot_rate < 5 else "B" if bot_rate < 15 else "C" if bot_rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": bot_rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

@app.post("/api/mock-data", dependencies=[Depends(verify_dashboard_key)])
def generate_mock(db: Session = Depends(get_db)):
    zones, countries = ["10245", "88321", "55410", "99120"], ["US", "UK", "EG", "SA"]
    for _ in range(50):
        verdict = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        score = random.randint(0, 30) if verdict == "valid" else random.randint(70, 100) if verdict == "invalid" else random.randint(40, 69)
        db.add(VisitModel(ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones), score=score, verdict=verdict, 
                          evidence=["Mock Data"], os="Windows", device="Desktop", browser="Chrome", country=random.choice(countries), isp="Mock ISP", timezone="UTC"))
    db.commit(); return {"status": "ok"}

# =========================================================
# TRACKER JS (Advanced)
# =========================================================
TRACKER_JS = r"""
(function () {
  "use strict";
  var ENDPOINT = "__ENDPOINT__";
  var finalSent = false;
  var startTime = performance.now();
  var events = { mousemove: 0, scroll: 0, click: 0, touchstart: 0 };
  
  var mousePoints = [];
  var mouseVariance = 0;

  document.addEventListener("mousemove", function (e) { 
      events.mousemove++; 
      if (events.mousemove < 100) mousePoints.push({x: e.clientX, y: e.clientY});
  }, { passive: true });
  document.addEventListener("scroll", function () { events.scroll++; }, { passive: true });
  document.addEventListener("click", function () { events.click++; }, { passive: true });
  document.addEventListener("touchstart", function () { events.touchstart++; }, { passive: true });

  function calcVariance() {
      if (mousePoints.length < 10) return 0;
      var slopes = [];
      for (var i = 1; i < mousePoints.length; i++) {
          var dx = mousePoints[i].x - mousePoints[i-1].x;
          var dy = mousePoints[i].y - mousePoints[i-1].y;
          if (dx !== 0) slopes.push(Math.abs(dy/dx));
      }
      if (slopes.length === 0) return 0;
      var sum = slopes.reduce((a,b) => a + b, 0);
      var avg = sum / slopes.length;
      var variance = slopes.reduce((a,b) => a + Math.pow(b - avg, 2), 0) / slopes.length;
      return variance;
  }

  function getCanvasFp() {
    try {
      var c = document.createElement("canvas");
      c.width = 200; c.height = 50;
      var ctx = c.getContext("2d");
      ctx.textBaseline = "top"; ctx.font = "14px Arial"; ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20); ctx.fillStyle = "#069"; ctx.fillText("OVG Secure", 2, 15);
      return c.toDataURL();
    } catch (e) { return "blocked"; }
  }

  function getWebGLFp() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return null;
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return { renderer: gl.getParameter(dbg ? dbg.UNMASKED_RENDERER_WEBGL : gl.RENDERER) };
    } catch (e) { return null; }
  }

  function buildPayload() {
    mouseVariance = calcVariance();
    return {
      url: location.href,
      nav: { ua: navigator.userAgent, webdriver: navigator.webdriver === true, platform: navigator.platform || "" },
      screen: { width: screen.width, height: screen.height },
      fingerprint: {
        webgl: getWebGLFp(), canvas_hash: getCanvasFp(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
      },
      behavior: { events: events, time_on_page_ms: Math.round(performance.now() - startTime), mouse_variance: mouseVariance },
    };
  }

  function send(isFinal) {
    if (isFinal && finalSent) return;
    if (isFinal) finalSent = true;
    try {
      var body = JSON.stringify(buildPayload());
      if (navigator.sendBeacon) {
        if (navigator.sendBeacon(ENDPOINT, new Blob([body], { type: "application/json" }))) return;
      }
      fetch(ENDPOINT, { method: "POST", body: body, keepalive: true, headers: { "Content-Type": "application/json" } }).catch(function(){});
    } catch (e) {}
  }

  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "hidden") send(true); });
  window.addEventListener("pagehide", function () { send(true); });
  setTimeout(function () { send(false); }, 15000); // Ping after 15s
})();
"""

@app.get("/tracker.js")
def serve_tracker(request: Request):
    endpoint = os.getenv("OVG_ENDPOINT") or (str(request.base_url).rstrip("/") + "/api/track")
    return Response(content=TRACKER_JS.replace("__ENDPOINT__", endpoint), media_type="application/javascript")

# =========================================================
# DASHBOARD (UI Updated)
# =========================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG Analytics V2</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
  <style>body { font-family: 'Cairo', sans-serif; background-color: #f8fafc; color: #1e293b; }</style>
</head>
<body class="flex h-screen overflow-hidden">
  <aside class="w-64 bg-white border-l border-slate-200 hidden md:flex flex-col shadow-sm">
    <div class="p-6 text-2xl font-bold text-indigo-600 border-b border-slate-100">OVG V2 🛡️</div>
    <nav class="flex-1 p-4 space-y-2">
      <button onclick="switchPage('dashboard')" class="w-full text-right px-4 py-3 rounded-xl bg-indigo-50 text-indigo-700 font-bold transition">لوحة التحكم</button>
      <button onclick="switchPage('zones')" class="w-full text-right px-4 py-3 rounded-xl text-slate-500 hover:bg-slate-50 hover:text-slate-800 font-semibold transition">تقارير الزونات</button>
    </nav>
  </aside>

  <main class="flex-1 overflow-y-auto p-4 md:p-8">
    <div id="page-dashboard" class="block">
      <h1 class="text-2xl font-bold mb-6 text-slate-800">نظرة عامة (المرحلة 2)</h1>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100">
          <p class="text-slate-500 text-sm font-semibold mb-1">إجمالي الزيارات</p>
          <p id="kpi-total" class="text-3xl font-bold text-slate-800">0</p>
        </div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-emerald-500">
          <p class="text-slate-500 text-sm font-semibold mb-1">زيارات صالحة</p>
          <p id="kpi-valid" class="text-3xl font-bold text-emerald-600">0</p>
        </div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-rose-500">
          <p class="text-slate-500 text-sm font-semibold mb-1">بوتات (Invalid)</p>
          <p id="kpi-invalid" class="text-3xl font-bold text-rose-600">0</p>
        </div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-amber-500">
          <p class="text-slate-500 text-sm font-semibold mb-1">مشبوهة</p>
          <p id="kpi-suspicious" class="text-3xl font-bold text-amber-500">0</p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 col-span-1">
          <h2 class="text-sm font-bold text-slate-700 mb-4">نسبة جودة الترافيك</h2>
          <div class="relative h-48 flex justify-center"><canvas id="qualityChart"></canvas></div>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 col-span-1 md:col-span-2 overflow-hidden">
          <div class="p-5 border-b border-slate-100 flex justify-between items-center">
              <h2 class="text-sm font-bold text-slate-700">أحدث الزيارات (Live)</h2>
              <span class="text-xs text-indigo-500 bg-indigo-50 px-2 py-1 rounded">دقة عالية V2</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-right">
              <thead class="text-xs text-slate-400 bg-slate-50">
                <tr><th class="px-4 py-3">الوقت</th><th class="px-4 py-3">الزون</th><th class="px-4 py-3">الدولة</th><th class="px-4 py-3">Score</th><th class="px-4 py-3">الحكم</th><th class="px-4 py-3">التفاصيل</th></tr>
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
          <thead class="bg-slate-50 text-slate-400 text-xs">
            <tr><th class="px-5 py-4">Zone ID</th><th class="px-5 py-4">الزيارات</th><th class="px-5 py-4">نسبة البوتات</th><th class="px-5 py-4">التقييم</th></tr>
          </thead>
          <tbody id="zones-table" class="divide-y divide-slate-100"></tbody>
        </table>
      </div>
    </div>
  </main>

  <!-- Modal for Details -->
  <div id="details-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50">
      <div class="bg-white rounded-2xl p-6 w-11/12 md:w-1/2 shadow-2xl">
          <h3 class="text-lg font-bold mb-4 text-indigo-700">تفاصيل التحليل (Evidence)</h3>
          <div id="modal-content" class="space-y-2 text-sm text-slate-600 mb-6"></div>
          <button onclick="closeModal()" class="w-full bg-slate-800 text-white py-2 rounded-xl">إغلاق</button>
      </div>
  </div>

  <script>
    const KEY = "__DASHBOARD_KEY__";
    const Q = KEY ? ("?key=" + encodeURIComponent(KEY)) : "";
    let chartInstance = null;

    function switchPage(page) {
      document.getElementById('page-dashboard').classList.add('hidden');
      document.getElementById('page-zones').classList.add('hidden');
      document.getElementById('page-' + page).classList.remove('hidden');
      if (page === 'zones') loadZones();
    }

    function showDetails(evidence, score, tz, hw) {
        const modal = document.getElementById('details-modal');
        const content = document.getElementById('modal-content');
        let html = `<p><strong>Score:</strong> <span class="text-rose-600 font-bold">${score}</span></p>`;
        html += `<p><strong>Timezone:</strong> ${tz}</p>`;
        html += `<p><strong>Hardware:</strong> ${hw}</p>`;
        html += `<hr class="my-2">`;
        if (evidence && evidence.length > 0) {
            html += `<ul class="list-disc pl-5 space-y-1">` + evidence.map(e => `<li>${e}</li>`).join('') + `</ul>`;
        } else {
            html += `<p class="text-emerald-600">لا توجد أسباب للمنع (زيارة سليمة).</p>`;
        }
        content.innerHTML = html;
        modal.classList.remove('hidden'); modal.classList.add('flex');
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

      const tbody = document.getElementById('live-table'); tbody.innerHTML = '';
      data.recent.forEach(v => {
        const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700' : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700';
        const scoreColor = v.score > 80 ? 'text-rose-600 font-bold' : v.score > 40 ? 'text-amber-600 font-bold' : 'text-emerald-600';
        window.visitsData = window.visitsData || {};
        window.visitsData[v.id] = v;

        tbody.innerHTML += `<tr class="hover:bg-slate-50 transition">
          <td class="px-4 py-3 text-slate-500">${v.time}</td>
          <td class="px-4 py-3 font-semibold">${v.zone}</td>
          <td class="px-4 py-3 text-slate-500">${v.country}</td>
          <td class="px-4 py-3 ${scoreColor}">${v.score}</td>
          <td class="px-4 py-3"><span class="${badge} px-2.5 py-1 rounded-md text-xs font-bold">${v.verdict}</span></td>
          <td class="px-4 py-3"><button onclick="showDetails(window.visitsData[${v.id}].evidence, ${v.score}, '${v.timezone}', '${v.hardware}')" class="text-indigo-600 hover:underline text-xs">عرض</button></td>
        </tr>`;
      });

      if (chartInstance) chartInstance.destroy();
      chartInstance = new Chart(document.getElementById('qualityChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: ['Valid', 'Invalid', 'Suspicious'], datasets: [{ data: [data.valid, data.invalid, data.suspicious], backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'], borderWidth: 0 }] },
        options: { cutout: '75%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, font: { size: 11 } } } } }
      });
    }

    async function loadZones() {
      const res = await fetch('/api/reports/zones' + Q); if (!res.ok) return;
      const data = await res.json(); const tbody = document.getElementById('zones-table'); tbody.innerHTML = '';
      data.forEach(z => {
        const gradeColor = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700' : z.grade === 'F' ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-700';
        tbody.innerHTML += `<tr class="hover:bg-slate-50 transition">
          <td class="px-5 py-4 font-bold text-slate-700">${z.zone}</td>
          <td class="px-5 py-4 text-slate-600">${z.total}</td>
          <td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${z.bot_rate}%</span></td>
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
        return HTMLResponse(content="<h2>Unauthorized</h2><p>Add ?key=YOUR_KEY</p>", status_code=401)
    return DASHBOARD_HTML.replace("__DASHBOARD_KEY__", key or "")