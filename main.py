"""
OVG Tracker — Session 1 (hardening)
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
DASHBOARD_KEY        = os.getenv("OVG_DASHBOARD_KEY", "")     # "" = disabled (DEV ONLY)
ALLOWED_ORIGINS      = [o.strip() for o in os.getenv("OVG_ORIGINS", "*").split(",") if o.strip()]
TRACK_RATE_PER_MIN   = int(os.getenv("OVG_TRACK_RATE", "120"))
GEO_LOOKUP_TIMEOUT   = float(os.getenv("OVG_GEO_TIMEOUT", "2.0"))
GEO_CACHE_TTL        = int(os.getenv("OVG_GEO_TTL", "86400"))
GEO_CACHE_MAX        = int(os.getenv("OVG_GEO_MAX", "50000"))

# =========================================================
# DB
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

    __table_args__ = (
        Index("ix_visits_zone_verdict", "zone_id", "verdict"),
        Index("ix_visits_ip_timestamp", "ip", "timestamp"),
    )


Base.metadata.create_all(bind=engine)

# =========================================================
# APP + CORS
# =========================================================
app = FastAPI(title="OVG Tracker", version="1.1.0")

if ALLOWED_ORIGINS == ["*"]:
    # Wildcard + credentials لا يعملان معًا حسب الـ spec
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# =========================================================
# Helpers: TTL Cache + Rate Limiter + IP + Auth
# =========================================================
class TTLCache:
    def __init__(self, maxsize: int = 10000, ttl: int = 3600):
        self.maxsize = maxsize
        self.ttl = ttl
        self._data: "OrderedDict[str, tuple[float, object]]" = OrderedDict()

    def get(self, key):
        entry = self._data.get(key)
        if entry is None:
            return None
        value, ts = entry
        if time.time() - ts > self.ttl:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key, value):
        self._data[key] = (value, time.time())
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)


class WindowRateLimiter:
    def __init__(self, max_req: int = 120, window: int = 60, maxsize: int = 100000):
        self.max_req = max_req
        self.window = window
        self.maxsize = maxsize
        self._d: "OrderedDict[str, tuple[int, float]]" = OrderedDict()

    def check(self, key: str):
        now = time.time()
        entry = self._d.get(key)
        if entry is None or now - entry[1] > self.window:
            self._d[key] = (1, now)
            self._d.move_to_end(key)
        else:
            count, start = entry
            self._d[key] = (count + 1, start)
            self._d.move_to_end(key)
        while len(self._d) > self.maxsize:
            self._d.popitem(last=False)
        if self._d[key][0] > self.max_req:
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(self.window)},
            )


ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """يقرأ الـ IP الحقيقي من الـ proxy headers."""
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


def verify_dashboard_key(request: Request):
    if not DASHBOARD_KEY:
        return  # معطّل (dev)
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if key != DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return ("Local", "Local ISP")
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"https://ipwho.is/{ip}", timeout=GEO_LOOKUP_TIMEOUT)
            if res.status_code == 200:
                data = res.json()
                if data.get("success") is True:
                    result = (
                        data.get("country", "Unknown"),
                        (data.get("connection") or {}).get("isp", "Unknown"),
                    )
                    ip_cache.set(ip, result)
                    return result
    except Exception:
        pass
    return ("Unknown", "Unknown")


def parse_ua(ua: str):
    ua_l = (ua or "").lower()
    if "mobi" in ua_l:
        device = "Mobile"
    elif "tablet" in ua_l or "ipad" in ua_l:
        device = "Tablet"
    else:
        device = "Desktop"

    if "windows nt" in ua_l:
        os_name = "Windows"
    elif "mac os" in ua_l or "macintosh" in ua_l:
        os_name = "macOS"
    elif "android" in ua_l:
        os_name = "Android"
    elif "iphone" in ua_l or "ipad" in ua_l or "ios" in ua_l:
        os_name = "iOS"
    elif "linux" in ua_l:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if "edg/" in ua_l or "edge/" in ua_l:
        browser = "Edge"
    elif "chrome" in ua_l and "chromium" not in ua_l:
        browser = "Chrome"
    elif "firefox" in ua_l:
        browser = "Firefox"
    elif "safari" in ua_l and "chrome" not in ua_l:
        browser = "Safari"
    else:
        browser = "Unknown"

    return os_name, device, browser


def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        qs = parse_qs(parsed.query)
        for k, v in qs.items():
            if k.lower() == "zoneid" and v:
                return v[0]
    except Exception:
        pass
    return "unknown"

# =========================================================
# ANALYSIS ENGINE (light fixes only — depth in Session 2)
# =========================================================
def analyze_visit(data: dict) -> dict:
    score = 0
    evidence = []

    nav = data.get("nav") or {}
    screen = data.get("screen") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}

    ua = str(nav.get("ua") or "").lower()
    platform = str(nav.get("platform") or "").lower()

    # Headless / automation
    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver Flag")

    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90
        evidence.append("Suspicious UA")

    # OS mismatch — الـ bug القديم: "win" كانت بتـmatch "darwin"
    is_windows_ua = "windows nt" in ua
    is_mac_ua = "mac os" in ua or "macintosh" in ua
    if is_windows_ua and platform and "win" not in platform:
        score += 50
        evidence.append("OS Mismatch (Win UA)")
    if is_mac_ua and platform and "mac" not in platform:
        score += 50
        evidence.append("OS Mismatch (Mac UA)")

    # Screen
    w = int(screen.get("width") or 0)
    h = int(screen.get("height") or 0)
    if w == 0 or h == 0:
        score += 40
        evidence.append("Zero Screen Size")

    # WebGL renderer
    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen", "microsoft basic render")):
        score += 60
        evidence.append("Virtual Renderer")

    # Timezone (خفيف — Session 2 هيوسّعه)
    tz = str(fp.get("timezone") or "")
    if tz in ("UTC", "Etc/UTC", "Etc/GMT"):
        score += 15
        evidence.append("UTC Timezone")

    # Behavior
    t_on_page = int(behavior.get("time_on_page_ms") or 0)
    if t_on_page < 1000:
        score += 40
        evidence.append("Left <1s")

    # no-interaction بس لو المستخدم قعد وقت كافي
    if t_on_page > 3000:
        has_move = int(events.get("mousemove") or 0) > 0
        has_touch = int(events.get("touchstart") or 0) > 0
        has_click = int(events.get("click") or 0) > 0
        if not has_move and not has_touch and not has_click:
            score += 30
            evidence.append("No Interaction")

    score = min(100, score)
    verdict = "invalid" if score >= 70 else "suspicious" if score >= 30 else "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}

# =========================================================
# MODELS
# =========================================================
class TrackPayload(BaseModel):
    url: str
    nav: dict
    fingerprint: dict
    behavior: dict
    screen: dict = {}

# =========================================================
# ROUTES
# =========================================================
@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}


@app.get("/")
def read_root():
    return {"status": "OVG Server is Running", "version": app.version}


@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    ip = get_client_ip(request)
    track_limiter.check(ip)

    zone_id = extract_zone_id(payload.url)
    ua = (payload.nav or {}).get("ua") or ""
    os_name, device, browser = parse_ua(ua)
    country, isp = await get_ip_info(ip)

    try:
        data = payload.model_dump()
    except AttributeError:
        data = payload.dict()

    result = analyze_visit(data)

    visit = VisitModel(
        ip=ip,
        user_agent=ua,
        zone_id=zone_id,
        score=result["score"],
        verdict=result["verdict"],
        evidence=result["evidence"],
        os=os_name,
        device=device,
        browser=browser,
        country=country,
        isp=isp,
    )
    try:
        db.add(visit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="DB write failed")
    return {"status": "success"}


@app.get("/api/stats", dependencies=[Depends(verify_dashboard_key)])
def get_stats(db: Session = Depends(get_db)):
    total      = db.query(func.count(VisitModel.id)).scalar() or 0
    valid      = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "valid").scalar() or 0
    invalid    = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "invalid").scalar() or 0
    suspicious = db.query(func.count(VisitModel.id)).filter(VisitModel.verdict == "suspicious").scalar() or 0

    recent = db.query(VisitModel).order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [
        {
            "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
            "zone": v.zone_id,
            "verdict": v.verdict,
            "country": v.country,
            "device": v.device,
            "os": v.os,
        }
        for v in recent
    ]
    return {
        "total": total, "valid": valid, "invalid": invalid,
        "suspicious": suspicious, "recent": recent_visits,
    }


@app.get("/api/reports/zones", dependencies=[Depends(verify_dashboard_key)])
def get_zone_reports(db: Session = Depends(get_db)):
    # ⚠️ func.iif لم تكن تعمل على SQLite — استبدلناها بـ case()
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    rows = (
        db.query(
            VisitModel.zone_id,
            func.count(VisitModel.id).label("total"),
            invalid_expr.label("invalid"),
        )
        .group_by(VisitModel.zone_id)
        .all()
    )
    report = []
    for z in rows:
        total = int(z.total or 0)
        invalid = int(z.invalid or 0)
        bot_rate = round((invalid / total) * 100, 1) if total > 0 else 0.0
        grade = "A" if bot_rate < 5 else "B" if bot_rate < 15 else "C" if bot_rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": bot_rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report


@app.post("/api/mock-data", dependencies=[Depends(verify_dashboard_key)])
def generate_mock(db: Session = Depends(get_db)):
    zones = ["10245", "88321", "55410", "99120"]
    countries = ["US", "UK", "EG", "SA"]
    try:
        for _ in range(150):
            verdict = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
            score = (
                random.randint(0, 30) if verdict == "valid"
                else random.randint(70, 100) if verdict == "invalid"
                else random.randint(30, 69)
            )
            db.add(VisitModel(
                ip="127.0.0.1", user_agent="Mock",
                zone_id=random.choice(zones), score=score, verdict=verdict,
                evidence=["Mock"],
                os=random.choice(["Windows", "Android", "iOS"]),
                device=random.choice(["Desktop", "Mobile"]),
                browser="Chrome",
                country=random.choice(countries), isp="Mock ISP",
            ))
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Mock generation failed")
    return {"status": "ok"}

# =========================================================
# TRACKER JS (served dynamically)
# =========================================================
TRACKER_JS = r"""
(function () {
  "use strict";
  var ENDPOINT = "__ENDPOINT__";
  var finalSent = false;
  var startTime = performance.now();
  var events = { mousemove: 0, scroll: 0, click: 0, touchstart: 0 };

  document.addEventListener("mousemove", function () { events.mousemove++; }, { passive: true });
  document.addEventListener("scroll",    function () { events.scroll++;    }, { passive: true });
  document.addEventListener("click",     function () { events.click++;     }, { passive: true });
  document.addEventListener("touchstart",function () { events.touchstart++;}, { passive: true });

  function getWebGLFp() {
    try {
      var c = document.createElement("canvas");
      var gl = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!gl) return null;
      var dbg = gl.getExtension("WEBGL_debug_renderer_info");
      return { renderer: gl.getParameter(dbg ? dbg.UNMASKED_RENDERER_WEBGL : gl.RENDERER) };
    } catch (e) { return null; }
  }

  function getTimezone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; }
    catch (e) { return "UTC"; }
  }

  function buildPayload() {
    return {
      url: location.href,
      nav: {
        ua: navigator.userAgent,
        webdriver: navigator.webdriver === true,
        platform: navigator.platform || "",
        languages: navigator.languages || [],
      },
      screen: { width: screen.width, height: screen.height },
      fingerprint: {
        webgl: getWebGLFp(),
        timezone: getTimezone(),
        timezoneOffset: new Date().getTimezoneOffset(),
        hardwareConcurrency: navigator.hardwareConcurrency || 0,
        deviceMemory: navigator.deviceMemory || 0,
      },
      behavior: {
        events: events,
        time_on_page_ms: Math.round(performance.now() - startTime),
      },
    };
  }

  function post(body) {
    try {
      if (navigator.sendBeacon) {
        var blob = new Blob([body], { type: "application/json" });
        if (navigator.sendBeacon(ENDPOINT, blob)) return;
      }
    } catch (e) {}
    try {
      fetch(ENDPOINT, {
        method: "POST",
        body: body,
        keepalive: true,
        headers: { "Content-Type": "application/json" },
      }).catch(function () {});
    } catch (e) {}
  }

  function send(isFinal) {
    if (isFinal && finalSent) return;
    if (isFinal) finalSent = true;
    try { post(JSON.stringify(buildPayload())); } catch (e) {}
  }

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") send(true);
  });
  window.addEventListener("pagehide", function () { send(true); });

  setTimeout(function () { send(false); }, 15000);
})();
"""


@app.get("/tracker.js")
def serve_tracker(request: Request):
    endpoint = os.getenv("OVG_ENDPOINT") or (str(request.base_url).rstrip("/") + "/api/track")
    js = TRACKER_JS.replace("__ENDPOINT__", endpoint)
    return Response(content=js, media_type="application/javascript")

# =========================================================
# DASHBOARD
# =========================================================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG Analytics</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" rel="stylesheet">
  <style>body { font-family: 'Cairo', sans-serif; background-color: #f8fafc; color: #1e293b; }</style>
</head>
<body class="flex h-screen overflow-hidden">
  <aside class="w-64 bg-white border-l border-slate-200 hidden md:flex flex-col shadow-sm">
    <div class="p-6 text-2xl font-bold text-indigo-600 border-b border-slate-100">OVG Analytics</div>
    <nav class="flex-1 p-4 space-y-2">
      <button onclick="switchPage('dashboard')" class="w-full text-right px-4 py-3 rounded-xl bg-indigo-50 text-indigo-700 font-bold transition">لوحة التحكم</button>
      <button onclick="switchPage('zones')" class="w-full text-right px-4 py-3 rounded-xl text-slate-500 hover:bg-slate-50 hover:text-slate-800 font-semibold transition">تقارير الزونات</button>
    </nav>
    <div class="p-4 border-t border-slate-100">
      <button onclick="generateMock()" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl text-sm font-bold shadow-md shadow-indigo-200 transition">توليد بيانات تجريبية</button>
    </div>
  </aside>

  <main class="flex-1 overflow-y-auto p-4 md:p-8">
    <div id="page-dashboard" class="block">
      <h1 class="text-2xl font-bold mb-6 text-slate-800">نظرة عامة</h1>
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
          <div class="relative h-48 flex justify-center">
            <canvas id="qualityChart"></canvas>
          </div>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 col-span-1 md:col-span-2 overflow-hidden">
          <div class="p-5 border-b border-slate-100"><h2 class="text-sm font-bold text-slate-700">أحدث الزيارات (Live)</h2></div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-right">
              <thead class="text-xs text-slate-400 bg-slate-50">
                <tr><th class="px-4 py-3">الوقت</th><th class="px-4 py-3">الزون</th><th class="px-4 py-3">الدولة</th><th class="px-4 py-3">الحكم</th></tr>
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

    async function generateMock() {
      await fetch('/api/mock-data' + Q, { method: 'POST' });
      loadData();
    }

    async function loadData() {
      const res = await fetch('/api/stats' + Q);
      if (!res.ok) { console.error('stats failed', res.status); return; }
      const data = await res.json();
      document.getElementById('kpi-total').innerText = data.total;
      document.getElementById('kpi-valid').innerText = data.valid;
      document.getElementById('kpi-invalid').innerText = data.invalid;
      document.getElementById('kpi-suspicious').innerText = data.suspicious;

      const tbody = document.getElementById('live-table');
      tbody.innerHTML = '';
      data.recent.forEach(v => {
        const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700'
                    : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700'
                    : 'bg-amber-100 text-amber-700';
        tbody.innerHTML += `<tr class="hover:bg-slate-50 transition">
          <td class="px-4 py-3 text-slate-500">${v.time}</td>
          <td class="px-4 py-3 font-semibold">${v.zone}</td>
          <td class="px-4 py-3 text-slate-500">${v.country}</td>
          <td class="px-4 py-3"><span class="${badge} px-2.5 py-1 rounded-md text-xs font-bold">${v.verdict}</span></td>
        </tr>`;
      });

      if (chartInstance) chartInstance.destroy();
      const ctx = document.getElementById('qualityChart').getContext('2d');
      chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Valid', 'Invalid', 'Suspicious'],
          datasets: [{ data: [data.valid, data.invalid, data.suspicious],
            backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'], borderWidth: 0 }]
        },
        options: { cutout: '75%', plugins: { legend: { position: 'bottom',
          labels: { usePointStyle: true, boxWidth: 8, font: { size: 11 } } } } }
      });
    }

    async function loadZones() {
      const res = await fetch('/api/reports/zones' + Q);
      if (!res.ok) { console.error('zones failed', res.status); return; }
      const data = await res.json();
      const tbody = document.getElementById('zones-table');
      tbody.innerHTML = '';
      data.forEach(z => {
        const gradeColor = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700'
                        : z.grade === 'F' ? 'bg-rose-100 text-rose-700'
                        : 'bg-slate-100 text-slate-700';
        tbody.innerHTML += `<tr class="hover:bg-slate-50 transition">
          <td class="px-5 py-4 font-bold text-slate-700">${z.zone}</td>
          <td class="px-5 py-4 text-slate-600">${z.total}</td>
          <td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${z.bot_rate}%</span></td>
          <td class="px-5 py-4"><span class="${gradeColor} px-3 py-1 rounded-lg text-xs font-bold">${z.grade}</span></td>
        </tr>`;
      });
    }

    loadData();
    setInterval(loadData, 15000);
  </script>
</body>
</html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(key: str = Query(None)):
    if DASHBOARD_KEY and key != DASHBOARD_KEY:
        return HTMLResponse(
            content="<html><body style='font-family:sans-serif;padding:40px;text-align:center;'>"
                    "<h2>Unauthorized</h2><p>Add <code>?key=YOUR_DASHBOARD_KEY</code> to the URL.</p>"
                    "</body></html>",
            status_code=401,
        )
    return DASHBOARD_HTML.replace("__DASHBOARD_KEY__", key or "")
