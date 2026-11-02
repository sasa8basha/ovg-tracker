"""
OVG Tracker — Session 6.0 (Enterprise Bot Detection Engine)
"""
import json
import random
import os
import csv
import io
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import case, func, desc
from sqlalchemy.orm import Session

# =========================================================
# LOCAL IMPORTS
# =========================================================
from config import (
    DASHBOARD_KEY, ALLOWED_ORIGINS, MAX_SITES_PER_USER,
    SESSION_COOKIE, SESSION_TTL, HEX_KEY_RE, USERNAME_RE
)
from database import engine, SessionLocal, Base, get_db
from models import UserModel, SiteModel, VisitModel
from utils import (
    get_client_ip, safe_origin, track_limiter, signup_limiter, login_limiter
)
from auth import (
    hash_password, verify_password, make_token, _optional_user, 
    current_user, bootstrap_admin
)
from analysis import (
    get_ip_info, parse_ua, extract_zone_id, new_site_key, analyze_visit
)

Base.metadata.create_all(bind=engine)
bootstrap_admin()

app = FastAPI(title="OVG Tracker", version="6.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

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

# =========================================================
# AUTH & SITES ROUTES (مختصرة لعدم الإطالة - نفس النسخة 5)
# =========================================================
@app.post("/api/auth/signup")
def signup(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request); signup_limiter.check(client_ip)
    if not USERNAME_RE.match(payload.username.strip()): raise HTTPException(400, "اسم المستخدم غير صالح")
    if len(payload.password) < 6: raise HTTPException(400, "كلمة المرور قصيرة")
    if db.query(UserModel).filter(UserModel.username == payload.username.strip()).first(): raise HTTPException(400, "مستخدم بالفعل")
    u = UserModel(username=payload.username.strip(), password_hash=hash_password(payload.password))
    db.add(u); db.commit(); db.refresh(u)
    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/login")
def login(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request); login_limiter.check(client_ip)
    u = db.query(UserModel).filter(UserModel.username == payload.username.strip()).first()
    if not u or not verify_password(payload.password, u.password_hash): raise HTTPException(401, "بيانات خاطئة")
    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/logout")
def logout(response: Response): response.delete_cookie(SESSION_COOKIE, path="/"); return {"ok": True}

@app.get("/api/auth/me")
def me(user: UserModel = Depends(current_user)): return {"id": user.id, "username": user.username}

@app.get("/api/sites")
def list_sites(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    sites = (db.query(SiteModel).filter(SiteModel.user_id == user.id).order_by(SiteModel.created_at.desc()).all())
    if not sites: return []
    ids = [s.id for s in sites]
    stats = db.query(VisitModel.site_id, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"), func.sum(case((VisitModel.verdict.in_(["invalid", "high_risk"]), 1), else_=0)).label("invalid"), func.max(VisitModel.timestamp).label("last")).filter(VisitModel.site_id.in_(ids)).group_by(VisitModel.site_id).all()
    smap = {r.site_id: r for r in stats}
    return [{"id": s.id, "name": s.name, "domain": s.domain, "site_key": s.site_key, "total": int(smap[s.id].total or 0) if s.id in smap else 0, "valid": int(smap[s.id].valid or 0) if s.id in smap else 0, "invalid": int(smap[s.id].invalid or 0) if s.id in smap else 0, "last_visit": smap[s.id].last.isoformat() if s.id in smap and smap[s.id].last else None, "created_at": s.created_at.isoformat() if s.created_at else None} for s in sites]

@app.post("/api/sites")
def create_site(payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    if db.query(SiteModel).filter(SiteModel.user_id == user.id).count() >= MAX_SITES_PER_USER: raise HTTPException(400, "الحد الأقصى للمواقع")
    site = SiteModel(user_id=user.id, name=payload.name.strip(), domain=payload.domain.strip(), site_key=new_site_key())
    db.add(site); db.commit(); db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}

@app.patch("/api/sites/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    site.name = payload.name.strip(); site.domain = payload.domain.strip()[:253]; db.commit(); return {"ok": True}

@app.delete("/api/sites/{site_id}")
def delete_site(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    db.query(VisitModel).filter(VisitModel.site_id == site.id).delete(); db.delete(site); db.commit(); return {"ok": True}

@app.post("/api/sites/{site_id}/rotate-key")
def rotate_key(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    site.site_key = new_site_key(); db.commit(); return {"site_key": site.site_key}

def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key: raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key, SiteModel.user_id == user.id).first()
    if not s: raise HTTPException(404, "الموقع غير موجود")
    return s

# =========================================================
# UPGRADED TRACKER TEMPLATE
# =========================================================
TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  var SITE_KEY = '__OVG_SITE_KEY__';
  var ENDPOINT = '__OVG_ENDPOINT__';
  var SEND_DELAY_MS = 4500; // وقت أطول عشان نجمع بيانات أكتر
  var WEBRTC_TIMEOUT = 1500;

  var startTime = Date.now();
  var mousemoves = 0, touchstarts = 0, clicks = 0, scrolls = 0;
  var mouseX = [], mouseY = [];
  var mouseTimestamps = [];
  var sent = false;
  
  // Timing metrics
  var timeToFirstMove = 0, timeToFirstClick = 0;
  var lastMouseTime = 0;

  document.addEventListener('mousemove', function (e) {
    var now = Date.now();
    if (mousemoves === 0) timeToFirstMove = now - startTime;
    
    mousemoves++;
    mouseX.push(e.clientX); mouseY.push(e.clientY);
    mouseTimestamps.push(now);
    
    if (mouseX.length > 200) { 
      mouseX.shift(); mouseY.shift(); mouseTimestamps.shift(); 
    }
    
    lastMouseTime = now;
  }, { passive: true });

  document.addEventListener('touchstart', function () { touchstarts++; }, { passive: true });
  document.addEventListener('click', function () { 
    if (clicks === 0) timeToFirstClick = Date.now() - startTime;
    clicks++; 
  }, { passive: true });
  document.addEventListener('scroll', function () { scrolls++; }, { passive: true });

  // حساب حركة الماوس (Curvature & Speed)
  function analyzeMouse() {
    if (mouseX.length < 3) return { avg_speed: 0, curvature: 0, pauses: 0 };
    
    var totalDist = 0, totalTime = 0, pauses = 0;
    var dirChanges = 0;
    var lastAngle = null;

    for (var i = 1; i < mouseX.length; i++) {
      var dx = mouseX[i] - mouseX[i-1];
      var dy = mouseY[i] - mouseY[i-1];
      var dt = mouseTimestamps[i] - mouseTimestamps[i-1];
      
      var dist = Math.sqrt(dx*dx + dy*dy);
      totalDist += dist;
      if (dt > 0) totalTime += dt;
      if (dt > 500) pauses++; // توقف أكتر من نص ثانية

      // حساب زاوية الحركة
      var angle = Math.atan2(dy, dx);
      if (lastAngle !== null) {
        var angleDiff = Math.abs(angle - lastAngle);
        if (angleDiff > 0.5) dirChanges++;
      }
      lastAngle = angle;
    }

    var avgSpeed = totalTime > 0 ? (totalDist / (totalTime / 1000)) : 0;
    // الـ Curvature: نسبة تغيير الاتجاه بالنسبة لعدد الحركات. البشر بغيروا اتجاههم كتير.
    var curvature = mousemoves > 1 ? (dirChanges / mousemoves) : 0;
    
    return { 
      avg_speed: Math.round(avgSpeed), 
      curvature: Number(curvature.toFixed(2)), 
      pauses: pauses 
    };
  }

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
      return { renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'), vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown') };
    } catch (e) { return { renderer: 'blocked', vendor: 'blocked' }; }
  }

  function getTimezone() {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch (e) { return 'Unknown'; }
  }

  function buildPayload(webrtc) {
    var mouseStats = analyzeMouse();
    return {
      url: location.href,
      site_key: SITE_KEY,
      nav: { ua: navigator.userAgent, platform: navigator.platform || '', webdriver: navigator.webdriver === true },
      fingerprint: { timezone: getTimezone(), canvas_hash: getCanvasHash(), hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0, deviceMemory: Number(navigator.deviceMemory) || 0, webgl: getWebGL() },
      behavior: { 
        time_on_page_ms: Date.now() - startTime, 
        mouse_variance: variance(mouseX) + variance(mouseY),
        events: { mousemove: mousemoves, touchstart: touchstarts, clicks: clicks, scrolls: scrolls },
        mouse: mouseStats,
        timing: { time_to_first_move: timeToFirstMove, time_to_first_click: timeToFirstClick }
      },
      screen: { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
      webrtc_ip: webrtc || 'None'
    };
  }

  function send() {
    if (sent) return;
    sent = true;
    getWebRTCIP().then(function (ip) {
      var body = JSON.stringify(buildPayload(ip));
      fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body, keepalive: true }).catch(function (err) {});
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
    origin = safe_origin(request); endpoint = f"{origin}/api/track"
    code = (TRACKER_CODE_TEMPLATE.replace("__OVG_SITE_KEY__", site.site_key).replace("__OVG_ENDPOINT__", endpoint))
    return Response(content='{"code":' + json.dumps(code) + '}', media_type="application/json", headers={"Cache-Control": "no-store, max-age=0"})

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
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    mouse = behavior.get("mouse") or {}
    timing = behavior.get("timing") or {}

    visit = VisitModel(
        site_id=site_id, ip=client_ip, user_agent=ua, zone_id=zone_id,
        score=int(result["score"]), verdict=result["verdict"], evidence=result["evidence"],
        os=os_name, device=device, browser=browser,
        country=ip_info["country"], isp=ip_info["isp"],
        timezone=fp.get("timezone", "Unknown"),
        canvas_hash=(str(fp.get("canvas_hash", "Unknown"))[:15] + "..."),
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"], asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"),
        webrtc_ip=payload.webrtc_ip,
        time_on_page=behavior.get("time_on_page_ms", 0),
        clicks=events.get("clicks", 0),
        scrolls=events.get("scrolls", 0),
        latitude=ip_info.get("lat", 0.0),
        longitude=ip_info.get("lon", 0.0),
        confidence=result["confidence"],
        threat_types=result["threat_types"],
        behavior_meta={"mouse": mouse, "timing": timing}
    )
    try:
        db.add(visit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "DB write failed")
    return {"status": "success"}

# =========================================================
# STATS / VISITS / API ROUTES (نفس النسخة 5 مع إضافة البيانات الجديدة)
# =========================================================
@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site: s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    total = q.count()
    valid = q.filter(VisitModel.verdict.in_(["clean", "valid"])).count()
    invalid = q.filter(VisitModel.verdict.in_(["invalid", "high_risk"])).count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()

    recent = q.order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country, "score": v.score,
        "confidence": v.confidence, "threats": v.threat_types
    } for v in recent]
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

@app.get("/api/visits")
def get_visits(site: str = Query(None), verdict: str = Query(None), page: int = Query(1, ge=1), per_page: int = Query(20, ge=10, le=100), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site: s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    if verdict: q = q.filter(VisitModel.verdict == verdict)
    total = q.count()
    visits = q.order_by(VisitModel.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

    items = [{
        "id": v.id, "time": v.timestamp.strftime("%Y-%m-%d %H:%M") if v.timestamp else "",
        "ip": v.ip, "zone": v.zone_id, "verdict": v.verdict, "score": v.score,
        "country": v.country, "browser": v.browser, "confidence": v.confidence,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls
    } for v in visits]
    return {"items": items, "total": total, "page": page, "pages": (total + per_page - 1) // per_page}

@app.get("/api/visits/{visit_id}")
def get_visit_detail(visit_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(SiteModel).filter(VisitModel.id == visit_id, SiteModel.user_id == user.id).first()
    if not v: raise HTTPException(404, "غير مصرح")
    return {
        "id": v.id, "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        "ip": v.ip, "zone_id": v.zone_id, "score": v.score, "verdict": v.verdict, "evidence": v.evidence or [],
        "os": v.os, "device": v.device, "browser": v.browser, "country": v.country, "isp": v.isp,
        "timezone": v.timezone, "canvas_hash": v.canvas_hash, "hardware": v.hardware,
        "connection_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc_ip": v.webrtc_ip,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls,
        "confidence": v.confidence, "threat_types": v.threat_types or [], "behavior_meta": v.behavior_meta or {}
    }

@app.get("/api/export/visits")
def export_visits(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site: s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)
    
    visits = q.order_by(VisitModel.id.desc()).limit(5000).all()
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(["ID", "Time", "IP", "Country", "Zone", "Verdict", "Score", "Confidence", "Threats", "OS", "Browser", "Time (s)", "Clicks", "Scrolls"])
    for v in visits:
        writer.writerow([v.id, v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "", v.ip, v.country, v.zone_id, v.verdict, v.score, v.confidence, ",".join(v.threat_types or []), v.os, v.browser, round(v.time_on_page/1000,1) if v.time_on_page else 0, v.clicks, v.scrolls])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=ovg_visits_export.csv"})

@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    countries = [("Egypt", 30.0444, 31.2357), ("US", 37.7749, -122.4194), ("India", 20.5937, 78.9629), ("UK", 51.5074, -0.1278)]
    threats = [["automation_tool"], ["vpn_proxy"], ["bot_farm", "click_fraud"], []]
    for _ in range(50):
        v = random.choices(["clean", "valid", "suspicious", "high_risk", "invalid"], weights=[40, 30, 15, 10, 5])[0]
        sc = random.randint(0, 25) if v in ["clean", "valid"] else random.randint(46, 65) if v == "suspicious" else random.randint(66, 100)
        conf = random.uniform(60.0, 99.0) if v in ["invalid", "high_risk"] else random.uniform(20.0, 70.0)
        c_name, c_lat, c_lon = random.choice(countries)
        db.add(VisitModel(
            site_id=s.id, ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones), 
            score=sc, verdict=v, evidence=["Mock Data"], country=c_name, isp="Mock ISP", 
            connection_type="residential", time_on_page=random.randint(1000, 15000),
            clicks=random.randint(0, 5), scrolls=random.randint(0, 10),
            latitude=c_lat + random.uniform(-2,2), longitude=c_lon + random.uniform(-2,2),
            confidence=conf, threat_types=random.choice(threats),
            behavior_meta={"mouse": {"curvature": random.uniform(0.1, 0.9)}, "timing": {"time_to_first_move": random.randint(100, 2000)}}
        ))
    db.commit()
    return {"status": "ok"}

@app.get("/health")
def health(): return {"status": "ok", "version": app.version}

# =========================================================
# HTML ROUTES
# =========================================================
def read_template(name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base_dir, "templates", name), "r", encoding="utf-8") as f: return f.read()

@app.get("/", response_class=HTMLResponse)
def root(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db): return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(read_template("login.html"))

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, key: str = None, db: Session = Depends(get_db)):
    if key and DASHBOARD_KEY and key == DASHBOARD_KEY:
        first = db.query(UserModel).first()
        if first:
            resp = RedirectResponse("/dashboard", status_code=302)
            resp.set_cookie(SESSION_COOKIE, make_token(first.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("dashboard.html"))

@app.get("/visits", response_class=HTMLResponse)
def all_visits_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("visits.html"))

@app.get("/visits/{visit_id}", response_class=HTMLResponse)
def visit_detail_page(request: Request, visit_id: int, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("visit_detail.html"))

@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("reports.html"))