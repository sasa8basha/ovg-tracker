"""
OVG Tracker — Session 5.0 (Ultimate Reports + Map + Export)

Phase R1 — Reports Engine Critical Fixes:
  [R1] CSV injection        → csv_safe() sanitizes formula starters (=, +, -, @, tab, CR)
  [R2] mock-data            → gated by OVG_ENV=dev only (404 in prod)
  [R3] Zone grade           → MIN_SAMPLE=10 avoids F on tiny samples
  [R4] "unknown" zone       → excluded from reports (adds min_sample_met flag)
  [R5] Latitude filter      → excludes ONLY (0,0), not legitimate equator visits
"""
import json
import random
import os
import csv
import io
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import case, func, desc, and_, not_
from sqlalchemy.orm import Session

# =========================================================
# LOCAL IMPORTS
# =========================================================
from config import (
    DASHBOARD_KEY, ALLOWED_ORIGINS, MAX_SITES_PER_USER,
    SESSION_COOKIE, SESSION_TTL, HEX_KEY_RE, USERNAME_RE,
    ENV,
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
    get_ip_info, parse_ua, extract_zone_id, new_site_key, analyze_visit,
    calc_confidence, count_categories, normalize_stored_evidence,
)

Base.metadata.create_all(bind=engine)
bootstrap_admin()

# =========================================================
# PHASE R1 — HELPERS
# =========================================================
def csv_safe(val):
    """
    Phase R1 — Fix [R1]: CSV / Formula Injection defense.

    Excel and Google Sheets interpret cells starting with these chars
    as formulas. A malicious value like "=cmd|'/c calc'!A1" could
    execute code when the exported file is opened.

    Defense: prefix with a single quote so the cell is treated as text.
    """
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


# =========================================================
# APP & STATIC FILES
# =========================================================
app = FastAPI(title="OVG Tracker", version="5.0")

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
# AUTH ROUTES
# =========================================================
@app.post("/api/auth/signup")
def signup(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    signup_limiter.check(client_ip)

    username = payload.username.strip()
    password = payload.password

    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم لازم 3-32 حرف")
    if len(password) < 6:
        raise HTTPException(400, "كلمة المرور لازم 6 حروف على الأقل")
    if db.query(UserModel).filter(UserModel.username == username).first():
        raise HTTPException(400, "اسم المستخدم مستخدم بالفعل")

    u = UserModel(username=username, password_hash=hash_password(password))
    db.add(u)
    db.commit()
    db.refresh(u)

    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/login")
def login(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    login_limiter.check(client_ip)

    u = db.query(UserModel).filter(UserModel.username == payload.username.strip()).first()
    if not u or not verify_password(payload.password, u.password_hash):
        raise HTTPException(401, "اسم المستخدم أو كلمة المرور غلط")

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
    sites = (db.query(SiteModel).filter(SiteModel.user_id == user.id).order_by(SiteModel.created_at.desc()).all())
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
def create_site(payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    count = db.query(SiteModel).filter(SiteModel.user_id == user.id).count()
    if count >= MAX_SITES_PER_USER:
        raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_SITES_PER_USER} موقع)")
    name = payload.name.strip()
    domain = payload.domain.strip()
    if not name:
        raise HTTPException(400, "اسم الموقع مطلوب")
    if len(name) > 100:
        raise HTTPException(400, "اسم الموقع طويل جداً")

    site = SiteModel(user_id=user.id, name=name, domain=domain, site_key=new_site_key())
    db.add(site)
    db.commit()
    db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}

@app.patch("/api/sites/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    site.name = payload.name.strip()
    site.domain = payload.domain.strip()[:253]
    db.commit()
    return {"ok": True}

@app.delete("/api/sites/{site_id}")
def delete_site(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    db.query(VisitModel).filter(VisitModel.site_id == site.id).delete()
    db.delete(site)
    db.commit()
    return {"ok": True}

@app.post("/api/sites/{site_id}/rotate-key")
def rotate_key(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    site.site_key = new_site_key()
    db.commit()
    return {"site_key": site.site_key}

def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key:
        raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key, SiteModel.user_id == user.id).first()
    if not s:
        raise HTTPException(404, "الموقع مش موجود أو مش بتاعك")
    return s

# =========================================================
# TRACKER TEMPLATE (from Phase 4)
# =========================================================
TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  var SITE_KEY = '__OVG_SITE_KEY__';
  var ENDPOINT = '__OVG_ENDPOINT__';
  var SEND_DELAY_MS = 2000;
  var WEBRTC_TIMEOUT = 1500;

  var startTime = Date.now();
  var mousemoves = 0, touchstarts = 0, clicks = 0, scrolls = 0;
  var mouseX = [], mouseY = [];
  var mousePoints = [];
  var sent = false;

  document.addEventListener('mousemove', function (e) {
    mousemoves++;
    mouseX.push(e.clientX); mouseY.push(e.clientY);
    if (mouseX.length > 200) { mouseX.shift(); mouseY.shift(); }
    mousePoints.push({ x: e.clientX, y: e.clientY, t: Date.now() });
    if (mousePoints.length > 100) mousePoints.shift();
  }, { passive: true });

  document.addEventListener('touchstart', function () { touchstarts++; }, { passive: true });
  document.addEventListener('click', function () { clicks++; }, { passive: true });
  document.addEventListener('scroll', function () { scrolls++; }, { passive: true });

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

  function getBraveFlag() {
    return new Promise(function (resolve) {
      try {
        if (navigator.brave && typeof navigator.brave.isBrave === 'function') {
          navigator.brave.isBrave().then(function (v) { resolve(v === true); }).catch(function () { resolve(false); });
        } else { resolve(false); }
      } catch (e) { resolve(false); }
    });
  }

  function getPluginsInfo() {
    try { var p = navigator.plugins; return { count: p ? p.length : 0 }; } catch (e) { return { count: -1 }; }
  }

  function getLanguages() {
    try {
      var langs = navigator.languages;
      if (!langs || !langs.length) return [];
      var arr = [];
      for (var i = 0; i < langs.length && i < 5; i++) arr.push(String(langs[i]));
      return arr;
    } catch (e) { return []; }
  }

  function getChromeCheck() {
    try {
      if (typeof window.chrome === 'undefined') return 'no_window_chrome';
      if (typeof window.chrome.runtime === 'undefined') return 'window_chrome_no_runtime';
      return 'full';
    } catch (e) { return 'error'; }
  }

  function getCDPDetected() {
    try {
      var detected = false;
      var err = new Error();
      Object.defineProperty(err, 'stack', { get: function () { detected = true; return ''; } });
      console.debug(err);
      return detected;
    } catch (e) { return false; }
  }

  function analyzeMouseTrajectory(points) {
    if (!points || points.length < 10) return { too_few: true };
    var velocities = [];
    for (var i = 1; i < points.length; i++) {
      var dx = points[i].x - points[i - 1].x;
      var dy = points[i].y - points[i - 1].y;
      var dt = points[i].t - points[i - 1].t;
      if (dt > 0 && dt < 1000) velocities.push(Math.sqrt(dx * dx + dy * dy) / dt);
    }
    if (velocities.length < 5) return { too_few: true };
    var sum_v = 0;
    for (var i = 0; i < velocities.length; i++) sum_v += velocities[i];
    var mean_v = sum_v / velocities.length;
    var var_v = 0;
    for (var i = 0; i < velocities.length; i++) { var d = velocities[i] - mean_v; var_v += d * d; }
    var_v = var_v / velocities.length;
    var dir_changes = 0;
    var last_sign = 0;
    for (var i = 2; i < points.length; i++) {
      var d1x = points[i - 1].x - points[i - 2].x;
      var d1y = points[i - 1].y - points[i - 2].y;
      var d2x = points[i].x - points[i - 1].x;
      var d2y = points[i].y - points[i - 1].y;
      var cross = d1x * d2y - d1y * d2x;
      if (Math.abs(cross) > 2) {
        var s = Math.sign(cross);
        if (last_sign !== 0 && s !== last_sign) dir_changes++;
        last_sign = s;
      }
    }
    var curvatures = [];
    for (var i = 2; i < points.length; i++) {
      var a1 = Math.atan2(points[i - 1].y - points[i - 2].y, points[i - 1].x - points[i - 2].x);
      var a2 = Math.atan2(points[i].y - points[i - 1].y, points[i].x - points[i - 1].x);
      var angle = a2 - a1;
      while (angle > Math.PI) angle -= 2 * Math.PI;
      while (angle < -Math.PI) angle += 2 * Math.PI;
      curvatures.push(Math.abs(angle));
    }
    var mean_c = 0;
    if (curvatures.length) {
      var sum_c = 0;
      for (var i = 0; i < curvatures.length; i++) sum_c += curvatures[i];
      mean_c = sum_c / curvatures.length;
    }
    return {
      too_few: false,
      velocity_variance: var_v,
      direction_changes: dir_changes,
      mean_curvature: mean_c,
      total_points: points.length
    };
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
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch (e) { return 'Unknown'; }
  }

  function buildPayload(webrtc, isBrave) {
    return {
      url: location.href,
      site_key: SITE_KEY,
      nav: {
        ua: navigator.userAgent,
        platform: navigator.platform || '',
        webdriver: navigator.webdriver === true,
        is_brave: isBrave === true
      },
      fingerprint: {
        timezone: getTimezone(),
        canvas_hash: getCanvasHash(),
        hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
        deviceMemory: Number(navigator.deviceMemory) || 0,
        webgl: getWebGL(),
        plugins: getPluginsInfo(),
        languages: getLanguages(),
        chrome_check: getChromeCheck(),
        cdp_detected: getCDPDetected()
      },
      behavior: {
        time_on_page_ms: Date.now() - startTime,
        mouse_variance: variance(mouseX) + variance(mouseY),
        mouse_analysis: analyzeMouseTrajectory(mousePoints),
        events: { mousemove: mousemoves, touchstart: touchstarts, clicks: clicks, scrolls: scrolls }
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
    Promise.all([getWebRTCIP(), getBraveFlag()]).then(function (results) {
      var body = JSON.stringify(buildPayload(results[0], results[1]));
      fetch(ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true
      }).catch(function (err) { console.error('[OVG Tracker] Send failed:', err); });
    });
  }

  setTimeout(send, SEND_DELAY_MS);
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') send(); });
  window.addEventListener('pagehide', function () { send(); });
  window.addEventListener('beforeunload', function () { send(); });
})();
</script>"""

@app.get("/api/sites/{site_id}/tracker-code")
def get_tracker_code(site_id: int, request: Request, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    if not HEX_KEY_RE.match(site.site_key or ""):
        site.site_key = new_site_key()
        db.commit()

    origin = safe_origin(request)
    endpoint = f"{origin}/api/track"
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
        if s:
            site_id = s.id

    try: data = payload.model_dump()
    except AttributeError: data = payload.dict()

    data["client_ip"] = client_ip

    # Fingerprint rate anomaly (Phase 3)
    canvas_raw = str((data.get("fingerprint") or {}).get("canvas_hash") or "")
    recent_fp_count = 0
    if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
        try:
            canvas_stored = canvas_raw[:15] + "..."
            cutoff = datetime.utcnow() - timedelta(minutes=1)
            recent_fp_count = db.query(VisitModel).filter(
                VisitModel.canvas_hash == canvas_stored,
                VisitModel.timestamp > cutoff,
            ).count()
        except Exception:
            recent_fp_count = 0
    data["_recent_fp_count"] = recent_fp_count

    result = analyze_visit(data, ip_info)
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}

    visit = VisitModel(
        site_id=site_id, ip=client_ip, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"],
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
        longitude=ip_info.get("lon", 0.0)
    )
    try:
        db.add(visit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "DB write failed")
    return {"status": "success"}

# =========================================================
# STATS / VISITS / EXPORT
# =========================================================
@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    total = q.count()
    valid = q.filter(VisitModel.verdict == "valid").count()
    invalid = q.filter(VisitModel.verdict == "invalid").count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()

    recent = q.order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country, "score": v.score,
        "evidence": v.evidence, "timezone": v.timezone, "hardware": v.hardware,
        "conn_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip,
    } for v in recent]

    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

@app.get("/api/visits")
def get_visits(
    site: str = Query(None), verdict: str = Query(None), country: str = Query(None),
    page: int = Query(1, ge=1), per_page: int = Query(20, ge=10, le=100),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db)
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    if verdict: q = q.filter(VisitModel.verdict == verdict)
    if country: q = q.filter(VisitModel.country == country)

    total = q.count()
    visits = q.order_by(VisitModel.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

    items = [{
        "id": v.id, "time": v.timestamp.strftime("%Y-%m-%d %H:%M") if v.timestamp else "",
        "ip": v.ip, "zone": v.zone_id, "verdict": v.verdict, "score": v.score,
        "country": v.country, "device": v.device, "browser": v.browser,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls
    } for v in visits]
    return {"items": items, "total": total, "page": page, "pages": (total + per_page - 1) // per_page}

@app.get("/api/visits/{visit_id}")
def get_visit_detail(visit_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(SiteModel).filter(VisitModel.id == visit_id, SiteModel.user_id == user.id).first()
    if not v: raise HTTPException(404, "غير مصرح لك بعرض هذه الزيارة")

    evidence = v.evidence or []
    signals = normalize_stored_evidence(evidence)
    confidence = calc_confidence(signals)
    raw_score = sum(s.get("score", 0) for s in signals)
    categories = count_categories(signals)

    return {
        "id": v.id, "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        "ip": v.ip, "zone_id": v.zone_id, "score": v.score, "verdict": v.verdict, "evidence": evidence,
        "os": v.os, "device": v.device, "browser": v.browser, "country": v.country, "isp": v.isp,
        "timezone": v.timezone, "canvas_hash": v.canvas_hash, "hardware": v.hardware,
        "connection_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc_ip": v.webrtc_ip,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls,
        "confidence": confidence,
        "raw_score": raw_score,
        "categories": categories,
    }

@app.get("/api/export/visits")
def export_visits(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    visits = q.order_by(VisitModel.id.desc()).limit(5000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Time", "IP", "Country", "Zone", "Verdict", "Score", "OS", "Browser", "Device", "Time on Page (s)", "Clicks", "Scrolls", "ISP", "ASN", "VPN"])
    for v in visits:
        # Phase R1 — Fix [R1]: csv_safe on every cell
        row = [
            v.id,
            v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
            v.ip,
            v.country,
            v.zone_id,
            v.verdict,
            v.score,
            v.os,
            v.browser,
            v.device,
            round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
            v.clicks,
            v.scrolls,
            v.isp,
            v.asn,
            v.is_vpn,
        ]
        writer.writerow([csv_safe(x) for x in row])

    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=ovg_visits_export.csv"})

# =========================================================
# REPORTS & MAP APIs
# =========================================================
@app.get("/api/reports/zones")
def get_zone_reports(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = db.query(VisitModel.zone_id, func.count(VisitModel.id).label("total"), invalid_expr.label("invalid"))
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)
    rows = q.group_by(VisitModel.zone_id).all()

    # Phase R1 — Fix [R3]: min sample for grade
    # Phase R1 — Fix [R4]: exclude "unknown" zone
    MIN_SAMPLE = 10
    report = []
    for z in rows:
        if not z.zone_id or z.zone_id == "unknown":
            continue
        total, invalid = int(z.total or 0), int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        if total < MIN_SAMPLE:
            grade = "?"
        else:
            grade = "A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F"
        report.append({
            "zone": z.zone_id,
            "total": total,
            "bot_rate": rate,
            "grade": grade,
            "min_sample_met": total >= MIN_SAMPLE,
        })
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

@app.get("/api/reports/countries")
def report_countries(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = db.query(VisitModel.country, func.count(VisitModel.id).label("total"), invalid_expr.label("invalid"))
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    rows = q.group_by(VisitModel.country).order_by(desc("total")).limit(15).all()
    return [{"name": r.country, "total": int(r.total), "invalid": int(r.invalid or 0)} for r in rows]

@app.get("/api/reports/tech")
def report_tech(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel.device, func.count(VisitModel.id).label("count"))
    q_b = db.query(VisitModel.browser, func.count(VisitModel.id).label("count"))

    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
        q_b = q_b.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        if ids:
            q = q.filter(VisitModel.site_id.in_(ids))
            q_b = q_b.filter(VisitModel.site_id.in_(ids))
        else:
            q = q.filter(False); q_b = q_b.filter(False)

    devices = [{"name": r.device, "count": int(r.count)} for r in q.group_by(VisitModel.device).all()]
    browsers = [{"name": r.browser, "count": int(r.count)} for r in q_b.group_by(VisitModel.browser).all()]
    return {"devices": devices, "browsers": browsers}

@app.get("/api/map/visits")
def map_visits(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)

    # Phase R1 — Fix [R5]: exclude only (0,0), keep legitimate equator visits
    visits = q.filter(
        not_(and_(VisitModel.latitude == 0.0, VisitModel.longitude == 0.0))
    ).order_by(VisitModel.id.desc()).limit(200).all()

    return [{
        "id": v.id, "lat": v.latitude, "lng": v.longitude, "verdict": v.verdict,
        "country": v.country, "ip": v.ip
    } for v in visits]

@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    # Phase R1 — Fix [R2]: gated by ENV
    if ENV != "dev":
        raise HTTPException(404, "Not Found")

    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    countries = [("Egypt", 30.0444, 31.2357), ("US", 37.7749, -122.4194), ("India", 20.5937, 78.9629), ("UK", 51.5074, -0.1278)]
    for _ in range(50):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid" else random.randint(70, 100) if v == "invalid" else random.randint(40, 69))
        c_name, c_lat, c_lon = random.choice(countries)
        db.add(VisitModel(
            site_id=s.id, ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones),
            score=sc, verdict=v, evidence=["Mock Data"], country=c_name, isp="Mock ISP",
            connection_type="residential", time_on_page=random.randint(1000, 15000),
            clicks=random.randint(0, 5), scrolls=random.randint(0, 10),
            latitude=c_lat + random.uniform(-2,2), longitude=c_lon + random.uniform(-2,2)
        ))
    db.commit()
    return {"status": "ok"}

@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}

# =========================================================
# HTML ROUTES
# =========================================================
def read_template(name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "templates", name)
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

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