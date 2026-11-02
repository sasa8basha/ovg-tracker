"""
OVG Tracker — Session 3.4.2 (Modularized + Design System)
Production-ready · No external auth libs · CSRF-safe · XSS-safe
"""
import json
import random
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles # <-- جديد عشان ملفات التصميم
from pydantic import BaseModel
from sqlalchemy import case, func
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

# إنشاء الجداول وإضافة الأدمن الافتراضي
Base.metadata.create_all(bind=engine)
bootstrap_admin()

# =========================================================
# APP
# =========================================================
app = FastAPI(title="OVG Tracker", version="3.4.2")

# ربط مجلد الملفات الثابتة (CSS/JS)
app.mount("/static", StaticFiles(directory="static"), name="static")

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                       allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])


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
# TRACKER CODE TEMPLATE
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
      site_key: SITE_KEY,
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
      }).catch(function (err) {
        console.error('[OVG Tracker] Send failed:', err);
      });
    });
  }

  setTimeout(send, SEND_DELAY_MS);
  window.addEventListener('beforeunload', function () { send(); });
})();
</script>"""

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
        content='{"code":' + json.dumps(code) + '}',
        media_type="application/json",
        headers={"Cache-Control": "no-store, max-age=0"},
    )

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
        if s:
            site_id = s.id

    try:
        data = payload.model_dump()
    except AttributeError:
        data = payload.dict()
    data["client_ip"] = client_ip
    result = analyze_visit(data, ip_info)
    fp = data.get("fingerprint") or {}

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
    )
    try:
        db.add(visit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "DB write failed")
    return {"status": "success"}


# =========================================================
# STATS / REPORTS
# =========================================================
@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user),
              db: Session = Depends(get_db)):
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

    return {"total": total, "valid": valid, "invalid": invalid,
            "suspicious": suspicious, "recent": recent_visits}


@app.get("/api/reports/zones")
def get_zone_reports(site: str = Query(None), user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    q = db.query(VisitModel.zone_id,
                 func.count(VisitModel.id).label("total"),
                 invalid_expr.label("invalid"))
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)
    rows = q.group_by(VisitModel.zone_id).all()

    report = []
    for z in rows:
        total, invalid = int(z.total or 0), int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = "A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report


@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user),
                  db: Session = Depends(get_db)):
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    for _ in range(50):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid" else
              random.randint(70, 100) if v == "invalid" else random.randint(40, 69))
        db.add(VisitModel(site_id=s.id, ip="127.0.0.1", user_agent="Mock",
                          zone_id=random.choice(zones), score=sc, verdict=v,
                          evidence=["Mock Data"], country="US", isp="Mock ISP",
                          connection_type="residential"))
    db.commit()
    return {"status": "ok"}


# =========================================================
# DEBUG / HEALTH
# =========================================================
@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}

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
        site_key: SITE_KEY,
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
      if (sent) return; sent = true;
      getWebRTCIP().then(function(ip) {
        var body = JSON.stringify(buildPayload(ip));
        fetch(ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: body,
          keepalive: true
        }).catch(function(err){ console.error('[OVG Tracker] Send failed:', err); });
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
# LOGIN / SIGNUP PAGE
# =========================================================
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG · تسجيل الدخول</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
  
  <!-- ملفات التصميم الجديدة -->
  <link rel="stylesheet" href="/static/css/design-tokens.css">
  <link rel="stylesheet" href="/static/css/components.css">

  <style>
    body{font-family:'Cairo',sans-serif}
    .bg-mesh{background:
      radial-gradient(at 20% 20%, rgba(99,102,241,.45) 0px, transparent 50%),
      radial-gradient(at 80% 80%, rgba(168,85,247,.4) 0px, transparent 50%),
      radial-gradient(at 50% 50%, rgba(59,130,246,.3) 0px, transparent 50%),
      #0f172a;}
    .card{background:rgba(255,255,255,.98);backdrop-filter:blur(30px)}
    .input{width:100%;padding:12px 16px;border:1.5px solid #e2e8f0;border-radius:12px;font-size:15px;transition:.15s;background:#fff}
    .input:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 4px rgba(99,102,241,.12)}
    .btn{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;padding:13px;border-radius:12px;font-weight:700;width:100%;transition:.15s;box-shadow:0 10px 25px -5px rgba(99,102,241,.5)}
    .btn:hover{transform:translateY(-1px);box-shadow:0 15px 30px -5px rgba(99,102,241,.6)}
    .btn:disabled{opacity:.6;cursor:not-allowed;transform:none}
    .tab{padding:10px;border-radius:10px;font-weight:700;font-size:14px;transition:.15s;color:#64748b;flex:1;background:transparent;border:none;cursor:pointer}
    .tab.active{background:#eef2ff;color:#4f46e5}
  </style>
</head>
<body class="bg-mesh min-h-screen flex items-center justify-center p-4">
  <div class="card w-full max-w-md rounded-3xl shadow-2xl p-8 md:p-10">
    <div class="text-center mb-6">
      <div class="w-20 h-20 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center mx-auto mb-4 shadow-lg shadow-indigo-500/40">
        <span class="text-4xl">🛡️</span>
      </div>
      <h1 class="text-2xl font-extrabold text-slate-900">OVG Tracker</h1>
      <p class="text-slate-500 text-sm mt-1">منصة تتبع الترافيك ومنع البوتات</p>
    </div>

    <div class="flex gap-2 mb-6 bg-slate-50 p-1 rounded-xl">
      <button type="button" id="tab-login" class="tab active" onclick="switchTab('login')">تسجيل دخول</button>
      <button type="button" id="tab-signup" class="tab" onclick="switchTab('signup')">إنشاء حساب</button>
    </div>

    <form id="authForm" class="space-y-4" autocomplete="on">
      <div>
        <label class="block text-sm font-semibold text-slate-700 mb-1.5">اسم المستخدم</label>
        <input name="username" class="input" placeholder="مثال: ahmed" autocomplete="username" required minlength="3" maxlength="32" pattern="[a-zA-Z0-9_.\\-]{3,32}">
        <p class="text-[11px] text-slate-400 mt-1 hidden" id="userHint">3-32 حرف (إنجليزي، أرقام، _ . -)</p>
      </div>
      <div>
        <label class="block text-sm font-semibold text-slate-700 mb-1.5">كلمة المرور</label>
        <input name="password" type="password" class="input" placeholder="••••••••" autocomplete="current-password" required minlength="6">
      </div>
      <div id="confirmWrap" class="hidden">
        <label class="block text-sm font-semibold text-slate-700 mb-1.5">تأكيد كلمة المرور</label>
        <input name="confirm" type="password" class="input" placeholder="••••••••" autocomplete="new-password">
      </div>
      <button type="submit" id="submitBtn" class="btn">تسجيل الدخول</button>
      <p id="error" class="hidden text-rose-600 text-sm text-center font-semibold bg-rose-50 py-2.5 rounded-lg"></p>
    </form>
    <p class="text-center text-xs text-slate-400 mt-8">© OVG Analytics — Session 3.4.2</p>
  </div>
  <script>
    let MODE = 'login';
    function switchTab(m) {
      MODE = m;
      document.getElementById('tab-login').classList.toggle('active', m === 'login');
      document.getElementById('tab-signup').classList.toggle('active', m === 'signup');
      document.getElementById('confirmWrap').classList.toggle('hidden', m !== 'signup');
      document.getElementById('userHint').classList.toggle('hidden', m !== 'signup');
      document.getElementById('submitBtn').textContent = m === 'signup' ? 'إنشاء حساب' : 'تسجيل الدخول';
      const pwd = document.querySelector('input[name=password]');
      pwd.autocomplete = m === 'signup' ? 'new-password' : 'current-password';
      document.getElementById('error').classList.add('hidden');
    }
    document.getElementById('authForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      const err = document.getElementById('error');
      btn.disabled = true; err.classList.add('hidden');
      const orig = btn.textContent;
      btn.textContent = 'جاري...';
      const fd = new FormData(e.target);
      const body = { username: (fd.get('username')||'').trim(), password: fd.get('password') };
      if (MODE === 'signup' && body.password !== fd.get('confirm')) {
        err.textContent = 'كلمتا المرور غير متطابقتين';
        err.classList.remove('hidden');
        btn.disabled = false; btn.textContent = orig;
        return;
      }
      const url = MODE === 'signup' ? '/api/auth/signup' : '/api/auth/login';
      try {
        const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        const d = await r.json().catch(()=>({}));
        if (r.ok) { location.href = '/dashboard'; return; }
        err.textContent = d.detail || 'فشل العملية';
        err.classList.remove('hidden');
      } catch(e) {
        err.textContent = 'خطأ في الاتصال بالسيرفر';
        err.classList.remove('hidden');
      } finally {
        btn.disabled = false; btn.textContent = orig;
      }
    });
  </script>
</body>
</html>
"""


# =========================================================
# MAIN DASHBOARD
# =========================================================
DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="ar" dir="rtl" data-theme="light">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVG · لوحة التحكم</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet">
  
  <!-- ملفات التصميم الجديدة -->
  <link rel="stylesheet" href="/static/css/design-tokens.css">
  <link rel="stylesheet" href="/static/css/components.css">

  <style>
    body{font-family:'Cairo',sans-serif;background:#f8fafc;color:#1e293b}
    ::-webkit-scrollbar{width:6px;height:6px}
    ::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:3px}
    .site-card{transition:all .2s ease}
    .site-card:hover{transform:translateY(-3px);box-shadow:0 20px 40px -12px rgba(99,102,241,.25)}
    .nav-btn.active{background:#eef2ff;color:#4f46e5;font-weight:700}
    .modal-bg{background:rgba(15,23,42,.6);backdrop-filter:blur(6px)}
    .toast{animation:slideUp .3s ease}
    @keyframes slideUp{from{transform:translate(-50%,20px);opacity:0}to{transform:translate(-50%,0);opacity:1}}
  </style>
</head>
<body class="min-h-screen">

<aside class="fixed right-0 top-0 h-screen w-72 bg-white border-l border-slate-200 flex flex-col z-40">
  <div class="p-6 border-b border-slate-100">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center text-white font-extrabold shadow-md shadow-indigo-500/30">O</div>
      <div>
        <h1 class="font-extrabold text-slate-900 leading-tight">OVG Tracker</h1>
        <p class="text-[11px] text-slate-400 font-semibold">ANALYTICS · V3.4.2</p>
      </div>
    </div>
  </div>

  <div id="siteContext" class="p-3 border-b border-slate-100 hidden relative">
    <button onclick="toggleSiteMenu(event)" class="w-full flex items-center justify-between p-3 bg-slate-50 hover:bg-slate-100 rounded-xl transition">
      <div class="flex items-center gap-2 min-w-0">
        <span class="text-lg">🌐</span>
        <span id="currentSiteName" class="font-semibold text-sm text-slate-700 truncate">...</span>
      </div>
      <span class="text-slate-400 text-xs">▼</span>
    </button>
    <div id="siteMenu" class="hidden absolute right-3 left-3 top-full mt-1 bg-white rounded-xl shadow-2xl border border-slate-100 py-2 z-50 max-h-80 overflow-y-auto"></div>
  </div>

  <nav class="flex-1 p-3 space-y-1 overflow-y-auto">
    <button onclick="navTo('sites')" data-nav="sites" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3">
      <span class="text-lg">📊</span> المواقع
    </button>
    <div id="siteNav" class="hidden space-y-1 pt-1">
      <button onclick="navTo('overview')" data-nav="overview" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3">
        <span class="text-lg">🏠</span> نظرة عامة
      </button>
      <button onclick="navTo('zones')" data-nav="zones" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3">
        <span class="text-lg">🎯</span> تقارير الزونات
      </button>
      <button onclick="navTo('tracker')" data-nav="tracker" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3">
        <span class="text-lg">🔧</span> كود التتبع
      </button>
      <button onclick="navTo('settings')" data-nav="settings" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3">
        <span class="text-lg">⚙️</span> إعدادات الموقع
      </button>
    </div>
  </nav>

  <div class="p-3 border-t border-slate-100">
    <!-- زرار الوضع الليلي الجديد -->
    <button onclick="toggleTheme()" class="w-full text-right px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 rounded-lg font-semibold transition mb-1 flex items-center justify-between">
      <span>🌓 تغيير المظهر</span>
    </button>

    <div class="flex items-center gap-3 p-2 mb-1 border-t border-slate-100 pt-3">
      <div class="w-9 h-9 bg-gradient-to-br from-slate-100 to-slate-200 rounded-full flex items-center justify-center text-slate-600 font-bold">👤</div>
      <div class="min-w-0 flex-1">
        <p id="userName" class="font-bold text-sm text-slate-800 truncate">...</p>
        <p class="text-[11px] text-slate-400">مسجل دخول</p>
      </div>
    </div>
    <button onclick="doLogout()" class="w-full text-right px-3 py-2 text-sm text-rose-600 hover:bg-rose-50 rounded-lg font-semibold transition">← تسجيل الخروج</button>
  </div>
</aside>

<main class="mr-72 min-h-screen">
  <div class="p-6 md:p-8 max-w-7xl mx-auto">

    <div id="view-sites" class="view">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div>
          <h1 class="text-2xl font-extrabold text-slate-900">مواقعي</h1>
          <p class="text-slate-500 text-sm mt-0.5">أدر كل مواقعك من مكان واحد · <span id="siteLimit">0/20</span></p>
        </div>
        <button onclick="openSiteModal()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-xl font-bold text-sm flex items-center gap-2 shadow-lg shadow-indigo-500/30 transition self-start">
          <span class="text-lg leading-none">+</span> موقع جديد
        </button>
      </div>
      <div id="sitesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"></div>
    </div>

    <div id="view-overview" class="view hidden">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h1 class="text-2xl font-extrabold text-slate-900">نظرة عامة</h1>
          <p id="overviewSubtitle" class="text-slate-500 text-sm mt-0.5">—</p>
        </div>
        <button onclick="runMock()" class="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-lg font-semibold transition">🧪 بيانات تجريبية</button>
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100">
          <p class="text-slate-500 text-xs font-semibold mb-1">إجمالي الزيارات</p>
          <p id="kpi-total" class="text-3xl font-extrabold text-slate-900">0</p>
        </div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-emerald-500">
          <p class="text-slate-500 text-xs font-semibold mb-1">زيارات صالحة</p>
          <p id="kpi-valid" class="text-3xl font-extrabold text-emerald-600">0</p>
        </div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-rose-500">
          <p class="text-slate-500 text-xs font-semibold mb-1">بوتات (Invalid)</p>
          <p id="kpi-invalid" class="text-3xl font-extrabold text-rose-600">0</p>
        </div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-amber-500">
          <p class="text-slate-500 text-xs font-semibold mb-1">مشبوهة</p>
          <p id="kpi-suspicious" class="text-3xl font-extrabold text-amber-500">0</p>
        </div>
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-100">
          <h2 class="text-sm font-bold text-slate-700 mb-4">نسبة جودة الترافيك</h2>
          <div class="h-56 flex justify-center"><canvas id="qualityChart"></canvas></div>
        </div>
        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 col-span-1 lg:col-span-2 overflow-hidden">
          <div class="p-5 border-b border-slate-100 flex justify-between items-center">
            <h2 class="text-sm font-bold text-slate-700">أحدث الزيارات (Live)</h2>
            <span class="text-[10px] text-indigo-600 bg-indigo-50 px-2 py-1 rounded font-bold">يتحدث كل 15 ث</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm text-right">
              <thead class="text-[11px] text-slate-400 bg-slate-50">
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

    <div id="view-zones" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">تقارير الزونات</h1>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
        <table class="w-full text-sm text-right">
          <thead class="bg-slate-50 text-slate-400 text-[11px]">
            <tr>
              <th class="px-5 py-4">Zone ID</th>
              <th class="px-5 py-4">الزيارات</th>
              <th class="px-5 py-4">نسبة البوتات</th>
              <th class="px-5 py-4">التقييم</th>
            </tr>
          </thead>
          <tbody id="zones-table" class="divide-y divide-slate-100"></tbody>
        </table>
      </div>
    </div>

    <div id="view-tracker" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-2">كود التتبع</h1>
      <p class="text-slate-500 text-sm mb-6">انسخ الكود ده وحطه في موقعك (في &lt;head&gt; أو قبل &lt;/body&gt; مباشرة)</p>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 mb-5">
        <label class="text-xs font-bold text-slate-500 mb-2 block">Site Key</label>
        <div class="flex gap-2">
          <input id="siteKeyInput" readonly class="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 font-mono text-sm text-slate-700">
          <button onclick="copyText(document.getElementById('siteKeyInput').value)" class="bg-slate-800 hover:bg-slate-900 text-white px-4 rounded-xl font-semibold text-sm">نسخ</button>
        </div>
        <p class="text-[11px] text-slate-400 mt-2">المفتاح مدمج جوه الكود تحت — مش محتاج تحطه يدوياً</p>
      </div>
      <div class="bg-slate-900 rounded-2xl shadow-sm p-6">
        <div class="flex justify-between items-center mb-3">
          <label class="text-xs font-bold text-slate-400">الكود الكامل (جاهز للنسخ)</label>
          <button onclick="copyText(document.getElementById('embedCode').textContent)" class="text-indigo-400 hover:text-indigo-300 text-xs font-bold">نسخ الكود</button>
        </div>
        <pre id="embedCode" class="text-emerald-400 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">جاري التحميل...</pre>
      </div>
      <div class="mt-5 bg-amber-50 border border-amber-200 rounded-xl p-4 text-sm text-amber-800">
        <p class="font-bold mb-1">⚠️ ملاحظة مهمة</p>
        <p class="text-xs leading-relaxed">لازم تضيف <code class="bg-amber-100 px-1 rounded">?zoneId=XXX</code> في روابط صفحات موقعك عشان الزون يظهر في التقارير.</p>
      </div>
    </div>

    <div id="view-settings" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">إعدادات الموقع</h1>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 max-w-xl mb-5">
        <h2 class="text-sm font-bold text-slate-700 mb-4">بيانات الموقع</h2>
        <div class="space-y-4">
          <div>
            <label class="text-xs font-bold text-slate-500 mb-1.5 block">اسم الموقع</label>
            <input id="editName" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="text-xs font-bold text-slate-500 mb-1.5 block">الدومين (اختياري)</label>
            <input id="editDomain" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500">
          </div>
          <button onclick="saveSiteSettings()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-xl font-bold text-sm transition">حفظ التعديلات</button>
        </div>
      </div>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 max-w-xl mb-5">
        <h2 class="text-sm font-bold text-slate-700 mb-2">تجديد المفتاح</h2>
        <p class="text-xs text-slate-500 mb-4">لو المفتاح اتسرّب، اعمله rotate. الكود القديم هيبطّل يشتغل فوراً.</p>
        <button onclick="rotateSiteKey()" class="bg-amber-500 hover:bg-amber-600 text-white px-5 py-2.5 rounded-xl font-bold text-sm transition">🔄 تجديد المفتاح</button>
      </div>
      <div class="bg-rose-50 border border-rose-200 rounded-2xl p-6 max-w-xl">
        <h2 class="text-sm font-bold text-rose-800 mb-2">منطقة الخطر</h2>
        <p class="text-xs text-rose-600 mb-4">حذف الموقع هيمسح كل البيانات المرتبطة بيه نهائياً</p>
        <button onclick="deleteCurrentSite()" class="bg-rose-600 hover:bg-rose-700 text-white px-5 py-2.5 rounded-xl font-bold text-sm transition">حذف الموقع نهائياً</button>
      </div>
    </div>

  </div>
</main>

<!-- Modal: create site -->
<div id="siteModal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4">
  <div class="bg-white rounded-3xl p-6 md:p-8 w-full max-w-md shadow-2xl">
    <h3 class="text-lg font-extrabold text-slate-900 mb-1">موقع جديد</h3>
    <p class="text-slate-500 text-xs mb-5">أضف موقع وابدأ تتبع الزيارات</p>
    <form id="siteForm" class="space-y-4">
      <div>
        <label class="text-xs font-bold text-slate-500 mb-1.5 block">اسم الموقع *</label>
        <input id="newName" required maxlength="100" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500" placeholder="مثال: متجر الأناقة">
      </div>
      <div>
        <label class="text-xs font-bold text-slate-500 mb-1.5 block">الدومين (اختياري)</label>
        <input id="newDomain" maxlength="253" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500" placeholder="shop.example.com">
      </div>
      <div class="flex gap-2 pt-2">
        <button type="button" onclick="closeSiteModal()" class="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 py-2.5 rounded-xl font-bold text-sm transition">إلغاء</button>
        <button type="submit" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl font-bold text-sm transition">إنشاء</button>
      </div>
    </form>
  </div>
</div>

<!-- Modal: created — show tracker code -->
<div id="createdModal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4">
  <div class="bg-white rounded-3xl p-6 md:p-8 w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto">
    <div class="text-center mb-5">
      <div class="w-16 h-16 rounded-full bg-emerald-100 flex items-center justify-center mx-auto mb-3">
        <span class="text-3xl">✅</span>
      </div>
      <h3 class="text-xl font-extrabold text-slate-900 mb-1">تم إنشاء الموقع بنجاح!</h3>
      <p class="text-slate-500 text-sm">الموقع <span id="createdSiteName" class="font-bold text-indigo-600"></span> جاهز للتتبع</p>
    </div>

    <div class="mb-4">
      <label class="text-xs font-bold text-slate-500 mb-1.5 block">Site Key</label>
      <div class="flex gap-2">
        <input id="createdKey" readonly class="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 font-mono text-xs text-slate-700">
        <button onclick="copyText(document.getElementById('createdKey').value)" class="bg-slate-800 hover:bg-slate-900 text-white px-3 rounded-xl font-semibold text-xs">نسخ</button>
      </div>
    </div>

    <div class="mb-5">
      <div class="flex justify-between items-center mb-2">
        <label class="text-xs font-bold text-slate-400">كود التتبع الكامل (انسخه وحطه في موقعك)</label>
        <button onclick="copyText(document.getElementById('createdCode').textContent)" class="text-indigo-600 hover:text-indigo-700 text-xs font-bold">نسخ الكود</button>
      </div>
      <pre id="createdCode" class="bg-slate-900 text-emerald-400 text-xs font-mono p-4 rounded-xl overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">جاري التحميل...</pre>
    </div>

    <div class="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-800 mb-5 leading-relaxed">
      ⚠️ لازم تضيف <code class="bg-amber-100 px-1 rounded">?zoneId=XXX</code> في روابط صفحات موقعك عشان الزون يظهر في التقارير.
    </div>

    <div class="flex gap-2">
      <button onclick="closeCreatedModal()" class="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 py-2.5 rounded-xl font-bold text-sm transition">+ إضافة موقع آخر</button>
      <button onclick="goToCreatedDashboard()" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl font-bold text-sm transition">روح للداشبورد ←</button>
    </div>
  </div>
</div>

<!-- Modal: visit details -->
<div id="details-modal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4">
  <div class="bg-white rounded-3xl p-6 md:p-8 w-full max-w-md shadow-2xl">
    <h3 class="text-lg font-extrabold text-indigo-700 mb-4">تفاصيل التحليل</h3>
    <div id="modal-content" class="space-y-2 text-sm text-slate-600 mb-6 max-h-96 overflow-y-auto"></div>
    <button onclick="closeDetails()" class="w-full bg-slate-800 hover:bg-slate-900 text-white py-2.5 rounded-xl font-bold transition">إغلاق</button>
  </div>
</div>

<div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 hidden bg-slate-900 text-white px-6 py-3 rounded-xl font-semibold text-sm shadow-2xl z-[100] toast"></div>

<script>
const state = {
  user: null, sites: [], currentSite: null, view: 'sites',
  chart: null, visitsData: {}
};
const MAX_SITES = 20;

// كود الوضع الليلي
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  toast(next === 'dark' ? 'تم تفعيل الوضع الليلي 🌙' : 'تم تفعيل الوضع النهاري ☀️');
}

// تفعيل الوضع المحفوظ عند فتح الصفحة
(function() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
})();

async function init() {
  const me = await fetch('/api/auth/me').then(r => r.ok ? r.json() : null).catch(() => null);
  if (!me) { location.href = '/'; return; }
  state.user = me;
  document.getElementById('userName').textContent = me.username;
  await loadSites();
  const siteKey = new URL(location.href).searchParams.get('site');
  if (siteKey) {
    const s = state.sites.find(x => x.site_key === siteKey);
    if (s) { selectSite(s, false); return; }
  }
  navTo('sites');
  if (state.sites.length === 0) {
    setTimeout(openSiteModal, 400);
  }
}

async function loadSites() {
  try {
    const r = await fetch('/api/sites');
    state.sites = await r.json();
    renderSites();
    renderSiteMenu();
    document.getElementById('siteLimit').textContent = state.sites.length + '/' + MAX_SITES;
  } catch (e) { toast('خطأ في تحميل المواقع'); }
}

function renderSites() {
  const grid = document.getElementById('sitesGrid');
  if (!state.sites.length) {
    grid.innerHTML = `
      <div class="col-span-full text-center py-20 bg-white rounded-3xl border-2 border-dashed border-slate-200">
        <div class="text-6xl mb-4">🌐</div>
        <h3 class="font-extrabold text-slate-800 text-lg mb-2">مفيش مواقع لسه</h3>
        <p class="text-slate-500 text-sm mb-6">أضف أول موقع ليك وابدأ تبعت الزيارات</p>
        <button onclick="openSiteModal()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-xl font-bold text-sm shadow-lg shadow-indigo-500/30 transition">+ أضف موقعك الأول</button>
      </div>`;
    return;
  }
  grid.innerHTML = state.sites.map(s => {
    const total = s.total || 0;
    const valid = s.valid || 0;
    const invalid = s.invalid || 0;
    const quality = total > 0 ? Math.round(valid / total * 100) : 0;
    const qColor = quality >= 80 ? 'text-emerald-600' : quality >= 50 ? 'text-amber-600' : 'text-rose-600';
    const last = s.last_visit ? timeAgo(new Date(s.last_visit)) : 'لا يوجد نشاط';
    return `
      <div class="site-card bg-white rounded-2xl p-5 border border-slate-100 cursor-pointer relative group" onclick="openSite('${s.site_key}')">
        <div class="flex justify-between items-start mb-4">
          <div class="min-w-0 flex-1">
            <h3 class="font-extrabold text-slate-900 text-lg truncate">${esc(s.name)}</h3>
            <p class="text-slate-400 text-xs truncate">${esc(s.domain || 'بدون دومين')}</p>
          </div>
          <div class="w-11 h-11 bg-gradient-to-br from-indigo-50 to-purple-50 rounded-xl flex items-center justify-center text-xl shrink-0">🌐</div>
        </div>
        <div class="grid grid-cols-3 gap-1 text-center py-3 border-y border-slate-100 mb-3">
          <div>
            <p class="text-[10px] text-slate-400 font-semibold">إجمالي</p>
            <p class="text-base font-extrabold text-slate-800">${total}</p>
          </div>
          <div>
            <p class="text-[10px] text-slate-400 font-semibold">صالح</p>
            <p class="text-base font-extrabold text-emerald-600">${valid}</p>
          </div>
          <div>
            <p class="text-[10px] text-slate-400 font-semibold">بوتات</p>
            <p class="text-base font-extrabold text-rose-600">${invalid}</p>
          </div>
        </div>
        <div class="flex justify-between items-center text-xs">
          <span class="text-slate-400">${last}</span>
          <span class="${qColor} font-extrabold">${quality}% جودة</span>
        </div>
      </div>`;
  }).join('');
}

function renderSiteMenu() {
  const menu = document.getElementById('siteMenu');
  menu.innerHTML = state.sites.map(s =>
    `<button onclick="openSite('${s.site_key}')" class="w-full text-right px-3 py-2 hover:bg-slate-50 rounded-lg text-sm ${state.currentSite?.id === s.id ? 'bg-indigo-50 text-indigo-700 font-bold' : 'text-slate-700'}">${esc(s.name)}</button>`
  ).join('') + `<hr class="my-1"><button onclick="clearSite()" class="w-full text-right px-3 py-2 hover:bg-slate-50 rounded-lg text-sm text-slate-600">← كل المواقع</button>`;
}

function toggleSiteMenu(e) {
  e.stopPropagation();
  document.getElementById('siteMenu').classList.toggle('hidden');
}
document.addEventListener('click', e => {
  const m = document.getElementById('siteMenu');
  if (m && !m.classList.contains('hidden') && !e.target.closest('#siteContext')) m.classList.add('hidden');
});

function openSite(key) {
  const s = state.sites.find(x => x.site_key === key);
  if (!s) return;
  selectSite(s, true);
}

function selectSite(site, push) {
  state.currentSite = site;
  document.getElementById('currentSiteName').textContent = site.name;
  document.getElementById('siteContext').classList.remove('hidden');
  document.getElementById('siteNav').classList.remove('hidden');
  if (push) history.pushState({}, '', '/dashboard?site=' + site.site_key);
  renderSiteMenu();
  navTo('overview');
}

function clearSite() {
  state.currentSite = null;
  document.getElementById('siteContext').classList.add('hidden');
  document.getElementById('siteNav').classList.add('hidden');
  history.pushState({}, '', '/dashboard');
  navTo('sites');
}

function navTo(view) {
  state.view = view;
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById('view-' + view).classList.remove('hidden');
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.remove('active');
    if (b.dataset.nav === view) b.classList.add('active');
  });
  if (view === 'sites') loadSites();
  if (view === 'overview') loadOverview();
  if (view === 'zones') loadZones();
  if (view === 'tracker') renderTracker();
  if (view === 'settings') renderSettings();
}

async function loadOverview() {
  if (!state.currentSite) return;
  document.getElementById('overviewSubtitle').textContent = state.currentSite.name + (state.currentSite.domain ? ' · ' + state.currentSite.domain : '');
  try {
    const r = await fetch('/api/stats?site=' + state.currentSite.site_key);
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('kpi-total').textContent = d.total;
    document.getElementById('kpi-valid').textContent = d.valid;
    document.getElementById('kpi-invalid').textContent = d.invalid;
    document.getElementById('kpi-suspicious').textContent = d.suspicious;
    const tb = document.getElementById('live-table');
    state.visitsData = {};
    if (!d.recent.length) {
      tb.innerHTML = `<tr><td colspan="6" class="text-center py-10 text-slate-400 text-sm">مفيش زيارات لسه — ركّب كود التتبع عشان تبدأ</td></tr>`;
    } else {
      tb.innerHTML = d.recent.map(v => {
        state.visitsData[v.id] = v;
        const badge = v.verdict === 'valid' ? 'bg-emerald-100 text-emerald-700' : v.verdict === 'invalid' ? 'bg-rose-100 text-rose-700' : 'bg-amber-100 text-amber-700';
        const sc = v.score > 80 ? 'text-rose-600 font-bold' : v.score > 40 ? 'text-amber-600 font-bold' : 'text-emerald-600';
        let netIcon = v.conn_type === 'hosting' ? '🚨 DC' : v.conn_type === 'Unknown' ? '❓' : '🏠 Home';
        if (v.is_vpn) netIcon = '🛡️ VPN';
        const netColor = v.is_vpn || v.conn_type === 'hosting' ? 'text-rose-500 font-bold' : 'text-slate-500';
        return `<tr class="hover:bg-slate-50">
          <td class="px-2 py-3 text-slate-500 text-xs text-center">${v.time}</td>
          <td class="px-2 py-3 font-semibold text-xs">${esc(v.zone)}</td>
          <td class="px-2 py-3 text-xs text-center"><div>${esc(v.country)}</div><div class="${netColor}" style="font-size:10px">${netIcon}</div></td>
          <td class="px-2 py-3 ${sc} text-center">${v.score}</td>
          <td class="px-2 py-3 text-center"><span class="${badge} px-2 py-1 rounded-md text-xs font-bold">${v.verdict}</span></td>
          <td class="px-2 py-3 text-center"><button onclick="showDetails(${v.id})" class="text-indigo-600 hover:underline text-xs font-semibold">عرض</button></td>
        </tr>`;
      }).join('');
    }
    renderChart(d);
  } catch (e) { console.error(e); }
}

function renderChart(d) {
  if (state.chart) state.chart.destroy();
  state.chart = new Chart(document.getElementById('qualityChart').getContext('2d'), {
    type: 'doughnut',
    data: { labels: ['Valid', 'Invalid', 'Suspicious'], datasets: [{ data: [d.valid, d.invalid, d.suspicious], backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'], borderWidth: 0 }] },
    options: { cutout: '75%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, font: { size: 11 } } } } }
  });
}

function showDetails(id) {
  const v = state.visitsData[id];
  if (!v) return;
  let html = `<p><strong>Score:</strong> <span class="text-rose-600 font-bold">${v.score}</span></p>`;
  html += `<p><strong>Timezone:</strong> ${esc(v.timezone)}</p>`;
  html += `<p><strong>Hardware:</strong> ${esc(v.hardware)}</p>`;
  html += `<p><strong>Connection:</strong> ${esc(v.conn_type)} (ASN: ${esc(v.asn)})</p>`;
  html += `<p><strong>VPN/Proxy:</strong> <span class="${v.is_vpn ? 'text-rose-600 font-bold' : 'text-emerald-600'}">${v.is_vpn ? 'YES' : 'NO'}</span></p>`;
  html += `<p><strong>WebRTC Leak:</strong> ${esc(v.webrtc || 'None')}</p><hr class="my-2">`;
  if (v.evidence && v.evidence.length) {
    html += `<ul class="list-disc pr-5 space-y-1">` + v.evidence.map(e => `<li>${esc(e)}</li>`).join('') + `</ul>`;
  } else html += `<p class="text-emerald-600">زيارة سليمة.</p>`;
  document.getElementById('modal-content').innerHTML = html;
  document.getElementById('details-modal').classList.remove('hidden');
  document.getElementById('details-modal').classList.add('flex');
}
function closeDetails() {
  document.getElementById('details-modal').classList.add('hidden');
  document.getElementById('details-modal').classList.remove('flex');
}

async function loadZones() {
  if (!state.currentSite) return;
  const r = await fetch('/api/reports/zones?site=' + state.currentSite.site_key);
  if (!r.ok) return;
  const d = await r.json();
  const tb = document.getElementById('zones-table');
  if (!d.length) {
    tb.innerHTML = `<tr><td colspan="4" class="text-center py-10 text-slate-400 text-sm">مفيش زونات لسه</td></tr>`;
    return;
  }
  tb.innerHTML = d.map(z => {
    const g = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700' : z.grade === 'F' ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-700';
    return `<tr class="hover:bg-slate-50">
      <td class="px-5 py-4 font-bold text-slate-700">${esc(z.zone)}</td>
      <td class="px-5 py-4 text-slate-600">${z.total}</td>
      <td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${z.bot_rate}%</span></td>
      <td class="px-5 py-4"><span class="${g} px-3 py-1 rounded-lg text-xs font-bold">${z.grade}</span></td>
    </tr>`;
  }).join('');
}

async function renderTracker() {
  if (!state.currentSite) return;
  document.getElementById('siteKeyInput').value = state.currentSite.site_key;
  document.getElementById('embedCode').textContent = 'جاري التحميل...';
  try {
    const r = await fetch('/api/sites/' + state.currentSite.id + '/tracker-code');
    const d = await r.json();
    document.getElementById('embedCode').textContent = d.code || 'فشل التحميل';
  } catch (e) {
    document.getElementById('embedCode').textContent = 'فشل تحميل الكود';
  }
}

function renderSettings() {
  if (!state.currentSite) return;
  document.getElementById('editName').value = state.currentSite.name;
  document.getElementById('editDomain').value = state.currentSite.domain || '';
}
async function saveSiteSettings() {
  const name = document.getElementById('editName').value.trim();
  const domain = document.getElementById('editDomain').value.trim();
  if (!name) { toast('اسم الموقع مطلوب'); return; }
  const r = await fetch('/api/sites/' + state.currentSite.id, {
    method: 'PATCH', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ name, domain })
  });
  if (r.ok) {
    toast('تم الحفظ ✅');
    await loadSites();
    state.currentSite = state.sites.find(s => s.id === state.currentSite.id);
    document.getElementById('currentSiteName').textContent = state.currentSite.name;
    renderSettings();
  } else toast('فشل الحفظ');
}
async function rotateSiteKey() {
  if (!confirm('تجديد المفتاح هيبطّل الكود القديم. متأكد؟')) return;
  const r = await fetch('/api/sites/' + state.currentSite.id + '/rotate-key', { method: 'POST' });
  const d = await r.json().catch(()=>({}));
  if (r.ok) {
    toast('تم تجديد المفتاح');
    await loadSites();
    state.currentSite = state.sites.find(s => s.id === state.currentSite.id);
    renderTracker();
    renderSettings();
  } else toast(d.detail || 'فشل التجديد');
}
async function deleteCurrentSite() {
  if (!confirm('هل أنت متأكد من حذف "' + state.currentSite.name + '"؟ البيانات مش هترجع تاني.')) return;
  const r = await fetch('/api/sites/' + state.currentSite.id, { method: 'DELETE' });
  if (r.ok) { toast('تم الحذف'); clearSite(); }
  else toast('فشل الحذف');
}

function openSiteModal() {
  document.getElementById('siteModal').classList.remove('hidden');
  document.getElementById('siteModal').classList.add('flex');
  setTimeout(() => document.getElementById('newName').focus(), 50);
}
function closeSiteModal() {
  document.getElementById('siteModal').classList.add('hidden');
  document.getElementById('siteModal').classList.remove('flex');
  document.getElementById('newName').value = '';
  document.getElementById('newDomain').value = '';
}

document.getElementById('siteForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('newName').value.trim();
  const domain = document.getElementById('newDomain').value.trim();
  if (!name) return;
  const r = await fetch('/api/sites', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name, domain }) });
  const d = await r.json().catch(()=>({}));
  if (r.ok) {
    closeSiteModal();
    await loadSites();
    showCreatedModal(d);
  } else {
    toast(d.detail || 'فشل الإنشاء');
  }
});

async function showCreatedModal(site) {
  document.getElementById('createdSiteName').textContent = site.name;
  document.getElementById('createdKey').value = site.site_key;
  document.getElementById('createdCode').textContent = 'جاري التحميل...';
  document.getElementById('createdModal').classList.remove('hidden');
  document.getElementById('createdModal').classList.add('flex');
  window._justCreatedKey = site.site_key;
  try {
    const r = await fetch('/api/sites/' + site.id + '/tracker-code');
    const d = await r.json();
    document.getElementById('createdCode').textContent = d.code || 'فشل التحميل';
  } catch (e) {
    document.getElementById('createdCode').textContent = 'فشل تحميل الكود';
  }
}

function closeCreatedModal() {
  document.getElementById('createdModal').classList.add('hidden');
  document.getElementById('createdModal').classList.remove('flex');
  window._justCreatedKey = null;
  setTimeout(openSiteModal, 200);
}

function goToCreatedDashboard() {
  document.getElementById('createdModal').classList.add('hidden');
  document.getElementById('createdModal').classList.remove('flex');
  const key = window._justCreatedKey;
  window._justCreatedKey = null;
  if (key) {
    const s = state.sites.find(x => x.site_key === key);
    if (s) { selectSite(s, true); return; }
  }
  navTo('sites');
}

async function runMock() {
  if (!state.currentSite) return;
  const r = await fetch('/api/mock-data?site=' + state.currentSite.site_key, { method: 'POST' });
  if (r.ok) { toast('تم توليد 50 زيارة تجريبية'); loadOverview(); }
  else toast('فشل التوليد');
}

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function copyText(t) { navigator.clipboard.writeText(t).then(() => toast('تم النسخ ✅')).catch(() => toast('فشل النسخ')); }
function toast(msg) { const el = document.getElementById('toast'); el.textContent = msg; el.classList.remove('hidden'); clearTimeout(el._t); el._t = setTimeout(() => el.classList.add('hidden'), 2500); }
function timeAgo(d) { const s = Math.floor((Date.now() - d.getTime())/1000); if (s < 60) return 'قبل لحظات'; if (s < 3600) return 'قبل ' + Math.floor(s/60) + ' د'; if (s < 86400) return 'قبل ' + Math.floor(s/3600) + ' س'; return 'قبل ' + Math.floor(s/86400) + ' يوم'; }

async function doLogout() {
  await fetch('/api/auth/logout', { method: 'POST' });
  location.href = '/';
}

setInterval(() => { if (state.view === 'overview' && state.currentSite) loadOverview(); }, 15000);

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
