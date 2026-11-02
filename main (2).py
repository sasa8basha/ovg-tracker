"""
OVG Tracker — Session 4.1 (All Visits + Visit Details)
"""
import json
import random
import os
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
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

Base.metadata.create_all(bind=engine)
bootstrap_admin()

# =========================================================
# APP & STATIC FILES
# =========================================================
app = FastAPI(title="OVG Tracker", version="4.1")

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
        raise HTTPException(400, "اسم الموقع طويل جداً (أقصى 100 حرف)")
    if len(domain) > 253:
        raise HTTPException(400, "الدومين طويل جداً")

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
# TRACKER TEMPLATE & TRACKING
# =========================================================
TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  var SITE_KEY = '__OVG_SITE_KEY__';
  var ENDPOINT = '__OVG_ENDPOINT__';
  var SEND_DELAY_MS = 4000;
  var WEBRTC_TIMEOUT = 1500;

  var startTime = Date.now();
  var mousemoves = 0, touchstarts = 0, clicks = 0, scrolls = 0;
  var mouseX = [], mouseY = [];
  var sent = false;

  document.addEventListener('mousemove', function (e) {
    mousemoves++;
    mouseX.push(e.clientX); mouseY.push(e.clientY);
    if (mouseX.length > 200) { mouseX.shift(); mouseY.shift(); }
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
    return {
      url: location.href,
      site_key: SITE_KEY,
      nav: { ua: navigator.userAgent, platform: navigator.platform || '', webdriver: navigator.webdriver === true },
      fingerprint: { timezone: getTimezone(), canvas_hash: getCanvasHash(), hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0, deviceMemory: Number(navigator.deviceMemory) || 0, webgl: getWebGL() },
      behavior: { 
        time_on_page_ms: Date.now() - startTime, 
        mouse_variance: variance(mouseX) + variance(mouseY), 
        events: { mousemove: mousemoves, touchstart: touchstarts, clicks: clicks, scrolls: scrolls } 
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
      fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body, keepalive: true }).catch(function (err) { console.error('[OVG Tracker] Send failed:', err); });
    });
  }

  setTimeout(send, SEND_DELAY_MS);
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

    try:
        data = payload.model_dump()
    except AttributeError:
        data = payload.dict()
    data["client_ip"] = client_ip
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
        scrolls=events.get("scrolls", 0)
    )
    try:
        db.add(visit)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(500, "DB write failed")
    return {"status": "success"}

# =========================================================
# STATS & VISITS REPORTS
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

    report = []
    for z in rows:
        total, invalid = int(z.total or 0), int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = "A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

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
    return {
        "id": v.id, "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        "ip": v.ip, "zone_id": v.zone_id, "score": v.score, "verdict": v.verdict, "evidence": v.evidence or [],
        "os": v.os, "device": v.device, "browser": v.browser, "country": v.country, "isp": v.isp,
        "timezone": v.timezone, "canvas_hash": v.canvas_hash, "hardware": v.hardware,
        "connection_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc_ip": v.webrtc_ip,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls
    }

@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    for _ in range(50):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid" else random.randint(70, 100) if v == "invalid" else random.randint(40, 69))
        db.add(VisitModel(
            site_id=s.id, ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones), 
            score=sc, verdict=v, evidence=["Mock Data"], country="US", isp="Mock ISP", 
            connection_type="residential",
            time_on_page=random.randint(1000, 15000),
            clicks=random.randint(0, 5),
            scrolls=random.randint(0, 10)
        ))
    db.commit()
    return {"status": "ok"}

@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}

@app.get("/debug/site/{site_key}")
def debug_site(site_key: str, db: Session = Depends(get_db)):
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key).first()
    if not s:
        return {"exists": False, "error": "❌ الـ site_key ده مش موجود في الداتابيز", "received_key": site_key, "total_sites_in_db": db.query(func.count(SiteModel.id)).scalar()}
    visits = db.query(func.count(VisitModel.id)).filter(VisitModel.site_id == s.id).scalar() or 0
    return {"exists": True, "site_name": s.name, "domain": s.domain, "site_key": s.site_key, "visits_count": visits, "created_at": s.created_at.isoformat() if s.created_at else None}

@app.get("/tracker.js")
def tracker_js():
    return Response(content=TRACKER_CODE_TEMPLATE, media_type="application/javascript", headers={"Cache-Control": "public, max-age=3600"})

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
    if _optional_user(request, db):
        return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(read_template("login.html"))

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, key: str = None, db: Session = Depends(get_db)):
    if key and DASHBOARD_KEY and key == DASHBOARD_KEY:
        first = db.query(UserModel).first()
        if first:
            resp = RedirectResponse("/dashboard", status_code=302)
            resp.set_cookie(SESSION_COOKIE, make_token(first.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("dashboard.html"))

@app.get("/visits", response_class=HTMLResponse)
def all_visits_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("visits.html"))

@app.get("/visits/{visit_id}", response_class=HTMLResponse)
def visit_detail_page(request: Request, visit_id: int, db: Session = Depends(get_db)):
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("visit_detail.html"))