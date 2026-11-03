"""
OVG Tracker — Session 5.0 (Advanced Tracking Phase A)
"""
import json
import random
import os
import csv
import io
import re
from collections import Counter
from datetime import datetime, timedelta
from fastapi import (
    Depends, FastAPI, HTTPException, Query, Request, Response,
    BackgroundTasks,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import case, func, desc, and_, not_
from sqlalchemy.orm import Session

from config import (
    DASHBOARD_KEY, ALLOWED_ORIGINS, MAX_SITES_PER_USER,
    SESSION_COOKIE, SESSION_TTL, HEX_KEY_RE, USERNAME_RE,
    ENV, PUBLIC_URL,
)
from database import engine, SessionLocal, Base, get_db, run_migrations
from models import (
    UserModel, SiteModel, VisitModel,
    PasswordResetToken, EmailVerificationToken,
)
from utils import (
    get_client_ip, safe_origin, track_limiter, signup_limiter, login_limiter,
    stats_cache, zone_evidence_cache,
    forgot_password_limiter, reset_password_limiter, verify_resend_limiter,
)
from auth import (
    hash_password, verify_password, password_strength, is_valid_email, normalize_email,
    make_token, verify_token, _optional_user, current_user, bootstrap_admin,
    create_password_reset_otp, consume_password_reset_otp,
    create_email_verification_token, consume_email_verification_token,
)
from analysis import (
    get_ip_info, parse_ua, extract_zone_id, new_site_key, analyze_visit,
    calc_confidence, count_categories, normalize_stored_evidence,
)
from email_service import (
    send_password_reset_email, send_email_verification, send_welcome_email,
)

Base.metadata.create_all(bind=engine)
run_migrations()
bootstrap_admin()

app = FastAPI(title="OVG Tracker", version="5.0")
app.mount("/static", StaticFiles(directory="static"), name="static")

if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# =========================================================
# HELPERS
# =========================================================
def csv_safe(val):
    if val is None: return ""
    s = str(val)
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s

def _country_key(country_code, country_name):
    code = (country_code or "").strip().upper()
    if code and code not in ("LO", "XX"):
        return code
    return (country_name or "Unknown").strip() or "Unknown"

def _parse_date(s):
    if not s: return None
    try:
        return datetime.strptime(str(s).strip(), "%Y-%m-%d")
    except (ValueError, TypeError):
        return None

def _apply_date_filter(q, from_date, to_date):
    fd = _parse_date(from_date)
    td = _parse_date(to_date)
    if fd: q = q.filter(VisitModel.timestamp >= fd)
    if td: q = q.filter(VisitModel.timestamp < (td + timedelta(days=1)))
    return q

def _safe_filename(base, *parts):
    s = "_".join([base] + [str(p) for p in parts if p])
    s = re.sub(r"[^a-zA-Z0-9_.-]", "_", s)[:100]
    return (s or "export") + ".csv"


# =========================================================
# SCHEMAS
# =========================================================
class AuthIn(BaseModel):
    username: str
    password: str
    email: str = ""

class ForgotPasswordIn(BaseModel):
    email: str

class ResetPasswordIn(BaseModel):
    email: str
    otp: str
    new_password: str

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

class ProfileUpdateIn(BaseModel):
    username: str = ""
    email: str = ""

class DeleteAccountIn(BaseModel):
    password: str
    confirm: str

class SiteIn(BaseModel):
    name: str
    domain: str = ""

class TrackPayload(BaseModel):
    url: str
    site_key: str = ""
    nav: dict = {}
    fingerprint: dict = {}
    behavior: dict = {}
    webrtc_ip: str = "None"

# =========================================================
# AUTH ROUTES
# =========================================================
@app.post("/api/auth/signup")
def signup(payload: AuthIn, request: Request, response: Response,
           background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    signup_limiter.check(client_ip)
    username = payload.username.strip()
    password = payload.password
    email = normalize_email(payload.email)

    if not USERNAME_RE.match(username):
        raise HTTPException(400, "اسم المستخدم لازم 3-32 حرف (إنجليزي وأرقام و _ . -)")
    ok, reason = password_strength(password)
    if not ok: raise HTTPException(400, reason)
    if not is_valid_email(email): raise HTTPException(400, "البريد الإلكتروني غير صالح")
    if db.query(UserModel).filter(UserModel.username == username).first():
        raise HTTPException(400, "اسم المستخدم مستخدم بالفعل")
    if db.query(UserModel).filter(UserModel.email == email).first():
        raise HTTPException(400, "البريد الإلكتروني مستخدم بالفعل")

    u = UserModel(username=username, password_hash=hash_password(password),
                  email=email, email_verified=False, token_version=1)
    db.add(u); db.commit(); db.refresh(u)

    response.set_cookie(SESSION_COOKIE, make_token(u), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    
    raw_token = create_email_verification_token(u.id, db)
    if raw_token:
        verify_url = f"{PUBLIC_URL}/verify-email?token={raw_token}"
        background_tasks.add_task(send_email_verification, u.email, u.username, verify_url)
    background_tasks.add_task(send_welcome_email, u.email, u.username)
    return {"ok": True, "username": u.username, "email": u.email}

@app.post("/api/auth/login")
def login(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    login_limiter.check(client_ip)
    identifier = payload.username.strip()
    u = None
    if identifier:
        u = db.query(UserModel).filter(UserModel.username == identifier).first()
        if not u and "@" in identifier:
            u = db.query(UserModel).filter(UserModel.email == normalize_email(identifier)).first()
    if not u or not verify_password(payload.password, u.password_hash):
        raise HTTPException(401, "بيانات الدخول غلط")
    response.set_cookie(SESSION_COOKIE, make_token(u), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}

@app.get("/api/auth/me")
def me(user: UserModel = Depends(current_user)):
    return {"id": user.id, "username": user.username, "email": user.email,
            "email_verified": bool(user.email_verified),
            "created_at": user.created_at.isoformat() if user.created_at else None}

@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordIn, request: Request,
                    background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    forgot_password_limiter.check(client_ip)
    email = normalize_email(payload.email)
    msg = "لو البريد موجود عندنا، هيوصلك كود مكون من 6 أرقام في دقايق."
    if not is_valid_email(email): return {"ok": True, "message": msg}
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user: return {"ok": True, "message": msg}
    otp = create_password_reset_otp(user.id, client_ip, db)
    if otp: background_tasks.add_task(send_password_reset_email, user.email, user.username, otp)
    return {"ok": True, "message": msg}

@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordIn, request: Request,
                   response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    reset_password_limiter.check(client_ip)
    ok, reason = password_strength(payload.new_password)
    if not ok: raise HTTPException(400, reason)
    email = normalize_email(payload.email)
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user: raise HTTPException(400, "الكود غير صالح أو الإيميل غير مسجل")
    if not consume_password_reset_otp(user.id, payload.otp, db):
        raise HTTPException(400, "الكود غير صحيح أو منتهي الصلاحية. اطلب كود جديد.")
    user.password_hash = hash_password(payload.new_password)
    user.token_version = int(user.token_version or 1) + 1
    db.commit(); db.refresh(user)
    response.set_cookie(SESSION_COOKIE, make_token(user), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "message": "تم إعادة تعيين كلمة المرور. باقي الأجهزة اتسجلت خروج."}

@app.post("/api/auth/resend-verification")
def resend_verification(request: Request, background_tasks: BackgroundTasks,
                        user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    verify_resend_limiter.check(client_ip)
    if not user.email: raise HTTPException(400, "مفيش بريد إلكتروني مرتبط بالحساب")
    if user.email_verified: return {"ok": True, "message": "البريد مفعّل بالفعل"}
    raw_token = create_email_verification_token(user.id, db)
    if raw_token:
        verify_url = f"{PUBLIC_URL}/verify-email?token={raw_token}"
        background_tasks.add_task(send_email_verification, user.email, user.username, verify_url)
    return {"ok": True, "message": "تم إرسال رابط التفعيل تاني"}

# =========================================================
# SETTINGS ENDPOINTS
# =========================================================
@app.get("/api/settings")
def get_settings(user: UserModel = Depends(current_user)):
    return {"id": user.id, "username": user.username, "email": user.email,
            "email_verified": bool(user.email_verified),
            "created_at": user.created_at.isoformat() if user.created_at else None}

@app.patch("/api/settings/profile")
def update_profile(payload: ProfileUpdateIn, request: Request, background_tasks: BackgroundTasks,
                   user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    changed_username = False; changed_email = False
    new_username = payload.username.strip() if payload.username else ""
    new_email = normalize_email(payload.email) if payload.email else ""
    if new_username and new_username != user.username:
        if not USERNAME_RE.match(new_username): raise HTTPException(400, "اسم المستخدم غير صالح")
        if db.query(UserModel).filter(UserModel.username == new_username, UserModel.id != user.id).first():
            raise HTTPException(400, "اسم المستخدم مستخدم بالفعل")
        user.username = new_username; changed_username = True
    if new_email and new_email != (user.email or ""):
        if not is_valid_email(new_email): raise HTTPException(400, "البريد غير صالح")
        if db.query(UserModel).filter(UserModel.email == new_email, UserModel.id != user.id).first():
            raise HTTPException(400, "البريد مستخدم بالفعل")
        user.email = new_email; user.email_verified = False; changed_email = True
    db.commit(); db.refresh(user)
    if changed_email:
        raw_token = create_email_verification_token(user.id, db)
        if raw_token:
            verify_url = f"{PUBLIC_URL}/verify-email?token={raw_token}"
            background_tasks.add_task(send_email_verification, user.email, user.username, verify_url)
    return {"ok": True, "username": user.username, "email": user.email,
            "email_verified": bool(user.email_verified),
            "changed_username": changed_username, "changed_email": changed_email}

@app.post("/api/settings/change-password")
def change_password(payload: ChangePasswordIn, response: Response,
                    user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "كلمة المرور الحالية غلط")
    ok, reason = password_strength(payload.new_password)
    if not ok: raise HTTPException(400, reason)
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(400, "كلمة المرور الجديدة مطابقة للقديمة")
    user.password_hash = hash_password(payload.new_password)
    user.token_version = int(user.token_version or 1) + 1
    db.commit(); db.refresh(user)
    response.set_cookie(SESSION_COOKIE, make_token(user), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "message": "تم تغيير كلمة المرور."}

@app.post("/api/settings/logout-all")
def logout_all(response: Response, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    user.token_version = int(user.token_version or 1) + 1
    db.commit(); db.refresh(user)
    response.set_cookie(SESSION_COOKIE, make_token(user), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "message": "تم تسجيل الخروج من باقي الأجهزة"}

@app.delete("/api/settings/account")
def delete_account(payload: DeleteAccountIn, response: Response,
                   user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(400, "كلمة المرور غلط")
    if payload.confirm.strip() != user.username:
        raise HTTPException(400, "لازم تكتب اسم المستخدم بالظبط للتأكيد")
    try:
        site_ids = [s.id for s in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        if site_ids: db.query(VisitModel).filter(VisitModel.site_id.in_(site_ids)).delete(synchronize_session=False)
        db.query(SiteModel).filter(SiteModel.user_id == user.id).delete(synchronize_session=False)
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete(synchronize_session=False)
        db.query(EmailVerificationToken).filter(EmailVerificationToken.user_id == user.id).delete(synchronize_session=False)
        db.delete(user); db.commit()
    except Exception as e:
        db.rollback(); raise HTTPException(500, f"Delete failed: {e}")
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}

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
        out.append({"id": s.id, "name": s.name, "domain": s.domain, "site_key": s.site_key,
                    "total": int(st.total or 0) if st else 0, "valid": int(st.valid or 0) if st else 0,
                    "invalid": int(st.invalid or 0) if st else 0,
                    "last_visit": st.last.isoformat() if st and st.last else None,
                    "created_at": s.created_at.isoformat() if s.created_at else None})
    return out

@app.post("/api/sites")
def create_site(payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    count = db.query(SiteModel).filter(SiteModel.user_id == user.id).count()
    if count >= MAX_SITES_PER_USER: raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_SITES_PER_USER} موقع)")
    name = payload.name.strip(); domain = payload.domain.strip()
    if not name: raise HTTPException(400, "اسم الموقع مطلوب")
    if len(name) > 100: raise HTTPException(400, "اسم الموقع طويل جداً")
    site = SiteModel(user_id=user.id, name=name, domain=domain, site_key=new_site_key())
    db.add(site); db.commit(); db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}

@app.patch("/api/sites/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع مش موجود")
    site.name = payload.name.strip(); site.domain = payload.domain.strip()[:253]
    db.commit(); return {"ok": True}

@app.delete("/api/sites/{site_id}")
def delete_site(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع مش موجود")
    stats_cache.invalidate(f"stats:site:{site.id}"); stats_cache.invalidate(f"stats:user:{user.id}:all")
    zone_evidence_cache.invalidate_prefix(f"zone_ev:")
    db.query(VisitModel).filter(VisitModel.site_id == site.id).delete()
    db.delete(site); db.commit()
    return {"ok": True}

@app.post("/api/sites/{site_id}/rotate-key")
def rotate_key(site_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع مش موجود")
    stats_cache.invalidate(f"stats:site:{site.id}")
    site.site_key = new_site_key(); db.commit(); return {"site_key": site.site_key}

def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key: raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key, SiteModel.user_id == user.id).first()
    if not s: raise HTTPException(404, "الموقع مش موجود أو مش بتاعك")
    return s

# =========================================================
# TRACKER (Phase A — Smart JS)
# =========================================================
TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  var SITE_KEY = '__OVG_SITE_KEY__';
  var ENDPOINT = '__OVG_ENDPOINT__';
  var SEND_DELAY_MS = 3000; // نستنى 3 ثواني عشان نجمع بيانات كفاية
  var startTime = Date.now();

  // 1. Data Collectors
  var mousemoves = 0, clicks = 0, scrolls = 0;
  var maxScrollDepth = 0;
  var keyPresses = 0;
  var hasCopied = false;
  var hasSwitchedTab = false;
  
  var mousePoints = [];
  var keyTimes = {};
  
  var velocities = [];
  var lastMouseX = 0, lastMouseY = 0, lastMouseTime = Date.now();
  var directionChanges = 0, lastDirection = 0;

  var audioHash = 'unknown';
  try {
    var audioCtx = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 44100, 44100);
    var oscillator = audioCtx.createOscillator();
    oscillator.type = 'triangle';
    oscillator.frequency.setValueAtTime(10000, audioCtx.currentTime);
    var compressor = audioCtx.createDynamicsCompressor();
    oscillator.connect(compressor);
    compressor.connect(audioCtx.destination);
    oscillator.start(0);
    audioCtx.startRendering().then(function(buffer) {
      var data = buffer.getChannelData(0);
      var sum = 0;
      for (var i = 4500; i < 5000; i++) sum += Math.abs(data[i]);
      audioHash = sum.toString().slice(0, 10);
    }).catch(function() {});
  } catch(e) {}

  document.addEventListener('mousemove', function (e) {
    mousemoves++;
    var now = Date.now();
    var dt = now - lastMouseTime;
    
    if (dt > 0 && mousemoves > 1) {
      var dx = e.clientX - lastMouseX;
      var dy = e.clientY - lastMouseY;
      var dist = Math.sqrt(dx*dx + dy*dy);
      velocities.push(dist / dt);
      
      var dir = Math.sign(dx) || Math.sign(dy);
      if (lastDirection !== 0 && dir !== lastDirection) directionChanges++;
      lastDirection = dir;
    }
    
    lastMouseX = e.clientX; lastMouseY = e.clientY; lastMouseTime = now;

    if (mousePoints.length < 100) {
        mousePoints.push({x: e.clientX, y: e.clientY, t: now});
    }
  }, { passive: true });

  document.addEventListener('click', function () { clicks++; }, { passive: true });
  
  document.addEventListener('scroll', function () {
    scrolls++;
    var scrollTop = window.scrollY || document.documentElement.scrollTop;
    var docHeight = document.documentElement.scrollHeight - window.innerHeight;
    var depth = Math.round((scrollTop / docHeight) * 100);
    if (depth > maxScrollDepth) maxScrollDepth = depth;
  }, { passive: true });

  document.addEventListener('copy', function() { hasCopied = true; }, { passive: true });
  
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') hasSwitchedTab = true;
  });

  document.addEventListener('keydown', function(e) {
    if (e.repeat) return;
    keyTimes[e.code] = Date.now();
    keyPresses++;
  }, { passive: true });

  document.addEventListener('keyup', function(e) {
    var down = keyTimes[e.code];
    if (down) {
      delete keyTimes[e.code];
    }
  }, { passive: true });

  function calculateMetrics() {
    var avgVel = 0, maxVel = 0, variance = 0;
    if (velocities.length > 0) {
      for (var i = 0; i < velocities.length; i++) {
        avgVel += velocities[i];
        if (velocities[i] > maxVel) maxVel = velocities[i];
      }
      avgVel = avgVel / velocities.length;
      for (var i = 0; i < velocities.length; i++) {
        variance += Math.pow(velocities[i] - avgVel, 2);
      }
      variance = variance / velocities.length;
    }
    return {
      avg_velocity: avgVel.toFixed(4),
      max_velocity: maxVel.toFixed(4),
      velocity_variance: variance.toFixed(4),
      direction_changes: directionChanges
    };
  }

  function getWebGL() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { renderer: 'blocked', vendor: 'blocked' };
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return { renderer: 'Unknown', vendor: 'Unknown' };
      return {
        renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown').substring(0, 50),
        vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown').substring(0, 50)
      };
    } catch (e) { return { renderer: 'blocked', vendor: 'blocked' }; }
  }

  function sendPayload(isExit) {
    var timeOnPage = Date.now() - startTime;
    var isSampled = Math.random() < 0.05; 
    var rawPath = isSampled ? mousePoints : null;

    var payload = {
      url: location.href,
      site_key: SITE_KEY,
      nav: {
        ua: navigator.userAgent,
        platform: navigator.platform || '',
        webdriver: navigator.webdriver === true
      },
      fingerprint: {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown',
        hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
        deviceMemory: Number(navigator.deviceMemory) || 0,
        webgl: getWebGL(),
        audio_hash: audioHash,
        screen: { w: screen.width, h: screen.height, ratio: window.devicePixelRatio || 1 }
      },
      behavior: {
        time_on_page_ms: timeOnPage,
        metrics: calculateMetrics(),
        events: {
          mousemove: mousemoves,
          clicks: clicks,
          scrolls: scrolls,
          max_scroll_depth: maxScrollDepth,
          key_presses: keyPresses,
          has_copied: hasCopied,
          has_switched_tab: hasSwitchedTab
        },
        raw_mouse_path: rawPath
      }
    };

    var body = JSON.stringify(payload);
    
    if (isExit && navigator.sendBeacon) {
      navigator.sendBeacon(ENDPOINT, body);
    } else {
      fetch(ENDPOINT, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: body, 
        keepalive: true 
      }).catch(function() {});
    }
  }

  setTimeout(function() { sendPayload(false); }, SEND_DELAY_MS);
  window.addEventListener('pagehide', function() { sendPayload(true); });
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') sendPayload(true);
  });

})();
</script>"""

@app.get("/api/sites/{site_id}/tracker-code")
def get_tracker_code(site_id: int, request: Request, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع مش موجود")
    if not HEX_KEY_RE.match(site.site_key or ""):
        site.site_key = new_site_key(); db.commit()
    origin = safe_origin(request)
    endpoint = f"{origin}/api/track"
    code = TRACKER_CODE_TEMPLATE.replace("__OVG_SITE_KEY__", site.site_key).replace("__OVG_ENDPOINT__", endpoint)
    return Response(content='{"code":' + json.dumps(code) + '}', media_type="application/json",
                    headers={"Cache-Control": "no-store, max-age=0"})

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
    
    behavior = payload.behavior or {}
    metrics = behavior.get("metrics", {})
    events = behavior.get("events", {})
    raw_mouse_path = behavior.get("raw_mouse_path")
    
    behavior_data_to_store = {"metrics": metrics, "events": events}

    canvas_raw = str((data.get("fingerprint") or {}).get("canvas_hash") or "")
    recent_fp_count = 0
    if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
        try:
            cutoff = datetime.utcnow() - timedelta(minutes=1)
            recent_fp_count = db.query(VisitModel).filter(
                VisitModel.canvas_hash == (canvas_raw[:15] + "..."),
                VisitModel.timestamp > cutoff,
            ).count()
        except Exception: recent_fp_count = 0
    data["_recent_fp_count"] = recent_fp_count

    result = analyze_visit(data, ip_info)
    fp = data.get("fingerprint") or {}

    cc = str(ip_info.get("country_code") or "").upper().strip()
    cc_stored = None if cc in ("LO", "XX", "") else cc[:2]

    visit = VisitModel(
        site_id=site_id, ip=client_ip, user_agent=ua, zone_id=zone_id,
        score=result["score"], verdict=result["verdict"], evidence=result["evidence"],
        os=os_name, device=device, browser=browser,
        country=ip_info["country"], country_code=cc_stored, isp=ip_info["isp"],
        timezone=fp.get("timezone", "Unknown"),
        canvas_hash=(str(fp.get("canvas_hash", "Unknown"))[:15] + "..."),
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"], asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"),
        webrtc_ip=payload.webrtc_ip,
        time_on_page=behavior.get("time_on_page_ms", 0),
        clicks=events.get("clicks", 0), scrolls=events.get("scrolls", 0),
        latitude=ip_info.get("lat", 0.0), longitude=ip_info.get("lon", 0.0),
        behavior_data=behavior_data_to_store,
        raw_mouse_path=raw_mouse_path
    )
    try:
        db.add(visit); db.commit()
    except Exception:
        db.rollback(); raise HTTPException(500, "DB write failed")

    if site_id: stats_cache.invalidate(f"stats:site:{site_id}")
    return {"status": "success"}

# =========================================================
# STATS / VISITS / EXPORT / REPORTS (كما هي)
# =========================================================
@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    if site:
        s = _resolve_user_site(site, user, db)
        cache_key = f"stats:site:{s.id}"; site_id_filter = s.id
    else:
        cache_key = f"stats:user:{user.id}:all"; site_id_filter = None
    cached = stats_cache.get(cache_key)
    if cached is not None: return cached
    def _build():
        q = db.query(VisitModel)
        if site_id_filter is not None: q = q.filter(VisitModel.site_id == site_id_filter)
        else: q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
        return q
    agg = _build().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    ).one()
    total = int(agg.total or 0); valid = int(agg.valid or 0)
    invalid = int(agg.invalid or 0); suspicious = int(agg.suspicious or 0)
    recent = _build().order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country, "score": v.score,
        "evidence": v.evidence, "timezone": v.timezone, "hardware": v.hardware,
        "conn_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip,
    } for v in recent]
    result = {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}
    stats_cache.set(cache_key, result)
    return result

@app.get("/api/visits")
def get_visits(
    site: str = Query(None), verdict: str = Query(None), country: str = Query(None),
    zone: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    page: int = Query(1, ge=1), per_page: int = Query(20, ge=10, le=100),
    cursor: int = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
    if verdict: q = q.filter(VisitModel.verdict == verdict)
    if country: q = q.filter((VisitModel.country_code == country) | (VisitModel.country == country))
    if zone: q = q.filter(VisitModel.zone_id == zone)
    q = _apply_date_filter(q, from_date, to_date)

    if cursor is not None:
        q = q.filter(VisitModel.id < cursor)
        visits = q.order_by(VisitModel.id.desc()).limit(per_page + 1).all()
        has_more = len(visits) > per_page
        visits = visits[:per_page]
        next_cursor = visits[-1].id if has_more else None
        total = None; pages = None; page = None
    else:
        try:
            rows = q.with_entities(VisitModel, func.count().over().label("tc")).order_by(VisitModel.id.desc()).offset((page-1)*per_page).limit(per_page).all()
            if rows: total = int(rows[0][1]); visits = [r[0] for r in rows]
            else: total = q.count(); visits = []
        except Exception:
            total = q.count(); visits = q.order_by(VisitModel.id.desc()).offset((page-1)*per_page).limit(per_page).all()
        pages = (total + per_page - 1) // per_page if total else 0
        next_cursor = None

    items = [{
        "id": v.id, "time": v.timestamp.strftime("%Y-%m-%d %H:%M") if v.timestamp else "",
        "ip": v.ip, "zone": v.zone_id, "verdict": v.verdict, "score": v.score,
        "country": v.country, "country_code": v.country_code,
        "device": v.device, "browser": v.browser,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls,
    } for v in visits]
    return {"items": items, "total": total, "page": page, "pages": pages, "next_cursor": next_cursor}

@app.get("/api/visits/{visit_id}")
def get_visit_detail(visit_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(SiteModel).filter(VisitModel.id == visit_id, SiteModel.user_id == user.id).first()
    if not v: raise HTTPException(404, "غير مصرح لك بعرض هذه الزيارة")
    evidence = v.evidence or []
    signals = normalize_stored_evidence(evidence)
    return {
        "id": v.id, "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        "ip": v.ip, "zone_id": v.zone_id, "score": v.score, "verdict": v.verdict, "evidence": evidence,
        "os": v.os, "device": v.device, "browser": v.browser,
        "country": v.country, "country_code": v.country_code, "isp": v.isp,
        "timezone": v.timezone, "canvas_hash": v.canvas_hash, "hardware": v.hardware,
        "connection_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc_ip": v.webrtc_ip,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls,
        "confidence": calc_confidence(signals),
        "raw_score": sum(s.get("score", 0) for s in signals),
        "categories": count_categories(signals),
        "behavior_data": v.behavior_data,
        "raw_mouse_path": v.raw_mouse_path
    }

@app.get("/api/export/visits")
def export_visits(
    site: str = Query(None), verdict: str = Query(None), zone: str = Query(None),
    from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
    if verdict: q = q.filter(VisitModel.verdict == verdict)
    if zone: q = q.filter(VisitModel.zone_id == zone)
    q = _apply_date_filter(q, from_date, to_date).order_by(VisitModel.id.desc()).limit(5000)

    fd = _parse_date(from_date); td = _parse_date(to_date)
    parts = []
    if verdict: parts.append(verdict)
    if fd: parts.append(fd.strftime("%Y%m%d"))
    if td: parts.append(td.strftime("%Y%m%d"))
    filename = _safe_filename("ovg_visits", *parts) if parts else "ovg_visits_export.csv"

    def iter_csv():
        try:
            out = io.StringIO(); w = csv.writer(out)
            w.writerow(["ID","Time","IP","Country","Country Code","Zone","Verdict","Score","OS","Browser","Device","Time on Page (s)","Clicks","Scrolls","ISP","ASN","VPN"])
            yield out.getvalue(); out.seek(0); out.truncate(0)
            for v in q.yield_per(500):
                row = [v.id, v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
                       v.ip, v.country, v.country_code or "", v.zone_id, v.verdict, v.score,
                       v.os, v.browser, v.device,
                       round(v.time_on_page/1000,1) if v.time_on_page else 0,
                       v.clicks, v.scrolls, v.isp, v.asn, v.is_vpn]
                w.writerow([csv_safe(x) for x in row])
                yield out.getvalue(); out.seek(0); out.truncate(0)
        except GeneratorExit: return
        except Exception as e: print(f"Export error: {e}")

    return StreamingResponse(iter_csv(), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})

@app.get("/api/reports/zones")
def get_zone_reports(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    inv = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    sus = func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0))
    val = func.sum(case((VisitModel.verdict == "valid", 1), else_=0))
    q = db.query(VisitModel.zone_id, func.count(VisitModel.id).label("total"),
                 val.label("valid"), inv.label("invalid"), sus.label("suspicious"))
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.zone_id).all()

    report = []
    for z in rows:
        if not z.zone_id or z.zone_id == "unknown": continue
        total = int(z.total or 0); invalid = int(z.invalid or 0)
        rate = round(invalid/total*100, 1) if total else 0.0
        grade = "?" if total < 10 else ("A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F")
        report.append({"zone": z.zone_id, "total": total, "valid": int(z.valid or 0),
                       "invalid": invalid, "suspicious": int(z.suspicious or 0),
                       "bot_rate": rate, "grade": grade, "min_sample_met": total >= 10})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

@app.get("/api/reports/countries")
def report_countries(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(VisitModel.country_code, VisitModel.country,
                 func.count(VisitModel.id).label("total"),
                 func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
                 func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
                 func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"))
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.country_code, VisitModel.country).all()

    cmap = {}
    for r in rows:
        k = _country_key(r.country_code, r.country)
        if k not in cmap: cmap[k] = {"code": r.country_code or None, "name": r.country or "Unknown",
                                     "total": 0, "valid": 0, "invalid": 0, "suspicious": 0}
        cmap[k]["total"] += int(r.total or 0); cmap[k]["valid"] += int(r.valid or 0)
        cmap[k]["invalid"] += int(r.invalid or 0); cmap[k]["suspicious"] += int(r.suspicious or 0)
    result = list(cmap.values())
    for c in result: c["bot_rate"] = round(c["invalid"]/c["total"]*100, 1) if c["total"] else 0.0
    result.sort(key=lambda x: x["total"], reverse=True)
    return result[:15]

@app.get("/api/reports/tech")
def report_tech(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    def _q(col):
        q = db.query(col, VisitModel.verdict, func.count(VisitModel.id).label("count"))
        if site:
            s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
        else:
            q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
        q = _apply_date_filter(q, from_date, to_date)
        return q.group_by(col, VisitModel.verdict).all()
    def _agg(rows, attr):
        m = {}
        for r in rows:
            n = getattr(r, attr, None) or "Unknown"
            if n not in m: m[n] = {"name": n, "total": 0, "valid": 0, "invalid": 0, "suspicious": 0}
            m[n][r.verdict] = int(r.count or 0); m[n]["total"] += int(r.count or 0)
        return sorted(m.values(), key=lambda x: x["total"], reverse=True)
    return {"devices": _agg(_q(VisitModel.device), "device"),
            "browsers": _agg(_q(VisitModel.browser), "browser")}

@app.get("/api/map/visits")
def map_visits(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(SiteModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    visits = q.filter(not_(and_(VisitModel.latitude == 0.0, VisitModel.longitude == 0.0))).order_by(VisitModel.id.desc()).limit(1000).all()
    return [{"id": v.id, "lat": v.latitude, "lng": v.longitude, "verdict": v.verdict,
             "country": v.country, "ip": v.ip} for v in visits]

@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    if ENV != "dev": raise HTTPException(404, "Not Found")
    s = _resolve_user_site(site, user, db)
    zones = ["10245", "88321", "55410", "99120"]
    countries = [("Egypt","EG",30.0444,31.2357),("United States","US",37.7749,-122.4194),
                 ("India","IN",20.5937,78.9629),("United Kingdom","GB",51.5074,-0.1278)]
    for _ in range(50):
        v = random.choices(["valid","invalid","suspicious"], weights=[75,20,5])[0]
        sc = random.randint(0,30) if v=="valid" else random.randint(70,100) if v=="invalid" else random.randint(40,69)
        cn, cc, clat, clon = random.choice(countries)
        db.add(VisitModel(site_id=s.id, ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones),
                          score=sc, verdict=v, evidence=["Mock Data"], country=cn, country_code=cc,
                          isp="Mock ISP", connection_type="residential",
                          time_on_page=random.randint(1000,15000),
                          clicks=random.randint(0,5), scrolls=random.randint(0,10),
                          latitude=clat+random.uniform(-2,2), longitude=clon+random.uniform(-2,2)))
    db.commit()
    stats_cache.invalidate(f"stats:site:{s.id}"); stats_cache.invalidate(f"stats:user:{user.id}:all")
    zone_evidence_cache.invalidate_prefix("zone_ev:")
    return {"status": "ok"}

@app.get("/health")
def health(): return {"status": "ok", "version": app.version}

# =========================================================
# PAGE ROUTES
# =========================================================
def read_template(name):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base_dir, "templates", name), "r", encoding="utf-8") as f:
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
            resp.set_cookie(SESSION_COOKIE, make_token(first), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
            return resp
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("dashboard.html"))

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    if not _optional_user(request, db): return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("settings.html"))

@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request, db: Session = Depends(get_db)):
    if _optional_user(request, db): return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(read_template("forgot_password.html"))

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse("/forgot-password", status_code=302)

@app.get("/verify-email", response_class=HTMLResponse)
def verify_email_page(token: str = "", db: Session = Depends(get_db)):
    if not token: return RedirectResponse("/dashboard?verify=invalid", status_code=302)
    user = consume_email_verification_token(token, db)
    if user: return RedirectResponse("/dashboard?verify=ok", status_code=302)
    return RedirectResponse("/dashboard?verify=invalid", status_code=302)

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