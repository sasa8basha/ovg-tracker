"""
OVG Tracker — Session 4.0 (Advanced Detection Engine)
153 signals · Weighted scoring · 11 Kill switches · HMAC challenges
"""
import hashlib
import hmac
import ipaddress
import json
import os
import random
import re
import secrets
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String,
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
GEO_LOOKUP_TIMEOUT = float(os.getenv("OVG_GEO_TIMEOUT", "3.0"))
GEO_CACHE_TTL      = int(os.getenv("OVG_GEO_TTL", "86400"))
GEO_CACHE_MAX      = int(os.getenv("OVG_GEO_MAX", "50000"))
MAX_SITES_PER_USER = int(os.getenv("OVG_MAX_SITES", "20"))
SESSION_COOKIE     = "ovg_session"
SESSION_TTL        = 86400 * 7
CHALLENGE_TTL      = 300

THRESHOLD_VALID      = 150
THRESHOLD_SUSPICIOUS = 400
THRESHOLD_INVALID    = 800

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")
HEX_KEY_RE  = re.compile(r"^[a-f0-9]{16}$")

# =========================================================
# DB MODELS
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
    score = Column(Integer, default=0)
    verdict = Column(String, index=True)
    bot_confidence = Column(Integer, default=0)
    signal_count = Column(Integer, default=0)
    kill_triggered = Column(Boolean, default=False)
    challenge_verified = Column(Boolean, default=False)
    triggered_signals = Column(JSON, default=list)
    family_scores = Column(JSON, default=dict)
    evidence = Column(JSON, default=list)
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
        Index("ix_visits_site_verdict", "site_id", "verdict"),
        Index("ix_visits_ip_ts", "ip", "timestamp"),
    )

Base.metadata.create_all(bind=engine)

# =========================================================
# AUTH & CHALLENGE HELPERS
# =========================================================
def hash_password(p):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 120_000).hex()
    return f"{salt}${h}"

def verify_password(p, stored):
    try:
        salt, h = stored.split("$", 1)
        calc = hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 120_000).hex()
        return hmac.compare_digest(calc, h)
    except: return False

def make_token(uid):
    exp = int(time.time()) + SESSION_TTL
    payload = f"{uid}.{exp}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def verify_token(token):
    try:
        uid, exp, sig = token.rsplit(".", 2)
        payload = f"{uid}.{exp}"
        exp_sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp_sig, sig): return None
        if int(exp) < time.time(): return None
        return int(uid)
    except: return None

def make_challenge():
    ts = int(time.time())
    nonce = secrets.token_hex(8)
    payload = f"{ts}.{nonce}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}.{sig}"

def verify_challenge(challenge):
    try:
        ts_str, nonce, sig = challenge.split(".")
        ts = int(ts_str)
        if time.time() - ts > CHALLENGE_TTL: return False
        expected = hmac.new(SECRET.encode(), f"{ts_str}.{nonce}".encode(), hashlib.sha256).hexdigest()[:16]
        return hmac.compare_digest(expected, sig)
    except: return False

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def _optional_user(request, db):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        uid = verify_token(token)
        if uid:
            u = db.query(UserModel).get(uid)
            if u: return u
    key = request.query_params.get("key") or request.headers.get("x-api-key")
    if DASHBOARD_KEY and key == DASHBOARD_KEY:
        return db.query(UserModel).first()
    return None

def current_user(request, db=Depends(get_db)):
    u = _optional_user(request, db)
    if not u: raise HTTPException(401, "Unauthorized")
    return u

def bootstrap_admin():
    if not ADMIN_USER or not ADMIN_PASS: return
    db = SessionLocal()
    try:
        if db.query(UserModel).filter(UserModel.username == ADMIN_USER).first(): return
        db.add(UserModel(username=ADMIN_USER, password_hash=hash_password(ADMIN_PASS)))
        db.commit()
    finally: db.close()

bootstrap_admin()

# =========================================================
# 153 SIGNAL REGISTRY
# Format: id: (family, weight, type) type: kill|strong|medium|weak
# =========================================================
SIGNALS = {
    # BROWSER (16)
    "B01_webdriver": ("browser", 100, "kill"), "B02_chrome_missing": ("browser", 40, "strong"),
    "B03_plugins_empty": ("browser", 25, "medium"), "B04_plugins_not_array": ("browser", 30, "medium"),
    "B05_notif_incon": ("browser", 20, "medium"), "B06_perm_incon": ("browser", 25, "medium"),
    "B07_cdp_channel": ("browser", 50, "strong"), "B08_automation_ext": ("browser", 80, "strong"),
    "B09_lang_incon": ("browser", 30, "medium"), "B10_hw_weird": ("browser", 15, "weak"),
    "B11_mem_weird": ("browser", 15, "weak"), "B12_plat_vs_ua": ("browser", 40, "strong"),
    "B13_pdf_missing": ("browser", 20, "medium"), "B14_native_tamper": ("browser", 100, "kill"),
    "B15_domrect_tamper": ("browser", 40, "strong"), "B16_worker_fail": ("browser", 30, "medium"),
    # HARDWARE (12)
    "H01_canvas_empty": ("hardware", 100, "kill"), "H02_webgl_vendor_fake": ("hardware", 45, "strong"),
    "H03_webgl_virtual": ("hardware", 100, "kill"), "H04_webgpu_missing": ("hardware", 20, "weak"),
    "H05_audio_fail": ("hardware", 40, "strong"), "H06_fonts_weird": ("hardware", 40, "strong"),
    "H07_screen_weird": ("hardware", 20, "weak"), "H08_cd_weird": ("hardware", 20, "weak"),
    "H09_dpr_weird": ("hardware", 25, "weak"), "H10_tz_vs_ip": ("hardware", 60, "strong"),
    "H11_intl_tz": ("hardware", 30, "medium"), "H12_codecs_weird": ("hardware", 20, "weak"),
    # BEHAVIORAL (14)
    "BH01_mouse_linear": ("behavior", 50, "strong"), "BH02_mouse_low_entropy": ("behavior", 40, "strong"),
    "BH03_click_center": ("behavior", 30, "medium"), "BH04_click_cadence": ("behavior", 40, "strong"),
    "BH05_keystroke_const": ("behavior", 30, "medium"), "BH06_dwell_const": ("behavior", 25, "medium"),
    "BH07_scroll_regular": ("behavior", 30, "medium"), "BH08_scroll_fast": ("behavior", 20, "weak"),
    "BH09_too_fast": ("behavior", 40, "medium"), "BH10_nav_short": ("behavior", 20, "weak"),
    "BH11_touch_pressure": ("behavior", 30, "medium"), "BH12_gyro_missing": ("behavior", 25, "weak"),
    "BH13_focus_missing": ("behavior", 20, "weak"), "BH14_pause_const": ("behavior", 25, "medium"),
    # CROSS (11)
    "C01_ua_platform": ("cross", 50, "strong"), "C02_ua_fonts": ("cross", 40, "strong"),
    "C03_ua_screen": ("cross", 40, "strong"), "C04_ua_tz": ("cross", 40, "strong"),
    "C05_tz_ip": ("cross", 50, "strong"), "C06_lang_ip": ("cross", 25, "medium"),
    "C07_canvas_webgl": ("cross", 35, "medium"), "C08_webdriver_cdp": ("cross", 60, "strong"),
    "C09_plugin_proto": ("cross", 35, "medium"), "C10_ch_missing": ("cross", 40, "strong"),
    "C11_touch_weird": ("cross", 30, "medium"),
    # IDENTITY (8)
    "U01_headless_ua": ("identity", 100, "kill"), "U02_bot_keywords": ("identity", 100, "kill"),
    "U03_unrecognized_ua": ("identity", 40, "medium"), "U04_library_ua": ("identity", 100, "kill"),
    "U05_empty_ua": ("identity", 100, "kill"), "U06_malformed_ua": ("identity", 30, "medium"),
    "U07_old_os": ("identity", 30, "medium"), "U08_ua_declared": ("identity", 40, "strong"),
    # AUTOMATION (9)
    "A01_headless_sig": ("automation", 60, "strong"), "A02_webdriver_true": ("automation", 80, "strong"),
    "A03_cdp_side": ("automation", 50, "strong"), "A04_wd_signature": ("automation", 60, "strong"),
    "A05_automation_ext": ("automation", 100, "kill"), "A06_permissions_weird": ("automation", 40, "medium"),
    "A07_chrome_missing": ("automation", 30, "medium"), "A08_plugin_proto": ("automation", 25, "medium"),
    "A09_tostring_tamper": ("automation", 80, "strong"),
    # VOLUUM (23)
    "V01_fast_click": ("voluum", 60, "strong"), "V02_freq_events": ("voluum", 50, "strong"),
    "V03_freq_campaign": ("voluum", 50, "strong"), "V04_mttc": ("voluum", 60, "strong"),
    "V05_honeypot": ("voluum", 100, "kill"), "V06_bad_referrer": ("voluum", 30, "medium"),
    "V07_unrec_device": ("voluum", 25, "medium"), "V08_known_bot": ("voluum", 80, "strong"),
    "V09_google_ip": ("voluum", 40, "medium"), "V10_googlebot_switch": ("voluum", 70, "strong"),
    "V11_datacenter": ("voluum", 60, "strong"), "V12_proxy_vpn": ("voluum", 50, "strong"),
    "V13_tor": ("voluum", 80, "strong"), "V14_click_injection": ("voluum", 50, "strong"),
    "V15_click_spam": ("voluum", 40, "medium"), "V16_sub_second": ("voluum", 30, "medium"),
    "V17_ip_repeat": ("voluum", 30, "medium"), "V18_ctr_anomaly": ("voluum", 25, "weak"),
    "V19_no_mouse": ("voluum", 30, "medium"), "V20_headless_fp": ("voluum", 50, "strong"),
    "V21_ua_incon": ("voluum", 30, "medium"), "V22_interstitial_time": ("voluum", 25, "weak"),
    "V23_geo_cloak": ("voluum", 30, "medium"),
    # ADVANCED (40)
    "ADV01_accel_var": ("advanced", 20, "weak"), "ADV02_gyro_var": ("advanced", 20, "weak"),
    "ADV03_touch_fp": ("advanced", 20, "weak"), "ADV04_pressure": ("advanced", 15, "weak"),
    "ADV05_battery": ("advanced", 20, "weak"), "ADV06_conn_type": ("advanced", 15, "weak"),
    "ADV07_rtt": ("advanced", 15, "weak"), "ADV08_jarm": ("advanced", 30, "medium"),
    "ADV09_p0f": ("advanced", 30, "medium"), "ADV10_h2_settings": ("advanced", 25, "medium"),
    "ADV11_window_size": ("advanced", 15, "weak"), "ADV12_out_in_diff": ("advanced", 15, "weak"),
    "ADV13_avail_w": ("advanced", 15, "weak"), "ADV14_maxtouch": ("advanced", 25, "medium"),
    "ADV15_eff_type": ("advanced", 15, "weak"), "ADV16_conn_rtt": ("advanced", 15, "weak"),
    "ADV17_downlink": ("advanced", 15, "weak"), "ADV18_hasfocus": ("advanced", 20, "weak"),
    "ADV19_visstate": ("advanced", 20, "weak"), "ADV20_perf_precision": ("advanced", 25, "medium"),
    "ADV21_raf_timing": ("advanced", 25, "medium"), "ADV22_mutobs": ("advanced", 20, "weak"),
    "ADV23_intobs": ("advanced", 15, "weak"), "ADV24_resizeobs": ("advanced", 15, "weak"),
    "ADV25_err_stack": ("advanced", 25, "medium"), "ADV26_tostring": ("advanced", 30, "medium"),
    "ADV27_getownprop": ("advanced", 30, "medium"), "ADV28_reflect_apply": ("advanced", 25, "medium"),
    "ADV29_proxy": ("advanced", 30, "medium"), "ADV30_sym_tag": ("advanced", 25, "medium"),
    "ADV31_canvas_url": ("advanced", 40, "strong"), "ADV32_webgl_param": ("advanced", 40, "strong"),
    "ADV33_audio_osc": ("advanced", 40, "strong"), "ADV34_perm_timeout": ("advanced", 30, "medium"),
    "ADV35_notif_behavior": ("advanced", 20, "weak"), "ADV36_sendbeacon": ("advanced", 15, "weak"),
    "ADV37_fetch_keep": ("advanced", 15, "weak"), "ADV38_sab": ("advanced", 20, "weak"),
    "ADV39_wasm": ("advanced", 20, "weak"), "ADV40_intl": ("advanced", 25, "medium"),
    # MY IDEAS (10)
    "I01_honeypot_link": ("ideas", 100, "kill"), "I02_time_drift": ("ideas", 40, "strong"),
    "I03_raf_fps": ("ideas", 40, "strong"), "I04_font_metric": ("ideas", 40, "strong"),
    "I05_worker_sandbox": ("ideas", 30, "medium"), "I06_speech_voices": ("ideas", 100, "kill"),
    "I07_css_supports": ("ideas", 25, "medium"), "I08_canvas_pixels": ("ideas", 35, "medium"),
    "I09_isTrusted": ("ideas", 45, "strong"), "I10_encrypted": ("ideas", 20, "weak"),
    # IMPOSSIBLE (10)
    "X01_hmac_fail": ("impossible", 100, "kill"), "X02_audio_fft": ("impossible", 45, "strong"),
    "X03_webgl_compile": ("impossible", 50, "strong"), "X04_css_transition": ("impossible", 40, "strong"),
    "X05_mut_batch": ("impossible", 35, "medium"), "X06_mouse_velocity": ("impossible", 50, "strong"),
    "X07_font_pixel": ("impossible", 45, "strong"), "X08_idle_callback": ("impossible", 30, "medium"),
    "X09_click_kinematics": ("impossible", 30, "medium"), "X10_nav_timing": ("impossible", 25, "medium"),
}

FAMILY_LABELS = {
    "browser": {"ar": "المتصفح", "icon": "🖥️"}, "hardware": {"ar": "العتاد", "icon": "🎨"},
    "behavior": {"ar": "السلوك", "icon": "🧠"}, "cross": {"ar": "تناقضات", "icon": "⚠️"},
    "identity": {"ar": "الهوية", "icon": "👤"}, "automation": {"ar": "الأتمتة", "icon": "🤖"},
    "voluum": {"ar": "Voluum", "icon": "🛡️"}, "advanced": {"ar": "متقدم", "icon": "🔬"},
    "ideas": {"ar": "أفكار ذكية", "icon": "✨"}, "impossible": {"ar": "مستحيل", "icon": "🚀"},
}
# =========================================================
# ANALYSIS ENGINE — CHECK FUNCTIONS
# =========================================================
def _safe(v, default=None):
    try: return v if v is not None else default
    except: return default

def _check_identity(data):
    r = []
    ua = str((data.get("nav") or {}).get("ua") or "")
    ual = ua.lower()
    if not ua or ua.strip() == "": r.append(("U05_empty_ua", "empty UA"))
    if "headlesschrome" in ual: r.append(("U01_headless_ua", "HeadlessChrome in UA"))
    for kw in ["python", "curl", "wget", "requests", "node-fetch", "axios", "php/", "java/", "go-http"]:
        if kw in ual: r.append(("U02_bot_keywords", f"bot keyword: {kw}")); break
    if any(x in ual for x in ["headless", "phantomjs", "slimerjs", "selenium", "puppeteer", "playwright"]):
        r.append(("U04_library_ua", "automation lib UA"))
    if ua and not any(x in ual for x in ["mozilla", "chrome", "safari", "firefox", "edge", "opera"]):
        r.append(("U03_unrecognized_ua", "unrecognized UA format"))
    if ua and "mozilla" not in ual and len(ua) > 0: r.append(("U06_malformed_ua", "UA not starting with Mozilla"))
    if any(x in ual for x in ["windows xp", "windows 2000", "android 2.", "android 3.", "android 4."]):
        r.append(("U07_old_os", "unsupported OS version"))
    nav = data.get("nav") or {}
    if "chrome" in ual and not nav.get("hasChrome"): r.append(("U08_ua_declared", "UA says Chrome but no Chrome object"))
    return r

def _check_browser(data):
    r = []
    nav = data.get("nav") or {}
    fp = data.get("fingerprint") or {}
    ua = str(nav.get("ua") or "").lower()
    if nav.get("webdriver") is True: r.append(("B01_webdriver", "navigator.webdriver = true"))
    if "chrome" in ua and not nav.get("hasChrome"): r.append(("B02_chrome_missing", "window.chrome missing"))
    if nav.get("pluginsLen") == 0: r.append(("B03_plugins_empty", "plugins.length = 0"))
    if nav.get("pluginsLen") and nav.get("pluginsLen") > 0 and not nav.get("pluginsIsArray"):
        r.append(("B04_plugins_not_array", "plugins is not PluginArray"))
    if nav.get("hasCDP"): r.append(("B07_cdp_channel", "CDP runtime artifact"))
    if nav.get("automationExt"): r.append(("B08_automation_ext", "automation extension detected"))
    acl = nav.get("acceptLanguage") or ""
    navLangs = nav.get("languages") or []
    if acl and navLangs and navLangs[0].lower() not in acl.lower() and acl.lower() not in navLangs[0].lower():
        r.append(("B09_lang_incon", "languages vs accept-lang mismatch"))
    hw = int(_safe(fp.get("hardwareConcurrency"), 0))
    if hw > 0 and (hw == 1 or hw > 128): r.append(("B10_hw_weird", f"CPU cores = {hw}"))
    mem = int(_safe(fp.get("deviceMemory"), 0))
    if mem > 0 and (mem == 1 or mem > 128): r.append(("B11_mem_weird", f"deviceMemory = {mem}"))
    plat = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and plat and "win" not in plat:
        r.append(("B12_plat_vs_ua", f"UA={ua[:30]} platform={plat}"))
    if nav.get("pdfViewerEnabled") is False and "chrome" in ua:
        r.append(("B13_pdf_missing", "pdfViewerEnabled=false on Chrome"))
    if not fp.get("fnToStringNative"): r.append(("B14_native_tamper", "Function.prototype.toString modified"))
    if not fp.get("domRectOk"): r.append(("B15_domrect_tamper", "DOMRect prototype tampered"))
    if fp.get("workerOk") is False: r.append(("B16_worker_fail", "Worker context failed"))
    return r

def _check_hardware(data, ip_info):
    r = []
    fp = data.get("fingerprint") or {}
    canvas = str(fp.get("canvas_hash") or "")
    if not canvas or canvas in ("blocked", "") or len(canvas) < 5:
        r.append(("H01_canvas_empty", "canvas fingerprint empty/blocked"))
    webgl = fp.get("webgl") or {}
    rend = str(webgl.get("renderer") or "").lower()
    vend = str(webgl.get("vendor") or "").lower()
    if "google inc" in vend and "swiftshader" in rend: r.append(("H03_webgl_virtual", f"renderer = {rend}"))
    if any(x in rend for x in ["swiftshader", "llvmpipe", "mesa offscreen", "vmware", "virtualbox"]):
        r.append(("H03_webgl_virtual", f"virtual renderer: {rend}"))
    if not webgl.get("renderer") or webgl.get("renderer") == "blocked":
        r.append(("H02_webgl_vendor_fake", "WebGL blocked/missing"))
    if not fp.get("webgpu"): r.append(("H04_webgpu_missing", "WebGPU not supported"))
    if fp.get("audioFail") is True: r.append(("H05_audio_fail", "AudioContext failed"))
    fonts = fp.get("fonts") or []
    if isinstance(fonts, list) and len(fonts) < 3: r.append(("H06_fonts_weird", f"fonts detected: {len(fonts)}"))
    sc = data.get("screen") or {}
    w = int(_safe(sc.get("width"), 0)); h = int(_safe(sc.get("height"), 0))
    if w and h:
        if w == 0 or h == 0: r.append(("H07_screen_weird", "0x0 screen"))
        elif w > 8000 or h > 8000: r.append(("H07_screen_weird", f"huge screen {w}x{h}"))
    cd = int(_safe(sc.get("colorDepth"), 0))
    if cd and cd not in (24, 30, 32, 48): r.append(("H08_cd_weird", f"colorDepth = {cd}"))
    dpr = float(_safe(sc.get("pixelRatio"), 1))
    if dpr and (dpr < 0.5 or dpr > 5): r.append(("H09_dpr_weird", f"DPR = {dpr}"))
    return r

def _check_cross(data, ip_info):
    r = []
    nav = data.get("nav") or {}; fp = data.get("fingerprint") or {}; sc = data.get("screen") or {}
    ua = str(nav.get("ua") or "").lower()
    country = ip_info.get("country", "Unknown")
    tz = str(fp.get("timezone") or "").lower()
    if country not in ("Unknown", "Local") and tz:
        cmap = {"Egypt": ["cairo", "africa"], "US": ["america/"], "UK": ["london"], "SA": ["riyadh"], "Italy": ["rome"], "Germany": ["berlin"], "France": ["paris"], "UAE": ["dubai"], "Turkey": ["istanbul"]}
        if country in cmap and not any(t in tz for t in cmap[country]):
            r.append(("C05_tz_ip", f"IP={country} TZ={tz}")); r.append(("H10_tz_vs_ip", f"IP={country} TZ={tz}"))
    if "iphone" in ua or "ipad" in ua or ("android" in ua and "mobile" in ua):
        w = int(_safe(sc.get("width"), 0))
        if w > 1500: r.append(("C03_ua_screen", f"mobile UA + screen {w}px"))
    if "windows" in ua and "mac" in str(nav.get("platform") or "").lower(): r.append(("C01_ua_platform", "UA=Windows platform=Mac"))
    if "mac" in ua and "win" in str(nav.get("platform") or "").lower(): r.append(("C01_ua_platform", "UA=Mac platform=Win"))
    mt = int(_safe(nav.get("maxTouchPoints"), -1))
    if mt == 0 and ("iphone" in ua or "ipad" in ua): r.append(("C11_touch_weird", "iPhone UA but 0 touch points"))
    if mt > 20: r.append(("C11_touch_weird", f"maxTouchPoints = {mt}"))
    if not data.get("ch_ua"): r.append(("C10_ch_missing", "client hints (sec-ch-ua) missing"))
    if nav.get("webdriver") is False and nav.get("hasCDP"): r.append(("C08_webdriver_cdp", "webdriver=false but CDP detected"))
    return r

def _check_automation(data):
    r = []
    nav = data.get("nav") or {}
    ua = str(nav.get("ua") or "").lower()
    if nav.get("webdriver") is True: r.append(("A02_webdriver_true", "webdriver=true"))
    if "headless" in ua: r.append(("A01_headless_sig", "headless in UA"))
    if nav.get("hasCDP"): r.append(("A03_cdp_side", "CDP side effects"))
    if nav.get("wdSig"): r.append(("A04_wd_signature", "WebDriver signature"))
    if nav.get("automationExt"): r.append(("A05_automation_ext", "automation extension"))
    if not nav.get("permissionsOk"): r.append(("A06_permissions_weird", "permissions API odd"))
    if "chrome" in ua and not nav.get("hasChrome"): r.append(("A07_chrome_missing", "chrome missing"))
    if nav.get("pluginsLen") and not nav.get("pluginsIsArray"): r.append(("A08_plugin_proto", "PluginArray proto wrong"))
    if not data.get("fingerprint", {}).get("fnToStringNative"): r.append(("A09_tostring_tamper", "toString tampered"))
    return r

def _check_behavioral(data):
    r = []
    b = data.get("behavior") or {}; ev = b.get("events") or {}
    t = int(_safe(b.get("time_on_page_ms"), 0))
    if t < 1500: r.append(("BH09_too_fast", f"time_on_page = {t}ms"))
    mm = int(_safe(ev.get("mousemove"), 0))
    if mm < 3 and t > 2000: r.append(("V19_no_mouse", "no mouse movement"))
    mv = float(_safe(b.get("mouse_variance"), 0))
    if mm > 10 and mv < 1.5: r.append(("BH01_mouse_linear", f"mouse variance = {mv:.2f}"))
    if mm > 20 and float(_safe(b.get("mouse_entropy"), 0)) < 0.3: r.append(("BH02_mouse_low_entropy", "low entropy"))
    cc = int(_safe(ev.get("click"), 0))
    if cc > 3 and int(_safe(b.get("click_center_hits"), 0)) >= cc - 1: r.append(("BH03_click_center", "clicks always at center"))
    if cc >= 3 and float(_safe(b.get("click_cadence_std"), -1)) == 0: r.append(("BH04_click_cadence", "fixed click intervals"))
    if b.get("scroll_regular"): r.append(("BH07_scroll_regular", "regular scroll pattern"))
    if float(_safe(b.get("scroll_speed"), 0)) > 5000: r.append(("BH08_scroll_fast", "scroll too fast"))
    if t > 3000 and mm == 0 and int(_safe(ev.get("touchstart"), 0)) == 0: r.append(("BH13_focus_missing", "no interaction zombie"))
    if b.get("isTrusted_ratio") is not None and float(b.get("isTrusted_ratio")) < 0.5:
        r.append(("I09_isTrusted", f"isTrusted ratio = {b.get('isTrusted_ratio')}"))
    return r

def _check_voluum(data, ip_info, historical):
    r = []
    b = data.get("behavior") or {}
    t = int(_safe(b.get("time_on_page_ms"), 0))
    if 0 < t < 800: r.append(("V01_fast_click", f"left in {t}ms"))
    if b.get("honeypotClicks", 0) > 0: r.append(("V05_honeypot", "honeypot clicked"))
    if b.get("honeypot_link_clicked"): r.append(("I01_honeypot_link", "honeypot link clicked"))
    if ip_info.get("type") == "hosting": r.append(("V11_datacenter", "datacenter IP"))
    if ip_info.get("security", {}).get("vpn") is True: r.append(("V12_proxy_vpn", "VPN/Proxy IP"))
    ua = str((data.get("nav") or {}).get("ua") or "").lower()
    for bot in ["googlebot", "bingbot", "ahrefsbot", "semrushbot", "yandexbot"]:
        if bot in ua: r.append(("V08_known_bot", f"known bot UA: {bot}")); break
    if historical:
        recent = historical.get("recent_visits", 0)
        if recent > 60: r.append(("V02_freq_events", f"frequent IP: {recent} in 1min"))
        if historical.get("ip_repeat", 0) > 20: r.append(("V17_ip_repeat", f"same IP repeated: {historical['ip_repeat']}"))
    return r

def _check_advanced(data):
    r = []
    adv = data.get("advanced") or {}
    if adv.get("canvasToDataURLTampered"): r.append(("ADV31_canvas_url", "toDataURL modified"))
    if adv.get("webglGetParamTampered"): r.append(("ADV32_webgl_param", "getParameter modified"))
    if adv.get("audioOscTampered"): r.append(("ADV33_audio_osc", "audio oscillator modified"))
    if adv.get("getOwnPropTampered"): r.append(("ADV27_getownprop", "getOwnPropertyDescriptor modified"))
    if adv.get("reflectApplyTampered"): r.append(("ADV28_reflect_apply", "Reflect.apply modified"))
    if adv.get("symbolToStringTag"): r.append(("ADV30_sym_tag", "Symbol.toStringTag tampered"))
    if adv.get("proxyUsage"): r.append(("ADV29_proxy", "Proxy usage detected"))
    if adv.get("permissionsTimeout"): r.append(("ADV34_perm_timeout", "permissions.query timeout"))
    if adv.get("errorStackSuspicious"): r.append(("ADV25_err_stack", "suspicious error stack"))
    if adv.get("perfPrecision") and adv.get("perfPrecision") < 1: r.append(("ADV20_perf_precision", "reduced timer precision"))
    return r

def _check_ideas(data):
    r = []
    b = data.get("behavior") or {}; adv = data.get("advanced") or {}; fp = data.get("fingerprint") or {}
    if adv.get("timeDrift") is not None and abs(float(adv.get("timeDrift"))) > 30:
        r.append(("I02_time_drift", f"time drift = {adv['timeDrift']}s"))
    fps = float(_safe(b.get("raf_fps"), 0))
    if fps > 0 and (fps < 30 or fps > 200): r.append(("I03_raf_fps", f"FPS = {fps}"))
    if adv.get("fontMetricWeird"): r.append(("I04_font_metric", "font metrics wrong"))
    if adv.get("workerSandboxOk") is False: r.append(("I05_worker_sandbox", "worker sandbox failed"))
    voices = fp.get("speechVoices")
    if voices is not None and isinstance(voices, list) and len(voices) == 0: r.append(("I06_speech_voices", "speech voices = []"))
    if adv.get("cssSupportsWeird"): r.append(("I07_css_supports", "CSS supports mismatch"))
    if adv.get("canvasPixelWrong"): r.append(("I08_canvas_pixels", "canvas pixels mismatch"))
    return r

def _check_impossible(data):
    r = []
    adv = data.get("advanced") or {}; probes = data.get("probes") or {}; b = data.get("behavior") or {}
    if data.get("_challenge_failed"): r.append(("X01_hmac_fail", "HMAC challenge invalid/missing"))
    if probes.get("audioFFT") in (None, "blocked", 0, "0", "0.000000"): r.append(("X02_audio_fft", "audio FFT blocked/empty"))
    ct = probes.get("webglCompileTime")
    if ct is not None and ct >= 0 and ct < 2: r.append(("X03_webgl_compile", f"shader compile = {ct}ms"))
    tt = probes.get("cssTransitionTime")
    if tt is not None and tt >= 0 and (tt < 50 or tt > 400): r.append(("X04_css_transition", f"transition = {tt}ms"))
    mb = probes.get("mutationBatch")
    if mb and mb.get("callbacks", 0) > 8: r.append(("X05_mut_batch", f"mutation callbacks = {mb['callbacks']}"))
    if b.get("mouse_velocity_linear"): r.append(("X06_mouse_velocity", "linear velocity curve"))
    if adv.get("fontPixelWeird"): r.append(("X07_font_pixel", "font pixel metrics wrong"))
    ic = probes.get("idleCallbackTime")
    if ic is not None and ic >= 0 and (ic == 0 or ic > 450): r.append(("X08_idle_callback", f"idle callback = {ic}ms"))
    if b.get("click_kinematics_wrong"): r.append(("X09_click_kinematics", "bad click approach direction"))
    if probes.get("navTimingAnomaly"): r.append(("X10_nav_timing", "navigation timing anomaly"))
    return r

def analyze_visit(data, ip_info, historical=None, challenge_ok=True):
    if not challenge_ok: data["_challenge_failed"] = True
    triggered = []
    triggered.extend(_check_browser(data)); triggered.extend(_check_hardware(data, ip_info))
    triggered.extend(_check_behavioral(data)); triggered.extend(_check_cross(data, ip_info))
    triggered.extend(_check_identity(data)); triggered.extend(_check_automation(data))
    triggered.extend(_check_voluum(data, ip_info, historical)); triggered.extend(_check_advanced(data))
    triggered.extend(_check_ideas(data)); triggered.extend(_check_impossible(data))

    seen = set(); unique = []
    for sig_id, ev in triggered:
        if sig_id in seen: continue
        seen.add(sig_id); unique.append((sig_id, ev))

    score = 0; family_scores = {}; kill_triggered = False; detail = []
    for sig_id, ev in unique:
        meta = SIGNALS.get(sig_id)
        if not meta: continue
        fam, weight, typ = meta
        score += weight
        family_scores[fam] = family_scores.get(fam, 0) + weight
        if typ == "kill": kill_triggered = True
        detail.append({"id": sig_id, "family": fam, "weight": weight, "type": typ, "evidence": ev})

    if kill_triggered: verdict = "bot"
    elif score >= THRESHOLD_INVALID: verdict = "bot"
    elif score >= THRESHOLD_SUSPICIOUS: verdict = "invalid"
    elif score >= THRESHOLD_VALID: verdict = "suspicious"
    else: verdict = "valid"

    if kill_triggered or score >= THRESHOLD_INVALID: confidence = 100
    elif score >= THRESHOLD_SUSPICIOUS: confidence = 70 + int((score - THRESHOLD_SUSPICIOUS) / (THRESHOLD_INVALID - THRESHOLD_SUSPICIOUS) * 30)
    elif score >= THRESHOLD_VALID: confidence = 30 + int((score - THRESHOLD_VALID) / (THRESHOLD_SUSPICIOUS - THRESHOLD_VALID) * 40)
    else: confidence = int(score / THRESHOLD_VALID * 30) if THRESHOLD_VALID else 0

    detail.sort(key=lambda x: x["weight"], reverse=True)
    top_evidence = [f"{d['id']}: {d['evidence']}" for d in detail[:8]]

    return {
        "score": score, "verdict": verdict, "kill_triggered": kill_triggered,
        "bot_confidence": confidence, "signal_count": len(unique),
        "triggered_signals": detail, "family_scores": family_scores,
        "evidence": top_evidence, "challenge_verified": challenge_ok,
    }
# =========================================================
# UTILS
# =========================================================
class TTLCache:
    def __init__(self, maxsize=10000, ttl=3600):
        self.maxsize, self.ttl = maxsize, ttl; self._data = OrderedDict()
    def get(self, key):
        e = self._data.get(key)
        if not e: return None
        v, ts = e
        if time.time() - ts > self.ttl: del self._data[key]; return None
        self._data.move_to_end(key); return v
    def set(self, key, val):
        self._data[key] = (val, time.time()); self._data.move_to_end(key)
        while len(self._data) > self.maxsize: self._data.popitem(last=False)

class WindowRateLimiter:
    def __init__(self, max_req=120, window=60, maxsize=100000):
        self.max_req, self.window, self.maxsize = max_req, window, maxsize; self._d = OrderedDict()
    def check(self, key):
        now = time.time(); e = self._d.get(key)
        if e is None or now - e[1] > self.window: self._d[key] = (1, now); self._d.move_to_end(key)
        else: self._d[key] = (e[0] + 1, e[1]); self._d.move_to_end(key)
        while len(self._d) > self.maxsize: self._d.popitem(last=False)
        if self._d[key][0] > self.max_req: raise HTTPException(429, "Too many requests", headers={"Retry-After": str(self.window)})

ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)
signup_limiter = WindowRateLimiter(max_req=5, window=300)
login_limiter = WindowRateLimiter(max_req=15, window=300)

def _is_private_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except: return False

def get_client_ip(request):
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

def safe_origin(request):
    origin = PUBLIC_URL
    if not origin:
        try: origin = str(request.base_url).rstrip("/")
        except: origin = "https://ovg-tracker.de1.netrun.io"
    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc: origin = "https://ovg-tracker.de1.netrun.io"
    for ch in ("'", '"', "<", ">", "`", "\\", "\n", "\r", "\t"): origin = origin.replace(ch, "")
    return origin.rstrip("/")

async def get_ip_info(ip):
    if not ip or _is_private_ip(ip): return {"country": "Local", "isp": "Local ISP", "type": "residential", "asn": "N/A", "security": {}}
    cached = ip_cache.get(ip)
    if cached: return cached
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,as,proxy,hosting", timeout=GEO_LOOKUP_TIMEOUT)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    is_vpn = bool(d.get("proxy") or d.get("hosting"))
                    out = {"country": d.get("country", "Unknown"), "isp": d.get("isp", "Unknown"), "type": "hosting" if is_vpn else "residential", "asn": (d.get("as") or "Unknown").split()[0], "security": {"vpn": is_vpn}}
                    ip_cache.set(ip, out); return out
    except: pass
    return {"country": "Unknown", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}}

def parse_ua(ua):
    u = (ua or "").lower()
    device = "Mobile" if "mobi" in u else "Tablet" if ("tablet" in u or "ipad" in u) else "Desktop"
    if "windows nt" in u: os_n = "Windows"
    elif "mac os" in u or "macintosh" in u: os_n = "macOS"
    elif "android" in u: os_n = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u: os_n = "iOS"
    elif "linux" in u: os_n = "Linux"
    else: os_n = "Unknown"
    if "edg/" in u: b = "Edge"
    elif "chrome" in u and "chromium" not in u: b = "Chrome"
    elif "firefox" in u: b = "Firefox"
    elif "safari" in u and "chrome" not in u: b = "Safari"
    else: b = "Unknown"
    return os_n, device, b

def extract_zone_id(url):
    try:
        for k, v in parse_qs(urlparse(url or "").query).items():
            if k.lower() == "zoneid" and v: return v[0]
    except: pass
    return "unknown"

def new_site_key(): return secrets.token_hex(8)

# =========================================================
# TRACKER CODE TEMPLATE
# =========================================================
TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  if (window.__OVG_LOADED__) return;
  window.__OVG_LOADED__ = true;

  var SITE_KEY = '__OVG_SITE_KEY__';
  var BASE     = '__OVG_ENDPOINT__';
  var ORIGIN   = BASE.replace('/api/track','');
  var SEND_DELAY_MS = 4000;
  var sent = false;
  var startTime = Date.now();

  var mousemoves = 0, touchstarts = 0, clicks = 0, keydowns = 0;
  var mouseX = [], mouseY = [], mouseVel = [];
  var clickCoords = [], lastClick = { x:0, y:0 };
  var trustedClicks = 0, totalClicks = 0;
  var lastMouse = null;
  var lastClickTime = 0;
  var clickIntervals = [];
  var honeypotClicks = 0;
  var focusChanges = 0;
  var scrollCount = 0, lastScrollY = 0;
  var raf_fps = 0, _rafCount = 0;

  try {
    var hp = document.createElement('a');
    hp.href = '#ovg-hp';
    hp.setAttribute('data-ovg-honeypot', '1');
    hp.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:auto;';
    hp.addEventListener('click', function(e){ e.preventDefault(); honeypotClicks++; });
    document.body.appendChild(hp);
  } catch(e) {}

  document.addEventListener('mousemove', function(e){
    mousemoves++;
    var now = performance.now();
    if (lastMouse) {
      var dt = now - lastMouse.t;
      if (dt > 0) {
        var dx = e.clientX - lastMouse.x, dy = e.clientY - lastMouse.y;
        mouseVel.push(Math.sqrt(dx*dx+dy*dy)/dt);
        if (mouseVel.length > 200) mouseVel.shift();
      }
    }
    lastMouse = {x:e.clientX, y:e.clientY, t:now};
    mouseX.push(e.clientX); mouseY.push(e.clientY);
    if (mouseX.length > 200) { mouseX.shift(); mouseY.shift(); }
  }, { passive: true });

  document.addEventListener('touchstart', function(){ touchstarts++; }, { passive: true });

  document.addEventListener('click', function(e){
    totalClicks++;
    if (e.isTrusted) trustedClicks++;
    clicks++;
    var now = performance.now();
    if (lastClickTime > 0) clickIntervals.push(now - lastClickTime);
    lastClickTime = now;
    clickCoords.push([e.clientX, e.clientY]);
    if (clickCoords.length > 30) clickCoords.shift();
    lastClick = {x:e.clientX, y:e.clientY};
  }, { passive: true });

  document.addEventListener('keydown', function(){ keydowns++; }, { passive: true });
  window.addEventListener('scroll', function(){ scrollCount++; lastScrollY = window.scrollY; }, { passive: true });
  window.addEventListener('focus', function(){ focusChanges++; });
  window.addEventListener('blur', function(){ focusChanges++; });

  function variance(arr){ if(arr.length<2) return 0; var m=0,i; for(i=0;i<arr.length;i++) m+=arr[i]; m/=arr.length; var s=0; for(i=0;i<arr.length;i++){ var d=arr[i]-m; s+=d*d; } return s/arr.length; }
  function stddev(arr){ return Math.sqrt(variance(arr)); }

  function getCanvasHash() {
    try {
      var c = document.createElement('canvas'); c.width=220; c.height=40;
      var ctx = c.getContext('2d');
      if (!ctx) return 'blocked';
      ctx.textBaseline='top'; ctx.font='15px Arial';
      ctx.fillStyle='#f60'; ctx.fillRect(120,1,62,20);
      ctx.fillStyle='#069'; ctx.fillText('OVG-FP-123',2,15);
      ctx.fillStyle='rgba(102,204,0,0.7)'; ctx.fillText('OVG-FP-123',4,17);
      var data = c.toDataURL();
      var h = 5381;
      for (var i=0;i<data.length;i++) h=((h<<5)+h+data.charCodeAt(i))|0;
      return 'fp_'+Math.abs(h).toString(16);
    } catch(e){ return 'blocked'; }
  }

  function getWebGL() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { renderer: 'blocked', vendor: 'blocked', version: '' };
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      if (!ext) return { renderer: 'Unknown', vendor: 'Unknown', version: '' };
      return { renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'), vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown'), version: String(gl.getParameter(gl.VERSION) || '') };
    } catch(e){ return { renderer: 'blocked', vendor: 'blocked', version: '' }; }
  }

  function getFonts() {
    try {
      var testFonts = ['Arial','Verdana','Times New Roman','Courier New','Georgia','Comic Sans MS','Trebuchet MS','Impact','Tahoma','Lucida Console','Segoe UI','Calibri'];
      var base = ['monospace','sans-serif','serif'];
      var canvas = document.createElement('canvas'); var ctx = canvas.getContext('2d');
      if (!ctx) return [];
      var baseWidths = {};
      base.forEach(function(b){ ctx.font = '72px ' + b; baseWidths[b] = ctx.measureText('mmmmmmmmmmlli').width; });
      var found = [];
      testFonts.forEach(function(f){ var detected = base.some(function(b){ ctx.font = '72px "' + f + '", ' + b; return ctx.measureText('mmmmmmmmmmlli').width !== baseWidths[b]; }); if (detected) found.push(f); });
      return found;
    } catch(e){ return []; }
  }

  function getTimezone(){ try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch(e){ return 'Unknown'; } }

  function probeAudioFFT() {
    return new Promise(function(resolve){
      try {
        var OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OAC) return resolve('blocked');
        var ctx = new OAC(1, 44100, 44100);
        var osc = ctx.createOscillator(); var comp = ctx.createDynamicsCompressor();
        osc.type = 'triangle'; osc.frequency.value = 10000;
        osc.connect(comp); comp.connect(ctx.destination); osc.start(0);
        ctx.startRendering().then(function(buf){ var data = buf.getChannelData(0); var slice = data.slice(4000, 5000); var sum = 0; for (var i=0;i<slice.length;i++) sum += Math.abs(slice[i]); resolve(parseFloat(sum.toFixed(6))); }).catch(function(){ resolve('blocked'); });
      } catch(e){ resolve('blocked'); }
    });
  }

  function probeWebGLCompile() {
    try {
      var c = document.createElement('canvas'); var gl = c.getContext('webgl');
      if (!gl) return -1;
      var fs = 'precision highp float; uniform float t; void main(){ vec2 u=gl_FragCoord.xy/100.0; float s=sin(u.x*100.0+t)*cos(u.y*100.0+t); float n=0.0; for(int i=0;i<100;i++){n+=sin(float(i)*u.x)*cos(float(i)*u.y);} gl_FragColor=vec4(s+n*0.001,0.0,0.0,1.0); }';
      var sh = gl.createShader(gl.FRAGMENT_SHADER); gl.shaderSource(sh, fs);
      var t1 = performance.now(); gl.compileShader(sh); return Math.max(0, performance.now() - t1);
    } catch(e){ return -1; }
  }

  function probeCSSTransition() {
    return new Promise(function(resolve){
      try {
        var el = document.createElement('div');
        el.style.cssText = 'position:fixed;top:-1000px;width:10px;height:10px;background:red;transition:width 100ms linear;';
        document.body.appendChild(el);
        var start = performance.now(); var done = false;
        el.addEventListener('transitionend', function(){ if (done) return; done = true; var elapsed = performance.now() - start; el.remove(); resolve(elapsed); });
        requestAnimationFrame(function(){ el.style.width = '100px'; });
        setTimeout(function(){ if (!done){ el.remove(); resolve(-1); } }, 600);
      } catch(e){ resolve(-1); }
    });
  }

  function probeMutationBatch() {
    return new Promise(function(resolve){
      try {
        var el = document.createElement('div'); document.body.appendChild(el);
        var callbacks = 0, mutations = 0;
        var obs = new MutationObserver(function(recs){ callbacks++; mutations += recs.length; });
        obs.observe(el, { attributes: true, childList: true, characterData: true });
        for (var i=0;i<10;i++) el.setAttribute('data-x', String(i));
        setTimeout(function(){ obs.disconnect(); el.remove(); resolve({ callbacks: callbacks, mutations: mutations }); }, 100);
      } catch(e){ resolve({callbacks:-1, mutations:-1}); }
    });
  }

  function probeIdleCallback() {
    return new Promise(function(resolve){
      if (!window.requestIdleCallback) return resolve(-1);
      var start = performance.now(); var done = false;
      window.requestIdleCallback(function(){ done = true; resolve(performance.now() - start); }, { timeout: 500 });
      setTimeout(function(){ if (!done) resolve(-2); }, 600);
    });
  }

  function probeFontMetrics() {
    try { var c = document.createElement('canvas'); var ctx = c.getContext('2d'); if (!ctx) return null; ctx.font = '24px Arial'; return ctx.measureText('OVG-Test-中文').width; } catch(e){ return null; }
  }

  function probeCSSSupports() {
    try { return { has: typeof CSS !== 'undefined' && CSS.supports ? CSS.supports('selector(:has(*))') : null, container: typeof CSS !== 'undefined' && CSS.supports ? CSS.supports('container-type: inline-size') : null }; } catch(e){ return {has:null, container:null}; }
  }

  function fetchChallenge() {
    return fetch(ORIGIN + '/api/challenge', { credentials: 'omit' }).then(function(r){ return r.ok ? r.json() : null; }).then(function(d){ return d ? d.challenge : ''; }).catch(function(){ return ''; });
  }

  function getPlugins() {
    try { var p = navigator.plugins; if (!p) return []; var arr = []; for (var i=0;i<p.length;i++) arr.push(p[i].name); return arr; } catch(e){ return []; }
  }

  function buildPayload(probes, challenge) {
    var nav = navigator; var webgl = getWebGL(); var fonts = getFonts();
    var mouseEntropy = 0;
    if (mouseX.length > 2) { var xs = variance(mouseX), ys = variance(mouseY); mouseEntropy = Math.min(1, Math.log10(1 + xs + ys) / 6); }
    var clickCenters = 0;
    for (var i=0;i<clickCoords.length;i++) { var cx = clickCoords[i][0], cy = clickCoords[i][1]; if (Math.abs(cx - innerWidth/2) < 20 && Math.abs(cy - innerHeight/2) < 20) clickCenters++; }
    var cadenceStd = clickIntervals.length > 1 ? stddev(clickIntervals) : -1;
    var velVar = variance(mouseVel); var velLinear = mouseVel.length > 10 && velVar < 1;
    var clickKinWrong = false;
    if (lastMouse && clicks > 0) { var dx = lastMouse.x - lastClick.x, dy = lastMouse.y - lastClick.y; var dist = Math.sqrt(dx*dx+dy*dy); if (dist < 2 && mouseVel.length > 5) clickKinWrong = true; }
    var ch = window.chrome; var pluginsArr = getPlugins(); var pluginsIsArray = false;
    try { pluginsIsArray = navigator.plugins instanceof PluginArray; } catch(e){}
    var fnToStringNative = false;
    try { fnToStringNative = Function.prototype.toString.toString().indexOf('[native code]') !== -1; } catch(e){}
    var audioCtx = null; try { audioCtx = !!(window.AudioContext || window.webkitAudioContext); } catch(e){}

    var data = {
      challenge: challenge || '', site_key: SITE_KEY, url: location.href,
      ch_ua: (navigator.userAgentData && navigator.userAgentData.brands) ? 'yes' : '',
      nav: {
        ua: nav.userAgent, platform: nav.platform || '', webdriver: nav.webdriver === true,
        languages: nav.languages || [], language: nav.language || '', acceptLanguage: (document.documentElement.getAttribute('lang') || ''),
        hardwareConcurrency: Number(nav.hardwareConcurrency) || 0, deviceMemory: Number(nav.deviceMemory) || 0,
        maxTouchPoints: Number(nav.maxTouchPoints) || 0, pdfViewerEnabled: !!nav.pdfViewerEnabled, vendor: nav.vendor || '',
        hasChrome: !!ch, pluginsLen: pluginsArr.length, pluginsIsArray: pluginsIsArray,
        hasCDP: !!window.__webdriver_evaluate || !!window.__driver_evaluate || !!window.__fxdriver_evaluate || !!window.__selenium_unwrapped,
        automationExt: false, wdSig: !!window.domAutomation || !!window.domAutomationController,
        permissionsOk: true, notificationPermission: (typeof Notification !== 'undefined') ? Notification.permission : null
      },
      screen: {
        width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight,
        colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1,
        outerWidth: window.outerWidth, outerHeight: window.outerHeight, innerWidth: window.innerWidth, innerHeight: window.innerHeight
      },
      fingerprint: {
        timezone: getTimezone(), timezoneOffset: new Date().getTimezoneOffset(), canvas_hash: getCanvasHash(),
        hardwareConcurrency: Number(nav.hardwareConcurrency) || 0, deviceMemory: Number(nav.deviceMemory) || 0,
        webgl: webgl, webgpu: !!(navigator.gpu), fonts: fonts, fnToStringNative: fnToStringNative, domRectOk: true,
        workerOk: (function(){ try { return typeof Worker !== 'undefined'; } catch(e){ return false; } })(),
        audioFail: !audioCtx, speechVoices: (function(){ try { return (window.speechSynthesis && speechSynthesis.getVoices().length) || 0; } catch(e){ return null; } })()
      },
      behavior: {
        time_on_page_ms: Date.now() - startTime, mouse_variance: variance(mouseX) + variance(mouseY),
        mouse_entropy: mouseEntropy, mouse_velocity_linear: velLinear, click_center_hits: clickCenters,
        click_cadence_std: cadenceStd, isTrusted_ratio: totalClicks > 0 ? (trustedClicks / totalClicks) : 1,
        scroll_regular: false, scroll_speed: 0, raf_fps: raf_fps, click_kinematics_wrong: clickKinWrong,
        honeypotClicks: honeypotClicks, honeypot_link_clicked: honeypotClicks > 0,
        events: { mousemove: mousemoves, touchstart: touchstarts, click: clicks, keydown: keydowns, scroll: scrollCount, focus: focusChanges }
      },
      advanced: {
        timeDrift: 0, fontMetricWeird: false, fontPixelWeird: false, cssSupportsWeird: false, canvasPixelWrong: false,
        workerSandboxOk: true, canvasToDataURLTampered: false, webglGetParamTampered: false, audioOscTampered: false,
        getOwnPropTampered: false, reflectApplyTampered: false, symbolToStringTag: false, proxyUsage: false,
        permissionsTimeout: false, errorStackSuspicious: false, perfPrecision: (function(){ try { var t1=performance.now(), t2=performance.now(); return (t2-t1) === 0 ? 0 : 1; } catch(e){ return 1; } })()
      },
      probes: {
        audioFFT: probes.audioFFT, webglCompileTime: probes.webglCompileTime, cssTransitionTime: probes.cssTransitionTime,
        mutationBatch: probes.mutationBatch, idleCallbackTime: probes.idleCallbackTime, navTimingAnomaly: false
      },
      webrtc_ip: 'None'
    };

    if (probes.fontMetric != null) { if (probes.fontMetric < 150 || probes.fontMetric > 400) data.advanced.fontMetricWeird = true; }
    if (probes.cssSupports) { var hasChrome120 = /Chrome\/(\d+)/.test(nav.userAgent); if (hasChrome120 && probes.cssSupports.has === false) data.advanced.cssSupportsWeird = true; }
    return data;
  }

  function send() {
    if (sent) return; sent = true;
    Promise.all([probeAudioFFT(), probeWebGLCompile(), probeCSSTransition(), probeMutationBatch(), probeIdleCallback(), Promise.resolve(probeFontMetrics()), Promise.resolve(probeCSSSupports()), fetchChallenge()])
    .then(function(res){
      var probes = { audioFFT: res[0], webglCompileTime: res[1], cssTransitionTime: res[2], mutationBatch: res[3], idleCallbackTime: res[4], fontMetric: res[5], cssSupports: res[6] };
      var payload = buildPayload(probes, res[7]);
      fetch(BASE, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), keepalive: true }).catch(function(err){});
    });
  }

  setTimeout(send, SEND_DELAY_MS);
  window.addEventListener('beforeunload', function() { send(); });
})();
</script>"""
# =========================================================
# API & ROUTES
# =========================================================
app = FastAPI(title="OVG Tracker", version="4.0.0")
if ALLOWED_ORIGINS == ["*"]:
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
else:
    app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

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
    challenge: str = ""
    ch_ua: str = ""
    advanced: dict = {}
    probes: dict = {}

@app.post("/api/auth/signup")
def signup(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    signup_limiter.check(client_ip)
    username = payload.username.strip(); password = payload.password
    if not USERNAME_RE.match(username): raise HTTPException(400, "اسم المستخدم لازم 3-32 حرف")
    if len(password) < 6: raise HTTPException(400, "كلمة المرور لازم 6 حروف على الأقل")
    if db.query(UserModel).filter(UserModel.username == username).first(): raise HTTPException(400, "اسم المستخدم مستخدم بالفعل")
    u = UserModel(username=username, password_hash=hash_password(password))
    db.add(u); db.commit(); db.refresh(u)
    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/login")
def login(payload: AuthIn, request: Request, response: Response, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)
    login_limiter.check(client_ip)
    u = db.query(UserModel).filter(UserModel.username == payload.username.strip()).first()
    if not u or not verify_password(payload.password, u.password_hash): raise HTTPException(401, "بيانات الدخول غلط")
    response.set_cookie(SESSION_COOKIE, make_token(u.id), httponly=True, samesite="lax", max_age=SESSION_TTL, path="/")
    return {"ok": True, "username": u.username}

@app.post("/api/auth/logout")
def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/"); return {"ok": True}

@app.get("/api/auth/me")
def me(user: UserModel = Depends(current_user)):
    return {"id": user.id, "username": user.username}

@app.get("/api/challenge")
def get_challenge():
    return {"challenge": make_challenge()}

@app.get("/api/sites")
def list_sites(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    sites = db.query(SiteModel).filter(SiteModel.user_id == user.id).order_by(SiteModel.created_at.desc()).all()
    if not sites: return []
    ids = [s.id for s in sites]
    stats = db.query(VisitModel.site_id, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"), func.sum(case((VisitModel.verdict.in_(["invalid","bot"]), 1), else_=0)).label("invalid"), func.max(VisitModel.timestamp).label("last")).filter(VisitModel.site_id.in_(ids)).group_by(VisitModel.site_id).all()
    smap = {r.site_id: r for r in stats}
    out = []
    for s in sites:
        st = smap.get(s.id)
        out.append({"id": s.id, "name": s.name, "domain": s.domain, "site_key": s.site_key, "total": int(st.total or 0) if st else 0, "valid": int(st.valid or 0) if st else 0, "invalid": int(st.invalid or 0) if st else 0, "last_visit": st.last.isoformat() if st and st.last else None, "created_at": s.created_at.isoformat() if s.created_at else None})
    return out

@app.post("/api/sites")
def create_site(payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    count = db.query(SiteModel).filter(SiteModel.user_id == user.id).count()
    if count >= MAX_SITES_PER_USER: raise HTTPException(400, f"وصلت للحد الأقصى ({MAX_SITES_PER_USER})")
    name = payload.name.strip()
    if not name: raise HTTPException(400, "اسم الموقع مطلوب")
    site = SiteModel(user_id=user.id, name=name, domain=payload.domain.strip(), site_key=new_site_key())
    db.add(site); db.commit(); db.refresh(site)
    return {"id": site.id, "name": site.name, "domain": site.domain, "site_key": site.site_key}

@app.patch("/api/sites/{site_id}")
def update_site(site_id: int, payload: SiteIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    if payload.name.strip(): site.name = payload.name.strip()
    site.domain = payload.domain.strip()[:253]
    db.commit(); return {"ok": True}

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

@app.get("/api/sites/{site_id}/tracker-code")
def get_tracker_code(site_id: int, request: Request, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(SiteModel.id == site_id, SiteModel.user_id == user.id).first()
    if not site: raise HTTPException(404, "الموقع غير موجود")
    origin = safe_origin(request); endpoint = f"{origin}/api/track"
    code = TRACKER_CODE_TEMPLATE.replace("__OVG_SITE_KEY__", site.site_key).replace("__OVG_ENDPOINT__", endpoint)
    return Response(content=json.dumps({"code": code}), media_type="application/json", headers={"Cache-Control": "no-store"})

def _resolve_user_site(site_key: str, user: UserModel, db: Session) -> SiteModel:
    if not site_key: raise HTTPException(400, "site_key مطلوب")
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key, SiteModel.user_id == user.id).first()
    if not s: raise HTTPException(404, "الموقع غير موجود")
    return s

@app.post("/api/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request); track_limiter.check(client_ip)
    zone_id = extract_zone_id(payload.url); ua = (payload.nav or {}).get("ua") or ""
    os_name, device, browser = parse_ua(ua); ip_info = await get_ip_info(client_ip)
    site_id = None
    if payload.site_key:
        s = db.query(SiteModel).filter(SiteModel.site_key == payload.site_key).first()
        if s: site_id = s.id
    ch_ok = verify_challenge(payload.challenge) if payload.challenge else False
    try: data = payload.model_dump()
    except AttributeError: data = payload.dict()
    data["client_ip"] = client_ip

    since = datetime.utcnow() - timedelta(minutes=1)
    recent_count = db.query(func.count(VisitModel.id)).filter(VisitModel.ip == client_ip, VisitModel.timestamp >= since).scalar() or 0
    historical = {"recent_visits": recent_count, "ip_repeat": 0}

    result = analyze_visit(data, ip_info, historical=historical, challenge_ok=ch_ok)
    fp = data.get("fingerprint") or {}
    visit = VisitModel(
        site_id=site_id, ip=client_ip, user_agent=ua, zone_id=zone_id, score=result["score"], verdict=result["verdict"],
        bot_confidence=result["bot_confidence"], signal_count=result["signal_count"], kill_triggered=result["kill_triggered"],
        challenge_verified=ch_ok, triggered_signals=result["triggered_signals"], family_scores=result["family_scores"],
        evidence=result["evidence"], os=os_name, device=device, browser=browser, country=ip_info["country"], isp=ip_info["isp"],
        timezone=fp.get("timezone", "Unknown"), canvas_hash=(str(fp.get("canvas_hash", "Unknown"))[:15] + "..."),
        hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
        connection_type=ip_info["type"], asn=str(ip_info["asn"]),
        is_vpn=(ip_info["security"].get("vpn") is True or ip_info["type"] == "hosting"), webrtc_ip=payload.webrtc_ip,
    )
    try: db.add(visit); db.commit()
    except Exception: db.rollback(); raise HTTPException(500, "DB error")
    return {"status": "success"}

@app.get("/api/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)
    total = q.count(); valid = q.filter(VisitModel.verdict == "valid").count()
    invalid = q.filter(VisitModel.verdict.in_(["invalid", "bot"])).count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()
    recent = q.order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "", "zone": v.zone_id,
        "verdict": v.verdict, "country": v.country, "score": v.score, "evidence": v.evidence,
        "timezone": v.timezone, "hardware": v.hardware, "conn_type": v.connection_type, "asn": v.asn,
        "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip, "bot_confidence": v.bot_confidence,
        "kill_triggered": v.kill_triggered, "signal_count": v.signal_count,
        "triggered_signals": v.triggered_signals or [], "family_scores": v.family_scores or {}
    } for v in recent]
    return {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}

@app.get("/api/reports/zones")
def get_zone_reports(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    invalid_expr = func.sum(case((VisitModel.verdict.in_(["invalid", "bot"]), 1), else_=0))
    q = db.query(VisitModel.zone_id, func.count(VisitModel.id).label("total"), invalid_expr.label("invalid"))
    if site:
        s = _resolve_user_site(site, user, db); q = q.filter(VisitModel.site_id == s.id)
    else:
        ids = [x.id for x in db.query(SiteModel.id).filter(SiteModel.user_id == user.id).all()]
        q = q.filter(VisitModel.site_id.in_(ids)) if ids else q.filter(False)
    rows = q.group_by(VisitModel.zone_id).all(); report = []
    for z in rows:
        total, invalid = int(z.total or 0), int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = "A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F"
        report.append({"zone": z.zone_id, "total": total, "bot_rate": rate, "grade": grade})
    report.sort(key=lambda x: x["bot_rate"], reverse=True); return report

@app.post("/api/mock-data")
def generate_mock(site: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    s = _resolve_user_site(site, user, db); zones = ["10245", "88321", "55410", "99120"]
    for _ in range(50):
        v = random.choices(["valid", "invalid", "suspicious"], weights=[75, 20, 5])[0]
        sc = (random.randint(0, 30) if v == "valid" else random.randint(70, 100) if v == "invalid" else random.randint(40, 69))
        db.add(VisitModel(site_id=s.id, ip="127.0.0.1", user_agent="Mock", zone_id=random.choice(zones), score=sc, verdict=v, evidence=["Mock Data"], country="US", isp="Mock ISP", connection_type="residential"))
    db.commit(); return {"status": "ok"}

@app.get("/health")
def health(): return {"status": "ok", "version": app.version}

@app.get("/debug/site/{site_key}")
def debug_site(site_key: str, db: Session = Depends(get_db)):
    s = db.query(SiteModel).filter(SiteModel.site_key == site_key).first()
    if not s: return {"exists": False, "error": "Site key not found"}
    visits = db.query(func.count(VisitModel.id)).filter(VisitModel.site_id == s.id).scalar() or 0
    return {"exists": True, "site_name": s.name, "visits_count": visits}

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

# =========================================================
# HTML TEMPLATES
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
      <p class="text-slate-500 text-sm mt-1">نظام الحماية المتقدم V4.0</p>
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
    <p class="text-center text-xs text-slate-400 mt-8">© OVG Analytics — V4.0 (153 Signals)</p>
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
      const orig = btn.textContent; btn.textContent = 'جاري...';
      const fd = new FormData(e.target);
      const body = { username: (fd.get('username')||'').trim(), password: fd.get('password') };
      if (MODE === 'signup' && body.password !== fd.get('confirm')) {
        err.textContent = 'كلمتا المرور غير متطابقتين'; err.classList.remove('hidden');
        btn.disabled = false; btn.textContent = orig; return;
      }
      const url = MODE === 'signup' ? '/api/auth/signup' : '/api/auth/login';
      try {
        const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
        const d = await r.json().catch(()=>({}));
        if (r.ok) { location.href = '/dashboard'; return; }
        err.textContent = d.detail || 'فشل العملية'; err.classList.remove('hidden');
      } catch(e) {
        err.textContent = 'خطأ في الاتصال بالسيرفر'; err.classList.remove('hidden');
      } finally { btn.disabled = false; btn.textContent = orig; }
    });
  </script>
</body>
</html>
"""

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
    .toast{animation:slideUp .3s ease}
    @keyframes slideUp{from{transform:translate(-50%,20px);opacity:0}to{transform:translate(-50%,0);opacity:1}}
    .family-bar { height: 6px; border-radius: 3px; background: #e2e8f0; overflow: hidden; }
    .family-bar > div { height: 100%; background: linear-gradient(90deg, #6366f1, #8b5cf6); }
    .signal-chip { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700; }
    .signal-kill { background: #fecaca; color: #991b1b; }
    .signal-strong { background: #fed7aa; color: #9a3412; }
    .signal-medium { background: #fef3c7; color: #92400e; }
    .signal-weak { background: #e0e7ff; color: #3730a3; }
  </style>
</head>
<body class="min-h-screen">
<aside class="fixed right-0 top-0 h-screen w-72 bg-white border-l border-slate-200 flex flex-col z-40">
  <div class="p-6 border-b border-slate-100">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center text-white font-extrabold shadow-md shadow-indigo-500/30">O</div>
      <div><h1 class="font-extrabold text-slate-900 leading-tight">OVG Tracker</h1><p class="text-[11px] text-slate-400 font-semibold">ANALYTICS · V4.0</p></div>
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
      <button onclick="navTo('zones')" data-nav="zones" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">🎯</span> تقارير الزونات</button>
      <button onclick="navTo('tracker')" data-nav="tracker" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">🔧</span> كود التتبع</button>
      <button onclick="navTo('settings')" data-nav="settings" class="nav-btn w-full text-right px-4 py-2.5 rounded-xl text-slate-600 hover:bg-slate-50 font-semibold text-sm flex items-center gap-3"><span class="text-lg">⚙️</span> إعدادات الموقع</button>
    </div>
  </nav>
  <div class="p-3 border-t border-slate-100">
    <div class="flex items-center gap-3 p-2 mb-1">
      <div class="w-9 h-9 bg-gradient-to-br from-slate-100 to-slate-200 rounded-full flex items-center justify-center text-slate-600 font-bold">👤</div>
      <div class="min-w-0 flex-1"><p id="userName" class="font-bold text-sm text-slate-800 truncate">...</p><p class="text-[11px] text-slate-400">مسجل دخول</p></div>
    </div>
    <button onclick="doLogout()" class="w-full text-right px-3 py-2 text-sm text-rose-600 hover:bg-rose-50 rounded-lg font-semibold transition">← تسجيل الخروج</button>
  </div>
</aside>
<main class="mr-72 min-h-screen">
  <div class="p-6 md:p-8 max-w-7xl mx-auto">
    <div id="view-sites" class="view">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
        <div><h1 class="text-2xl font-extrabold text-slate-900">مواقعي</h1><p class="text-slate-500 text-sm mt-0.5">أدر كل مواقعك من مكان واحد · <span id="siteLimit">0/20</span></p></div>
        <button onclick="openSiteModal()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-xl font-bold text-sm flex items-center gap-2 shadow-lg shadow-indigo-500/30 transition self-start"><span class="text-lg leading-none">+</span> موقع جديد</button>
      </div>
      <div id="sitesGrid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5"></div>
    </div>
    <div id="view-overview" class="view hidden">
      <div class="flex items-center justify-between mb-6">
        <div><h1 class="text-2xl font-extrabold text-slate-900">نظرة عامة</h1><p id="overviewSubtitle" class="text-slate-500 text-sm mt-0.5">—</p></div>
        <button onclick="runMock()" class="text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-lg font-semibold transition">🧪 بيانات تجريبية</button>
      </div>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100"><p class="text-slate-500 text-xs font-semibold mb-1">إجمالي الزيارات</p><p id="kpi-total" class="text-3xl font-extrabold text-slate-900">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-emerald-500"><p class="text-slate-500 text-xs font-semibold mb-1">زيارات صالحة</p><p id="kpi-valid" class="text-3xl font-extrabold text-emerald-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-rose-500"><p class="text-slate-500 text-xs font-semibold mb-1">بوتات</p><p id="kpi-invalid" class="text-3xl font-extrabold text-rose-600">0</p></div>
        <div class="bg-white p-5 rounded-2xl shadow-sm border border-slate-100 border-r-4 border-r-amber-500"><p class="text-slate-500 text-xs font-semibold mb-1">مشبوهة</p><p id="kpi-suspicious" class="text-3xl font-extrabold text-amber-500">0</p></div>
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="bg-white p-6 rounded-2xl shadow-sm border border-slate-100"><h2 class="text-sm font-bold text-slate-700 mb-4">نسبة جودة الترافيك</h2><div class="h-56 flex justify-center"><canvas id="qualityChart"></canvas></div></div>
        <div class="bg-white rounded-2xl shadow-sm border border-slate-100 col-span-1 lg:col-span-2 overflow-hidden">
          <div class="p-5 border-b border-slate-100 flex justify-between items-center"><h2 class="text-sm font-bold text-slate-700">أحدث الزيارات (Live)</h2><span class="text-[10px] text-indigo-600 bg-indigo-50 px-2 py-1 rounded font-bold">يتحدث كل 15 ث</span></div>
          <div class="overflow-x-auto"><table class="w-full text-sm text-right">
            <thead class="text-[11px] text-slate-400 bg-slate-50"><tr><th class="px-2 py-3 text-center">الوقت</th><th class="px-2 py-3">الزون</th><th class="px-2 py-3 text-center">الدولة/الشبكة</th><th class="px-2 py-3 text-center">Score</th><th class="px-2 py-3 text-center">الحكم</th><th class="px-2 py-3 text-center">تفاصيل</th></tr></thead>
            <tbody id="live-table" class="divide-y divide-slate-100"></tbody>
          </table></div>
        </div>
      </div>
    </div>
    <div id="view-zones" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">تقارير الزونات</h1>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
        <table class="w-full text-sm text-right"><thead class="bg-slate-50 text-slate-400 text-[11px]"><tr><th class="px-5 py-4">Zone ID</th><th class="px-5 py-4">الزيارات</th><th class="px-5 py-4">نسبة البوتات</th><th class="px-5 py-4">التقييم</th></tr></thead><tbody id="zones-table" class="divide-y divide-slate-100"></tbody></table>
      </div>
    </div>
    <div id="view-tracker" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-2">كود التتبع</h1>
      <p class="text-slate-500 text-sm mb-6">انسخ الكود ده وحطه في موقعك (في &lt;head&gt; أو قبل &lt;/body&gt; مباشرة)</p>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 mb-5">
        <label class="text-xs font-bold text-slate-500 mb-2 block">Site Key</label>
        <div class="flex gap-2"><input id="siteKeyInput" readonly class="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 font-mono text-sm text-slate-700"><button onclick="copyText(document.getElementById('siteKeyInput').value)" class="bg-slate-800 hover:bg-slate-900 text-white px-4 rounded-xl font-semibold text-sm">نسخ</button></div>
      </div>
      <div class="bg-slate-900 rounded-2xl shadow-sm p-6">
        <div class="flex justify-between items-center mb-3"><label class="text-xs font-bold text-slate-400">الكود الكامل (جاهز للنسخ)</label><button onclick="copyText(document.getElementById('embedCode').textContent)" class="text-indigo-400 hover:text-indigo-300 text-xs font-bold">نسخ الكود</button></div>
        <pre id="embedCode" class="text-emerald-400 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto">جاري التحميل...</pre>
      </div>
    </div>
    <div id="view-settings" class="view hidden">
      <h1 class="text-2xl font-extrabold text-slate-900 mb-6">إعدادات الموقع</h1>
      <div class="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 max-w-xl mb-5">
        <h2 class="text-sm font-bold text-slate-700 mb-4">بيانات الموقع</h2>
        <div class="space-y-4">
          <div><label class="text-xs font-bold text-slate-500 mb-1.5 block">اسم الموقع</label><input id="editName" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500"></div>
          <div><label class="text-xs font-bold text-slate-500 mb-1.5 block">الدومين (اختياري)</label><input id="editDomain" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500"></div>
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
<!-- Site create modal -->
<div id="siteModal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4">
  <div class="bg-white rounded-3xl p-6 md:p-8 w-full max-w-md shadow-2xl">
    <h3 class="text-lg font-extrabold text-slate-900 mb-1">موقع جديد</h3><p class="text-slate-500 text-xs mb-5">أضف موقع وابدأ تتبع الزيارات</p>
    <form id="siteForm" class="space-y-4">
      <div><label class="text-xs font-bold text-slate-500 mb-1.5 block">اسم الموقع *</label><input id="newName" required maxlength="100" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500" placeholder="مثال: متجر الأناقة"></div>
      <div><label class="text-xs font-bold text-slate-500 mb-1.5 block">الدومين (اختياري)</label><input id="newDomain" maxlength="253" class="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-indigo-500" placeholder="shop.example.com"></div>
      <div class="flex gap-2 pt-2"><button type="button" onclick="closeSiteModal()" class="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 py-2.5 rounded-xl font-bold text-sm transition">إلغاء</button><button type="submit" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl font-bold text-sm transition">إنشاء</button></div>
    </form>
  </div>
</div>
<!-- Created modal -->
<div id="createdModal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4">
  <div class="bg-white rounded-3xl p-6 md:p-8 w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto">
    <div class="text-center mb-5">
      <div class="w-16 h-16 rounded-full bg-emerald-100 flex items-center justify-center mx-auto mb-3"><span class="text-3xl">✅</span></div>
      <h3 class="text-xl font-extrabold text-slate-900 mb-1">تم إنشاء الموقع بنجاح!</h3>
      <p class="text-slate-500 text-sm">الموقع <span id="createdSiteName" class="font-bold text-indigo-600"></span> جاهز للتتبع</p>
    </div>
    <div class="mb-4"><label class="text-xs font-bold text-slate-500 mb-1.5 block">Site Key</label><div class="flex gap-2"><input id="createdKey" readonly class="flex-1 bg-slate-50 border border-slate-200 rounded-xl px-4 py-2.5 font-mono text-xs text-slate-700"><button onclick="copyText(document.getElementById('createdKey').value)" class="bg-slate-800 hover:bg-slate-900 text-white px-3 rounded-xl font-semibold text-xs">نسخ</button></div></div>
    <div class="mb-5"><div class="flex justify-between items-center mb-2"><label class="text-xs font-bold text-slate-400">كود التتبع الكامل</label><button onclick="copyText(document.getElementById('createdCode').textContent)" class="text-indigo-600 hover:text-indigo-700 text-xs font-bold">نسخ الكود</button></div><pre id="createdCode" class="bg-slate-900 text-emerald-400 text-xs font-mono p-4 rounded-xl overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-72 overflow-y-auto">جاري التحميل...</pre></div>
    <div class="flex gap-2"><button onclick="closeCreatedModal()" class="flex-1 bg-slate-100 hover:bg-slate-200 text-slate-700 py-2.5 rounded-xl font-bold text-sm transition">+ إضافة موقع آخر</button><button onclick="goToCreatedDashboard()" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2.5 rounded-xl font-bold text-sm transition">روح للداشبورد ←</button></div>
  </div>
</div>
<!-- Details Modal -->
<div id="details-modal" class="fixed inset-0 modal-bg hidden items-center justify-center z-50 p-4">
  <div class="bg-white rounded-3xl p-6 md:p-8 w-full max-w-2xl shadow-2xl max-h-[90vh] overflow-y-auto">
    <h3 class="text-lg font-extrabold text-indigo-700 mb-4">تفاصيل التحليل المتقدم</h3>
    <div id="modal-content" class="space-y-2 text-sm text-slate-600 mb-6"></div>
    <button onclick="closeDetails()" class="w-full bg-slate-800 hover:bg-slate-900 text-white py-2.5 rounded-xl font-bold transition">إغلاق</button>
  </div>
</div>
<div id="toast" class="fixed bottom-6 left-1/2 -translate-x-1/2 hidden bg-slate-900 text-white px-6 py-3 rounded-xl font-semibold text-sm shadow-2xl z-[100] toast"></div>
<script>
const state = { user: null, sites: [], currentSite: null, view: 'sites', chart: null, visitsData: {} };
const MAX_SITES = 20;
async function init() {
  const me = await fetch('/api/auth/me').then(r => r.ok ? r.json() : null).catch(() => null);
  if (!me) { location.href = '/'; return; }
  state.user = me; document.getElementById('userName').textContent = me.username;
  await loadSites();
  const siteKey = new URL(location.href).searchParams.get('site');
  if (siteKey) { const s = state.sites.find(x => x.site_key === siteKey); if (s) { selectSite(s, false); return; } }
  navTo('sites'); if (state.sites.length === 0) setTimeout(openSiteModal, 400);
}
async function loadSites() {
  try { const r = await fetch('/api/sites'); state.sites = await r.json(); renderSites(); renderSiteMenu(); document.getElementById('siteLimit').textContent = state.sites.length + '/' + MAX_SITES; } catch (e) { toast('خطأ في تحميل المواقع'); }
}
function renderSites() {
  const grid = document.getElementById('sitesGrid');
  if (!state.sites.length) { grid.innerHTML = `<div class="col-span-full text-center py-20 bg-white rounded-3xl border-2 border-dashed border-slate-200"><div class="text-6xl mb-4">🌐</div><h3 class="font-extrabold text-slate-800 text-lg mb-2">مفيش مواقع لسه</h3><p class="text-slate-500 text-sm mb-6">أضف أول موقع ليك وابدأ تبعت الزيارات</p><button onclick="openSiteModal()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-xl font-bold text-sm shadow-lg shadow-indigo-500/30 transition">+ أضف موقعك الأول</button></div>`; return; }
  grid.innerHTML = state.sites.map(s => {
    const total = s.total || 0, valid = s.valid || 0, invalid = s.invalid || 0;
    const quality = total > 0 ? Math.round(valid / total * 100) : 0;
    const qColor = quality >= 80 ? 'text-emerald-600' : quality >= 50 ? 'text-amber-600' : 'text-rose-600';
    const last = s.last_visit ? timeAgo(new Date(s.last_visit)) : 'لا يوجد نشاط';
    return `<div class="site-card bg-white rounded-2xl p-5 border border-slate-100 cursor-pointer relative group" onclick="openSite('${s.site_key}')"><div class="flex justify-between items-start mb-4"><div class="min-w-0 flex-1"><h3 class="font-extrabold text-slate-900 text-lg truncate">${esc(s.name)}</h3><p class="text-slate-400 text-xs truncate">${esc(s.domain || 'بدون دومين')}</p></div><div class="w-11 h-11 bg-gradient-to-br from-indigo-50 to-purple-50 rounded-xl flex items-center justify-center text-xl shrink-0">🌐</div></div><div class="grid grid-cols-3 gap-1 text-center py-3 border-y border-slate-100 mb-3"><div><p class="text-[10px] text-slate-400 font-semibold">إجمالي</p><p class="text-base font-extrabold text-slate-800">${total}</p></div><div><p class="text-[10px] text-slate-400 font-semibold">صالح</p><p class="text-base font-extrabold text-emerald-600">${valid}</p></div><div><p class="text-[10px] text-slate-400 font-semibold">بوتات</p><p class="text-base font-extrabold text-rose-600">${invalid}</p></div></div><div class="flex justify-between items-center text-xs"><span class="text-slate-400">${last}</span><span class="${qColor} font-extrabold">${quality}% جودة</span></div></div>`;
  }).join('');
}
function renderSiteMenu() {
  const menu = document.getElementById('siteMenu');
  menu.innerHTML = state.sites.map(s => `<button onclick="openSite('${s.site_key}')" class="w-full text-right px-3 py-2 hover:bg-slate-50 rounded-lg text-sm ${state.currentSite?.id === s.id ? 'bg-indigo-50 text-indigo-700 font-bold' : 'text-slate-700'}">${esc(s.name)}</button>`).join('') + `<hr class="my-1"><button onclick="clearSite()" class="w-full text-right px-3 py-2 hover:bg-slate-50 rounded-lg text-sm text-slate-600">← كل المواقع</button>`;
}
function toggleSiteMenu(e) { e.stopPropagation(); document.getElementById('siteMenu').classList.toggle('hidden'); }
document.addEventListener('click', e => { const m = document.getElementById('siteMenu'); if (m && !m.classList.contains('hidden') && !e.target.closest('#siteContext')) m.classList.add('hidden'); });
function openSite(key) { const s = state.sites.find(x => x.site_key === key); if (!s) return; selectSite(s, true); }
function selectSite(site, push) { state.currentSite = site; document.getElementById('currentSiteName').textContent = site.name; document.getElementById('siteContext').classList.remove('hidden'); document.getElementById('siteNav').classList.remove('hidden'); if (push) history.pushState({}, '', '/dashboard?site=' + site.site_key); renderSiteMenu(); navTo('overview'); }
function clearSite() { state.currentSite = null; document.getElementById('siteContext').classList.add('hidden'); document.getElementById('siteNav').classList.add('hidden'); history.pushState({}, '', '/dashboard'); navTo('sites'); }
function navTo(view) {
  state.view = view; document.querySelectorAll('.view').forEach(v => v.classList.add('hidden')); document.getElementById('view-' + view).classList.remove('hidden');
  document.querySelectorAll('.nav-btn').forEach(b => { b.classList.remove('active'); if (b.dataset.nav === view) b.classList.add('active'); });
  if (view === 'sites') loadSites(); if (view === 'overview') loadOverview(); if (view === 'zones') loadZones(); if (view === 'tracker') renderTracker(); if (view === 'settings') renderSettings();
}
async function loadOverview() {
  if (!state.currentSite) return;
  document.getElementById('overviewSubtitle').textContent = state.currentSite.name + (state.currentSite.domain ? ' · ' + state.currentSite.domain : '');
  try {
    const r = await fetch('/api/stats?site=' + state.currentSite.site_key); if (!r.ok) return;
    const d = await r.json();
    document.getElementById('kpi-total').textContent = d.total; document.getElementById('kpi-valid').textContent = d.valid; document.getElementById('kpi-invalid').textContent = d.invalid; document.getElementById('kpi-suspicious').textContent = d.suspicious;
    const tb = document.getElementById('live-table'); state.visitsData = {};
    if (!d.recent.length) { tb.innerHTML = `<tr><td colspan="6" class="text-center py-10 text-slate-400 text-sm">مفيش زيارات لسه</td></tr>`; }
    else {
      tb.innerHTML = d.recent.map(v => {
        state.visitsData[v.id] = v;
        let badge = 'bg-slate-100 text-slate-700';
        if (v.verdict === 'valid') badge = 'bg-emerald-100 text-emerald-700'; else if (v.verdict === 'suspicious') badge = 'bg-amber-100 text-amber-700'; else if (v.verdict === 'invalid') badge = 'bg-orange-100 text-orange-700'; else if (v.verdict === 'bot') badge = 'bg-rose-100 text-rose-700';
        const sc = v.score > 400 ? 'text-rose-600 font-bold' : v.score > 150 ? 'text-amber-600 font-bold' : 'text-emerald-600';
        let netIcon = v.conn_type === 'hosting' ? '🚨 DC' : '🏠 Home'; if (v.is_vpn) netIcon = '🛡️ VPN';
        const netColor = v.is_vpn || v.conn_type === 'hosting' ? 'text-rose-500 font-bold' : 'text-slate-500';
        return `<tr class="hover:bg-slate-50"><td class="px-2 py-3 text-slate-500 text-xs text-center">${v.time}</td><td class="px-2 py-3 font-semibold text-xs">${esc(v.zone)}</td><td class="px-2 py-3 text-xs text-center"><div>${esc(v.country)}</div><div class="${netColor}" style="font-size:10px">${netIcon}</div></td><td class="px-2 py-3 ${sc} text-center">${v.score}</td><td class="px-2 py-3 text-center"><span class="${badge} px-2 py-1 rounded-md text-xs font-bold">${v.verdict}</span></td><td class="px-2 py-3 text-center"><button onclick="showDetails(${v.id})" class="text-indigo-600 hover:underline text-xs font-semibold">عرض</button></td></tr>`;
      }).join('');
    }
    renderChart(d);
  } catch (e) { console.error(e); }
}
function renderChart(d) {
  if (state.chart) state.chart.destroy();
  state.chart = new Chart(document.getElementById('qualityChart').getContext('2d'), { type: 'doughnut', data: { labels: ['Valid', 'Bots', 'Suspicious'], datasets: [{ data: [d.valid, d.invalid, d.suspicious], backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'], borderWidth: 0 }] }, options: { cutout: '75%', plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, font: { size: 11 } } } } } });
}
function showDetails(id) {
  const v = state.visitsData[id]; if (!v) return;
  let html = `<div class="grid grid-cols-2 gap-2 mb-4">
    <div class="bg-slate-50 p-3 rounded-xl"><p class="text-[10px] text-slate-400 font-bold">SCORE</p><p class="text-xl font-extrabold ${v.score>400?'text-rose-600':'text-slate-800'}">${v.score}</p></div>
    <div class="bg-slate-50 p-3 rounded-xl"><p class="text-[10px] text-slate-400 font-bold">CONFIDENCE</p><p class="text-xl font-extrabold ${v.bot_confidence>70?'text-rose-600':'text-emerald-600'}">${v.bot_confidence}%</p></div>
  </div>
  <div class="space-y-1 mb-4"><p class="text-xs font-bold text-slate-700">التصنيف (${v.signal_count} إشارة):</p>`;
  const fams = {'browser':'🖥️ المتصفح','hardware':'🎨 العتاد','behavior':'🧠 السلوك','cross':'⚠️ تناقضات','identity':'👤 الهوية','automation':'🤖 أتمتة','voluum':'🛡️ Voluum','advanced':'🔬 متقدم','ideas':'✨ أفكار','impossible':'🚀 مستحيل'};
  if (v.family_scores) {
    Object.keys(fams).forEach(k => { const val = v.family_scores[k] || 0; if (val > 0) { html += `<div class="flex items-center gap-2 text-xs"><span class="w-24 text-slate-500">${fams[k]}</span><div class="family-bar flex-1"><div style="width:${Math.min(100, val/10*100)}%"></div></div><span class="font-bold text-slate-700 w-8 text-left">${val}</span></div>`; } });
  }
  html += `</div>`;
  if (v.kill_triggered) html += `<div class="bg-rose-50 border border-rose-200 p-3 rounded-xl mb-4"><p class="text-xs font-bold text-rose-800">🚨 Kill Switch Triggered!</p></div>`;
  html += `<hr class="my-3"><p class="text-xs font-bold text-slate-700 mb-2">أهم الإشارات:</p><div class="space-y-1">`;
  if (v.triggered_signals && v.triggered_signals.length) {
    v.triggered_signals.slice(0, 10).forEach(s => {
      const cls = s.type === 'kill' ? 'signal-kill' : s.type === 'strong' ? 'signal-strong' : s.type === 'medium' ? 'signal-medium' : 'signal-weak';
      html += `<div class="flex items-start gap-2 text-xs mb-1"><span class="signal-chip ${cls}">${s.weight}</span><div class="flex-1"><p class="font-bold text-slate-700">${esc(s.id)}</p><p class="text-slate-500 text-[11px]">${esc(s.evidence)}</p></div></div>`;
    });
    if (v.triggered_signals.length > 10) html += `<p class="text-xs text-slate-400 italic">... و ${v.triggered_signals.length - 10} إشارة أخرى</p>`;
  } else { html += `<p class="text-emerald-600 text-xs">زيارة سليمة.</p>`; }
  html += `</div>`;
  document.getElementById('modal-content').innerHTML = html;
  document.getElementById('details-modal').classList.remove('hidden'); document.getElementById('details-modal').classList.add('flex');
}
function closeDetails() { document.getElementById('details-modal').classList.add('hidden'); document.getElementById('details-modal').classList.remove('flex'); }
async function loadZones() {
  if (!state.currentSite) return;
  const r = await fetch('/api/reports/zones?site=' + state.currentSite.site_key); if (!r.ok) return;
  const d = await r.json(); const tb = document.getElementById('zones-table');
  if (!d.length) { tb.innerHTML = `<tr><td colspan="4" class="text-center py-10 text-slate-400 text-sm">مفيش زونات لسه</td></tr>`; return; }
  tb.innerHTML = d.map(z => { const g = z.grade === 'A' ? 'bg-indigo-100 text-indigo-700' : z.grade === 'F' ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-700'; return `<tr class="hover:bg-slate-50"><td class="px-5 py-4 font-bold text-slate-700">${esc(z.zone)}</td><td class="px-5 py-4 text-slate-600">${z.total}</td><td class="px-5 py-4"><span class="${z.bot_rate > 30 ? 'text-rose-600 font-bold' : 'text-slate-600'}">${z.bot_rate}%</span></td><td class="px-5 py-4"><span class="${g} px-3 py-1 rounded-lg text-xs font-bold">${z.grade}</span></td></tr>`; }).join('');
}
async function renderTracker() {
  if (!state.currentSite) return; document.getElementById('siteKeyInput').value = state.currentSite.site_key; document.getElementById('embedCode').textContent = 'جاري التحميل...';
  try { const r = await fetch('/api/sites/' + state.currentSite.id + '/tracker-code'); const d = await r.json(); document.getElementById('embedCode').textContent = d.code || 'فشل التحميل'; } catch (e) { document.getElementById('embedCode').textContent = 'فشل تحميل الكود'; }
}
function renderSettings() { if (!state.currentSite) return; document.getElementById('editName').value = state.currentSite.name; document.getElementById('editDomain').value = state.currentSite.domain || ''; }
async function saveSiteSettings() {
  const name = document.getElementById('editName').value.trim(); const domain = document.getElementById('editDomain').value.trim(); if (!name) { toast('اسم الموقع مطلوب'); return; }
  const r = await fetch('/api/sites/' + state.currentSite.id, { method: 'PATCH', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name, domain }) });
  if (r.ok) { toast('تم الحفظ ✅'); await loadSites(); state.currentSite = state.sites.find(s => s.id === state.currentSite.id); document.getElementById('currentSiteName').textContent = state.currentSite.name; renderSettings(); } else toast('فشل الحفظ');
}
async function rotateSiteKey() {
  if (!confirm('تجديد المفتاح هيبطّل الكود القديم. متأكد؟')) return;
  const r = await fetch('/api/sites/' + state.currentSite.id + '/rotate-key', { method: 'POST' }); const d = await r.json().catch(()=>({}));
  if (r.ok) { toast('تم تجديد المفتاح'); await loadSites(); state.currentSite = state.sites.find(s => s.id === state.currentSite.id); renderTracker(); renderSettings(); } else toast(d.detail || 'فشل التجديد');
}
async function deleteCurrentSite() {
  if (!confirm('هل أنت متأكد من حذف "' + state.currentSite.name + '"؟ البيانات مش هترجع تاني.')) return;
  const r = await fetch('/api/sites/' + state.currentSite.id, { method: 'DELETE' });
  if (r.ok) { toast('تم الحذف'); clearSite(); } else toast('فشل الحذف');
}
function openSiteModal() { document.getElementById('siteModal').classList.remove('hidden'); document.getElementById('siteModal').classList.add('flex'); setTimeout(() => document.getElementById('newName').focus(), 50); }
function closeSiteModal() { document.getElementById('siteModal').classList.add('hidden'); document.getElementById('siteModal').classList.remove('flex'); document.getElementById('newName').value = ''; document.getElementById('newDomain').value = ''; }
document.getElementById('siteForm').addEventListener('submit', async (e) => {
  e.preventDefault(); const name = document.getElementById('newName').value.trim(); const domain = document.getElementById('newDomain').value.trim(); if (!name) return;
  const r = await fetch('/api/sites', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ name, domain }) }); const d = await r.json().catch(()=>({}));
  if (r.ok) { closeSiteModal(); await loadSites(); showCreatedModal(d); } else { toast(d.detail || 'فشل الإنشاء'); }
});
async function showCreatedModal(site) {
  document.getElementById('createdSiteName').textContent = site.name; document.getElementById('createdKey').value = site.site_key; document.getElementById('createdCode').textContent = 'جاري التحميل...'; document.getElementById('createdModal').classList.remove('hidden'); document.getElementById('createdModal').classList.add('flex'); window._justCreatedKey = site.site_key;
  try { const r = await fetch('/api/sites/' + site.id + '/tracker-code'); const d = await r.json(); document.getElementById('createdCode').textContent = d.code || 'فشل التحميل'; } catch (e) { document.getElementById('createdCode').textContent = 'فشل تحميل الكود'; }
}
function closeCreatedModal() { document.getElementById('createdModal').classList.add('hidden'); document.getElementById('createdModal').classList.remove('flex'); window._justCreatedKey = null; setTimeout(openSiteModal, 200); }
function goToCreatedDashboard() { document.getElementById('createdModal').classList.add('hidden'); document.getElementById('createdModal').classList.remove('flex'); const key = window._justCreatedKey; window._justCreatedKey = null; if (key) { const s = state.sites.find(x => x.site_key === key); if (s) { selectSite(s, true); return; } } navTo('sites'); }
async function runMock() { if (!state.currentSite) return; const r = await fetch('/api/mock-data?site=' + state.currentSite.site_key, { method: 'POST' }); if (r.ok) { toast('تم توليد 50 زيارة تجريبية'); loadOverview(); } else toast('فشل التوليد'); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function copyText(t) { navigator.clipboard.writeText(t).then(() => toast('تم النسخ ✅')).catch(() => toast('فشل النسخ')); }
function toast(msg) { const el = document.getElementById('toast'); el.textContent = msg; el.classList.remove('hidden'); clearTimeout(el._t); el._t = setTimeout(() => el.classList.add('hidden'), 2500); }
function timeAgo(d) { const s = Math.floor((Date.now() - d.getTime())/1000); if (s < 60) return 'قبل لحظات'; if (s < 3600) return 'قبل ' + Math.floor(s/60) + ' د'; if (s < 86400) return 'قبل ' + Math.floor(s/3600) + ' س'; return 'قبل ' + Math.floor(s/86400) + ' يوم'; }
async function doLogout() { await fetch('/api/auth/logout', { method: 'POST' }); location.href = '/'; }
setInterval(() => { if (state.view === 'overview' && state.currentSite) loadOverview(); }, 15000);
init();
</script>
</body>
</html>
"""
