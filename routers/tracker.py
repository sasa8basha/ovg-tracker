"""
routers/tracker.py — Tracking routes + tracker JS template.
"""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from config import HEX_KEY_RE
from database import get_db
from models import UserModel, SiteModel, VisitModel
from schemas import TrackPayload
from auth import current_user
from analysis import (
    get_ip_info, parse_ua, extract_zone_id, new_site_key, analyze_visit,
)
from helpers import _resolve_user_site
from utils import (
    get_client_ip, safe_origin, track_limiter, stats_cache,
)

router = APIRouter()


TRACKER_CODE_TEMPLATE = r"""<script>
(function () {
  "use strict";
  var SITE_KEY = '__OVG_SITE_KEY__';
  var ENDPOINT = '__OVG_ENDPOINT__';
  var SEND_DELAY_MS = 2000;
  var WEBRTC_TIMEOUT = 1500;
  var startTime = Date.now();
  var mousemoves = 0, touchstarts = 0, clicks = 0, scrolls = 0;
  var mouseX = [], mouseY = [], mousePoints = [], sent = false;

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
  function getPluginsInfo() { try { var p = navigator.plugins; return { count: p ? p.length : 0 }; } catch (e) { return { count: -1 }; } }
  function getLanguages() {
    try { var langs = navigator.languages; if (!langs || !langs.length) return []; var arr = [];
      for (var i = 0; i < langs.length && i < 5; i++) arr.push(String(langs[i])); return arr;
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
      var dx = points[i].x - points[i - 1].x, dy = points[i].y - points[i - 1].y;
      var dt = points[i].t - points[i - 1].t;
      if (dt > 0 && dt < 1000) velocities.push(Math.sqrt(dx * dx + dy * dy) / dt);
    }
    if (velocities.length < 5) return { too_few: true };
    var sv = 0; for (var i = 0; i < velocities.length; i++) sv += velocities[i];
    var mv = sv / velocities.length;
    var vv = 0; for (var i = 0; i < velocities.length; i++) { var d = velocities[i] - mv; vv += d * d; }
    vv = vv / velocities.length;
    var dc = 0, ls = 0;
    for (var i = 2; i < points.length; i++) {
      var d1x = points[i-1].x - points[i-2].x, d1y = points[i-1].y - points[i-2].y;
      var d2x = points[i].x - points[i-1].x, d2y = points[i].y - points[i-1].y;
      var cr = d1x*d2y - d1y*d2x;
      if (Math.abs(cr) > 2) { var s = Math.sign(cr); if (ls !== 0 && s !== ls) dc++; ls = s; }
    }
    var cv = [];
    for (var i = 2; i < points.length; i++) {
      var a1 = Math.atan2(points[i-1].y - points[i-2].y, points[i-1].x - points[i-2].x);
      var a2 = Math.atan2(points[i].y - points[i-1].y, points[i].x - points[i-1].x);
      var ang = a2 - a1;
      while (ang > Math.PI) ang -= 2 * Math.PI;
      while (ang < -Math.PI) ang += 2 * Math.PI;
      cv.push(Math.abs(ang));
    }
    var mc = 0; if (cv.length) { var sc = 0; for (var i = 0; i < cv.length; i++) sc += cv[i]; mc = sc / cv.length; }
    return { too_few: false, velocity_variance: vv, direction_changes: dc, mean_curvature: mc, total_points: points.length };
  }
  function getCanvasHash() {
    try {
      var c = document.createElement('canvas'); c.width = 220; c.height = 40;
      var ctx = c.getContext('2d'); if (!ctx) return 'blocked';
      ctx.textBaseline = 'top'; ctx.font = '15px Arial';
      ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
      ctx.fillStyle = '#069'; ctx.fillText('OVG-FP-123', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('OVG-FP-123', 4, 17);
      var data = c.toDataURL(); var h = 5381;
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
  function getTimezone() { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch (e) { return 'Unknown'; } }
  function buildPayload(webrtc, isBrave) {
    return {
      url: location.href, site_key: SITE_KEY,
      nav: { ua: navigator.userAgent, platform: navigator.platform || '', webdriver: navigator.webdriver === true, is_brave: isBrave === true },
      fingerprint: {
        timezone: getTimezone(), canvas_hash: getCanvasHash(),
        hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
        deviceMemory: Number(navigator.deviceMemory) || 0,
        webgl: getWebGL(), plugins: getPluginsInfo(), languages: getLanguages(),
        chrome_check: getChromeCheck(), cdp_detected: getCDPDetected()
      },
      behavior: {
        time_on_page_ms: Date.now() - startTime,
        mouse_variance: variance(mouseX) + variance(mouseY),
        mouse_analysis: analyzeMouseTrajectory(mousePoints),
        events: { mousemove: mousemoves, touchstart: touchstarts, clicks: clicks, scrolls: scrolls }
      },
      screen: { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1 },
      webrtc_ip: webrtc || 'None'
    };
  }
  function send() {
    if (sent) return; sent = true;
    Promise.all([getWebRTCIP(), getBraveFlag()]).then(function (results) {
      var body = JSON.stringify(buildPayload(results[0], results[1]));
      fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body, keepalive: true }).catch(function (err) { console.error('[OVG] Send failed:', err); });
    });
  }
  setTimeout(send, SEND_DELAY_MS);
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') send(); });
  window.addEventListener('pagehide', function () { send(); });
  window.addEventListener('beforeunload', function () { send(); });
})();
</script>"""


@router.get("/sites/{site_id}/tracker-code")
def get_tracker_code(site_id: int, request: Request,
                     user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    site = db.query(SiteModel).filter(
        SiteModel.id == site_id, SiteModel.user_id == user.id
    ).first()
    if not site:
        raise HTTPException(404, "الموقع مش موجود")
    if not HEX_KEY_RE.match(site.site_key or ""):
        site.site_key = new_site_key()
        db.commit()
    origin = safe_origin(request)
    endpoint = f"{origin}/api/track"
    code = TRACKER_CODE_TEMPLATE.replace("__OVG_SITE_KEY__", site.site_key).replace("__OVG_ENDPOINT__", endpoint)
    return Response(
        content='{"code":' + json.dumps(code) + '}',
        media_type="application/json",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


@router.post("/track")
async def track_visit(payload: TrackPayload, request: Request,
                      db: Session = Depends(get_db)):
    try:
        client_ip = get_client_ip(request)
        print(f"[TRACK] incoming from {client_ip} site_key={(payload.site_key or '')[:12]}")

        try:
            track_limiter.check(client_ip)
        except Exception as e:
            print(f"[TRACK] rate-limit hit: {client_ip} - {e}")
            raise

        try:
            zone_id = extract_zone_id(payload.url)
        except Exception as e:
            print(f"[TRACK] extract_zone_id failed: {e} url={payload.url!r}")
            zone_id = None

        ua = (payload.nav or {}).get("ua") or ""
        try:
            os_name, device, browser = parse_ua(ua)
        except Exception as e:
            print(f"[TRACK] parse_ua failed: {e}")
            os_name, device, browser = "Unknown", "Unknown", "Unknown"

        try:
            ip_info = await get_ip_info(client_ip)
            if not isinstance(ip_info, dict):
                raise ValueError(f"ip_info not dict: {type(ip_info)}")
        except Exception as e:
            print(f"[TRACK] get_ip_info failed: {e} — using fallback")
            ip_info = {
                "country": "Unknown", "country_code": None, "isp": "Unknown",
                "asn": "", "type": "unknown", "security": {}, "lat": 0.0, "lon": 0.0,
            }

        site_id = None
        site_owner_id = None
        if payload.site_key:
            s = db.query(SiteModel).filter(SiteModel.site_key == payload.site_key).first()
            if s:
                site_id = s.id
                site_owner_id = s.user_id
            else:
                print(f"[TRACK] site_key NOT matched in DB: {(payload.site_key or '')[:12]}")

        try:
            data = payload.model_dump()
        except AttributeError:
            data = payload.dict()
        data["client_ip"] = client_ip

        canvas_raw = str((data.get("fingerprint") or {}).get("canvas_hash") or "")
        recent_fp_count = 0
        if len(canvas_raw) >= 15 and canvas_raw not in ("blocked", "Unknown"):
            try:
                cutoff = datetime.utcnow() - timedelta(minutes=1)
                recent_fp_count = db.query(VisitModel).filter(
                    VisitModel.canvas_hash == (canvas_raw[:15] + "..."),
                    VisitModel.timestamp > cutoff,
                ).count()
            except Exception as e:
                print(f"[TRACK] recent_fp_count query failed: {e}")
                recent_fp_count = 0
        data["_recent_fp_count"] = recent_fp_count

        try:
            result = analyze_visit(data, ip_info)
        except Exception as e:
            print(f"[TRACK] analyze_visit failed: {e}")
            import traceback as _tb
            _tb.print_exc()
            result = {
                "score": 50,
                "verdict": "suspicious",
                "evidence": [{"signal": "analysis_error", "score": 0, "detail": str(e)[:200]}],
            }

        fp = data.get("fingerprint") or {}
        behavior = data.get("behavior") or {}
        events = behavior.get("events") or {}

        cc = str(ip_info.get("country_code") or "").upper().strip()
        cc_stored = None if cc in ("LO", "XX", "") else cc[:2]

        visit = VisitModel(
            site_id=site_id, ip=client_ip, user_agent=ua, zone_id=zone_id,
            score=result.get("score", 0),
            verdict=result.get("verdict", "suspicious"),
            evidence=result.get("evidence", []),
            os=os_name, device=device, browser=browser,
            country=ip_info.get("country", "Unknown"),
            country_code=cc_stored,
            isp=ip_info.get("isp", "Unknown"),
            timezone=fp.get("timezone", "Unknown"),
            canvas_hash=(str(fp.get("canvas_hash", "Unknown"))[:15] + "..."),
            hardware=f"{fp.get('hardwareConcurrency', 0)} cores / {fp.get('deviceMemory', 0)} GB",
            connection_type=ip_info.get("type", "unknown"),
            asn=str(ip_info.get("asn", "")),
            is_vpn=(ip_info.get("security", {}).get("vpn") is True or ip_info.get("type") == "hosting"),
            webrtc_ip=payload.webrtc_ip,
            time_on_page=behavior.get("time_on_page_ms", 0),
            clicks=events.get("clicks", 0), scrolls=events.get("scrolls", 0),
            latitude=ip_info.get("lat", 0.0), longitude=ip_info.get("lon", 0.0),
        )

        try:
            db.add(visit); db.commit()
            print(f"[TRACK] saved visit id={visit.id} site_id={site_id} verdict={visit.verdict} score={visit.score}")
        except Exception as e:
            db.rollback()
            print(f"[TRACK] DB write failed: {e}")
            raise HTTPException(500, "DB write failed")

        if site_id:
            stats_cache.invalidate(f"stats:site:{site_id}")
        if site_owner_id:
            stats_cache.invalidate(f"stats:user:{site_owner_id}:all")

        return {"status": "success"}

    except HTTPException:
        raise
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        print(f"[TRACK] unhandled error: {e}")
        raise HTTPException(500, "track failed")
