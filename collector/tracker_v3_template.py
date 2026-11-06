"""
collector/tracker_v3_template.py — V3 tracker (PopAds macros capture).
"""
TRACKER_V3_JS = r"""(function () {
  'use strict';
  var CAMPAIGN_KEY  = '__OVG_CAMPAIGN_KEY__';
  var ENDPOINT      = '__OVG_ENDPOINT_BASE__';
  var HANDSHAKE_DELAY_MS    = 500;
  var HEARTBEAT_INTERVAL_MS = 10000;
  var HEARTBEAT_JITTER_MS   = 2000;
  var FINAL_TIMEOUT_MS      = 30 * 60 * 1000;

  var startTime = Date.now();
  var sessionId = null;
  var clickId = null;
  var seq = 0;
  var handshakeDone = false;
  var finalSent = false;
  var heartbeatTimer = null;
  var finalTimeoutTimer = null;
  var counters = { mousemove: 0, clicks: 0, scrolls: 0, touchstart: 0, keydown: 0, backspace: 0, wheel: 0 };

  var mousePoints = []; var mouseDirectionChanges = 0; var mousePauses = 0; var lastMouseTime = 0; var lastMouseDir = 0; var mouseTotalDistance = 0; var lastMouseX = 0, lastMouseY = 0;
  var scrollMaxDepthPct = 0; var scrollDirectionChanges = 0; var lastScrollY = 0; var lastScrollDir = 0; var scrollPauses = 0; var lastScrollTime = 0;
  var firstMoveTime = null; var firstInteractionTime = null; var firstScrollTime = null; var firstClickTime = null; var firstKeyTime = null;
  var keyIntervals = []; var lastKeyTime = 0; var typingBursts = 0;
  var idlePeriods = []; var lastActivityTime = Date.now(); var currentIdleStart = null;
  var honeypotTriggered = false;

  // 🔴 Capture PopAds macros from URL
  var trackingParams = {};
  try {
    var urlParams = new URLSearchParams(window.location.search);
    var knownMacros = ['bid','impid','websiteid','website_id','quality','country','isp','ispname','ispid','adblock','os','osname','browser','browsername','device','devicename','category','categoryid','categoryname','campaignid','campaignname','screenresolution','formfactor','formfactorname','lang','impid','impressionid','ua','useragent','ip','xforwardedfor','secchua','secchuaarch','secchuabitness','secchuamodel','secchuaplatform','secchuaplatformversion','secchuafullversion','secchuamobile','ipv6'];
    knownMacros.forEach(function(key) {
      var val = urlParams.get(key);
      if (val !== null && val !== '') trackingParams[key] = String(val).substring(0, 500);
    });
  } catch(e) {}

  function now() { return Date.now() - startTime; }
  function uuid() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID(); } catch (e) {}
    var d = Date.now().toString(16); var r = '';
    for (var i = 0; i < 24; i++) { if (i === 8 || i === 12 || i === 16 || i === 20) r += '-'; r += Math.floor(Math.random() * 16).toString(16); }
    return d.substring(0, 8) + '-' + r.substring(0, 27);
  }
  function safeSend(url, body, useBeacon) {
    var bodyStr;
    try { bodyStr = JSON.stringify(body); } catch (e) { return Promise.reject(e); }
    if (useBeacon && navigator.sendBeacon) {
      try { var blob = new Blob([bodyStr], { type: 'text/plain;charset=UTF-8' }); if (navigator.sendBeacon(url, blob)) return Promise.resolve({ ok: true }); } catch (e) {}
    }
    try {
      return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: bodyStr, keepalive: true, credentials: 'omit' }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, data: d }; }); });
    } catch (e) { return Promise.reject(e); }
  }
  function markActivity() {
    lastActivityTime = Date.now();
    if (currentIdleStart !== null) { var dur = Date.now() - currentIdleStart; if (dur >= 30000) idlePeriods.push({ dur: dur }); currentIdleStart = null; }
  }
  function checkIdle() { var gap = Date.now() - lastActivityTime; if (gap >= 30000 && currentIdleStart === null) currentIdleStart = lastActivityTime + 1000; }

  function injectHoneypots() {
    try {
      var container = document.createElement('div'); container.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0.01;';
      var a = document.createElement('a'); a.href = '#hp-' + Math.random(); a.textContent = 'info';
      a.addEventListener('click', function (e) { e.preventDefault(); honeypotTriggered = true; }); container.appendChild(a);
      var input = document.createElement('input'); input.type = 'text'; input.tabIndex = -1;
      input.addEventListener('input', function () { honeypotTriggered = true; }); container.appendChild(input);
      if (document.body) document.body.appendChild(container); else document.addEventListener('DOMContentLoaded', function () { document.body.appendChild(container); });
    } catch (e) {}
  }

  function setupListeners() {
    document.addEventListener('mousemove', function (e) {
      counters.mousemove++; if (firstMoveTime === null) firstMoveTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      markActivity();
      var t = Date.now(); var x = e.clientX, y = e.clientY;
      if (lastMouseX && lastMouseY) {
        var dx = x - lastMouseX, dy = y - lastMouseY; mouseTotalDistance += Math.sqrt(dx * dx + dy * dy);
        var dir = Math.atan2(dy, dx); if (lastMouseDir && Math.abs(dir - lastMouseDir) > 0.5) mouseDirectionChanges++; lastMouseDir = dir;
        if (lastMouseTime && (t - lastMouseTime) > 500) mousePauses++; lastMouseTime = t;
      }
      lastMouseX = x; lastMouseY = y; mousePoints.push({ x: x, y: y, t: t }); if (mousePoints.length > 200) mousePoints.shift();
    }, { passive: true });
    document.addEventListener('click', function (e) {
      counters.clicks++; if (firstClickTime === null) firstClickTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now(); markActivity();
    }, { passive: true });
    document.addEventListener('scroll', function () {
      counters.scrolls++; if (firstScrollTime === null) firstScrollTime = Date.now(); markActivity();
      var t = Date.now(); var y = window.pageYOffset || 0;
      try { var docH = Math.max(document.documentElement.scrollHeight - window.innerHeight, 1); var pct = Math.min(100, (y / docH) * 100); if (pct > scrollMaxDepthPct) scrollMaxDepthPct = Math.round(pct); } catch (e) {}
      if (lastScrollY !== null) {
        var dy = y - lastScrollY;
        if (Math.abs(dy) > 5) {
          var dir = dy > 0 ? 1 : -1; if (lastScrollDir !== 0 && dir !== lastScrollDir) scrollDirectionChanges++; lastScrollDir = dir;
          if (lastScrollTime && (t - lastScrollTime) > 500) scrollPauses++;
          lastScrollTime = t;
        }
      }
      lastScrollY = y;
    }, { passive: true });
    document.addEventListener('touchstart', function () { counters.touchstart++; if (firstInteractionTime === null) firstInteractionTime = Date.now(); markActivity(); }, { passive: true });
    document.addEventListener('keydown', function (e) {
      counters.keydown++; if (firstKeyTime === null) firstKeyTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now(); markActivity();
      if (e.key === 'Backspace') counters.backspace++;
      var t = Date.now(); if (window._ovgLastKeyTime) { var interval = t - window._ovgLastKeyTime; if (interval > 0 && interval < 5000) { keyIntervals.push(interval); if (keyIntervals.length > 100) keyIntervals.shift(); } } window._ovgLastKeyTime = t;
      if (lastKeyTime && (t - lastKeyTime) < 1000) {} else if (lastKeyTime) typingBursts++; lastKeyTime = t;
    }, { passive: true });
    window.addEventListener('blur', function () { markActivity(); });
    document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') finalize('hidden'); });
    window.addEventListener('pagehide', function () { finalize('pagehide'); });
    setInterval(checkIdle, 5000);
  }

  function buildBehavioral() {
    var totalVisible = now();
    var mouseVelocities = [];
    for (var i = 1; i < mousePoints.length; i++) {
      var dt = mousePoints[i].t - mousePoints[i-1].t;
      if (dt > 0 && dt < 1000) { var dx = mousePoints[i].x - mousePoints[i-1].x; var dy = mousePoints[i].y - mousePoints[i-1].y; mouseVelocities.push(Math.sqrt(dx * dx + dy * dy) / dt); }
    }
    var unfocusedTotal = 0;
    return {
      mouse_distance_total: Math.round(mouseTotalDistance),
      mouse_velocity_variance: mouseVelocities.length ? Math.round(mouseVelocities.reduce(function(a,b,i,arr){var m=arr.reduce(function(x,y){return x+y},0)/arr.length;return a+Math.pow(b-m,2)},0)/mouseVelocities.length * 100)/100 : 0,
      mouse_direction_changes: mouseDirectionChanges, mouse_pauses: mousePauses,
      first_move_delay_ms: firstMoveTime ? firstMoveTime - startTime : -1,
      scroll_depth_pct: scrollMaxDepthPct, scroll_direction_changes: scrollDirectionChanges, scroll_pauses: scrollPauses,
      keydown_count: counters.keydown, key_intervals: keyIntervals.slice(-20), backspace_count: counters.backspace, typing_bursts: typingBursts,
      clicks: counters.clicks, clicks_before_move: (firstClickTime && firstMoveTime && firstClickTime < firstMoveTime) ? 1 : 0,
      total_time_ms: Math.round(now()), visible_time_ms: Math.round(totalVisible), focused_time_ms: Math.round(totalVisible - unfocusedTotal),
      idle_periods_count: idlePeriods.length, longest_idle_ms: idlePeriods.length ? Math.max.apply(null, idlePeriods.map(function(p){return p.dur;})) : 0,
      events: { mousemove: counters.mousemove, touchstart: counters.touchstart, clicks: counters.clicks, scrolls: counters.scrolls, keydown: counters.keydown }
    };
  }

  function getCanvasHash() {
    try { var c = document.createElement('canvas'); c.width = 220; c.height = 40; var ctx = c.getContext('2d'); if (!ctx) return 'blocked'; ctx.textBaseline = 'top'; ctx.font = '15px Arial'; ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20); ctx.fillStyle = '#069'; ctx.fillText('OVG-v3', 2, 15); var data = c.toDataURL(); var h = 5381; for (var i = 0; i < data.length; i++) h = ((h << 5) + h + data.charCodeAt(i)) | 0; return 'fp_' + Math.abs(h).toString(16); } catch (e) { return 'blocked'; }
  }
  function getWebGL() {
    try { var c = document.createElement('canvas'); var gl = c.getContext('webgl') || c.getContext('experimental-webgl'); if (!gl) return { renderer: 'blocked', vendor: 'blocked' }; var ext = gl.getExtension('WEBGL_debug_renderer_info'); if (!ext) return { renderer: 'Unknown', vendor: 'Unknown' }; return { renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'), vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown') }; } catch (e) { return { renderer: 'blocked', vendor: 'blocked' }; }
  }
  function getAutomation() {
    var out = { puppeteer: false, playwright: false, selenium: false, nightmare: false, phantom: false, cdc: false };
    try { if (window.__puppeteer_evaluation_script__ !== undefined) out.puppeteer = true; if (window.__playwright__ !== undefined) out.playwright = true; if (window.__nightmare !== undefined) out.nightmare = true; if (window.callPhantom !== undefined) out.phantom = true; var keys = Object.keys(window); for (var i = 0; i < keys.length; i++) { var k = keys[i]; if (k.indexOf('$cdc_') === 0 || k.indexOf('cdc_') === 0) { out.cdc = true; out.selenium = true; break; } } } catch (e) {}
    return out;
  }
  function getCDP() { try { var detected = false; var err = new Error(); Object.defineProperty(err, 'stack', { get: function () { detected = true; return ''; } }); if (console.debug) console.debug(err); return detected; } catch (e) { return false; } }
  function getBraveFlag() { return new Promise(function(resolve){ try { if (navigator.brave && navigator.brave.isBrave) navigator.brave.isBrave().then(function(v){ resolve(v === true); }).catch(function(){ resolve(false); }); else resolve(false); } catch(e) { resolve(false); } }); }

  function buildNav() {
    var nav = { ua: navigator.userAgent, platform: navigator.platform || '', webdriver: navigator.webdriver === true, language: String(navigator.language || ''), maxTouchPoints: Number(navigator.maxTouchPoints) || 0, has_touch: ('ontouchstart' in window) || (Number(navigator.maxTouchPoints) > 0) };
    try { if (navigator.userAgentData) nav.ua_data = { mobile: navigator.userAgentData.mobile === true, platform: String(navigator.userAgentData.platform || '') }; } catch (e) {}
    return nav;
  }
  function buildFingerprint() {
    var pluginsCount = -1; try { pluginsCount = navigator.plugins ? navigator.plugins.length : -1; } catch (e) {}
    var langs = []; try { var l = navigator.languages; if (l) for (var i = 0; i < l.length && i < 5; i++) langs.push(String(l[i])); } catch (e) {}
    var tz = 'Unknown'; try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch (e) {}
    var chromeCheck = 'error'; try { if (typeof window.chrome === 'undefined') chromeCheck = 'no_window_chrome'; else if (typeof window.chrome.runtime === 'undefined') chromeCheck = 'window_chrome_no_runtime'; else chromeCheck = 'full'; } catch (e) {}
    return {
      timezone: tz, canvas_hash: getCanvasHash(), hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0, deviceMemory: Number(navigator.deviceMemory) || 0,
      webgl: getWebGL(), plugins: { count: pluginsCount }, languages: langs, chrome_check: chromeCheck, cdp_detected: getCDP(),
      automation: getAutomation(), mime_types_count: (navigator.mimeTypes ? navigator.mimeTypes.length : -1),
      pdf_viewer: (navigator.pdfViewerEnabled === true)
    };
  }
  function buildScreen() { return { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1, innerWidth: window.innerWidth || 0, innerHeight: window.innerHeight || 0 }; }

  function doHandshake() {
    if (handshakeDone) return; handshakeDone = true;
    getBraveFlag().then(function(isBrave) {
      var navObj = buildNav(); if (isBrave) navObj.is_brave = true;
      var body = { v: 3, session_id: sessionId, click_id: clickId, campaign_key: CAMPAIGN_KEY, url: location.href, t_ms: Math.round(now()), nav: navObj, fp: buildFingerprint(), consent_state: 'unknown', tracking_params: trackingParams };
      safeSend(ENDPOINT + '/api/collect/handshake', body, false).then(function (r) {
        if (r && r.data && r.data.hide) { document.body.innerHTML = ''; window.location.replace('/404'); return; }
        startHeartbeatTimer();
      }).catch(function () { setTimeout(function () { handshakeDone = false; doHandshake(); }, 3000); });
    });
  }
  function sendHeartbeat() { if (finalSent) return; seq++; var body = { v: 3, session_id: sessionId, seq: seq, t_ms: Math.round(now()), clicks: counters.clicks, scrolls: counters.scrolls, mousemoves: counters.mousemove, keydowns: counters.keydown, is_visible: document.visibilityState === 'visible', is_focused: document.hasFocus() }; safeSend(ENDPOINT + '/api/collect/heartbeat', body, false).catch(function () {}); }
  function startHeartbeatTimer() { if (heartbeatTimer) return; scheduleNextHeartbeat(); }
  function scheduleNextHeartbeat() { if (finalSent) return; var jitter = (Math.random() - 0.5) * 2 * HEARTBEAT_JITTER_MS; var wait = HEARTBEAT_INTERVAL_MS + jitter; heartbeatTimer = setTimeout(function () { sendHeartbeat(); scheduleNextHeartbeat(); }, wait); }

  function finalize(reason) {
    if (finalSent) return; finalSent = true;
    if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
    if (finalTimeoutTimer) { clearTimeout(finalTimeoutTimer); finalTimeoutTimer = null; }
    var behavior = buildBehavioral();
    getBraveFlag().then(function(isBrave) {
      var navObj = buildNav(); if (isBrave) navObj.is_brave = true;
      var body = {
        v: 3, session_id: sessionId, click_id: clickId, campaign_key: CAMPAIGN_KEY, seq: 999, t_ms: Math.round(now()),
        url: location.href, webrtc_ip: 'None', nav: navObj, fingerprint: buildFingerprint(), behavior: behavior, screen: buildScreen(),
        milestones: {}, first_30s: {}, ad_events: [], honeypot_triggered: honeypotTriggered, clock_drift_ms: 0, consent_state: 'unknown',
        data_quality: reason === 'timeout' ? 'partial' : 'full', tracking_params: trackingParams
      };
      var bodyStr; try { bodyStr = JSON.stringify(body); } catch (e) { bodyStr = '{}'; }
      var ok = false;
      try { ok = navigator.sendBeacon(ENDPOINT + '/api/collect/final', new Blob([bodyStr], { type: 'text/plain;charset=UTF-8' })); } catch (e) { ok = false; }
      if (!ok) {
        try { fetch(ENDPOINT + '/api/collect/final', { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: bodyStr, keepalive: true, credentials: 'omit' }).catch(function () {}); } catch (e) {}
      }
    });
  }

  function boot() {
    try {
      sessionId = uuid(); clickId = uuid();
      setupListeners();
      if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', function () { injectHoneypots(); }); }
      else { injectHoneypots(); }
      finalTimeoutTimer = setTimeout(function () { finalize('timeout'); }, FINAL_TIMEOUT_MS);
      var delay = function () { setTimeout(doHandshake, HANDSHAKE_DELAY_MS); };
      if ('requestIdleCallback' in window) requestIdleCallback(delay, { timeout: 2000 }); else delay();
    } catch (e) {}
  }
  boot();
})();
"""
