"""
collector/tracker_v3_template.py — V3 tracker (fixed data flow + full macros)
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
  var serverTimeAtBoot = null;
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

  var first30s = { start_ms: 0, clicks_30s: 0, scrolls_30s: 0, mousemoves_30s: 0, keys_30s: 0, has_interaction_30s: false };
  var first30sTimer = null;

  var adEvents = [];
  var adObserver = null;
  var adSeenLoaded = false;

  var milestones = {};

  // =========================================================
  // 🔴 PopAds Macros — capture EVERY URL param
  // =========================================================
  // PopAds replaces [MACRO] tags with real values before redirect,
  // so they arrive as normal query params. We take everything to be safe.
  var trackingParams = {};
  try {
    var urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach(function (value, key) {
      if (value !== null && value !== '') {
        trackingParams[key] = String(value).substring(0, 500);
      }
    });
    // Aliases: بعض الـ campaign URL بيستخدم impid بدل impressionid
    if (!trackingParams.impressionid && trackingParams.impid) {
      trackingParams.impressionid = trackingParams.impid;
    }
    if (!trackingParams.website_id && trackingParams.websiteid) {
      trackingParams.website_id = trackingParams.websiteid;
    }
  } catch (e) {}

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

  // ============ AD EVENT TRACKING ============
  var AD_DOMAINS = ['adsterra', 'highperformanceformat', 'profitableratecpm', 'adsterratools', 'sunmaxim', 'monetag', 'adcash', 'popads'];

  function isAdElement(el) {
    try {
      if (!el) return false;
      var src = (el.src || '') + ' ' + (el.href || '') + ' ' + (el.data || '');
      var cls = (el.className && typeof el.className === 'string') ? el.className : '';
      var id = el.id || '';
      var combined = (src + ' ' + cls + ' ' + id).toLowerCase();
      for (var i = 0; i < AD_DOMAINS.length; i++) {
        if (combined.indexOf(AD_DOMAINS[i]) !== -1) return true;
      }
      if (el.tagName === 'IFRAME' && (el.width >= 300 || el.style.width)) return true;
      if (el.tagName === 'INS' && el.getAttribute('data-ad-client')) return true;
      return false;
    } catch (e) { return false; }
  }

  function setupAdObserver() {
    if (!window.MutationObserver) return;
    try {
      adObserver = new MutationObserver(function (mutations) {
        if (now() > 60000) { adObserver.disconnect(); return; }
        mutations.forEach(function (m) {
          if (m.type === 'childList') {
            m.addedNodes.forEach(function (n) {
              if (n.nodeType === 1 && isAdElement(n)) {
                if (!adSeenLoaded) {
                  adSeenLoaded = true;
                  adEvents.push({ event: 'loaded', t: now() });
                }
              }
            });
            m.removedNodes.forEach(function (n) {
              if (n.nodeType === 1 && isAdElement(n)) {
                adEvents.push({ event: 'removed', t: now() });
              }
            });
          } else if (m.type === 'attributes') {
            if (isAdElement(m.target)) {
              var vis = window.getComputedStyle(m.target).display;
              var opac = window.getComputedStyle(m.target).opacity;
              if ((vis === 'none' || opac === '0' || opac === '0.0') && adSeenLoaded) {
                var last = adEvents[adEvents.length - 1];
                if (!last || last.event !== 'hidden') {
                  adEvents.push({ event: 'hidden', t: now() });
                }
              }
            }
          }
        });
      });
      adObserver.observe(document.documentElement || document.body, {
        childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class']
      });
      setTimeout(function () {
        try {
          var ads = document.querySelectorAll('iframe, ins, [id*="ad"], [class*="ad"]');
          for (var i = 0; i < ads.length; i++) {
            if (isAdElement(ads[i])) {
              adEvents.push({ event: 'loaded', t: now() });
              adSeenLoaded = true;
              break;
            }
          }
        } catch (e) {}
      }, 2000);
    } catch (e) {}
  }

  function collectMilestones() {
    try {
      var t = performance.timing || {};
      var navStart = t.navigationStart || 0;
      if (navStart > 0) {
        if (t.responseStart > 0) milestones.t_response_start = t.responseStart - navStart;
        if (t.domContentLoadedEventEnd > 0) milestones.t_dom_content_loaded = t.domContentLoadedEventEnd - navStart;
        if (t.loadEventEnd > 0) milestones.t_load_event = t.loadEventEnd - navStart;
      }
      try {
        var paints = performance.getEntriesByType('paint');
        for (var i = 0; i < paints.length; i++) {
          if (paints[i].name === 'first-paint') {
            milestones.t_first_paint = Math.round(paints[i].startTime);
          }
        }
      } catch (e) {}
      if (firstInteractionTime) milestones.t_first_interaction = firstInteractionTime - startTime;
      if (firstMoveTime) milestones.t_first_move = firstMoveTime - startTime;
      if (firstClickTime) milestones.t_first_click = firstClickTime - startTime;
      if (firstScrollTime) milestones.t_first_scroll = firstScrollTime - startTime;
    } catch (e) {}
    return milestones;
  }

  function setupListeners() {
    document.addEventListener('mousemove', function (e) {
      counters.mousemove++; if (firstMoveTime === null) firstMoveTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      if (first30s.start_ms === 0) first30s.start_ms = now();
      if (now() <= 30000) { first30s.mousemoves_30s++; if (counters.mousemove > 5) first30s.has_interaction_30s = true; }
      markActivity();
      var t = Date.now(); var x = e.clientX, y = e.clientY;
      if (lastMouseX && lastMouseY) {
        var dx = x - lastMouseX, dy = y - lastMouseY; mouseTotalDistance += Math.sqrt(dx * dx + dy * dy);
        var dir = Math.atan2(dy, dx); if (lastMouseDir && Math.abs(dir - lastMouseDir) > 0.5) mouseDirectionChanges++; lastMouseDir = dir;
        if (lastMouseTime && (t - lastMouseTime) > 500) mousePauses++; lastMouseTime = t;
      }
      lastMouseX = x; lastMouseY = y;
      mousePoints.push({ x: Math.round(x), y: Math.round(y), t: t - startTime });
      if (mousePoints.length > 100) mousePoints.shift();
    }, { passive: true });

    document.addEventListener('click', function (e) {
      counters.clicks++; if (firstClickTime === null) firstClickTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      if (now() <= 30000) { first30s.clicks_30s++; first30s.has_interaction_30s = true; }
      markActivity();
    }, { passive: true });

    document.addEventListener('scroll', function () {
      counters.scrolls++; if (firstScrollTime === null) firstScrollTime = Date.now(); markActivity();
      if (now() <= 30000) { first30s.scrolls_30s++; first30s.has_interaction_30s = true; }
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

    document.addEventListener('touchstart', function () {
      counters.touchstart++; if (firstInteractionTime === null) firstInteractionTime = Date.now(); markActivity();
      if (now() <= 30000) { first30s.has_interaction_30s = true; }
    }, { passive: true });

    document.addEventListener('keydown', function (e) {
      counters.keydown++; if (firstKeyTime === null) firstKeyTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now(); markActivity();
      if (now() <= 30000) { first30s.keys_30s++; first30s.has_interaction_30s = true; }
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
      if (dt > 0 && dt < 1000) {
        var dx = mousePoints[i].x - mousePoints[i-1].x;
        var dy = mousePoints[i].y - mousePoints[i-1].y;
        mouseVelocities.push(Math.sqrt(dx * dx + dy * dy) / dt);
      }
    }
    var meanVel = 0, variance = 0;
    if (mouseVelocities.length > 1) {
      var sum = 0; for (var j = 0; j < mouseVelocities.length; j++) sum += mouseVelocities[j];
      meanVel = sum / mouseVelocities.length;
      var sqSum = 0; for (var k = 0; k < mouseVelocities.length; k++) sqSum += Math.pow(mouseVelocities[k] - meanVel, 2);
      variance = sqSum / mouseVelocities.length;
    }
    var unfocusedTotal = 0;
    return {
      mouse_distance_total: Math.round(mouseTotalDistance),
      mouse_velocity_variance: Math.round(variance * 100) / 100,
      mouse_velocity_median: Math.round(meanVel),
      mouse_direction_changes: mouseDirectionChanges,
      mouse_pauses: mousePauses,
      first_move_delay_ms: firstMoveTime ? firstMoveTime - startTime : -1,
      scroll_depth_pct: scrollMaxDepthPct,
      scroll_direction_changes: scrollDirectionChanges,
      scroll_pauses: scrollPauses,
      keydown_count: counters.keydown,
      key_intervals: keyIntervals.slice(-20),
      backspace_count: counters.backspace,
      typing_bursts: typingBursts,
      clicks: counters.clicks,
      clicks_before_move: (firstClickTime && firstMoveTime && firstClickTime < firstMoveTime) ? 1 : 0,
      total_time_ms: Math.round(now()),
      visible_time_ms: Math.round(totalVisible),
      focused_time_ms: Math.round(totalVisible - unfocusedTotal),
      idle_periods_count: idlePeriods.length,
      longest_idle_ms: idlePeriods.length ? Math.max.apply(null, idlePeriods.map(function(p){return p.dur;})) : 0,
      events: { mousemove: counters.mousemove, touchstart: counters.touchstart, clicks: counters.clicks, scrolls: counters.scrolls, keydown: counters.keydown },
      mouse_points: mousePoints.slice(-100)
    };
  }

  function getCanvasHash() {
    try { var c = document.createElement('canvas'); c.width = 220; c.height = 40; var ctx = c.getContext('2d'); if (!ctx) return 'blocked'; ctx.textBaseline = 'top'; ctx.font = '15px Arial'; ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20); ctx.fillStyle = '#069'; ctx.fillText('OVG-v3', 2, 15); var data = c.toDataURL(); var h = 5381; for (var i = 0; i < data.length; i++) h = ((h << 5) + h + data.charCodeAt(i)) | 0; return 'fp_' + Math.abs(h).toString(16); } catch (e) { return 'blocked'; }
  }
  function getWebGL() {
    try { var c = document.createElement('canvas'); var gl = c.getContext('webgl') || c.getContext('experimental-webgl'); if (!gl) return { renderer: 'blocked', vendor: 'blocked' }; var ext = gl.getExtension('WEBGL_debug_renderer_info'); if (!ext) return { renderer: 'Unknown', vendor: 'Unknown' }; return { renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'), vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown') }; } catch (e) { return { renderer: 'blocked', vendor: 'blocked' }; }
  }
  function getWebGLPrecision() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { high_float: -1, medium_float: -1 };
      var hf = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
      var mf = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT);
      return {
        high_float: hf ? hf.precision : -1,
        medium_float: mf ? mf.precision : -1,
        range_min: hf ? hf.rangeMin : 0,
        range_max: hf ? hf.rangeMax : 0
      };
    } catch (e) { return { high_float: -1, medium_float: -1 }; }
  }
  function getAutomation() {
    var out = { puppeteer: false, playwright: false, selenium: false, nightmare: false, phantom: false, cdc: false };
    try { if (window.__puppeteer_evaluation_script__ !== undefined) out.puppeteer = true; if (window.__playwright__ !== undefined) out.playwright = true; if (window.__nightmare !== undefined) out.nightmare = true; if (window.callPhantom !== undefined) out.phantom = true; var keys = Object.keys(window); for (var i = 0; i < keys.length; i++) { var k = keys[i]; if (k.indexOf('$cdc_') === 0 || k.indexOf('cdc_') === 0) { out.cdc = true; out.selenium = true; break; } } } catch (e) {}
    return out;
  }
  function getCDP() { try { var detected = false; var err = new Error(); Object.defineProperty(err, 'stack', { get: function () { detected = true; return ''; } }); if (console.debug) console.debug(err); return detected; } catch (e) { return false; } }
  function getBraveFlag() { return new Promise(function(resolve){ try { if (navigator.brave && navigator.brave.isBrave) navigator.brave.isBrave().then(function(v){ resolve(v === true); }).catch(function(){ resolve(false); }); else resolve(false); } catch(e) { resolve(false); } }); }

  var _speechVoices = null;
  function initSpeechVoices() {
    try {
      if (!window.speechSynthesis) { _speechVoices = -1; return; }
      var v = window.speechSynthesis.getVoices();
      if (v && v.length > 0) { _speechVoices = v.length; return; }
      window.speechSynthesis.onvoiceschanged = function () {
        var v2 = window.speechSynthesis.getVoices();
        _speechVoices = v2 ? v2.length : 0;
      };
      _speechVoices = v ? v.length : 0;
    } catch (e) { _speechVoices = -1; }
  }

  function getUABrands() {
    try {
      if (navigator.userAgentData && navigator.userAgentData.brands) {
        return navigator.userAgentData.brands.map(function (b) {
          return { brand: String(b.brand || ''), version: String(b.version || '') };
        });
      }
    } catch (e) {}
    return [];
  }

  function getIntlLocale() {
    try { return Intl.DateTimeFormat().resolvedOptions().locale || 'Unknown'; } catch (e) { return 'Unknown'; }
  }

  function getConnection() {
    try {
      var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (!c) return { rtt: -1, downlink: -1, effective_type: 'Unknown' };
      return {
        rtt: typeof c.rtt === 'number' ? c.rtt : -1,
        downlink: typeof c.downlink === 'number' ? c.downlink : -1,
        effective_type: String(c.effectiveType || 'Unknown'),
        save_data: c.saveData === true
      };
    } catch (e) { return { rtt: -1, downlink: -1, effective_type: 'Unknown' }; }
  }

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
      timezone: tz,
      canvas_hash: getCanvasHash(),
      hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
      deviceMemory: Number(navigator.deviceMemory) || 0,
      webgl: getWebGL(),
      webgl_precision: getWebGLPrecision(),
      plugins: { count: pluginsCount },
      languages: langs,
      chrome_check: chromeCheck,
      cdp_detected: getCDP(),
      automation: getAutomation(),
      mime_types_count: (navigator.mimeTypes ? navigator.mimeTypes.length : -1),
      pdf_viewer: (navigator.pdfViewerEnabled === true),
      speech_voices: _speechVoices,
      ua_brands: getUABrands(),
      intl_locale: getIntlLocale(),
      connection: getConnection()
    };
  }

  function buildScreen() { return { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1, innerWidth: window.innerWidth || 0, innerHeight: window.innerHeight || 0 }; }

  function doHandshake() {
    if (handshakeDone) return; handshakeDone = true;
    getBraveFlag().then(function(isBrave) {
      var navObj = buildNav(); if (isBrave) navObj.is_brave = true;
      var body = {
        v: 3,
        session_id: sessionId,
        click_id: clickId,
        campaign_key: CAMPAIGN_KEY,
        url: location.href,
        t_ms: Math.round(now()),
        nav: navObj,
        fp: buildFingerprint(),
        consent_state: 'unknown',
        tracking_params: trackingParams  // 🔴 كل الماكروز
      };
      safeSend(ENDPOINT + '/api/collect/handshake', body, false).then(function (r) {
        if (r && r.data && r.data.hide) { document.body.innerHTML = ''; window.location.replace('/404'); return; }
        if (r && r.data && typeof r.data.server_time === 'number') {
          serverTimeAtBoot = r.data.server_time;
        }
        startHeartbeatTimer();
      }).catch(function () { setTimeout(function () { handshakeDone = false; doHandshake(); }, 3000); });
    });
  }

  function sendHeartbeat() {
    if (finalSent) return; seq++;
    var body = { v: 3, session_id: sessionId, seq: seq, t_ms: Math.round(now()), clicks: counters.clicks, scrolls: counters.scrolls, mousemoves: counters.mousemove, keydowns: counters.keydown, is_visible: document.visibilityState === 'visible', is_focused: document.hasFocus() };
    safeSend(ENDPOINT + '/api/collect/heartbeat', body, false).catch(function () {});
  }
  function startHeartbeatTimer() { if (heartbeatTimer) return; scheduleNextHeartbeat(); }
  function scheduleNextHeartbeat() { if (finalSent) return; var jitter = (Math.random() - 0.5) * 2 * HEARTBEAT_JITTER_MS; var wait = HEARTBEAT_INTERVAL_MS + jitter; heartbeatTimer = setTimeout(function () { sendHeartbeat(); scheduleNextHeartbeat(); }, wait); }

  function finalize(reason) {
    if (finalSent) return; finalSent = true;
    if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
    if (finalTimeoutTimer) { clearTimeout(finalTimeoutTimer); finalTimeoutTimer = null; }
    if (adObserver) { try { adObserver.disconnect(); } catch (e) {} }
    if (first30sTimer) { clearTimeout(first30sTimer); first30sTimer = null; }

    var behavior = buildBehavioral();
    var milestonesData = collectMilestones();

    getBraveFlag().then(function(isBrave) {
      var navObj = buildNav(); if (isBrave) navObj.is_brave = true;
      var body = {
        v: 3,
        session_id: sessionId,
        click_id: clickId,
        campaign_key: CAMPAIGN_KEY,
        seq: 999,
        t_ms: Math.round(now()),
        url: location.href,
        webrtc_ip: 'None',
        nav: navObj,
        fingerprint: buildFingerprint(),
        behavior: behavior,
        screen: buildScreen(),
        milestones: milestonesData,
        first_30s: first30s,
        ad_events: adEvents,
        honeypot_triggered: honeypotTriggered,
        clock_drift_ms: 0,
        consent_state: 'unknown',
        data_quality: reason === 'timeout' ? 'partial' : 'full',
        tracking_params: trackingParams  // 🔴 كل الماكروز (تأكيد أخير)
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
      sessionId = uuid();
      clickId = uuid();
      initSpeechVoices();
      setupListeners();
      setupAdObserver();
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { injectHoneypots(); });
      } else {
        injectHoneypots();
      }
      first30sTimer = setTimeout(function () {}, 30000);
      finalTimeoutTimer = setTimeout(function () { finalize('timeout'); }, FINAL_TIMEOUT_MS);
      var delay = function () { setTimeout(doHandshake, HANDSHAKE_DELAY_MS); };
      if ('requestIdleCallback' in window) requestIdleCallback(delay, { timeout: 2000 }); else delay();
    } catch (e) {}
  }
  boot();
})();
"""
