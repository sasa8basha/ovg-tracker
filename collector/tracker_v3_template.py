"""
collector/tracker_v3_template.py — V3 tracker (v8.1 — Beacon fix)

Integrated:
    - BotD (18 detectors from FingerprintJS)
    - vi-bot (28 detectors + Stack Traps + Honeypots)
    - Flagon (rage clicks, intervals, mutations, detailed events)
    - rebrowser-bot-detector (22 modern tests — catches Patchright/Puppeteer/Playwright)
    - BehaviorTracker (mouse/keys/scroll/touch/interaction)

FIX v8.1:
    - sendBeacon now uses text/plain (simple content type → no preflight).
      Previously used application/json which triggered CORS preflight
      (OPTIONS succeeded but POST never fired).
"""
TRACKER_V3_JS = r"""(function () {
  'use strict';

  var CAMPAIGN_KEY  = '__OVG_CAMPAIGN_KEY__';
  var ENDPOINT      = '__OVG_ENDPOINT_BASE__';
  var HANDSHAKE_DELAY_MS    = 500;
  var HEARTBEAT_INTERVAL_MS = 10000;
  var HEARTBEAT_JITTER_MS   = 2000;
  var FINAL_TIMEOUT_MS      = 90 * 1000;
  var RESOLUTION_MS         = 500;

  var startTime = Date.now();
  var sessionId = null;
  var clickId = null;
  var seq = 0;
  var handshakeDone = false;
  var finalSent = false;
  var heartbeatTimer = null;
  var finalTimeoutTimer = null;

  var counters = { mousemove: 0, clicks: 0, scrolls: 0, touchstart: 0, keydown: 0, backspace: 0, wheel: 0 };

  var mousePoints = [];
  var mouseDirectionChanges = 0;
  var mousePauses = 0;
  var lastMouseTime = 0;
  var lastMouseDir = 0;
  var mouseTotalDistance = 0;
  var lastMouseX = 0, lastMouseY = 0;

  var scrollMaxDepthPct = 0;
  var scrollDirectionChanges = 0;
  var lastScrollY = 0;
  var lastScrollDir = 0;
  var scrollPauses = 0;
  var lastScrollTime = 0;
  var scrollVelocities = [];

  var firstMoveTime = null;
  var firstInteractionTime = null;
  var firstScrollTime = null;
  var firstClickTime = null;
  var firstKeyTime = null;

  var keyIntervals = [];
  var lastKeyTime = 0;
  var typingBursts = 0;
  var clicksPoints = [];

  var idlePeriods = [];
  var lastActivityTime = Date.now();
  var currentIdleStart = null;

  var honeypotTriggered = false;

  var first30s = { start_ms: 0, clicks_30s: 0, scrolls_30s: 0, mousemoves_30s: 0, keys_30s: 0, has_interaction_30s: false };

  var adEvents = [];
  var adObserver = null;
  var adSeenLoaded = false;

  var milestones = {};
  var trapTriggers = {};

  // Flagon: Rage Click state
  var rageClickBuffer = [];
  var rageClickEvents = [];

  // Flagon: Interval Log state
  var intervalLogState = {
    id: null, type: null, path: null,
    startTimer: null, counter: 0, intervalLogs: []
  };

  // Flagon: Mutation Observer state
  var domMutationObserver = null;
  var mutationSummary = {
    added: 0, removed: 0, attributes: 0,
    targets: [], totalEvents: 0
  };

  // Flagon: Detailed Events
  var detailedEvents = [];

  var trackingParams = {};
  try {
    var urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach(function (value, key) {
      if (value !== null && value !== '') {
        trackingParams[key] = String(value).substring(0, 500);
      }
    });
    if (!trackingParams.impressionid && trackingParams.impid) trackingParams.impressionid = trackingParams.impid;
    if (!trackingParams.website_id && trackingParams.websiteid) trackingParams.website_id = trackingParams.websiteid;
  } catch (e) {}

  // =========================================================
  // HELPERS
  // =========================================================
  function now() { return Date.now() - startTime; }

  function uuid() {
    try { if (window.crypto && crypto.randomUUID) return crypto.randomUUID(); } catch (e) {}
    var d = Date.now().toString(16); var r = '';
    for (var i = 0; i < 24; i++) {
      if (i === 8 || i === 12 || i === 16 || i === 20) r += '-';
      r += Math.floor(Math.random() * 16).toString(16);
    }
    return d.substring(0, 8) + '-' + r.substring(0, 27);
  }

  // ===================== IMPORTANT FIX =====================
  // sendBeacon with 'application/json' Blob triggers a CORS preflight
  // (OPTIONS fires, but the actual POST never fires because sendBeacon
  //  doesn't follow the preflight flow). Using 'text/plain' makes the
  // request "simple" — no preflight — and the server parses JSON anyway.
  // =========================================================
  function safeSend(url, body, useBeacon) {
    var bodyStr;
    try { bodyStr = JSON.stringify(body); } catch (e) { return Promise.reject(e); }

    if (useBeacon && navigator.sendBeacon) {
      try {
        var blob = new Blob([bodyStr], { type: 'text/plain;charset=UTF-8' });
        if (navigator.sendBeacon(url, blob)) return Promise.resolve({ ok: true });
      } catch (e) {}
    }

    try {
      return fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: bodyStr,
        keepalive: true,
        credentials: 'omit'
      }).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (d) {
          return { ok: r.ok, data: d };
        });
      });
    } catch (e) { return Promise.reject(e); }
  }

  function markActivity() {
    lastActivityTime = Date.now();
    if (currentIdleStart !== null) {
      var dur = Date.now() - currentIdleStart;
      if (dur >= 30000) idlePeriods.push({ dur: dur });
      currentIdleStart = null;
    }
  }

  function checkIdle() {
    var gap = Date.now() - lastActivityTime;
    if (gap >= 30000 && currentIdleStart === null) currentIdleStart = lastActivityTime + 1000;
  }

  function safeStr(v) { try { return String(v); } catch (e) { return ''; } }

  function isNativeFn(fnStr) {
    try { return /\(\)\s*{\s+\[native code\]\s+}\s*$/.test(String(fnStr)); }
    catch (e) { return false; }
  }

  // =========================================================
  // FLAGON: SELECTOR / PATH / RECT
  // =========================================================
  function getSelector(ele) {
    try {
      if (ele instanceof HTMLElement || ele instanceof Element) {
        var rawClass = typeof ele.className === 'string' ? ele.className : (ele.getAttribute ? ele.getAttribute('class') : '');
        var tag = ele.localName || ele.nodeName;
        if (tag) return tag + (ele.id ? '#' + ele.id : '') + (rawClass ? '.' + rawClass : '');
      } else if (ele instanceof Document) return '#document';
      else if (ele === globalThis) return 'Window';
    } catch (e) {}
    return 'Unknown';
  }

  function buildPath(e) {
    try {
      var path = [];
      var composed = (typeof e.composedPath === 'function') ? e.composedPath() : [];
      for (var i = 0; i < composed.length && i < 10; i++) path.push(getSelector(composed[i]));
      return path;
    } catch (err) { return []; }
  }

  function getTargetRect(target) {
    try {
      if (target && typeof target.getBoundingClientRect === 'function') {
        var r = target.getBoundingClientRect();
        if (r && isFinite(r.x) && isFinite(r.y) && isFinite(r.width) && isFinite(r.height)) {
          return { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) };
        }
      }
    } catch (e) {}
    return null;
  }

  // =========================================================
  // FLAGON: RAGE CLICK DETECTOR
  // =========================================================
  function recordRageClick(target, x, y) {
    try {
      var nowTs = Date.now();
      var targetSel = getSelector(target);
      rageClickBuffer.push({ target: targetSel, timestamp: nowTs, x: x, y: y });
      var cutoff = nowTs - 1000;
      rageClickBuffer = rageClickBuffer.filter(function (c) { return c.timestamp >= cutoff; });
      var matching = rageClickBuffer.filter(function (c) {
        if (c.target !== targetSel) return false;
        var dx = c.x - x, dy = c.y - y;
        return Math.sqrt(dx*dx + dy*dy) <= 30;
      });
      if (matching.length >= 3) {
        rageClickEvents.push({ target: targetSel, count: matching.length, t: now(), x: x, y: y });
        if (rageClickEvents.length > 20) rageClickEvents.shift();
        rageClickBuffer = rageClickBuffer.filter(function (c) { return c.target !== targetSel; });
      }
    } catch (e) {}
  }

  // =========================================================
  // FLAGON: INTERVAL LOG
  // =========================================================
  function packageIntervalEvent(e) {
    try {
      var targetSel = e.target ? getSelector(e.target) : null;
      var path = buildPath(e);
      var type = e.type;
      var ts = Date.now();

      if (intervalLogState.id === null) {
        intervalLogState.id = targetSel;
        intervalLogState.type = type;
        intervalLogState.path = path;
        intervalLogState.startTimer = ts;
        intervalLogState.counter = 0;
      }

      if (intervalLogState.id !== targetSel || intervalLogState.type !== type) {
        if (intervalLogState.counter > 1 && intervalLogState.startTimer) {
          intervalLogState.intervalLogs.push({
            target: intervalLogState.id,
            path: intervalLogState.path,
            type: intervalLogState.type,
            count: intervalLogState.counter,
            duration: ts - intervalLogState.startTimer,
            t: now()
          });
          if (intervalLogState.intervalLogs.length > 30) intervalLogState.intervalLogs.shift();
        }
        intervalLogState.id = targetSel;
        intervalLogState.type = type;
        intervalLogState.path = path;
        intervalLogState.startTimer = ts;
        intervalLogState.counter = 0;
      }

      if (intervalLogState.id === targetSel && intervalLogState.type === type) {
        intervalLogState.counter += 1;
      }
    } catch (err) {}
  }

  // =========================================================
  // FLAGON: MUTATION OBSERVER
  // =========================================================
  function setupMutationObserver() {
    if (!window.MutationObserver) return;
    try {
      domMutationObserver = new MutationObserver(function (records) {
        for (var i = 0; i < records.length; i++) {
          var rec = records[i];
          if (rec.type === 'childList') {
            mutationSummary.added += rec.addedNodes ? rec.addedNodes.length : 0;
            mutationSummary.removed += rec.removedNodes ? rec.removedNodes.length : 0;
          } else if (rec.type === 'attributes') {
            mutationSummary.attributes += 1;
          }
          mutationSummary.totalEvents += 1;
          if (rec.target && mutationSummary.targets.length < 15) {
            var sel = getSelector(rec.target);
            if (sel && sel !== 'Unknown') mutationSummary.targets.push(sel);
          }
        }
      });
      if (document.documentElement) {
        domMutationObserver.observe(document.documentElement, {
          childList: true, subtree: true, attributes: true,
          attributeFilter: ['class', 'id', 'hidden', 'disabled', 'style', 'aria-expanded']
        });
      }
    } catch (e) {}
  }

  // =========================================================
  // AD OBSERVER
  // =========================================================
  var AD_DOMAINS = ['adsterra', 'highperformanceformat', 'profitableratecpm', 'adsterratools', 'sunmaxim', 'monetag', 'adcash', 'popads'];

  function isAdElement(el) {
    try {
      if (!el) return false;
      var combined = ((el.src || '') + ' ' + (el.href || '') + ' ' + ((typeof el.className === 'string') ? el.className : '') + ' ' + (el.id || '')).toLowerCase();
      for (var i = 0; i < AD_DOMAINS.length; i++) if (combined.indexOf(AD_DOMAINS[i]) !== -1) return true;
      if (el.tagName === 'IFRAME' && (el.width >= 300 || el.style.width)) return true;
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
              if (n.nodeType === 1 && isAdElement(n) && !adSeenLoaded) {
                adSeenLoaded = true;
                adEvents.push({ event: 'loaded', t: now() });
              }
            });
          }
        });
      });
      adObserver.observe(document.documentElement || document.body, { childList: true, subtree: true });
    } catch (e) {}
  }

  // =========================================================
  // MILESTONES
  // =========================================================
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
        for (var i = 0; i < paints.length; i++) if (paints[i].name === 'first-paint') milestones.t_first_paint = Math.round(paints[i].startTime);
      } catch (e) {}
      if (firstInteractionTime) milestones.t_first_interaction = firstInteractionTime - startTime;
      if (firstMoveTime) milestones.t_first_move = firstMoveTime - startTime;
      if (firstClickTime) milestones.t_first_click = firstClickTime - startTime;
      if (firstScrollTime) milestones.t_first_scroll = firstScrollTime - startTime;
    } catch (e) {}
    return milestones;
  }

  // =========================================================
  // STACK TRACE TRAPS
  // =========================================================
  function installTrap(obj, method) {
    try {
      var original = obj[method];
      if (typeof original !== 'function') return;
      var disabled = false;
      obj[method] = function () {
        if (disabled) return original.apply(this, arguments);
        try {
          disabled = true;
          null[0]();
        } catch (e) {
          disabled = false;
          var stackStr = (e && e.stack) ? String(e.stack).toLowerCase() : '';
          if (stackStr) {
            var sigs = {
              errorTrapPhantomJS: ['phantomjs'],
              errorTrapPuppeteer: ['puppeteer', '__puppeteer'],
              errorTrapPlaywrightChrome: ['playwright', '__playwright'],
              errorTrapPlaywrightFirefox: ['juggler', 'playwright'],
              errorTrapSeleniumChrome: ['selenium', 'webdriver'],
              errorTrapNightmare: ['nightmare', '__nightmare'],
              errorTrapCypress: ['cypress', '__cypress'],
              errorTrapPatchright: ['patchright'],
              errorTrapPptrUrl: ['pptr:'],
              errorTrapUtilityScript: ['utilityscript']
            };
            for (var key in sigs) {
              var sigList = sigs[key];
              var allMatched = true;
              for (var i = 0; i < sigList.length; i++) {
                if (stackStr.indexOf(sigList[i]) === -1) { allMatched = false; break; }
              }
              if (allMatched) trapTriggers[key] = true;
            }
          }
        }
        return original.apply(this, arguments);
      };
    } catch (e) {}
  }

  function setupTraps() {
    try {
      installTrap(Document.prototype, 'querySelector');
      installTrap(Document.prototype, 'querySelectorAll');
      installTrap(Document.prototype, 'getElementById');
      installTrap(window, 'eval');
    } catch (e) {}
  }

  // =========================================================
  // HONEYPOTS
  // =========================================================
  function randomFieldName() {
    var prefixes = ['email', 'username', 'name', 'phone', 'address', 'zip', 'city', 'website', 'company', 'comment'];
    return prefixes[Math.floor(Math.random() * prefixes.length)] + '_' + Math.random().toString(36).slice(2, 6);
  }

  function injectHoneypots() {
    try {
      var container = document.createElement('div');
      container.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0.01;';

      var field = document.createElement('input');
      field.type = 'text';
      field.name = randomFieldName();
      field.tabIndex = -1;
      field.autocomplete = 'off';
      field.style.cssText = 'position:fixed;top:-5000px;left:-5000px;width:1px;height:1px;';
      field.setAttribute('aria-hidden', 'true');
      field.addEventListener('input', function () { if (field.value.length > 0) honeypotTriggered = true; });
      field.addEventListener('change', function () { if (field.value.length > 0) honeypotTriggered = true; });
      container.appendChild(field);

      var link = document.createElement('a');
      link.href = '#hp-' + Math.random();
      link.textContent = 'info';
      link.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;';
      link.setAttribute('aria-hidden', 'true');
      link.addEventListener('click', function (e) { e.preventDefault(); honeypotTriggered = true; });
      container.appendChild(link);

      if (document.body) document.body.appendChild(container);
      else document.addEventListener('DOMContentLoaded', function () { document.body.appendChild(container); });
    } catch (e) {}
  }

  // =========================================================
  // BEHAVIOR ANALYSIS
  // =========================================================
  function analyzeMouseBehavior() {
    if (mousePoints.length < 5) return 0;
    var angleChanges = 0, straightSegments = 0, pauses = 0, speedJitter = 0;
    for (var i = 1; i < mousePoints.length; i++) {
      var dx = mousePoints[i].x - mousePoints[i-1].x;
      var dy = mousePoints[i].y - mousePoints[i-1].y;
      var dt = mousePoints[i].t - mousePoints[i-1].t;
      var dist = Math.sqrt(dx*dx + dy*dy);
      if (dt > 0) {
        var speed = dist / dt;
        if (i > 1) {
          var prevDx = mousePoints[i-1].x - mousePoints[i-2].x;
          var prevDy = mousePoints[i-1].y - mousePoints[i-2].y;
          var prevDist = Math.sqrt(prevDx*prevDx + prevDy*prevDy);
          var prevDt = mousePoints[i-1].t - mousePoints[i-2].t;
          var prevSpeed = prevDt > 0 ? prevDist / prevDt : 0;
          speedJitter += Math.abs(speed - prevSpeed);
          if (dx !== 0 || dy !== 0) {
            var angle = Math.atan2(dy, dx);
            var prevAngle = Math.atan2(prevDy, prevDx);
            if (Math.abs(angle - prevAngle) > 0.05) angleChanges++;
          }
          if (dist > 5 && prevDist > 5) {
            var dot = prevDx*dx + prevDy*dy;
            var mag = prevDist * dist;
            if (mag > 0 && (dot / mag) > 0.99) straightSegments++;
          }
        }
        if (speed < 0.01 && dt > 100) pauses++;
      }
    }
    var avgJitter = speedJitter / Math.max(1, mousePoints.length - 2);
    var pauseRatio = pauses / Math.max(1, mousePoints.length);
    var angleRatio = angleChanges / Math.max(1, mousePoints.length);
    var straightRatio = straightSegments / Math.max(1, mousePoints.length - 2);
    var humanSignals = 0;
    if (avgJitter > 0.001) humanSignals++;
    if (pauseRatio > 0.01) humanSignals++;
    if (angleRatio > 0.1) humanSignals++;
    if (straightRatio < 0.3) humanSignals++;
    if (mousePoints.length < 10) return 0.3;
    return 1 - (humanSignals / 4);
  }

  function analyzeKeyBehavior() {
    if (keyIntervals.length < 3) return 0;
    var mean = 0;
    for (var i = 0; i < keyIntervals.length; i++) mean += keyIntervals[i];
    mean = mean / keyIntervals.length;
    var variance = 0;
    for (var j = 0; j < keyIntervals.length; j++) variance += Math.pow(keyIntervals[j] - mean, 2);
    variance = variance / keyIntervals.length;
    var cv = Math.sqrt(variance) / Math.max(mean, 0.001);
    if (keyIntervals.length < 10) return 0;
    var identicalCount = 0;
    for (var k = 0; k < keyIntervals.length - 1; k++) {
      if (Math.abs(keyIntervals[k] - keyIntervals[k+1]) < 0.5) identicalCount++;
    }
    var burstPattern = identicalCount > keyIntervals.length * 0.3;
    var isHuman = cv > 0.15 && mean > 30 && mean < 500 && !burstPattern;
    if (isHuman) return 0;
    var score = 0;
    if (cv <= 0.15) score += 0.4;
    if (mean < 20) score += 0.3;
    if (mean > 500) score += 0.1;
    if (burstPattern) score += 0.3;
    return Math.min(1, score);
  }

  function analyzeScrollBehavior() {
    if (scrollVelocities.length < 2) return 0;
    var speedChanges = 0;
    for (var i = 1; i < scrollVelocities.length; i++) {
      if (Math.abs(scrollVelocities[i] - scrollVelocities[i-1]) > 0.01) speedChanges++;
    }
    var changeRatio = speedChanges / (scrollVelocities.length - 1);
    if (changeRatio < 0.1) return 0.7;
    if (scrollDirectionChanges === 0 && scrollVelocities.length > 5) return 0.3;
    return 0;
  }

  function analyzeInteractionBehavior() {
    var elapsed = now();
    if (firstInteractionTime === null) {
      if (elapsed > 10000) return 0.5;
      return 0;
    }
    var timeToInteract = firstInteractionTime - startTime;
    if (timeToInteract < 50) return 0.4;
    if (timeToInteract < 200) return 0.2;
    if (elapsed > 5000 && counters.mousemove === 0 && counters.touchstart === 0) return 0.3;
    return 0;
  }

  // =========================================================
  // BOTD DETECTORS (18)
  // =========================================================
  function runBotDDetectors() {
    var det = {};
    var w = window, n = navigator, d = document, s = screen;

    try { if (n.webdriver === true) det.webdriver = 1; } catch (e) {}
    try {
      if (Object.prototype.hasOwnProperty.call(n, 'webdriver')) det.webdriverOwn = 1;
      var wdGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
      if (wdGetter && wdGetter.get && !isNativeFn(wdGetter.get.toString())) det.webdriverSpoofed = 1;
    } catch (e) {}
    try { if (d.hasFocus && d.hasFocus() && w.outerWidth === 0 && w.outerHeight === 0) det.windowSize = 1; } catch (e) {}
    try {
      if (n.appVersion) {
        if (/headless/i.test(n.appVersion)) det.appVersionHeadless = 1;
        if (/electron/i.test(n.appVersion)) det.appVersionElectron = 1;
      }
    } catch (e) {}
    try {
      if (n.userAgent) {
        if (/PhantomJS/i.test(n.userAgent)) det.userAgentPhantom = 1;
        if (/Headless/i.test(n.userAgent)) det.userAgentHeadless = 1;
        if (/Electron/i.test(n.userAgent)) det.userAgentElectron = 1;
      }
    } catch (e) {}
    try { if (!Array.isArray(n.plugins)) det.pluginsArray = 1; } catch (e) {}
    try { if (n.languages && n.languages.length === 0) det.languagesEmpty = 1; } catch (e) {}
    try {
      var c = d.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (gl) {
        var ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (ext) {
          var v = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
          var r = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
          if (v === 'Brian Paul' && r === 'Mesa OffScreen') det.webglMesa = 1;
        }
      }
    } catch (e) {}
    try {
      if (w.process) {
        if (w.process.type === 'renderer') det.processRenderer = 1;
        if (w.process.versions && w.process.versions.electron) det.processElectron = 1;
      }
    } catch (e) {}
    try {
      var err = new Error();
      throw err;
    } catch (e) {
      if (/PhantomJS/i.test(e.stack || '')) det.errorTracePhantom = 1;
    }
    try { if (typeof Function.prototype.bind === 'undefined') det.functionBind = 1; } catch (e) {}
    try {
      if (w.callPhantom || w._phantom || w.phantom) det.distinctivePhantom = 1;
      if (w.__nightmare) det.distinctiveNightmare = 1;
    } catch (e) {}
    try {
      var docKeys = Object.getOwnPropertyNames(d.documentElement);
      if (docKeys.indexOf('selenium') !== -1 || docKeys.indexOf('webdriver') !== -1) det.documentAttributes = 1;
    } catch (e) {}
    try { if (w.external && /Sequentum/i.test(String(w.external))) det.windowExternal = 1; } catch (e) {}
    try {
      var ua = n.userAgent.toLowerCase();
      var bk = 'unknown';
      if (ua.indexOf('edg/') !== -1) bk = 'edge';
      else if (ua.indexOf('firefox') !== -1) bk = 'firefox';
      else if (ua.indexOf('chrome') !== -1) bk = 'chrome';
      else if (ua.indexOf('safari') !== -1) bk = 'safari';
      if ((bk === 'chrome' || bk === 'safari') && n.productSub !== '20030107') det.productSub = 1;
    } catch (e) {}
    try {
      var isChrome = n.userAgent.indexOf('Chrome') !== -1 && n.userAgent.indexOf('Edg/') === -1;
      if (isChrome && typeof Notification !== 'undefined' && Notification.permission === 'granted') det.notificationPermissions = 1;
    } catch (e) {}
    try {
      var evalLen = eval.toString().length;
      var isChromium = (n.vendor && n.vendor.indexOf('Google') === 0);
      if (isChromium && evalLen === 33) det.evalLength = 1;
    } catch (e) {}

    return det;
  }

  // =========================================================
  // VI-BOT DETECTORS (28)
  // =========================================================
  function runVIBotDetectors() {
    var det = {};
    var w = window, n = navigator, d = document, s = screen;

    try {
      var allKeys = Object.getOwnPropertyNames(w);
      for (var i = 0; i < allKeys.length; i++) {
        var k = allKeys[i];
        if (k.indexOf('cdc_') === 0 || k === '__playwright__' || k === '__puppeteer__' || k.indexOf('__pw_') === 0) {
          det.cdpDetected = 1;
          break;
        }
      }
    } catch (e) {}
    try {
      if (w.__puppeteer_evaluation_script__ !== undefined) det.puppeteer = 1;
      if (w.__playwright__ !== undefined) det.playwright = 1;
      if (w.__nightmare !== undefined) det.nightmare = 1;
      if (w.callPhantom !== undefined) det.phantom = 1;
    } catch (e) {}
    try {
      var docKeys = Object.keys(d);
      for (var j = 0; j < docKeys.length; j++) {
        var val = d[docKeys[j]];
        if (typeof val === 'object' && val !== null && 'cache_' in val) { det.chromeDriver = 1; break; }
      }
    } catch (e) {}
    try {
      var createStr = Document.prototype.createElement.toString();
      var docCreateStr = document.createElement.toString();
      if (isNativeFn(createStr) && isNativeFn(docCreateStr) && Document.prototype.createElement !== document.createElement) {
        det.fakeCreateElement = 1;
      }
    } catch (e) {}
    try { if (!isNativeFn(Function.prototype.toString.toString())) det.toStringSpoofed = 1; } catch (e) {}
    try {
      var notifGetter = Object.getOwnPropertyDescriptor(Notification.prototype, 'permission');
      if (notifGetter && notifGetter.get && !isNativeFn(notifGetter.get.toString())) det.stealthNotification = 1;
    } catch (e) {}
    try {
      var pluginsGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins');
      if (pluginsGetter && pluginsGetter.get && !isNativeFn(pluginsGetter.get.toString())) det.stealthPlugins = 1;
    } catch (e) {}
    try {
      var gcsStr = HTMLCanvasElement.prototype.getContext.toString();
      if (!isNativeFn(gcsStr) && gcsStr.length > 200) det.stealthCanvas = 1;
    } catch (e) {}
    try {
      if (w.chrome && typeof w.chrome === 'object') {
        var chromeKeys = Object.keys(w.chrome);
        if (chromeKeys.indexOf('loadTimes') !== -1 && chromeKeys[0] !== 'loadTimes') det.wrongChromeOrder = 1;
      }
    } catch (e) {}
    try {
      var isChromium3 = n.vendor && n.vendor.indexOf('Google') === 0;
      if (isChromium3 && s.orientation && s.orientation.type === 'landscape-primary' && s.orientation.angle === 90) {
        var hasChromeRt = w.chrome && w.chrome.runtime;
        if (!hasChromeRt && 'SharedWorker' in w) det.playwrightOrientation = 1;
      }
    } catch (e) {}
    try {
      var iframe = d.createElement('iframe');
      iframe.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;';
      if (d.body) d.body.appendChild(iframe);
      var ifWin = iframe.contentWindow;
      if (ifWin) {
        if (ifWin.chrome && ifWin.chrome.runtime) {
          if (ifWin.chrome.runtime.connect || ifWin.chrome.runtime.sendMessage) det.iframeChromeRuntime = 1;
        }
      }
      if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
    } catch (e) {}
    try {
      if (s.width === 0 || s.height === 0) det.screenZero = 1;
      if (s.availWidth > s.width || s.availHeight > s.height) det.screenAvail = 1;
      if (s.colorDepth !== s.pixelDepth) det.colorMismatch = 1;
    } catch (e) {}
    try {
      if (!n.languages || n.languages.length === 0) det.navLanguages = 1;
      if (!n.plugins || n.plugins.length === 0) det.navPlugins = 1;
      if (n.hardwareConcurrency === undefined || n.hardwareConcurrency === 0) det.navCores = 1;
    } catch (e) {}
    try {
      var hc = n.hardwareConcurrency;
      if (hc === undefined || hc === 0) det.hardwareZero = 1;
      if (hc > 64) det.hardwareAbsurd = 1;
    } catch (e) {}
    try {
      var p = w.performance;
      if (p && p.timing && p.timing.navigationStart === 0 && p.timing.fetchStart === 0) det.performanceZero = 1;
    } catch (e) {}
    try {
      var t0 = performance.now();
      var t1 = performance.now();
      if (t1 - t0 === 0) {
        var t2 = performance.now();
        var t3 = performance.now();
        if (t3 - t2 === 0) det.timingZero = 1;
      }
    } catch (e) {}
    try {
      var baseFonts = ['Arial', 'Calibri', 'Cambria', 'Consolas', 'Courier New', 'Georgia', 'Helvetica', 'Impact', 'Tahoma', 'Times New Roman'];
      var fcanvas = d.createElement('canvas');
      var fctx = fcanvas.getContext('2d');
      if (fctx) {
        var text = 'mmmmmmmmmmlli';
        fctx.font = '12px monospace';
        var baseline = fctx.measureText(text).width;
        var found = 0;
        for (var fi = 0; fi < baseFonts.length; fi++) {
          fctx.font = '12px ' + baseFonts[fi] + ', monospace';
          if (fctx.measureText(text).width !== baseline) found++;
        }
        if (found <= 3) det.fontFew = 1;
      }
    } catch (e) {}
    try {
      var isTouch = ('ontouchstart' in w) || n.maxTouchPoints > 0;
      if (!isTouch && d.body) {
        var div = d.createElement('div');
        var inner = d.createElement('div');
        div.style.cssText = 'width:100px;height:200px;overflow:scroll;';
        inner.style.cssText = 'width:100px;height:200px;';
        div.appendChild(inner);
        d.body.appendChild(div);
        if (div.clientWidth === div.offsetWidth) det.hiddenScroll = 1;
        d.body.removeChild(div);
      }
    } catch (e) {}
    try {
      var isTouch2 = ('ontouchstart' in w) || n.maxTouchPoints > 0;
      if (!isTouch2) {
        try {
          var hover = w.matchMedia('(hover)').matches;
          var anyHover = w.matchMedia('(any-hover: hover)').matches;
          if (!hover && !anyHover) det.noHover = 1;
        } catch (e) {}
      }
    } catch (e) {}
    try {
      var wglCanvas = d.createElement('canvas');
      var wglCtx = wglCanvas.getContext('webgl') || wglCanvas.getContext('experimental-webgl');
      if (!wglCtx) {
        if (!('WebGLRenderingContext' in w)) det.webglDisabled = 1;
      }
    } catch (e) {}

    return det;
  }

  // =========================================================
  // REBROWSER-BOT-DETECTOR TESTS
  // =========================================================
  function runRebrowserTests() {
    var rb = {};
    var w = window, n = navigator, d = document;

    // 1) pwInitScripts
    try {
      if (typeof w.__pwInitScripts !== 'undefined') rb.pwInitScripts = 1;
      if (typeof w.__playwright__binding__ !== 'undefined') rb.pwBinding = 1;
    } catch (e) {}

    // 2) documentInterception
    try {
      var navEntries = performance.getEntriesByType('navigation');
      if (navEntries && navEntries.length > 0) {
        var navEntry = navEntries[0];
        var nextHop = navEntry.nextHopProtocol || '';
        var transferSize = navEntry.transferSize || 0;
        var workerStart = navEntry.workerStart || 0;
        if (nextHop === '' && transferSize > 0 && workerStart === 0) {
          rb.documentInterception = 1;
        }
      }
    } catch (e) {}

    // 3) runtimeEnableLeak
    try {
      var stackLookupCount = 0;
      var prepareStackTraceCount = 0;
      var nameGetterCount = 0;
      var rounds = 3;

      for (var ri = 0; ri < rounds; ri++) {
        var testErr = new Error();
        Object.defineProperty(testErr, 'stack', {
          configurable: false, enumerable: false,
          get: function () { stackLookupCount += 1; return ''; }
        });
        try { console.debug(testErr); } catch (e) {}

        var origDesc = Object.getOwnPropertyDescriptor(Error, 'prepareStackTrace');
        if (!origDesc || origDesc.configurable) {
          var origPrepare = Error.prepareStackTrace;
          var probeErr;
          try {
            Object.defineProperty(Error, 'prepareStackTrace', {
              configurable: true, writable: true,
              value: function (err, frames) {
                if (err === probeErr) prepareStackTraceCount += 1;
                return origPrepare ? origPrepare(err, frames) : String(err);
              }
            });
            probeErr = new Error('runtimeEnableLeak');
            try { console.debug(probeErr); } catch (e) {}
          } finally {
            if (origDesc) Object.defineProperty(Error, 'prepareStackTrace', origDesc);
            else delete Error.prepareStackTrace;
          }
        }

        class RLE extends Error {
          get name() { nameGetterCount += 1; return 'RuntimeEnableLeakError'; }
        }
        try { console.debug(new RLE('runtimeEnableLeak')); } catch (e) {}
      }

      if (prepareStackTraceCount > 0 || nameGetterCount / rounds > 1.5) rb.runtimeEnableLeak = 1;
      else if (stackLookupCount > 0) rb.runtimeEnableLeak = 0.7;
    } catch (e) {}

    // 4) sourceUrlLeak
    try {
      var srcErr = new Error('Detection Error');
      var stackStr = srcErr.stack ? srcErr.stack.toString() : '';
      if (stackStr.indexOf('pptr:') !== -1) { rb.sourceUrlLeak = 1; rb.sourceUrlKind = 'puppeteer'; }
      else if (stackStr.indexOf('UtilityScript.') !== -1) { rb.sourceUrlLeak = 1; rb.sourceUrlKind = 'playwright'; }
      else {
        var bareFiles = [];
        var lines = stackStr.split('\n');
        for (var li = 0; li < lines.length; li++) {
          var line = lines[li];
          if (!/^\s*at /.test(line)) continue;
          var m = line.match(/([^\s(),]*):(\d+):(\d+)/g);
          if (m) {
            for (var mi = 0; mi < m.length; mi++) {
              var fp = m[mi].split(':')[0];
              if (fp === '' || fp === '<anonymous>' || /^[a-z][a-z0-9+.-]*:/i.test(fp)) continue;
              bareFiles.push(fp);
            }
          }
        }
        if (bareFiles.length > 0) { rb.sourceUrlLeak = 0.5; rb.bareFiles = bareFiles.slice(0, 5); }
      }
    } catch (e) {}

    // 5) nativeTampering
    try {
      var tampered = [];
      var automationFrames = [];
      var targets = {
        'Navigator.webdriver': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver'); return dd && dd.get; })(),
        'Navigator.userAgent': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent'); return dd && dd.get; })(),
        'Navigator.platform': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform'); return dd && dd.get; })(),
        'Navigator.languages': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages'); return dd && dd.get; })(),
        'Navigator.plugins': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins'); return dd && dd.get; })(),
        'Navigator.hardwareConcurrency': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'hardwareConcurrency'); return dd && dd.get; })(),
        'Navigator.deviceMemory': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'deviceMemory'); return dd && dd.get; })(),
        'Navigator.maxTouchPoints': (function () { var dd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'maxTouchPoints'); return dd && dd.get; })(),
        'Screen.width': (function () { var dd = Object.getOwnPropertyDescriptor(Screen.prototype, 'width'); return dd && dd.get; })(),
        'Screen.height': (function () { var dd = Object.getOwnPropertyDescriptor(Screen.prototype, 'height'); return dd && dd.get; })(),
        'Permissions.query': w.Permissions && w.Permissions.prototype && w.Permissions.prototype.query,
        'WebGLRenderingContext.getParameter': w.WebGLRenderingContext && w.WebGLRenderingContext.prototype && w.WebGLRenderingContext.prototype.getParameter,
        'HTMLCanvasElement.toDataURL': HTMLCanvasElement.prototype.toDataURL,
        'HTMLIFrameElement.contentWindow': (function () { var dd = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow'); return dd && dd.get; })(),
        'Function.toString': Function.prototype.toString,
        'Date.getTimezoneOffset': Date.prototype.getTimezoneOffset,
        'Intl.DateTimeFormat.resolvedOptions': Intl.DateTimeFormat.prototype.resolvedOptions
      };

      for (var tname in targets) {
        var fn = targets[tname];
        if (typeof fn !== 'function') continue;
        var reasons = [];

        var src = Function.prototype.toString.call(fn);
        if (!/^function [^(]*\(\) \{\s*\[native code\]\s*\}$/.test(src)) {
          reasons.push('toString mismatch');
        }

        if (Object.prototype.hasOwnProperty.call(fn, 'prototype')) {
          reasons.push('has own prototype');
        }

        var origProto = Object.getPrototypeOf(fn);
        try {
          Object.setPrototypeOf(fn, Object.create(fn));
          reasons.push('proxy detected (cyclic __proto__ accepted)');
        } catch (ce) {
          // Expected for native functions
        } finally {
          try {
            if (Object.getPrototypeOf(fn) !== origProto) Object.setPrototypeOf(fn, origProto);
          } catch (re) {
            reasons.push('prototype restore threw');
          }
        }

        try {
          var callResult = fn.call(Object.create(null));
          if (callResult && typeof callResult.then === 'function') {
            // Skip async
          }
        } catch (ce) {
          var errStack = String(ce && ce.stack).split('\n').slice(1);
          for (var ei = 0; ei < errStack.length; ei++) {
            if (/pptr:|UtilityScript\.|newHandler\.<computed>/.test(errStack[ei])) {
              automationFrames.push(tname);
              break;
            }
          }
        }

        if (reasons.length > 0) tampered.push({ name: tname, reasons: reasons });
      }

      try {
        var ownNav = Object.getOwnPropertyNames(navigator);
        if (ownNav.length > 0) {
          rb.navOwnProps = ownNav.slice(0, 10);
        }
      } catch (e) {}

      try {
        var ifr = d.createElement('iframe');
        ifr.srcdoc = '<p></p>';
        ifr.style.display = 'none';
        d.body.appendChild(ifr);
        setTimeout(function () {
          try {
            if (ifr.contentWindow && ifr.contentWindow.Navigator === window.Navigator) {
              rb.iframeRealmShared = 1;
            }
          } catch (e) {}
          try { ifr.remove(); } catch (e) {}
        }, 100);
      } catch (e) {}

      if (tampered.length > 0) rb.nativeTampered = tampered.slice(0, 5);
      if (automationFrames.length > 0) rb.automationFrames = automationFrames.slice(0, 5);
    } catch (e) {}

    // 6) exposeFunctionLeak
    try {
      var keyList = Object.keys(window);
      for (var ki = 0; ki < keyList.length; ki++) {
        var kname = keyList[ki];
        if (kname.indexOf('puppeteer_') === 0) { rb.exposeFunctionLeak = 1; rb.exposeKind = 'puppeteer'; break; }
        if (kname === '__playwright__binding__') { rb.exposeFunctionLeak = 1; rb.exposeKind = 'playwright'; break; }
        try {
          if (typeof window[kname] === 'function' && window[kname].__installed === true) {
            rb.exposeFunctionLeak = 1; rb.exposeKind = 'playwright_installed'; break;
          }
        } catch (e) {}
      }
    } catch (e) {}

    // 7) cdpBindingGlobals
    try {
      var unnamed = [];
      var props = Object.getOwnPropertyNames(window);
      for (var pi = 0; pi < props.length; pi++) {
        try {
          var desc = Object.getOwnPropertyDescriptor(window, props[pi]);
          if (!desc || !('value' in desc)) continue;
          if (typeof desc.value === 'function' && desc.value.name === '' && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(desc.value))) {
            unnamed.push(props[pi]);
          }
        } catch (e) {}
      }
      if (unnamed.length >= 2) rb.cdpBindingGlobals = unnamed.slice(0, 5);
    } catch (e) {}

    // 8) headless indicators
    try {
      var isDesktop = !(navigator.userAgentData && navigator.userAgentData.mobile) && !/Android|iPhone|iPad|Mobile/.test(navigator.userAgent);
      var isChromium = n.vendor && n.vendor.indexOf('Google') === 0;
      if (isChromium && isDesktop && typeof window.chrome === 'undefined') {
        rb.headlessNoChrome = 1;
      }
      if (window.Notification && Notification.permission === 'denied') {
        rb.headlessNotificationDenied = 0.5;
      }
      if (screen.width === 800 && screen.height === 600) {
        rb.headless800x600 = 0.5;
      }
      if (navigator.userAgent.indexOf('HeadlessChrome') !== -1) {
        rb.headlessUA = 1;
      }
    } catch (e) {}

    // 9) mobile emulation
    try {
      var isMobileUA = /Android|iPhone|iPad|iPod|Mobile/.test(navigator.userAgent);
      if (isMobileUA) {
        if (navigator.maxTouchPoints === 1) rb.mobileTouch1 = 0.5;
        if (navigator.maxTouchPoints === 0) rb.mobileTouch0 = 0.5;
        var uaIsIOS = /iPhone|iPad|iPod/.test(navigator.userAgent);
        if (uaIsIOS && navigator.vendor === 'Google Inc.') rb.mobileIOSChromium = 0.5;
      }
    } catch (e) {}

    // 10) platform mismatch
    try {
      var uaLower = navigator.userAgent.toLowerCase();
      var platformLower = (navigator.platform || '').toLowerCase();
      var uaOS = 'unknown';
      if (uaLower.indexOf('windows') !== -1) uaOS = 'windows';
      else if (uaLower.indexOf('mac os') !== -1 || uaLower.indexOf('macintosh') !== -1) uaOS = 'macos';
      else if (uaLower.indexOf('linux') !== -1) uaOS = 'linux';
      else if (uaLower.indexOf('android') !== -1) uaOS = 'android';
      else if (uaLower.indexOf('iphone') !== -1 || uaLower.indexOf('ipad') !== -1) uaOS = 'ios';

      var platOS = 'unknown';
      if (platformLower.indexOf('win') === 0) platOS = 'windows';
      else if (platformLower.indexOf('mac') === 0) platOS = 'macos';
      else if (platformLower.indexOf('linux') === 0) platOS = 'linux';
      else if (platformLower.indexOf('iphone') === 0 || platformLower.indexOf('ipad') === 0) platOS = 'ios';

      if (uaOS !== 'unknown' && platOS !== 'unknown' && uaOS !== platOS) {
        rb.platformMismatch = { ua: uaOS, platform: platOS };
      }

      try {
        var el = d.createElement('div');
        el.style.setProperty('color-scheme', 'light', 'important');
        el.style.setProperty('color', 'ActiveText', 'important');
        d.body.appendChild(el);
        var activeColor = window.getComputedStyle(el).color;
        el.remove();
        if (uaOS === 'windows' && activeColor === 'rgb(255, 0, 0)') {
          rb.activeTextMismatch = 0.5;
        }
      } catch (e) {}
    } catch (e) {}

    return rb;
  }

  // =========================================================
  // EVENT LISTENERS
  // =========================================================
  function setupListeners() {
    document.addEventListener('mousemove', function (e) {
      counters.mousemove++;
      if (firstMoveTime === null) firstMoveTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      if (first30s.start_ms === 0) first30s.start_ms = now();
      if (now() <= 30000) {
        first30s.mousemoves_30s++;
        if (counters.mousemove > 5) first30s.has_interaction_30s = true;
      }
      markActivity();
      var t = Date.now(), x = e.clientX, y = e.clientY;
      if (lastMouseX && lastMouseY) {
        var dx = x - lastMouseX, dy = y - lastMouseY;
        mouseTotalDistance += Math.sqrt(dx*dx + dy*dy);
        var dir = Math.atan2(dy, dx);
        if (lastMouseDir && Math.abs(dir - lastMouseDir) > 0.5) mouseDirectionChanges++;
        lastMouseDir = dir;
        if (lastMouseTime && (t - lastMouseTime) > 500) mousePauses++;
        lastMouseTime = t;
      }
      lastMouseX = x; lastMouseY = y;
      mousePoints.push({ x: Math.round(x), y: Math.round(y), t: t - startTime });
      if (mousePoints.length > 100) mousePoints.shift();
    }, { passive: true });

    document.addEventListener('click', function (e) {
      counters.clicks++;
      if (firstClickTime === null) firstClickTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      if (now() <= 30000) { first30s.clicks_30s++; first30s.has_interaction_30s = true; }

      var cx = Math.round(e.clientX), cy = Math.round(e.clientY);
      clicksPoints.push({ x: cx, y: cy, t: now() });
      if (clicksPoints.length > 20) clicksPoints.shift();

      recordRageClick(e.target, cx, cy);
      packageIntervalEvent(e);

      try {
        var rect = getTargetRect(e.target);
        var path = buildPath(e);
        detailedEvents.push({
          type: 'click',
          target: e.target ? getSelector(e.target) : 'Unknown',
          path: path, rect: rect,
          details: { clicks: e.detail, ctrl: e.ctrlKey, alt: e.altKey, shift: e.shiftKey, meta: e.metaKey },
          t: now()
        });
        if (detailedEvents.length > 50) detailedEvents.shift();
      } catch (err) {}
      markActivity();
    }, { passive: true });

    document.addEventListener('scroll', function () {
      counters.scrolls++;
      if (firstScrollTime === null) firstScrollTime = Date.now();
      markActivity();
      if (now() <= 30000) { first30s.scrolls_30s++; first30s.has_interaction_30s = true; }
      packageIntervalEvent({ type: 'scroll', target: document.body });

      var t = Date.now(), y = window.pageYOffset || 0;
      try {
        var docH = Math.max(document.documentElement.scrollHeight - window.innerHeight, 1);
        var pct = Math.min(100, (y / docH) * 100);
        if (pct > scrollMaxDepthPct) scrollMaxDepthPct = Math.round(pct);
      } catch (e) {}
      if (lastScrollY !== null) {
        var dy = y - lastScrollY;
        if (Math.abs(dy) > 5) {
          var dir = dy > 0 ? 1 : -1;
          if (lastScrollDir !== 0 && dir !== lastScrollDir) scrollDirectionChanges++;
          lastScrollDir = dir;
          if (lastScrollTime && (t - lastScrollTime) > 500) scrollPauses++;
          try {
            if (lastScrollTime && (t - lastScrollTime) > 0) {
              var velocity = Math.abs(dy) / (t - lastScrollTime);
              if (velocity > 0) {
                scrollVelocities.push(velocity);
                if (scrollVelocities.length > 50) scrollVelocities.shift();
              }
            }
          } catch (err) {}
          lastScrollTime = t;
        }
      }
      lastScrollY = y;
    }, { passive: true });

    document.addEventListener('wheel', function (e) {
      counters.wheel++;
      markActivity();
      packageIntervalEvent(e);
    }, { passive: true });

    document.addEventListener('touchstart', function (e) {
      counters.touchstart++;
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      markActivity();
      if (now() <= 30000) first30s.has_interaction_30s = true;
      packageIntervalEvent(e);
    }, { passive: true });

    document.addEventListener('keydown', function (e) {
      counters.keydown++;
      if (firstKeyTime === null) firstKeyTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      markActivity();
      if (now() <= 30000) { first30s.keys_30s++; first30s.has_interaction_30s = true; }
      if (e.key === 'Backspace') counters.backspace++;
      var t = Date.now();
      if (window._ovgLastKeyTime) {
        var interval = t - window._ovgLastKeyTime;
        if (interval > 0 && interval < 5000) { keyIntervals.push(interval); if (keyIntervals.length > 100) keyIntervals.shift(); }
      }
      window._ovgLastKeyTime = t;
      if (lastKeyTime && (t - lastKeyTime) < 1000) {} else if (lastKeyTime) typingBursts++;
      lastKeyTime = t;
      packageIntervalEvent(e);
    }, { passive: true });

    window.addEventListener('blur', function () { markActivity(); });
    document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') finalize('hidden'); });
    window.addEventListener('pagehide', function () { finalize('pagehide'); });
    window.addEventListener('beforeunload', function () { finalize('beforeunload'); });
    setInterval(checkIdle, 5000);
  }

  // =========================================================
  // FINGERPRINT BUILDERS
  // =========================================================
  function getCanvasHash() {
    try {
      var c = document.createElement('canvas'); c.width = 220; c.height = 40;
      var ctx = c.getContext('2d');
      if (!ctx) return 'blocked';
      ctx.textBaseline = 'top'; ctx.font = '15px Arial';
      ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
      ctx.fillStyle = '#069'; ctx.fillText('OVG-v3', 2, 15);
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

  function getWebGLPrecision() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { high_float: -1, medium_float: -1 };
      var hf = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
      var mf = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT);
      return { high_float: hf ? hf.precision : -1, medium_float: mf ? mf.precision : -1 };
    } catch (e) { return { high_float: -1, medium_float: -1 }; }
  }

  function getAutomation() {
    var out = { puppeteer: false, playwright: false, selenium: false, nightmare: false, phantom: false, cdc: false };
    try {
      if (window.__puppeteer_evaluation_script__ !== undefined) out.puppeteer = true;
      if (window.__playwright__ !== undefined) out.playwright = true;
      if (window.__nightmare !== undefined) out.nightmare = true;
      if (window.callPhantom !== undefined) out.phantom = true;
      var keys = Object.keys(window);
      for (var i = 0; i < keys.length; i++) {
        if (keys[i].indexOf('$cdc_') === 0 || keys[i].indexOf('cdc_') === 0) { out.cdc = true; out.selenium = true; break; }
      }
    } catch (e) {}
    return out;
  }

  function getCDP() {
    try {
      var detected = false;
      var err = new Error();
      Object.defineProperty(err, 'stack', { get: function () { detected = true; return ''; } });
      if (console.debug) console.debug(err);
      return detected;
    } catch (e) { return false; }
  }

  var _speechVoices = null;
  function initSpeechVoices() {
    try {
      if (!window.speechSynthesis) { _speechVoices = -1; return; }
      var v = window.speechSynthesis.getVoices();
      if (v && v.length > 0) { _speechVoices = v.length; return; }
      window.speechSynthesis.onvoiceschanged = function () {
        _speechVoices = window.speechSynthesis.getVoices().length;
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

  function getConnection() {
    try {
      var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (!c) return { rtt: -1, downlink: -1, effective_type: 'Unknown' };
      return {
        rtt: typeof c.rtt === 'number' ? c.rtt : -1,
        downlink: typeof c.downlink === 'number' ? c.downlink : -1,
        effective_type: String(c.effectiveType || 'Unknown')
      };
    } catch (e) { return { rtt: -1, downlink: -1, effective_type: 'Unknown' }; }
  }

  function buildNav() {
    var nav = {
      ua: navigator.userAgent,
      platform: navigator.platform || '',
      webdriver: navigator.webdriver === true,
      language: String(navigator.language || ''),
      maxTouchPoints: Number(navigator.maxTouchPoints) || 0,
      has_touch: ('ontouchstart' in window) || (Number(navigator.maxTouchPoints) > 0)
    };
    try {
      if (navigator.userAgentData) {
        nav.ua_data = {
          mobile: navigator.userAgentData.mobile === true,
          platform: String(navigator.userAgentData.platform || '')
        };
      }
    } catch (e) {}
    return nav;
  }

  function buildFingerprint() {
    var pluginsCount = -1;
    try { pluginsCount = navigator.plugins ? navigator.plugins.length : -1; } catch (e) {}
    var langs = [];
    try { var l = navigator.languages; if (l) for (var i = 0; i < l.length && i < 5; i++) langs.push(String(l[i])); } catch (e) {}
    var tz = 'Unknown';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch (e) {}
    var chromeCheck = 'error';
    try {
      if (typeof window.chrome === 'undefined') chromeCheck = 'no_window_chrome';
      else if (typeof window.chrome.runtime === 'undefined') chromeCheck = 'window_chrome_no_runtime';
      else chromeCheck = 'full';
    } catch (e) {}
    var intlLocale = 'Unknown';
    try { intlLocale = Intl.DateTimeFormat().resolvedOptions().locale || 'Unknown'; } catch (e) {}

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
      intl_locale: intlLocale,
      connection: getConnection(),
      botd: runBotDDetectors(),
      vib: runVIBotDetectors(),
      rebrowser: runRebrowserTests(),
      trap_triggers: trapTriggers,
      honeypot_triggered: honeypotTriggered
    };
  }

  function buildScreen() {
    return {
      width: screen.width, height: screen.height,
      availWidth: screen.availWidth, availHeight: screen.availHeight,
      colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1,
      innerWidth: window.innerWidth || 0, innerHeight: window.innerHeight || 0
    };
  }

  function buildBehavioral() {
    var totalVisible = now();
    var mouseVelocities = [];
    for (var i = 1; i < mousePoints.length; i++) {
      var dt = mousePoints[i].t - mousePoints[i-1].t;
      if (dt > 0 && dt < 1000) {
        var dx = mousePoints[i].x - mousePoints[i-1].x;
        var dy = mousePoints[i].y - mousePoints[i-1].y;
        mouseVelocities.push(Math.sqrt(dx*dx + dy*dy) / dt);
      }
    }
    var meanVel = 0, variance = 0;
    if (mouseVelocities.length > 1) {
      var sum = 0;
      for (var j = 0; j < mouseVelocities.length; j++) sum += mouseVelocities[j];
      meanVel = sum / mouseVelocities.length;
      var sqSum = 0;
      for (var k = 0; k < mouseVelocities.length; k++) sqSum += Math.pow(mouseVelocities[k] - meanVel, 2);
      variance = sqSum / mouseVelocities.length;
    }
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
      scroll_velocity_samples: scrollVelocities.slice(-50),
      keydown_count: counters.keydown,
      key_intervals: keyIntervals.slice(-20),
      backspace_count: counters.backspace,
      typing_bursts: typingBursts,
      clicks: counters.clicks,
      clicks_points: clicksPoints.slice(-20),
      wheel_events: counters.wheel,
      clicks_before_move: (firstClickTime && firstMoveTime && firstClickTime < firstMoveTime) ? 1 : 0,
      total_time_ms: Math.round(now()),
      visible_time_ms: Math.round(totalVisible),
      idle_periods_count: idlePeriods.length,
      longest_idle_ms: idlePeriods.length ? Math.max.apply(null, idlePeriods.map(function(p){return p.dur;})) : 0,
      events: {
        mousemove: counters.mousemove, touchstart: counters.touchstart,
        clicks: counters.clicks, scrolls: counters.scrolls, keydown: counters.keydown
      },
      mouse_points: mousePoints.slice(-100),
      behavior_scores: {
        mouse: analyzeMouseBehavior(),
        keys: analyzeKeyBehavior(),
        scroll: analyzeScrollBehavior(),
        interaction: analyzeInteractionBehavior()
      },
      rage_clicks: rageClickEvents.slice(-20),
      interval_logs: intervalLogState.intervalLogs.slice(-30),
      mutation_summary: {
        added: mutationSummary.added,
        removed: mutationSummary.removed,
        attributes: mutationSummary.attributes,
        targets: mutationSummary.targets.slice(0, 15),
        total_events: mutationSummary.totalEvents
      },
      detailed_events: detailedEvents.slice(-30)
    };
  }

  // =========================================================
  // NETWORK
  // =========================================================
  function doHandshake() {
    if (handshakeDone) return;
    handshakeDone = true;
    var body = {
      v: 3, session_id: sessionId, click_id: clickId,
      campaign_key: CAMPAIGN_KEY, url: location.href, t_ms: Math.round(now()),
      nav: buildNav(), fp: buildFingerprint(),
      consent_state: 'unknown', tracking_params: trackingParams
    };
    safeSend(ENDPOINT + '/api/collect/handshake', body, false).then(function (r) {
      if (r && r.data && r.data.hide) {
        document.body.innerHTML = '';
        window.location.replace('/404');
        return;
      }
      startHeartbeatTimer();
    }).catch(function () {
      setTimeout(function () { handshakeDone = false; doHandshake(); }, 3000);
    });
  }

  function sendHeartbeat() {
    if (finalSent) return;
    seq++;
    safeSend(ENDPOINT + '/api/collect/heartbeat', {
      v: 3, session_id: sessionId, seq: seq, t_ms: Math.round(now()),
      clicks: counters.clicks, scrolls: counters.scrolls,
      mousemoves: counters.mousemove, keydowns: counters.keydown,
      is_visible: document.visibilityState === 'visible',
      is_focused: document.hasFocus()
    }, false).catch(function () {});
  }

  function startHeartbeatTimer() {
    if (heartbeatTimer) return;
    scheduleNextHeartbeat();
  }

  function scheduleNextHeartbeat() {
    if (finalSent) return;
    var jitter = (Math.random() - 0.5) * 2 * HEARTBEAT_JITTER_MS;
    heartbeatTimer = setTimeout(function () {
      sendHeartbeat();
      scheduleNextHeartbeat();
    }, HEARTBEAT_INTERVAL_MS + jitter);
  }

  function finalize(reason) {
    if (finalSent) return;
    finalSent = true;
    if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
    if (finalTimeoutTimer) { clearTimeout(finalTimeoutTimer); finalTimeoutTimer = null; }
    if (adObserver) { try { adObserver.disconnect(); } catch (e) {} }
    if (domMutationObserver) { try { domMutationObserver.disconnect(); } catch (e) {} }

    var behavior, milestonesData, navObj, fpObj, screenObj;
    try { behavior = buildBehavioral(); } catch (e) { behavior = {}; }
    try { milestonesData = collectMilestones(); } catch (e) { milestonesData = {}; }
    try { navObj = buildNav(); } catch (e) { navObj = {}; }
    try { fpObj = buildFingerprint(); } catch (e) { fpObj = {}; }
    try { screenObj = buildScreen(); } catch (e) { screenObj = {}; }

    var body = {
      v: 3, session_id: sessionId, click_id: clickId,
      campaign_key: CAMPAIGN_KEY, seq: 999, t_ms: Math.round(now()),
      url: location.href, referrer: document.referrer || '',
      webrtc_ip: 'None',
      nav: navObj, fingerprint: fpObj, behavior: behavior, screen: screenObj,
      milestones: milestonesData, first_30s: first30s, ad_events: adEvents,
      honeypot_triggered: honeypotTriggered, clock_drift_ms: 0,
      consent_state: 'unknown',
      data_quality: reason === 'timeout' ? 'partial' : 'full',
      tracking_params: trackingParams
    };

    var bodyStr;
    try { bodyStr = JSON.stringify(body); } catch (e) { return; }

    var sent = false;
    // ============ CRITICAL FIX ============
    // text/plain → no preflight → sendBeacon actually fires the POST
    try {
      sent = navigator.sendBeacon(
        ENDPOINT + '/api/collect/final',
        new Blob([bodyStr], { type: 'text/plain;charset=UTF-8' })
      );
    } catch (e) {}

    if (!sent) {
      try {
        fetch(ENDPOINT + '/api/collect/final', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: bodyStr, keepalive: true, credentials: 'omit'
        }).catch(function () {});
      } catch (e) {}
    }
  }

  function boot() {
    try {
      sessionId = uuid();
      clickId = uuid();
      initSpeechVoices();
      setupTraps();
      setupListeners();
      setupAdObserver();
      setupMutationObserver();

      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { injectHoneypots(); });
      } else {
        injectHoneypots();
      }

      finalTimeoutTimer = setTimeout(function () { finalize('timeout'); }, FINAL_TIMEOUT_MS);

      var delay = function () { setTimeout(doHandshake, HANDSHAKE_DELAY_MS); };
      if ('requestIdleCallback' in window) requestIdleCallback(delay, { timeout: 2000 });
      else delay();
    } catch (e) {}
  }
  boot();
})();
"""