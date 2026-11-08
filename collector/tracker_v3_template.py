"""
collector/tracker_v3_template.py — V3 tracker (v6.0 — Ultimate Detection Suite)

Integrates:
    - BotD (FingerprintJS) — 18 detectors
    - vi-bot — 28 detectors
    - BehaviorTracker — mouse/keys/scroll/touch analysis
    - HoneypotTraps — hidden fields, links, decoys
    - StackTraceTraps — DOM API traps for automation tools
"""
TRACKER_V3_JS = r"""(function () {
  'use strict';

  var CAMPAIGN_KEY  = '__OVG_CAMPAIGN_KEY__';
  var ENDPOINT      = '__OVG_ENDPOINT_BASE__';
  var HANDSHAKE_DELAY_MS    = 500;
  var HEARTBEAT_INTERVAL_MS = 10000;
  var HEARTBEAT_JITTER_MS   = 2000;
  var FINAL_TIMEOUT_MS      = 90 * 1000;

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
  var kpmWindow = { start: Date.now(), count: 0, history: [] };

  // =========================================================
  // TRACKING PARAMS
  // =========================================================
  var trackingParams = {};
  try {
    var urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach(function (value, key) {
      if (value !== null && value !== '') {
        trackingParams[key] = String(value).substring(0, 500);
      }
    });
    if (!trackingParams.impressionid && trackingParams.impid) {
      trackingParams.impressionid = trackingParams.impid;
    }
    if (!trackingParams.website_id && trackingParams.websiteid) {
      trackingParams.website_id = trackingParams.websiteid;
    }
  } catch (e) {}

  // =========================================================
  // HELPERS
  // =========================================================
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
      return fetch(url, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: bodyStr, keepalive: true, credentials: 'omit' }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, data: d }; }); });
    } catch (e) { return Promise.reject(e); }
  }

  // =========================================================
  // [STACK TRACE TRAPS] — Detect automation tools that use DOM APIs
  // =========================================================
  function installTrap(obj, method, name) {
    try {
      var original = obj[method];
      if (typeof original !== 'function') return;
      var trapDisabled = false;
      obj[method] = function () {
        if (trapDisabled) return original.apply(this, arguments);
        try {
          trapDisabled = true;
          null[0]();  // intentional TypeError to capture stack
        } catch (e) {
          trapDisabled = false;
          var stackStr = (e && e.stack) ? String(e.stack).toLowerCase() : '';
          if (stackStr) {
            var signatures = {
              'errorTrapPhantomJS': ['phantomjs'],
              'errorTrapPuppeteer': ['puppeteer', '__puppeteer'],
              'errorTrapPlaywrightChrome': ['playwright', '__playwright'],
              'errorTrapPlaywrightFirefox': ['juggler', 'playwright'],
              'errorTrapPlaywrightWebKit': ['playwright', 'webkit'],
              'errorTrapSeleniumChrome': ['selenium', 'webdriver'],
              'errorTrapNightmare': ['nightmare', '__nightmare'],
              'errorTrapCypress': ['cypress', '__cypress'],
              'errorTrapBotd': ['botd'],
              'errorTrapFingerprintJS': ['fingerprintjs'],
              'errorTrapPatchright': ['patchright'],
            };
            for (var key in signatures) {
              var sigs = signatures[key];
              var matched = true;
              for (var i = 0; i < sigs.length; i++) {
                if (stackStr.indexOf(sigs[i]) === -1) { matched = false; break; }
              }
              if (matched) { trapTriggers[key] = true; }
            }
          }
        }
        return original.apply(this, arguments);
      };
    } catch (e) {}
  }

  function setupTraps() {
    try {
      installTrap(Document.prototype, 'querySelector', 'querySelector');
      installTrap(Document.prototype, 'querySelectorAll', 'querySelectorAll');
      installTrap(Document.prototype, 'getElementById', 'getElementById');
      installTrap(window, 'eval', 'eval');
    } catch (e) {}
  }

  // =========================================================
  // HONEYPOT TRAPS — hidden fields, links, decoys
  // =========================================================
  var honeypotFields = [];
  var honeypotDecoys = [];

  function randomStyle(visible) {
    if (visible) {
      return 'display:block;visibility:visible;opacity:1;';
    }
    var strategies = [
      'position:fixed;top:-5000px;left:-5000px;width:1px;height:1px;',
      'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0.01;',
      'position:fixed;left:0;top:0;z-index:-9999;width:1px;height:1px;overflow:hidden;',
      'position:absolute;clip:rect(0,0,0,0);width:1px;height:1px;margin:-1px;overflow:hidden;'
    ];
    return strategies[Math.floor(Math.random() * strategies.length)];
  }

  function randomFieldName() {
    var prefixes = ['email', 'username', 'name', 'phone', 'address', 'zip', 'city', 'website', 'company', 'comment'];
    return prefixes[Math.floor(Math.random() * prefixes.length)] + '_' + Math.random().toString(36).slice(2, 6);
  }

  function injectHoneypots() {
    try {
      var container = document.createElement('div');
      container.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0.01;';

      // Hidden field
      var field = document.createElement('input');
      field.type = 'text';
      field.name = randomFieldName();
      field.tabIndex = -1;
      field.autocomplete = 'off';
      field.style.cssText = randomStyle(false);
      field.setAttribute('aria-hidden', 'true');
      field.addEventListener('input', function () { if (field.value.length > 0) honeypotTriggered = true; });
      field.addEventListener('change', function () { if (field.value.length > 0) honeypotTriggered = true; });
      container.appendChild(field);
      honeypotFields.push(field);

      // Hidden link
      var link = document.createElement('a');
      link.href = '#hp-' + Math.random();
      link.textContent = 'info';
      link.style.cssText = randomStyle(false);
      link.setAttribute('aria-hidden', 'true');
      link.setAttribute('tabindex', '-1');
      link.addEventListener('click', function (e) { e.preventDefault(); honeypotTriggered = true; });
      container.appendChild(link);

      // Decoy (read-only, hidden getter)
      var decoy = document.createElement('input');
      decoy.type = 'text';
      decoy.name = randomFieldName();
      decoy.style.cssText = randomStyle(true);
      decoy.readOnly = true;
      decoy.tabIndex = -1;
      decoy.setAttribute('aria-hidden', 'true');
      try {
        Object.defineProperty(decoy, 'value', { get: function () { return ''; }, set: function () {} });
      } catch (e) {}
      container.appendChild(decoy);
      honeypotDecoys.push(decoy);

      if (document.body) document.body.appendChild(container);
      else document.addEventListener('DOMContentLoaded', function () { document.body.appendChild(container); });
    } catch (e) {}
  }

  // =========================================================
  // [BEHAVIOR TRACKER] — Advanced mouse/keys/scroll/touch analysis
  // =========================================================
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

  function analyzeMouseBehavior() {
    if (mousePoints.length < 5) return 0;
    var angleChanges = 0, straightLineSegments = 0, pauses = 0, speedJitter = 0;
    for (var i = 1; i < mousePoints.length; i++) {
      var dx = mousePoints[i].x - mousePoints[i-1].x;
      var dy = mousePoints[i].y - mousePoints[i-1].y;
      var dt = mousePoints[i].t - mousePoints[i-1].t;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dt > 0) {
        var speed = dist / dt;
        if (i > 1) {
          var prevDx = mousePoints[i-1].x - mousePoints[i-2].x;
          var prevDy = mousePoints[i-1].y - mousePoints[i-2].y;
          var prevDist = Math.sqrt(prevDx * prevDx + prevDy * prevDy);
          var prevDt = mousePoints[i-1].t - mousePoints[i-2].t;
          var prevSpeed = prevDt > 0 ? prevDist / prevDt : 0;
          speedJitter += Math.abs(speed - prevSpeed);
          if (dx !== 0 || dy !== 0) {
            var angle = Math.atan2(dy, dx);
            var prevAngle = Math.atan2(prevDy, prevDx);
            if (Math.abs(angle - prevAngle) > 0.05) angleChanges++;
          }
          if (dist > 5 && prevDist > 5) {
            var dot = (prevDx * dx + prevDy * dy);
            var mag = prevDist * dist;
            if (mag > 0 && (dot / mag) > 0.99) straightLineSegments++;
          }
        }
        if (speed < 0.01 && dt > 100) pauses++;
      }
    }
    var avgJitter = speedJitter / Math.max(1, mousePoints.length - 2);
    var pauseRatio = pauses / Math.max(1, mousePoints.length);
    var angleChangeRatio = angleChanges / Math.max(1, mousePoints.length);
    var straightLineRatio = straightLineSegments / Math.max(1, mousePoints.length - 2);
    var humanSignals = 0;
    if (avgJitter > 0.001) humanSignals++;
    if (pauseRatio > 0.01) humanSignals++;
    if (angleChangeRatio > 0.1) humanSignals++;
    if (straightLineRatio < 0.3) humanSignals++;
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
    var stdDev = Math.sqrt(variance);
    var cv = stdDev / Math.max(mean, 0.001);
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
  // [BOTD + vi-bot] — 46 Detection functions
  // =========================================================
  function isNativeFn(fnStr) { return /\(\)\s*{\s+\[native code\]\s+}\s*$/.test(fnStr); }

  function runAllDetections() {
    var results = {};
    var w = window, n = navigator, d = document, s = screen;

    // ==================== WEBDRIVER (advanced) ====================
    try {
      if (n.webdriver === true) results.webdriver = 1;
      if (Object.prototype.hasOwnProperty.call(n, 'webdriver')) results.webdriver = Math.max(results.webdriver || 0, 0.8);
      var wdGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')?.get?.toString?.();
      if (wdGetter && !isNativeFn(wdGetter)) results.webdriver = Math.max(results.webdriver || 0, 0.6);
      var seleniumProps = ['_Selenium_IDE_Recorder', 'callSelenium', '_selenium', '__webdriver_script_fn', '__driver_evaluate', '__webdriver_evaluate', '__selenium_evaluate', '__fxdriver_evaluate', '__driver_unwrapped', '__webdriver_unwrapped', '__selenium_unwrapped', '__fxdriver_unwrapped'];
      for (var sp = 0; sp < seleniumProps.length; sp++) {
        if (seleniumProps[sp] in w || seleniumProps[sp] in d) results.webdriver = 1;
      }
      if (d.documentElement.getAttribute('selenium') !== null || d.documentElement.getAttribute('webdriver') !== null || d.documentElement.getAttribute('driver') !== null) results.webdriver = 1;
    } catch (e) {}

    // ==================== CHROMEDRIVER ====================
    try {
      var docKeys = Object.keys(d);
      for (var dk = 0; dk < docKeys.length; dk++) {
        var val = d[docKeys[dk]];
        if (typeof val === 'object' && val !== null && 'cache_' in val) { results.chromeDriver = 1; break; }
      }
      var winList = ['Array', 'Promise', 'Symbol'];
      var winKeys = Object.keys(w);
      var found = 0;
      for (var wk = 0; wk < winKeys.length; wk++) {
        if (winKeys[wk] === 'webkitStorageInfo') continue;
        for (var wl = 0; wl < winList.length; wl++) {
          if (winKeys[wk] !== winList[wl] && w[winKeys[wk]] === w[winList[wl]]) { found++; }
        }
      }
      if (found >= 3) results.chromeDriver = Math.max(results.chromeDriver || 0, 1);
    } catch (e) {}

    // ==================== CDP DETECTION ====================
    try {
      var allKeys = Object.getOwnPropertyNames(w);
      for (var ck = 0; ck < allKeys.length; ck++) {
        var key = allKeys[ck];
        if (key.indexOf('cdc_') === 0) results.cdpDetection = 1;
        if (key === '__playwright__' || key === '__puppeteer__' || key === '__pw_') results.cdpDetection = 1;
        if (key.indexOf('__firefox__') === 0) results.cdpDetection = Math.max(results.cdpDetection || 0, 0.9);
      }
      var err = new Error();
      var stack = (err.stack || '').toLowerCase();
      if (stack.indexOf('__puppeteer') !== -1 || stack.indexOf('__playwright') !== -1) results.cdpDetection = Math.max(results.cdpDetection || 0, 0.9);
    } catch (e) {}

    // ==================== PHANTOM ====================
    try {
      if ('callPhantom' in w || '_phantom' in w) results.phantomWindow = 1;
    } catch (e) {}

    // ==================== NIGHTMARE ====================
    try {
      if (w.__nightmare) results.nightmareDetected = 1;
    } catch (e) {}

    // ==================== FAKE CREATE ELEMENT ====================
    try {
      var createElStr = Document.prototype.createElement.toString();
      var docCreateStr = w.document.createElement.toString();
      if (isNativeFn(createElStr) && isNativeFn(docCreateStr) && Document.prototype.createElement !== w.document.createElement) {
        results.fakeCreateElement = 1;
      }
    } catch (e) {}

    // ==================== TO STRING SPOOFED ====================
    try {
      var fnToString = Function.prototype.toString;
      if (!isNativeFn(fnToString.toString())) results.toStringSpoofed = 0.7;
      var protoDesc = Object.getOwnPropertyDescriptor(Function.prototype, 'toString');
      if (protoDesc && protoDesc.value && !isNativeFn(protoDesc.value.toString())) results.toStringSpoofed = Math.max(results.toStringSpoofed || 0, 0.7);
    } catch (e) {}

    // ==================== STEALTH DETECTION ====================
    try {
      var notifGetter = Object.getOwnPropertyDescriptor(Notification.prototype, 'permission')?.get?.toString?.();
      if (notifGetter && !isNativeFn(notifGetter)) results.stealthDetection = 0.6;
      var pluginsGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, 'plugins')?.get?.toString?.();
      if (pluginsGetter && !isNativeFn(pluginsGetter)) results.stealthDetection = Math.max(results.stealthDetection || 0, 0.5);
      var langGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, 'languages')?.get?.toString?.();
      if (langGetter && !isNativeFn(langGetter)) results.stealthDetection = Math.max(results.stealthDetection || 0, 0.5);
      var gcsStr = HTMLCanvasElement.prototype.getContext.toString();
      if (gcsStr && !isNativeFn(gcsStr) && gcsStr.length > 200) results.stealthDetection = Math.max(results.stealthDetection || 0, 0.7);
    } catch (e) {}

    // ==================== WRONG CHROME ORDER ====================
    try {
      if (w.chrome && typeof w.chrome === 'object') {
        var chromeKeys = Object.keys(w.chrome);
        if (chromeKeys.indexOf('loadTimes') !== -1 && chromeKeys[0] !== 'loadTimes') {
          results.wrongChromeOrder = 1;
        }
      }
    } catch (e) {}

    // ==================== PLAYWRIGHT ORIENTATION ====================
    try {
      var isChromium = n.vendor && n.vendor.indexOf('Google') === 0;
      if (isChromium && s.orientation && s.orientation.type === 'landscape-primary' && s.orientation.angle === 90) {
        var hasChromeRt = w.chrome && w.chrome.runtime;
        var hasSharedWorker = 'SharedWorker' in w;
        if (!hasChromeRt && hasSharedWorker) results.playwrightOrientation = 0.5;
      }
    } catch (e) {}

    // ==================== IFRAME CHROME RUNTIME ====================
    try {
      var iframe = d.createElement('iframe');
      iframe.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;';
      if (d.body) d.body.appendChild(iframe);
      var iframeWin = iframe.contentWindow;
      if (iframeWin) {
        var ifChrome = iframeWin.chrome;
        if (ifChrome && ifChrome.runtime && (ifChrome.runtime.connect || ifChrome.runtime.sendMessage)) {
          results.iframeChromeRuntime = 0.8;
        }
        if ('callPhantom' in iframeWin || '_phantom' in iframeWin) results.phantomWindow = 1;
        var ifWd = iframeWin.navigator && iframeWin.navigator.webdriver;
        if (ifWd === true) results.webdriver = 1;
      }
      if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
    } catch (e) {}

    // ==================== CANVAS FINGERPRINT ====================
    try {
      var canvas = d.createElement('canvas');
      canvas.width = 240; canvas.height = 60;
      var ctx = canvas.getContext('2d');
      if (!ctx) { results.canvasFingerprint = 0.5; }
      else {
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f60';
        ctx.fillRect(100, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.font = '11pt Arial';
        ctx.fillText('BotDetect', 2, 45);
        var imageData = ctx.getImageData(0, 0, 240, 60).data;
        var pixelSum = 0;
        for (var pi = 0; pi < imageData.length; pi += 4) pixelSum += imageData[pi] + imageData[pi+1] + imageData[pi+2];
        if (pixelSum < 10000 || pixelSum === 0) results.canvasFingerprint = 0.6;
      }
    } catch (e) {}

    // ==================== AUDIO FINGERPRINT ====================
    try {
      var AudioCtx = w.AudioContext || w.webkitAudioContext;
      if (!AudioCtx) results.audioFingerprint = 0.2;
      else {
        var aCtx = new AudioCtx();
        if (aCtx.sampleRate !== 44100 && aCtx.sampleRate !== 48000) results.audioFingerprint = 0.3;
        if (aCtx.state !== 'closed') aCtx.close().catch(function () {});
      }
    } catch (e) {}

    // ==================== WEBGL FINGERPRINT ====================
    try {
      var wcanvas = d.createElement('canvas');
      var wgl = wcanvas.getContext('webgl') || wcanvas.getContext('experimental-webgl');
      if (!wgl) results.webglFingerprint = 0;
      else {
        var dbgExt = wgl.getExtension('WEBGL_debug_renderer_info');
        if (!dbgExt) results.webglFingerprint = 0.3;
        else {
          var vendor = String(wgl.getParameter(dbgExt.UNMASKED_VENDOR_WEBGL) || '');
          var renderer = String(wgl.getParameter(dbgExt.UNMASKED_RENDERER_WEBGL) || '');
          if (vendor === 'Brian Paul') results.webglFingerprint = 0.7;
          if (renderer.indexOf('SwiftShader') !== -1) results.webglFingerprint = 0.7;
          if (renderer.indexOf('llvmpipe') !== -1) results.webglFingerprint = 0.7;
          if (renderer.indexOf('VirtualBox') !== -1 || renderer.indexOf('VMware') !== -1) results.webglFingerprint = Math.max(results.webglFingerprint || 0, 0.5);
          if (!vendor || !renderer || vendor === '' || renderer === '') results.webglFingerprint = Math.max(results.webglFingerprint || 0, 0.4);
        }
        var precision = wgl.getShaderPrecisionFormat(wgl.FRAGMENT_SHADER, wgl.HIGH_FLOAT);
        if (!precision || precision.precision === 0) results.webglFingerprint = Math.max(results.webglFingerprint || 0, 0.3);
      }
    } catch (e) {}

    // ==================== SCREEN ANOMALIES ====================
    try {
      var sc = s;
      var screenScore = 0;
      if (sc.width === 0 || sc.height === 0) screenScore += 0.7;
      if (sc.availWidth === 0 || sc.availHeight === 0) screenScore += 0.6;
      if (sc.availWidth > sc.width || sc.availHeight > sc.height) screenScore += 0.5;
      if (sc.colorDepth === 0 || sc.pixelDepth === 0) screenScore += 0.6;
      if (sc.colorDepth !== sc.pixelDepth) screenScore += 0.3;
      if (screenScore > 0) results.screenAnomalies = Math.min(1, screenScore / 5);
    } catch (e) {}

    // ==================== NAVIGATOR INCONSISTENCIES ====================
    try {
      var navScore = 0, navChecks = 0;
      navChecks++;
      if (!n.languages || n.languages.length === 0) navScore += 0.5;
      navChecks++;
      if (!n.plugins || n.plugins.length === 0) navScore += 0.3;
      navChecks++;
      if (!n.mimeTypes || n.mimeTypes.length === 0) navScore += 0.3;
      navChecks++;
      if (n.hardwareConcurrency === undefined || n.hardwareConcurrency === 0) navScore += 0.4;
      if (navScore > 0) results.navigatorInconsistencies = Math.min(1, navScore / navChecks);
    } catch (e) {}

    // ==================== HARDWARE CONCURRENCY ====================
    try {
      var hc = n.hardwareConcurrency;
      if (hc === undefined || hc === 0) results.hardwareConcurrency = 0.6;
      else if (hc > 64) results.hardwareConcurrency = 0.5;
      else if (hc === 1 && !/Mobile|Android|iPhone|iPad/i.test(n.userAgent)) results.hardwareConcurrency = 0.3;
    } catch (e) {}

    // ==================== PERFORMANCE ANOMALIES ====================
    try {
      var p = w.performance;
      if (!p || !p.timing) results.performanceAnomalies = 0.3;
      else {
        var t = p.timing;
        if (t.navigationStart === 0 && t.fetchStart === 0) results.performanceAnomalies = 0.5;
        if (t.navigationStart > t.loadEventEnd && t.loadEventEnd !== 0) results.performanceAnomalies = Math.max(results.performanceAnomalies || 0, 0.4);
      }
    } catch (e) {}

    // ==================== TIMING ANOMALIES ====================
    try {
      var t0 = performance.now();
      var t1 = performance.now();
      if (t1 - t0 === 0) {
        var t2 = performance.now();
        var t3 = performance.now();
        if (t3 - t2 === 0) results.timingAnomalies = 0.6;
      }
    } catch (e) {}

    // ==================== FONT ENUMERATION ====================
    try {
      var baseFonts = ['Arial', 'Calibri', 'Cambria', 'Consolas', 'Courier New', 'Georgia', 'Helvetica', 'Impact', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Verdana'];
      var foundFonts = 0;
      var fcanvas = d.createElement('canvas');
      var fctx = fcanvas.getContext('2d');
      if (fctx) {
        var text = 'mmmmmmmmmmlli';
        fctx.font = '12px monospace';
        var baseline = fctx.measureText(text).width;
        for (var fi = 0; fi < baseFonts.length; fi++) {
          fctx.font = '12px ' + baseFonts[fi] + ', monospace';
          if (fctx.measureText(text).width !== baseline) foundFonts++;
        }
      }
      if (foundFonts <= 3) results.fontEnumeration = 0.8;
      else if (foundFonts <= 6) results.fontEnumeration = 0.5;
    } catch (e) {}

    // ==================== FINGERPRINT CONSISTENCY ====================
    try {
      var fpScore = 0;
      if (!n.plugins || n.plugins.length === 0) fpScore += 0.4;
      if (!n.mimeTypes || n.mimeTypes.length === 0) fpScore += 0.4;
      if (!n.languages || n.languages.length === 0) fpScore += 0.4;
      if (fpScore > 0) results.fingerprintConsistency = Math.min(1, fpScore / 3);
    } catch (e) {}

    // ==================== HIDDEN SCROLL ====================
    try {
      var isTouch = ('ontouchstart' in w) || n.maxTouchPoints > 0;
      if (!isTouch && d.body) {
        var scrollDiv = d.createElement('div');
        var internalNode = d.createElement('div');
        scrollDiv.style.cssText = 'width:100px;height:200px;overflow:scroll;';
        internalNode.style.cssText = 'width:100px;height:200px;';
        scrollDiv.appendChild(internalNode);
        d.body.appendChild(scrollDiv);
        if (scrollDiv.clientWidth === scrollDiv.offsetWidth) results.hiddenScroll = 0.6;
        d.body.removeChild(scrollDiv);
      }
    } catch (e) {}

    // ==================== NO HOVER ====================
    try {
      var isTouchDevice = ('ontouchstart' in w) || n.maxTouchPoints > 0;
      if (!isTouchDevice) {
        try {
          var hasHover = w.matchMedia('(hover)').matches;
          var anyHover = w.matchMedia('(any-hover: hover)').matches;
          if (!hasHover && !anyHover) results.noHovermq = 0.6;
          else if (!hasHover && anyHover) results.noHovermq = 0.3;
        } catch (e) {}
      }
    } catch (e) {}

    // ==================== WEBGL DISABLED ====================
    try {
      var wglCanvas = d.createElement('canvas');
      var wglCtx = wglCanvas.getContext('webgl') || wglCanvas.getContext('experimental-webgl');
      if (!wglCtx) {
        if (!('WebGLRenderingContext' in w)) results.webGLDisabled = 0.4;
        else if ('OffscreenCanvas' in w) results.webGLDisabled = 0.5;
        else results.webGLDisabled = 0.3;
      }
    } catch (e) {}

    // ==================== IFRAME CHROME RUNTIME (dup check) ====================
    // (already done above)

    // ==================== WRONG CHROME ORDER (dup) ====================
    // (already done above)

    // ==================== BOTD SPECIFIC ====================
    // WebDriver (BotD style)
    if (n.webdriver === true) results.detectWebDriver = 'headless_chrome';

    // Window size 0x0
    try { if (d.hasFocus && d.hasFocus() && w.outerWidth === 0 && w.outerHeight === 0) results.detectWindowSize = 'headless_chrome'; } catch (e) {}

    // App version
    try {
      if (n.appVersion) {
        if (/headless/i.test(n.appVersion)) results.detectAppVersion = 'headless_chrome';
        else if (/electron/i.test(n.appVersion)) results.detectAppVersion = 'electron';
      }
    } catch (e) {}

    // User agent
    try {
      if (n.userAgent) {
        if (/PhantomJS/i.test(n.userAgent)) results.detectUserAgent = 'phantomjs';
        else if (/Headless/i.test(n.userAgent)) results.detectUserAgent = 'headless_chrome';
        else if (/Electron/i.test(n.userAgent)) results.detectUserAgent = 'electron';
      }
    } catch (e) {}

    // Plugins array
    try { if (!Array.isArray(n.plugins)) results.detectPluginsArray = 'headless_chrome'; } catch (e) {}

    // Languages
    try { if (n.languages && n.languages.length === 0) results.detectLanguagesLengthInconsistency = 'headless_chrome'; } catch (e) {}

    // ProductSub
    try {
      var ua = n.userAgent.toLowerCase();
      var bk = 'unknown';
      if (ua.indexOf('edg/') !== -1) bk = 'edge';
      else if (ua.indexOf('firefox') !== -1) bk = 'firefox';
      else if (ua.indexOf('chrome') !== -1) bk = 'chrome';
      else if (ua.indexOf('safari') !== -1) bk = 'safari';
      if ((bk === 'chrome' || bk === 'safari') && n.productSub !== '20030107') results.detectProductSub = 'unknown';
    } catch (e) {}

    // Notification permissions
    try {
      var isChrome = n.userAgent.indexOf('Chrome') !== -1 && n.userAgent.indexOf('Edg/') === -1;
      if (isChrome && Notification && Notification.permission === 'granted') results.detectNotificationPermissions = 'headless_chrome';
    } catch (e) {}

    // Eval length
    try {
      var evalLen = eval.toString().length;
      var isChromiumEval = (n.vendor && n.vendor.indexOf('Google') === 0);
      if (isChromiumEval && evalLen === 33) results.detectEvalLengthInconsistency = 'unknown';
    } catch (e) {}

    // Error trace
    try {
      var errObj = new Error();
      errObj.stack = '';
      try { throw errObj; } catch (e) {}
      if (/PhantomJS/i.test(errObj.stack || '')) results.detectErrorTrace = 'phantomjs';
    } catch (e) {}

    // Function bind
    try { if (typeof Function.prototype.bind === 'undefined') results.detectFunctionBind = 'phantomjs'; } catch (e) {}

    // Distinctive props
    try {
      if (w.callPhantom || w._phantom || w.phantom) results.detectDistinctiveProperties = 'phantomjs';
      if (w.__nightmare) results.detectDistinctiveProperties = 'nightmarejs';
    } catch (e) {}

    // Document attributes
    try {
      var docKeyList = Object.getOwnPropertyNames(d.documentElement);
      if (docKeyList.indexOf('selenium') !== -1 || docKeyList.indexOf('webdriver') !== -1) results.detectDocumentAttributes = 'selenium';
    } catch (e) {}

    // Window external
    try { if (w.external && /Sequentum/i.test(w.external)) results.detectWindowExternal = 'sequentum'; } catch (e) {}

    // WebGL Mesa OffScreen
    try {
      var mesaCanvas = d.createElement('canvas');
      var mesaGl = mesaCanvas.getContext('webgl');
      if (mesaGl) {
        var mesaExt = mesaGl.getExtension('WEBGL_debug_renderer_info');
        if (mesaExt) {
          var mfr = mesaGl.getParameter(mesaExt.UNMASKED_RENDERER_WEBGL);
          if (mfr === 'Mesa OffScreen') results.detectWebGL = 'headless_chrome';
        }
      }
    } catch (e) {}

    // Process (Electron)
    try { if (w.process && (w.process.type === 'renderer' || (w.process.versions && w.process.versions.electron))) results.detectProcess = 'electron'; } catch (e) {}

    return results;
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
  // EVENT LISTENERS
  // =========================================================
  function setupListeners() {
    document.addEventListener('mousemove', function (e) {
      counters.mousemove++;
      if (firstMoveTime === null) firstMoveTime = Date.now();
      if (firstInteractionTime === null) firstInteractionTime = Date.now();
      if (first30s.start_ms === 0) first30s.start_ms = now();
      if (now() <= 30000) { first30s.mousemoves_30s++; if (counters.mousemove > 5) first30s.has_interaction_30s = true; }
      markActivity();
      var t = Date.now(); var x = e.clientX, y = e.clientY;
      if (lastMouseX && lastMouseY) {
        var dx = x - lastMouseX, dy = y - lastMouseY;
        mouseTotalDistance += Math.sqrt(dx * dx + dy * dy);
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
      try { clicksPoints.push({ x: Math.round(e.clientX), y: Math.round(e.clientY), t: now() }); if (clicksPoints.length > 20) clicksPoints.shift(); } catch (err) {}
      markActivity();
    }, { passive: true });

    document.addEventListener('scroll', function () {
      counters.scrolls++;
      if (firstScrollTime === null) firstScrollTime = Date.now();
      markActivity();
      if (now() <= 30000) { first30s.scrolls_30s++; first30s.has_interaction_30s = true; }
      var t = Date.now(); var y = window.pageYOffset || 0;
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
              if (velocity > 0) { scrollVelocities.push(velocity); if (scrollVelocities.length > 50) scrollVelocities.shift(); }
            }
          } catch (err) {}
          lastScrollTime = t;
        }
      }
      lastScrollY = y;
    }, { passive: true });

    document.addEventListener('wheel', function () { counters.wheel++; markActivity(); }, { passive: true });
    document.addEventListener('touchstart', function () { counters.touchstart++; if (firstInteractionTime === null) firstInteractionTime = Date.now(); markActivity(); if (now() <= 30000) first30s.has_interaction_30s = true; }, { passive: true });

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
    }, { passive: true });

    window.addEventListener('blur', function () { markActivity(); });
    document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') finalize('hidden'); });
    window.addEventListener('pagehide', function () { finalize('pagehide'); });
    window.addEventListener('beforeunload', function () { finalize('beforeunload'); });
    setInterval(checkIdle, 5000);
  }

  // =========================================================
  // BUILD PAYLOADS
  // =========================================================
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
      events: { mousemove: counters.mousemove, touchstart: counters.touchstart, clicks: counters.clicks, scrolls: counters.scrolls, keydown: counters.keydown },
      mouse_points: mousePoints.slice(-100),
      behavior_scores: {
        mouse: analyzeMouseBehavior(),
        keys: analyzeKeyBehavior(),
        scroll: analyzeScrollBehavior(),
        interaction: analyzeInteractionBehavior()
      }
    };
  }

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
      return { renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown'), vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown') };
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
      window.speechSynthesis.onvoiceschanged = function () { _speechVoices = window.speechSynthesis.getVoices().length; };
      _speechVoices = v ? v.length : 0;
    } catch (e) { _speechVoices = -1; }
  }

  function getUABrands() {
    try {
      if (navigator.userAgentData && navigator.userAgentData.brands) {
        return navigator.userAgentData.brands.map(function (b) { return { brand: String(b.brand || ''), version: String(b.version || '') }; });
      }
    } catch (e) {}
    return [];
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
        nav.ua_data = { mobile: navigator.userAgentData.mobile === true, platform: String(navigator.userAgentData.platform || '') };
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
    var connection = { rtt: -1, downlink: -1, effective_type: 'Unknown' };
    try {
      var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (c) connection = { rtt: typeof c.rtt === 'number' ? c.rtt : -1, downlink: typeof c.downlink === 'number' ? c.downlink : -1, effective_type: String(c.effectiveType || 'Unknown') };
    } catch (e) {}

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
      intl_locale: (function () { try { return Intl.DateTimeFormat().resolvedOptions().locale || 'Unknown'; } catch (e) { return 'Unknown'; } })(),
      connection: connection,
      // 🎯 NEW: All 46 detection results
      detections: runAllDetections(),
      // 🎯 NEW: Stack trace trap results
      trap_triggers: trapTriggers,
      // 🎯 NEW: Honeypot trigger
      honeypot_triggered: honeypotTriggered
    };
  }

  function buildScreen() {
    return { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, pixelRatio: window.devicePixelRatio || 1, innerWidth: window.innerWidth || 0, innerHeight: window.innerHeight || 0 };
  }

  // =========================================================
  // NETWORK CALLS
  // =========================================================
  function doHandshake() {
    if (handshakeDone) return;
    handshakeDone = true;
    var body = {
      v: 3, session_id: sessionId, click_id: clickId,
      campaign_key: CAMPAIGN_KEY, url: location.href, t_ms: Math.round(now()),
      nav: buildNav(), fp: buildFingerprint(), consent_state: 'unknown',
      tracking_params: trackingParams
    };
    safeSend(ENDPOINT + '/api/collect/handshake', body, false).then(function (r) {
      if (r && r.data && r.data.hide) { document.body.innerHTML = ''; window.location.replace('/404'); return; }
      startHeartbeatTimer();
    }).catch(function () { setTimeout(function () { handshakeDone = false; doHandshake(); }, 3000); });
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
  function startHeartbeatTimer() { if (heartbeatTimer) return; scheduleNextHeartbeat(); }
  function scheduleNextHeartbeat() {
    if (finalSent) return;
    var jitter = (Math.random() - 0.5) * 2 * HEARTBEAT_JITTER_MS;
    heartbeatTimer = setTimeout(function () { sendHeartbeat(); scheduleNextHeartbeat(); }, HEARTBEAT_INTERVAL_MS + jitter);
  }

  function finalize(reason) {
    if (finalSent) return;
    finalSent = true;
    if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
    if (finalTimeoutTimer) { clearTimeout(finalTimeoutTimer); finalTimeoutTimer = null; }
    if (adObserver) { try { adObserver.disconnect(); } catch (e) {} }

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
    try {
      sent = navigator.sendBeacon(ENDPOINT + '/api/collect/final', new Blob([bodyStr], { type: 'text/plain;charset=UTF-8' }));
    } catch (e) {}
    if (!sent) {
      try {
        fetch(ENDPOINT + '/api/collect/final', { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: bodyStr, keepalive: true, credentials: 'omit' }).catch(function () {});
      } catch (e) {}
    }
  }

  // =========================================================
  // BOOT
  // =========================================================
  function boot() {
    try {
      sessionId = uuid();
      clickId = uuid();
      initSpeechVoices();
      setupTraps();
      setupListeners();
      setupAdObserver();
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