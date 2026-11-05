"""
tracker_v3_template.py — Collector v3 JS Template (Phase 1.2)

Heartbeat-based multi-send collector.

Placeholders:
  __OVG_SITE_KEY__      → site_key (legacy)
  __OVG_CAMPAIGN_KEY__  → campaign_key (v3 — الـ preferred)
  __OVG_ENDPOINT_BASE__ → base URL (e.g. https://ovg-tracker.de1.netrun.io)
"""

TRACKER_V3_JS = r"""(function () {
  'use strict';

  /* ============================================================
   * OVG Tracker v3 — Collector
   * Multi-send: handshake + heartbeats + final beacon
   * ============================================================ */

  // ============ CONFIG ============
  var SITE_KEY      = '__OVG_SITE_KEY__';
  var CAMPAIGN_KEY  = '__OVG_CAMPAIGN_KEY__';
  var ENDPOINT      = '__OVG_ENDPOINT_BASE__';

  var HANDSHAKE_DELAY_MS    = 500;
  var HEARTBEAT_INTERVAL_MS = 10000;
  var HEARTBEAT_JITTER_MS   = 2000;
  var BATCH_INTERVAL_MS     = 15000;
  var FIRST_30S_WINDOW_MS   = 30000;
  var IDLE_THRESHOLD_MS     = 30000;
  var MAX_QUEUE_SIZE        = 30;
  var FINAL_TIMEOUT_MS      = 30 * 60 * 1000; // 30 دقيقة

  // ============ STATE ============
  var startTime = Date.now();
  var sessionId = null;
  var serverTimeOffset = 0;
  var seq = 0;
  var handshakeDone = false;
  var finalSent = false;
  var heartbeatTimer = null;
  var batchTimer = null;
  var finalTimeoutTimer = null;

  var consentState = 'unknown';
  try {
    if (typeof window.__consent_state === 'string') {
      consentState = window.__consent_state;
    }
  } catch (e) {}

  // ============ COUNTERS ============
  var counters = {
    mousemove: 0, clicks: 0, scrolls: 0, touchstart: 0,
    keydown: 0, backspace: 0, wheel: 0, copy: 0, selection: 0,
    dblclick: 0, rightclick: 0, focus: 0, blur: 0
  };

  // ============ MOUSE ============
  var mousePoints = [];
  var firstMoveTime = null;
  var mouseDirectionChanges = 0;
  var mousePauses = 0;
  var lastMouseTime = 0;
  var lastMouseDir = 0;
  var mouseTotalDistance = 0;
  var lastMouseX = 0, lastMouseY = 0;

  // ============ SCROLL ============
  var firstScrollTime = null;
  var scrollMaxDepthPct = 0;
  var scrollDirectionChanges = 0;
  var lastScrollY = 0;
  var lastScrollDir = 0;
  var scrollPauses = 0;
  var lastScrollTime = 0;
  var wheelDeltaTotal = 0;
  var scrollVelocitySamples = [];

  // ============ KEYBOARD ============
  var firstKeyTime = null;
  var lastKeyTime = 0;
  var typingBursts = 0;
  var formInputs = 0;

  // ============ CLICKS ============
  var clickPoints = [];
  var firstClickTime = null;
  var clicksBeforeMove = 0;
  var clicksOnLinks = 0;
  var clicksOnButtons = 0;

  // ============ FOCUS ============
  var firstBlurTime = null;
  var totalUnfocusedTime = 0;
  var unfocusedSince = null;
  var tabSwitches = 0;

  // ============ IDLE ============
  var lastActivityTime = Date.now();
  var idlePeriods = [];
  var currentIdleStart = null;

  // ============ FIRST INTERACTION ============
  var firstInteractionTime = null;

  // ============ MILESTONES ============
  var milestones = {
    t_first_paint: null,
    t_first_content_viewable: null,
    t_first_ad_loaded: null,
    t_first_ad_visible_50: null,
    t_first_interaction: null,
    t_first_scroll: null,
    t_first_click: null,
    t_first_keydown: null,
    t_last_activity: null,
    t_departure: null
  };

  // ============ FIRST 30s SNAPSHOT ============
  var first30sSnapshot = null;
  var first30sCaptured = false;

  // ============ AD EVENTS ============
  var adEvents = [];
  var trackedAdElements = [];
  var adObserver = null;
  var adVisibilityStart = {}; // elId -> {t, pct}
  var adFired50_1s = {};

  // ============ HONEYPOT ============
  var honeypotTriggered = false;

  // ============ SEND QUEUE ============
  var sendQueue = [];
  var QUEUE_KEY = 'ovg_q_v3';

  /* ============================================================
   * UTILITIES
   * ============================================================ */
  function now() { return Date.now() - startTime; }

  function variance(arr) {
    if (!arr || arr.length < 2) return 0;
    var m = 0, i;
    for (i = 0; i < arr.length; i++) m += arr[i];
    m = m / arr.length;
    var s = 0;
    for (i = 0; i < arr.length; i++) { var d = arr[i] - m; s += d * d; }
    return s / arr.length;
  }

  function median(arr) {
    if (!arr || !arr.length) return 0;
    var s = arr.slice().sort(function (a, b) { return a - b; });
    var mid = Math.floor(s.length / 2);
    return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
  }

  function uuid() {
    try {
      if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
    } catch (e) {}
    // Fallback
    var d = Date.now().toString(16);
    var r = '';
    for (var i = 0; i < 24; i++) {
      if (i === 8 || i === 12 || i === 16 || i === 20) r += '-';
      r += Math.floor(Math.random() * 16).toString(16);
    }
    return d.substring(0, 8) + '-' + r.substring(0, 27);
  }

  function safeSend(url, body, useBeacon) {
    var bodyStr;
    try { bodyStr = JSON.stringify(body); } catch (e) { return Promise.reject(e); }

    if (useBeacon && navigator.sendBeacon) {
      try {
        var blob = new Blob([bodyStr], { type: 'application/json' });
        var ok = navigator.sendBeacon(url, blob);
        if (ok) return Promise.resolve({ ok: true, via: 'beacon' });
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
          return { ok: r.ok, status: r.status, data: d, via: 'fetch' };
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }

  function enqueue(url, body) {
    try {
      var q = JSON.parse(localStorage.getItem(QUEUE_KEY) || '[]');
      q.push({ url: url, body: body, ts: Date.now() });
      while (q.length > MAX_QUEUE_SIZE) q.shift();
      localStorage.setItem(QUEUE_KEY, JSON.stringify(q));
    } catch (e) {}
  }

  function flushQueue() {
    var q;
    try { q = JSON.parse(localStorage.getItem(QUEUE_KEY) || '[]'); }
    catch (e) { return; }
    if (!q.length) return;

    try { localStorage.removeItem(QUEUE_KEY); } catch (e) {}

    q.forEach(function (item, idx) {
      var delay = Math.min(30000, Math.pow(2, idx) * 1000);
      setTimeout(function () {
        safeSend(item.url, item.body, false).catch(function () {});
      }, delay);
    });
  }

  function markActivity() {
    lastActivityTime = Date.now();
    if (currentIdleStart !== null) {
      // خلص idle period
      var dur = Date.now() - currentIdleStart;
      if (dur >= IDLE_THRESHOLD_MS) {
        idlePeriods.push({ start: currentIdleStart - startTime, end: Date.now() - startTime, dur: dur });
      }
      currentIdleStart = null;
    }
    milestones.t_last_activity = now();
  }

  function checkIdle() {
    var gap = Date.now() - lastActivityTime;
    if (gap >= IDLE_THRESHOLD_MS && currentIdleStart === null) {
      currentIdleStart = lastActivityTime + 1000;
    }
  }

  /* ============================================================
   * HONEYPOT INJECTION
   * ============================================================ */
  function injectHoneypots() {
    try {
      var container = document.createElement('div');
      container.style.cssText = 'position:absolute;left:-9999px;top:-9999px;opacity:0.01;pointer-events:auto;';
      container.setAttribute('aria-hidden', 'true');

      // 1) لينك مخفي
      var a = document.createElement('a');
      a.href = '#hp-' + Math.random().toString(36).substring(7);
      a.textContent = 'info';
      a.addEventListener('click', function (e) {
        e.preventDefault();
        honeypotTriggered = true;
        track('HONEYPOT_CLICK', { type: 'link' });
      });
      container.appendChild(a);

      // 2) input مخفي
      var form = document.createElement('form');
      form.style.cssText = 'display:block;';
      var input = document.createElement('input');
      input.type = 'text';
      input.name = 'email';
      input.tabIndex = -1;
      input.autocomplete = 'off';
      input.addEventListener('input', function () {
        honeypotTriggered = true;
        track('HONEYPOT_FORM_FILL', { length: this.value.length });
      });
      form.appendChild(input);
      container.appendChild(form);

      // 3) زرار مخفي
      var btn = document.createElement('button');
      btn.textContent = 'Submit';
      btn.tabIndex = -1;
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        honeypotTriggered = true;
        track('HONEYPOT_CLICK', { type: 'button' });
      });
      container.appendChild(btn);

      if (document.body) {
        document.body.appendChild(container);
      } else {
        document.addEventListener('DOMContentLoaded', function () {
          document.body.appendChild(container);
        });
      }
    } catch (e) {}
  }

  /* ============================================================
   * AD TRACKING
   * ============================================================ */
  var AD_SELECTORS = [
    'iframe[src*="adsterra"]',
    'iframe[src*="monetag"]',
    'iframe[src*="kdm"]',
    '[data-ovg-ad]',
    'ins.adsbygoogle',
    'div[class*="adsterra"]',
    'div[class*="monetag"]'
  ];

  function looksLikeAd(el) {
    if (!el || el.nodeType !== 1) return false;
    var tag = el.tagName.toLowerCase();
    if (tag !== 'iframe' && tag !== 'ins' && tag !== 'div' && tag !== 'script') return false;

    for (var i = 0; i < AD_SELECTORS.length; i++) {
      try {
        if (el.matches && el.matches(AD_SELECTORS[i])) return true;
      } catch (e) {}
    }
    if (el.hasAttribute && el.hasAttribute('data-ovg-ad')) return true;

    // حجم كبير + iframe = محتمل إعلان
    if (tag === 'iframe') {
      var w = el.offsetWidth || parseInt(el.getAttribute('width') || 0);
      var h = el.offsetHeight || parseInt(el.getAttribute('height') || 0);
      if (w >= 200 && h >= 100) return true;
    }
    return false;
  }

  function trackAdElement(el) {
    if (!el || trackedAdElements.indexOf(el) !== -1) return;
    trackedAdElements.push(el);

    var adId = 'ad_' + trackedAdElements.length;

    milestones.t_first_ad_loaded = milestones.t_first_ad_loaded || now();

    // IntersectionObserver
    if (!adObserver) return;

    try {
      adObserver.observe(el);
      el._ovg_adId = adId;
    } catch (e) {}

    adEvents.push({
      event: 'ad_script_loaded',
      zone_id: '',
      t_ms: now(),
      ad_id: adId
    });
  }

  function setupAdObserver() {
    if (typeof IntersectionObserver === 'undefined') return;

    adObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var el = entry.target;
        var adId = el._ovg_adId || 'unknown';
        var pct = Math.round(entry.intersectionRatio * 100);

        if (entry.isIntersecting && pct >= 50) {
          if (!adVisibilityStart[adId]) {
            adVisibilityStart[adId] = { t: now(), pct: pct };
            milestones.t_first_ad_visible_50 = milestones.t_first_ad_visible_50 || now();

            adEvents.push({
              event: 'ad_viewable_50pct_start',
              zone_id: '',
              t_ms: now(),
              viewport_pct: pct,
              ad_id: adId
            });

            // بعد 1 ثانية متصلة → billable
            setTimeout(function () {
              if (adFired50_1s[adId]) return;
              var still = adVisibilityStart[adId];
              if (!still) return;
              adFired50_1s[adId] = true;
              adEvents.push({
                event: 'ad_viewable_50pct_1s',
                zone_id: '',
                t_ms: now(),
                viewport_pct: pct,
                duration_ms: now() - still.t,
                ad_id: adId
              });
            }, 1000);
          }
        } else {
          if (adVisibilityStart[adId]) {
            var start = adVisibilityStart[adId];
            adEvents.push({
              event: 'ad_viewable_end',
              zone_id: '',
              t_ms: now(),
              viewport_pct: pct,
              duration_ms: now() - start.t,
              ad_id: adId
            });
            delete adVisibilityStart[adId];
          }
        }
      });
    }, { threshold: [0, 0.25, 0.5, 0.75, 1.0] });

    // امسح العناصر الموجودة
    for (var i = 0; i < AD_SELECTORS.length; i++) {
      try {
        var els = document.querySelectorAll(AD_SELECTORS[i]);
        for (var j = 0; j < els.length; j++) {
          if (looksLikeAd(els[j])) trackAdElement(els[j]);
        }
      } catch (e) {}
    }

    // راقب أي إضافة جديدة
    if (typeof MutationObserver !== 'undefined') {
      var mo = new MutationObserver(function (muts) {
        muts.forEach(function (m) {
          for (var k = 0; k < m.addedNodes.length; k++) {
            var n = m.addedNodes[k];
            if (n.nodeType !== 1) continue;
            if (looksLikeAd(n)) trackAdElement(n);
            try {
              var inner = n.querySelectorAll ? n.querySelectorAll('iframe, ins, div[data-ovg-ad]') : [];
              for (var x = 0; x < inner.length; x++) {
                if (looksLikeAd(inner[x])) trackAdElement(inner[x]);
              }
            } catch (e) {}
          }
        });
      });
      try { mo.observe(document.documentElement, { childList: true, subtree: true }); } catch (e) {}
    }
  }

  /* ============================================================
   * MILESTONES (paint + LCP)
   * ============================================================ */
  function capturePaint() {
    try {
      var entries = performance.getEntriesByType('paint');
      entries.forEach(function (e) {
        if (e.name === 'first-paint') milestones.t_first_paint = Math.round(e.startTime);
        if (e.name === 'first-contentful-paint') milestones.t_first_content_viewable = Math.round(e.startTime);
      });
    } catch (e) {}

    if (typeof PerformanceObserver !== 'undefined') {
      try {
        var po = new PerformanceObserver(function (list) {
          var entries = list.getEntries();
          if (entries.length) {
            var lcp = entries[entries.length - 1];
            milestones.t_first_content_viewable = milestones.t_first_content_viewable || Math.round(lcp.startTime);
          }
        });
        po.observe({ type: 'largest-contentful-paint', buffered: true });
      } catch (e) {}
    }
  }

  /* ============================================================
   * FIRST 30s SNAPSHOT
   * ============================================================ */
  function captureFirst30s() {
    if (first30sCaptured) return;
    first30sCaptured = true;

    var maxScroll = 0;
    try {
      var docH = Math.max(document.documentElement.scrollHeight - window.innerHeight, 1);
      maxScroll = Math.min(1, (window.pageYOffset || 0) / docH);
    } catch (e) {}

    first30sSnapshot = {
      clicks_30s: counters.clicks,
      scrolls_30s: counters.scrolls,
      mousemoves_30s: counters.mousemove,
      keydowns_30s: counters.keydown,
      max_scroll_pct_30s: Math.round(maxScroll * 100),
      has_interaction_30s: (counters.clicks + counters.scrolls + counters.keydown) > 0,
      time_to_first_interaction_ms: firstInteractionTime ? Math.round(firstInteractionTime - startTime) : -1
    };
  }

  /* ============================================================
   * EVENT LISTENERS
   * ============================================================ */
  function setupListeners() {
    // MOUSE
    document.addEventListener('mousemove', function (e) {
      counters.mousemove++;
      if (firstMoveTime === null) firstMoveTime = Date.now();
      if (firstInteractionTime === null) {
        firstInteractionTime = Date.now();
        milestones.t_first_interaction = milestones.t_first_interaction || now();
      }
      markActivity();

      var t = Date.now();
      var x = e.clientX, y = e.clientY;

      if (lastMouseX && lastMouseY) {
        var dx = x - lastMouseX, dy = y - lastMouseY;
        mouseTotalDistance += Math.sqrt(dx * dx + dy * dy);

        var dir = Math.atan2(dy, dx);
        if (lastMouseDir && Math.abs(dir - lastMouseDir) > 0.5) {
          mouseDirectionChanges++;
        }
        lastMouseDir = dir;

        if (lastMouseTime && (t - lastMouseTime) > 500) {
          mousePauses++;
        }
        lastMouseTime = t;
      }
      lastMouseX = x; lastMouseY = y;

      mousePoints.push({ x: x, y: y, t: t });
      if (mousePoints.length > 200) mousePoints.shift();
    }, { passive: true });

    // CLICKS
    document.addEventListener('click', function (e) {
      counters.clicks++;
      if (firstClickTime === null) firstClickTime = Date.now();
      if (firstMoveTime === null) clicksBeforeMove++;
      if (firstInteractionTime === null) {
        firstInteractionTime = Date.now();
        milestones.t_first_interaction = milestones.t_first_interaction || now();
      }
      milestones.t_first_click = milestones.t_first_click || now();
      markActivity();

      var target = e.target;
      if (target) {
        var tag = (target.tagName || '').toLowerCase();
        if (tag === 'a') clicksOnLinks++;
        if (tag === 'button' || (tag === 'input' && target.type === 'submit')) clicksOnButtons++;
      }

      clickPoints.push({ x: e.clientX, y: e.clientY, t: Date.now() });
      if (clickPoints.length > 20) clickPoints.shift();
    }, { passive: true });

    document.addEventListener('dblclick', function () { counters.dblclick++; }, { passive: true });
    document.addEventListener('contextmenu', function () { counters.rightclick++; }, { passive: true });

    // SCROLL
    var scrollHandler = function () {
      counters.scrolls++;
      if (firstScrollTime === null) firstScrollTime = Date.now();
      milestones.t_first_scroll = milestones.t_first_scroll || now();
      markActivity();

      var t = Date.now();
      var y = window.pageYOffset || document.documentElement.scrollTop || 0;

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

          if (lastScrollTime) {
            var dt = (t - lastScrollTime) / 1000;
            if (dt > 0 && dt < 2) {
              scrollVelocitySamples.push(Math.abs(dy) / dt);
              if (scrollVelocitySamples.length > 50) scrollVelocitySamples.shift();
            }
          }
          lastScrollTime = t;
        }
      }
      lastScrollY = y;
    };
    document.addEventListener('scroll', scrollHandler, { passive: true });

    // WHEEL
    document.addEventListener('wheel', function (e) {
      counters.wheel++;
      wheelDeltaTotal += Math.abs(e.deltaY || 0);
    }, { passive: true });

    // TOUCH
    document.addEventListener('touchstart', function () {
      counters.touchstart++;
      if (firstInteractionTime === null) {
        firstInteractionTime = Date.now();
        milestones.t_first_interaction = milestones.t_first_interaction || now();
      }
      markActivity();
    }, { passive: true });

    // KEYBOARD
    document.addEventListener('keydown', function (e) {
      counters.keydown++;
      if (firstKeyTime === null) firstKeyTime = Date.now();
      milestones.t_first_keydown = milestones.t_first_keydown || now();
      if (firstInteractionTime === null) {
        firstInteractionTime = Date.now();
        milestones.t_first_interaction = milestones.t_first_interaction || now();
      }
      markActivity();

      if (e.key === 'Backspace' || e.keyCode === 8) counters.backspace++;

      var t = Date.now();
      if (lastKeyTime && (t - lastKeyTime) < 1000) {
        // في وسط typing burst
      } else if (lastKeyTime) {
        typingBursts++;
      }
      lastKeyTime = t;
    }, { passive: true });

    // COPY / SELECTION
    document.addEventListener('copy', function () { counters.copy++; }, { passive: true });
    document.addEventListener('selectionchange', function () { counters.selection++; }, { passive: true });

    // FORM INPUTS
    document.addEventListener('input', function (e) {
      var t = e.target;
      if (!t) return;
      var tag = (t.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') {
        formInputs++;
      }
    }, { passive: true });

    // FOCUS / BLUR
    window.addEventListener('focus', function () {
      counters.focus++;
      if (unfocusedSince !== null) {
        totalUnfocusedTime += Date.now() - unfocusedSince;
        unfocusedSince = null;
      }
    });
    window.addEventListener('blur', function () {
      counters.blur++;
      if (firstBlurTime === null) firstBlurTime = Date.now();
      unfocusedSince = Date.now();
      tabSwitches++;
    });

    // VISIBILITY
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') {
        finalize('hidden');
      }
    });
    window.addEventListener('pagehide', function () { finalize('pagehide'); });
    window.addEventListener('beforeunload', function () { finalize('unload'); });

    // IDLE CHECK
    setInterval(checkIdle, 5000);
  }

  /* ============================================================
   * BUILD BEHAVIORAL SNAPSHOT
   * ============================================================ */
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

    var scrollVelMedian = scrollVelocitySamples.length ? Math.round(median(scrollVelocitySamples)) : 0;

    var scrollPattern = 'none';
    if (counters.scrolls > 0) {
      if (scrollDirectionChanges === 0 && scrollPauses === 0) scrollPattern = 'linear';
      else if (scrollDirectionChanges <= 2 && scrollPauses <= 2) scrollPattern = 'organic';
      else scrollPattern = 'erratic';
    }

    var unfocusedTotal = totalUnfocusedTime;
    if (unfocusedSince !== null) unfocusedTotal += Date.now() - unfocusedSince;

    return {
      // Mouse
      mouse_distance_total: Math.round(mouseTotalDistance),
      mouse_velocity_median: mouseVelocities.length ? Math.round(median(mouseVelocities)) : 0,
      mouse_velocity_variance: mouseVelocities.length ? Math.round(variance(mouseVelocities) * 100) / 100 : 0,
      mouse_direction_changes: mouseDirectionChanges,
      mouse_pauses: mousePauses,
      first_move_delay_ms: firstMoveTime ? firstMoveTime - startTime : -1,
      mouse_points: mousePoints.slice(-50),

      // Scroll
      scroll_depth_pct: scrollMaxDepthPct,
      scroll_velocity_median: scrollVelMedian,
      scroll_pattern: scrollPattern,
      scroll_direction_changes: scrollDirectionChanges,
      scroll_pauses: scrollPauses,
      first_scroll_delay_ms: firstScrollTime ? firstScrollTime - startTime : -1,
      wheel_events: counters.wheel,
      wheel_delta_total: Math.round(wheelDeltaTotal),

      // Keyboard
      keydown_count: counters.keydown,
      backspace_count: counters.backspace,
      typing_bursts: typingBursts,
      form_inputs: formInputs,

      // Interaction
      clicks: counters.clicks,
      dblclicks: counters.dblclick,
      rightclicks: counters.rightclick,
      clicks_on_links: clicksOnLinks,
      clicks_on_buttons: clicksOnButtons,
      clicks_before_move: clicksBeforeMove,
      clicks_points: clickPoints.slice(-20),
      touch_events: counters.touchstart,
      copy_events: counters.copy,
      selection_events: counters.selection,

      // Focus
      tab_switches: tabSwitches,
      blur_count: counters.blur,
      focus_count: counters.focus,
      total_unfocused_ms: Math.round(unfocusedTotal),
      first_blur_delay_ms: firstBlurTime ? firstBlurTime - startTime : -1,

      // Time
      total_time_ms: Math.round(now()),
      visible_time_ms: Math.round(totalVisible),
      focused_time_ms: Math.round(totalVisible - unfocusedTotal),

      // Idle
      idle_periods_count: idlePeriods.length,
      longest_idle_ms: idlePeriods.length ? Math.max.apply(null, idlePeriods.map(function(p){return p.dur;})) : 0,

      // Events summary (للـ backward compat)
      events: {
        mousemove: counters.mousemove,
        touchstart: counters.touchstart,
        clicks: counters.clicks,
        scrolls: counters.scrolls,
        keydown: counters.keydown
      }
    };
  }

  /* ============================================================
   * COLLECT NAV + FP
   * ============================================================ */
  function getCanvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 220; c.height = 40;
      var ctx = c.getContext('2d');
      if (!ctx) return 'blocked';
      ctx.textBaseline = 'top'; ctx.font = '15px Arial';
      ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
      ctx.fillStyle = '#069'; ctx.fillText('OVG-v3', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('OVG-v3', 4, 17);
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

  function getAutomation() {
    var out = { puppeteer: false, playwright: false, selenium: false, nightmare: false, phantom: false, cdc: false };
    try {
      if (window.__puppeteer_evaluation_script__ !== undefined) out.puppeteer = true;
      if (window.__playwright__ !== undefined || window.__playwright_evaluation_script__ !== undefined) out.playwright = true;
      if (window.__nightmare !== undefined) out.nightmare = true;
      if (window.callPhantom !== undefined || window._phantom !== undefined) out.phantom = true;
      var keys = Object.keys(window);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k.indexOf('$cdc_') === 0 || k.indexOf('cdc_') === 0 || k.indexOf('$wdc_') === 0) { out.cdc = true; out.selenium = true; break; }
        if (k === '_Selenium_IDE_Recorder' || k === '_selenium' || k === 'calledSelenium') { out.selenium = true; break; }
      }
    } catch (e) {}
    return out;
  }

  function getCDP() {
    try {
      var detected = false;
      var err = new Error();
      Object.defineProperty(err, 'stack', { get: function () { detected = true; return ''; } });
      // eslint-disable-next-line no-console
      if (typeof console !== 'undefined') console.debug(err);
      return detected;
    } catch (e) { return false; }
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
    try {
      var l = navigator.languages;
      if (l) for (var i = 0; i < l.length && i < 5; i++) langs.push(String(l[i]));
    } catch (e) {}

    var tz = 'Unknown';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Unknown'; } catch (e) {}

    var intlLocale = '';
    try { intlLocale = Intl.DateTimeFormat().resolvedOptions().locale || ''; } catch (e) {}

    var mimeCount = -1;
    try { mimeCount = navigator.mimeTypes ? navigator.mimeTypes.length : -1; } catch (e) {}

    var pdfViewer = null;
    try { pdfViewer = navigator.pdfViewerEnabled === true; } catch (e) {}

    var chromeCheck = 'error';
    try {
      if (typeof window.chrome === 'undefined') chromeCheck = 'no_window_chrome';
      else if (typeof window.chrome.runtime === 'undefined') chromeCheck = 'window_chrome_no_runtime';
      else chromeCheck = 'full';
    } catch (e) {}

    return {
      timezone: tz,
      canvas_hash: getCanvasHash(),
      hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
      deviceMemory: Number(navigator.deviceMemory) || 0,
      webgl: getWebGL(),
      plugins: { count: pluginsCount },
      languages: langs,
      chrome_check: chromeCheck,
      cdp_detected: getCDP(),
      automation: getAutomation(),
      intl_locale: intlLocale,
      mime_types_count: mimeCount,
      pdf_viewer: pdfViewer
    };
  }

  function buildScreen() {
    return {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio || 1,
      innerWidth: window.innerWidth || 0,
      innerHeight: window.innerHeight || 0,
      orientation: (screen.orientation && String(screen.orientation.type || '')) || ''
    };
  }

  /* ============================================================
   * SEND: HANDSHAKE
   * ============================================================ */
  function doHandshake() {
    if (handshakeDone) return;
    handshakeDone = true;

    var body = {
      v: 3,
      session_id: sessionId,
      site_key: SITE_KEY || '',
      campaign_key: CAMPAIGN_KEY || SITE_KEY || '',
      url: location.href,
      t_ms: Math.round(now()),
      nav: buildNav(),
      fp: buildFingerprint(),
      consent_state: consentState
    };

    safeSend(ENDPOINT + '/api/collect/handshake', body, false).then(function (r) {
      if (r && r.ok && r.data && r.data.server_time) {
        serverTimeOffset = r.data.server_time - Date.now();
      }
      startHeartbeatTimer();
      startBatchTimer();
    }).catch(function () {
      // لو فشل، نحاول تاني بعد 3 ثواني
      setTimeout(function () {
        handshakeDone = false;
        doHandshake();
      }, 3000);
    });
  }

  /* ============================================================
   * SEND: HEARTBEAT
   * ============================================================ */
  function sendHeartbeat() {
    if (finalSent) return;
    seq++;

    var body = {
      v: 3,
      session_id: sessionId,
      seq: seq,
      t_ms: Math.round(now()),
      clicks: counters.clicks,
      scrolls: counters.scrolls,
      mousemoves: counters.mousemove,
      keydowns: counters.keydown,
      is_visible: document.visibilityState === 'visible',
      is_focused: document.hasFocus()
    };

    safeSend(ENDPOINT + '/api/collect/heartbeat', body, false).catch(function () {});
  }

  function startHeartbeatTimer() {
    if (heartbeatTimer) return;
    scheduleNextHeartbeat();
  }

  function scheduleNextHeartbeat() {
    if (finalSent) return;
    var jitter = (Math.random() - 0.5) * 2 * HEARTBEAT_JITTER_MS;
    var wait = HEARTBEAT_INTERVAL_MS + jitter;
    heartbeatTimer = setTimeout(function () {
      sendHeartbeat();
      scheduleNextHeartbeat();
    }, wait);
  }

  /* ============================================================
   * SEND: BATCH (interaction digest)
   * ============================================================ */
  function sendBatch() {
    if (finalSent) return;
    // batch = lightweight — مش محتاجينه دايماً، بس بيدي frequency info
    var body = {
      v: 3,
      session_id: sessionId,
      seq: seq + 10000, // رقم مميز
      t_ms: Math.round(now()),
      clicks: counters.clicks,
      scrolls: counters.scrolls,
      mousemoves: counters.mousemove,
      keydowns: counters.keydown,
      is_visible: document.visibilityState === 'visible',
      is_focused: document.hasFocus()
    };
    safeSend(ENDPOINT + '/api/collect/heartbeat', body, false).catch(function () {});
  }

  function startBatchTimer() {
    if (batchTimer) return;
    batchTimer = setInterval(sendBatch, BATCH_INTERVAL_MS);
  }

  /* ============================================================
   * FINAL
   * ============================================================ */
  function finalize(reason) {
    if (finalSent) return;
    finalSent = true;

    if (heartbeatTimer) { clearTimeout(heartbeatTimer); heartbeatTimer = null; }
    if (batchTimer) { clearInterval(batchTimer); batchTimer = null; }
    if (finalTimeoutTimer) { clearTimeout(finalTimeoutTimer); finalTimeoutTimer = null; }

    milestones.t_departure = now();

    // Snapshot أول 30 ثانية (لو لسه)
    captureFirst30s();

    var behavior = buildBehavioral();

    var body = {
      v: 3,
      session_id: sessionId,
      seq: 999,
      t_ms: Math.round(now()),
      site_key: SITE_KEY || '',
      campaign_key: CAMPAIGN_KEY || SITE_KEY || '',
      url: location.href,
      webrtc_ip: 'None', // مش بنجمع WebRTC في v3 (بيبطأ)
      nav: buildNav(),
      fingerprint: buildFingerprint(),
      behavior: behavior,
      screen: buildScreen(),
      milestones: milestones,
      first_30s: first30sSnapshot || {},
      ad_events: adEvents,
      honeypot_triggered: honeypotTriggered,
      clock_drift_ms: serverTimeOffset,
      consent_state: consentState,
      data_quality: reason === 'timeout' ? 'partial' : 'full'
    };

    var ok = false;
    try {
      ok = navigator.sendBeacon(ENDPOINT + '/api/collect/final',
        new Blob([JSON.stringify(body)], { type: 'application/json' }));
    } catch (e) {}

    if (!ok) {
      safeSend(ENDPOINT + '/api/collect/final', body, true).catch(function () {
        enqueue(ENDPOINT + '/api/collect/final', body);
      });
    }
  }

  /* ============================================================
   * TRACK (mini — للـ honeypot)
   * ============================================================ */
  function track(code, detail) {
    try {
      safeSend(ENDPOINT + '/api/collect/heartbeat', {
        v: 3,
        session_id: sessionId,
        seq: ++seq,
        t_ms: Math.round(now()),
        clicks: counters.clicks,
        scrolls: counters.scrolls,
        mousemoves: counters.mousemove,
        keydowns: counters.keydown,
        is_visible: true,
        is_focused: true
      }, false);
    } catch (e) {}
  }

  /* ============================================================
   * BOOT
   * ============================================================ */
  function boot() {
    try {
      sessionId = uuid();
      flushQueue(); // حاول تبعت أي حاجة قديمة
      capturePaint();
      setupListeners();

      // Honeypots + Ads بعد DOM ready
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
          injectHoneypots();
          setupAdObserver();
        });
      } else {
        injectHoneypots();
        setupAdObserver();
      }

      // First-30s snapshot
      setTimeout(captureFirst30s, FIRST_30S_WINDOW_MS);

      // Final timeout (30 دقيقة max)
      finalTimeoutTimer = setTimeout(function () {
        finalize('timeout');
      }, FINAL_TIMEOUT_MS);

      // Handshake بعد 500ms (عشان LCP)
      var doHandshakeDelayed = function () { setTimeout(doHandshake, HANDSHAKE_DELAY_MS); };
      if ('requestIdleCallback' in window) {
        requestIdleCallback(doHandshakeDelayed, { timeout: 2000 });
      } else {
        doHandshakeDelayed();
      }
    } catch (e) {}
  }

  boot();
})();
"""
