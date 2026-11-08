"""
collector/interstitial_template.py — Fast Router + Anubis PoW (v3.0)
"""

INTERSTITIAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>Loading</title>
<style>
  html, body { margin: 0; padding: 0; background: #fff; height: 100%; overflow: hidden; }
  body {
    display: flex; justify-content: center; align-items: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  #stage { text-align: center; max-width: 420px; padding: 24px; }
  .spinner {
    width: 32px; height: 32px; margin: 0 auto 18px;
    border: 3px solid rgba(0,0,0,0.08);
    border-top-color: #333;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  #msg { font-size: 13px; color: #444; line-height: 1.5; }
  #progress-wrap {
    display: none; margin-top: 16px;
    width: 240px; height: 4px;
    background: #eee; border-radius: 3px;
    margin-left: auto; margin-right: auto;
    overflow: hidden;
  }
  #progress-bar {
    height: 100%; width: 0%;
    background: #6366f1;
    transition: width 200ms ease-out;
  }
  #progress-pct {
    display: none; margin-top: 8px;
    font-size: 11px; color: #888;
    font-family: ui-monospace, "Courier New", monospace;
  }
  #speed {
    display: none; margin-top: 6px;
    font-size: 10px; color: #aaa;
    font-family: ui-monospace, "Courier New", monospace;
  }
  #error {
    display: none; color: #b91c1c;
    font-size: 13px; line-height: 1.5;
  }
</style>
</head>
<body>
<div id="stage">
  <div class="spinner" id="spinner"></div>
  <div id="msg">Loading…</div>
  <div id="progress-wrap"><div id="progress-bar"></div></div>
  <div id="progress-pct"></div>
  <div id="speed"></div>
  <div id="error"></div>
</div>

<script>
(function () {
  "use strict";

  var CK = "__CAMPAIGN_KEY__";
  var PU = "__PRECHECK_URL__";
  var CHU = "__CHALLENGE_URL__";
  var VU = "__VERIFY_URL__";
  var DU = "__DEST_URL__";
  var SID = "";

  var $ = function (id) { return document.getElementById(id); };
  var msgEl = $("msg");
  var spinner = $("spinner");
  var progWrap = $("progress-wrap");
  var progBar = $("progress-bar");
  var progPct = $("progress-pct");
  var speedEl = $("speed");
  var errEl = $("error");

  function uuid() {
    try { if (crypto.randomUUID) return crypto.randomUUID(); } catch (e) {}
    var s = [];
    for (var i = 0; i < 32; i++) s.push((Math.random() * 16 | 0).toString(16));
    return s.slice(0, 8).join("") + "-" + s.slice(8, 12).join("") + "-" +
           s.slice(12, 16).join("") + "-" + s.slice(16, 20).join("") + "-" +
           s.slice(20).join("");
  }
  SID = uuid();

  var trackingParams = {};
  try {
    var urlParams = new URLSearchParams(window.location.search);
    urlParams.forEach(function (value, key) {
      if (value !== null && value !== "") {
        trackingParams[key] = String(value).substring(0, 500);
      }
    });
  } catch (e) {}

  function fail(reason) {
    spinner.style.display = "none";
    msgEl.style.display = "none";
    progWrap.style.display = "none";
    progPct.style.display = "none";
    speedEl.style.display = "none";
    errEl.style.display = "block";
    errEl.textContent = "Something went wrong. (" + reason + ")";
    setTimeout(function () {
      window.location.replace("/404?reason=" + encodeURIComponent(reason || "blocked"));
    }, 400);
  }

  function redirectTo(url) {
    if (!url) { fail("no_dest"); return; }
    var sep = url.indexOf("?") > -1 ? "&" : "?";
    window.location.replace(url + sep + "sub_id=" + SID);
  }

  function isNativeFn(fnStr) {
    return /\(\)\s*{\s+\[native code\]\s+}\s*$/.test(String(fnStr));
  }

  function runDetections() {
    var det = {};
    var w = window, n = navigator, d = document, s = screen;

    try { if (n.webdriver === true) det.webdriver = 1; } catch (e) {}
    try {
      var wdGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (wdGetter && wdGetter.get && !isNativeFn(wdGetter.get.toString())) det.webdriverSpoofed = 1;
    } catch (e) {}
    try { if (w.outerWidth === 0 && w.outerHeight === 0) det.windowSize = 1; } catch (e) {}
    try {
      if (n.userAgent) {
        if (/PhantomJS/i.test(n.userAgent)) det.userAgentPhantom = 1;
        if (/Headless/i.test(n.userAgent)) det.userAgentHeadless = 1;
      }
    } catch (e) {}
    try {
      var allKeys = Object.getOwnPropertyNames(w);
      for (var i = 0; i < allKeys.length; i++) {
        var k = allKeys[i];
        if (k.indexOf("cdc_") === 0 || k === "__playwright__" || k === "__puppeteer__") {
          det.cdpDetected = 1;
          break;
        }
      }
    } catch (e) {}
    try {
      var createStr = Document.prototype.createElement.toString();
      if (!isNativeFn(createStr)) det.fakeCreateElement = 1;
    } catch (e) {}
    try {
      if (!isNativeFn(Function.prototype.toString.toString())) det.toStringSpoofed = 1;
    } catch (e) {}
    try {
      if (w.chrome && typeof w.chrome === "object") {
        var chromeKeys = Object.keys(w.chrome);
        if (chromeKeys.indexOf("loadTimes") !== -1 && chromeKeys[0] !== "loadTimes") det.wrongChromeOrder = 1;
      }
    } catch (e) {}
    try {
      var isChromium3 = n.vendor && n.vendor.indexOf("Google") === 0;
      if (isChromium3 && s.orientation && s.orientation.type === "landscape-primary" && s.orientation.angle === 90) {
        if (!(w.chrome && w.chrome.runtime) && "SharedWorker" in w) det.playwrightOrientation = 1;
      }
    } catch (e) {}

    return det;
  }

  function getFingerprint() {
    var fp = {
      canvas_hash: "blocked",
      webgl: { vendor: "Unknown", renderer: "Unknown" },
      detections: runDetections()
    };

    try {
      var c = document.createElement("canvas");
      c.width = 220; c.height = 40;
      var ctx = c.getContext("2d");
      if (ctx) {
        ctx.textBaseline = "top"; ctx.font = "15px Arial";
        ctx.fillStyle = "#f60"; ctx.fillRect(120, 1, 62, 20);
        ctx.fillStyle = "#069"; ctx.fillText("OVG-v3", 2, 15);
        var data = c.toDataURL();
        var h = 5381;
        for (var i = 0; i < data.length; i++) h = ((h << 5) + h + data.charCodeAt(i)) | 0;
        fp.canvas_hash = "fp_" + Math.abs(h).toString(16);
      }
    } catch (e) {}

    try {
      var wc = document.createElement("canvas");
      var gl = wc.getContext("webgl") || wc.getContext("experimental-webgl");
      if (gl) {
        var ext = gl.getExtension("WEBGL_debug_renderer_info");
        if (ext) {
          fp.webgl = {
            vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || "Unknown"),
            renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "Unknown")
          };
        }
      }
    } catch (e) {}

    return fp;
  }

  function precheck() {
    var payload = {
      v: 3,
      session_id: SID,
      campaign_key: CK,
      t_ms: 0,
      url: window.location.href,
      nav: {
        ua: navigator.userAgent,
        platform: navigator.platform || "",
        webdriver: navigator.webdriver === true,
        language: navigator.language || "",
        has_touch: ("ontouchstart" in window),
        max_touch_points: Number(navigator.maxTouchPoints) || 0
      },
      fp: getFingerprint(),
      tracking_params: trackingParams
    };

    fetch(PU, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      keepalive: true,
      credentials: "same-origin"
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (!res) { fail("no_response"); return; }
      if (res.action === "block") { fail("blocked"); return; }
      if (res.action === "redirect") { redirectTo(res.url || DU); return; }
      if (res.action === "challenge") { startChallenge(res); return; }
      fail("unknown_action");
    }).catch(function () {
      redirectTo(DU);
    });
  }

  function startChallenge(precheckRes) {
    msgEl.innerHTML = "Verifying your browser…<br><span style=\"font-size:11px;color:#888;\">This may take a moment.</span>";
    progWrap.style.display = "block";
    progPct.style.display = "block";
    speedEl.style.display = "block";

    fetch(CHU, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: SID, campaign_key: CK }),
      keepalive: true,
      credentials: "same-origin"
    }).then(function (r) { return r.json(); }).then(function (ch) {
      if (!ch || !ch.ok) { fail("challenge_issue"); return; }
      runPoW(ch, precheckRes);
    }).catch(function () {
      fail("challenge_fetch");
    });
  }

  function runPoW(challenge, precheckRes) {
    var randomData = challenge.random_data;
    var difficulty = challenge.difficulty | 0;
    var target = new Array(difficulty + 1).join("0");
    var expectedAttempts = Math.pow(16, difficulty);
    var startedAt = performance.now();
    var lastPct = -1;
    var lastSpeedUpdate = 0;
    var startTime = performance.now();

    var workerSrc = [
      "self.onmessage = function(ev){",
      "  var d = ev.data;",
      "  var randomData = d.randomData, difficulty = d.difficulty;",
      "  var target = new Array(difficulty + 1).join('0');",
      "  var nonce = 0;",
      "  var iterations = 0;",
      "  var encoder = new TextEncoder();",
      "  function hex(buf) {",
      "    var b = new Uint8Array(buf);",
      "    var s = '';",
      "    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);",
      "    return s;",
      "  }",
      "  function step() {",
      "    var CHUNK = 500;",
      "    var processed = 0;",
      "    function loopInner() {",
      "      while (processed < CHUNK) {",
      "        (function(n){",
      "          var data = randomData + n;",
      "          crypto.subtle.digest('SHA-256', encoder.encode(data)).then(function (buf) {",
      "            var h = hex(buf);",
      "            if (h.indexOf(target) === 0) {",
      "              self.postMessage({ type: 'done', nonce: n, hash: h });",
      "            }",
      "          });",
      "        })(nonce);",
      "        nonce++;",
      "        processed++;",
      "        iterations++;",
      "      }",
      "      self.postMessage({ type: 'progress', nonce: nonce, iterations: iterations });",
      "      setTimeout(step, 0);",
      "    }",
      "    loopInner();",
      "  }",
      "  step();",
      "};"
    ].join("\n");

    var worker = null;
    try {
      var blob = new Blob([workerSrc], { type: "application/javascript" });
      worker = new Worker(URL.createObjectURL(blob));
    } catch (e) {
      fail("worker_init");
      return;
    }

    worker.onmessage = function (ev) {
      var d = ev.data || {};
      if (d.type === "progress") {
        var pct = Math.min(99, Math.floor((d.iterations / expectedAttempts) * 100));
        if (pct !== lastPct) {
          lastPct = pct;
          progBar.style.width = pct + "%";
          progPct.textContent = pct + "% · nonce=" + d.nonce;
        }
        var now = performance.now();
        if (now - lastSpeedUpdate > 500) {
          lastSpeedUpdate = now;
          var hps = Math.floor(d.iterations / Math.max(1, (now - startTime) / 1000));
          speedEl.textContent = "Speed: " + hps + " h/s";
        }
      } else if (d.type === "done") {
        try { worker.terminate(); } catch (e) {}
        var elapsed = Math.round(performance.now() - startedAt);
        progBar.style.width = "100%";
        progPct.textContent = "100%";
        verifySolution(d.nonce, d.hash, elapsed, precheckRes);
      }
    };

    worker.onerror = function (err) {
      console.error("[PoW] worker error", err);
      fail("worker_error");
    };

    worker.postMessage({ randomData: randomData, difficulty: difficulty });
  }

  function verifySolution(nonce, hash, elapsedMs, precheckRes) {
    msgEl.innerHTML = "Almost there…";
    fetch(VU, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: SID,
        nonce: nonce,
        hash: hash,
        elapsed_ms: elapsedMs
      }),
      keepalive: true,
      credentials: "same-origin"
    }).then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        if (res && res.ok && res.j && res.j.ok) {
          redirectTo((precheckRes && precheckRes.url) || DU);
        } else {
          fail("verify_failed");
        }
      }).catch(function () {
        fail("verify_fetch");
      });
  }

  if (document.readyState === "complete") {
    precheck();
  } else {
    window.addEventListener("load", precheck);
  }
})();
</script>
</body>
</html>"""