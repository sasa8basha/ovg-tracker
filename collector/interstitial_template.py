"""
collector/interstitial_template.py — Fast Router for Direct Links (v2.0 — Bot Detection Integrated)
"""
INTERSTITIAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Loading</title>
<style>
body { margin:0; background:#fff; display:flex; justify-content:center; align-items:center; height:100vh; overflow:hidden; }
.spinner { width:30px; height:30px; border:3px solid rgba(0,0,0,0.1); border-top-color:#333; border-radius:50%; animation:spin 0.8s linear infinite; }
@keyframes spin { to { transform:rotate(360deg); } }
</style>
</head>
<body>
<div class="spinner"></div>
<script>
(function(){
    var CK = "__CAMPAIGN_KEY__";
    var PU = "__PRECHECK_URL__";
    var DU = "__DEST_URL__";
    var SID = "";

    function uuid() {
        try { if (crypto.randomUUID) return crypto.randomUUID(); } catch(e){}
        var s = []; for(var i=0; i<32; i++) s.push((Math.random()*16|0).toString(16));
        return s.slice(0,8).join('')+'-'+s.slice(8,12).join('')+'-'+s.slice(12,16).join('')+'-'+s.slice(16,20).join('')+'-'+s.slice(20).join('');
    }
    SID = uuid();

    var trackingParams = {};
    try {
        var urlParams = new URLSearchParams(window.location.search);
        urlParams.forEach(function(value, key) {
            if (value !== null && value !== '') trackingParams[key] = String(value).substring(0, 500);
        });
    } catch(e) {}

    // =========================================================
    // BOT DETECTIONS (vi-bot & BotD)
    // =========================================================
    function isNativeFn(fnStr) { return /\(\)\s*{\s+\[native code\]\s+}\s*$/.test(String(fnStr)); }

    function runDetections() {
        var det = {};
        var w = window, n = navigator, d = document, s = screen;
        var wd = false;

        try { if (n.webdriver === true) det.webdriver = 1; } catch(e){}
        try {
            var wdGetter = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
            if (wdGetter && wdGetter.get && !isNativeFn(wdGetter.get.toString())) det.webdriverSpoofed = 1;
        } catch(e){}

        try {
            if (w.outerWidth === 0 && w.outerHeight === 0) det.windowSize = 1;
        } catch(e){}

        try {
            if (n.userAgent) {
                if (/PhantomJS/i.test(n.userAgent)) det.userAgentPhantom = 1;
                if (/Headless/i.test(n.userAgent)) det.userAgentHeadless = 1;
                if (/Electron/i.test(n.userAgent)) det.userAgentElectron = 1;
            }
        } catch(e){}

        try {
            var err = new Error();
            throw err;
        } catch(e) {
            if (/PhantomJS/i.test(e.stack || '')) det.errorTracePhantom = 1;
        }

        try {
            var allKeys = Object.getOwnPropertyNames(w);
            for (var i = 0; i < allKeys.length; i++) {
                var k = allKeys[i];
                if (k.indexOf('cdc_') === 0 || k === '__playwright__' || k === '__puppeteer__') det.cdpDetected = 1;
            }
        } catch(e){}

        try {
            var createStr = Document.prototype.createElement.toString();
            if (!isNativeFn(createStr)) det.fakeCreateElement = 1;
        } catch(e){}

        try {
            if (!isNativeFn(Function.prototype.toString.toString())) det.toStringSpoofed = 1;
        } catch(e){}

        try {
            if (w.chrome && typeof w.chrome === 'object') {
                var chromeKeys = Object.keys(w.chrome);
                if (chromeKeys.indexOf('loadTimes') !== -1 && chromeKeys[0] !== 'loadTimes') det.wrongChromeOrder = 1;
            }
        } catch(e){}

        try {
            var isChromium3 = n.vendor && n.vendor.indexOf('Google') === 0;
            if (isChromium3 && s.orientation && s.orientation.type === 'landscape-primary' && s.orientation.angle === 90) {
                if (!(w.chrome && w.chrome.runtime) && 'SharedWorker' in w) det.playwrightOrientation = 1;
            }
        } catch(e){}

        return det;
    }

    function getFingerprint() {
        var fp = {
            canvas_hash: "blocked",
            webgl: { vendor: "Unknown", renderer: "Unknown" },
            detections: runDetections()
        };

        try {
            var c = document.createElement('canvas');
            c.width = 220; c.height = 40;
            var ctx = c.getContext('2d');
            if (ctx) {
                ctx.textBaseline = 'top'; ctx.font = '15px Arial';
                ctx.fillStyle = '#f60'; ctx.fillRect(120, 1, 62, 20);
                ctx.fillStyle = '#069'; ctx.fillText('OVG-v3', 2, 15);
                var data = c.toDataURL();
                var h = 5381;
                for (var i = 0; i < data.length; i++) h = ((h << 5) + h + data.charCodeAt(i)) | 0;
                fp.canvas_hash = 'fp_' + Math.abs(h).toString(16);
            }
        } catch(e){}

        try {
            var wc = document.createElement('canvas');
            var gl = wc.getContext('webgl') || wc.getContext('experimental-webgl');
            if (gl) {
                var ext = gl.getExtension('WEBGL_debug_renderer_info');
                if (ext) {
                    fp.webgl = {
                        vendor: String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || 'Unknown'),
                        renderer: String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || 'Unknown')
                    };
                }
            }
        } catch(e){}

        return fp;
    }

    function collect() {
        var payload = {
            session_id: SID,
            campaign_key: CK,
            url: window.location.href,
            nav: {
                ua: navigator.userAgent,
                platform: navigator.platform || '',
                webdriver: navigator.webdriver === true,
                language: navigator.language || '',
                has_touch: ('ontouchstart' in window),
                max_touch_points: Number(navigator.maxTouchPoints) || 0
            },
            fp: getFingerprint(),
            tracking_params: trackingParams
        };

        fetch(PU, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
            keepalive: true
        }).then(function(r) { return r.json(); }).then(function(res) {
            if (res.action === "redirect" && res.url) {
                var sep = res.url.indexOf('?') > -1 ? '&' : '?';
                var finalUrl = res.url + sep + "sub_id=" + SID;
                window.location.replace(finalUrl);
            } else {
                window.location.replace("/404?reason=" + (res.reasons ? res.reasons[0] : "blocked"));
            }
        }).catch(function() {
            window.location.replace(DU);
        });
    }

    if (document.readyState === 'complete') collect();
    else window.addEventListener('load', collect);
})();
</script>
</body>
</html>"""
