"""
collector/interstitial_template.py — Fast Router for Direct Links.
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

    // 🔴 Capture PopAds macros
    var trackingParams = {};
    try {
        var urlParams = new URLSearchParams(window.location.search);
        var knownMacros = ['bid','impid','websiteid','website_id','quality','country','isp','ispname','ispid','adblock','os','osname','browser','browsername','device','devicename','category','categoryid','categoryname','campaignid','campaignname','screenresolution','formfactor','formfactorname','lang','impressionid','ua','useragent','ip','xforwardedfor','secchua','secchuaarch','secchuabitness','secchuamodel','secchuaplatform','secchuaplatformversion','secchuafullversion','secchuamobile','ipv6'];
        knownMacros.forEach(function(key) {
            var val = urlParams.get(key);
            if (val !== null && val !== '') trackingParams[key] = String(val).substring(0, 500);
        });
    } catch(e) {}

    function getCanvas() {
        try { var c = document.createElement('canvas'); var ctx = c.getContext('2d'); ctx.textBaseline="top"; ctx.font="14px Arial"; ctx.fillStyle="#f60"; ctx.fillRect(125,1,62,20); ctx.fillStyle="#069"; ctx.fillText("OVG-v4",2,15); return c.toDataURL(); } catch(e) { return "blocked"; }
    }

    function collect() {
        var payload = {
            session_id: SID,
            campaign_key: CK,
            url: window.location.href,
            nav: {
                ua: navigator.userAgent,
                platform: navigator.platform,
                webdriver: navigator.webdriver === true,
                language: navigator.language,
                has_touch: ('ontouchstart' in window),
                max_touch_points: Number(navigator.maxTouchPoints) || 0
            },
            fp: {
                canvas_hash: getCanvas(),
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown",
                hardwareConcurrency: Number(navigator.hardwareConcurrency) || 0,
                deviceMemory: Number(navigator.deviceMemory) || 0,
                automation: {
                    puppeteer: window.__puppeteer_evaluation_script__ !== undefined,
                    playwright: window.__playwright__ !== undefined,
                    cdc: Object.keys(window).some(function(k) { return k.indexOf('cdc_') === 0 || k.indexOf('$cdc_') === 0; })
                }
            },
            tracking_params: trackingParams
        };

        fetch(PU, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
            keepalive: true
        }).then(function(r) { return r.json(); }).then(function(res) {
            if (res.action === "redirect" && res.url) {
                // Append sub_id to destination for Adsterra
                var finalUrl = res.url + (res.url.indexOf('?') > -1 ? '&' : '?') + "sub_id=" + SID;
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
