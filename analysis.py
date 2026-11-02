import secrets
import httpx
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip

async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {"country": "Local", "isp": "Local ISP", "type": "residential", "asn": "N/A", "security": {}, "lat": 0.0, "lon": 0.0}
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient() as c:
            # ضفنا lat و lon هنا
            r = await c.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,isp,as,proxy,hosting,lat,lon",
                timeout=GEO_LOOKUP_TIMEOUT,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    is_vpn = bool(d.get("proxy") or d.get("hosting"))
                    out = {
                        "country": d.get("country", "Unknown"),
                        "isp": d.get("isp", "Unknown"),
                        "type": "hosting" if is_vpn else "residential",
                        "asn": (d.get("as") or "Unknown").split()[0],
                        "security": {"vpn": is_vpn},
                        "lat": d.get("lat", 0.0),
                        "lon": d.get("lon", 0.0),
                    }
                    ip_cache.set(ip, out)
                    return out
    except Exception:
        pass
    return {"country": "Unknown", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}, "lat": 0.0, "lon": 0.0}

def parse_ua(ua: str):
    u = (ua or "").lower()
    device = "Mobile" if "mobi" in u else "Tablet" if ("tablet" in u or "ipad" in u) else "Desktop"
    if "windows nt" in u:
        os_name = "Windows"
    elif "mac os" in u or "macintosh" in u:
        os_name = "macOS"
    elif "android" in u:
        os_name = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u:
        os_name = "iOS"
    elif "linux" in u:
        os_name = "Linux"
    else:
        os_name = "Unknown"
    if "edg/" in u or "edge/" in u:
        browser = "Edge"
    elif "chrome" in u and "chromium" not in u:
        browser = "Chrome"
    elif "firefox" in u:
        browser = "Firefox"
    elif "safari" in u and "chrome" not in u:
        browser = "Safari"
    else:
        browser = "Unknown"
    return os_name, device, browser

def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v:
                return v[0]
    except Exception:
        pass
    return "unknown"

def new_site_key() -> str:
    return secrets.token_hex(8)

def analyze_visit(data: dict, ip_info: dict) -> dict:
    score = 0
    evidence = []
    nav = data.get("nav") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    ua = str(nav.get("ua") or "").lower()
    sec = ip_info.get("security", {})

    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver Flag")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90
        evidence.append("Suspicious User-Agent")

    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        score += 50
        evidence.append("OS Mismatch (Win)")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        score += 50
        evidence.append("OS Mismatch (Mac)")

    if sec.get("vpn") is True:
        score += 70
        evidence.append("VPN/Proxy Detected")
    if str(ip_info.get("type", "")).lower() == "hosting":
        score += 80
        evidence.append("Datacenter/Hosting IP")

    webrtc = data.get("webrtc_ip")
    if webrtc and webrtc != "None" and not _is_private_ip(webrtc) and webrtc != data.get("client_ip"):
        score += 90
        evidence.append(f"WebRTC Leak (Real IP: {webrtc})")

    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        score += 60
        evidence.append("Missing Canvas FP")
    try:
        cores = int(fp.get("hardwareConcurrency") or 0)
    except Exception:
        cores = 0
    if cores <= 1:
        score += 40
        evidence.append(f"Low CPU ({cores})")

    tz = str(fp.get("timezone") or "").lower()
    country = ip_info.get("country", "Unknown")
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        score += 30
        evidence.append("UTC/Unknown Timezone")
    elif country not in ("Unknown", "Local"):
        cmap = {
            "Egypt": ["cairo", "africa"],
            "US": ["america/"],
            "UK": ["london", "europe/london"],
            "SA": ["riyadh", "asia/riyadh"],
            "Italy": ["rome", "europe/rome"],
        }
        if country in cmap and not any(t in tz for t in cmap[country]):
            score += 60
            evidence.append(f"Timezone Mismatch (IP:{country} vs TZ:{tz})")

    try:
        t_on_page = int(behavior.get("time_on_page_ms") or 0)
    except Exception:
        t_on_page = 0
    if t_on_page < 1500:
        score += 40
        evidence.append("Left too fast")
    try:
        mv = float(behavior.get("mouse_variance") or 0)
    except Exception:
        mv = 0.0
    if events.get("mousemove", 0) > 10 and mv < 1.5:
        score += 50
        evidence.append("Robotic Mouse")
    if t_on_page > 3000 and events.get("mousemove", 0) == 0 and events.get("touchstart", 0) == 0:
        score += 30
        evidence.append("No Interaction (Zombie)")

    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        score += 60
        evidence.append("Virtual Renderer")

    score = min(150, score)
    verdict = "invalid" if score >= 80 else "suspicious" if score >= 40 else "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}
