import re
import secrets
import httpx
import ipaddress
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip


# =========================================================
# PHASE 1 — SAFE HELPERS (Crash Protection)
# =========================================================
def safe_int(val, default=0, max_val=10**9):
    """
    تحويل آمن لأي قيمة لـ int مع bounds.
    يحمي من: None, '', '8 cores', 10**20, inf, nan, negative.
    لو فشل التحويل المباشر، بيحاول يستخرج رقم من string.
    """
    if val is None:
        return default
    try:
        n = int(float(val))
        return max(-max_val, min(max_val, n))
    except (ValueError, TypeError, OverflowError):
        pass
    # Fallback: حاول تستخرج أول رقم من string
    match = re.search(r"-?\d+", str(val))
    if match:
        try:
            n = int(match.group())
            return max(-max_val, min(max_val, n))
        except (ValueError, OverflowError):
            pass
    return default


def safe_float(val, default=0.0, max_val=10**9):
    """نفس safe_int لكن بترجع float."""
    if val is None:
        return default
    try:
        n = float(val)
    except (ValueError, TypeError, OverflowError):
        return default
    # حماية من NaN / Inf
    if n != n or n in (float("inf"), float("-inf")):  # NaN check via x != x
        return default
    return max(-max_val, min(max_val, n))


def safe_asn(as_field):
    """
    ip-api بيرجع `as` بصيغة 'AS12345 Vodafone' — أو '', ' ', None.
    Fix C1: يحمي من IndexError لما يكون فيه مسافات بس.
    """
    if not as_field:
        return "Unknown"
    parts = str(as_field).strip().split()
    return parts[0] if parts else "Unknown"


# =========================================================
# IP GEO (معدّل: safe_asn + safe_float للـ lat/lon)
# =========================================================
async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {
            "country": "Local", "isp": "Local ISP", "type": "residential",
            "asn": "N/A", "security": {}, "lat": 0.0, "lon": 0.0,
        }
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient() as c:
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
                        "asn": safe_asn(d.get("as")),            # ← Fix C1
                        "security": {"vpn": is_vpn},
                        "lat": safe_float(d.get("lat"), 0.0),    # ← Fix
                        "lon": safe_float(d.get("lon"), 0.0),    # ← Fix
                    }
                    ip_cache.set(ip, out)
                    return out
    except Exception:
        pass
    return {
        "country": "Unknown", "isp": "Unknown", "type": "Unknown",
        "asn": "Unknown", "security": {}, "lat": 0.0, "lon": 0.0,
    }


# =========================================================
# UA PARSER (لم يتغير — سيتم تحسينه في المرحلة 3)
# =========================================================
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


# =========================================================
# ANALYZE VISIT (معدّل: كل parsing بقى آمن)
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    score = 0
    evidence = []
    nav = data.get("nav") or {}
    fp = data.get("fingerprint") or {}
    behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}
    ua = str(nav.get("ua") or "").lower()
    sec = ip_info.get("security") or {}

    # ===== Automation =====
    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver Flag")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90
        evidence.append("Suspicious User-Agent")

    # ===== OS/Platform Mismatch =====
    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform:
        score += 50
        evidence.append("OS Mismatch (Win)")
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        score += 50
        evidence.append("OS Mismatch (Mac)")

    # ===== Network =====
    if sec.get("vpn") is True:
        score += 70
        evidence.append("VPN/Proxy Detected")
    if str(ip_info.get("type", "")).lower() == "hosting":
        score += 80
        evidence.append("Datacenter/Hosting IP")

    # ===== WebRTC =====
    webrtc = data.get("webrtc_ip")
    if webrtc and webrtc != "None" and not _is_private_ip(webrtc) and webrtc != data.get("client_ip"):
        score += 90
        evidence.append(f"WebRTC Leak (Real IP: {webrtc})")

    # ===== Canvas =====
    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked":
        score += 60
        evidence.append("Missing Canvas FP")

    # ===== Hardware — Fix C4 =====
    # "8 cores" → 8 (بدل ما كان crash → 0 → +40 ظلم)
    cores = safe_int(fp.get("hardwareConcurrency"), 0, max_val=256)
    if cores <= 1:
        score += 40
        evidence.append(f"Low CPU ({cores})")

    # ===== Timezone =====
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

    # ===== Behavior — Fix C2, C3 =====
    # safe_int بيحمي من None, "abc", "8s" → رجّع 0 بدل crash
    mousemove = safe_int(events.get("mousemove"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)

    if t_on_page < 1500:
        score += 40
        evidence.append("Left too fast")

    mv = safe_float(behavior.get("mouse_variance"), 0.0)
    if mousemove > 10 and mv < 1.5:
        score += 50
        evidence.append("Robotic Mouse")

    if t_on_page > 3000 and mousemove == 0 and touchstart == 0:
        score += 30
        evidence.append("No Interaction (Zombie)")

    # ===== WebGL =====
    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        score += 60
        evidence.append("Virtual Renderer")

    # ===== Finalize =====
    score = min(150, score)
    verdict = "invalid" if score >= 80 else "suspicious" if score >= 40 else "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}
