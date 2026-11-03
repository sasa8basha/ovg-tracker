"""
analysis.py — OVG Tracker

Phase 1 — Hardening:
  [1]  events non-dict        → _safe_dict()
  [2]  webgl non-dict         → _safe_dict()
  [3]  XSS via webrtc_ip      → _safe_str() + frontend textContent
  [4]  XSS via tz             → _safe_str() + frontend textContent
  [5]  Evidence unbounded     → truncate to 200 chars
  [6]  Country cmap broken    → country_code + TZ_BY_COUNTRY_CODE (30+)
  [7]  VPN + hosting double   → if/elif max, not sum
  [8]  Canvas "blocked"       → +10 (privacy) not +60
  [9]  Platform empty         → silent skip
  [10] WebRTC multi-IP        → parse each IP individually

Phase 2 — False Positive Reduction:
  [11] Firefox RFP detection  → bypass TZ/core/platform penalties
  [12] Brave detection        → is_brave flag from JS + canvas heuristic
  [13] CPU=0 with Firefox RFP → skip core penalty
  [14] Linux software render  → +20 with known vendor, +60 without
  [15] Zombie check           → include scrolls/clicks, threshold 8s
  [16] UTC timezone           → +20 (was +30), skip for privacy browsers
  [17] Left too fast          → threshold 1800 (matches JS SEND_DELAY 2000)
"""
import re
import secrets
import httpx
import ipaddress
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip


# =========================================================
# SAFE HELPERS
# =========================================================
def safe_int(val, default=0, max_val=10**9):
    """تحويل آمن لأي قيمة لـ int مع bounds."""
    if val is None:
        return default
    try:
        n = int(float(val))
        return max(-max_val, min(max_val, n))
    except (ValueError, TypeError, OverflowError):
        pass
    match = re.search(r"-?\d+", str(val))
    if match:
        try:
            n = int(match.group())
            return max(-max_val, min(max_val, n))
        except (ValueError, OverflowError):
            pass
    return default


def safe_float(val, default=0.0, max_val=10**9):
    """نفس safe_int لكن float مع NaN/Inf protection."""
    if val is None:
        return default
    try:
        n = float(val)
    except (ValueError, TypeError, OverflowError):
        return default
    if n != n or n in (float("inf"), float("-inf")):
        return default
    return max(-max_val, min(max_val, n))


def safe_asn(as_field):
    """آمن ASN extraction — ip-api بيرجع 'AS12345 Vodafone' أو ''."""
    if not as_field:
        return "Unknown"
    parts = str(as_field).strip().split()
    return parts[0] if parts else "Unknown"


def _safe_dict(val):
    """Phase 1 Fix #1, #2: يضمن dict، وإلا يرجّع {}."""
    return val if isinstance(val, dict) else {}


def _safe_str(val, max_len=200):
    """
    Phase 1 Fix #3, #4, #5: string sanitization.
    - control chars removal (log injection)
    - < > removal (XSS defense in depth)
    - length cap (DoS)
    """
    if val is None:
        return ""
    s = str(val)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    s = s.replace("<", "").replace(">", "")
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s


# =========================================================
# TIMEZONE MAP (Phase 1 Fix #6)
# =========================================================
TZ_BY_COUNTRY_CODE = {
    "EG": {"cairo", "africa/cairo"},
    "SA": {"asia/riyadh"},
    "AE": {"asia/dubai"},
    "KW": {"asia/kuwait"},
    "QA": {"asia/qatar"},
    "BH": {"asia/bahrain"},
    "OM": {"asia/muscat"},
    "JO": {"asia/amman"},
    "LB": {"asia/beirut"},
    "SY": {"asia/damascus"},
    "IQ": {"asia/baghdad"},
    "YE": {"asia/aden"},
    "PS": {"asia/gaza", "asia/hebron"},
    "TR": {"europe/istanbul", "asia/istanbul"},
    "MA": {"africa/casablanca"},
    "DZ": {"africa/algiers"},
    "TN": {"africa/tunis"},
    "LY": {"africa/tripoli"},
    "SD": {"africa/khartoum"},
    "GB": {"europe/london"},
    "IT": {"europe/rome"},
    "DE": {"europe/berlin"},
    "FR": {"europe/paris"},
    "ES": {"europe/madrid"},
    "NL": {"europe/amsterdam"},
    "RU": {"europe/moscow", "asia/"},
    "US": {"america/"},
    "CA": {"america/toronto", "america/vancouver", "america/edmonton",
           "america/winnipeg", "america/halifax", "america/st_johns"},
    "BR": {"america/sao_paulo"},
    "IN": {"asia/kolkata", "asia/calcutta"},
    "JP": {"asia/tokyo"},
    "CN": {"asia/shanghai", "asia/beijing"},
    "AU": {"australia/"},
}


# =========================================================
# IP GEO
# =========================================================
async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {
            "country": "Local", "country_code": "LO", "isp": "Local ISP",
            "type": "residential", "asn": "N/A", "security": {},
            "lat": 0.0, "lon": 0.0,
        }
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,country,countryCode,isp,as,proxy,hosting,lat,lon",
                timeout=GEO_LOOKUP_TIMEOUT,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    is_proxy = bool(d.get("proxy"))
                    is_hosting = bool(d.get("hosting"))
                    out = {
                        "country": d.get("country", "Unknown"),
                        "country_code": str(d.get("countryCode") or "").upper()[:2],
                        "isp": d.get("isp", "Unknown"),
                        "type": "hosting" if is_hosting else "residential",
                        "asn": safe_asn(d.get("as")),
                        "security": {
                            "vpn": is_proxy or is_hosting,
                            "proxy": is_proxy,
                            "hosting": is_hosting,
                        },
                        "lat": safe_float(d.get("lat"), 0.0),
                        "lon": safe_float(d.get("lon"), 0.0),
                    }
                    ip_cache.set(ip, out)
                    return out
    except Exception:
        pass
    return {
        "country": "Unknown", "country_code": "", "isp": "Unknown",
        "type": "Unknown", "asn": "Unknown", "security": {},
        "lat": 0.0, "lon": 0.0,
    }


# =========================================================
# UA PARSER
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
# PHASE 2 — PRIVACY BROWSER DETECTION (Fix #11, #12)
# =========================================================
def _detect_privacy_browser(ua: str, platform: str, fp: dict, nav: dict):
    """
    Returns (is_privacy_browser: bool, name: str)

    Priority:
      1. is_brave flag from JS (most reliable)
      2. Firefox RFP heuristic (platform == "" + firefox UA)
      3. Brave heuristic (canvas blocked + chrome UA)

    ليه ده مهم:
      Brave و Firefox-RFP بيحموا الخصوصية عمدًا. إشاراتهم
      بتشبه البوتات (canvas blocked، platform فاضي، UTC timezone).
      من غير detection ده = بنظلمهم.
    """
    ua_lower = ua.lower()

    # Priority 1: JS flag (Brave.isBrave() promise من الـ tracker)
    if nav.get("is_brave") is True:
        return True, "Brave"

    # Priority 2: Firefox RFP
    # Firefox resistFingerprinting بيبعت: platform = "" + timezone = "UTC"
    if "firefox" in ua_lower and not platform:
        return True, "Firefox-RFP"

    # Priority 3: Brave heuristic (fallback لو JS flag مش موجود)
    # Brave shields default = canvas blocked + chrome UA
    canvas = fp.get("canvas_hash")
    if (
        canvas == "blocked"
        and "chrome" in ua_lower
        and "headless" not in ua_lower
    ):
        return True, "Brave(heuristic)"

    return False, ""


# =========================================================
# WEBRTC CHECK (Phase 1 Fix #10)
# =========================================================
def _check_webrtc(webrtc_str, client_ip, ip_info):
    if not webrtc_str or webrtc_str == "None":
        return 0, ""
    if not client_ip:
        return 0, ""

    raw_parts = [p.strip() for p in str(webrtc_str).split(",") if p.strip()]
    valid_leaks = []

    for part in raw_parts:
        try:
            addr = ipaddress.ip_address(part)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            continue
        if part == client_ip:
            continue
        valid_leaks.append(part)

    if not valid_leaks:
        return 0, ""

    if ip_info.get("security", {}).get("vpn"):
        return 20, f"WebRTC Differs (likely VPN): {_safe_str(valid_leaks[0], 60)}"

    return 90, f"WebRTC Leak: {_safe_str(valid_leaks[0], 60)}"


# =========================================================
# ANALYZE VISIT (Phase 1 + Phase 2)
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    score = 0
    evidence = []

    # ===== Phase 1: defensive dict extraction =====
    nav = _safe_dict(data.get("nav"))
    fp = _safe_dict(data.get("fingerprint"))
    behavior = _safe_dict(data.get("behavior"))
    events = _safe_dict(behavior.get("events"))
    webgl = _safe_dict(fp.get("webgl"))
    sec = _safe_dict(ip_info.get("security"))

    ua = str(nav.get("ua") or "").lower()
    platform = str(nav.get("platform") or "").lower()

    # ===== Phase 2 Fix #11, #12: Privacy browser detection =====
    is_privacy_browser, privacy_name = _detect_privacy_browser(ua, platform, fp, nav)

    # ===== Automation =====
    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver Flag")

    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90
        evidence.append("Suspicious User-Agent")

    # ===== OS/Platform Mismatch (Phase 1 Fix #9) =====
    if not platform:
        # Phase 1 Fix #9 + Phase 2 Fix #11, #12:
        # platform فاضي = privacy browser (Brave / Firefox RFP) = skip
        pass
    else:
        if "windows nt" in ua and "win" not in platform:
            score += 50
            evidence.append("OS Mismatch (Win)")
        if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
            score += 50
            evidence.append("OS Mismatch (Mac)")

    # ===== Network (Phase 1 Fix #7: max, not sum) =====
    is_proxy = sec.get("proxy") is True
    is_hosting = (
        sec.get("hosting") is True
        or str(ip_info.get("type", "")).lower() == "hosting"
    )

    if is_proxy and is_hosting:
        score += 70
        evidence.append("VPN + Datacenter")
    elif is_hosting:
        score += 50
        evidence.append("Datacenter/Hosting IP")
    elif is_proxy:
        score += 40
        evidence.append("VPN/Proxy Detected")

    # ===== WebRTC (Phase 1 Fix #10) =====
    webrtc_penalty, webrtc_evidence = _check_webrtc(
        data.get("webrtc_ip"),
        data.get("client_ip"),
        ip_info,
    )
    if webrtc_penalty:
        score += webrtc_penalty
        if webrtc_evidence:
            evidence.append(webrtc_evidence)

    # ===== Canvas (Phase 1 Fix #8) =====
    canvas = fp.get("canvas_hash")
    if canvas == "blocked":
        # privacy browser = عقوبة خفيفة (مش bot)
        score += 10
        evidence.append("Canvas Blocked (privacy)")
    elif not canvas or len(str(canvas)) < 5:
        score += 60
        evidence.append("Missing Canvas FP")

    # ===== Hardware (Phase 2 Fix #13: skip CPU=0 for Firefox RFP) =====
    cores = safe_int(fp.get("hardwareConcurrency"), 0, max_val=256)
    if cores <= 1:
        # Phase 2 Fix #13: Firefox RFP بيبعت 0 أو 2 (مش مؤشر بوت)
        if cores == 0 and is_privacy_browser:
            pass  # mفيش عقوبة
        elif cores == 0 and "firefox" in ua:
            # Firefox بدون RFP ممكن يبعت 0 في إصدارات قديمة
            pass
        else:
            score += 40
            evidence.append(f"Low CPU ({cores})")

    # ===== Timezone (Phase 1 Fix #6 + Phase 2 Fix #16) =====
    tz = str(fp.get("timezone") or "").lower()
    country_code = str(ip_info.get("country_code") or "").upper()

    if not tz or tz in ("utc", "etc/utc", "unknown"):
        # Phase 2 Fix #16: عقوبة 20 بدل 30 + skip للـ privacy browsers
        if is_privacy_browser:
            pass  # Firefox RFP default = UTC، مش مؤشر
        else:
            score += 20
            evidence.append("UTC/Unknown Timezone")
    elif country_code in TZ_BY_COUNTRY_CODE:
        expected_tzs = TZ_BY_COUNTRY_CODE[country_code]
        if not any(t in tz for t in expected_tzs):
            score += 60
            evidence.append(
                f"TZ Mismatch (IP:{country_code} vs TZ:{_safe_str(tz, 40)})"
            )

    # ===== Behavior (Phase 2 Fix #15, #17) =====
    mousemove = safe_int(events.get("mousemove"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)

    # Phase 2 Fix #17: threshold 1800 (because JS SEND_DELAY = 2000ms)
    # أي إرسال عادي هيبقى t_on_page >= 2000. أقل من 1800 = خرج قبل الـ delay
    if t_on_page < 1800:
        score += 40
        evidence.append("Left too fast")

    mv = safe_float(behavior.get("mouse_variance"), 0.0)
    if mousemove > 10 and mv < 1.5:
        score += 50
        evidence.append("Robotic Mouse")

    # Phase 2 Fix #15: zombie check بيشمل scrolls/clicks + threshold 8s
    has_any_interaction = (
        mousemove > 5
        or touchstart > 0
        or scrolls > 0
        or clicks > 0
    )
    if t_on_page > 8000 and not has_any_interaction:
        score += 30
        evidence.append("No Interaction (Zombie)")

    # ===== WebGL (Phase 2 Fix #14: vendor-aware) =====
    renderer = str(webgl.get("renderer") or "").lower()
    vendor = str(webgl.get("vendor") or "").lower()

    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        # Phase 2 Fix #14: لو فيه vendor معروف = Linux/VM dev (عقوبة خفيفة)
        # لو مفيش vendor = headless (عقوبة كاملة)
        known_vendors = ("intel", "nvidia", "amd", "microsoft", "google", "apple")
        if any(v in vendor for v in known_vendors):
            score += 20
            evidence.append(f"Software Renderer ({_safe_str(vendor, 30)})")
        else:
            score += 60
            evidence.append("Virtual Renderer (no vendor)")

    # ===== Finalize =====
    evidence = [_safe_str(e, 200) for e in evidence]

    score = min(150, score)
    verdict = "invalid" if score >= 80 else "suspicious" if score >= 40 else "valid"
    return {
        "score": score,
        "verdict": verdict,
        "evidence": evidence,
        # Phase 2: expose privacy browser for future UI use
        "privacy_browser": privacy_name or None,
}
