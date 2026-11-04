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
  [12] Brave detection        → is_brave flag + canvas heuristic
  [13] CPU=0 with Firefox RFP → skip core penalty
  [14] Linux software render  → +20 with known vendor, +60 without
  [15] Zombie check           → include scrolls/clicks, threshold 8s
  [16] UTC timezone           → +20, skip for privacy browsers
  [17] Left too fast          → threshold 1800 (matches SEND_DELAY 2000)

Phase 3 — False Negative Reduction:
  [18] UA patterns            → 25+ patterns + word-boundary regex
  [19] navigator.plugins      → Chrome desktop with 0 plugins
  [20] navigator.languages    → empty +40, single en-US +15
  [21] window.chrome check    → no_window_chrome +50
  [22] CDP detection          → critical signal
  [23] Fingerprint rate       → sliding scale by count/min
  [24] Mouse trajectory       → velocity variance + curvature + direction
  [25] Cross-validation       → Windows+Linux, mobile+wide-screen

Phase 4 — Rule-Based Architecture:
  [26] Rule-based scoring     → critical/high/medium/low categories
  [27] Human signals          → negative scores for genuine behavior
  [28] Confidence score       → 0-1 based on severity diversity
  [29] Structured evidence    → {code, severity, score, detail}
  [30] Raw score + final score → before/after cap
  [32] Thresholds calibrated  → critical=auto, 2 high=invalid, etc.

Phase 5 — CPM Arbitrage Effectiveness:
  [33] Datacenter ASN map     → 40+ known DC/VPN ASNs
  [34] CPM quality classifier → premium/standard/low/wasted/invalid
  [35] Wasted impression flag → valid traffic that won't see ads
  [36] Headless viewport      → 800x600 / 0x0 detection
  [37] Screen sanity checks   → desktop < 1024px, mobile > 1920px
  [38] TZ map hardened        → exact match (no wildcard)
  [39] CPU split             → cores=0 vs cores=1

Phase 6 — Analysis Deep Fixes:
  [40] Googlebot + SEO bots   → full search engine patterns
  [41] python word-boundary   → \bpython\b, not substring
  [42] LEFT_FAST visibility   → send_reason: hidden=15, unload=40
  [43] Tablet vs phone        → is_tablet + is_mobile_phone split
  [44] deviceMemory           → LOW_MEMORY signal
  [45] colorDepth             → LOW_COLOR_DEPTH signal
  [46] pixelRatio on mobile   → MOBILE_PIXEL_RATIO signal
  [47] Absurd cores           → ABSURD_CORES signal
  [48] calc_confidence revamp → severity-weighted curve
  [49] Function split         → 10 focused _check_* functions
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
    if not as_field:
        return "Unknown"
    parts = str(as_field).strip().split()
    return parts[0] if parts else "Unknown"


def _safe_dict(val):
    return val if isinstance(val, dict) else {}


def _safe_str(val, max_len=200):
    if val is None:
        return ""
    s = str(val)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    s = s.replace("<", "").replace(">", "")
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s


# =========================================================
# BOT UA PATTERNS (Phase 3 + Phase 5 + Phase 6)
# =========================================================
BOT_UA_PATTERNS = (
    # Generic tooling
    "curl", "wget", "httpie",
    "python-requests", "requests/",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "undici",
    "httpclient", "libwww", "restsharp",
    "headless", "selenium", "phantom", "puppeteer", "playwright",
    "scrapy", "guzzle", "httpx",
    "postman", "insomnia", "apitester",
    "automated", "automation", "http_request",
    # SEO / AI crawlers (Phase 5)
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot",
    "petalbot", "bytespider", "gptbot", "claudebot",
    "ccbot", "yandexbot", "slurp", "bingpreview",
    "facebookexternalhit", "linkedinbot", "twitterbot",
    "duckduckbot", "applebot",
    # Search engines (Phase 6 — was missing)
    "googlebot", "google-inspectiontool", "adsbot-google",
    "mediapartners-google", "bingbot", "msnbot",
    "baiduspider", "sogou", "exabot", "ia_archiver",
)

# Short patterns that need word boundary (avoid "pythonic")
BOT_UA_WORDS_RE = re.compile(r"\bpython\b", re.IGNORECASE)

# Word-boundary bot keywords
BOT_WORD_RE = re.compile(r"\b(bot|bots|spider|crawler|robot|scraper)\b", re.IGNORECASE)


def _is_bot_ua(ua: str) -> bool:
    if not ua:
        return True
    ua_lower = ua.lower()
    if any(x in ua_lower for x in BOT_UA_PATTERNS):
        return True
    if BOT_UA_WORDS_RE.search(ua):
        return True
    if BOT_WORD_RE.search(ua):
        return True
    return False


# =========================================================
# PHASE 5 — DATACENTER / VPN ASNs
# =========================================================
DATACENTER_ASNS = frozenset([
    "AS14061", "AS16509", "AS14618", "AS396982", "AS15169",
    "AS8075", "AS31898", "AS45102", "AS7506", "AS37963",
    "AS24940", "AS16276", "AS20473", "AS20454", "AS63949",
    "AS51167", "AS60781", "AS16265", "AS12876", "AS197540",
    "AS197695", "AS49505", "AS208046", "AS40676", "AS53667",
    "AS59711", "AS29802", "AS63023", "AS212238", "AS9312",
    "AS35916", "AS21859", "AS36352", "AS209854",
    "AS9009", "AS3223", "AS62838", "AS200373", "AS9002",
    "AS394711", "AS3462", "AS6079",
])


# =========================================================
# PHASE 5 — TIMEZONE MAP (exact match only)
# =========================================================
TZ_BY_COUNTRY_CODE = {
    "EG": {"africa/cairo"},
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
    "IL": {"asia/jerusalem", "asia/tel_aviv"},
    "IR": {"asia/tehran"},
    "MA": {"africa/casablanca"},
    "DZ": {"africa/algiers"},
    "TN": {"africa/tunis"},
    "LY": {"africa/tripoli"},
    "SD": {"africa/khartoum"},
    "GB": {"europe/london"},
    "IE": {"europe/dublin"},
    "IT": {"europe/rome", "europe/milan"},
    "DE": {"europe/berlin", "europe/frankfurt"},
    "FR": {"europe/paris"},
    "ES": {"europe/madrid", "africa/ceuta"},
    "PT": {"europe/lisbon", "atlantic/azores"},
    "NL": {"europe/amsterdam"},
    "BE": {"europe/brussels"},
    "CH": {"europe/zurich"},
    "AT": {"europe/vienna"},
    "SE": {"europe/stockholm"},
    "NO": {"europe/oslo"},
    "DK": {"europe/copenhagen"},
    "FI": {"europe/helsinki"},
    "PL": {"europe/warsaw"},
    "CZ": {"europe/prague"},
    "RO": {"europe/bucharest"},
    "GR": {"europe/athens"},
    "RU": {
        "europe/moscow", "europe/kaliningrad", "europe/samara",
        "europe/volgograd", "europe/saratov",
        "asia/yekaterinburg", "asia/novosibirsk", "asia/omsk",
        "asia/krasnoyarsk", "asia/irkutsk", "asia/yakutsk",
        "asia/vladivostok", "asia/magadan", "asia/kamchatka",
    },
    "US": {
        "america/new_york", "america/chicago", "america/denver",
        "america/phoenix", "america/los_angeles",
        "america/anchorage", "america/honolulu", "america/detroit",
        "america/indianapolis", "america/boise", "america/juneau",
        "america/sitka", "america/nome", "america/adak",
    },
    "CA": {
        "america/toronto", "america/vancouver", "america/edmonton",
        "america/winnipeg", "america/halifax", "america/st_johns",
        "america/regina", "america/whitehorse", "america/yellowknife",
    },
    "MX": {
        "america/mexico_city", "america/tijuana", "america/cancun",
        "america/monterrey", "america/chihuahua",
    },
    "BR": {
        "america/sao_paulo", "america/rio_branco", "america/manaus",
        "america/belem", "america/fortaleza", "america/recife",
        "america/noronha",
    },
    "AR": {"america/argentina/buenos_aires", "america/argentina/cordoba"},
    "CO": {"america/bogota"},
    "CL": {"america/santiago", "pacific/easter"},
    "PE": {"america/lima"},
    "VE": {"america/caracas"},
    "IN": {"asia/kolkata", "asia/calcutta"},
    "JP": {"asia/tokyo"},
    "CN": {"asia/shanghai", "asia/beijing", "asia/chongqing"},
    "HK": {"asia/hong_kong"},
    "KR": {"asia/seoul"},
    "TW": {"asia/taipei"},
    "TH": {"asia/bangkok"},
    "VN": {"asia/ho_chi_minh"},
    "MY": {"asia/kuala_lumpur"},
    "SG": {"asia/singapore"},
    "ID": {"asia/jakarta", "asia/makassar", "asia/jayapura"},
    "PH": {"asia/manila"},
    "PK": {"asia/karachi", "asia/lahore"},
    "BD": {"asia/dhaka"},
    "LK": {"asia/colombo"},
    "AF": {"asia/kabul"},
    "NG": {"africa/lagos"},
    "KE": {"africa/nairobi"},
    "GH": {"africa/accra"},
    "ZA": {"africa/johannesburg", "africa/cape_town"},
    "ET": {"africa/addis_ababa"},
    "AU": {
        "australia/sydney", "australia/melbourne", "australia/brisbane",
        "australia/perth", "australia/adelaide", "australia/hobart",
        "australia/darwin",
    },
    "NZ": {"pacific/auckland"},
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
# PRIVACY BROWSER DETECTION
# =========================================================
def _detect_privacy_browser(ua: str, platform: str, fp: dict, nav: dict):
    ua_lower = ua.lower()
    if nav.get("is_brave") is True:
        return True, "Brave"
    if "firefox" in ua_lower and not platform:
        return True, "Firefox-RFP"
    canvas = fp.get("canvas_hash")
    if canvas == "blocked" and "chrome" in ua_lower and "headless" not in ua_lower:
        return True, "Brave(heuristic)"
    return False, ""


# =========================================================
# WEBRTC CHECK
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
# PHASE 4 — EVIDENCE COLLECTOR
# =========================================================
VALID_SEVERITIES = frozenset(["critical", "high", "medium", "low", "human"])


class EvidenceCollector:
    """
    يجمع الإشارات مع {code, severity, score, detail}.
    يحسب raw_score, final_score, confidence, categories.
    """

    def __init__(self):
        self.items = []

    def _add(self, code, severity, score, detail):
        if severity not in VALID_SEVERITIES:
            severity = "medium"
        self.items.append({
            "code": _safe_str(code, 50),
            "severity": severity,
            "score": int(score),
            "detail": _safe_str(detail, 200),
        })

    def risk(self, code, severity, score, detail):
        self._add(code, severity, abs(int(score)), detail)

    def human(self, code, score, detail):
        self._add(code, "human", -abs(int(score)), detail)

    def has_critical(self) -> bool:
        return any(i["severity"] == "critical" for i in self.items)

    def raw_score(self) -> int:
        return sum(i["score"] for i in self.items)

    def final_score(self) -> int:
        return max(0, min(150, self.raw_score()))

    def counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
        for item in self.items:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        return counts


def _apply_items(ev, items):
    """Helper: apply list of (code, severity, score, detail) tuples to collector."""
    for code, sev, score, detail in items:
        if sev == "human":
            ev.human(code, abs(score), detail)
        else:
            ev.risk(code, sev, score, detail)


# =========================================================
# PHASE 6 — CONFIDENCE (severity-weighted curve)
# =========================================================
def calc_confidence(signals: list) -> float:
    """
    حساب confidence (0.0–1.0) بناءً على:
      - Critical → 0.95 دائمًا
      - Total severity weight → curve تصاعدية

    Severity weights: high=30, medium=15, low=5
    """
    if not signals:
        return 0.0

    non_human = [s for s in signals if s.get("severity") != "human"]
    if not non_human:
        return 0.0

    if any(s.get("severity") == "critical" for s in non_human):
        return 0.95

    weights = {"high": 30, "medium": 15, "low": 5}
    total_weight = sum(weights.get(s.get("severity"), 10) for s in non_human)

    if total_weight >= 60:
        return 0.90
    if total_weight >= 40:
        return 0.80
    if total_weight >= 25:
        return 0.65
    if total_weight >= 15:
        return 0.50
    if total_weight >= 5:
        return 0.35
    return 0.20


def count_categories(signals: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
    for s in signals:
        sev = s.get("severity", "medium") if isinstance(s, dict) else "medium"
        if sev in counts:
            counts[sev] += 1
    return counts


def normalize_stored_evidence(evidence):
    if not evidence:
        return []
    result = []
    for e in evidence:
        if isinstance(e, dict):
            result.append({
                "code": e.get("code", "UNKNOWN"),
                "severity": e.get("severity", "medium"),
                "score": int(e.get("score", 0) or 0),
                "detail": e.get("detail", ""),
            })
        elif isinstance(e, str):
            result.append({
                "code": "LEGACY_SIGNAL",
                "severity": "medium",
                "score": 0,
                "detail": e,
            })
    return result


# =========================================================
# PHASE 5 — CPM QUALITY CLASSIFIER
# =========================================================
_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])
_PREMIUM_HUMAN_CODES = frozenset(["HUMAN_NATURAL_MOUSE", "HUMAN_RICH_INTERACTION"])
_PREMIUM_EXTRA_CODES = frozenset(["HUMAN_LONG_ENGAGEMENT"])


def compute_cpm_quality(evidence_items: list, verdict: str) -> str:
    if verdict == "invalid":
        return "invalid"
    codes = {
        e.get("code") for e in evidence_items
        if isinstance(e, dict) and e.get("code")
    }
    if codes & _WASTED_CODES:
        return "wasted"
    if verdict == "suspicious":
        return "low"
    if (codes & _PREMIUM_HUMAN_CODES) and (codes & _PREMIUM_EXTRA_CODES):
        return "premium"
    if len(codes & _PREMIUM_HUMAN_CODES) >= 2:
        return "premium"
    return "standard"


def is_wasted_impression(evidence_items: list, verdict: str) -> bool:
    if verdict == "invalid":
        return False
    codes = {
        e.get("code") for e in evidence_items
        if isinstance(e, dict) and e.get("code")
    }
    return bool(codes & _WASTED_CODES)


# =========================================================
# PHASE 6 — SIGNAL CHECKS (each returns list of tuples)
# =========================================================
def _check_critical(nav, fp, ua, platform, chrome_check):
    """Critical signals — auto-invalid."""
    items = []
    if nav.get("webdriver") is True:
        items.append(("WEBDRIVER_FLAG", "critical", 80, "navigator.webdriver === true"))
    if fp.get("cdp_detected") is True:
        items.append(("CDP_DETECTED", "critical", 100, "CDP Runtime Detected"))
    if "windows nt" in ua and platform and ("linux" in platform or "x11" in platform):
        items.append((
            "WINDOWS_UA_LINUX", "critical", 100,
            f"Windows UA + Linux platform ({_safe_str(platform, 30)})",
        ))
    if "firefox" in ua and chrome_check == "full":
        items.append((
            "FIREFOX_CHROME_OBJ", "critical", 80,
            "Firefox UA + window.chrome (impossible)",
        ))
    return items


def _check_network(ip_info, data, asn_value, is_proxy, is_hosting):
    """Network signals — proxy/hosting/ASN/WebRTC."""
    items = []
    if is_proxy and is_hosting:
        items.append(("VPN_DATACENTER", "high", 70, "VPN + Datacenter IP"))
    elif is_hosting:
        items.append(("DATACENTER_IP", "medium", 50, "Datacenter/Hosting IP"))
    elif is_proxy:
        items.append(("VPN_PROXY", "medium", 40, "VPN/Proxy IP"))

    if asn_value and asn_value.upper() in DATACENTER_ASNS and not is_hosting:
        items.append(("DATACENTER_ASN", "high", 70, f"Datacenter ASN: {asn_value}"))

    webrtc_penalty, webrtc_evidence = _check_webrtc(
        data.get("webrtc_ip"), data.get("client_ip"), ip_info,
    )
    if webrtc_penalty >= 90:
        items.append(("WEBRTC_LEAK", "high", webrtc_penalty, webrtc_evidence))
    elif webrtc_penalty > 0:
        items.append(("WEBRTC_VPN_DIFF", "medium", webrtc_penalty, webrtc_evidence))

    return items


def _check_fingerprint(fp, plugins_info, is_desktop_chrome, is_privacy_browser,
                       chrome_check, ua):
    """Fingerprint signals — plugins, chrome object, canvas, languages."""
    items = []
    plugin_count = safe_int(plugins_info.get("count"), -1, max_val=1000)
    if is_desktop_chrome and not is_privacy_browser and plugin_count == 0:
        items.append(("PLUGINS_ZERO", "high", 60, "Chrome desktop: 0 plugins"))

    if is_desktop_chrome and not is_privacy_browser and chrome_check == "no_window_chrome":
        items.append(("CHROME_NO_OBJ", "high", 50, "Chrome UA: no window.chrome"))

    canvas = fp.get("canvas_hash")
    if canvas == "blocked":
        items.append(("CANVAS_BLOCKED", "low", 10, "Canvas blocked (privacy browser)"))
    elif not canvas or len(str(canvas)) < 5:
        items.append(("CANVAS_MISSING", "medium", 60, "Canvas hash missing or invalid"))

    langs_raw = fp.get("languages")
    if isinstance(langs_raw, list):
        if len(langs_raw) == 0:
            items.append(("LANGUAGES_EMPTY", "medium", 40, "Empty navigator.languages"))
        elif (len(langs_raw) == 1 and langs_raw[0] == "en-US"
              and is_desktop_chrome and not is_privacy_browser):
            items.append(("SINGLE_LANG", "low", 15, "Only single en-US language"))

    return items


def _check_fingerprint_reuse(data):
    """Fingerprint reuse rate."""
    items = []
    recent_fp = safe_int(data.get("_recent_fp_count"), 0)
    if recent_fp >= 50:
        items.append(("FINGERPRINT_REUSE_HIGH", "high", 80, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp >= 30:
        items.append(("FINGERPRINT_REUSE_HIGH", "high", 60, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp >= 20:
        items.append(("FINGERPRINT_REUSE_MED", "medium", 40, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp > 10:
        items.append(("FINGERPRINT_REUSE_LOW", "low", 25, f"Fingerprint reuse ({recent_fp}/min)"))
    return items


def _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone):
    """Hardware signals — cores, memory, pixel ratio, color depth (Phase 6)."""
    items = []
    cores = safe_int(fp.get("hardwareConcurrency"), -1, max_val=256)
    memory = safe_float(fp.get("deviceMemory"), -1, max_val=1024)
    pixel_ratio = safe_float(screen_dict.get("pixelRatio"), -1, max_val=100)
    color_depth = safe_int(screen_dict.get("colorDepth"), -1, max_val=64)

    if cores == 0:
        if not is_privacy_browser and "firefox" not in ua:
            items.append(("CORES_ZERO", "medium", 40, "hardwareConcurrency=0 (impossible)"))
    elif cores == 1:
        items.append(("CORES_LOW", "low", 15, "Single-core device (low-end or emulator)"))
    elif cores > 128:
        items.append(("ABSURD_CORES", "high", 60, f"hardwareConcurrency={cores} (spoofed)"))

    if 0 <= memory < 0.25:
        items.append(("LOW_MEMORY", "low", 15, f"deviceMemory={memory}GB"))

    if is_mobile_phone and pixel_ratio == 1:
        items.append((
            "MOBILE_PIXEL_RATIO", "medium", 40,
            "Mobile UA + pixelRatio=1 (desktop spoof)",
        ))

    if 0 <= color_depth < 24:
        items.append(("LOW_COLOR_DEPTH", "low", 20, f"colorDepth={color_depth} (headless?)"))

    return items


def _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile):
    """Screen sanity — headless viewport, zero viewport, absurd dimensions."""
    items = []
    screen_w = safe_int(screen_dict.get("width"), 0)
    avail_w = safe_int(screen_dict.get("availWidth"), 0)
    avail_h = safe_int(screen_dict.get("availHeight"), 0)

    if avail_w == 800 and avail_h == 600:
        items.append(("HEADLESS_VIEWPORT", "high", 70, "Default 800x600 headless viewport"))

    if avail_w == 0 or avail_h == 0:
        items.append(("VIEWPORT_ZERO", "medium", 50, "Viewport is 0x0 (headless)"))

    if is_mobile_phone and screen_w > 1920:
        items.append((
            "MOBILE_WIDE_SCREEN", "medium", 50,
            f"Mobile UA + {screen_w}px wide screen",
        ))

    if is_tablet and screen_w > 3840:
        items.append((
            "TABLET_WIDE_SCREEN", "medium", 40,
            f"Tablet UA + {screen_w}px screen",
        ))

    if is_desktop_chrome and not is_mobile and 0 < screen_w < 1024:
        items.append((
            "SCREEN_TINY", "medium", 30,
            f"Desktop Chrome + {screen_w}px screen (headless/VNC)",
        ))

    return items


def _check_os_mismatch(ua, platform):
    """OS mismatch (soft) — UA vs platform."""
    items = []
    if not platform:
        return items
    if ("windows nt" in ua
            and "win" not in platform
            and "linux" not in platform
            and "x11" not in platform):
        items.append((
            "OS_MISMATCH_WIN", "medium", 50,
            f"Windows UA + platform {_safe_str(platform, 30)}",
        ))
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        items.append((
            "OS_MISMATCH_MAC", "medium", 50,
            f"macOS UA + platform {_safe_str(platform, 30)}",
        ))
    return items


def _check_timezone(fp, country_code, is_privacy_browser):
    """Timezone vs country match."""
    items = []
    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        if not is_privacy_browser:
            items.append(("UTC_TZ", "low", 20, "UTC/Unknown timezone"))
    elif country_code in TZ_BY_COUNTRY_CODE:
        expected_tzs = TZ_BY_COUNTRY_CODE[country_code]
        if tz not in expected_tzs:
            items.append((
                "TZ_MISMATCH", "medium", 60,
                f"IP country {country_code} vs TZ {_safe_str(tz, 40)}",
            ))
    return items


def _check_behavior(behavior, events):
    """Behavior signals — time on page, mouse, zombie."""
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)
    send_reason = str(behavior.get("send_reason") or "unknown").lower()

    # LEFT_FAST — Phase 6 fix: differentiate visibility-hidden vs unload
    if t_on_page < 1800:
        if send_reason == "hidden":
            items.append((
                "LEFT_FAST_HIDDEN", "low", 15,
                f"Hidden after {t_on_page}ms (user switched tab)",
            ))
        else:
            items.append(("LEFT_FAST", "medium", 40, f"Left after {t_on_page}ms"))

    # Mouse trajectory
    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse_analysis = (
        not mouse_analysis.get("too_few", True)
        and "total_points" in mouse_analysis
    )

    if has_mouse_analysis:
        tp = safe_int(mouse_analysis.get("total_points"), 0)
        dv = safe_float(mouse_analysis.get("velocity_variance"), 0)
        dc = safe_int(mouse_analysis.get("direction_changes"), 0)
        mc = safe_float(mouse_analysis.get("mean_curvature"), 0)

        if tp > 20 and dv < 0.01 and dc < 2:
            items.append((
                "ROBOTIC_LINEAR", "high", 60,
                f"Linear motion ({dc} turns, var={dv:.4f})",
            ))
        elif tp > 20 and mc < 0.001 and dc < 3:
            items.append((
                "ROBOTIC_CURVATURE", "medium", 40,
                f"Zero curvature (mc={mc:.4f})",
            ))
    else:
        mv = safe_float(behavior.get("mouse_variance"), 0.0)
        if mousemove > 10 and mv < 1.5:
            items.append((
                "ROBOTIC_VARIANCE", "medium", 50,
                f"Low mouse variance ({mv:.2f})",
            ))

    # Zombie
    has_any_interaction = (
        mousemove > 5
        or safe_int(events.get("touchstart"), 0) > 0
        or scrolls > 0
        or clicks > 0
    )
    if t_on_page > 8000 and not has_any_interaction:
        items.append(("ZOMBIE", "low", 30, f"No interaction after {t_on_page}ms"))

    return items


def _check_webgl(webgl):
    """WebGL — software/virtual renderer detection."""
    items = []
    renderer = str(webgl.get("renderer") or "").lower()
    vendor = str(webgl.get("vendor") or "").lower()

    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        known_vendors = ("intel", "nvidia", "amd", "microsoft", "google", "apple")
        if any(v in vendor for v in known_vendors):
            items.append((
                "SOFT_RENDERER", "low", 20,
                f"Software renderer ({_safe_str(vendor, 30)})",
            ))
        else:
            items.append(("SOFT_RENDERER", "medium", 60, "Virtual renderer (no vendor)"))

    return items


def _check_cpm(nav, ua, privacy_name):
    """Phase 5/6 — CPM signals (wasted impressions)."""
    items = []
    if privacy_name in ("Brave", "Brave(heuristic)") or nav.get("is_brave") is True:
        items.append((
            "CPM_BRAVE", "low", 15,
            f"{privacy_name or 'Brave'} user (built-in ad block)",
        ))

    _adblock_uas = ("firefox focus", "duckduckgo", "opera mini", "brave")
    for _abu in _adblock_uas:
        if _abu in ua and _abu != "brave":
            items.append((
                "CPM_ADBLOCK_BROWSER", "low", 10,
                f"AdBlock-heavy browser: {_safe_str(_abu, 30)}",
            ))
            break

    return items


def _check_human(behavior, events):
    """Human signals (negative scores)."""
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)

    if mousemove > 50 and scrolls > 5 and clicks > 2 and t_on_page > 15000:
        items.append((
            "HUMAN_RICH_INTERACTION", "human", -30,
            f"Rich interaction ({mousemove}mm, {scrolls}sc, {clicks}cl, {t_on_page}ms)",
        ))

    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse_analysis = (
        not mouse_analysis.get("too_few", True)
        and "total_points" in mouse_analysis
    )

    if has_mouse_analysis:
        if (safe_float(mouse_analysis.get("velocity_variance"), 0) > 0.1
                and safe_int(mouse_analysis.get("direction_changes"), 0) > 5
                and safe_float(mouse_analysis.get("mean_curvature"), 0) > 0.01):
            items.append((
                "HUMAN_NATURAL_MOUSE", "human", -20,
                "Natural mouse trajectory",
            ))

    if t_on_page > 30000 and (mousemove > 10 or touchstart > 0 or scrolls > 0):
        items.append((
            "HUMAN_LONG_ENGAGEMENT", "human", -15,
            f"Long engagement ({t_on_page}ms)",
        ))

    return items


# =========================================================
# ANALYZE VISIT — Orchestrator
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    """
    محرك الحكم — Phase 6 refactored orchestrator.

    كل التحقق في _check_* functions. هنا بس بنجمع النتائج.
    """
    ev = EvidenceCollector()

    # ===== Defensive dict extraction =====
    nav = _safe_dict(data.get("nav"))
    fp = _safe_dict(data.get("fingerprint"))
    behavior = _safe_dict(data.get("behavior"))
    events = _safe_dict(behavior.get("events"))
    webgl = _safe_dict(fp.get("webgl"))
    plugins_info = _safe_dict(fp.get("plugins"))
    screen_dict = _safe_dict(data.get("screen"))
    sec = _safe_dict(ip_info.get("security"))

    ua = str(nav.get("ua") or "").lower()
    platform = str(nav.get("platform") or "").lower()

    # ===== UA classification =====
    is_ios = "iphone" in ua or "ipad" in ua or "ipod" in ua
    is_mobile = "mobile" in ua or "android" in ua
    is_tablet = "ipad" in ua or "tablet" in ua
    is_mobile_phone = ("mobile" in ua) and not is_tablet
    is_desktop_chrome = (
        "chrome" in ua
        and not is_mobile
        and not is_ios
        and "headless" not in ua
        and "edg/" not in ua
        and "opr/" not in ua
    )

    # ===== Privacy browser =====
    is_privacy_browser, privacy_name = _detect_privacy_browser(ua, platform, fp, nav)

    # ===== Derived flags =====
    chrome_check = fp.get("chrome_check", "")
    asn_value = safe_asn(ip_info.get("asn", ""))
    if asn_value and not asn_value.upper().startswith("AS"):
        asn_value = "AS" + asn_value
    is_proxy = sec.get("proxy") is True
    is_hosting = (
        sec.get("hosting") is True
        or str(ip_info.get("type", "")).lower() == "hosting"
    )
    country_code = str(ip_info.get("country_code") or "").upper()

    # ===== Collect signals =====
    _apply_items(ev, _check_critical(nav, fp, ua, platform, chrome_check))

    if _is_bot_ua(ua):
        ev.risk("BOT_UA", "high", 90, f"Suspicious UA: {_safe_str(ua[:60], 60)}")

    _apply_items(ev, _check_network(ip_info, data, asn_value, is_proxy, is_hosting))
    _apply_items(ev, _check_fingerprint(
        fp, plugins_info, is_desktop_chrome, is_privacy_browser, chrome_check, ua,
    ))
    _apply_items(ev, _check_fingerprint_reuse(data))
    _apply_items(ev, _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone))
    _apply_items(ev, _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile))
    _apply_items(ev, _check_os_mismatch(ua, platform))
    _apply_items(ev, _check_timezone(fp, country_code, is_privacy_browser))
    _apply_items(ev, _check_behavior(behavior, events))
    _apply_items(ev, _check_webgl(webgl))
    _apply_items(ev, _check_cpm(nav, ua, privacy_name))
    _apply_items(ev, _check_human(behavior, events))

    # ===== VERDICT =====
    raw = ev.raw_score()
    final = ev.final_score()
    confidence = calc_confidence(ev.items)
    categories = ev.counts()

    if ev.has_critical():
        verdict = "invalid"
    elif final >= 80:
        verdict = "invalid"
    elif final >= 40:
        verdict = "suspicious"
    else:
        verdict = "valid"

    cpm_quality = compute_cpm_quality(ev.items, verdict)
    wasted = is_wasted_impression(ev.items, verdict)

    return {
        "raw_score": raw,
        "score": final,
        "final_score": final,
        "verdict": verdict,
        "confidence": confidence,
        "evidence": ev.items,
        "categories": categories,
        "privacy_browser": privacy_name or None,
        "cpm_quality": cpm_quality,
        "wasted_impression": wasted,
    }