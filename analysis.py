"""
analysis.py — OVG Tracker — The Brain (v3.1 Accuracy Boost)

v3.1 changes:
  - Data Quality Gate (legacy/failed → unknown verdict)
  - 8 new detection signals (speech_voices, webgl_precision, isTrusted, ua_brands, connection)
  - Relaxed 8 signals that caused false positives (DRIVE_BY, TZ_MISMATCH, AD_HIDDEN, etc.)
  - Expanded DATACENTER_ASNS (60+ providers)
  - Added HeadlessChrome, PhantomJS, Splinter to BOT_UA_PATTERNS

SYSTEM 1 INTEGRATION (v9.2):
  - All 20 checks wrapped in circuit breakers (collector.circuit_breaker)
  - Single check failure never crashes the analysis pipeline
  - Self-tests run automatically on import

SYSTEM 2 INTEGRATION (v9.3):
  - Verdict determined by Bayesian probability, not score sum
  - 5 weak signals no longer equal 1 strong signal
  - IMPOSSIBLE severity overrides everything → invalid
  - CRITICAL signal floors verdict at suspicious (never valid)
  - Returns new fields: probability, log_odds, bayesian_confidence, safety_triggered
  - Self-tests run automatically on import
"""
import os
import re
import ipaddress
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip
from collector.circuit_breaker import (
    safe_call as cb_safe_call,
    breakers as cb_breakers,
    health_status as cb_health_status,
)
from collector.bayesian_engine import (
    bayesian_evaluate as bayes_evaluate,
    compute_probability as bayes_compute,
    health_status as bayes_health_status,
)


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


def _safe_list(val):
    return val if isinstance(val, list) else []


def _safe_str(val, max_len=200):
    if val is None:
        return ""
    s = str(val)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    s = s.replace("<", "").replace(">", "")
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s


def _duration_ms(behavior):
    """Get duration from behavior — supports v2 (time_on_page_ms) and v3 (total_time_ms)."""
    t = safe_int(behavior.get("time_on_page_ms"), 0)
    if t == 0:
        t = safe_int(behavior.get("total_time_ms"), 0)
    return t


def _mouse_points_count(behavior):
    """v2 uses mouse_analysis.total_points; v3 uses mouse_points list length."""
    ma = _safe_dict(behavior.get("mouse_analysis"))
    if not ma.get("too_few", True):
        return safe_int(ma.get("total_points"), 0)
    pts = _safe_list(behavior.get("mouse_points"))
    return len(pts)


# =========================================================
# BOT UA PATTERNS (v3.1 — expanded)
# =========================================================
BOT_UA_PATTERNS = (
    # CLI/HTTP clients
    "curl", "wget", "httpie",
    "python-requests", "requests/",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "undici",
    "httpclient", "libwww", "restsharp",
    # Automation
    "headless", "headlesschrome", "headless_chrome",
    "selenium", "phantomjs", "phantom", "puppeteer", "playwright",
    "splinter", "mechanize", "splash", "scrapinghub",
    # Libraries
    "scrapy", "guzzle", "httpx", "aiohttp", "urllib",
    # Tools
    "postman", "insomnia", "apitester", "http_request",
    "automated", "automation",
    # SEO crawlers
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot",
    "petalbot", "bytespider", "gptbot", "claudebot",
    "ccbot", "yandexbot", "slurp", "bingpreview",
    "facebookexternalhit", "linkedinbot", "twitterbot",
    "duckduckbot", "applebot",
    "googlebot", "google-inspectiontool", "adsbot-google",
    "mediapartners-google", "bingbot", "msnbot",
    "baiduspider", "sogou", "exabot", "ia_archiver",
)

BOT_UA_WORDS_RE = re.compile(r"\bpython\b", re.IGNORECASE)
BOT_WORD_RE = re.compile(r"\b(bot|bots|spider|crawler|robot|scraper)\b", re.IGNORECASE)
HEADLESS_UA_RE = re.compile(r"headless(?:chrome|_chrome|firefox)?", re.IGNORECASE)


def _is_bot_ua(ua: str) -> bool:
    """Legacy bot UA check — used only if critical headless not detected."""
    if not ua:
        return False  # v3.1: empty UA is handled separately (not auto-bot)
    ua_lower = ua.lower()
    if any(x in ua_lower for x in BOT_UA_PATTERNS):
        return True
    if BOT_UA_WORDS_RE.search(ua):
        return True
    if BOT_WORD_RE.search(ua):
        return True
    return False


def _is_headless_ua(ua: str) -> bool:
    """v3.1 — explicit headless UA check (critical, not just 'suspicious')."""
    if not ua:
        return False
    return bool(HEADLESS_UA_RE.search(ua))


# =========================================================
# DATACENTER ASNs (v3.1 — expanded to 60+)
# =========================================================
DATACENTER_ASNS = frozenset([
    # AWS
    "AS16509", "AS14618", "AS8987",
    # Google Cloud
    "AS396982", "AS15169", "AS19527",
    # Azure
    "AS8075", "AS8068", "AS8069",
    # Cloudflare
    "AS13335", "AS209242",
    # Akamai
    "AS20940", "AS16625", "AS21342", "AS16702",
    # Fastly
    "AS54113", "AS394192",
    # DigitalOcean
    "AS14061", "AS393406",
    # Linode
    "AS63949", "AS48337",
    # Vultr/Choopa
    "AS20473", "AS3223",
    # Hetzner
    "AS24940", "AS213230",
    # OVH
    "AS16276", "AS35540",
    # Oracle Cloud
    "AS31898", "AS7160",
    # Alibaba
    "AS45102", "AS37963", "AS24429",
    # Tencent
    "AS132203", "AS45090",
    # Huawei
    "AS136907", "AS55990",
    # Hostinger
    "AS47583", "AS199524",
    # Contabo
    "AS51167", "AS141995",
    # Scaleway/Online.net
    "AS12876", "AS29447",
    # IONOS/1&1
    "AS8560", "AS15418",
    # GoDaddy
    "AS26496", "AS398101",
    # Namecheap
    "AS22612",
    # Bluehost
    "AS11798", "AS46606",
    # HostGator
    "AS19871",
    # Rackspace
    "AS19994", "AS33070",
    # Other known
    "AS60781", "AS394711", "AS9009", "AS62838", "AS200373", "AS9002",
    "AS49505", "AS208046", "AS40676", "AS53667", "AS59711",
    "AS29802", "AS63023", "AS212238", "AS9312", "AS35916",
    "AS21859", "AS36352", "AS209854", "AS3462", "AS6079",
    "AS197540", "AS197695", "AS7506", "AS16265", "AS20454",
])


TZ_BY_COUNTRY_CODE = {
    "EG": {"africa/cairo"}, "SA": {"asia/riyadh"}, "AE": {"asia/dubai"},
    "KW": {"asia/kuwait"}, "QA": {"asia/qatar"}, "BH": {"asia/bahrain"},
    "OM": {"asia/muscat"}, "JO": {"asia/amman"}, "LB": {"asia/beirut"},
    "SY": {"asia/damascus"}, "IQ": {"asia/baghdad"}, "YE": {"asia/aden"},
    "PS": {"asia/gaza", "asia/hebron"},
    "TR": {"europe/istanbul", "asia/istanbul"},
    "IL": {"asia/jerusalem", "asia/tel_aviv"},
    "IR": {"asia/tehran"},
    "MA": {"africa/casablanca"}, "DZ": {"africa/algiers"},
    "TN": {"africa/tunis"}, "LY": {"africa/tripoli"}, "SD": {"africa/khartoum"},
    "GB": {"europe/london"}, "IE": {"europe/dublin"},
    "IT": {"europe/rome", "europe/milan"},
    "DE": {"europe/berlin", "europe/frankfurt"},
    "FR": {"europe/paris"},
    "ES": {"europe/madrid", "africa/ceuta"},
    "PT": {"europe/lisbon", "atlantic/azores"},
    "NL": {"europe/amsterdam"}, "BE": {"europe/brussels"},
    "CH": {"europe/zurich"}, "AT": {"europe/vienna"},
    "SE": {"europe/stockholm"}, "NO": {"europe/oslo"},
    "DK": {"europe/copenhagen"}, "FI": {"europe/helsinki"},
    "PL": {"europe/warsaw"}, "CZ": {"europe/prague"},
    "RO": {"europe/bucharest"}, "GR": {"europe/athens"},
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
    "MX": {"america/mexico_city", "america/tijuana", "america/cancun",
           "america/monterrey", "america/chihuahua"},
    "BR": {"america/sao_paulo", "america/rio_branco", "america/manaus",
           "america/belem", "america/fortaleza", "america/recife",
           "america/noronha"},
    "AR": {"america/argentina/buenos_aires", "america/argentina/cordoba"},
    "CO": {"america/bogota"}, "CL": {"america/santiago", "pacific/easter"},
    "PE": {"america/lima"}, "VE": {"america/caracas"},
    "IN": {"asia/kolkata", "asia/calcutta"},
    "JP": {"asia/tokyo"},
    "CN": {"asia/shanghai", "asia/beijing", "asia/chongqing"},
    "HK": {"asia/hong_kong"}, "KR": {"asia/seoul"}, "TW": {"asia/taipei"},
    "TH": {"asia/bangkok"}, "VN": {"asia/ho_chi_minh"},
    "MY": {"asia/kuala_lumpur"}, "SG": {"asia/singapore"},
    "ID": {"asia/jakarta", "asia/makassar", "asia/jayapura"},
    "PH": {"asia/manila"},
    "PK": {"asia/karachi", "asia/lahore"},
    "BD": {"asia/dhaka"}, "LK": {"asia/colombo"}, "AF": {"asia/kabul"},
    "NG": {"africa/lagos"}, "KE": {"africa/nairobi"}, "GH": {"africa/accra"},
    "ZA": {"africa/johannesburg", "africa/cape_town"},
    "ET": {"africa/addis_ababa"},
    "AU": {"australia/sydney", "australia/melbourne", "australia/brisbane",
           "australia/perth", "australia/adelaide", "australia/hobart",
           "australia/darwin"},
    "NZ": {"pacific/auckland"},
}


LANG_COUNTRY_MAP = {
    "ar": {"EG", "SA", "AE", "KW", "QA", "BH", "OM", "JO", "LB", "SY",
           "IQ", "YE", "PS", "MA", "DZ", "TN", "LY", "SD"},
    "es": {"ES", "MX", "AR", "CO", "CL", "PE", "VE"},
    "fr": {"FR", "BE", "CH", "CA"},
    "de": {"DE", "AT", "CH"},
    "pt": {"PT", "BR"},
    "ru": {"RU", "BY", "KZ"},
    "zh": {"CN", "TW", "HK", "SG"},
    "ja": {"JP"}, "ko": {"KR"}, "hi": {"IN"}, "tr": {"TR"},
    "it": {"IT"}, "nl": {"NL", "BE"}, "pl": {"PL"},
    "vi": {"VN"}, "th": {"TH"}, "id": {"ID"},
    "ms": {"MY", "SG"}, "fa": {"IR", "AF"}, "he": {"IL"},
}

_STRONG_LANG_COUNTRIES = {
    "EG", "SA", "AE", "KW", "QA", "BH", "OM", "JO", "LB", "SY",
    "IQ", "YE", "PS", "MA", "DZ", "TN", "LY", "SD",
    "RU", "CN", "JP", "KR", "IR", "TR", "IL", "TH", "VN", "ID",
}


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
        import httpx
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
    import secrets
    return secrets.token_hex(8)


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


VALID_SEVERITIES = frozenset(["critical", "high", "medium", "low", "human"])
VALID_VERDICTS = frozenset(["valid", "invalid", "suspicious", "unknown"])


class EvidenceCollector:
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
    for code, sev, score, detail in items:
        if sev == "human":
            ev.human(code, abs(score), detail)
        else:
            ev.risk(code, sev, score, detail)


def calc_confidence(signals: list) -> float:
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
                "code": "LEGACY_SIGNAL", "severity": "medium",
                "score": 0, "detail": e,
            })
    return result


_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])
_PREMIUM_HUMAN_CODES = frozenset(["HUMAN_NATURAL_MOUSE", "HUMAN_RICH_INTERACTION"])
_PREMIUM_EXTRA_CODES = frozenset(["HUMAN_LONG_ENGAGEMENT"])


def compute_cpm_quality(evidence_items: list, verdict: str) -> str:
    if verdict == "invalid":
        return "invalid"
    if verdict == "unknown":
        return "unknown"
    codes = {e.get("code") for e in evidence_items
             if isinstance(e, dict) and e.get("code")}
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
    codes = {e.get("code") for e in evidence_items
             if isinstance(e, dict) and e.get("code")}
    return bool(codes & _WASTED_CODES)


# =========================================================
# EXPLAINABILITY (v3.1 — new codes added)
# =========================================================
CODE_TO_SOURCE = {
    # ===== Critical =====
    "WEBDRIVER_FLAG": "critical", "CDP_DETECTED": "critical",
    "WINDOWS_UA_LINUX": "critical", "FIREFOX_CHROME_OBJ": "critical",
    "HEADLESS_UA": "critical",
    "UNTRUSTED_CLICK": "critical",
    "HONEYPOT_CLICK": "honeypot", "HONEYPOT_FORM_FILL": "honeypot",
    "IMPOSSIBLE_SPEED": "behavior_deep",
    # ===== Automation =====
    "PUPPETEER_DETECTED": "automation", "PLAYWRIGHT_DETECTED": "automation",
    "SELENIUM_DETECTED": "automation", "NIGHTMARE_DETECTED": "automation",
    "PHANTOM_DETECTED": "automation",
    # ===== UA =====
    "BOT_UA": "ua",
    # ===== Network =====
    "VPN_DATACENTER": "network", "DATACENTER_IP": "network",
    "VPN_PROXY": "network", "DATACENTER_ASN": "network",
    "WEBRTC_LEAK": "network", "WEBRTC_VPN_DIFF": "network",
    # ===== Fingerprint =====
    "PLUGINS_ZERO": "fingerprint", "CHROME_NO_OBJ": "fingerprint",
    "CANVAS_BLOCKED": "fingerprint", "CANVAS_MISSING": "fingerprint",
    "LANGUAGES_EMPTY": "fingerprint", "SINGLE_LANG": "fingerprint",
    "NO_MIME_TYPES": "fingerprint", "NO_PDF_VIEWER": "fingerprint",
    "SPEECH_VOICES_ZERO": "fingerprint",
    "WEBGL_PRECISION_ZERO": "fingerprint",
    "UA_BRANDS_MISMATCH": "fingerprint",
    # ===== Fingerprint reuse =====
    "FINGERPRINT_REUSE_HIGH": "fingerprint_reuse",
    "FINGERPRINT_REUSE_MED": "fingerprint_reuse",
    "FINGERPRINT_REUSE_LOW": "fingerprint_reuse",
    # ===== Cross-visit =====
    "IP_VELOCITY_HIGH": "cross_visit", "IP_VELOCITY_MED": "cross_visit",
    "FINGERPRINT_MULTI_IP": "cross_visit", "IP_MULTI_FINGERPRINT": "cross_visit",
    # ===== Hardware =====
    "CORES_ZERO": "hardware", "CORES_LOW": "hardware",
    "ABSURD_CORES": "hardware", "LOW_MEMORY": "hardware",
    "CPU_MEMORY_MISMATCH": "hardware", "MOBILE_PIXEL_RATIO": "hardware",
    "LOW_COLOR_DEPTH": "hardware",
    # ===== Screen =====
    "HEADLESS_VIEWPORT": "screen", "VIEWPORT_ZERO": "screen",
    "MOBILE_WIDE_SCREEN": "screen", "TABLET_WIDE_SCREEN": "screen",
    "SCREEN_TINY": "screen", "INNER_WIDER_THAN_SCREEN": "screen",
    "INNER_TALLER_THAN_SCREEN": "screen",
    # ===== OS =====
    "OS_MISMATCH_WIN": "os", "OS_MISMATCH_MAC": "os",
    # ===== Contradictions =====
    "TOUCH_UA_MISMATCH": "contradictions", "FIRST_LANG_MISMATCH": "contradictions",
    "INTL_LOCALE_MISMATCH": "contradictions",
    "WEBGL_VENDOR_RENDERER_MISMATCH": "contradictions",
    "UA_CHROME_OLD": "contradictions", "UA_CHROME_FUTURE": "contradictions",
    "CLIENT_HINTS_MISMATCH": "contradictions",
    # ===== Locale =====
    "LANG_COUNTRY_MISMATCH": "locale",
    # ===== Timezone =====
    "UTC_TZ": "timezone", "TZ_MISMATCH": "timezone",
    # ===== Behavior =====
    "LEFT_FAST": "behavior", "LEFT_FAST_HIDDEN": "behavior",
    "ROBOTIC_LINEAR": "behavior", "ROBOTIC_CURVATURE": "behavior",
    "ROBOTIC_VARIANCE": "behavior", "ZOMBIE": "behavior",
    "SCROLL_LINEAR": "behavior", "MOUSE_TOO_SMOOTH": "behavior",
    # ===== Behavior deep =====
    "INSTANT_FIRST_MOVE": "behavior_deep", "CLICK_BEFORE_MOVE": "behavior_deep",
    "IDLE_VISIBLE": "behavior_deep", "RAPID_REPEAT_CLICKS": "behavior_deep",
    "ENGAGEMENT_ZERO": "behavior_deep", "ENGAGEMENT_VERY_LOW": "behavior_deep",
    "FIRST_30S_BURST": "behavior_deep", "ZOMBIE_60S": "behavior_deep",
    "NO_MOUSE_NO_TOUCH": "behavior_deep",
    # ===== WebGL =====
    "SOFT_RENDERER": "webgl",
    # ===== Session =====
    "SILENT_AFTER_INITIAL": "session", "HEARTBEAT_GAP": "session",
    "DRIVE_BY": "session", "CLOCK_DRIFT": "session",
    # ===== Ad events =====
    "AD_HIDDEN_AFTER_LOAD": "ad_events",
    # ===== Milestones =====
    "INTERACTION_BEFORE_PAINT": "milestones",
    # ===== Connection =====
    "CONNECTION_RTT_ZERO": "connection",
    # ===== CPM =====
    "CPM_BRAVE": "cpm", "CPM_ADBLOCK_BROWSER": "cpm",
    # ===== Human =====
    "HUMAN_RICH_INTERACTION": "human", "HUMAN_NATURAL_MOUSE": "human",
    "HUMAN_LONG_ENGAGEMENT": "human", "HUMAN_DEEP_SCROLL": "human",
    "HUMAN_KEYBOARD": "human", "HUMAN_ENGAGED": "human",
    # ===== Meta =====
    "LEGACY_SIGNAL": "legacy", "MOCK_SIGNAL": "mock",
    "DATA_LEGACY": "data_quality", "DATA_INSUFFICIENT": "data_quality",
}


def build_explainability_trace(evidence_items):
    if not evidence_items:
        return []
    trace = []
    running = 0
    step = 0
    for e in evidence_items:
        if isinstance(e, dict):
            code = e.get("code", "UNKNOWN")
            sev = e.get("severity", "medium")
            score = int(e.get("score", 0) or 0)
            detail = e.get("detail", "")
        elif isinstance(e, str):
            code = "LEGACY_SIGNAL"
            sev = "medium"
            score = 0
            detail = e
        else:
            continue
        step += 1
        running += score
        trace.append({
            "step": step,
            "code": _safe_str(code, 50),
            "source": CODE_TO_SOURCE.get(code, "unknown"),
            "severity": sev,
            "score": score,
            "running_total": running,
            "detail": _safe_str(detail, 200),
        })
    return trace


# =========================================================
# SIGNAL CHECKS
# =========================================================
def _check_critical(nav, fp, ua, platform, chrome_check):
    items = []

    # Headless UA (v3.1 — critical)
    if _is_headless_ua(ua):
        items.append(("HEADLESS_UA", "critical", 100,
                      f"Headless UA detected: {_safe_str(ua[:60], 60)}"))

    # Untrusted click (v3.1 — critical)
    untrusted = safe_int(fp.get("_untrusted_clicks"), 0)
    if untrusted >= 1:
        items.append(("UNTRUSTED_CLICK", "critical", 100,
                      f"{untrusted} click(s) with isTrusted=false (JS-injected)"))

    if nav.get("webdriver") is True:
        items.append(("WEBDRIVER_FLAG", "critical", 80, "navigator.webdriver === true"))

    if fp.get("cdp_detected") is True:
        items.append(("CDP_DETECTED", "critical", 100, "CDP Runtime Detected"))

    if "windows nt" in ua and platform and ("linux" in platform or "x11" in platform):
        items.append(("WINDOWS_UA_LINUX", "critical", 100,
                      f"Windows UA + Linux platform ({_safe_str(platform, 30)})"))

    if "firefox" in ua and chrome_check == "full":
        items.append(("FIREFOX_CHROME_OBJ", "critical", 80,
                      "Firefox UA + window.chrome (impossible)"))

    return items


def _check_automation_globals(fp):
    items = []
    automation = _safe_dict(fp.get("automation"))
    if automation.get("puppeteer") is True:
        items.append(("PUPPETEER_DETECTED", "critical", 100, "__puppeteer_evaluation_script__ present"))
    if automation.get("playwright") is True:
        items.append(("PLAYWRIGHT_DETECTED", "critical", 100, "__playwright_* globals present"))
    if automation.get("selenium") is True or automation.get("cdc") is True:
        items.append(("SELENIUM_DETECTED", "critical", 100, "Selenium CDP identifiers present"))
    if automation.get("nightmare") is True:
        items.append(("NIGHTMARE_DETECTED", "critical", 100, "__nightmare present"))
    if automation.get("phantom") is True:
        items.append(("PHANTOM_DETECTED", "critical", 100, "PhantomJS globals present"))
    return items


def _check_network(ip_info, data, asn_value, is_proxy, is_hosting):
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

    mime_count = safe_int(fp.get("mime_types_count"), -1)
    if is_desktop_chrome and not is_privacy_browser and mime_count == 0:
        items.append(("NO_MIME_TYPES", "medium", 40, "Chrome desktop: 0 navigator.mimeTypes"))

    pdf_viewer = fp.get("pdf_viewer")
    if is_desktop_chrome and not is_privacy_browser and pdf_viewer is False:
        items.append(("NO_PDF_VIEWER", "low", 15, "Chrome desktop: pdfViewerEnabled=false"))

    # v3.1 — speech voices (headless = 0)
    speech = fp.get("speech_voices")
    if speech is not None:
        sv = safe_int(speech, -1)
        if sv == 0 and not is_privacy_browser:
            items.append(("SPEECH_VOICES_ZERO", "high", 70,
                          "speechSynthesis.getVoices() = 0 (headless/bot indicator)"))

    # v3.1 — WebGL precision (headless = 0/-1)
    wgp = _safe_dict(fp.get("webgl_precision"))
    if wgp:
        hf = safe_int(wgp.get("high_float"), -99)
        if hf in (0, -1) and not is_privacy_browser:
            items.append(("WEBGL_PRECISION_ZERO", "high", 60,
                          f"WebGL high_float precision = {hf} (headless)"))

    return items


def _check_fingerprint_reuse(data):
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


def _check_cross_visit(data):
    items = []
    same_ip = safe_int(data.get("_same_ip_last_minute"), 0)
    canvas_ips = safe_int(data.get("_same_canvas_ip_count"), 0)
    ip_canvases = safe_int(data.get("_same_ip_canvas_count"), 0)
    if same_ip >= 10:
        items.append(("IP_VELOCITY_HIGH", "high", 70, f"Same IP: {same_ip} visits/min"))
    elif same_ip >= 5:
        items.append(("IP_VELOCITY_MED", "medium", 40, f"Same IP: {same_ip} visits/min"))
    if canvas_ips >= 5:
        items.append(("FINGERPRINT_MULTI_IP", "high", 60, f"Same canvas from {canvas_ips} distinct IPs/hour"))
    elif canvas_ips >= 3:
        items.append(("FINGERPRINT_MULTI_IP", "medium", 40, f"Same canvas from {canvas_ips} distinct IPs/hour"))
    if ip_canvases >= 10:
        items.append(("IP_MULTI_FINGERPRINT", "high", 70, f"Same IP with {ip_canvases} distinct canvases/hour"))
    elif ip_canvases >= 5:
        items.append(("IP_MULTI_FINGERPRINT", "medium", 40, f"Same IP with {ip_canvases} distinct canvases/hour"))
    return items


def _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone):
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
    if cores >= 16 and 0 <= memory < 2:
        items.append(("CPU_MEMORY_MISMATCH", "medium", 40, f"{cores} cores but only {memory}GB RAM"))
    elif cores >= 8 and 0 <= memory < 1:
        items.append(("CPU_MEMORY_MISMATCH", "medium", 40, f"{cores} cores but only {memory}GB RAM"))

    if is_mobile_phone and pixel_ratio == 1:
        items.append(("MOBILE_PIXEL_RATIO", "medium", 40, "Mobile UA + pixelRatio=1 (desktop spoof)"))

    if 0 <= color_depth < 24:
        items.append(("LOW_COLOR_DEPTH", "low", 20, f"colorDepth={color_depth} (headless?)"))

    return items


def _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile):
    items = []
    screen_w = safe_int(screen_dict.get("width"), 0)
    screen_h = safe_int(screen_dict.get("height"), 0)
    avail_w = safe_int(screen_dict.get("availWidth"), 0)
    avail_h = safe_int(screen_dict.get("availHeight"), 0)
    inner_w = safe_int(screen_dict.get("innerWidth"), 0)
    inner_h = safe_int(screen_dict.get("innerHeight"), 0)

    if avail_w == 800 and avail_h == 600:
        items.append(("HEADLESS_VIEWPORT", "high", 70, "Default 800x600 headless viewport"))

    if avail_w == 0 or avail_h == 0:
        items.append(("VIEWPORT_ZERO", "medium", 50, "Viewport is 0x0 (headless)"))

    if is_mobile_phone and screen_w > 1920:
        items.append(("MOBILE_WIDE_SCREEN", "medium", 50, f"Mobile UA + {screen_w}px wide screen"))

    if is_tablet and screen_w > 3840:
        items.append(("TABLET_WIDE_SCREEN", "medium", 40, f"Tablet UA + {screen_w}px screen"))

    # v3.1 — relaxed from < 1024 to < 800
    if is_desktop_chrome and not is_mobile and 0 < screen_w < 800:
        items.append(("SCREEN_TINY", "medium", 30, f"Desktop Chrome + {screen_w}px screen"))

    if screen_w > 0 and inner_w > 0:
        if inner_w > screen_w * 1.5:
            items.append(("INNER_WIDER_THAN_SCREEN", "medium", 40, f"innerWidth {inner_w} > 1.5× screen.width {screen_w}"))
        elif inner_w > screen_w:
            items.append(("INNER_WIDER_THAN_SCREEN", "low", 10, f"innerWidth {inner_w} > screen.width {screen_w} (zoom?)"))

    if screen_h > 0 and inner_h > 0:
        if inner_h > screen_h * 1.5:
            items.append(("INNER_TALLER_THAN_SCREEN", "medium", 40, f"innerHeight {inner_h} > 1.5× screen.height {screen_h}"))
        elif inner_h > screen_h:
            items.append(("INNER_TALLER_THAN_SCREEN", "low", 10, f"innerHeight {inner_h} > screen.height {screen_h} (zoom?)"))

    return items


def _check_os_mismatch(ua, platform):
    items = []
    if not platform:
        return items
    if ("windows nt" in ua
            and "win" not in platform
            and "linux" not in platform
            and "x11" not in platform):
        items.append(("OS_MISMATCH_WIN", "medium", 50, f"Windows UA + platform {_safe_str(platform, 30)}"))
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        items.append(("OS_MISMATCH_MAC", "medium", 50, f"macOS UA + platform {_safe_str(platform, 30)}"))
    return items


def _check_contradictions(nav, fp, screen_dict, ua, is_mobile, is_mobile_phone,
                           is_tablet, is_desktop_chrome, is_privacy_browser):
    items = []
    has_touch = nav.get("has_touch")
    max_touch = safe_int(nav.get("max_touch_points", nav.get("maxTouchPoints")), -1)

    if is_mobile_phone and has_touch is False:
        items.append(("TOUCH_UA_MISMATCH", "medium", 40, "Mobile UA but no touch support"))
    if is_mobile_phone and max_touch == 0:
        items.append(("TOUCH_UA_MISMATCH", "medium", 40, "Mobile UA but maxTouchPoints=0"))

    lang = str(nav.get("language") or "").strip()
    langs_raw = fp.get("languages")
    if lang and isinstance(langs_raw, list) and langs_raw:
        first_lang = str(langs_raw[0]).strip()
        if first_lang and first_lang.lower() != lang.lower():
            items.append(("FIRST_LANG_MISMATCH", "low", 15,
                          f"language={_safe_str(lang, 20)}, languages[0]={_safe_str(first_lang, 20)}"))

    intl_locale = str(fp.get("intl_locale") or "").strip()
    if intl_locale and lang:
        intl_primary = intl_locale.split("-")[0].lower()
        lang_primary = lang.split("-")[0].lower()
        if intl_primary and lang_primary and intl_primary != lang_primary:
            items.append(("INTL_LOCALE_MISMATCH", "low", 20,
                          f"Intl={_safe_str(intl_locale, 20)}, language={_safe_str(lang, 20)}"))

    webgl = _safe_dict(fp.get("webgl"))
    vendor = str(webgl.get("vendor") or "").lower()
    renderer = str(webgl.get("renderer") or "").lower()
    if vendor and renderer:
        mismatch = (
            ("nvidia" in vendor and ("intel" in renderer or "amd" in renderer)) or
            ("amd" in vendor and ("nvidia" in renderer or "intel" in renderer)) or
            ("intel" in vendor and ("nvidia" in renderer or "amd" in renderer))
        )
        if mismatch:
            items.append(("WEBGL_VENDOR_RENDERER_MISMATCH", "high", 50,
                          f"Vendor={_safe_str(vendor, 25)}, Renderer={_safe_str(renderer, 25)}"))

    chrome_match = re.search(r"Chrome/(\d+)", ua)
    if chrome_match:
        chrome_major = safe_int(chrome_match.group(1), 0)
        if 0 < chrome_major < 80:
            items.append(("UA_CHROME_OLD", "medium", 30, f"Chrome {chrome_major} (outdated template)"))
        elif chrome_major > 200:
            items.append(("UA_CHROME_FUTURE", "high", 60, f"Chrome {chrome_major} (future version, spoofed)"))

    ua_data = _safe_dict(nav.get("ua_data"))
    ua_data_mobile = ua_data.get("mobile")
    if ua_data_mobile is True and is_desktop_chrome:
        items.append(("CLIENT_HINTS_MISMATCH", "medium", 40, "userAgentData.mobile=true on desktop Chrome"))
    if ua_data_mobile is False and is_mobile_phone:
        items.append(("CLIENT_HINTS_MISMATCH", "medium", 40, "userAgentData.mobile=false but mobile UA"))

    # v3.1 — UA brands mismatch (headless shows "Chromium" not "Google Chrome")
    brands = _safe_list(fp.get("ua_brands"))
    if brands and "chrome" in ua and not is_mobile:
        has_google = any("Google Chrome" in str(b.get("brand", "")) for b in brands if isinstance(b, dict))
        has_chromium = any("Chromium" in str(b.get("brand", "")) for b in brands if isinstance(b, dict))
        if has_chromium and not has_google and "chrome/" in ua:
            items.append(("UA_BRANDS_MISMATCH", "medium", 40,
                          "UA says Chrome but brands only show Chromium (headless)"))

    return items


def _check_locale_consistency(nav, fp, country_code):
    items = []
    if not country_code or country_code not in _STRONG_LANG_COUNTRIES:
        return items
    lang = str(nav.get("language") or "").strip().lower()
    primary_lang = ""
    if lang:
        primary_lang = lang.split("-")[0]
    else:
        langs_raw = fp.get("languages")
        if isinstance(langs_raw, list) and langs_raw:
            primary_lang = str(langs_raw[0]).split("-")[0].lower()
    if not primary_lang:
        return items
    expected_countries = LANG_COUNTRY_MAP.get(primary_lang)
    if expected_countries and country_code not in expected_countries:
        items.append(("LANG_COUNTRY_MISMATCH", "low", 20,
                      f"Primary lang '{primary_lang}' but IP country {country_code}"))
    return items


def _check_timezone(fp, country_code, is_privacy_browser):
    items = []
    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        if not is_privacy_browser:
            items.append(("UTC_TZ", "low", 20, "UTC/Unknown timezone"))
    elif country_code in TZ_BY_COUNTRY_CODE:
        expected_tzs = TZ_BY_COUNTRY_CODE[country_code]
        if tz not in expected_tzs:
            # v3.1 — relaxed from +60 to +30 (VPN users are legit)
            items.append(("TZ_MISMATCH", "low", 30, f"IP country {country_code} vs TZ {_safe_str(tz, 40)}"))
    return items


def _check_behavior(behavior, events):
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    keydown = safe_int(events.get("keydown"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    t_on_page = _duration_ms(behavior)
    send_reason = str(behavior.get("send_reason") or "unknown").lower()

    if t_on_page > 0 and t_on_page < 1800:
        if send_reason == "hidden":
            items.append(("LEFT_FAST_HIDDEN", "low", 15, f"Hidden after {t_on_page}ms"))
        else:
            items.append(("LEFT_FAST", "medium", 40, f"Left after {t_on_page}ms"))

    # Mouse analysis (v2 + v3 compatible)
    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse_analysis = (
        not mouse_analysis.get("too_few", True)
        and "total_points" in mouse_analysis
    )
    has_v3_mouse = (
        "mouse_velocity_variance" in behavior
        and _mouse_points_count(behavior) >= 20
    )

    if has_mouse_analysis:
        tp = safe_int(mouse_analysis.get("total_points"), 0)
        dv = safe_float(mouse_analysis.get("velocity_variance"), 0)
        dc = safe_int(mouse_analysis.get("direction_changes"), 0)
        mc = safe_float(mouse_analysis.get("mean_curvature"), 0)
        if tp > 20 and dv < 0.01 and dc < 2:
            items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear motion ({dc} turns, var={dv:.4f})"))
        elif tp > 20 and mc < 0.001 and dc < 3:
            items.append(("ROBOTIC_CURVATURE", "medium", 40, f"Zero curvature (mc={mc:.4f})"))
    elif has_v3_mouse:
        tp = _mouse_points_count(behavior)
        dv = safe_float(behavior.get("mouse_velocity_variance"), 0)
        dc = safe_int(behavior.get("mouse_direction_changes"), 0)
        if tp > 20 and dv < 0.01 and dc < 2:
            items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear motion ({dc} turns, var={dv:.4f})"))
    else:
        mv = safe_float(behavior.get("mouse_variance"), 0.0)
        if mousemove > 10 and mv < 1.5:
            items.append(("ROBOTIC_VARIANCE", "medium", 50, f"Low mouse variance ({mv:.2f})"))

    has_any_interaction = (
        mousemove > 5
        or touchstart > 0
        or scrolls > 0
        or clicks > 0
    )
    if t_on_page > 8000 and not has_any_interaction:
        items.append(("ZOMBIE", "low", 30, f"No interaction after {t_on_page}ms"))

    return items


def _check_behavior_deep(behavior, events):
    items = []
    t_on_page = _duration_ms(behavior)
    first_move = safe_int(behavior.get("first_move_delay_ms"), -1)
    clicks_before_move = safe_int(behavior.get("clicks_before_move"), 0)
    visible_time = safe_int(behavior.get("visible_time_ms"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    mousemove = safe_int(events.get("mousemove"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    keydown = safe_int(events.get("keydown"), 0)

    if 0 <= first_move < 100 and mousemove > 0:
        items.append(("INSTANT_FIRST_MOVE", "medium", 30, f"First mousemove after {first_move}ms (scripted)"))

    if clicks_before_move > 0 and touchstart == 0:
        items.append(("CLICK_BEFORE_MOVE", "high", 60, f"{clicks_before_move} clicks before any mousemove"))

    if t_on_page > 5000 and visible_time > 0:
        ratio = visible_time / t_on_page
        if ratio > 0.98 and mousemove == 0 and clicks == 0 and scrolls == 0 and touchstart == 0:
            items.append(("IDLE_VISIBLE", "medium", 30, f"Visible {ratio*100:.0f}% with no interaction"))

    click_points = behavior.get("clicks_points") or behavior.get("click_points")
    if isinstance(click_points, list) and len(click_points) >= 5:
        coord_set = set()
        for cp in click_points[:20]:
            if isinstance(cp, dict):
                try:
                    coord_set.add((int(cp.get("x", 0)), int(cp.get("y", 0))))
                except (ValueError, TypeError):
                    pass
        if len(click_points) >= 5 and len(coord_set) == 1:
            items.append(("RAPID_REPEAT_CLICKS", "medium", 40, f"{len(click_points)} clicks at same point"))

    return items


def _check_webgl(webgl):
    items = []
    renderer = str(webgl.get("renderer") or "").lower()
    vendor = str(webgl.get("vendor") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        known_vendors = ("intel", "nvidia", "amd", "microsoft", "google", "apple")
        if any(v in vendor for v in known_vendors):
            items.append(("SOFT_RENDERER", "low", 20, f"Software renderer ({_safe_str(vendor, 30)})"))
        else:
            items.append(("SOFT_RENDERER", "medium", 60, "Virtual renderer (no vendor)"))
    return items


def _check_cpm(nav, ua, privacy_name):
    items = []
    if privacy_name in ("Brave", "Brave(heuristic)") or nav.get("is_brave") is True:
        items.append(("CPM_BRAVE", "low", 15, f"{privacy_name or 'Brave'} user (built-in ad block)"))
    _adblock_uas = ("firefox focus", "duckduckgo", "opera mini", "brave")
    for _abu in _adblock_uas:
        if _abu in ua and _abu != "brave":
            items.append(("CPM_ADBLOCK_BROWSER", "low", 10, f"AdBlock-heavy browser: {_safe_str(_abu, 30)}"))
            break
    return items


def _check_human(behavior, events):
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = _duration_ms(behavior)

    if mousemove > 50 and scrolls > 5 and clicks > 2 and t_on_page > 15000:
        items.append(("HUMAN_RICH_INTERACTION", "human", -30,
                      f"Rich interaction ({mousemove}mm, {scrolls}sc, {clicks}cl, {t_on_page}ms)"))

    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse_analysis = (
        not mouse_analysis.get("too_few", True)
        and "total_points" in mouse_analysis
    )
    if has_mouse_analysis:
        if (safe_float(mouse_analysis.get("velocity_variance"), 0) > 0.1
                and safe_int(mouse_analysis.get("direction_changes"), 0) > 5
                and safe_float(mouse_analysis.get("mean_curvature"), 0) > 0.01):
            items.append(("HUMAN_NATURAL_MOUSE", "human", -20, "Natural mouse trajectory"))
    elif "mouse_velocity_variance" in behavior:
        if (safe_float(behavior.get("mouse_velocity_variance"), 0) > 0.1
                and safe_int(behavior.get("mouse_direction_changes"), 0) > 5
                and _mouse_points_count(behavior) > 30):
            items.append(("HUMAN_NATURAL_MOUSE", "human", -20, "Natural mouse trajectory (v3)"))

    if t_on_page > 30000 and (mousemove > 10 or touchstart > 0 or scrolls > 0):
        items.append(("HUMAN_LONG_ENGAGEMENT", "human", -15, f"Long engagement ({t_on_page}ms)"))

    return items


# =========================================================
# v3 SIGNALS (heartbeat, milestones, first_30s, ad_events)
# =========================================================
def _check_v3_signals(data, behavior, events, fp, ua):
    items = []

    hb_count = safe_int(data.get("_heartbeat_count"), 0)
    t_on_page = _duration_ms(behavior)
    ad_events = _safe_list(data.get("_ad_events"))
    milestones = _safe_dict(data.get("_milestones"))
    first_30s = _safe_dict(data.get("_first_30s"))
    clock_drift = safe_int(data.get("_clock_drift_ms"), 0)
    connection = _safe_dict(fp.get("connection"))

    # 1) Drive-by bot (v3.1 — relaxed: 5s + medium, not critical)
    if hb_count == 0 and 0 < t_on_page < 5000:
        items.append(("DRIVE_BY", "medium", 40,
                      f"Drive-by: {t_on_page}ms, no heartbeat"))

    # 2) Silent after initial (only if NO interaction at all)
    elif hb_count == 0 and t_on_page >= 5000:
        total_events = (
            safe_int(events.get("mousemove"), 0)
            + safe_int(events.get("clicks"), 0) * 3
            + safe_int(events.get("scrolls"), 0) * 2
            + safe_int(events.get("keydown"), 0) * 3
            + safe_int(events.get("touchstart"), 0) * 2
        )
        if total_events == 0:
            items.append(("SILENT_AFTER_INITIAL", "high", 70,
                          f"No heartbeat + no interaction over {t_on_page}ms"))

    # 3) Engagement zero (v3.1 — 15s not 10s)
    if t_on_page >= 15000:
        total_events = (
            safe_int(events.get("mousemove"), 0)
            + safe_int(events.get("clicks"), 0) * 3
            + safe_int(events.get("scrolls"), 0) * 2
            + safe_int(events.get("keydown"), 0) * 3
            + safe_int(events.get("touchstart"), 0) * 2
        )
        if total_events == 0:
            items.append(("ENGAGEMENT_ZERO", "medium", 40,
                          f"Zero interaction over {t_on_page/1000:.1f}s"))
        elif total_events <= 2 and t_on_page >= 45000:
            items.append(("ENGAGEMENT_VERY_LOW", "low", 25,
                          f"Only {total_events} interactions over {t_on_page/1000:.1f}s"))

    # 4) First 30s burst
    if isinstance(first_30s, dict) and first_30s:
        has_int_30s = first_30s.get("has_interaction_30s")
        clicks_30s = safe_int(first_30s.get("clicks_30s"), 0)
        scrolls_30s = safe_int(first_30s.get("scrolls_30s"), 0)
        total_early = clicks_30s + scrolls_30s

        if has_int_30s is False and t_on_page > 60000:
            items.append(("ZOMBIE_60S", "medium", 30,
                          "No interaction in first 30s over 60s+"))

        if has_int_30s is True and total_early >= 5 and t_on_page > 45000:
            total_clicks = safe_int(events.get("clicks"), 0)
            total_scrolls = safe_int(events.get("scrolls"), 0)
            late = (total_clicks - clicks_30s) + (total_scrolls - scrolls_30s)
            if late <= 1:
                items.append(("FIRST_30S_BURST", "high", 50,
                              f"Heavy early ({total_early}) then dead"))

    # 5) Ad loaded but never visible (v3.1 — 30s not 15s)
    if ad_events:
        loaded = any(
            "loaded" in str(ev.get("event", ""))
            for ev in ad_events if isinstance(ev, dict)
        )
        visible = any(
            "viewable_50pct_1s" in str(ev.get("event", ""))
            for ev in ad_events if isinstance(ev, dict)
        )
        if loaded and not visible and t_on_page > 30000:
            items.append(("AD_HIDDEN_AFTER_LOAD", "medium", 40,
                          "Ad loaded but never visible over 30s (bot cloaking?)"))

    # 6) Interaction before paint (v3.1 — 500ms diff, not 100)
    if isinstance(milestones, dict):
        t_paint = milestones.get("t_first_paint")
        t_int = milestones.get("t_first_interaction")
        try:
            if t_paint is not None and t_int is not None and int(t_int) < int(t_paint):
                diff = int(t_paint) - int(t_int)
                if diff > 500 and int(t_paint) > 100:
                    items.append(("INTERACTION_BEFORE_PAINT", "high", 60,
                                  f"Interaction {diff}ms before paint"))
        except (ValueError, TypeError):
            pass

    # 7) Clock drift
    if abs(clock_drift) > 30000:
        items.append(("CLOCK_DRIFT", "medium", 30,
                      f"Clock drift: {clock_drift}ms"))

    # 8) Scroll pattern (v3)
    scroll_pattern = str(behavior.get("scroll_pattern") or "").lower()
    scroll_depth = safe_int(behavior.get("scroll_depth_pct"), 0)

    if scroll_pattern == "linear" and safe_int(events.get("scrolls"), 0) > 5:
        items.append(("SCROLL_LINEAR", "medium", 40,
                      "Perfectly linear scroll (no pauses, no reversals)"))

    # 9) Mouse too smooth (v3.1 — < 0.1, not < 0.5)
    mouse_var = safe_float(behavior.get("mouse_velocity_variance"), 0)
    mouse_pts = _mouse_points_count(behavior)
    if mouse_pts >= 50 and 0 <= mouse_var < 0.1:
        items.append(("MOUSE_TOO_SMOOTH", "medium", 40,
                      f"Mouse velocity variance too low: {mouse_var:.3f}"))

    # 10) No mouse + no touch (v3.1 — new signal)
    mm = safe_int(events.get("mousemove"), 0)
    tt = safe_int(events.get("touchstart"), 0)
    if t_on_page > 8000 and mm == 0 and tt == 0:
        items.append(("NO_MOUSE_NO_TOUCH", "high", 60,
                      f"No mouse or touch events over {t_on_page/1000:.0f}s"))

    # 11) Connection RTT zero (headless indicator)
    if isinstance(connection, dict):
        rtt = safe_int(connection.get("rtt"), -1)
        if rtt == 0 and t_on_page > 3000:
            items.append(("CONNECTION_RTT_ZERO", "low", 15,
                          "connection.rtt = 0 (headless default)"))

    # ===== HUMAN SIGNALS =====
    if t_on_page > 30000 and hb_count >= 3:
        cl = safe_int(events.get("clicks"), 0)
        sc = safe_int(events.get("scrolls"), 0)
        if mm > 20 and cl >= 1 and sc >= 2:
            items.append(("HUMAN_ENGAGED", "human", -20,
                          f"Engaged: {mm}mm, {cl}cl, {sc}sc over {t_on_page/1000:.0f}s"))

    if scroll_pattern == "organic" and scroll_depth >= 60:
        items.append(("HUMAN_DEEP_SCROLL", "human", -20,
                      f"Organic deep scroll: {scroll_depth}%"))

    kd = safe_int(events.get("keydown"), 0)
    if kd >= 3:
        items.append(("HUMAN_KEYBOARD", "human", -15,
                      f"Typed {kd} keys"))

    return items


# =========================================================
# DATA QUALITY GATE (v3.1) — DEPRECATED in System 2
# =========================================================
# Kept for backward compatibility. bayesian_evaluate() now handles
# data quality internally, so this function is no longer called by
# analyze_visit(). Any external code that imports it will still work.
def _data_quality_gate(data_quality, evidence):
    """
    DEPRECATED (System 2): moved into bayesian_engine.bayesian_evaluate().
    Kept for backward compatibility only.

    لو البيانات ناقصة، verdict = 'unknown' مش 'invalid'.
    """
    if data_quality == "legacy":
        return "unknown", "DATA_LEGACY"

    if data_quality == "failed":
        return "unknown", "DATA_INSUFFICIENT"

    if data_quality == "partial":
        has_critical = any(e.get("severity") == "critical" for e in evidence)
        if not has_critical:
            return "unknown", "DATA_INSUFFICIENT"

    return None, None


# =========================================================
# HELPERS FOR INLINE LOGIC (System 1 integration)
# =========================================================
def _check_honeypot(data):
    """Inline honeypot logic — wrapped for circuit breaker."""
    items = []
    if data.get("_honeypot_triggered") is True:
        items.append((
            "HONEYPOT_CLICK", "critical", 100,
            "Honeypot triggered (link/button)",
        ))
    return items


def _check_bot_ua(ua):
    """Inline bot UA logic — wrapped for circuit breaker."""
    items = []
    if _is_bot_ua(ua):
        items.append((
            "BOT_UA", "high", 90,
            f"Suspicious UA: {_safe_str(ua[:60], 60)}",
        ))
    return items


# =========================================================
# MAIN ANALYZER
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    ev = EvidenceCollector()

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

    is_ios = "iphone" in ua or "ipad" in ua or "ipod" in ua
    is_mobile = "mobile" in ua or "android" in ua
    is_tablet = "ipad" in ua or "tablet" in ua
    is_mobile_phone = ("mobile" in ua) and not is_tablet
    is_desktop_chrome = (
        "chrome" in ua and not is_mobile and not is_ios
        and "headless" not in ua and "edg/" not in ua and "opr/" not in ua
    )

    is_privacy_browser, privacy_name = _detect_privacy_browser(ua, platform, fp, nav)

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

    # ===== SYSTEM 1: all checks wrapped in circuit breakers =====

    # Critical & automation
    _apply_items(ev, cb_safe_call(
        _check_critical, nav, fp, ua, platform, chrome_check,
        check_name="critical",
    ))
    _apply_items(ev, cb_safe_call(
        _check_automation_globals, fp,
        check_name="automation_globals",
    ))

    # Honeypot & bot UA (inline logic now wrapped)
    _apply_items(ev, cb_safe_call(
        _check_honeypot, data,
        check_name="honeypot",
    ))
    _apply_items(ev, cb_safe_call(
        _check_bot_ua, ua,
        check_name="bot_ua",
    ))

    # Network & fingerprint
    _apply_items(ev, cb_safe_call(
        _check_network, ip_info, data, asn_value, is_proxy, is_hosting,
        check_name="network",
    ))
    _apply_items(ev, cb_safe_call(
        _check_fingerprint, fp, plugins_info, is_desktop_chrome,
        is_privacy_browser, chrome_check, ua,
        check_name="fingerprint",
    ))
    _apply_items(ev, cb_safe_call(
        _check_fingerprint_reuse, data,
        check_name="fingerprint_reuse",
    ))
    _apply_items(ev, cb_safe_call(
        _check_cross_visit, data,
        check_name="cross_visit",
    ))

    # Hardware & screen
    _apply_items(ev, cb_safe_call(
        _check_hardware, fp, screen_dict, ua, is_privacy_browser, is_mobile_phone,
        check_name="hardware",
    ))
    _apply_items(ev, cb_safe_call(
        _check_screen, screen_dict, is_mobile_phone, is_tablet,
        is_desktop_chrome, is_mobile,
        check_name="screen",
    ))

    # OS & contradictions
    _apply_items(ev, cb_safe_call(
        _check_os_mismatch, ua, platform,
        check_name="os_mismatch",
    ))
    _apply_items(ev, cb_safe_call(
        _check_contradictions, nav, fp, screen_dict, ua, is_mobile,
        is_mobile_phone, is_tablet, is_desktop_chrome, is_privacy_browser,
        check_name="contradictions",
    ))

    # Locale & timezone
    _apply_items(ev, cb_safe_call(
        _check_locale_consistency, nav, fp, country_code,
        check_name="locale",
    ))
    _apply_items(ev, cb_safe_call(
        _check_timezone, fp, country_code, is_privacy_browser,
        check_name="timezone",
    ))

    # Behavior
    _apply_items(ev, cb_safe_call(
        _check_behavior, behavior, events,
        check_name="behavior",
    ))
    _apply_items(ev, cb_safe_call(
        _check_behavior_deep, behavior, events,
        check_name="behavior_deep",
    ))

    # v3 signals
    _apply_items(ev, cb_safe_call(
        _check_v3_signals, data, behavior, events, fp, ua,
        check_name="v3_signals",
    ))

    # WebGL, CPM, Human
    _apply_items(ev, cb_safe_call(
        _check_webgl, webgl,
        check_name="webgl",
    ))
    _apply_items(ev, cb_safe_call(
        _check_cpm, nav, ua, privacy_name,
        check_name="cpm",
    ))
    _apply_items(ev, cb_safe_call(
        _check_human, behavior, events,
        check_name="human",
    ))

    # ===== SYSTEM 2: Bayesian verdict =====
    raw = ev.raw_score()

    data_quality = str(data.get("_data_quality") or "unknown")
    bayes_result = bayes_evaluate(ev.items, data_quality)
    final_verdict = bayes_result["verdict"]

    if final_verdict == "unknown":
        # Insufficient data — don't call it invalid, don't call it valid
        final = 0
        confidence = 0.0
        gate_code = bayes_result.get("gate_code") or "DATA_INSUFFICIENT"
        ev.items.append({
            "code": gate_code,
            "severity": "medium",
            "score": 0,
            "detail": f"Data quality: {data_quality} — insufficient for verdict",
        })
    else:
        final = ev.final_score()
        confidence = calc_confidence(ev.items)

    categories = ev.counts()
    cpm_quality = compute_cpm_quality(ev.items, final_verdict)
    wasted = is_wasted_impression(ev.items, final_verdict)

    return {
        # Existing fields (backward compat)
        "raw_score": raw,
        "score": final,
        "final_score": final,
        "verdict": final_verdict,
        "confidence": confidence,
        "evidence": ev.items,
        "categories": categories,
        "privacy_browser": privacy_name or None,
        "cpm_quality": cpm_quality,
        "wasted_impression": wasted,
        "data_quality": data_quality,
        # SYSTEM 2 — new Bayesian fields
        "probability": bayes_result["probability"],
        "log_odds": bayes_result["log_odds"],
        "bayesian_confidence": bayes_result["confidence"],
        "safety_triggered": bayes_result.get("safety"),
        "bayesian_contributions": bayes_result.get("contributions", []),
    }


# =========================================================
# SYSTEM 1 — INTEGRATION SELF-TEST
# =========================================================
def _system1_integration_test():
    """Verify analysis.py integrates correctly with circuit_breaker."""
    import sys as _sys
    print("\n" + "=" * 70)
    print("  SYSTEM 1: INTEGRATION TEST (analysis.py + circuit_breaker)")
    print("=" * 70)

    results = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # Test 1: safe_call + apply_items
    try:
        ev = EvidenceCollector()

        def fake_check():
            return [("FAKE_SIGNAL", "medium", 15, "test detail")]

        _apply_items(ev, cb_safe_call(fake_check, check_name="test_normal"))
        _chk(len(ev.items) == 1 and ev.items[0]["code"] == "FAKE_SIGNAL",
             "Test 1: safe_call + _apply_items work together",
             f"Test 1: failed (items={len(ev.items)})")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # Test 2: safe_call isolates broken checks
    try:
        def broken_check():
            raise RuntimeError("intentional failure")

        items = cb_safe_call(broken_check, check_name="test_broken_iso")
        _chk(items == [],
             "Test 2: safe_call returns [] on check failure",
             f"Test 2: expected [], got {items}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # Test 3: independent safe_calls
    try:
        ev = EvidenceCollector()

        def good1():
            return [("A", "low", 5, "a")]

        def bad():
            raise ValueError("bad")

        def good2():
            return [("B", "high", 30, "b")]

        _apply_items(ev, cb_safe_call(good1, check_name="iso_good1"))
        _apply_items(ev, cb_safe_call(bad, check_name="iso_bad"))
        _apply_items(ev, cb_safe_call(good2, check_name="iso_good2"))

        codes = {item["code"] for item in ev.items}
        _chk("A" in codes and "B" in codes and len(ev.items) == 2,
             "Test 3: isolated breakers (failure doesn't affect others)",
             f"Test 3: failed (codes={codes}, count={len(ev.items)})")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # Test 4: analyze_visit end-to-end
    try:
        fake_data = {
            "nav": {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0", "platform": "Win32"},
            "fingerprint": {
                "hardwareConcurrency": 8, "deviceMemory": 8,
                "canvas_hash": "abc123def456", "languages": ["en-US", "en"],
            },
            "behavior": {
                "events": {"mousemove": 100, "clicks": 2, "scrolls": 5, "touchstart": 0, "keydown": 0},
                "total_time_ms": 25000,
                "mouse_variance": 2.5,
            },
            "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040},
            "_data_quality": "full",
            "_heartbeat_count": 3,
        }
        fake_ip = {"country": "US", "country_code": "US", "isp": "Comcast",
                   "type": "residential", "asn": "AS7922", "security": {}}
        result = analyze_visit(fake_data, fake_ip)
        _chk(result is not None and "verdict" in result and "evidence" in result
             and result["verdict"] in ("valid", "suspicious", "invalid", "unknown"),
             "Test 4: analyze_visit runs end-to-end without crashing",
             f"Test 4: analyze_visit failed")
    except Exception as e:
        import traceback
        traceback.print_exc()
        _chk(False, "", f"Test 4: crashed ({e})")

    # Test 5: breaker opens after repeated failures
    try:
        cb_breakers.reset_all()

        def always_fails():
            raise ValueError("repeat")

        for _ in range(6):
            cb_safe_call(always_fails, check_name="test_opens")

        b = cb_breakers.get("test_opens")
        _chk(b is not None and b.state.value == "open",
             "Test 5: breaker opens after threshold failures",
             f"Test 5: expected open, got {b.state.value if b else 'None'}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if success:
        print(f"  ✅ SYSTEM 1 INTEGRATION PASSED — {passed}/{total} tests")
    else:
        print(f"  ❌ SYSTEM 1 INTEGRATION FAILED — {passed}/{total} passed")

    print("=" * 70 + "\n")
    cb_breakers.reset_all()
    return success


# =========================================================
# SYSTEM 2 — INTEGRATION SELF-TEST
# =========================================================
def _system2_integration_test():
    """Verify analysis.py integrates correctly with bayesian_engine."""
    print("\n" + "=" * 70)
    print("  SYSTEM 2: INTEGRATION TEST (analysis.py + bayesian_engine)")
    print("=" * 70)

    results = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # Prepare a clean visit data
    clean_data = {
        "nav": {"ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0", "platform": "Win32"},
        "fingerprint": {
            "hardwareConcurrency": 8, "deviceMemory": 8,
            "canvas_hash": "abc123def456789abc",
            "languages": ["en-US", "en"],
            "timezone": "America/New_York",
        },
        "behavior": {
            "events": {"mousemove": 100, "clicks": 3, "scrolls": 6, "touchstart": 0, "keydown": 0},
            "total_time_ms": 25000,
            "mouse_variance": 2.5,
        },
        "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040},
        "_data_quality": "full",
        "_heartbeat_count": 3,
    }
    clean_ip = {"country": "US", "country_code": "US", "isp": "Comcast",
                "type": "residential", "asn": "AS7922", "security": {}}

    # Test 1: analyze_visit returns new Bayesian fields
    try:
        result = analyze_visit(clean_data, clean_ip)
        _chk("probability" in result and "log_odds" in result
             and "bayesian_confidence" in result,
             "Test 1: analyze_visit returns new Bayesian fields",
             f"Test 1: missing fields (keys={list(result.keys())})")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # Test 2: clean visit → valid verdict
    try:
        result = analyze_visit(clean_data, clean_ip)
        _chk(result["verdict"] == "valid",
             "Test 2: clean visit → valid verdict",
             f"Test 2: expected valid, got {result['verdict']} (P={result.get('probability')})")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # Test 3: webdriver=true → invalid verdict
    try:
        bad_data = dict(clean_data)
        bad_data["nav"] = dict(clean_data["nav"])
        bad_data["nav"]["webdriver"] = True
        result = analyze_visit(bad_data, clean_ip)
        _chk(result["verdict"] == "invalid",
             "Test 3: webdriver=true → invalid verdict",
             f"Test 3: expected invalid, got {result['verdict']} (P={result.get('probability')})")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # Test 4: legacy data_quality → unknown verdict
    try:
        legacy_data = dict(clean_data)
        legacy_data["_data_quality"] = "legacy"
        result = analyze_visit(legacy_data, clean_ip)
        _chk(result["verdict"] == "unknown",
             "Test 4: legacy quality → unknown verdict",
             f"Test 4: expected unknown, got {result['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # Test 5: probability is always in [0, 1]
    try:
        result = analyze_visit(clean_data, clean_ip)
        p = result["probability"]
        _chk(0.0 <= p <= 1.0,
             "Test 5: probability is in [0, 1]",
             f"Test 5: probability={p} out of range")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if success:
        print(f"  ✅ SYSTEM 2 INTEGRATION PASSED — {passed}/{total} tests")
    else:
        print(f"  ❌ SYSTEM 2 INTEGRATION FAILED — {passed}/{total} passed")

    print("=" * 70 + "\n")
    return success


# =========================================================
# AUTO-RUN INTEGRATION TESTS
# =========================================================
if os.getenv("OVG_SELF_TEST_ENABLED", "1") == "1" and "pytest" not in __import__("sys").modules:
    try:
        _system1_integration_test()
    except Exception as _e:
        print(f"⚠️  [SYSTEM 1] Integration test crashed: {_e}")
    try:
        _system2_integration_test()
    except Exception as _e:
        print(f"⚠️  [SYSTEM 2] Integration test crashed: {_e}")