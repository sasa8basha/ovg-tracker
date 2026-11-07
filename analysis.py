"""
analysis.py — OVG Tracker — The Brain (v10.0 FINAL)

8 integrated systems:
  1. Circuit Breaker — failure isolation
  2. Bayesian Engine — probability-based verdict
  3. Confidence-tiered Verdict — 6-tier classification
  4. Server Cross-Validation — HTTP header analysis
  5. Adaptive Thresholds — data-driven thresholds
  6. Threat Intel — TOR/CIDR/AbuseIPDB/IPQS
  7. Fingerprint Graph — bot farm detection
  8. ML Engine — logistic regression model
"""
import os
import re
import ipaddress
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip
from collector.adaptive_thresholds import (
    get_threshold as adaptive_get_threshold,
    get_reliability as adaptive_get_reliability,
    health_status as adaptive_health_status,
)
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
from collector.verdict_engine import (
    VerdictV2,
    classify_verdict_v2,
    to_legacy_verdict,
    verdict_metadata,
    health_status as verdict_health_status,
)
from collector.server_cross_validator import (
    analyze_server_headers as scv_analyze,
    health_status as scv_health_status,
)
from collector.threat_intel import (
    analyze_threat_intel as ti_analyze,
    health_status as ti_health_status,
)
from collector.fingerprint_graph import (
    record_and_analyze as fp_graph_analyze,
    mark_known_bad as fp_graph_mark_bad,
    health_status as fp_graph_health_status,
)
from collector.ml_engine import (
    analyze_ml as ml_analyze,
    health_status as ml_health_status,
)


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
    t = safe_int(behavior.get("time_on_page_ms"), 0)
    if t == 0:
        t = safe_int(behavior.get("total_time_ms"), 0)
    return t


def _mouse_points_count(behavior):
    ma = _safe_dict(behavior.get("mouse_analysis"))
    if not ma.get("too_few", True):
        return safe_int(ma.get("total_points"), 0)
    pts = _safe_list(behavior.get("mouse_points"))
    return len(pts)


BOT_UA_PATTERNS = (
    "curl", "wget", "httpie",
    "python-requests", "requests/",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "undici",
    "httpclient", "libwww", "restsharp",
    "headless", "headlesschrome", "headless_chrome",
    "selenium", "phantomjs", "phantom", "puppeteer", "playwright",
    "splinter", "mechanize", "splash", "scrapinghub",
    "scrapy", "guzzle", "httpx", "aiohttp", "urllib",
    "postman", "insomnia", "apitester", "http_request",
    "automated", "automation",
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
    if not ua:
        return False
    ua_lower = ua.lower()
    if any(x in ua_lower for x in BOT_UA_PATTERNS):
        return True
    if BOT_UA_WORDS_RE.search(ua):
        return True
    if BOT_WORD_RE.search(ua):
        return True
    return False


def _is_headless_ua(ua: str) -> bool:
    if not ua:
        return False
    return bool(HEADLESS_UA_RE.search(ua))


DATACENTER_ASNS = frozenset([
    "AS16509", "AS14618", "AS8987", "AS396982", "AS15169", "AS19527",
    "AS8075", "AS8068", "AS8069", "AS13335", "AS209242", "AS20940",
    "AS16625", "AS21342", "AS16702", "AS54113", "AS394192", "AS14061",
    "AS393406", "AS63949", "AS48337", "AS20473", "AS3223", "AS24940",
    "AS213230", "AS16276", "AS35540", "AS31898", "AS7160", "AS45102",
    "AS37963", "AS24429", "AS132203", "AS45090", "AS136907", "AS55990",
    "AS47583", "AS199524", "AS51167", "AS141995", "AS12876", "AS29447",
    "AS8560", "AS15418", "AS26496", "AS398101", "AS22612", "AS11798",
    "AS46606", "AS19871", "AS19994", "AS33070", "AS60781", "AS394711",
    "AS9009", "AS62838", "AS200373", "AS9002", "AS49505", "AS208046",
    "AS40676", "AS53667", "AS59711", "AS29802", "AS63023", "AS212238",
    "AS9312", "AS35916", "AS21859", "AS36352", "AS209854", "AS3462",
    "AS6079", "AS197540", "AS197695", "AS7506", "AS16265", "AS20454",
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
    "RU": {"europe/moscow", "europe/kaliningrad", "europe/samara",
           "europe/volgograd", "europe/saratov",
           "asia/yekaterinburg", "asia/novosibirsk", "asia/omsk",
           "asia/krasnoyarsk", "asia/irkutsk", "asia/yakutsk",
           "asia/vladivostok", "asia/magadan", "asia/kamchatka"},
    "US": {"america/new_york", "america/chicago", "america/denver",
           "america/phoenix", "america/los_angeles",
           "america/anchorage", "america/honolulu", "america/detroit",
           "america/indianapolis", "america/boise", "america/juneau",
           "america/sitka", "america/nome", "america/adak"},
    "CA": {"america/toronto", "america/vancouver", "america/edmonton",
           "america/winnipeg", "america/halifax", "america/st_johns",
           "america/regina", "america/whitehorse", "america/yellowknife"},
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


VALID_SEVERITIES = frozenset(["impossible", "critical", "high", "medium", "low", "human"])
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
        return any(i["severity"] in ("critical", "impossible") for i in self.items)

    def raw_score(self) -> int:
        return sum(i["score"] for i in self.items)

    def final_score(self) -> int:
        return max(0, min(150, self.raw_score()))

    def counts(self) -> dict:
        counts = {"impossible": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
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
    if any(s.get("severity") in ("critical", "impossible") for s in non_human):
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
    counts = {"impossible": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
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


CODE_TO_SOURCE = {
    "WEBDRIVER_FLAG": "critical", "CDP_DETECTED": "critical",
    "WINDOWS_UA_LINUX": "critical", "FIREFOX_CHROME_OBJ": "critical",
    "HEADLESS_UA": "critical", "UNTRUSTED_CLICK": "critical",
    "HONEYPOT_CLICK": "honeypot", "HONEYPOT_FORM_FILL": "honeypot",
    "IMPOSSIBLE_SPEED": "behavior_deep",
    "PUPPETEER_DETECTED": "automation", "PLAYWRIGHT_DETECTED": "automation",
    "SELENIUM_DETECTED": "automation", "NIGHTMARE_DETECTED": "automation",
    "PHANTOM_DETECTED": "automation", "BOT_UA": "ua",
    "VPN_DATACENTER": "network", "DATACENTER_IP": "network",
    "VPN_PROXY": "network", "DATACENTER_ASN": "network",
    "WEBRTC_LEAK": "network", "WEBRTC_VPN_DIFF": "network",
    "PLUGINS_ZERO": "fingerprint", "CHROME_NO_OBJ": "fingerprint",
    "CANVAS_BLOCKED": "fingerprint", "CANVAS_MISSING": "fingerprint",
    "LANGUAGES_EMPTY": "fingerprint", "SINGLE_LANG": "fingerprint",
    "NO_MIME_TYPES": "fingerprint", "NO_PDF_VIEWER": "fingerprint",
    "SPEECH_VOICES_ZERO": "fingerprint", "WEBGL_PRECISION_ZERO": "fingerprint",
    "UA_BRANDS_MISMATCH": "fingerprint",
    "FINGERPRINT_REUSE_HIGH": "fingerprint_reuse",
    "FINGERPRINT_REUSE_MED": "fingerprint_reuse",
    "FINGERPRINT_REUSE_LOW": "fingerprint_reuse",
    "IP_VELOCITY_HIGH": "cross_visit", "IP_VELOCITY_MED": "cross_visit",
    "FINGERPRINT_MULTI_IP": "cross_visit", "IP_MULTI_FINGERPRINT": "cross_visit",
    "CORES_ZERO": "hardware", "CORES_LOW": "hardware",
    "ABSURD_CORES": "hardware", "LOW_MEMORY": "hardware",
    "CPU_MEMORY_MISMATCH": "hardware", "MOBILE_PIXEL_RATIO": "hardware",
    "LOW_COLOR_DEPTH": "hardware",
    "HEADLESS_VIEWPORT": "screen", "VIEWPORT_ZERO": "screen",
    "MOBILE_WIDE_SCREEN": "screen", "TABLET_WIDE_SCREEN": "screen",
    "SCREEN_TINY": "screen", "INNER_WIDER_THAN_SCREEN": "screen",
    "INNER_TALLER_THAN_SCREEN": "screen",
    "OS_MISMATCH_WIN": "os", "OS_MISMATCH_MAC": "os",
    "TOUCH_UA_MISMATCH": "contradictions", "FIRST_LANG_MISMATCH": "contradictions",
    "INTL_LOCALE_MISMATCH": "contradictions",
    "WEBGL_VENDOR_RENDERER_MISMATCH": "contradictions",
    "UA_CHROME_OLD": "contradictions", "UA_CHROME_FUTURE": "contradictions",
    "CLIENT_HINTS_MISMATCH": "contradictions",
    "LANG_COUNTRY_MISMATCH": "locale",
    "UTC_TZ": "timezone", "TZ_MISMATCH": "timezone",
    "LEFT_FAST": "behavior", "LEFT_FAST_HIDDEN": "behavior",
    "ROBOTIC_LINEAR": "behavior", "ROBOTIC_CURVATURE": "behavior",
    "ROBOTIC_VARIANCE": "behavior", "ZOMBIE": "behavior",
    "SCROLL_LINEAR": "behavior", "MOUSE_TOO_SMOOTH": "behavior",
    "INSTANT_FIRST_MOVE": "behavior_deep", "CLICK_BEFORE_MOVE": "behavior_deep",
    "IDLE_VISIBLE": "behavior_deep", "RAPID_REPEAT_CLICKS": "behavior_deep",
    "ENGAGEMENT_ZERO": "behavior_deep", "ENGAGEMENT_VERY_LOW": "behavior_deep",
    "FIRST_30S_BURST": "behavior_deep", "ZOMBIE_60S": "behavior_deep",
    "NO_MOUSE_NO_TOUCH": "behavior_deep",
    "SOFT_RENDERER": "webgl",
    "SILENT_AFTER_INITIAL": "session", "HEARTBEAT_GAP": "session",
    "DRIVE_BY": "session", "CLOCK_DRIFT": "session",
    "AD_HIDDEN_AFTER_LOAD": "ad_events",
    "INTERACTION_BEFORE_PAINT": "milestones",
    "CONNECTION_RTT_ZERO": "connection",
    "CPM_BRAVE": "cpm", "CPM_ADBLOCK_BROWSER": "cpm",
    "HUMAN_RICH_INTERACTION": "human", "HUMAN_NATURAL_MOUSE": "human",
    "HUMAN_LONG_ENGAGEMENT": "human", "HUMAN_DEEP_SCROLL": "human",
    "HUMAN_KEYBOARD": "human", "HUMAN_ENGAGED": "human",
    "LEGACY_SIGNAL": "legacy", "MOCK_SIGNAL": "mock",
    "DATA_LEGACY": "data_quality", "DATA_INSUFFICIENT": "data_quality",
    "HTTP_UA_JS_MISMATCH": "server_cross", "MISSING_SEC_CH_UA": "server_cross",
    "SEC_CH_UA_ON_FIREFOX": "server_cross", "SEC_CH_UA_ON_SAFARI": "server_cross",
    "SEC_CH_UA_MOBILE_MISMATCH": "server_cross",
    "SEC_CH_HEADLESS_BRAND": "server_cross",
    "SEC_CH_UA_GOOGLE_MISSING": "server_cross",
    "HTTP_1_1_ON_HTTPS": "server_cross",
    "CF_COUNTRY_TZ_MISMATCH": "server_cross",
    "THREAT_TOR_EXIT": "threat_intel", "THREAT_DATACENTER_CIDR": "threat_intel",
    "THREAT_ABUSE_HIGH": "threat_intel", "THREAT_ABUSE_MED": "threat_intel",
    "THREAT_IPQS_TOR": "threat_intel", "THREAT_IPQS_VPN_HIGH": "threat_intel",
    "THREAT_IPQS_PROXY_HIGH": "threat_intel", "THREAT_IPQS_PROXY_MED": "threat_intel",
    "FINGERPRINT_FARM_MASSIVE": "fingerprint_graph",
    "FINGERPRINT_FARM_LARGE": "fingerprint_graph",
    "FINGERPRINT_FARM_SMALL": "fingerprint_graph",
    "IP_MANY_FPS": "fingerprint_graph",
    "FINGERPRINT_KNOWN_BAD": "fingerprint_graph",
    "ML_HIGH_RISK": "ml_engine", "ML_ELEVATED_RISK": "ml_engine",
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
            "step": step, "code": _safe_str(code, 50),
            "source": CODE_TO_SOURCE.get(code, "unknown"),
            "severity": sev, "score": score, "running_total": running,
            "detail": _safe_str(detail, 200),
        })
    return trace


# =========================================================
# SIGNAL CHECKS
# =========================================================
def _check_critical(nav, fp, ua, platform, chrome_check):
    items = []
    if _is_headless_ua(ua):
        items.append(("HEADLESS_UA", "critical", 100, f"Headless UA detected: {_safe_str(ua[:60], 60)}"))
    untrusted = safe_int(fp.get("_untrusted_clicks"), 0)
    if untrusted >= 1:
        items.append(("UNTRUSTED_CLICK", "critical", 100, f"{untrusted} click(s) with isTrusted=false"))
    if nav.get("webdriver") is True:
        items.append(("WEBDRIVER_FLAG", "critical", 80, "navigator.webdriver === true"))
    if fp.get("cdp_detected") is True:
        items.append(("CDP_DETECTED", "critical", 100, "CDP Runtime Detected"))
    if "windows nt" in ua and platform and ("linux" in platform or "x11" in platform):
        items.append(("WINDOWS_UA_LINUX", "critical", 100, f"Windows UA + Linux platform ({_safe_str(platform, 30)})"))
    if "firefox" in ua and chrome_check == "full":
        items.append(("FIREFOX_CHROME_OBJ", "critical", 80, "Firefox UA + window.chrome (impossible)"))
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
    webrtc_penalty, webrtc_evidence = _check_webrtc(data.get("webrtc_ip"), data.get("client_ip"), ip_info)
    if webrtc_penalty >= 90:
        items.append(("WEBRTC_LEAK", "high", webrtc_penalty, webrtc_evidence))
    elif webrtc_penalty > 0:
        items.append(("WEBRTC_VPN_DIFF", "medium", webrtc_penalty, webrtc_evidence))
    return items


def _check_fingerprint(fp, plugins_info, is_desktop_chrome, is_privacy_browser, chrome_check, ua):
    items = []
    plugin_count = safe_int(plugins_info.get("count"), -1, max_val=1000)
    if is_desktop_chrome and not is_privacy_browser and plugin_count == 0:
        items.append(("PLUGINS_ZERO", "high", 60, "Chrome desktop: 0 plugins"))
    if is_desktop_chrome and not is_privacy_browser and chrome_check == "no_window_chrome":
        items.append(("CHROME_NO_OBJ", "high", 50, "Chrome UA: no window.chrome"))
    canvas = fp.get("canvas_hash")
    if canvas == "blocked":
        items.append(("CANVAS_BLOCKED", "low", 10, "Canvas blocked"))
    elif not canvas or len(str(canvas)) < 5:
        items.append(("CANVAS_MISSING", "medium", 60, "Canvas hash missing or invalid"))
    langs_raw = fp.get("languages")
    if isinstance(langs_raw, list):
        if len(langs_raw) == 0:
            items.append(("LANGUAGES_EMPTY", "medium", 40, "Empty navigator.languages"))
        elif len(langs_raw) == 1 and langs_raw[0] == "en-US" and is_desktop_chrome and not is_privacy_browser:
            items.append(("SINGLE_LANG", "low", 15, "Only single en-US language"))
    mime_count = safe_int(fp.get("mime_types_count"), -1)
    if is_desktop_chrome and not is_privacy_browser and mime_count == 0:
        items.append(("NO_MIME_TYPES", "medium", 40, "Chrome desktop: 0 mimeTypes"))
    pdf_viewer = fp.get("pdf_viewer")
    if is_desktop_chrome and not is_privacy_browser and pdf_viewer is False:
        items.append(("NO_PDF_VIEWER", "low", 15, "pdfViewerEnabled=false"))
    speech = fp.get("speech_voices")
    if speech is not None:
        sv = safe_int(speech, -1)
        if sv == 0 and not is_privacy_browser:
            items.append(("SPEECH_VOICES_ZERO", "high", 70, "speechSynthesis.getVoices() = 0"))
    wgp = _safe_dict(fp.get("webgl_precision"))
    if wgp:
        hf = safe_int(wgp.get("high_float"), -99)
        if hf in (0, -1) and not is_privacy_browser:
            items.append(("WEBGL_PRECISION_ZERO", "high", 60, f"WebGL precision = {hf}"))
    return items


def _check_fingerprint_reuse(data):
    items = []
    recent_fp = safe_int(data.get("_recent_fp_count"), 0)
    t_high = adaptive_get_threshold("reuse_high_per_min", 50)
    t_med = adaptive_get_threshold("reuse_med_per_min", 30)
    t_low = adaptive_get_threshold("reuse_low_per_min", 20)
    if recent_fp >= t_high:
        items.append(("FINGERPRINT_REUSE_HIGH", "high", 80, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp >= t_med:
        items.append(("FINGERPRINT_REUSE_HIGH", "high", 60, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp >= t_low:
        items.append(("FINGERPRINT_REUSE_MED", "medium", 40, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp > 10:
        items.append(("FINGERPRINT_REUSE_LOW", "low", 25, f"Fingerprint reuse ({recent_fp}/min)"))
    return items


def _check_cross_visit(data):
    items = []
    same_ip = safe_int(data.get("_same_ip_last_minute"), 0)
    canvas_ips = safe_int(data.get("_same_canvas_ip_count"), 0)
    ip_canvases = safe_int(data.get("_same_ip_canvas_count"), 0)
    v_high = adaptive_get_threshold("ip_velocity_high", 10)
    v_med = adaptive_get_threshold("ip_velocity_med", 5)
    if same_ip >= v_high:
        items.append(("IP_VELOCITY_HIGH", "high", 70, f"Same IP: {same_ip}/min"))
    elif same_ip >= v_med:
        items.append(("IP_VELOCITY_MED", "medium", 40, f"Same IP: {same_ip}/min"))
    if canvas_ips >= 5:
        items.append(("FINGERPRINT_MULTI_IP", "high", 60, f"Same canvas from {canvas_ips} IPs/hr"))
    elif canvas_ips >= 3:
        items.append(("FINGERPRINT_MULTI_IP", "medium", 40, f"Same canvas from {canvas_ips} IPs/hr"))
    if ip_canvases >= 10:
        items.append(("IP_MULTI_FINGERPRINT", "high", 70, f"Same IP with {ip_canvases} canvases/hr"))
    elif ip_canvases >= 5:
        items.append(("IP_MULTI_FINGERPRINT", "medium", 40, f"Same IP with {ip_canvases} canvases/hr"))
    return items


def _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone):
    items = []
    cores = safe_int(fp.get("hardwareConcurrency"), -1, max_val=256)
    memory = safe_float(fp.get("deviceMemory"), -1, max_val=1024)
    pixel_ratio = safe_float(screen_dict.get("pixelRatio"), -1, max_val=100)
    color_depth = safe_int(screen_dict.get("colorDepth"), -1, max_val=64)
    cores_high = adaptive_get_threshold("cores_high", 128)
    if cores == 0:
        if not is_privacy_browser and "firefox" not in ua:
            items.append(("CORES_ZERO", "medium", 40, "hardwareConcurrency=0"))
    elif cores == 1:
        items.append(("CORES_LOW", "low", 15, "Single-core device"))
    elif cores > cores_high:
        items.append(("ABSURD_CORES", "high", 60, f"cores={cores}"))
    if 0 <= memory < 0.25:
        items.append(("LOW_MEMORY", "low", 15, f"deviceMemory={memory}GB"))
    if cores >= 16 and 0 <= memory < 2:
        items.append(("CPU_MEMORY_MISMATCH", "medium", 40, f"{cores} cores + {memory}GB"))
    elif cores >= 8 and 0 <= memory < 1:
        items.append(("CPU_MEMORY_MISMATCH", "medium", 40, f"{cores} cores + {memory}GB"))
    if is_mobile_phone and pixel_ratio == 1:
        items.append(("MOBILE_PIXEL_RATIO", "medium", 40, "Mobile + pixelRatio=1"))
    if 0 <= color_depth < 24:
        items.append(("LOW_COLOR_DEPTH", "low", 20, f"colorDepth={color_depth}"))
    return items


def _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile):
    items = []
    screen_w = safe_int(screen_dict.get("width"), 0)
    screen_h = safe_int(screen_dict.get("height"), 0)
    avail_w = safe_int(screen_dict.get("availWidth"), 0)
    avail_h = safe_int(screen_dict.get("availHeight"), 0)
    inner_w = safe_int(screen_dict.get("innerWidth"), 0)
    inner_h = safe_int(screen_dict.get("innerHeight"), 0)
    vp_w = adaptive_get_threshold("headless_viewport_w", 800)
    vp_h = adaptive_get_threshold("headless_viewport_h", 600)
    tiny_thresh = adaptive_get_threshold("screen_tiny_threshold", 800)
    if avail_w == vp_w and avail_h == vp_h:
        items.append(("HEADLESS_VIEWPORT", "high", 70, f"{int(vp_w)}x{int(vp_h)} viewport"))
    if avail_w == 0 or avail_h == 0:
        items.append(("VIEWPORT_ZERO", "medium", 50, "Viewport 0x0"))
    if is_mobile_phone and screen_w > 1920:
        items.append(("MOBILE_WIDE_SCREEN", "medium", 50, f"Mobile + {screen_w}px"))
    if is_tablet and screen_w > 3840:
        items.append(("TABLET_WIDE_SCREEN", "medium", 40, f"Tablet + {screen_w}px"))
    if is_desktop_chrome and not is_mobile and 0 < screen_w < tiny_thresh:
        items.append(("SCREEN_TINY", "medium", 30, f"Desktop Chrome + {screen_w}px"))
    if screen_w > 0 and inner_w > 0:
        if inner_w > screen_w * 1.5:
            items.append(("INNER_WIDER_THAN_SCREEN", "medium", 40, f"innerWidth {inner_w} > 1.5× {screen_w}"))
        elif inner_w > screen_w:
            items.append(("INNER_WIDER_THAN_SCREEN", "low", 10, f"innerWidth {inner_w} > {screen_w}"))
    if screen_h > 0 and inner_h > 0:
        if inner_h > screen_h * 1.5:
            items.append(("INNER_TALLER_THAN_SCREEN", "medium", 40, f"innerHeight {inner_h} > 1.5× {screen_h}"))
        elif inner_h > screen_h:
            items.append(("INNER_TALLER_THAN_SCREEN", "low", 10, f"innerHeight {inner_h} > {screen_h}"))
    return items


def _check_os_mismatch(ua, platform):
    items = []
    if not platform:
        return items
    if "windows nt" in ua and "win" not in platform and "linux" not in platform and "x11" not in platform:
        items.append(("OS_MISMATCH_WIN", "medium", 50, f"Windows UA + {_safe_str(platform, 30)}"))
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        items.append(("OS_MISMATCH_MAC", "medium", 50, f"macOS UA + {_safe_str(platform, 30)}"))
    return items


def _check_contradictions(nav, fp, screen_dict, ua, is_mobile, is_mobile_phone,
                           is_tablet, is_desktop_chrome, is_privacy_browser):
    items = []
    has_touch = nav.get("has_touch")
    max_touch = safe_int(nav.get("max_touch_points", nav.get("maxTouchPoints")), -1)
    if is_mobile_phone and has_touch is False:
        items.append(("TOUCH_UA_MISMATCH", "medium", 40, "Mobile UA but no touch"))
    if is_mobile_phone and max_touch == 0:
        items.append(("TOUCH_UA_MISMATCH", "medium", 40, "Mobile UA but maxTouchPoints=0"))
    lang = str(nav.get("language") or "").strip()
    langs_raw = fp.get("languages")
    if lang and isinstance(langs_raw, list) and langs_raw:
        first_lang = str(langs_raw[0]).strip()
        if first_lang and first_lang.lower() != lang.lower():
            items.append(("FIRST_LANG_MISMATCH", "low", 15, f"language={_safe_str(lang, 20)}, langs[0]={_safe_str(first_lang, 20)}"))
    intl_locale = str(fp.get("intl_locale") or "").strip()
    if intl_locale and lang:
        if intl_locale.split("-")[0].lower() != lang.split("-")[0].lower():
            items.append(("INTL_LOCALE_MISMATCH", "low", 20, f"Intl={_safe_str(intl_locale, 20)}, lang={_safe_str(lang, 20)}"))
    webgl = _safe_dict(fp.get("webgl"))
    vendor = str(webgl.get("vendor") or "").lower()
    renderer = str(webgl.get("renderer") or "").lower()
    if vendor and renderer:
        if (("nvidia" in vendor and ("intel" in renderer or "amd" in renderer)) or
            ("amd" in vendor and ("nvidia" in renderer or "intel" in renderer)) or
            ("intel" in vendor and ("nvidia" in renderer or "amd" in renderer))):
            items.append(("WEBGL_VENDOR_RENDERER_MISMATCH", "high", 50, f"Vendor={_safe_str(vendor, 25)}, Renderer={_safe_str(renderer, 25)}"))
    chrome_match = re.search(r"Chrome/(\d+)", ua)
    if chrome_match:
        chrome_major = safe_int(chrome_match.group(1), 0)
        if 0 < chrome_major < 80:
            items.append(("UA_CHROME_OLD", "medium", 30, f"Chrome {chrome_major}"))
        elif chrome_major > 200:
            items.append(("UA_CHROME_FUTURE", "high", 60, f"Chrome {chrome_major}"))
    ua_data = _safe_dict(nav.get("ua_data"))
    if ua_data.get("mobile") is True and is_desktop_chrome:
        items.append(("CLIENT_HINTS_MISMATCH", "medium", 40, "mobile=true on desktop"))
    if ua_data.get("mobile") is False and is_mobile_phone:
        items.append(("CLIENT_HINTS_MISMATCH", "medium", 40, "mobile=false but mobile UA"))
    brands = _safe_list(fp.get("ua_brands"))
    if brands and "chrome" in ua and not is_mobile:
        has_google = any("Google Chrome" in str(b.get("brand", "")) for b in brands if isinstance(b, dict))
        has_chromium = any("Chromium" in str(b.get("brand", "")) for b in brands if isinstance(b, dict))
        if has_chromium and not has_google and "chrome/" in ua:
            items.append(("UA_BRANDS_MISMATCH", "medium", 40, "Chrome UA + Chromium-only brands"))
    return items


def _check_locale_consistency(nav, fp, country_code):
    items = []
    if not country_code or country_code not in _STRONG_LANG_COUNTRIES:
        return items
    lang = str(nav.get("language") or "").strip().lower()
    primary_lang = lang.split("-")[0] if lang else ""
    if not primary_lang:
        langs_raw = fp.get("languages")
        if isinstance(langs_raw, list) and langs_raw:
            primary_lang = str(langs_raw[0]).split("-")[0].lower()
    if not primary_lang:
        return items
    expected = LANG_COUNTRY_MAP.get(primary_lang)
    if expected and country_code not in expected:
        items.append(("LANG_COUNTRY_MISMATCH", "low", 20, f"lang '{primary_lang}' but country {country_code}"))
    return items


def _check_timezone(fp, country_code, is_privacy_browser):
    items = []
    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        if not is_privacy_browser:
            items.append(("UTC_TZ", "low", 20, "UTC/Unknown timezone"))
    elif country_code in TZ_BY_COUNTRY_CODE:
        if tz not in TZ_BY_COUNTRY_CODE[country_code]:
            items.append(("TZ_MISMATCH", "low", 30, f"country {country_code} vs TZ {_safe_str(tz, 40)}"))
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
    left_fast = adaptive_get_threshold("left_fast_ms", 1800)
    zombie_min = adaptive_get_threshold("zombie_ms", 8000)
    if t_on_page > 0 and t_on_page < left_fast:
        if send_reason == "hidden":
            items.append(("LEFT_FAST_HIDDEN", "low", 15, f"Hidden after {t_on_page}ms"))
        else:
            items.append(("LEFT_FAST", "medium", 40, f"Left after {t_on_page}ms"))
    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse_analysis = (not mouse_analysis.get("too_few", True) and "total_points" in mouse_analysis)
    has_v3_mouse = ("mouse_velocity_variance" in behavior and _mouse_points_count(behavior) >= 20)
    if has_mouse_analysis:
        tp = safe_int(mouse_analysis.get("total_points"), 0)
        dv = safe_float(mouse_analysis.get("velocity_variance"), 0)
        dc = safe_int(mouse_analysis.get("direction_changes"), 0)
        mc = safe_float(mouse_analysis.get("mean_curvature"), 0)
        if tp > 20 and dv < 0.01 and dc < 2:
            items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear motion ({dc} turns, var={dv:.4f})"))
        elif tp > 20 and mc < 0.001 and dc < 3:
            items.append(("ROBOTIC_CURVATURE", "medium", 40, f"Zero curvature"))
    elif has_v3_mouse:
        tp = _mouse_points_count(behavior)
        dv = safe_float(behavior.get("mouse_velocity_variance"), 0)
        dc = safe_int(behavior.get("mouse_direction_changes"), 0)
        if tp > 20 and dv < 0.01 and dc < 2:
            items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear motion ({dc} turns, var={dv:.4f})"))
    else:
        mv = safe_float(behavior.get("mouse_variance"), 0.0)
        mv_low = adaptive_get_threshold("mouse_variance_low", 1.5)
        if mousemove > 10 and mv < mv_low:
            items.append(("ROBOTIC_VARIANCE", "medium", 50, f"Low mouse variance ({mv:.2f})"))
    has_any = mousemove > 5 or touchstart > 0 or scrolls > 0 or clicks > 0
    if t_on_page > zombie_min and not has_any:
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
    instant_move = adaptive_get_threshold("first_move_instant_ms", 100)
    idle_min = adaptive_get_threshold("idle_visible_min_ms", 5000)
    idle_ratio = adaptive_get_threshold("idle_visible_ratio", 0.98)
    if 0 <= first_move < instant_move and mousemove > 0:
        items.append(("INSTANT_FIRST_MOVE", "medium", 30, f"First mousemove after {first_move}ms"))
    if clicks_before_move > 0 and touchstart == 0:
        items.append(("CLICK_BEFORE_MOVE", "high", 60, f"{clicks_before_move} clicks before mousemove"))
    if t_on_page > idle_min and visible_time > 0:
        ratio = visible_time / t_on_page
        if ratio > idle_ratio and mousemove == 0 and clicks == 0 and scrolls == 0 and touchstart == 0:
            items.append(("IDLE_VISIBLE", "medium", 30, f"Visible {ratio*100:.0f}% no interaction"))
    click_points = behavior.get("clicks_points") or behavior.get("click_points")
    if isinstance(click_points, list) and len(click_points) >= 5:
        coord_set = set()
        for cp in click_points[:20]:
            if isinstance(cp, dict):
                try:
                    coord_set.add((int(cp.get("x", 0)), int(cp.get("y", 0))))
                except (ValueError, TypeError):
                    pass
        if len(coord_set) == 1:
            items.append(("RAPID_REPEAT_CLICKS", "medium", 40, f"{len(click_points)} clicks same point"))
    return items


def _check_webgl(webgl):
    items = []
    renderer = str(webgl.get("renderer") or "").lower()
    vendor = str(webgl.get("vendor") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        known = ("intel", "nvidia", "amd", "microsoft", "google", "apple")
        if any(v in vendor for v in known):
            items.append(("SOFT_RENDERER", "low", 20, f"Software renderer"))
        else:
            items.append(("SOFT_RENDERER", "medium", 60, "Virtual renderer"))
    return items


def _check_cpm(nav, ua, privacy_name):
    items = []
    if privacy_name in ("Brave", "Brave(heuristic)") or nav.get("is_brave") is True:
        items.append(("CPM_BRAVE", "low", 15, "Brave user"))
    _adblock_uas = ("firefox focus", "duckduckgo", "opera mini", "brave")
    for _abu in _adblock_uas:
        if _abu in ua and _abu != "brave":
            items.append(("CPM_ADBLOCK_BROWSER", "low", 10, f"AdBlock browser: {_safe_str(_abu, 30)}"))
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
        items.append(("HUMAN_RICH_INTERACTION", "human", -30, f"Rich interaction"))
    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_ma = (not mouse_analysis.get("too_few", True) and "total_points" in mouse_analysis)
    if has_ma:
        if (safe_float(mouse_analysis.get("velocity_variance"), 0) > 0.1
                and safe_int(mouse_analysis.get("direction_changes"), 0) > 5
                and safe_float(mouse_analysis.get("mean_curvature"), 0) > 0.01):
            items.append(("HUMAN_NATURAL_MOUSE", "human", -20, "Natural mouse"))
    elif "mouse_velocity_variance" in behavior:
        if (safe_float(behavior.get("mouse_velocity_variance"), 0) > 0.1
                and safe_int(behavior.get("mouse_direction_changes"), 0) > 5
                and _mouse_points_count(behavior) > 30):
            items.append(("HUMAN_NATURAL_MOUSE", "human", -20, "Natural mouse (v3)"))
    if t_on_page > 30000 and (mousemove > 10 or touchstart > 0 or scrolls > 0):
        items.append(("HUMAN_LONG_ENGAGEMENT", "human", -15, f"Long engagement"))
    return items


def _check_v3_signals(data, behavior, events, fp, ua):
    items = []
    hb_count = safe_int(data.get("_heartbeat_count"), 0)
    t_on_page = _duration_ms(behavior)
    ad_events = _safe_list(data.get("_ad_events"))
    milestones = _safe_dict(data.get("_milestones"))
    first_30s = _safe_dict(data.get("_first_30s"))
    clock_drift = safe_int(data.get("_clock_drift_ms"), 0)
    connection = _safe_dict(fp.get("connection"))
    drive_by = adaptive_get_threshold("drive_by_ms", 5000)
    silent_min = adaptive_get_threshold("silent_after_initial_ms", 5000)
    engage_zero = adaptive_get_threshold("engagement_zero_ms", 15000)
    no_mouse_min = adaptive_get_threshold("no_mouse_no_touch_ms", 8000)
    var_smooth = adaptive_get_threshold("mouse_var_smooth", 0.1)
    if hb_count == 0 and 0 < t_on_page < drive_by:
        items.append(("DRIVE_BY", "medium", 40, f"Drive-by: {t_on_page}ms"))
    elif hb_count == 0 and t_on_page >= silent_min:
        total_events = (safe_int(events.get("mousemove"), 0) + safe_int(events.get("clicks"), 0) * 3 +
                        safe_int(events.get("scrolls"), 0) * 2 + safe_int(events.get("keydown"), 0) * 3 +
                        safe_int(events.get("touchstart"), 0) * 2)
        if total_events == 0:
            items.append(("SILENT_AFTER_INITIAL", "high", 70, f"No heartbeat + no interaction"))
    if t_on_page >= engage_zero:
        total_events = (safe_int(events.get("mousemove"), 0) + safe_int(events.get("clicks"), 0) * 3 +
                        safe_int(events.get("scrolls"), 0) * 2 + safe_int(events.get("keydown"), 0) * 3 +
                        safe_int(events.get("touchstart"), 0) * 2)
        if total_events == 0:
            items.append(("ENGAGEMENT_ZERO", "medium", 40, f"Zero interaction {t_on_page/1000:.1f}s"))
        elif total_events <= 2 and t_on_page >= 45000:
            items.append(("ENGAGEMENT_VERY_LOW", "low", 25, f"Only {total_events} interactions"))
    if isinstance(first_30s, dict) and first_30s:
        has_int = first_30s.get("has_interaction_30s")
        c30 = safe_int(first_30s.get("clicks_30s"), 0)
        s30 = safe_int(first_30s.get("scrolls_30s"), 0)
        if has_int is False and t_on_page > 60000:
            items.append(("ZOMBIE_60S", "medium", 30, "No interaction in first 30s"))
        if has_int is True and (c30 + s30) >= 5 and t_on_page > 45000:
            late = (safe_int(events.get("clicks"), 0) - c30) + (safe_int(events.get("scrolls"), 0) - s30)
            if late <= 1:
                items.append(("FIRST_30S_BURST", "high", 50, "Heavy early then dead"))
    if ad_events:
        loaded = any("loaded" in str(ev.get("event", "")) for ev in ad_events if isinstance(ev, dict))
        visible = any("viewable_50pct_1s" in str(ev.get("event", "")) for ev in ad_events if isinstance(ev, dict))
        if loaded and not visible and t_on_page > 30000:
            items.append(("AD_HIDDEN_AFTER_LOAD", "medium", 40, "Ad never visible"))
    if isinstance(milestones, dict):
        t_paint = milestones.get("t_first_paint")
        t_int = milestones.get("t_first_interaction")
        try:
            if t_paint is not None and t_int is not None and int(t_int) < int(t_paint):
                diff = int(t_paint) - int(t_int)
                if diff > 500 and int(t_paint) > 100:
                    items.append(("INTERACTION_BEFORE_PAINT", "high", 60, f"Interaction {diff}ms before paint"))
        except (ValueError, TypeError):
            pass
    if abs(clock_drift) > 30000:
        items.append(("CLOCK_DRIFT", "medium", 30, f"Clock drift {clock_drift}ms"))
    scroll_pattern = str(behavior.get("scroll_pattern") or "").lower()
    scroll_depth = safe_int(behavior.get("scroll_depth_pct"), 0)
    if scroll_pattern == "linear" and safe_int(events.get("scrolls"), 0) > 5:
        items.append(("SCROLL_LINEAR", "medium", 40, "Linear scroll"))
    mouse_var = safe_float(behavior.get("mouse_velocity_variance"), 0)
    mouse_pts = _mouse_points_count(behavior)
    if mouse_pts >= 50 and 0 <= mouse_var < var_smooth:
        items.append(("MOUSE_TOO_SMOOTH", "medium", 40, f"Mouse variance too low: {mouse_var:.3f}"))
    mm = safe_int(events.get("mousemove"), 0)
    tt = safe_int(events.get("touchstart"), 0)
    if t_on_page > no_mouse_min and mm == 0 and tt == 0:
        items.append(("NO_MOUSE_NO_TOUCH", "high", 60, f"No mouse/touch for {t_on_page/1000:.0f}s"))
    if isinstance(connection, dict):
        rtt = safe_int(connection.get("rtt"), -1)
        if rtt == 0 and t_on_page > 3000:
            items.append(("CONNECTION_RTT_ZERO", "low", 15, "rtt=0"))
    if t_on_page > 30000 and hb_count >= 3:
        cl = safe_int(events.get("clicks"), 0)
        sc = safe_int(events.get("scrolls"), 0)
        if mm > 20 and cl >= 1 and sc >= 2:
            items.append(("HUMAN_ENGAGED", "human", -20, "Engaged"))
    if scroll_pattern == "organic" and scroll_depth >= 60:
        items.append(("HUMAN_DEEP_SCROLL", "human", -20, f"Organic deep scroll {scroll_depth}%"))
    kd = safe_int(events.get("keydown"), 0)
    if kd >= 3:
        items.append(("HUMAN_KEYBOARD", "human", -15, f"Typed {kd} keys"))
    return items


def _data_quality_gate(data_quality, evidence):
    if data_quality == "legacy":
        return "unknown", "DATA_LEGACY"
    if data_quality == "failed":
        return "unknown", "DATA_INSUFFICIENT"
    if data_quality == "partial":
        if not any(e.get("severity") in ("critical", "impossible") for e in evidence):
            return "unknown", "DATA_INSUFFICIENT"
    return None, None


def _check_honeypot(data):
    items = []
    if data.get("_honeypot_triggered") is True:
        items.append(("HONEYPOT_CLICK", "critical", 100, "Honeypot triggered"))
    return items


def _check_bot_ua(ua):
    items = []
    if _is_bot_ua(ua):
        items.append(("BOT_UA", "high", 90, f"Suspicious UA: {_safe_str(ua[:60], 60)}"))
    return items


def _check_server_cross(nav, fp, data):
    headers = data.get("_headers") or {}
    http_version = data.get("_http_version") or "1.1"
    return scv_analyze(headers, http_version, nav, fp)


def _check_threat_intel(ip_info, data):
    ip = data.get("client_ip") or ""
    return ti_analyze(ip, ip_info)


def _check_fingerprint_graph(data):
    fp_hash = str(data.get("_fp_hash") or "").strip()
    client_ip = str(data.get("client_ip") or "").strip()
    if not fp_hash or not client_ip:
        return []
    return fp_graph_analyze(fp_hash, client_ip)


def _check_ml(data, ip_info):
    return ml_analyze(data, ip_info)


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
    is_desktop_chrome = ("chrome" in ua and not is_mobile and not is_ios
                         and "headless" not in ua and "edg/" not in ua and "opr/" not in ua)
    is_privacy_browser, privacy_name = _detect_privacy_browser(ua, platform, fp, nav)
    chrome_check = fp.get("chrome_check", "")
    asn_value = safe_asn(ip_info.get("asn", ""))
    if asn_value and not asn_value.upper().startswith("AS"):
        asn_value = "AS" + asn_value
    is_proxy = sec.get("proxy") is True
    is_hosting = (sec.get("hosting") is True or str(ip_info.get("type", "")).lower() == "hosting")
    country_code = str(ip_info.get("country_code") or "").upper()

    _apply_items(ev, cb_safe_call(_check_critical, nav, fp, ua, platform, chrome_check, check_name="critical"))
    _apply_items(ev, cb_safe_call(_check_automation_globals, fp, check_name="automation_globals"))
    _apply_items(ev, cb_safe_call(_check_honeypot, data, check_name="honeypot"))
    _apply_items(ev, cb_safe_call(_check_bot_ua, ua, check_name="bot_ua"))
    _apply_items(ev, cb_safe_call(_check_network, ip_info, data, asn_value, is_proxy, is_hosting, check_name="network"))
    _apply_items(ev, cb_safe_call(_check_fingerprint, fp, plugins_info, is_desktop_chrome,
                                   is_privacy_browser, chrome_check, ua, check_name="fingerprint"))
    _apply_items(ev, cb_safe_call(_check_fingerprint_reuse, data, check_name="fingerprint_reuse"))
    _apply_items(ev, cb_safe_call(_check_cross_visit, data, check_name="cross_visit"))
    _apply_items(ev, cb_safe_call(_check_hardware, fp, screen_dict, ua, is_privacy_browser, is_mobile_phone, check_name="hardware"))
    _apply_items(ev, cb_safe_call(_check_screen, screen_dict, is_mobile_phone, is_tablet,
                                   is_desktop_chrome, is_mobile, check_name="screen"))
    _apply_items(ev, cb_safe_call(_check_os_mismatch, ua, platform, check_name="os_mismatch"))
    _apply_items(ev, cb_safe_call(_check_contradictions, nav, fp, screen_dict, ua, is_mobile,
                                   is_mobile_phone, is_tablet, is_desktop_chrome, is_privacy_browser, check_name="contradictions"))
    _apply_items(ev, cb_safe_call(_check_locale_consistency, nav, fp, country_code, check_name="locale"))
    _apply_items(ev, cb_safe_call(_check_timezone, fp, country_code, is_privacy_browser, check_name="timezone"))
    _apply_items(ev, cb_safe_call(_check_behavior, behavior, events, check_name="behavior"))
    _apply_items(ev, cb_safe_call(_check_behavior_deep, behavior, events, check_name="behavior_deep"))
    _apply_items(ev, cb_safe_call(_check_v3_signals, data, behavior, events, fp, ua, check_name="v3_signals"))
    _apply_items(ev, cb_safe_call(_check_webgl, webgl, check_name="webgl"))
    _apply_items(ev, cb_safe_call(_check_cpm, nav, ua, privacy_name, check_name="cpm"))
    _apply_items(ev, cb_safe_call(_check_human, behavior, events, check_name="human"))
    _apply_items(ev, cb_safe_call(_check_server_cross, nav, fp, data, check_name="server_cross"))
    _apply_items(ev, cb_safe_call(_check_threat_intel, ip_info, data, check_name="threat_intel"))
    _apply_items(ev, cb_safe_call(_check_fingerprint_graph, data, check_name="fingerprint_graph"))
    _apply_items(ev, cb_safe_call(_check_ml, data, ip_info, check_name="ml_engine"))

    raw = ev.raw_score()
    data_quality = str(data.get("_data_quality") or "unknown")
    prob_result = bayes_compute(ev.items)
    probability = prob_result["probability"]
    log_odds = prob_result["log_odds"]
    bayesian_confidence = prob_result["confidence"]
    verdict_result = classify_verdict_v2(ev.items, data_quality, probability=probability)
    verdict_v2 = verdict_result["verdict"]
    final_verdict = to_legacy_verdict(verdict_v2)
    if verdict_v2 == VerdictV2.INSUFFICIENT_DATA:
        final = 0
        confidence = 0.0
        gate_code = verdict_result.get("gate_code") or "DATA_INSUFFICIENT"
        ev.items.append({
            "code": gate_code, "severity": "medium", "score": 0,
            "detail": f"Data quality: {data_quality} — insufficient",
        })
    else:
        final = ev.final_score()
        confidence = calc_confidence(ev.items)
    categories = ev.counts()
    cpm_quality = compute_cpm_quality(ev.items, final_verdict)
    wasted = is_wasted_impression(ev.items, final_verdict)
    return {
        "raw_score": raw, "score": final, "final_score": final,
        "verdict": final_verdict, "confidence": confidence,
        "evidence": ev.items, "categories": categories,
        "privacy_browser": privacy_name or None,
        "cpm_quality": cpm_quality, "wasted_impression": wasted,
        "data_quality": data_quality,
        "probability": probability, "log_odds": log_odds,
        "bayesian_confidence": bayesian_confidence,
        "bayesian_contributions": prob_result.get("contributions", []),
        "verdict_v2": verdict_v2.value,
        "verdict_metadata": verdict_metadata(verdict_v2),
        "safety_triggered": verdict_result.get("safety"),
        "gate_code": verdict_result.get("gate_code"),
    }


# =========================================================
# INTEGRATION TESTS (all 8 systems)
# =========================================================
_CLEAN_DATA = {
    "nav": {"ua": "Mozilla/5.0 Chrome/120.0.0.0", "platform": "Win32"},
    "fingerprint": {"hardwareConcurrency": 8, "deviceMemory": 8,
                    "canvas_hash": "abc123def456789",
                    "languages": ["en-US", "en"], "timezone": "America/New_York"},
    "behavior": {"events": {"mousemove": 100, "clicks": 3, "scrolls": 6},
                  "total_time_ms": 25000, "mouse_variance": 2.5},
    "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040},
    "_data_quality": "full", "_heartbeat_count": 3,
}
_CLEAN_IP = {"country": "US", "country_code": "US", "isp": "Comcast",
             "type": "residential", "asn": "AS7922", "security": {}}


def _run_system_tests(system_num: int, tests: list):
    print("\n" + "=" * 70)
    print(f"  SYSTEM {system_num}: INTEGRATION TEST")
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

    for name, fn in tests:
        try:
            fn(_chk)
        except Exception as e:
            _chk(False, "", f"{name}: crashed ({e})")

    for r in results:
        print(f"  {r}")
    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    status = "✅ PASSED" if success else "❌ FAILED"
    print(f"  {status} — {passed}/{len(results)} tests")
    print("=" * 70 + "\n")
    return success


def _system1_integration_test():
    def t1(_chk):
        ev = EvidenceCollector()
        _apply_items(ev, cb_safe_call(lambda: [("F", "medium", 15, "x")], check_name="t1"))
        _chk(len(ev.items) == 1, "Test 1: safe_call works", "Test 1: failed")
    def t2(_chk):
        items = cb_safe_call(lambda: (_ for _ in ()).throw(RuntimeError()), check_name="t2")
        _chk(items == [], "Test 2: [] on failure", "Test 2: failed")
    def t3(_chk):
        ev = EvidenceCollector()
        _apply_items(ev, cb_safe_call(lambda: [("A", "low", 5, "a")], check_name="t3a"))
        _apply_items(ev, cb_safe_call(lambda: (_ for _ in ()).throw(ValueError()), check_name="t3b"))
        _apply_items(ev, cb_safe_call(lambda: [("B", "high", 30, "b")], check_name="t3c"))
        _chk(len(ev.items) == 2, "Test 3: isolated breakers", "Test 3: failed")
    def t4(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r is not None and "verdict" in r, "Test 4: end-to-end", "Test 4: failed")
    def t5(_chk):
        cb_breakers.reset_all()
        for _ in range(6):
            cb_safe_call(lambda: (_ for _ in ()).throw(ValueError()), check_name="t5")
        b = cb_breakers.get("t5")
        _chk(b is not None and b.state.value == "open", "Test 5: opens", "Test 5: failed")
        cb_breakers.reset_all()
    return _run_system_tests(1, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5)])


def _system2_integration_test():
    def t1(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk("probability" in r and "log_odds" in r, "Test 1: Bayesian fields", "Test 1: failed")
    def t2(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(0.0 <= r["probability"] <= 1.0, "Test 2: P range", "Test 2: failed")
    def t3(_chk):
        bad = dict(_CLEAN_DATA); bad["nav"] = dict(_CLEAN_DATA["nav"]); bad["nav"]["webdriver"] = True
        r = analyze_visit(bad, _CLEAN_IP)
        _chk(r["probability"] > 0.90, "Test 3: webdriver", "Test 3: failed")
    def t4(_chk):
        legacy = dict(_CLEAN_DATA); legacy["_data_quality"] = "legacy"
        r = analyze_visit(legacy, _CLEAN_IP)
        _chk(r["verdict"] == "unknown", "Test 4: legacy", "Test 4: failed")
    def t5(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(isinstance(r["log_odds"], (int, float)), "Test 5: log_odds", "Test 5: failed")
    return _run_system_tests(2, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5)])


def _system3_integration_test():
    def t1(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk("verdict_v2" in r, "Test 1: verdict_v2", "Test 1: failed")
    def t2(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(isinstance(r.get("verdict_metadata"), dict), "Test 2: metadata", "Test 2: failed")
    def t3(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r["verdict"] == to_legacy_verdict(r["verdict_v2"]), "Test 3: consistency", "Test 3: failed")
    def t4(_chk):
        bad = dict(_CLEAN_DATA); bad["nav"] = dict(_CLEAN_DATA["nav"]); bad["nav"]["webdriver"] = True
        r = analyze_visit(bad, _CLEAN_IP)
        _chk(r["verdict_v2"] in ("confirmed_bot", "likely_bot"), "Test 4: bot tier", "Test 4: failed")
    def t5(_chk):
        legacy = dict(_CLEAN_DATA); legacy["_data_quality"] = "legacy"
        r = analyze_visit(legacy, _CLEAN_IP)
        _chk(r["verdict_v2"] == "insufficient_data", "Test 5: insufficient", "Test 5: failed")
    def t6(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r["verdict"] == "valid", "Test 6: valid tier", "Test 6: failed")
    return _run_system_tests(3, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5), ("T6", t6)])


def _system4_integration_test():
    def t1(_chk):
        d = dict(_CLEAN_DATA); d["_headers"] = {}
        r = analyze_visit(d, _CLEAN_IP)
        _chk(r is not None, "Test 1: empty headers", "Test 1: failed")
    def t2(_chk):
        d = dict(_CLEAN_DATA); d["_headers"] = {"user-agent": "Firefox/100.0"}
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("HTTP_UA_JS_MISMATCH" in codes, "Test 2: mismatch", "Test 2: failed")
    def t3(_chk):
        d = dict(_CLEAN_DATA); d["nav"] = {"ua": "Firefox/120.0", "platform": "Win32"}
        d["_headers"] = {"user-agent": "Firefox/120.0", "sec-ch-ua": '"Chromium";v="120"', "x-forwarded-proto": "https"}
        r = analyze_visit(d, _CLEAN_IP)
        imp = [e for e in r["evidence"] if isinstance(e, dict) and e.get("code") == "SEC_CH_UA_ON_FIREFOX"]
        _chk(len(imp) == 1 and imp[0].get("severity") == "impossible", "Test 3: impossible", "Test 3: failed")
    def t4(_chk):
        d = dict(_CLEAN_DATA); d["nav"] = {"ua": "Firefox/120.0", "platform": "Win32"}
        d["_headers"] = {"user-agent": "Firefox/120.0", "sec-ch-ua": '"Chromium";v="120"', "x-forwarded-proto": "https"}
        r = analyze_visit(d, _CLEAN_IP)
        _chk(r["verdict_v2"] == "confirmed_bot", "Test 4: confirmed_bot", "Test 4: failed")
    def t5(_chk):
        d = dict(_CLEAN_DATA); d["_headers"] = {"user-agent": "Chrome/120", "sec-ch-ua": '"HeadlessChrome";v="120"', "x-forwarded-proto": "https"}
        r = analyze_visit(d, _CLEAN_IP)
        _chk(r["verdict_v2"] == "confirmed_bot", "Test 5: Headless", "Test 5: failed")
    def t6(_chk):
        ev = EvidenceCollector()
        ev.risk("X", "impossible", 100, "test")
        _chk(ev.has_critical(), "Test 6: impossible counts", "Test 6: failed")
    return _run_system_tests(4, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5), ("T6", t6)])


def _system5_integration_test():
    def t1(_chk):
        v = adaptive_get_threshold("left_fast_ms", 1800)
        _chk(v == 1800.0, "Test 1: default threshold", "Test 1: failed")
    def t2(_chk):
        v = adaptive_get_reliability("UNKNOWN", 0.75)
        _chk(v == 0.75, "Test 2: default reliability", "Test 2: failed")
    def t3(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r is not None, "Test 3: works", "Test 3: failed")
    def t4(_chk):
        from collector import adaptive_thresholds as _at
        _at._get_instance().set_threshold("left_fast_ms", 10000)
        quick = dict(_CLEAN_DATA); quick["behavior"] = dict(_CLEAN_DATA["behavior"])
        quick["behavior"]["total_time_ms"] = 5000
        quick["behavior"]["events"] = {"mousemove": 0, "clicks": 0, "scrolls": 0}
        r = analyze_visit(quick, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _at._get_instance().set_threshold("left_fast_ms", 1800)
        _chk("LEFT_FAST" in codes, "Test 4: adaptive threshold", "Test 4: failed")
    def t5(_chk):
        h = adaptive_health_status()
        _chk(isinstance(h, dict) and h.get("system") == "adaptive_thresholds", "Test 5: health", "Test 5: failed")
    return _run_system_tests(5, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5)])


def _system6_integration_test():
    def t1(_chk):
        d = dict(_CLEAN_DATA); d["client_ip"] = "185.220.100.240"
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("THREAT_TOR_EXIT" in codes and r["verdict_v2"] == "confirmed_bot", "Test 1: TOR", "Test 1: failed")
    def t2(_chk):
        d = dict(_CLEAN_DATA); d["client_ip"] = "3.5.5.5"
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("THREAT_DATACENTER_CIDR" in codes, "Test 2: AWS CIDR", "Test 2: failed")
    def t3(_chk):
        d = dict(_CLEAN_DATA); d["client_ip"] = "190.5.5.5"
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("THREAT_TOR_EXIT" not in codes and "THREAT_DATACENTER_CIDR" not in codes, "Test 3: clean", "Test 3: failed")
    def t4(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r is not None, "Test 4: no client_ip", "Test 4: failed")
    def t5(_chk):
        d = dict(_CLEAN_DATA); d["client_ip"] = "192.168.1.100"
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("THREAT_TOR_EXIT" not in codes and "THREAT_DATACENTER_CIDR" not in codes, "Test 5: private IP", "Test 5: failed")
    def t6(_chk):
        h = ti_health_status()
        _chk(isinstance(h, dict) and h.get("system") == "threat_intel", "Test 6: health", "Test 6: failed")
    return _run_system_tests(6, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5), ("T6", t6)])


def _system7_integration_test():
    def t1(_chk):
        from collector import fingerprint_graph as fpg
        fpg.reset()
        d = dict(_CLEAN_DATA); d["_fp_hash"] = "fp_single_" + str(id(d)); d["client_ip"] = "50.0.0.1"
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("FINGERPRINT_FARM_MASSIVE" not in codes and "FINGERPRINT_FARM_SMALL" not in codes,
             "Test 1: single visit no farm", "Test 1: failed")
    def t2(_chk):
        import time as _t
        from collector import fingerprint_graph as fpg
        fpg.reset()
        fp_key = "fp_small_" + str(_t.time_ns())
        for i in range(5):
            d = dict(_CLEAN_DATA); d["_fp_hash"] = fp_key; d["client_ip"] = f"51.0.0.{i}"
            r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("FINGERPRINT_FARM_SMALL" in codes, "Test 2: 5 IPs small", "Test 2: failed")
    def t3(_chk):
        import time as _t
        from collector import fingerprint_graph as fpg
        fpg.reset()
        fp_key = "fp_massive_" + str(_t.time_ns())
        for i in range(20):
            d = dict(_CLEAN_DATA); d["_fp_hash"] = fp_key; d["client_ip"] = f"52.0.0.{i}"
            r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("FINGERPRINT_FARM_MASSIVE" in codes, "Test 3: 20 IPs massive", "Test 3: failed")
    def t4(_chk):
        import time as _t
        from collector import fingerprint_graph as fpg
        fpg.reset()
        fp_key = "fp_bad_" + str(_t.time_ns())
        fpg.mark_known_bad(fp_key)
        d = dict(_CLEAN_DATA); d["_fp_hash"] = fp_key; d["client_ip"] = "53.0.0.1"
        r = analyze_visit(d, _CLEAN_IP)
        codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
        _chk("FINGERPRINT_KNOWN_BAD" in codes, "Test 4: known bad", "Test 4: failed")
    def t5(_chk):
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r is not None, "Test 5: no fp_hash", "Test 5: failed")
    def t6(_chk):
        h = fp_graph_health_status()
        _chk(isinstance(h, dict) and h.get("system") == "fingerprint_graph", "Test 6: health", "Test 6: failed")
    return _run_system_tests(7, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5), ("T6", t6)])


def _system8_integration_test():
    def t1(_chk):
        # No model → analyze_visit works gracefully
        from collector import ml_engine as ml_mod
        # Ensure no model in place for this test
        r = analyze_visit(dict(_CLEAN_DATA), _CLEAN_IP)
        _chk(r is not None and "verdict" in r, "Test 1: analyze_visit works without ML model", "Test 1: failed")
    def t2(_chk):
        # ml_analyze returns list always
        from collector.ml_engine import analyze_ml
        r = analyze_ml({}, {})
        _chk(isinstance(r, list), "Test 2: analyze_ml returns list", "Test 2: failed")
    def t3(_chk):
        # health status works
        h = ml_health_status()
        _chk(isinstance(h, dict) and h.get("system") == "ml_engine", "Test 3: health_status", "Test 3: failed")
    def t4(_chk):
        # CODE_TO_SOURCE has ML entries
        _chk("ML_HIGH_RISK" in CODE_TO_SOURCE and CODE_TO_SOURCE["ML_HIGH_RISK"] == "ml_engine",
             "Test 4: CODE_TO_SOURCE has ML entries", "Test 4: failed")
    def t5(_chk):
        # After mock training + save, analyze_visit includes ML signal
        import tempfile, os as _os
        from collector import ml_engine as ml_mod
        orig = ml_mod.DEFAULT_STORAGE_PATH
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
        _os.close(tmp_fd)
        _os.unlink(tmp_path)
        ml_mod.DEFAULT_STORAGE_PATH = tmp_path
        try:
            class FakeBot:
                ground_truth = "bot"
                evidence = [{"code": "WEBDRIVER_FLAG"}]
                clicks = 0; scrolls = 0; time_on_page = 500
                hardware = ""; is_vpn = True; canvas_hash = ""
                device = "Desktop"; os = "Linux"
            class FakeHuman:
                ground_truth = "human"
                evidence = []
                clicks = 5; scrolls = 10; time_on_page = 30000
                hardware = ""; is_vpn = False; canvas_hash = "abc"
                device = "Desktop"; os = "Windows"
            visits = []
            for _ in range(60):
                visits.append(FakeBot())
                visits.append(FakeHuman())
            model = ml_mod.train_from_visits(visits, epochs=300)
            ml_mod.save_model(model)
            # Now run analyze_visit on a bot-like visit
            bot_data = {
                "nav": {"ua": "Mozilla/5.0 Chrome/120", "platform": "Win32", "webdriver": True},
                "fingerprint": {"hardwareConcurrency": 2, "deviceMemory": 2,
                                "canvas_hash": "abc123", "languages": ["en-US"]},
                "behavior": {"events": {"mousemove": 0, "clicks": 0, "scrolls": 0},
                              "total_time_ms": 500, "mouse_variance": 0.0},
                "screen": {"width": 800, "height": 600, "availWidth": 800, "availHeight": 600},
                "_data_quality": "full", "_heartbeat_count": 0,
            }
            bot_ip = {"country": "US", "country_code": "US", "isp": "X",
                      "type": "residential", "asn": "AS1",
                      "security": {"vpn": True, "proxy": True}}
            r = analyze_visit(bot_data, bot_ip)
            codes = {e.get("code") for e in r["evidence"] if isinstance(e, dict)}
            _chk("ML_HIGH_RISK" in codes or "ML_ELEVATED_RISK" in codes,
                 f"Test 5: ML signal fires after training (got {codes})",
                 f"Test 5: no ML signal (got {codes})")
        finally:
            ml_mod.DEFAULT_STORAGE_PATH = orig
            if _os.path.exists(tmp_path):
                _os.unlink(tmp_path)
            ml_mod.reload_model()
    def t6(_chk):
        # ML doesn't crash on garbage input
        from collector.ml_engine import analyze_ml
        try:
            r = analyze_ml(None, None)
            r2 = analyze_ml({}, None)
            r3 = analyze_ml({"weird": "data"}, {"weird": "ip"})
            _chk(all(isinstance(x, list) for x in (r, r2, r3)),
                 "Test 6: ML handles garbage input", "Test 6: crashed")
        except Exception as e:
            _chk(False, "", f"Test 6: crashed ({e})")
    return _run_system_tests(8, [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5), ("T6", t6)])


if os.getenv("OVG_SELF_TEST_ENABLED", "1") == "1" and "pytest" not in __import__("sys").modules:
    for _tfn in [_system1_integration_test, _system2_integration_test,
                 _system3_integration_test, _system4_integration_test,
                 _system5_integration_test, _system6_integration_test,
                 _system7_integration_test, _system8_integration_test]:
        try:
            _tfn()
        except Exception as _e:
            print(f"⚠️  [{_tfn.__name__}] crashed: {_e}")