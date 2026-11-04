"""
analysis.py — OVG Tracker

Phase 1-7 (see prior changelog).
Phase 8 — Ground Truth + Explainability:
  [60] CODE_TO_SOURCE          → map evidence code → source check
  [61] build_explainability_trace → decision path reconstruction
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
# BOT UA PATTERNS
# =========================================================
BOT_UA_PATTERNS = (
    "curl", "wget", "httpie",
    "python-requests", "requests/",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "undici",
    "httpclient", "libwww", "restsharp",
    "headless", "selenium", "phantom", "puppeteer", "playwright",
    "scrapy", "guzzle", "httpx",
    "postman", "insomnia", "apitester",
    "automated", "automation", "http_request",
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
# EXPLAINABILITY ENGINE (Phase 8)
# =========================================================
CODE_TO_SOURCE = {
    "WEBDRIVER_FLAG": "critical", "CDP_DETECTED": "critical",
    "WINDOWS_UA_LINUX": "critical", "FIREFOX_CHROME_OBJ": "critical",
    "PUPPETEER_DETECTED": "automation", "PLAYWRIGHT_DETECTED": "automation",
    "SELENIUM_DETECTED": "automation", "NIGHTMARE_DETECTED": "automation",
    "PHANTOM_DETECTED": "automation",
    "BOT_UA": "ua",
    "VPN_DATACENTER": "network", "DATACENTER_IP": "network",
    "VPN_PROXY": "network", "DATACENTER_ASN": "network",
    "WEBRTC_LEAK": "network", "WEBRTC_VPN_DIFF": "network",
    "PLUGINS_ZERO": "fingerprint", "CHROME_NO_OBJ": "fingerprint",
    "CANVAS_BLOCKED": "fingerprint", "CANVAS_MISSING": "fingerprint",
    "LANGUAGES_EMPTY": "fingerprint", "SINGLE_LANG": "fingerprint",
    "NO_MIME_TYPES": "fingerprint", "NO_PDF_VIEWER": "fingerprint",
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
    "INSTANT_FIRST_MOVE": "behavior_deep", "CLICK_BEFORE_MOVE": "behavior_deep",
    "IDLE_VISIBLE": "behavior_deep", "RAPID_REPEAT_CLICKS": "behavior_deep",
    "SOFT_RENDERER": "webgl",
    "CPM_BRAVE": "cpm", "CPM_ADBLOCK_BROWSER": "cpm",
    "HUMAN_RICH_INTERACTION": "human", "HUMAN_NATURAL_MOUSE": "human",
    "HUMAN_LONG_ENGAGEMENT": "human",
    "LEGACY_SIGNAL": "legacy", "MOCK_SIGNAL": "mock",
}


def build_explainability_trace(evidence_items):
    """يبني decision path من evidence المخزّن."""
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
    if is_desktop_chrome and not is_mobile and 0 < screen_w < 1024:
        items.append(("SCREEN_TINY", "medium", 30, f"Desktop Chrome + {screen_w}px screen (headless/VNC)"))
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
    max_touch = safe_int(nav.get("max_touch_points"), -1)
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
            items.append(("TZ_MISMATCH", "medium", 60, f"IP country {country_code} vs TZ {_safe_str(tz, 40)}"))
    return items


def _check_behavior(behavior, events):
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)
    send_reason = str(behavior.get("send_reason") or "unknown").lower()
    if t_on_page < 1800:
        if send_reason == "hidden":
            items.append(("LEFT_FAST_HIDDEN", "low", 15, f"Hidden after {t_on_page}ms (user switched tab)"))
        else:
            items.append(("LEFT_FAST", "medium", 40, f"Left after {t_on_page}ms"))
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
            items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear motion ({dc} turns, var={dv:.4f})"))
        elif tp > 20 and mc < 0.001 and dc < 3:
            items.append(("ROBOTIC_CURVATURE", "medium", 40, f"Zero curvature (mc={mc:.4f})"))
    else:
        mv = safe_float(behavior.get("mouse_variance"), 0.0)
        if mousemove > 10 and mv < 1.5:
            items.append(("ROBOTIC_VARIANCE", "medium", 50, f"Low mouse variance ({mv:.2f})"))
    has_any_interaction = (
        mousemove > 5
        or safe_int(events.get("touchstart"), 0) > 0
        or scrolls > 0
        or clicks > 0
    )
    if t_on_page > 8000 and not has_any_interaction:
        items.append(("ZOMBIE", "low", 30, f"No interaction after {t_on_page}ms"))
    return items


def _check_behavior_deep(behavior, events):
    items = []
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)
    first_move = safe_int(behavior.get("first_move_delay_ms"), -1)
    clicks_before_move = safe_int(behavior.get("clicks_before_move"), 0)
    visible_time = safe_int(behavior.get("visible_time_ms"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    mousemove = safe_int(events.get("mousemove"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    if 0 <= first_move < 100 and mousemove > 0:
        items.append(("INSTANT_FIRST_MOVE", "medium", 30, f"First mousemove after {first_move}ms (scripted)"))
    if clicks_before_move > 0 and touchstart == 0:
        items.append(("CLICK_BEFORE_MOVE", "high", 60, f"{clicks_before_move} clicks before any mousemove"))
    if t_on_page > 5000 and visible_time > 0:
        ratio = visible_time / t_on_page
        if ratio > 0.98 and mousemove == 0 and clicks == 0 and scrolls == 0 and touchstart == 0:
            items.append(("IDLE_VISIBLE", "medium", 30, f"Visible {ratio*100:.0f}% with no interaction"))
    click_points = behavior.get("click_points")
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
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)
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
    if t_on_page > 30000 and (mousemove > 10 or touchstart > 0 or scrolls > 0):
        items.append(("HUMAN_LONG_ENGAGEMENT", "human", -15, f"Long engagement ({t_on_page}ms)"))
    return items


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

    _apply_items(ev, _check_critical(nav, fp, ua, platform, chrome_check))
    _apply_items(ev, _check_automation_globals(fp))

    if _is_bot_ua(ua):
        ev.risk("BOT_UA", "high", 90, f"Suspicious UA: {_safe_str(ua[:60], 60)}")

    _apply_items(ev, _check_network(ip_info, data, asn_value, is_proxy, is_hosting))
    _apply_items(ev, _check_fingerprint(
        fp, plugins_info, is_desktop_chrome, is_privacy_browser, chrome_check, ua,
    ))
    _apply_items(ev, _check_fingerprint_reuse(data))
    _apply_items(ev, _check_cross_visit(data))
    _apply_items(ev, _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone))
    _apply_items(ev, _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile))
    _apply_items(ev, _check_os_mismatch(ua, platform))
    _apply_items(ev, _check_contradictions(
        nav, fp, screen_dict, ua, is_mobile, is_mobile_phone,
        is_tablet, is_desktop_chrome, is_privacy_browser,
    ))
    _apply_items(ev, _check_locale_consistency(nav, fp, country_code))
    _apply_items(ev, _check_timezone(fp, country_code, is_privacy_browser))
    _apply_items(ev, _check_behavior(behavior, events))
    _apply_items(ev, _check_behavior_deep(behavior, events))
    _apply_items(ev, _check_webgl(webgl))
    _apply_items(ev, _check_cpm(nav, ua, privacy_name))
    _apply_items(ev, _check_human(behavior, events))

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