"""
analysis.py — OVG Tracker — The Brain (v3.2 Precision)
"""
import re
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


# =========================================================
# BOT UA PATTERNS
# =========================================================
BOT_UA_PATTERNS = (
    "curl", "wget", "httpie", "python-requests", "requests/",
    "go-http-client", "java/", "okhttp", "axios/", "node-fetch",
    "headless", "headlesschrome", "selenium", "phantomjs", "puppeteer",
    "playwright", "scrapy", "postman", "insomnia", "automated",
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "petalbot", "bytespider",
    "gptbot", "claudebot", "ccbot", "yandexbot", "bingpreview",
    "facebookexternalhit", "linkedinbot", "twitterbot", "googlebot",
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
    if BOT_UA_WORDS_RE.search(ua) or BOT_WORD_RE.search(ua):
        return True
    return False


def _is_headless_ua(ua: str) -> bool:
    if not ua:
        return False
    return bool(HEADLESS_UA_RE.search(ua))


# =========================================================
# DATACENTER ASNs
# =========================================================
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
    "PS": {"asia/gaza", "asia/hebron"}, "TR": {"europe/istanbul", "asia/istanbul"},
    "IL": {"asia/jerusalem", "asia/tel_aviv"}, "IR": {"asia/tehran"},
    "MA": {"africa/casablanca"}, "DZ": {"africa/algiers"}, "TN": {"africa/tunis"},
    "LY": {"africa/tripoli"}, "SD": {"africa/khartoum"}, "GB": {"europe/london"},
    "IE": {"europe/dublin"}, "IT": {"europe/rome", "europe/milan"},
    "DE": {"europe/berlin", "europe/frankfurt"}, "FR": {"europe/paris"},
    "ES": {"europe/madrid", "africa/ceuta"}, "PT": {"europe/lisbon", "atlantic/azores"},
    "NL": {"europe/amsterdam"}, "BE": {"europe/brussels"}, "CH": {"europe/zurich"},
    "AT": {"europe/vienna"}, "SE": {"europe/stockholm"}, "NO": {"europe/oslo"},
    "DK": {"europe/copenhagen"}, "FI": {"europe/helsinki"}, "PL": {"europe/warsaw"},
    "CZ": {"europe/prague"}, "RO": {"europe/bucharest"}, "GR": {"europe/athens"},
    "RU": {"europe/moscow", "europe/kaliningrad", "europe/samara", "europe/volgograd",
           "europe/saratov", "asia/yekaterinburg", "asia/novosibirsk", "asia/omsk",
           "asia/krasnoyarsk", "asia/irkutsk", "asia/yakutsk", "asia/vladivostok",
           "asia/magadan", "asia/kamchatka"},
    "US": {"america/new_york", "america/chicago", "america/denver", "america/phoenix",
           "america/los_angeles", "america/anchorage", "america/honolulu", "america/detroit",
           "america/indianapolis", "america/boise", "america/juneau", "america/sitka",
           "america/nome", "america/adak"},
    "CA": {"america/toronto", "america/vancouver", "america/edmonton", "america/winnipeg",
           "america/halifax", "america/st_johns", "america/regina", "america/whitehorse",
           "america/yellowknife"},
    "MX": {"america/mexico_city", "america/tijuana", "america/cancun", "america/monterrey", "america/chihuahua"},
    "BR": {"america/sao_paulo", "america/rio_branco", "america/manaus", "america/belem", "america/fortaleza", "america/recife", "america/noronha"},
    "AR": {"america/argentina/buenos_aires", "america/argentina/cordoba"},
    "CO": {"america/bogota"}, "CL": {"america/santiago", "pacific/easter"},
    "PE": {"america/lima"}, "VE": {"america/caracas"}, "IN": {"asia/kolkata", "asia/calcutta"},
    "JP": {"asia/tokyo"}, "CN": {"asia/shanghai", "asia/beijing", "asia/chongqing"},
    "HK": {"asia/hong_kong"}, "KR": {"asia/seoul"}, "TW": {"asia/taipei"},
    "TH": {"asia/bangkok"}, "VN": {"asia/ho_chi_minh"}, "MY": {"asia/kuala_lumpur"},
    "SG": {"asia/singapore"}, "ID": {"asia/jakarta", "asia/makassar", "asia/jayapura"},
    "PH": {"asia/manila"}, "PK": {"asia/karachi", "asia/lahore"}, "BD": {"asia/dhaka"},
    "LK": {"asia/colombo"}, "AF": {"asia/kabul"}, "NG": {"africa/lagos"},
    "KE": {"africa/nairobi"}, "GH": {"africa/accra"}, "ZA": {"africa/johannesburg", "africa/cape_town"},
    "ET": {"africa/addis_ababa"}, "AU": {"australia/sydney", "australia/melbourne", "australia/brisbane",
                                        "australia/perth", "australia/adelaide", "australia/hobart", "australia/darwin"},
    "NZ": {"pacific/auckland"},
}

LANG_COUNTRY_MAP = {
    "ar": {"EG", "SA", "AE", "KW", "QA", "BH", "OM", "JO", "LB", "SY", "IQ", "YE", "PS", "MA", "DZ", "TN", "LY", "SD"},
    "es": {"ES", "MX", "AR", "CO", "CL", "PE", "VE"}, "fr": {"FR", "BE", "CH", "CA"},
    "de": {"DE", "AT", "CH"}, "pt": {"PT", "BR"}, "ru": {"RU", "BY", "KZ"},
    "zh": {"CN", "TW", "HK", "SG"}, "ja": {"JP"}, "ko": {"KR"}, "hi": {"IN"}, "tr": {"TR"},
    "it": {"IT"}, "nl": {"NL", "BE"}, "pl": {"PL"}, "vi": {"VN"}, "th": {"TH"},
    "id": {"ID"}, "ms": {"MY", "SG"}, "fa": {"IR", "AF"}, "he": {"IL"},
}

_STRONG_LANG_COUNTRIES = {
    "EG", "SA", "AE", "KW", "QA", "BH", "OM", "JO", "LB", "SY", "IQ", "YE", "PS",
    "MA", "DZ", "TN", "LY", "SD", "RU", "CN", "JP", "KR", "IR", "TR", "IL", "TH", "VN", "ID",
}


async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {"country": "Local", "country_code": "LO", "isp": "Local ISP", "type": "residential", "asn": "N/A", "security": {}, "lat": 0.0, "lon": 0.0}
    cached = ip_cache.get(ip)
    if cached is not None:
        return cached
    try:
        import httpx
        async with httpx.AsyncClient() as c:
            r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,as,proxy,hosting,lat,lon", timeout=GEO_LOOKUP_TIMEOUT)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    is_proxy = bool(d.get("proxy"))
                    is_hosting = bool(d.get("hosting"))
                    out = {
                        "country": d.get("country", "Unknown"), "country_code": str(d.get("countryCode") or "").upper()[:2],
                        "isp": d.get("isp", "Unknown"), "type": "hosting" if is_hosting else "residential",
                        "asn": safe_asn(d.get("as")), "security": {"vpn": is_proxy or is_hosting, "proxy": is_proxy, "hosting": is_hosting},
                        "lat": safe_float(d.get("lat"), 0.0), "lon": safe_float(d.get("lon"), 0.0),
                    }
                    ip_cache.set(ip, out)
                    return out
    except Exception:
        pass
    return {"country": "Unknown", "country_code": "", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}, "lat": 0.0, "lon": 0.0}


def parse_ua(ua: str):
    u = (ua or "").lower()
    device = "Mobile" if "mobi" in u else "Tablet" if ("tablet" in u or "ipad" in u) else "Desktop"
    if "windows nt" in u: os_name = "Windows"
    elif "mac os" in u or "macintosh" in u: os_name = "macOS"
    elif "android" in u: os_name = "Android"
    elif "iphone" in u or "ipad" in u or "ios" in u: os_name = "iOS"
    elif "linux" in u: os_name = "Linux"
    else: os_name = "Unknown"
    if "edg/" in u or "edge/" in u: browser = "Edge"
    elif "chrome" in u and "chromium" not in u: browser = "Chrome"
    elif "firefox" in u: browser = "Firefox"
    elif "safari" in u and "chrome" not in u: browser = "Safari"
    else: browser = "Unknown"
    return os_name, device, browser


def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v: return v[0]
    except Exception: pass
    return "unknown"


def new_site_key() -> str:
    import secrets
    return secrets.token_hex(8)


def _detect_privacy_browser(ua: str, platform: str, fp: dict, nav: dict):
    ua_lower = ua.lower()
    if nav.get("is_brave") is True: return True, "Brave"
    if "firefox" in ua_lower and not platform: return True, "Firefox-RFP"
    canvas = fp.get("canvas_hash")
    if canvas == "blocked" and "chrome" in ua_lower and "headless" not in ua_lower: return True, "Brave(heuristic)"
    return False, ""


def _check_webrtc(webrtc_str, client_ip, ip_info):
    if not webrtc_str or webrtc_str == "None" or not client_ip: return 0, ""
    raw_parts = [p.strip() for p in str(webrtc_str).split(",") if p.strip()]
    valid_leaks = []
    for part in raw_parts:
        try: addr = ipaddress.ip_address(part)
        except ValueError: continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved: continue
        if part == client_ip: continue
        valid_leaks.append(part)
    if not valid_leaks: return 0, ""
    if ip_info.get("security", {}).get("vpn"): return 20, f"WebRTC Differs (likely VPN): {_safe_str(valid_leaks[0], 60)}"
    return 90, f"WebRTC Leak: {_safe_str(valid_leaks[0], 60)}"


VALID_SEVERITIES = frozenset(["critical", "high", "medium", "low", "human"])
VALID_VERDICTS = frozenset(["valid", "invalid", "suspicious", "unknown"])


class EvidenceCollector:
    def __init__(self):
        self.items = []
    def _add(self, code, severity, score, detail):
        if severity not in VALID_SEVERITIES: severity = "medium"
        self.items.append({"code": _safe_str(code, 50), "severity": severity, "score": int(score), "detail": _safe_str(detail, 200)})
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
        for item in self.items: counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        return counts


def _apply_items(ev, items):
    for code, sev, score, detail in items:
        if sev == "human": ev.human(code, abs(score), detail)
        else: ev.risk(code, sev, score, detail)


def calc_confidence(signals: list) -> float:
    if not signals: return 0.0
    non_human = [s for s in signals if s.get("severity") != "human"]
    if not non_human: return 0.0
    criticals = sum(1 for s in non_human if s.get("severity") == "critical")
    highs = sum(1 for s in non_human if s.get("severity") == "high")
    mediums = sum(1 for s in non_human if s.get("severity") == "medium")

    if criticals >= 2: return 0.99
    if criticals == 1: return 0.95
    if highs >= 3: return 0.90
    if highs >= 2 and mediums >= 1: return 0.85
    if highs >= 2: return 0.80
    if highs == 1 and mediums >= 2: return 0.70
    if highs == 1: return 0.60
    if mediums >= 3: return 0.55
    if mediums >= 1: return 0.35
    return 0.20


def count_categories(signals: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
    for s in signals:
        sev = s.get("severity", "medium") if isinstance(s, dict) else "medium"
        if sev in counts: counts[sev] += 1
    return counts


def normalize_stored_evidence(evidence):
    if not evidence: return []
    result = []
    for e in evidence:
        if isinstance(e, dict):
            result.append({"code": e.get("code", "UNKNOWN"), "severity": e.get("severity", "medium"), "score": int(e.get("score", 0) or 0), "detail": e.get("detail", "")})
        elif isinstance(e, str):
            result.append({"code": "LEGACY_SIGNAL", "severity": "medium", "score": 0, "detail": e})
    return result


_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])
_PREMIUM_HUMAN_CODES = frozenset(["HUMAN_NATURAL_MOUSE", "HUMAN_RICH_INTERACTION"])
_PREMIUM_EXTRA_CODES = frozenset(["HUMAN_LONG_ENGAGEMENT"])


def compute_cpm_quality(evidence_items: list, verdict: str) -> str:
    if verdict == "invalid": return "invalid"
    if verdict == "unknown": return "unknown"
    codes = {e.get("code") for e in evidence_items if isinstance(e, dict) and e.get("code")}
    if codes & _WASTED_CODES: return "wasted"
    if verdict == "suspicious": return "low"
    if (codes & _PREMIUM_HUMAN_CODES) and (codes & _PREMIUM_EXTRA_CODES): return "premium"
    if len(codes & _PREMIUM_HUMAN_CODES) >= 2: return "premium"
    return "standard"


def is_wasted_impression(evidence_items: list, verdict: str) -> bool:
    if verdict == "invalid": return False
    codes = {e.get("code") for e in evidence_items if isinstance(e, dict) and e.get("code")}
    return bool(codes & _WASTED_CODES)


CODE_TO_SOURCE = {
    "WEBDRIVER_FLAG": "critical", "CDP_DETECTED": "critical", "WINDOWS_UA_LINUX": "critical",
    "FIREFOX_CHROME_OBJ": "critical", "HEADLESS_UA": "critical", "UNTRUSTED_CLICK": "critical",
    "HONEYPOT_CLICK": "honeypot", "HONEYPOT_FORM_FILL": "honeypot", "IMPOSSIBLE_SPEED": "behavior_deep",
    "PUPPETEER_DETECTED": "automation", "PLAYWRIGHT_DETECTED": "automation", "SELENIUM_DETECTED": "automation",
    "NIGHTMARE_DETECTED": "automation", "PHANTOM_DETECTED": "automation", "BOT_UA": "ua",
    "VPN_DATACENTER": "network", "DATACENTER_IP": "network", "VPN_PROXY": "network",
    "DATACENTER_ASN": "network", "WEBRTC_LEAK": "network", "WEBRTC_VPN_DIFF": "network",
    "PLUGINS_ZERO": "fingerprint", "CHROME_NO_OBJ": "fingerprint", "CANVAS_BLOCKED": "fingerprint",
    "CANVAS_MISSING": "fingerprint", "LANGUAGES_EMPTY": "fingerprint", "SINGLE_LANG": "fingerprint",
    "NO_MIME_TYPES": "fingerprint", "NO_PDF_VIEWER": "fingerprint", "SPEECH_VOICES_ZERO": "fingerprint",
    "WEBGL_PRECISION_ZERO": "fingerprint", "UA_BRANDS_MISMATCH": "fingerprint",
    "FINGERPRINT_REUSE_HIGH": "fingerprint_reuse", "FINGERPRINT_REUSE_MED": "fingerprint_reuse",
    "FINGERPRINT_REUSE_LOW": "fingerprint_reuse", "IP_VELOCITY_HIGH": "cross_visit",
    "IP_VELOCITY_MED": "cross_visit", "FINGERPRINT_MULTI_IP": "cross_visit",
    "IP_MULTI_FINGERPRINT": "cross_visit", "CORES_ZERO": "hardware", "CORES_LOW": "hardware",
    "ABSURD_CORES": "hardware", "LOW_MEMORY": "hardware", "CPU_MEMORY_MISMATCH": "hardware",
    "MOBILE_PIXEL_RATIO": "hardware", "LOW_COLOR_DEPTH": "hardware", "HEADLESS_VIEWPORT": "screen",
    "VIEWPORT_ZERO": "screen", "MOBILE_WIDE_SCREEN": "screen", "TABLET_WIDE_SCREEN": "screen",
    "SCREEN_TINY": "screen", "INNER_WIDER_THAN_SCREEN": "screen", "INNER_TALLER_THAN_SCREEN": "screen",
    "OS_MISMATCH_WIN": "os", "OS_MISMATCH_MAC": "os", "TOUCH_UA_MISMATCH": "contradictions",
    "FIRST_LANG_MISMATCH": "contradictions", "INTL_LOCALE_MISMATCH": "contradictions",
    "WEBGL_VENDOR_RENDERER_MISMATCH": "contradictions", "UA_CHROME_OLD": "contradictions",
    "UA_CHROME_FUTURE": "contradictions", "CLIENT_HINTS_MISMATCH": "contradictions",
    "LANG_COUNTRY_MISMATCH": "locale", "UTC_TZ": "timezone", "TZ_MISMATCH": "timezone",
    "LEFT_FAST": "behavior", "LEFT_FAST_HIDDEN": "behavior", "ROBOTIC_LINEAR": "behavior",
    "ROBOTIC_CURVATURE": "behavior", "ZOMBIE": "behavior", "SCROLL_LINEAR": "behavior",
    "MOUSE_TOO_SMOOTH": "behavior", "INSTANT_FIRST_MOVE": "behavior_deep",
    "CLICK_BEFORE_MOVE": "behavior_deep", "IDLE_VISIBLE": "behavior_deep",
    "RAPID_REPEAT_CLICKS": "behavior_deep", "ENGAGEMENT_ZERO": "behavior_deep",
    "ENGAGEMENT_VERY_LOW": "behavior_deep", "FIRST_30S_BURST": "behavior_deep",
    "ZOMBIE_60S": "behavior_deep", "NO_MOUSE_NO_TOUCH": "behavior_deep",
    "SOFT_RENDERER": "webgl", "SILENT_AFTER_INITIAL": "session", "HEARTBEAT_GAP": "session",
    "DRIVE_BY": "session", "CLOCK_DRIFT": "session", "AD_HIDDEN_AFTER_LOAD": "ad_events",
    "INTERACTION_BEFORE_PAINT": "milestones", "CONNECTION_RTT_ZERO": "connection",
    "CPM_BRAVE": "cpm", "CPM_ADBLOCK_BROWSER": "cpm", "HUMAN_RICH_INTERACTION": "human",
    "HUMAN_NATURAL_MOUSE": "human", "HUMAN_LONG_ENGAGEMENT": "human", "HUMAN_DEEP_SCROLL": "human",
    "HUMAN_KEYBOARD": "human", "HUMAN_ENGAGED": "human", "LEGACY_SIGNAL": "legacy",
    "MOCK_SIGNAL": "mock", "DATA_LEGACY": "data_quality", "DATA_INSUFFICIENT": "data_quality",
}


def build_explainability_trace(evidence_items):
    if not evidence_items: return []
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
        else: continue
        step += 1
        running += score
        trace.append({"step": step, "code": _safe_str(code, 50), "source": CODE_TO_SOURCE.get(code, "unknown"), "severity": sev, "score": score, "running_total": running, "detail": _safe_str(detail, 200)})
    return trace


# =========================================================
# SIGNAL CHECKS
# =========================================================
def _check_critical(nav, fp, ua, platform, chrome_check):
    items = []
    if _is_headless_ua(ua): items.append(("HEADLESS_UA", "critical", 100, f"Headless UA: {_safe_str(ua[:60], 60)}"))
    untrusted = safe_int(fp.get("_untrusted_clicks"), 0)
    if untrusted >= 1: items.append(("UNTRUSTED_CLICK", "critical", 100, f"{untrusted} JS-injected clicks"))
    if nav.get("webdriver") is True: items.append(("WEBDRIVER_FLAG", "critical", 100, "navigator.webdriver === true"))
    if fp.get("cdp_detected") is True: items.append(("CDP_DETECTED", "critical", 100, "CDP Runtime Detected"))
    return items


def _check_automation_globals(fp):
    items = []
    automation = _safe_dict(fp.get("automation"))
    if automation.get("puppeteer") is True: items.append(("PUPPETEER_DETECTED", "critical", 100, "puppeteer present"))
    if automation.get("playwright") is True: items.append(("PLAYWRIGHT_DETECTED", "critical", 100, "playwright present"))
    if automation.get("selenium") is True or automation.get("cdc") is True: items.append(("SELENIUM_DETECTED", "critical", 100, "selenium/cdc present"))
    if automation.get("nightmare") is True: items.append(("NIGHTMARE_DETECTED", "critical", 100, "__nightmare present"))
    if automation.get("phantom") is True: items.append(("PHANTOM_DETECTED", "critical", 100, "PhantomJS present"))
    return items


def _check_network(ip_info, data, asn_value, is_proxy, is_hosting):
    items = []
    if is_proxy and is_hosting: items.append(("VPN_DATACENTER", "high", 80, "VPN + Datacenter IP"))
    elif is_hosting: items.append(("DATACENTER_IP", "high", 70, "Datacenter/Hosting IP"))
    elif is_proxy: items.append(("VPN_PROXY", "medium", 50, "VPN/Proxy IP"))
    
    if asn_value and asn_value.upper() in DATACENTER_ASNS and not is_hosting:
        items.append(("DATACENTER_ASN", "high", 80, f"Datacenter ASN: {asn_value}"))
        
    webrtc_penalty, webrtc_evidence = _check_webrtc(data.get("webrtc_ip"), data.get("client_ip"), ip_info)
    if webrtc_penalty >= 90: items.append(("WEBRTC_LEAK", "high", webrtc_penalty, webrtc_evidence))
    elif webrtc_penalty > 0: items.append(("WEBRTC_VPN_DIFF", "medium", webrtc_penalty, webrtc_evidence))
    return items


def _check_fingerprint(fp, plugins_info, is_desktop_chrome, is_privacy_browser, chrome_check, ua):
    items = []
    plugin_count = safe_int(plugins_info.get("count"), -1, max_val=1000)
    if is_desktop_chrome and not is_privacy_browser and plugin_count == 0:
        items.append(("PLUGINS_ZERO", "high", 60, "Chrome desktop: 0 plugins"))
    if is_desktop_chrome and not is_privacy_browser and chrome_check == "no_window_chrome":
        items.append(("CHROME_NO_OBJ", "high", 60, "Chrome UA: no window.chrome"))

    canvas = fp.get("canvas_hash")
    if canvas == "blocked": items.append(("CANVAS_BLOCKED", "low", 10, "Canvas blocked (privacy)"))
    elif not canvas or len(str(canvas)) < 5: items.append(("CANVAS_MISSING", "medium", 60, "Canvas hash missing"))

    langs_raw = fp.get("languages")
    if isinstance(langs_raw, list):
        if len(langs_raw) == 0: items.append(("LANGUAGES_EMPTY", "medium", 40, "Empty languages"))
        elif len(langs_raw) == 1 and langs_raw[0] == "en-US" and is_desktop_chrome and not is_privacy_browser:
            items.append(("SINGLE_LANG", "low", 15, "Only single en-US language"))

    mime_count = safe_int(fp.get("mime_types_count"), -1)
    if is_desktop_chrome and not is_privacy_browser and mime_count == 0:
        items.append(("NO_MIME_TYPES", "medium", 40, "Chrome desktop: 0 mimeTypes"))

    pdf_viewer = fp.get("pdf_viewer")
    if is_desktop_chrome and not is_privacy_browser and pdf_viewer is False:
        items.append(("NO_PDF_VIEWER", "low", 15, "Chrome desktop: pdfViewer=false"))

    speech = fp.get("speech_voices")
    if speech is not None:
        sv = safe_int(speech, -1)
        if sv == 0 and not is_privacy_browser:
            items.append(("SPEECH_VOICES_ZERO", "high", 70, "speechSynthesis.getVoices() = 0"))

    wgp = _safe_dict(fp.get("webgl_precision"))
    if wgp:
        hf = safe_int(wgp.get("high_float"), -99)
        if hf in (0, -1) and not is_privacy_browser:
            items.append(("WEBGL_PRECISION_ZERO", "high", 60, f"WebGL high_float = {hf}"))

    return items


def _check_fingerprint_reuse(data):
    items = []
    recent_fp = safe_int(data.get("_recent_fp_count"), 0)
    if recent_fp >= 50: items.append(("FINGERPRINT_REUSE_HIGH", "high", 80, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp >= 30: items.append(("FINGERPRINT_REUSE_HIGH", "high", 60, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp >= 20: items.append(("FINGERPRINT_REUSE_MED", "medium", 40, f"Fingerprint reuse ({recent_fp}/min)"))
    elif recent_fp > 10: items.append(("FINGERPRINT_REUSE_LOW", "low", 25, f"Fingerprint reuse ({recent_fp}/min)"))
    return items


def _check_cross_visit(data):
    items = []
    same_ip = safe_int(data.get("_same_ip_last_minute"), 0)
    canvas_ips = safe_int(data.get("_same_canvas_ip_count"), 0)
    ip_canvases = safe_int(data.get("_same_ip_canvas_count"), 0)
    if same_ip >= 10: items.append(("IP_VELOCITY_HIGH", "high", 70, f"Same IP: {same_ip} visits/min"))
    elif same_ip >= 5: items.append(("IP_VELOCITY_MED", "medium", 40, f"Same IP: {same_ip} visits/min"))
    if canvas_ips >= 5: items.append(("FINGERPRINT_MULTI_IP", "high", 60, f"Same canvas {canvas_ips} IPs/hr"))
    elif canvas_ips >= 3: items.append(("FINGERPRINT_MULTI_IP", "medium", 40, f"Same canvas {canvas_ips} IPs/hr"))
    if ip_canvases >= 10: items.append(("IP_MULTI_FINGERPRINT", "high", 70, f"Same IP {ip_canvases} canvases/hr"))
    elif ip_canvases >= 5: items.append(("IP_MULTI_FINGERPRINT", "medium", 40, f"Same IP {ip_canvases} canvases/hr"))
    return items


def _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone):
    items = []
    cores = safe_int(fp.get("hardwareConcurrency"), -1, max_val=256)
    memory = safe_float(fp.get("deviceMemory"), -1, max_val=1024)
    pixel_ratio = safe_float(screen_dict.get("pixelRatio"), -1, max_val=100)
    color_depth = safe_int(screen_dict.get("colorDepth"), -1, max_val=64)

    if cores == 0:
        if not is_privacy_browser and "firefox" not in ua: items.append(("CORES_ZERO", "medium", 40, "hardwareConcurrency=0"))
    elif cores == 1: items.append(("CORES_LOW", "low", 15, "Single-core"))
    elif cores > 128: items.append(("ABSURD_CORES", "high", 60, f"cores={cores} (spoofed)"))

    if 0 <= memory < 0.25: items.append(("LOW_MEMORY", "low", 15, f"deviceMemory={memory}GB"))
    if cores >= 16 and 0 <= memory < 2: items.append(("CPU_MEMORY_MISMATCH", "medium", 40, f"{cores} cores + {memory}GB RAM"))
    elif cores >= 8 and 0 <= memory < 1: items.append(("CPU_MEMORY_MISMATCH", "medium", 40, f"{cores} cores + {memory}GB RAM"))

    if is_mobile_phone and pixel_ratio == 1: items.append(("MOBILE_PIXEL_RATIO", "medium", 40, "Mobile pixelRatio=1"))
    if 0 <= color_depth < 24: items.append(("LOW_COLOR_DEPTH", "low", 20, f"colorDepth={color_depth}"))
    return items


def _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile):
    items = []
    screen_w = safe_int(screen_dict.get("width"), 0)
    screen_h = safe_int(screen_dict.get("height"), 0)
    avail_w = safe_int(screen_dict.get("availWidth"), 0)
    avail_h = safe_int(screen_dict.get("availHeight"), 0)
    inner_w = safe_int(screen_dict.get("innerWidth"), 0)
    inner_h = safe_int(screen_dict.get("innerHeight"), 0)

    if avail_w == 800 and avail_h == 600: items.append(("HEADLESS_VIEWPORT", "high", 70, "Default 800x600"))
    if avail_w == 0 or avail_h == 0: items.append(("VIEWPORT_ZERO", "medium", 50, "Viewport 0x0"))
    if is_mobile_phone and screen_w > 1920: items.append(("MOBILE_WIDE_SCREEN", "medium", 50, f"Mobile {screen_w}px"))
    if is_tablet and screen_w > 3840: items.append(("TABLET_WIDE_SCREEN", "medium", 40, f"Tablet {screen_w}px"))
    if is_desktop_chrome and not is_mobile and 0 < screen_w < 800: items.append(("SCREEN_TINY", "medium", 30, f"Desktop {screen_w}px"))

    if screen_w > 0 and inner_w > 0:
        if inner_w > screen_w * 2.0: items.append(("INNER_WIDER_THAN_SCREEN", "medium", 40, f"innerWidth {inner_w} > 2x {screen_w}"))
    if screen_h > 0 and inner_h > 0:
        if inner_h > screen_h * 2.0: items.append(("INNER_TALLER_THAN_SCREEN", "medium", 40, f"innerHeight {inner_h} > 2x {screen_h}"))
    return items


def _check_os_mismatch(ua, platform):
    items = []
    if not platform: return items
    if "windows nt" in ua and "win" not in platform and "linux" not in platform and "x11" not in platform:
        items.append(("OS_MISMATCH_WIN", "medium", 50, f"Windows UA + platform {_safe_str(platform, 30)}"))
    if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
        items.append(("OS_MISMATCH_MAC", "medium", 50, f"macOS UA + platform {_safe_str(platform, 30)}"))
    return items


def _check_contradictions(nav, fp, screen_dict, ua, is_mobile, is_mobile_phone, is_tablet, is_desktop_chrome, is_privacy_browser):
    items = []
    has_touch = nav.get("has_touch")
    max_touch = safe_int(nav.get("max_touch_points", nav.get("maxTouchPoints")), -1)

    if is_mobile_phone and has_touch is False: items.append(("TOUCH_UA_MISMATCH", "medium", 40, "Mobile UA no touch"))
    if is_mobile_phone and max_touch == 0: items.append(("TOUCH_UA_MISMATCH", "medium", 40, "Mobile UA maxTouchPoints=0"))

    lang = str(nav.get("language") or "").strip()
    langs_raw = fp.get("languages")
    if lang and isinstance(langs_raw, list) and langs_raw:
        first_lang = str(langs_raw[0]).strip()
        if first_lang and first_lang.lower() != lang.lower():
            items.append(("FIRST_LANG_MISMATCH", "low", 15, f"language vs languages[0]"))

    intl_locale = str(fp.get("intl_locale") or "").strip()
    if intl_locale and lang:
        intl_primary = intl_locale.split("-")[0].lower()
        lang_primary = lang.split("-")[0].lower()
        if intl_primary and lang_primary and intl_primary != lang_primary:
            items.append(("INTL_LOCALE_MISMATCH", "low", 20, f"Intl={intl_locale} vs lang={lang}"))

    webgl = _safe_dict(fp.get("webgl"))
    vendor = str(webgl.get("vendor") or "").lower()
    renderer = str(webgl.get("renderer") or "").lower()
    if vendor and renderer:
        mismatch = ("nvidia" in vendor and ("intel" in renderer or "amd" in renderer)) or \
                   ("amd" in vendor and ("nvidia" in renderer or "intel" in renderer)) or \
                   ("intel" in vendor and ("nvidia" in renderer or "amd" in renderer))
        if mismatch: items.append(("WEBGL_VENDOR_RENDERER_MISMATCH", "high", 50, f"Vendor={vendor}, Renderer={renderer}"))

    chrome_match = re.search(r"Chrome/(\d+)", ua)
    if chrome_match:
        chrome_major = safe_int(chrome_match.group(1), 0)
        if 0 < chrome_major < 80: items.append(("UA_CHROME_OLD", "medium", 30, f"Chrome {chrome_major}"))
        elif chrome_major > 200: items.append(("UA_CHROME_FUTURE", "high", 60, f"Chrome {chrome_major}"))

    ua_data = _safe_dict(nav.get("ua_data"))
    ua_data_mobile = ua_data.get("mobile")
    if ua_data_mobile is True and is_desktop_chrome: items.append(("CLIENT_HINTS_MISMATCH", "medium", 40, "uaData mobile=true on desktop"))
    if ua_data_mobile is False and is_mobile_phone: items.append(("CLIENT_HINTS_MISMATCH", "medium", 40, "uaData mobile=false on mobile"))

    brands = _safe_list(fp.get("ua_brands"))
    if brands and "chrome" in ua and not is_mobile:
        has_google = any("Google Chrome" in str(b.get("brand", "")) for b in brands if isinstance(b, dict))
        has_chromium = any("Chromium" in str(b.get("brand", "")) for b in brands if isinstance(b, dict))
        if has_chromium and not has_google and "chrome/" in ua:
            items.append(("UA_BRANDS_MISMATCH", "medium", 40, "UA Chrome but brands only Chromium"))
    return items


def _check_locale_consistency(nav, fp, country_code):
    items = []
    if not country_code or country_code not in _STRONG_LANG_COUNTRIES: return items
    lang = str(nav.get("language") or "").strip().lower()
    primary_lang = lang.split("-")[0] if lang else ""
    if not primary_lang:
        langs_raw = fp.get("languages")
        if isinstance(langs_raw, list) and langs_raw: primary_lang = str(langs_raw[0]).split("-")[0].lower()
    if not primary_lang: return items
    expected_countries = LANG_COUNTRY_MAP.get(primary_lang)
    if expected_countries and country_code not in expected_countries:
        items.append(("LANG_COUNTRY_MISMATCH", "low", 20, f"Lang '{primary_lang}' vs IP {country_code}"))
    return items


def _check_timezone(fp, country_code, is_privacy_browser):
    items = []
    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        if not is_privacy_browser: items.append(("UTC_TZ", "low", 20, "UTC/Unknown timezone"))
    elif country_code in TZ_BY_COUNTRY_CODE:
        expected_tzs = TZ_BY_COUNTRY_CODE[country_code]
        if tz not in expected_tzs: items.append(("TZ_MISMATCH", "low", 30, f"IP {country_code} vs TZ {tz}"))
    return items


def _check_behavior(behavior, events):
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    t_on_page = _duration_ms(behavior)
    
    # 1. Mouse
    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse = not mouse_analysis.get("too_few", True) and "total_points" in mouse_analysis
    has_v3_mouse = "mouse_velocity_variance" in behavior and _mouse_points_count(behavior) >= 20

    if has_mouse:
        tp = safe_int(mouse_analysis.get("total_points"), 0)
        dv = safe_float(mouse_analysis.get("velocity_variance"), 0)
        dc = safe_int(mouse_analysis.get("direction_changes"), 0)
        mc = safe_float(mouse_analysis.get("mean_curvature"), 0)
        if tp > 20 and dv < 0.01 and dc < 2: items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear ({dc} turns)"))
        elif tp > 20 and mc < 0.001 and dc < 3: items.append(("ROBOTIC_CURVATURE", "medium", 40, f"Zero curvature"))
    elif has_v3_mouse:
        tp = _mouse_points_count(behavior)
        dv = safe_float(behavior.get("mouse_velocity_variance"), 0)
        dc = safe_int(behavior.get("mouse_direction_changes"), 0)
        if tp > 20 and dv < 0.01 and dc < 2: items.append(("ROBOTIC_LINEAR", "high", 60, f"Linear ({dc} turns)"))

    # 2. Interaction
    has_any = (mousemove > 5 or touchstart > 0 or scrolls > 0 or clicks > 0)
    
    # 3. Zombie (جلسة طويلة بدون أي تفاعل)
    if t_on_page > 8000 and not has_any:
        items.append(("ZOMBIE", "high", 60, f"No interaction after {t_on_page}ms"))
        
    return items


def _check_behavior_deep(behavior, events):
    items = []
    t_on_page = _duration_ms(behavior)
    first_move = safe_int(behavior.get("first_move_delay_ms"), -1)
    clicks_before_move = safe_int(behavior.get("clicks_before_move"), 0)
    visible_time = safe_int(behavior.get("visible_time_ms"), 0)
    mousemove = safe_int(events.get("mousemove"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)

    if 0 <= first_move < 100 and mousemove > 0: items.append(("INSTANT_FIRST_MOVE", "medium", 30, "First move < 100ms"))
    if clicks_before_move > 0 and touchstart == 0: items.append(("CLICK_BEFORE_MOVE", "high", 60, "Click before move"))
    if t_on_page > 5000 and visible_time > 0:
        ratio = visible_time / t_on_page
        if ratio > 0.98 and mousemove == 0 and clicks == 0 and scrolls == 0 and touchstart == 0:
            items.append(("IDLE_VISIBLE", "medium", 30, "Visible idle"))

    click_points = behavior.get("clicks_points") or behavior.get("click_points")
    if isinstance(click_points, list) and len(click_points) >= 5:
        coord_set = set()
        for cp in click_points[:20]:
            if isinstance(cp, dict):
                try: coord_set.add((int(cp.get("x", 0)), int(cp.get("y", 0))))
                except (ValueError, TypeError): pass
        if len(click_points) >= 5 and len(coord_set) == 1:
            items.append(("RAPID_REPEAT_CLICKS", "medium", 40, "Same point clicks"))
    return items


def _check_v3_signals(data, behavior, events, fp, ua):
    items = []
    hb_count = safe_int(data.get("_heartbeat_count"), 0)
    t_on_page = _duration_ms(behavior)
    ad_events = _safe_list(data.get("_ad_events"))
    milestones = _safe_dict(data.get("_milestones"))
    clock_drift = safe_int(data.get("_clock_drift_ms"), 0)
    connection = _safe_dict(fp.get("connection"))

    if hb_count == 0 and 0 < t_on_page < 5000: items.append(("DRIVE_BY", "medium", 40, f"Drive-by: {t_on_page}ms"))
    elif hb_count == 0 and t_on_page >= 5000:
        total_events = safe_int(events.get("mousemove"), 0) + safe_int(events.get("clicks"), 0)*3 + safe_int(events.get("scrolls"), 0)*2
        if total_events == 0: items.append(("SILENT_AFTER_INITIAL", "high", 70, "No heartbeat + no interaction"))

    if t_on_page >= 15000:
        total_events = safe_int(events.get("mousemove"), 0) + safe_int(events.get("clicks"), 0)*3 + safe_int(events.get("scrolls"), 0)*2
        if total_events == 0: items.append(("ENGAGEMENT_ZERO", "medium", 40, f"Zero over {t_on_page/1000:.1f}s"))
        elif total_events <= 2 and t_on_page >= 45000: items.append(("ENGAGEMENT_VERY_LOW", "low", 25, f"Only {total_events} interactions"))

    if ad_events:
        loaded = any("loaded" in str(ev.get("event", "")) for ev in ad_events if isinstance(ev, dict))
        visible = any("viewable_50pct_1s" in str(ev.get("event", "")) for ev in ad_events if isinstance(ev, dict))
        if loaded and not visible and t_on_page > 30000: items.append(("AD_HIDDEN_AFTER_LOAD", "medium", 40, "Ad cloaking"))

    if isinstance(milestones, dict):
        t_paint = milestones.get("t_first_paint")
        t_int = milestones.get("t_first_interaction")
        try:
            if t_paint is not None and t_int is not None and int(t_int) < int(t_paint):
                diff = int(t_paint) - int(t_int)
                if diff > 500 and int(t_paint) > 100: items.append(("INTERACTION_BEFORE_PAINT", "high", 60, f"Interaction {diff}ms before paint"))
        except (ValueError, TypeError): pass

    if abs(clock_drift) > 30000: items.append(("CLOCK_DRIFT", "medium", 30, f"Drift {clock_drift}ms"))
    
    scroll_pattern = str(behavior.get("scroll_pattern") or "").lower()
    if scroll_pattern == "linear" and safe_int(events.get("scrolls"), 0) > 5: items.append(("SCROLL_LINEAR", "medium", 40, "Linear scroll"))
    
    mouse_var = safe_float(behavior.get("mouse_velocity_variance"), 0)
    if _mouse_points_count(behavior) >= 50 and 0 <= mouse_var < 0.1: items.append(("MOUSE_TOO_SMOOTH", "medium", 40, "Too smooth"))
    
    if t_on_page > 8000 and safe_int(events.get("mousemove"), 0) == 0 and safe_int(events.get("touchstart"), 0) == 0:
        items.append(("NO_MOUSE_NO_TOUCH", "high", 60, f"No mouse/touch over {t_on_page/1000:.0f}s"))

    if isinstance(connection, dict):
        if safe_int(connection.get("rtt"), -1) == 0 and t_on_page > 3000: items.append(("CONNECTION_RTT_ZERO", "low", 15, "RTT=0"))

    return items


def _check_human(behavior, events):
    items = []
    mousemove = safe_int(events.get("mousemove"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = _duration_ms(behavior)

    if mousemove > 50 and scrolls > 5 and clicks > 2 and t_on_page > 15000:
        items.append(("HUMAN_RICH_INTERACTION", "human", -30, f"Rich interaction"))
    mouse_analysis = _safe_dict(behavior.get("mouse_analysis"))
    has_mouse = not mouse_analysis.get("too_few", True) and "total_points" in mouse_analysis
    if has_mouse:
        if safe_float(mouse_analysis.get("velocity_variance"), 0) > 0.1 and safe_int(mouse_analysis.get("direction_changes"), 0) > 5:
            items.append(("HUMAN_NATURAL_MOUSE", "human", -20, "Natural mouse"))
    elif "mouse_velocity_variance" in behavior:
        if safe_float(behavior.get("mouse_velocity_variance"), 0) > 0.1 and safe_int(behavior.get("mouse_direction_changes"), 0) > 5:
            items.append(("HUMAN_NATURAL_MOUSE", "human", -20, "Natural mouse (v3)"))
    if t_on_page > 30000 and (mousemove > 10 or safe_int(events.get("touchstart"), 0) > 0 or scrolls > 0):
        items.append(("HUMAN_LONG_ENGAGEMENT", "human", -15, f"Long engagement"))
    return items


def _data_quality_gate(data_quality, evidence):
    if data_quality == "legacy": return "unknown", "DATA_LEGACY"
    if data_quality == "failed": return "unknown", "DATA_INSUFFICIENT"
    if data_quality == "partial":
        has_critical = any(e.get("severity") == "critical" for e in evidence)
        if not has_critical: return "unknown", "DATA_INSUFFICIENT"
    return None, None


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
    is_desktop_chrome = "chrome" in ua and not is_mobile and not is_ios and "headless" not in ua and "edg/" not in ua and "opr/" not in ua

    is_privacy_browser, privacy_name = _detect_privacy_browser(ua, platform, fp, nav)
    chrome_check = fp.get("chrome_check", "")
    asn_value = safe_asn(ip_info.get("asn", ""))
    if asn_value and not asn_value.upper().startswith("AS"): asn_value = "AS" + asn_value
    
    is_proxy = sec.get("proxy") is True
    is_hosting = sec.get("hosting") is True or str(ip_info.get("type", "")).lower() == "hosting"
    country_code = str(ip_info.get("country_code") or "").upper()

    _apply_items(ev, _check_critical(nav, fp, ua, platform, chrome_check))
    _apply_items(ev, _check_automation_globals(fp))
    
    if data.get("_honeypot_triggered") is True: ev.risk("HONEYPOT_CLICK", "critical", 100, "Honeypot triggered")
    if _is_bot_ua(ua): ev.risk("BOT_UA", "high", 90, f"UA: {_safe_str(ua[:60], 60)}")

    _apply_items(ev, _check_network(ip_info, data, asn_value, is_proxy, is_hosting))
    _apply_items(ev, _check_fingerprint(fp, plugins_info, is_desktop_chrome, is_privacy_browser, chrome_check, ua))
    _apply_items(ev, _check_fingerprint_reuse(data))
    _apply_items(ev, _check_cross_visit(data))
    _apply_items(ev, _check_hardware(fp, screen_dict, ua, is_privacy_browser, is_mobile_phone))
    _apply_items(ev, _check_screen(screen_dict, is_mobile_phone, is_tablet, is_desktop_chrome, is_mobile))
    _apply_items(ev, _check_os_mismatch(ua, platform))
    _apply_items(ev, _check_contradictions(nav, fp, screen_dict, ua, is_mobile, is_mobile_phone, is_tablet, is_desktop_chrome, is_privacy_browser))
    _apply_items(ev, _check_locale_consistency(nav, fp, country_code))
    _apply_items(ev, _check_timezone(fp, country_code, is_privacy_browser))
    _apply_items(ev, _check_behavior(behavior, events))
    _apply_items(ev, _check_behavior_deep(behavior, events))
    _apply_items(ev, _check_v3_signals(data, behavior, events, fp, ua))
    _apply_items(ev, _check_human(behavior, events))

    raw = ev.raw_score()
    final = ev.final_score()
    confidence = calc_confidence(ev.items)
    categories = ev.counts()

    data_quality = str(data.get("_data_quality") or "unknown")
    gate_verdict, gate_code = _data_quality_gate(data_quality, ev.items)

    if gate_verdict == "unknown":
        final_verdict = "unknown"
        final = 0
        ev.items.append({"code": gate_code, "severity": "medium", "score": 0, "detail": f"Data quality: {data_quality}"})
        confidence = 0.0
    else:
        if ev.has_critical(): final_verdict = "invalid"
        elif final >= 80: final_verdict = "invalid"
        elif final >= 40: final_verdict = "suspicious"
        else: final_verdict = "valid"

    cpm_quality = compute_cpm_quality(ev.items, final_verdict)
    wasted = is_wasted_impression(ev.items, final_verdict)

    return {
        "raw_score": raw, "score": final, "final_score": final, "verdict": final_verdict,
        "confidence": confidence, "evidence": ev.items, "categories": categories,
        "privacy_browser": privacy_name or None, "cpm_quality": cpm_quality,
        "wasted_impression": wasted, "data_quality": data_quality,
    }