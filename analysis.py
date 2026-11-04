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
  [33] Datacenter ASN map     → 40+ known DC/VPN ASNs (independent of ip-api)
  [34] CPM quality classifier → premium/standard/low/wasted/invalid
  [35] Wasted impression flag → valid traffic that won't see ads (Brave/AdBlock)
  [36] Headless viewport      → 800x600 / 0x0 detection
  [37] Screen sanity checks   → desktop < 1024px, mobile > 1920px
  [38] TZ map hardened        → exact match (no wildcard "asia/" or "america/")
  [39] CPU split             → cores=0 (headless) vs cores=1 (low-end device)
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
# BOT UA PATTERNS (Phase 3 + Phase 5)
# =========================================================
BOT_UA_PATTERNS = (
    # Generic tooling
    "curl", "wget", "httpie",
    "python", "python-requests", "requests/",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "undici",
    "httpclient", "libwww", "restsharp",
    "headless", "selenium", "phantom", "puppeteer", "playwright",
    "scrapy", "guzzle", "httpx",
    "postman", "insomnia", "apitester",
    "automated", "automation", "http_request",
    # Phase 5: SEO / AI crawlers (no "bot" word in name)
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot",
    "petalbot", "bytespider", "gptbot", "claudebot",
    "ccbot", "yandexbot", "slurp", "bingpreview",
    "facebookexternalhit", "linkedinbot", "twitterbot",
    "duckduckbot", "applebot",
)

BOT_WORD_RE = re.compile(r"\b(bot|spider|crawler)\b")


def _is_bot_ua(ua: str) -> bool:
    if not ua:
        return True
    if any(x in ua for x in BOT_UA_PATTERNS):
        return True
    if BOT_WORD_RE.search(ua):
        return True
    return False


# =========================================================
# PHASE 5 — DATACENTER / VPN ASNs
# =========================================================
# مصدر: قوائم عامة (Spur, IPinfo, MaxMind) + خبرة ميدانية
# الفكرة: لو الـ ASN موجود هنا، الزيارة جاية من DC مؤكد — حتى لو ip-api
# قال "residential" (بيحصل بسبب proxies).
DATACENTER_ASNS = frozenset([
    # Big cloud
    "AS14061", "AS16509", "AS14618", "AS396982", "AS15169",
    "AS8075", "AS31898", "AS45102", "AS7506", "AS37963",
    # Mid-tier hosting
    "AS24940",  # Hetzner
    "AS16276",  # OVH
    "AS20473",  # Vultr
    "AS20454",  # Choopa (Vultr parent)
    "AS63949",  # Linode
    "AS51167",  # Contabo
    "AS60781",  # LeaseWeb
    "AS16265",  # LeaseWeb NL
    "AS12876",  # Scaleway
    "AS197540", # netcup
    "AS197695", # Reg.ru
    "AS49505",  # Selectel
    "AS208046", # ColocationX
    "AS40676",  # Psychz Networks
    "AS53667",  # FranTech / BuyVM
    "AS59711",  # HZ Hosting
    "AS29802",  # Hivelocity
    "AS63023",  # GTHost
    "AS212238", # Datacamp
    "AS9312",   # XSERVER
    "AS35916",  # Multacom
    "AS21859",  # Zenlayer
    "AS36352",  # ColoCrossing (proxy-heavy)
    "AS209854", # Cyberzone
    # VPN-heavy
    "AS9009",   # M247
    "AS3223",   # Voxility
    "AS62838",  # VPNTunnel
    "AS200373", # Netherlands DC (NordVPN infra)
    "AS9002",   # RETN
    "AS394711", # Limelight (some VPNs)
    "AS3462",   # HiNet DC
    "AS6079",   # RCN (sometimes DC)
])


# =========================================================
# PHASE 5 — TIMEZONE MAP (exact match only)
# =========================================================
# قاعدة التصميم: no wildcards. كل TZ لازم تكون كاملة.
# "america/" كانت بتطابق البرازيل، "asia/" كانت بتطابق الصين.
TZ_BY_COUNTRY_CODE = {
    # Middle East / North Africa
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
    # Europe
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
    # North America
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
    # South America
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
    # Asia
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
    # Africa
    "NG": {"africa/lagos"},
    "KE": {"africa/nairobi"},
    "GH": {"africa/accra"},
    "ZA": {"africa/johannesburg", "africa/cape_town"},
    "ET": {"africa/addis_ababa"},
    # Oceania
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
    # Firefox RFP: single platform "Linux x86_64" regardless of OS + canvas blocked
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
        """إشارة سلبية (تزيد الخطورة)."""
        self._add(code, severity, abs(int(score)), detail)

    def human(self, code, score, detail):
        """إشارة إيجابية (تقلل الخطورة)."""
        self._add(code, "human", -abs(int(score)), detail)

    def has_critical(self) -> bool:
        return any(i["severity"] == "critical" for i in self.items)

    def raw_score(self) -> int:
        """مجموع كل النقاط (موجب + سالب)، غير محدود."""
        return sum(i["score"] for i in self.items)

    def final_score(self) -> int:
        """مجموع النقاط مقيّد [0, 150]."""
        return max(0, min(150, self.raw_score()))

    def counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
        for item in self.items:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        return counts


# =========================================================
# PHASE 4 — CONFIDENCE + CATEGORIES HELPERS
# =========================================================
def calc_confidence(signals: list) -> float:
    """
    يحسب confidence (0.0–1.0) بناءً على:
    - Critical → 0.95 دايمًا
    - تنوع severities + عدد الإشارات

    يقبل list of dicts فيها severity (يتجاهل human).
    """
    if not signals:
        return 0.0

    non_human = [s for s in signals if s.get("severity") != "human"]

    if any(s.get("severity") == "critical" for s in non_human):
        return 0.95

    if not non_human:
        return 0.0

    count = len(non_human)

    if count == 1:
        sev = non_human[0].get("severity", "medium")
        return {
            "critical": 0.95,
            "high": 0.70,
            "medium": 0.45,
            "low": 0.25,
        }.get(sev, 0.30)

    severities = set(s.get("severity", "medium") for s in non_human)
    diversity = len(severities)

    if diversity >= 3:
        return 0.85
    if diversity == 2 and count >= 3:
        return 0.75
    if diversity == 2:
        return 0.65
    if count >= 3:
        return 0.60
    return 0.50


def count_categories(signals: list) -> dict:
    """يعد الإشارات حسب الفئة."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
    for s in signals:
        sev = s.get("severity", "medium") if isinstance(s, dict) else "medium"
        if sev in counts:
            counts[sev] += 1
    return counts


def normalize_stored_evidence(evidence):
    """
    يوحّد شكل الـ evidence من DB (يدعم القديم strings والجديد dicts).
    يُرجع list of dicts.
    """
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
# المجموعات اللي بتحدد جودة الزيارة من منظور CPM arbitrage
_WASTED_CODES = frozenset(["CPM_BRAVE", "CPM_ADBLOCK_BROWSER"])
_PREMIUM_HUMAN_CODES = frozenset(["HUMAN_NATURAL_MOUSE", "HUMAN_RICH_INTERACTION"])
_PREMIUM_EXTRA_CODES = frozenset(["HUMAN_LONG_ENGAGEMENT"])


def compute_cpm_quality(evidence_items: list, verdict: str) -> str:
    """
    يصنف الزيارة من منظور CPM:
      - invalid  : بوت (لا قيمة)
      - wasted   : يوزر حقيقي بس مش هيشوف إعلانات (Brave/AdBlock) → impression ضايع
      - low      : suspicious (قيمة منخفضة/غير مؤكدة)
      - standard : valid عادي
      - premium  : valid + إشارات بشرية واضحة (أعلى CPM)

    لا يعتمد على الـ DB — يعتمد على evidence codes (persisted already).
    """
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

    # Premium = at least one strong human signal + one supporting
    if (codes & _PREMIUM_HUMAN_CODES) and (codes & _PREMIUM_EXTRA_CODES):
        return "premium"
    if len(codes & _PREMIUM_HUMAN_CODES) >= 2:
        return "premium"

    return "standard"


def is_wasted_impression(evidence_items: list, verdict: str) -> bool:
    """
    True لو الزيارة valid (مش بوت) لكن الـ user مش هيشوف إعلانات
    (Brave Shields, AdBlock built-in). الـ impression بيتحسب عند
    شركة الإعلانات بس مش بيتدفع = خسارة صافية في CPM arbitrage.
    """
    if verdict == "invalid":
        return False
    codes = {
        e.get("code") for e in evidence_items
        if isinstance(e, dict) and e.get("code")
    }
    return bool(codes & _WASTED_CODES)


# =========================================================
# ANALYZE VISIT — Phase 4 + Phase 5 Rule-Based Engine
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    """
    محرك الحكم بنظام Rule-based.

    Categories:
      - critical : invalid فورًا (webdriver, CDP, impossible combos)
      - high     : 40-100 pts (bot UA, DC ASN, headless viewport, WebRTC leak)
      - medium   : 20-60 pts (datacenter, missing canvas, TZ mismatch)
      - low      : 10-25 pts (UTC, canvas blocked, Brave, single lang)
      - human    : -15 to -30 pts (rich interaction, natural mouse)

    Verdict:
      - critical signal → invalid
      - final_score >= 80 → invalid
      - final_score >= 40 → suspicious
      - else → valid

    Phase 5 additions:
      - cpm_quality (premium/standard/low/wasted/invalid)
      - wasted_impression (bool)
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
    is_desktop_chrome = (
        "chrome" in ua
        and not is_mobile
        and not is_ios
        and "headless" not in ua
        and "edg/" not in ua
        and "opr/" not in ua
    )

    # ===== Privacy browser detection =====
    is_privacy_browser, privacy_name = _detect_privacy_browser(ua, platform, fp, nav)

    # =====================================================
    # === CRITICAL SIGNALS (auto-invalid) ===
    # =====================================================

    if nav.get("webdriver") is True:
        ev.risk("WEBDRIVER_FLAG", "critical", 80, "navigator.webdriver === true")

    if fp.get("cdp_detected") is True:
        ev.risk("CDP_DETECTED", "critical", 100, "CDP Runtime Detected")

    # Windows UA + Linux platform = headless default
    if "windows nt" in ua and platform and ("linux" in platform or "x11" in platform):
        ev.risk("WINDOWS_UA_LINUX", "critical", 100,
                f"Windows UA + Linux platform ({_safe_str(platform, 30)})")

    # Firefox UA + window.chrome = impossible
    chrome_check = fp.get("chrome_check", "")
    if "firefox" in ua and chrome_check == "full":
        ev.risk("FIREFOX_CHROME_OBJ", "critical", 80,
                "Firefox UA + window.chrome (impossible)")

    # =====================================================
    # === HIGH SIGNALS ===
    # =====================================================

    if _is_bot_ua(ua):
        ev.risk("BOT_UA", "high", 90, f"Suspicious UA: {_safe_str(ua[:60], 60)}")

    # Network: proxy / hosting via ip-api
    is_proxy = sec.get("proxy") is True
    is_hosting = (
        sec.get("hosting") is True
        or str(ip_info.get("type", "")).lower() == "hosting"
    )

    if is_proxy and is_hosting:
        ev.risk("VPN_DATACENTER", "high", 70, "VPN + Datacenter IP")
    elif is_hosting:
        ev.risk("DATACENTER_IP", "medium", 50, "Datacenter/Hosting IP")
    elif is_proxy:
        ev.risk("VPN_PROXY", "medium", 40, "VPN/Proxy IP")

    # Phase 5: ASN-based DC detection (independent of ip-api verdict)
    asn_value = safe_asn(ip_info.get("asn", ""))
    if asn_value and not asn_value.upper().startswith("AS"):
        asn_value = "AS" + asn_value
    if asn_value and asn_value.upper() in DATACENTER_ASNS and not is_hosting:
        # مفيش double-penalty: لو is_hosting اتضبط فوق، مش هنضيف تاني
        ev.risk("DATACENTER_ASN", "high", 70,
                f"Datacenter ASN: {asn_value}")

    # WebRTC
    webrtc_penalty, webrtc_evidence = _check_webrtc(
        data.get("webrtc_ip"),
        data.get("client_ip"),
        ip_info,
    )
    if webrtc_penalty >= 90:
        ev.risk("WEBRTC_LEAK", "high", webrtc_penalty, webrtc_evidence)
    elif webrtc_penalty > 0:
        ev.risk("WEBRTC_VPN_DIFF", "medium", webrtc_penalty, webrtc_evidence)

    # Plugins
    plugin_count = safe_int(plugins_info.get("count"), -1, max_val=1000)
    if is_desktop_chrome and not is_privacy_browser and plugin_count == 0:
        ev.risk("PLUGINS_ZERO", "high", 60, "Chrome desktop: 0 plugins")

    # window.chrome
    if is_desktop_chrome and not is_privacy_browser:
        if chrome_check == "no_window_chrome":
            ev.risk("CHROME_NO_OBJ", "high", 50, "Chrome UA: no window.chrome")

    # Fingerprint rate
    recent_fp = safe_int(data.get("_recent_fp_count"), 0)
    if recent_fp >= 50:
        ev.risk("FINGERPRINT_REUSE_HIGH", "high", 80,
                f"Fingerprint reuse ({recent_fp}/min)")
    elif recent_fp >= 30:
        ev.risk("FINGERPRINT_REUSE_HIGH", "high", 60,
                f"Fingerprint reuse ({recent_fp}/min)")
    elif recent_fp >= 20:
        ev.risk("FINGERPRINT_REUSE_MED", "medium", 40,
                f"Fingerprint reuse ({recent_fp}/min)")
    elif recent_fp > 10:
        ev.risk("FINGERPRINT_REUSE_LOW", "low", 25,
                f"Fingerprint reuse ({recent_fp}/min)")

    # Phase 5: Headless viewport — 800x600 (default headless Chrome)
    avail_w = safe_int(screen_dict.get("availWidth"), 0)
    avail_h = safe_int(screen_dict.get("availHeight"), 0)
    if avail_w == 800 and avail_h == 600:
        ev.risk("HEADLESS_VIEWPORT", "high", 70,
                "Default 800x600 headless viewport")

    # =====================================================
    # === MEDIUM SIGNALS ===
    # =====================================================

    # Canvas
    canvas = fp.get("canvas_hash")
    if canvas == "blocked":
        ev.risk("CANVAS_BLOCKED", "low", 10, "Canvas blocked (privacy browser)")
    elif not canvas or len(str(canvas)) < 5:
        ev.risk("CANVAS_MISSING", "medium", 60, "Canvas hash missing or invalid")

    # Phase 5: Viewport = 0x0 → headless
    if avail_w == 0 or avail_h == 0:
        ev.risk("VIEWPORT_ZERO", "medium", 50, "Viewport is 0x0 (headless)")

    # CPU (Phase 5 refinement)
    cores = safe_int(fp.get("hardwareConcurrency"), -1, max_val=256)
    if cores == 0:
        # Chrome on real hardware can't have 0 — Firefox RFP is the exception
        if not is_privacy_browser and "firefox" not in ua:
            ev.risk("CORES_ZERO", "medium", 40, "hardwareConcurrency=0 (impossible)")
    elif cores == 1:
        ev.risk("CORES_LOW", "low", 15, "Single-core device (low-end or emulator)")

    # Languages
    langs_raw = fp.get("languages")
    if isinstance(langs_raw, list):
        if len(langs_raw) == 0:
            ev.risk("LANGUAGES_EMPTY", "medium", 40, "Empty navigator.languages")
        elif (
            len(langs_raw) == 1
            and langs_raw[0] == "en-US"
            and is_desktop_chrome
            and not is_privacy_browser
        ):
            ev.risk("SINGLE_LANG", "low", 15, "Only single en-US language")

    # OS mismatch (soft)
    if platform:
        if "windows nt" in ua and "win" not in platform and "linux" not in platform and "x11" not in platform:
            ev.risk("OS_MISMATCH_WIN", "medium", 50, f"Windows UA + platform {_safe_str(platform, 30)}")
        if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
            ev.risk("OS_MISMATCH_MAC", "medium", 50, f"macOS UA + platform {_safe_str(platform, 30)}")

    # Timezone
    tz = str(fp.get("timezone") or "").lower()
    country_code = str(ip_info.get("country_code") or "").upper()

    if not tz or tz in ("utc", "etc/utc", "unknown"):
        if not is_privacy_browser:
            ev.risk("UTC_TZ", "low", 20, "UTC/Unknown timezone")
    elif country_code in TZ_BY_COUNTRY_CODE:
        expected_tzs = TZ_BY_COUNTRY_CODE[country_code]
        if tz not in expected_tzs:
            ev.risk("TZ_MISMATCH", "medium", 60,
                    f"IP country {country_code} vs TZ {_safe_str(tz, 40)}")

    # Mobile + wide screen
    screen_w = safe_int(screen_dict.get("width"), 0)
    if is_mobile and screen_w > 1920:
        ev.risk("MOBILE_WIDE_SCREEN", "medium", 50,
                f"Mobile UA + {screen_w}px wide screen")

    # Phase 5: Desktop + tiny screen (headless default / VNC)
    if is_desktop_chrome and not is_mobile and 0 < screen_w < 1024:
        ev.risk("SCREEN_TINY", "medium", 30,
                f"Desktop Chrome + {screen_w}px screen (headless/VNC)")

    # =====================================================
    # === PHASE 5 — CPM SIGNALS ===
    # =====================================================

    # Brave = built-in Shields block ads by default
    if privacy_name in ("Brave", "Brave(heuristic)") or nav.get("is_brave") is True:
        ev.risk("CPM_BRAVE", "low", 15,
                f"{privacy_name or 'Brave'} user (built-in ad block)")

    # AdBlock-heavy browsers (UA fingerprint)
    _adblock_uas = ("firefox focus", "duckduckgo", "opera mini", "brave")
    for _abu in _adblock_uas:
        if _abu in ua and _abu != "brave":  # Brave handled above
            ev.risk("CPM_ADBLOCK_BROWSER", "low", 10,
                    f"AdBlock-heavy browser: {_safe_str(_abu, 30)}")
            break

    # =====================================================
    # === BEHAVIOR ===
    # =====================================================
    mousemove = safe_int(events.get("mousemove"), 0)
    touchstart = safe_int(events.get("touchstart"), 0)
    scrolls = safe_int(events.get("scrolls"), 0)
    clicks = safe_int(events.get("clicks"), 0)
    t_on_page = safe_int(behavior.get("time_on_page_ms"), 0)

    # Left too fast
    if t_on_page < 1800:
        ev.risk("LEFT_FAST", "medium", 40, f"Left after {t_on_page}ms")

    # Mouse trajectory (Phase 3 + Phase 4 scoring)
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
            ev.risk("ROBOTIC_LINEAR", "high", 60,
                    f"Linear motion ({dc} turns, var={dv:.4f})")
        elif tp > 20 and mc < 0.001 and dc < 3:
            ev.risk("ROBOTIC_CURVATURE", "medium", 40,
                    f"Zero curvature (mc={mc:.4f})")
    else:
        mv = safe_float(behavior.get("mouse_variance"), 0.0)
        if mousemove > 10 and mv < 1.5:
            ev.risk("ROBOTIC_VARIANCE", "medium", 50, f"Low mouse variance ({mv:.2f})")

    # Zombie
    has_any_interaction = (
        mousemove > 5 or touchstart > 0 or scrolls > 0 or clicks > 0
    )
    if t_on_page > 8000 and not has_any_interaction:
        ev.risk("ZOMBIE", "low", 30, f"No interaction after {t_on_page}ms")

    # =====================================================
    # === WEBGL ===
    # =====================================================
    renderer = str(webgl.get("renderer") or "").lower()
    vendor = str(webgl.get("vendor") or "").lower()

    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        known_vendors = ("intel", "nvidia", "amd", "microsoft", "google", "apple")
        if any(v in vendor for v in known_vendors):
            ev.risk("SOFT_RENDERER", "low", 20,
                    f"Software renderer ({_safe_str(vendor, 30)})")
        else:
            ev.risk("SOFT_RENDERER", "medium", 60, "Virtual renderer (no vendor)")

    # =====================================================
    # === HUMAN SIGNALS (negative) ===
    # =====================================================
    rich_interaction = (
        mousemove > 50 and scrolls > 5 and clicks > 2 and t_on_page > 15000
    )
    if rich_interaction:
        ev.human("HUMAN_RICH_INTERACTION", 30,
                 f"Rich interaction ({mousemove}mm, {scrolls}sc, {clicks}cl, {t_on_page}ms)")

    if has_mouse_analysis:
        if (
            safe_float(mouse_analysis.get("velocity_variance"), 0) > 0.1
            and safe_int(mouse_analysis.get("direction_changes"), 0) > 5
            and safe_float(mouse_analysis.get("mean_curvature"), 0) > 0.01
        ):
            ev.human("HUMAN_NATURAL_MOUSE", 20, "Natural mouse trajectory")

    if t_on_page > 30000 and (mousemove > 10 or touchstart > 0 or scrolls > 0):
        ev.human("HUMAN_LONG_ENGAGEMENT", 15, f"Long engagement ({t_on_page}ms)")

    # =====================================================
    # === VERDICT ===
    # =====================================================
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

    # Phase 5 — CPM quality classification
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
        # Phase 5 additions
        "cpm_quality": cpm_quality,
        "wasted_impression": wasted,
    }