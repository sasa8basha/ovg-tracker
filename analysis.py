"""
analysis.py — OVG Tracker

Phase 1 — Hardening applied:
  [1]  events non-dict        → _safe_dict() defensive extraction
  [2]  webgl non-dict         → _safe_dict() defensive extraction
  [3]  XSS via webrtc_ip      → _safe_str() sanitization + frontend escape
  [4]  XSS via tz             → _safe_str() sanitization + frontend escape
  [5]  Evidence unbounded     → truncation to 200 chars per string
  [6]  Country cmap broken    → country_code-based TZ_MAP (30+ countries)
  [7]  VPN + hosting double   → max(), not sum() — prevents auto-invalid
  [8]  Canvas "blocked"       → +10 (privacy browser) not +60
  [9]  Platform empty         → silent skip (privacy browser)
  [10] WebRTC multi-IP        → parse each IP individually (comma-split)
"""
import re
import secrets
import httpx
import ipaddress
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip


# =========================================================
# PHASE 1 — SAFE HELPERS
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
    """نفس safe_int لكن بترجع float، مع NaN/Inf protection."""
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
    """
    Phase 1 — Fix #1, #2: يضمن إن القيمة dict، وإلا يرجّع {}.
    يمنع AttributeError على .get() لو الـ payload فيه list/str/int.
    """
    return val if isinstance(val, dict) else {}


def _safe_str(val, max_len=200):
    """
    Phase 1 — Fix #3, #4, #5: string sanitization.
    - يحوّل أي قيمة لـ string
    - يشيل control chars (يمنع logs injection)
    - يشيل < و > (XSS defense in depth)
    - يحدد الطول (DoS protection)
    """
    if val is None:
        return ""
    s = str(val)
    # إزالة control chars (نخلي \t \n \r)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    # إزالة < > (XSS tag injection)
    s = s.replace("<", "").replace(">", "")
    if len(s) > max_len:
        s = s[:max_len] + "..."
    return s


# =========================================================
# TIMEZONE MAP (Phase 1 — Fix #6)
# =========================================================
# نستخدم country_code (ISO 2-letter) بدل country name لأن ip-api
# بيرجع "United States" مش "US" — الكود القديم كان بيشتغل على مصر وإيطاليا بس.
#
# ملاحظة: بعض البادئات عامة (america/ للولايات المتحدة) لتقليل false positives.
# التحسين الدقيق يحتاج IP-to-TZ database — Phase 5.
TZ_BY_COUNTRY_CODE = {
    # الشرق الأوسط
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
    # أفريقيا
    "MA": {"africa/casablanca"},
    "DZ": {"africa/algiers"},
    "TN": {"africa/tunis"},
    "LY": {"africa/tripoli"},
    "SD": {"africa/khartoum"},
    # أوروبا
    "GB": {"europe/london"},
    "IT": {"europe/rome"},
    "DE": {"europe/berlin"},
    "FR": {"europe/paris"},
    "ES": {"europe/madrid"},
    "NL": {"europe/amsterdam"},
    "RU": {"europe/moscow", "asia/"},
    # أمريكا
    "US": {"america/"},  # كل US timezones
    "CA": {"america/toronto", "america/vancouver", "america/edmonton",
           "america/winnipeg", "america/halifax", "america/st_johns"},
    "BR": {"america/sao_paulo"},
    # آسيا
    "IN": {"asia/kolkata", "asia/calcutta"},
    "JP": {"asia/tokyo"},
    "CN": {"asia/shanghai", "asia/beijing"},
    "AU": {"australia/"},
}


# =========================================================
# IP GEO (Phase 1 — Fix #6: country_code + detailed security)
# =========================================================
async def get_ip_info(ip: str):
    """
    Returns ip_info dict with:
    - country, country_code (ISO 2-letter)
    - isp, asn
    - type (hosting/residential)
    - security: {vpn, proxy, hosting} — detached for accurate scoring
    - lat, lon
    """
    if not ip or _is_private_ip(ip):
        return {
            "country": "Local",
            "country_code": "LO",
            "isp": "Local ISP",
            "type": "residential",
            "asn": "N/A",
            "security": {},
            "lat": 0.0,
            "lon": 0.0,
        }
    cached = ip_cache.get(ip)
    if cached is not None:
        # Phase 1 fix: keep backward compat with old cached entries
        # (old cache has "vpn" only, no "proxy"/"hosting"/"country_code")
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
        "country": "Unknown",
        "country_code": "",
        "isp": "Unknown",
        "type": "Unknown",
        "asn": "Unknown",
        "security": {},
        "lat": 0.0,
        "lon": 0.0,
    }


# =========================================================
# UA PARSER (unchanged in Phase 1)
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
# WebRTC CHECK (Phase 1 — Fix #10: parse each IP)
# =========================================================
def _check_webrtc(webrtc_str, client_ip, ip_info):
    """
    يحلل WebRTC IPs (comma-separated).
    Returns (penalty, evidence_text).

    - يمر على كل IP منفصل
    - يتجاهل private / loopback / link-local / invalid
    - يتجاهل IP اللي = client_ip
    - يقلل العقوبة لو العميل على VPN (احتمال مش leak)
    """
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
            continue  # مش IP، تجاهل
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            continue
        if part == client_ip:
            continue
        valid_leaks.append(part)

    if not valid_leaks:
        return 0, ""

    # لو الـ IP بتاع VPN، ممكن يكون WebRTC IP الـ VPN مش leak حقيقي
    if ip_info.get("security", {}).get("vpn"):
        return 20, f"WebRTC Differs (likely VPN): {_safe_str(valid_leaks[0], 60)}"

    return 90, f"WebRTC Leak: {_safe_str(valid_leaks[0], 60)}"


# =========================================================
# ANALYZE VISIT (Phase 1 — كل الإصلاحات)
# =========================================================
def analyze_visit(data: dict, ip_info: dict) -> dict:
    score = 0
    evidence = []

    # ===== Phase 1 Fix #1, #2: defensive dict extraction =====
    nav = _safe_dict(data.get("nav"))
    fp = _safe_dict(data.get("fingerprint"))
    behavior = _safe_dict(data.get("behavior"))
    events = _safe_dict(behavior.get("events"))
    webgl = _safe_dict(fp.get("webgl"))
    sec = _safe_dict(ip_info.get("security"))

    ua = str(nav.get("ua") or "").lower()
    platform = str(nav.get("platform") or "").lower()

    # ===== Automation =====
    if nav.get("webdriver") is True:
        score += 80
        evidence.append("WebDriver Flag")

    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget")):
        score += 90
        evidence.append("Suspicious User-Agent")

    # ===== OS/Platform Mismatch (Phase 1 Fix #9: empty platform = skip) =====
    if not platform:
        # Phase 1 Fix #9: platform فاضي = privacy browser (Brave / Firefox RFP)
        # مفيش عقوبة — silent skip. لو حطينا evidence هنا هيتلخبط مع العلامات الحقيقية.
        pass
    else:
        if "windows nt" in ua and "win" not in platform:
            score += 50
            evidence.append("OS Mismatch (Win)")
        if ("mac os" in ua or "macintosh" in ua) and "mac" not in platform:
            score += 50
            evidence.append("OS Mismatch (Mac)")

    # ===== Network (Phase 1 Fix #7: VPN + hosting = max not sum) =====
    is_proxy = sec.get("proxy") is True
    is_hosting = (
        sec.get("hosting") is True
        or str(ip_info.get("type", "")).lower() == "hosting"
    )
    # Backward compat: old cache entries have only {"vpn": bool}
    # (no "proxy"/"hosting"), and type="hosting" if vpn.
    # The `is_hosting` check above catches those via type fallback.

    if is_proxy and is_hosting:
        # VPN على datacenter = suspicious بس مش auto-invalid
        score += 70
        evidence.append("VPN + Datacenter")
    elif is_hosting:
        score += 50
        evidence.append("Datacenter/Hosting IP")
    elif is_proxy:
        score += 40
        evidence.append("VPN/Proxy Detected")
    # else: no penalty (residential IP)

    # ===== WebRTC (Phase 1 Fix #10: parse each IP) =====
    webrtc_penalty, webrtc_evidence = _check_webrtc(
        data.get("webrtc_ip"),
        data.get("client_ip"),
        ip_info,
    )
    if webrtc_penalty:
        score += webrtc_penalty
        if webrtc_evidence:
            evidence.append(webrtc_evidence)

    # ===== Canvas (Phase 1 Fix #8: blocked = +10 not +60) =====
    canvas = fp.get("canvas_hash")
    if canvas == "blocked":
        # Phase 1 Fix #8: privacy browser (Brave / Firefox RFP) = عقوبة خفيفة
        score += 10
        evidence.append("Canvas Blocked (privacy)")
    elif not canvas or len(str(canvas)) < 5:
        score += 60
        evidence.append("Missing Canvas FP")

    # ===== Hardware =====
    cores = safe_int(fp.get("hardwareConcurrency"), 0, max_val=256)
    if cores <= 1:
        score += 40
        evidence.append(f"Low CPU ({cores})")

    # ===== Timezone (Phase 1 Fix #6: country_code + expanded TZ_MAP) =====
    tz = str(fp.get("timezone") or "").lower()
    country_code = str(ip_info.get("country_code") or "").upper()

    if not tz or tz in ("utc", "etc/utc", "unknown"):
        score += 30
        evidence.append("UTC/Unknown Timezone")
    elif country_code in TZ_BY_COUNTRY_CODE:
        expected_tzs = TZ_BY_COUNTRY_CODE[country_code]
        if not any(t in tz for t in expected_tzs):
            score += 60
            evidence.append(
                f"TZ Mismatch (IP:{country_code} vs TZ:{_safe_str(tz, 40)})"
            )

    # ===== Behavior (Phase 1 Fix #1: events آمن) =====
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

    # ===== WebGL (Phase 1 Fix #2: webgl آمن) =====
    renderer = str(webgl.get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")):
        score += 60
        evidence.append("Virtual Renderer")

    # ===== Finalize (Phase 1 Fix #5: evidence truncation) =====
    # Defense in depth: نمر على كل evidence strings ونأمّنها.
    # الـ strings الاستاتيكية مش هتتأثر، والـ interpolated هتتأمن لو فات منها حاجة.
    evidence = [_safe_str(e, 200) for e in evidence]

    score = min(150, score)
    verdict = "invalid" if score >= 80 else "suspicious" if score >= 40 else "valid"
    return {"score": score, "verdict": verdict, "evidence": evidence}
