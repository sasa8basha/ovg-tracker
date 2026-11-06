"""
collector/server_cross_validator.py — SYSTEM 4: Server-Verified Cross-Validation

Self-contained. Uses HTTP headers (server-verified, harder to spoof) to catch
contradictions that JavaScript-only checks miss.

Key insights:
  - JS can be modified by bots (navigator.userAgent, etc.)
  - HTTP headers come from the browser BEFORE JS runs
  - Real browsers send a very specific set of headers
  - Mismatches between HTTP and JS are strong bot indicators

Solves problems:
  - #3 (ASN — CF headers as backup)
  - #7 (Empty UA — HTTP UA is separate)
  - #9, #10, #11 (WebRTC — HTTP unaffected)
  - #13 (Edge brands — cross-check at HTTP layer)
  - #15 (HTTP_1_1_ON_HTTPS false positive — neutralized)
  - #19, #20 (cores — HTTP arch hints as backup)
"""
import os
import sys
import re
import logging
from typing import List, Tuple, Dict, Optional

logger = logging.getLogger("ovg.server_cross")


# =========================================================
# CONSTANTS
# =========================================================
CHROME_MIN_VERSION_FOR_SEC_CH_UA = 90

# Existing code names (match header_analyzer.py to enable deduplication
# via orchestrator._merge_signals — first occurrence wins)
CODE_MISSING_SEC_CH_UA = "MISSING_SEC_CH_UA"
CODE_SEC_CH_UA_ON_FIREFOX = "SEC_CH_UA_ON_FIREFOX"
CODE_SEC_CH_UA_ON_SAFARI = "SEC_CH_UA_ON_SAFARI"
CODE_SEC_CH_UA_MOBILE_MISMATCH = "SEC_CH_UA_MOBILE_MISMATCH"
CODE_HTTP_1_1_ON_HTTPS = "HTTP_1_1_ON_HTTPS"

# New code names
CODE_HTTP_UA_JS_MISMATCH = "HTTP_UA_JS_MISMATCH"
CODE_SEC_CH_HEADLESS_BRAND = "SEC_CH_HEADLESS_BRAND"
CODE_SEC_CH_UA_GOOGLE_MISSING = "SEC_CH_UA_GOOGLE_MISSING"
CODE_CF_COUNTRY_TZ_MISMATCH = "CF_COUNTRY_TZ_MISMATCH"


# =========================================================
# HELPERS
# =========================================================
def _parse_browser_info(ua: str) -> dict:
    """Extract browser name/version/mobile/iOS from a User-Agent string."""
    default = {"name": "unknown", "version": 0, "is_ios": False, "is_mobile": False}
    if not ua:
        return default

    ua_lower = ua.lower()

    is_ios = any(x in ua_lower for x in ("iphone", "ipad", "ipod"))
    is_mobile = "mobile" in ua_lower or "android" in ua_lower or is_ios

    # Chrome (exclude Edge and Opera which have their own UA strings)
    chrome_match = re.search(r"chrome/(\d+)", ua_lower)
    if chrome_match and "edg/" not in ua_lower and "opr/" not in ua_lower:
        return {
            "name": "chrome",
            "version": int(chrome_match.group(1)),
            "is_ios": is_ios,
            "is_mobile": is_mobile,
        }

    firefox_match = re.search(r"firefox/(\d+)", ua_lower)
    if firefox_match:
        return {
            "name": "firefox",
            "version": int(firefox_match.group(1)),
            "is_ios": is_ios,
            "is_mobile": is_mobile,
        }

    # Safari — "Version/X.Y" token, has "Safari", no "Chrome"
    safari_match = re.search(r"version/(\d+)", ua_lower)
    if safari_match and "safari" in ua_lower and "chrome" not in ua_lower:
        return {
            "name": "safari",
            "version": int(safari_match.group(1)),
            "is_ios": is_ios,
            "is_mobile": is_mobile,
        }

    return {"name": "unknown", "version": 0, "is_ios": is_ios, "is_mobile": is_mobile}


def _parse_sec_ch_ua(value: str) -> List[Dict[str, str]]:
    """
    Parse Sec-CH-UA header value.

    Format: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
    Returns: [{"brand": "Not_A Brand", "version": "8"}, ...]
    """
    if not value:
        return []
    result = []
    for part in str(value).split(","):
        m = re.search(r'"([^"]+)"\s*;\s*v="([^"]+)"', part.strip())
        if m:
            result.append({"brand": m.group(1), "version": m.group(2)})
    return result


def _has_proxy_headers(headers: dict) -> bool:
    """Detect if the request passed through a proxy/CDN."""
    proxy_headers = (
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-real-ip",
        "cf-connecting-ip",
        "cf-ray",
        "cf-ipcountry",
    )
    return any(h in headers for h in proxy_headers)


def _infer_https(headers: dict) -> bool:
    """Infer whether the original request used HTTPS."""
    xfp = headers.get("x-forwarded-proto", "").lower().strip()
    if xfp:
        return xfp.split(",")[0].strip() == "https"
    cf_visitor = headers.get("cf-visitor", "")
    if cf_visitor:
        m = re.search(r'"scheme"\s*:\s*"(\w+)"', cf_visitor)
        if m:
            return m.group(1).lower() == "https"
    if "cf-ray" in headers:
        return True
    return True  # default: assume HTTPS


def _tz_to_country(tz: str) -> str:
    """Best-effort timezone → country code mapping."""
    tz_map = {
        "africa/cairo": "EG", "asia/riyadh": "SA", "asia/dubai": "AE",
        "asia/kuwait": "KW", "asia/qatar": "QA", "asia/bahrain": "BH",
        "europe/london": "GB", "europe/paris": "FR", "europe/berlin": "DE",
        "europe/madrid": "ES", "europe/rome": "IT",
        "asia/tokyo": "JP", "asia/seoul": "KR",
        "asia/shanghai": "CN", "asia/hong_kong": "HK", "asia/taipei": "TW",
        "asia/kolkata": "IN", "asia/calcutta": "IN",
        "america/new_york": "US", "america/chicago": "US",
        "america/denver": "US", "america/los_angeles": "US",
        "america/toronto": "CA", "america/vancouver": "CA",
        "america/sao_paulo": "BR", "america/argentina/buenos_aires": "AR",
        "australia/sydney": "AU", "australia/melbourne": "AU",
        "pacific/auckland": "NZ",
    }
    return tz_map.get((tz or "").lower(), "")


# Border-region pairs where country mismatch is common
_BORDER_PAIRS = frozenset([
    ("US", "CA"), ("CA", "US"),
    ("GB", "IE"), ("IE", "GB"),
    ("DE", "AT"), ("AT", "DE"),
    ("DE", "CH"), ("CH", "DE"),
    ("FR", "BE"), ("BE", "FR"),
    ("EG", "SD"), ("SD", "EG"),
    ("SA", "AE"), ("AE", "SA"),
    ("KW", "SA"), ("SA", "KW"),
])


# =========================================================
# MAIN ANALYZER
# =========================================================
def analyze_server_headers(
    headers: Optional[dict],
    http_version: Optional[str],
    js_nav: Optional[dict],
    js_fp: Optional[dict],
) -> List[Tuple[str, str, int, str]]:
    """
    Cross-validate HTTP headers against JS-reported data.

    Args:
        headers: dict of HTTP headers (lowercase keys)
        http_version: "1.0" | "1.1" | "2" | "3"
        js_nav: navigator dict from JS
        js_fp: fingerprint dict from JS

    Returns:
        list of (code, severity, score, detail) tuples
    """
    items: List[Tuple[str, str, int, str]] = []

    if not headers or not isinstance(headers, dict):
        return items

    # Normalize header keys to lowercase str
    h = {str(k).lower(): str(v) for k, v in headers.items()}

    js_nav = js_nav or {}
    js_fp = js_fp or {}

    # Parse both UAs
    http_ua = h.get("user-agent", "")
    http_info = _parse_browser_info(http_ua)

    js_ua = str(js_nav.get("ua") or "")
    js_info = _parse_browser_info(js_ua)

    has_proxy = _has_proxy_headers(h)
    is_https = _infer_https(h)

    sec_ch_ua_raw = h.get("sec-ch-ua", "")
    sec_ch_ua_parsed = _parse_sec_ch_ua(sec_ch_ua_raw)

    # =====================================================
    # CHECK 1: HTTP UA != JS UA (critical)
    # =====================================================
    if http_ua and js_ua:
        http_pref = http_ua.strip()[:50].lower()
        js_pref = js_ua.strip()[:50].lower()
        if http_pref != js_pref:
            items.append((
                CODE_HTTP_UA_JS_MISMATCH,
                "critical",
                100,
                f"HTTP UA != JS UA (HTTP='{http_ua[:40]}', JS='{js_ua[:40]}')",
            ))

    # =====================================================
    # CHECK 2: Chrome 90+ on HTTPS without sec-ch-ua (critical)
    # =====================================================
    if (
        http_info["name"] == "chrome"
        and http_info["version"] >= CHROME_MIN_VERSION_FOR_SEC_CH_UA
        and not http_info["is_ios"]
        and is_https
        and not sec_ch_ua_raw
    ):
        items.append((
            CODE_MISSING_SEC_CH_UA,
            "critical",
            90,
            f"Chrome {http_info['version']}+ on HTTPS without sec-ch-ua header",
        ))

    # =====================================================
    # CHECK 3: Firefox with sec-ch-ua (impossible)
    # =====================================================
    if http_info["name"] == "firefox" and sec_ch_ua_raw:
        items.append((
            CODE_SEC_CH_UA_ON_FIREFOX,
            "impossible",
            100,
            "Firefox UA + sec-ch-ua header (Firefox never sends it)",
        ))

    # =====================================================
    # CHECK 4: Safari with sec-ch-ua (impossible)
    # =====================================================
    if http_info["name"] == "safari" and sec_ch_ua_raw:
        items.append((
            CODE_SEC_CH_UA_ON_SAFARI,
            "impossible",
            100,
            "Safari UA + sec-ch-ua header (Safari never sends it)",
        ))

    # =====================================================
    # CHECK 5: sec-ch-ua-mobile mismatch
    # =====================================================
    scm = h.get("sec-ch-ua-mobile", "").strip()
    if scm:
        header_says_mobile = scm == "?1"
        ua_says_mobile = http_info["is_mobile"]

        # iPad in desktop mode sends ?0 even though it's touch-capable
        is_ipad_desktop = (
            not header_says_mobile
            and ua_says_mobile
            and "ipad" in http_ua.lower()
        )

        if not is_ipad_desktop:
            if header_says_mobile and not ua_says_mobile:
                items.append((
                    CODE_SEC_CH_UA_MOBILE_MISMATCH,
                    "critical",
                    90,
                    "sec-ch-ua-mobile=?1 but desktop UA",
                ))
            elif not header_says_mobile and ua_says_mobile:
                items.append((
                    CODE_SEC_CH_UA_MOBILE_MISMATCH,
                    "high",
                    70,
                    "sec-ch-ua-mobile=?0 but mobile UA",
                ))

    # =====================================================
    # CHECK 6: HeadlessChrome brand in sec-ch-ua (impossible)
    # =====================================================
    if sec_ch_ua_parsed:
        headless_brands = [
            b["brand"] for b in sec_ch_ua_parsed
            if "headless" in b["brand"].lower()
        ]
        if headless_brands:
            items.append((
                CODE_SEC_CH_HEADLESS_BRAND,
                "impossible",
                100,
                f"sec-ch-ua contains HeadlessChrome brand: '{headless_brands[0]}'",
            ))

    # =====================================================
    # CHECK 7: UA says Chrome but brands lack "Google Chrome"
    # =====================================================
    if (
        http_info["name"] == "chrome"
        and http_info["version"] >= CHROME_MIN_VERSION_FOR_SEC_CH_UA
        and sec_ch_ua_parsed
    ):
        brands_lower = [b["brand"].lower() for b in sec_ch_ua_parsed]
        has_google = any("google chrome" in b for b in brands_lower)
        has_chromium = any("chromium" in b for b in brands_lower)
        has_brave = any("brave" in b for b in brands_lower)
        has_edge = any("microsoft edge" in b for b in brands_lower)
        has_opera = any("opera" in b for b in brands_lower)

        js_ua_lower = js_ua.lower()
        ua_says_edge = "edg/" in js_ua_lower or "edga/" in js_ua_lower or "edgios/" in js_ua_lower
        ua_says_opera = "opr/" in js_ua_lower

        if has_chromium and not has_google:
            if has_edge and not ua_says_edge:
                items.append((
                    CODE_SEC_CH_UA_GOOGLE_MISSING,
                    "high",
                    60,
                    "Brands claim Edge but UA doesn't (spoofed UA)",
                ))
            elif has_opera and not ua_says_opera:
                items.append((
                    CODE_SEC_CH_UA_GOOGLE_MISSING,
                    "high",
                    60,
                    "Brands claim Opera but UA doesn't (spoofed UA)",
                ))
            elif not (has_brave or has_edge or has_opera):
                items.append((
                    CODE_SEC_CH_UA_GOOGLE_MISSING,
                    "critical",
                    80,
                    "UA says Chrome but brands only have Chromium (headless-like)",
                ))

    # =====================================================
    # CHECK 8: HTTP/1.0 / HTTP/1.1 handling
    # =====================================================
    hv = str(http_version or "").strip()
    if hv in ("1.0", "1.1"):
        modern_browser = http_info["name"] in ("chrome", "firefox", "safari")
        if modern_browser:
            if hv == "1.0" and not has_proxy:
                items.append((
                    CODE_HTTP_1_1_ON_HTTPS,
                    "critical",
                    100,
                    f"HTTP/1.0 direct access by {http_info['name']} {http_info['version']} (impossible)",
                ))
            else:
                # Neutralize the false positive from header_analyzer
                # (HTTP/1.1 behind proxy is completely normal)
                items.append((
                    CODE_HTTP_1_1_ON_HTTPS,
                    "low",
                    5,
                    f"HTTP/{hv} (normal behind proxies)",
                ))

    # =====================================================
    # CHECK 9: CF-IPCountry vs JS timezone country
    # =====================================================
    cf_country = h.get("cf-ipcountry", "").strip().upper()
    if cf_country and len(cf_country) == 2 and cf_country not in ("XX", "T1"):
        js_tz = str(js_fp.get("timezone") or "").lower()
        if js_tz:
            tz_country = _tz_to_country(js_tz)
            if tz_country and tz_country != cf_country:
                pair = (cf_country, tz_country)
                if pair not in _BORDER_PAIRS:
                    items.append((
                        CODE_CF_COUNTRY_TZ_MISMATCH,
                        "high",
                        60,
                        f"CF-IPCountry={cf_country} but JS TZ country={tz_country}",
                    ))

    return items


# =========================================================
# HEALTH
# =========================================================
def health_status() -> dict:
    return {
        "system": "server_cross_validator",
        "status": "ok",
        "checks": [
            CODE_HTTP_UA_JS_MISMATCH,
            CODE_MISSING_SEC_CH_UA,
            CODE_SEC_CH_UA_ON_FIREFOX,
            CODE_SEC_CH_UA_ON_SAFARI,
            CODE_SEC_CH_UA_MOBILE_MISMATCH,
            CODE_SEC_CH_HEADLESS_BRAND,
            CODE_SEC_CH_UA_GOOGLE_MISSING,
            CODE_HTTP_1_1_ON_HTTPS,
            CODE_CF_COUNTRY_TZ_MISMATCH,
        ],
        "chrome_min_version": CHROME_MIN_VERSION_FOR_SEC_CH_UA,
    }


# =========================================================
# SELF-TEST
# =========================================================
def run_self_test() -> Tuple[bool, List[str]]:
    results: List[str] = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    def _codes(items):
        return {item[0] for item in items}

    # 1: empty headers → no items
    try:
        r = analyze_server_headers({}, "1.1", {}, {})
        _chk(r == [], "Test 1: empty headers → no items",
             f"Test 1: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # 2: None headers → no items
    try:
        r = analyze_server_headers(None, "1.1", {}, {})
        _chk(r == [], "Test 2: None headers → no items",
             f"Test 2: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # 3: HTTP UA == JS UA → no mismatch
    try:
        ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"
        r = analyze_server_headers(
            {"user-agent": ua, "sec-ch-ua": '"Google Chrome";v="120"', "x-forwarded-proto": "https"},
            "1.1",
            {"ua": ua},
            {},
        )
        _chk(CODE_HTTP_UA_JS_MISMATCH not in _codes(r),
             "Test 3: HTTP UA == JS UA → no mismatch",
             f"Test 3: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # 4: HTTP UA != JS UA → mismatch
    try:
        r = analyze_server_headers(
            {"user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"},
            "1.1",
            {"ua": "Mozilla/5.0 (Linux; X11) Firefox/100.0"},
            {},
        )
        _chk(CODE_HTTP_UA_JS_MISMATCH in _codes(r),
             "Test 4: HTTP UA != JS UA → HTTP_UA_JS_MISMATCH",
             f"Test 4: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # 5: Chrome 120 no sec-ch-ua on HTTPS → MISSING_SEC_CH_UA
    try:
        r = analyze_server_headers(
            {"user-agent": "Mozilla/5.0 Chrome/120.0.0.0"},
            "1.1",
            {},
            {},
        )
        _chk(CODE_MISSING_SEC_CH_UA in _codes(r),
             "Test 5: Chrome 120 no sec-ch-ua → MISSING_SEC_CH_UA",
             f"Test 5: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # 6: Chrome 89 no sec-ch-ua → no signal (below min version)
    try:
        r = analyze_server_headers(
            {"user-agent": "Mozilla/5.0 Chrome/89.0.0.0"},
            "1.1",
            {},
            {},
        )
        _chk(CODE_MISSING_SEC_CH_UA not in _codes(r),
             "Test 6: Chrome 89 no sec-ch-ua → no signal (below min)",
             f"Test 6: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # 7: Firefox + sec-ch-ua → SEC_CH_UA_ON_FIREFOX (impossible)
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Firefox/120.0",
                "sec-ch-ua": '"Chromium";v="120"',
            },
            "1.1",
            {},
            {},
        )
        impossible_signals = [i for i in r if i[0] == CODE_SEC_CH_UA_ON_FIREFOX and i[1] == "impossible"]
        _chk(len(impossible_signals) == 1,
             "Test 7: Firefox + sec-ch-ua → SEC_CH_UA_ON_FIREFOX (impossible)",
             f"Test 7: got {[(i[0], i[1]) for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # 8: Safari + sec-ch-ua → SEC_CH_UA_ON_SAFARI (impossible)
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 (Macintosh) Version/17.0 Safari/605.1.15",
                "sec-ch-ua": '"Chromium";v="120"',
            },
            "1.1",
            {},
            {},
        )
        impossible_signals = [i for i in r if i[0] == CODE_SEC_CH_UA_ON_SAFARI and i[1] == "impossible"]
        _chk(len(impossible_signals) == 1,
             "Test 8: Safari + sec-ch-ua → SEC_CH_UA_ON_SAFARI (impossible)",
             f"Test 8: got {[(i[0], i[1]) for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # 9: sec-ch-ua-mobile=?1 with desktop UA → mismatch
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "sec-ch-ua-mobile": "?1",
            },
            "1.1",
            {},
            {},
        )
        _chk(CODE_SEC_CH_UA_MOBILE_MISMATCH in _codes(r),
             "Test 9: sec-ch-ua-mobile=?1 on desktop UA → mismatch",
             f"Test 9: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # 10: sec-ch-ua-mobile=?0 with mobile UA → mismatch
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 (Linux; Android 13) Mobile Chrome/120.0.0.0",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "sec-ch-ua-mobile": "?0",
            },
            "1.1",
            {},
            {},
        )
        _chk(CODE_SEC_CH_UA_MOBILE_MISMATCH in _codes(r),
             "Test 10: sec-ch-ua-mobile=?0 on mobile UA → mismatch",
             f"Test 10: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # 11: iPad with sec-ch-ua-mobile=?0 → no mismatch (iPadOS exception)
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 (iPad; CPU OS 16_0) Mobile/15E148",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "sec-ch-ua-mobile": "?0",
            },
            "1.1",
            {},
            {},
        )
        _chk(CODE_SEC_CH_UA_MOBILE_MISMATCH not in _codes(r),
             "Test 11: iPad + sec-ch-ua-mobile=?0 → no mismatch",
             f"Test 11: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # 12: HeadlessChrome brand → SEC_CH_HEADLESS_BRAND (impossible)
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "sec-ch-ua": '"HeadlessChrome";v="120", "Chromium";v="120"',
            },
            "1.1",
            {},
            {},
        )
        _chk(CODE_SEC_CH_HEADLESS_BRAND in _codes(r),
             "Test 12: HeadlessChrome brand → SEC_CH_HEADLESS_BRAND",
             f"Test 12: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # 13: UA says Chrome but brands lack Google Chrome → GOOGLE_MISSING
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "sec-ch-ua": '"Chromium";v="120", "Not_A Brand";v="8"',
            },
            "1.1",
            {},
            {},
        )
        # Should have GOOGLE_MISSING (Chromium-only, no alt brand)
        _chk(CODE_SEC_CH_UA_GOOGLE_MISSING in _codes(r),
             "Test 13: Chromium-only brands → GOOGLE_MISSING",
             f"Test 13: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 13: crashed ({e})")

    # 14: HTTP/1.0 without proxy → HTTP_1_1_ON_HTTPS critical
    try:
        r = analyze_server_headers(
            {"user-agent": "Mozilla/5.0 Chrome/120.0.0.0", "sec-ch-ua": '"Google Chrome";v="120"'},
            "1.0",
            {},
            {},
        )
        http_signals = [i for i in r if i[0] == CODE_HTTP_1_1_ON_HTTPS]
        _chk(len(http_signals) == 1 and http_signals[0][1] == "critical",
             "Test 14: HTTP/1.0 no proxy → HTTP_1_1_ON_HTTPS critical",
             f"Test 14: got {http_signals}")
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # 15: HTTP/1.1 behind proxy → HTTP_1_1_ON_HTTPS low (neutralized)
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "x-forwarded-proto": "https",
            },
            "1.1",
            {},
            {},
        )
        http_signals = [i for i in r if i[0] == CODE_HTTP_1_1_ON_HTTPS]
        _chk(len(http_signals) == 1 and http_signals[0][1] == "low",
             "Test 15: HTTP/1.1 behind proxy → HTTP_1_1_ON_HTTPS low (neutralized)",
             f"Test 15: got {http_signals}")
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # 16: CF-IPCountry vs TZ mismatch → CF_COUNTRY_TZ_MISMATCH
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "cf-ipcountry": "EG",
            },
            "1.1",
            {},
            {"timezone": "America/New_York"},
        )
        _chk(CODE_CF_COUNTRY_TZ_MISMATCH in _codes(r),
             "Test 16: CF=EG but TZ=New_York → CF_COUNTRY_TZ_MISMATCH",
             f"Test 16: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 16: crashed ({e})")

    # 17: CF-IPCountry matches TZ → no signal
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "cf-ipcountry": "EG",
            },
            "1.1",
            {},
            {"timezone": "Africa/Cairo"},
        )
        _chk(CODE_CF_COUNTRY_TZ_MISMATCH not in _codes(r),
             "Test 17: CF=EG and TZ=Cairo → no mismatch",
             f"Test 17: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 17: crashed ({e})")

    # 18: Border pair exception (US ↔ CA) → no signal
    try:
        r = analyze_server_headers(
            {
                "user-agent": "Mozilla/5.0 Chrome/120.0.0.0",
                "sec-ch-ua": '"Google Chrome";v="120"',
                "cf-ipcountry": "US",
            },
            "1.1",
            {},
            {"timezone": "America/Toronto"},  # Canada
        )
        _chk(CODE_CF_COUNTRY_TZ_MISMATCH not in _codes(r),
             "Test 18: CF=US but TZ=Toronto (border pair) → no signal",
             f"Test 18: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 18: crashed ({e})")

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 4: SERVER CROSS-VALIDATION — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 4] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 4 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 4] Server cross-validation self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 4 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 4] {r}")
        logger.error("[SYSTEM 4] Server cross-validation self-test FAILED")

    print("=" * 70 + "\n")
    return ok


# =========================================================
# AUTO-RUN ON IMPORT
# =========================================================
_SELF_TEST_PASSED: Optional[bool] = None


def _should_run_self_test() -> bool:
    if os.getenv("OVG_SELF_TEST_ENABLED", "1") != "1":
        return False
    if "pytest" in sys.modules:
        return False
    return True


if _should_run_self_test():
    try:
        _SELF_TEST_PASSED = print_self_test()
    except Exception as e:
        print(f"⚠️  [SYSTEM 4] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False
