"""
contradiction_engine.py — Impossibility & Contradiction Detection (v4.0)

Philosophy:
  NOT "does it look like a bot" — but "is this PHYSICALLY IMPOSSIBLE for a
  real browser?"

Severity tiers:
  - impossible: 100% impossible on real hardware (verdict=invalid instantly)
  - critical:   99%+ impossible (verdict=invalid)
  - high:       strong contradiction (verdict=suspicious or invalid)
  - medium:     unusual pattern worth noting
  - low:        slightly odd

v4.0 additions (vs v3.4):
  - Every finding now carries `direction` and `base_strength` so the
    new fusion layer can weight it probabilistically.
  - Everything else (rules) unchanged.
"""
import re

from collector.signals import SIGNAL_REGISTRY


# =========================================================
# HELPERS FOR SIGNAL ENRICHMENT
# =========================================================
def _base_for(code: str, severity: str) -> float:
    """Look up base_strength from registry; fall back to severity-based default."""
    reg = SIGNAL_REGISTRY.get(code)
    if reg:
        try:
            return float(reg.get("base", 0.5))
        except (ValueError, TypeError):
            pass
    return {
        "impossible": 0.98,
        "critical":   0.85,
        "high":       0.70,
        "medium":     0.45,
        "low":        0.20,
    }.get(severity, 0.45)


class ContradictionEngine:
    def __init__(self):
        self.findings = []

    def add(self, code, severity, score, detail, category=""):
        if severity not in ("impossible", "critical", "high", "medium", "low"):
            severity = "medium"
        base = _base_for(code, severity)
        self.findings.append({
            "code": code,
            "severity": severity,
            "score": int(score),
            "detail": detail[:200],
            "category": category,
            "source": "contradiction",
            # === v4.0 unified shape ===
            "direction": "bot",
            "base_strength": base,
        })

    def run(self, ctx):
        for rule_name, rule in RULES:
            try:
                result = rule(ctx)
                if result:
                    self.add(
                        rule_name,
                        result["severity"],
                        result["score"],
                        result["detail"],
                        result.get("category", ""),
                    )
            except Exception:
                continue
        return self.findings

    def has_impossible(self):
        return any(f["severity"] == "impossible" for f in self.findings)


# =========================================================
# RULE HELPERS
# =========================================================
def _safe_dict(v):
    return v if isinstance(v, dict) else {}


def _safe_list(v):
    return v if isinstance(v, list) else []


def _safe_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _safe_float(v, default=0.0):
    try:
        f = float(v)
        if f != f:
            return default
        return f
    except (ValueError, TypeError):
        return default


def _get(ctx, path, default=None):
    cur = ctx
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
        if cur is None:
            return default
    return cur if cur is not None else default


# =========================================================
# IMPOSSIBILITY RULES (100% — cannot be spoofed without breaking)
# =========================================================

def rule_windows_linux_platform(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    platform = (_get(ctx, "nav.platform") or "").lower()
    if "windows nt" in ua and platform:
        if "linux" in platform or "x11" in platform or "ubuntu" in platform:
            return {"severity": "impossible", "score": 100,
                    "detail": f"Windows UA + platform='{platform}'",
                    "category": "os"}
    return None


def rule_macos_windows_platform(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    platform = (_get(ctx, "nav.platform") or "").lower()
    if ("mac os" in ua or "macintosh" in ua) and platform:
        if "win" in platform:
            return {"severity": "impossible", "score": 100,
                    "detail": f"macOS UA + platform='{platform}'",
                    "category": "os"}
    return None


def rule_firefox_chrome_obj(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    chrome_check = _get(ctx, "fp.chrome_check")
    if "firefox" in ua and chrome_check == "full":
        return {"severity": "impossible", "score": 100,
                "detail": "Firefox UA + full window.chrome.runtime",
                "category": "browser"}
    return None


def rule_safari_chrome_obj(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    chrome_check = _get(ctx, "fp.chrome_check")
    is_safari = ("safari" in ua and "chrome" not in ua and "chromium" not in ua)
    if is_safari and chrome_check == "full":
        return {"severity": "impossible", "score": 100,
                "detail": "Safari UA + full window.chrome.runtime",
                "category": "browser"}
    return None


def rule_ios_user_agent_data(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    ua_data = _get(ctx, "nav.ua_data")
    is_ios_safari = ("iphone" in ua or "ipad" in ua) and "safari" in ua and "crios" not in ua
    if is_ios_safari and ua_data:
        return {"severity": "impossible", "score": 100,
                "detail": "iOS Safari + navigator.userAgentData (Chrome-only API)",
                "category": "browser"}
    return None


def rule_mobile_no_touch(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    max_touch = _safe_int(_get(ctx, "nav.maxTouchPoints", -1), -1)
    if not max_touch:
        max_touch = _safe_int(_get(ctx, "nav.max_touch_points", -1), -1)
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)
    if is_mobile and max_touch == 0:
        return {"severity": "impossible", "score": 100,
                "detail": f"Mobile UA + maxTouchPoints={max_touch}",
                "category": "hardware"}
    return None


def rule_sec_ch_ua_platform_mismatch(ctx):
    headers = _safe_dict(ctx.get("headers"))
    platform = (_get(ctx, "nav.platform") or "").lower()
    sec_platform_raw = headers.get("sec-ch-ua-platform", "")
    if not sec_platform_raw or not platform:
        return None

    sec_platform = str(sec_platform_raw).strip('"').strip("'").lower()

    js_is_win = "win" in platform
    js_is_mac = "mac" in platform
    js_is_linux = "linux" in platform or "x11" in platform

    sec_is_win = sec_platform == "windows"
    sec_is_mac = "macos" in sec_platform or "mac" in sec_platform
    sec_is_linux = sec_platform in ("linux", "android")

    if sec_is_win and (js_is_mac or js_is_linux):
        return {"severity": "impossible", "score": 100,
                "detail": f"sec-ch-ua-platform=Windows vs JS platform={platform}",
                "category": "headers"}
    if sec_is_mac and (js_is_win or js_is_linux):
        return {"severity": "impossible", "score": 100,
                "detail": f"sec-ch-ua-platform=macOS vs JS platform={platform}",
                "category": "headers"}
    if sec_is_linux and (js_is_win or js_is_mac):
        return {"severity": "impossible", "score": 100,
                "detail": f"sec-ch-ua-platform=Linux vs JS platform={platform}",
                "category": "headers"}
    return None


def rule_sec_ch_ua_mobile_mismatch(ctx):
    headers = _safe_dict(ctx.get("headers"))
    ua = (_get(ctx, "ua") or "").lower()
    scm = headers.get("sec-ch-ua-mobile", "").strip()

    is_mobile_ua = ("mobile" in ua or "android" in ua or "iphone" in ua)
    is_desktop_ua = not is_mobile_ua and ("windows nt" in ua or "mac os" in ua or "linux" in ua)

    if scm == "?1" and is_desktop_ua:
        return {"severity": "impossible", "score": 100,
                "detail": "sec-ch-ua-mobile=?1 but desktop UA",
                "category": "headers"}
    if scm == "?0" and is_mobile_ua and "ipad" not in ua:
        return {"severity": "high", "score": 70,
                "detail": "sec-ch-ua-mobile=?0 but mobile UA",
                "category": "headers"}
    return None


def rule_iphone_wide_screen(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    screen_w = _safe_int(_get(ctx, "screen.width"), 0)
    is_iphone = "iphone" in ua
    if is_iphone and screen_w > 500:
        return {"severity": "impossible", "score": 100,
                "detail": f"iPhone UA + screen.width={screen_w}",
                "category": "screen"}
    return None


def rule_mobile_4k_screen(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    screen_w = _safe_int(_get(ctx, "screen.width"), 0)
    is_mobile = ("mobile" in ua or "android" in ua)
    if is_mobile and screen_w >= 3000:
        return {"severity": "impossible", "score": 100,
                "detail": f"Mobile UA + screen.width={screen_w}px",
                "category": "screen"}
    return None


def rule_avail_greater_than_screen(ctx):
    w = _safe_int(_get(ctx, "screen.width"), 0)
    aw = _safe_int(_get(ctx, "screen.availWidth"), 0)
    if w > 0 and aw > w:
        return {"severity": "impossible", "score": 100,
                "detail": f"availWidth({aw}) > width({w}) — physically impossible",
                "category": "screen"}

    h = _safe_int(_get(ctx, "screen.height"), 0)
    ah = _safe_int(_get(ctx, "screen.availHeight"), 0)
    if h > 0 and ah > h:
        return {"severity": "impossible", "score": 100,
                "detail": f"availHeight({ah}) > height({h}) — physically impossible",
                "category": "screen"}
    return None


def rule_interaction_before_paint(ctx):
    milestones = _safe_dict(ctx.get("milestones"))
    t_paint = milestones.get("t_first_paint")
    t_int = milestones.get("t_first_interaction")
    if t_paint is None or t_int is None:
        return None
    try:
        tp = int(t_paint)
        ti = int(t_int)
    except (ValueError, TypeError):
        return None
    if tp > 100 and ti < tp:
        diff = tp - ti
        if diff > 2000:
            return {"severity": "impossible", "score": 100,
                    "detail": f"Interaction {diff}ms before paint — impossible",
                    "category": "temporal"}
    return None


def rule_click_no_mouse_desktop(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    events = _safe_dict(_get(ctx, "behavior.events"))
    clicks = _safe_int(events.get("clicks"), 0)
    mousemoves = _safe_int(events.get("mousemove"), 0)
    touchstarts = _safe_int(events.get("touchstart"), 0)

    is_desktop = ("windows nt" in ua or "mac os" in ua or "linux" in ua)
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)

    if is_desktop and not is_mobile:
        if clicks > 0 and mousemoves == 0 and touchstarts == 0:
            return {"severity": "impossible", "score": 100,
                    "detail": f"{clicks} clicks but 0 mousemove (desktop)",
                    "category": "behavior"}
    return None


def rule_viewport_2x_screen(ctx):
    sw = _safe_int(_get(ctx, "screen.width"), 0)
    iw = _safe_int(_get(ctx, "screen.innerWidth"), 0)
    if sw > 0 and iw > sw * 2:
        return {"severity": "impossible", "score": 100,
                "detail": f"innerWidth({iw}) > 2× screen.width({sw})",
                "category": "screen"}
    return None


# =========================================================
# CRITICAL RULES (99%+)
# =========================================================

def rule_ua_chrome_missing_sec_ch_ua(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    headers = _safe_dict(ctx.get("headers"))
    m = re.search(r"chrome/(\d+)", ua)
    if not m:
        return None
    try:
        version = int(m.group(1))
    except (ValueError, TypeError):
        return None
    if version < 90:
        return None
    if "crios" in ua or "fxios" in ua:
        return None
    if "iphone" in ua or "ipad" in ua:
        return None

    if not headers.get("sec-ch-ua"):
        return {"severity": "critical", "score": 90,
                "detail": f"Chrome {version}+ UA missing sec-ch-ua header",
                "category": "headers"}
    return None


def rule_ua_brands_mismatch(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    brands = _safe_list(_get(ctx, "fp.ua_brands"))

    if "chrome/" not in ua or "crios" in ua or "edg/" in ua:
        return None
    if "iphone" in ua or "ipad" in ua:
        return None
    if not brands:
        return None

    has_google = False
    has_chromium = False
    for b in brands:
        if not isinstance(b, dict):
            continue
        brand = str(b.get("brand", "")).lower()
        if "google chrome" in brand:
            has_google = True
        if "chromium" in brand:
            has_chromium = True

    if has_chromium and not has_google:
        return {"severity": "critical", "score": 85,
                "detail": "UA says Chrome, brands say Chromium only",
                "category": "headers"}
    return None


def rule_accept_language_js_mismatch(ctx):
    headers = _safe_dict(ctx.get("headers"))
    header_lang = (headers.get("accept-language") or "").lower().strip()
    js_lang = (_get(ctx, "nav.language") or "").lower().strip()

    if not header_lang or not js_lang:
        return None

    header_primary = header_lang.split(",")[0].split(";")[0].strip().split("-")[0]
    js_primary = js_lang.split("-")[0]

    if not header_primary or not js_primary:
        return None

    if header_primary != js_primary:
        return {"severity": "high", "score": 60,
                "detail": f"Accept-Language '{header_primary}' vs JS language '{js_primary}'",
                "category": "headers"}
    return None


def rule_chrome_low_version_with_ua_data(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    ua_data = _get(ctx, "nav.ua_data")
    m = re.search(r"chrome/(\d+)", ua)
    if not m:
        return None
    try:
        version = int(m.group(1))
    except (ValueError, TypeError):
        return None
    if version < 90 and ua_data:
        return {"severity": "impossible", "score": 100,
                "detail": f"Chrome {version} + navigator.userAgentData (requires 90+)",
                "category": "browser"}
    return None


def rule_ip_tz_lang_triple_mismatch(ctx):
    cc = (_get(ctx, "ip_info.country_code") or "").upper().strip()
    tz = (_get(ctx, "fp.timezone") or "").lower()
    lang = (_get(ctx, "nav.language") or "").lower()

    if not cc or not tz or not lang:
        return None
    if cc in ("LO", "XX", ""):
        return None

    TZ_TO_COUNTRY = {
        "africa/cairo": "EG", "asia/riyadh": "SA", "asia/dubai": "AE",
        "asia/kuwait": "KW", "asia/qatar": "QA", "asia/bahrain": "BH",
        "africa/casablanca": "MA", "africa/algiers": "DZ", "africa/tunis": "TN",
        "europe/london": "GB", "europe/paris": "FR", "europe/berlin": "DE",
        "europe/madrid": "ES", "europe/rome": "IT",
        "asia/tokyo": "JP", "asia/seoul": "KR", "asia/shanghai": "CN",
        "asia/kolkata": "IN", "asia/calcutta": "IN",
        "america/new_york": "US", "america/chicago": "US",
        "america/denver": "US", "america/los_angeles": "US",
        "america/toronto": "CA", "america/vancouver": "CA",
        "america/sao_paulo": "BR", "australia/sydney": "AU",
    }

    LANG_TO_COUNTRY = {
        "ar": {"EG", "SA", "AE", "KW", "QA", "BH", "OM", "JO", "MA", "DZ", "TN", "LY"},
        "en": {"US", "GB", "CA", "AU", "NZ", "IE"},
        "es": {"ES", "MX", "AR", "CO", "CL", "PE"},
        "fr": {"FR", "BE", "CH", "CA"},
        "de": {"DE", "AT", "CH"},
        "it": {"IT"},
        "ja": {"JP"}, "ko": {"KR"}, "zh": {"CN", "TW", "HK", "SG"},
        "hi": {"IN"},
    }

    tz_country = TZ_TO_COUNTRY.get(tz)
    lang_primary = lang.split("-")[0]
    lang_countries = LANG_TO_COUNTRY.get(lang_primary, set())

    if tz_country and lang_countries:
        if (cc != tz_country
                and cc not in lang_countries
                and tz_country not in lang_countries):
            return {"severity": "critical", "score": 85,
                    "detail": f"Triple mismatch: IP={cc}, TZ={tz}, Lang={lang}",
                    "category": "locale"}
    return None


def rule_desktop_no_mouse_no_touch_long(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    events = _safe_dict(_get(ctx, "behavior.events"))
    duration = _safe_int(_get(ctx, "behavior.total_time_ms"), 0)
    if not duration:
        duration = _safe_int(_get(ctx, "behavior.time_on_page_ms"), 0)

    mm = _safe_int(events.get("mousemove"), 0)
    ts = _safe_int(events.get("touchstart"), 0)
    kd = _safe_int(events.get("keydown"), 0)

    is_desktop = ("windows nt" in ua or "mac os" in ua or "linux" in ua)
    is_mobile = ("mobile" in ua or "android" in ua)

    if is_desktop and not is_mobile and duration > 15000:
        if mm == 0 and ts == 0 and kd == 0:
            return {"severity": "critical", "score": 85,
                    "detail": f"Desktop {duration/1000:.0f}s: zero input events",
                    "category": "behavior"}
    return None


def rule_scroll_no_wheel_desktop(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    events = _safe_dict(_get(ctx, "behavior.events"))
    scrolls = _safe_int(events.get("scrolls"), 0)
    wheel = _safe_int(_get(ctx, "behavior.wheel_events"), 0)
    duration = _safe_int(_get(ctx, "behavior.total_time_ms"), 0)
    if not duration:
        duration = _safe_int(_get(ctx, "behavior.time_on_page_ms"), 0)

    is_desktop = ("windows nt" in ua or "mac os" in ua or "linux" in ua)
    is_mobile = ("mobile" in ua or "android" in ua)

    if is_desktop and not is_mobile and scrolls >= 5 and duration > 5000:
        if wheel == 0:
            return {"severity": "high", "score": 55,
                    "detail": f"{scrolls} scrolls, 0 wheel events (desktop)",
                    "category": "behavior"}
    return None


def rule_webgl2_no_webgl1(ctx):
    wg = _safe_dict(_get(ctx, "fp.webgl"))
    if wg.get("webgl2") is True and wg.get("renderer") == "blocked":
        return {"severity": "critical", "score": 80,
                "detail": "WebGL2 available but WebGL1 blocked",
                "category": "webgl"}
    return None


def rule_speech_zero_with_chrome_desktop(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    speech = _safe_int(_get(ctx, "fp.speech_voices"), -1)
    is_chrome = "chrome" in ua and "edg/" not in ua and "opr/" not in ua
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)
    if is_chrome and not is_mobile and speech == 0:
        return {"severity": "critical", "score": 85,
                "detail": "Chrome desktop speechSynthesis=0 (headless indicator)",
                "category": "browser"}
    return None


# =========================================================
# HIGH RULES
# =========================================================

def rule_impossible_cpu_memory(ctx):
    cores = _safe_int(_get(ctx, "fp.hardwareConcurrency"), 0)
    memory = _safe_float(_get(ctx, "fp.deviceMemory"), 0)
    if cores >= 16 and 0 < memory <= 2:
        return {"severity": "high", "score": 70,
                "detail": f"{cores} cores + {memory}GB RAM",
                "category": "hardware"}
    if cores >= 8 and 0 < memory <= 1:
        return {"severity": "high", "score": 65,
                "detail": f"{cores} cores + {memory}GB RAM",
                "category": "hardware"}
    return None


def rule_absurd_hardware_4k(ctx):
    sw = _safe_int(_get(ctx, "screen.width"), 0)
    cores = _safe_int(_get(ctx, "fp.hardwareConcurrency"), 0)
    if sw >= 2560 and 0 < cores <= 2:
        return {"severity": "high", "score": 60,
                "detail": f"screen.width={sw}px but {cores} cores",
                "category": "hardware"}
    return None


def rule_mobile_high_memory(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    memory = _safe_float(_get(ctx, "fp.deviceMemory"), 0)
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)
    if is_mobile and memory > 8:
        return {"severity": "high", "score": 65,
                "detail": f"Mobile UA + deviceMemory={memory}GB",
                "category": "hardware"}
    return None


def rule_mobile_pixel_ratio_1(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    pr = _safe_float(_get(ctx, "screen.pixelRatio"), 1)
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)
    if is_mobile and pr == 1:
        return {"severity": "high", "score": 55,
                "detail": "Mobile UA + pixelRatio=1 (desktop spoof)",
                "category": "screen"}
    return None


def rule_chrome_http_1_0(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    http_ver = str(ctx.get("http_version") or "").strip()
    is_chrome = "chrome" in ua or "chromium" in ua
    if is_chrome and http_ver == "1.0":
        return {"severity": "critical", "score": 80,
                "detail": "Chrome UA + HTTP/1.0 (impossible)",
                "category": "headers"}
    return None


def rule_firefox_sec_ch_ua(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    headers = _safe_dict(ctx.get("headers"))
    if "firefox" in ua and headers.get("sec-ch-ua"):
        return {"severity": "critical", "score": 85,
                "detail": "Firefox UA + sec-ch-ua header (impossible)",
                "category": "headers"}
    return None


def rule_safari_sec_ch_ua(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    headers = _safe_dict(ctx.get("headers"))
    is_safari = ("safari" in ua and "chrome" not in ua and "chromium" not in ua)
    is_mobile_safari = ("iphone" in ua or "ipad" in ua)
    if (is_safari or is_mobile_safari) and headers.get("sec-ch-ua"):
        return {"severity": "critical", "score": 85,
                "detail": "Safari UA + sec-ch-ua (impossible)",
                "category": "headers"}
    return None


def rule_webgl_vendor_no_renderer(ctx):
    wg = _safe_dict(_get(ctx, "fp.webgl"))
    vendor = str(wg.get("vendor") or "").lower()
    renderer = str(wg.get("renderer") or "").lower()
    ua = (_get(ctx, "ua") or "").lower()

    if "google" in vendor and "chrome" in ua and "chromium" not in ua:
        if not renderer or renderer in ("unknown", "google", ""):
            return {"severity": "high", "score": 55,
                    "detail": f"WebGL vendor='{vendor}' + renderer='{renderer}'",
                    "category": "webgl"}
    return None


def rule_webgl_no_vendor(ctx):
    wg = _safe_dict(_get(ctx, "fp.webgl"))
    vendor = str(wg.get("vendor") or "").strip()
    renderer = str(wg.get("renderer") or "").strip()
    if renderer and renderer != "blocked" and renderer != "Unknown":
        if not vendor or vendor == "Unknown":
            return {"severity": "high", "score": 55,
                    "detail": f"WebGL renderer='{renderer}' but vendor empty",
                    "category": "webgl"}
    return None


# =========================================================
# MEDIUM RULES
# =========================================================

def rule_ua_chrome_outdated(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    m = re.search(r"chrome/(\d+)", ua)
    if not m:
        return None
    try:
        version = int(m.group(1))
    except (ValueError, TypeError):
        return None
    if 0 < version < 80:
        return {"severity": "medium", "score": 35,
                "detail": f"Chrome {version} (outdated template)",
                "category": "browser"}
    return None


def rule_touch_desktop_high(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    max_touch = _safe_int(_get(ctx, "nav.maxTouchPoints"), 0)
    if not max_touch:
        max_touch = _safe_int(_get(ctx, "nav.max_touch_points"), 0)
    is_desktop = ("windows nt" in ua or "mac os" in ua or "linux" in ua)
    if is_desktop and max_touch > 10:
        return {"severity": "medium", "score": 40,
                "detail": f"Desktop UA + maxTouchPoints={max_touch}",
                "category": "hardware"}
    return None


def rule_language_list_too_long(ctx):
    langs = _safe_list(_get(ctx, "fp.languages"))
    if len(langs) > 8:
        return {"severity": "medium", "score": 30,
                "detail": f"navigator.languages has {len(langs)} items",
                "category": "locale"}
    return None


def rule_multi_locale_conflict(ctx):
    nav_lang = (_get(ctx, "nav.language") or "").lower()
    langs = _safe_list(_get(ctx, "fp.languages"))
    first_lang = str(langs[0]).lower() if langs else ""
    intl = (_get(ctx, "fp.intl_locale") or "").lower()

    if not nav_lang or not first_lang or not intl:
        return None

    nav_p = nav_lang.split("-")[0]
    first_p = first_lang.split("-")[0]
    intl_p = intl.split("-")[0]

    if nav_p and first_p and intl_p:
        if nav_p != first_p and nav_p != intl_p and first_p != intl_p:
            return {"severity": "medium", "score": 40,
                    "detail": f"3 different: nav='{nav_lang}', first='{first_lang}', intl='{intl}'",
                    "category": "locale"}
    return None


def rule_desktop_small_screen(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    sw = _safe_int(_get(ctx, "screen.width"), 0)
    is_desktop = ("windows nt" in ua or "mac os" in ua)
    is_mobile = ("mobile" in ua or "android" in ua)
    if is_desktop and not is_mobile and 0 < sw < 800:
        return {"severity": "medium", "score": 35,
                "detail": f"Desktop UA + screen.width={sw}px",
                "category": "screen"}
    return None


# =========================================================
# BEHAVIORAL CONTRADICTIONS
# =========================================================

def rule_heartbeat_beyond_session(ctx):
    heartbeats = _safe_list(ctx.get("heartbeats"))
    session_dur = _safe_int(_get(ctx, "behavior.total_time_ms"), 0)
    if not session_dur or not heartbeats:
        return None
    max_hb_t = 0
    for hb in heartbeats:
        if isinstance(hb, dict):
            t = _safe_int(hb.get("t_ms"), 0)
            if t > max_hb_t:
                max_hb_t = t
    if max_hb_t > session_dur + 2000:
        return {"severity": "high", "score": 60,
                "detail": f"Heartbeat t={max_hb_t}ms > session={session_dur}ms",
                "category": "temporal"}
    return None


def rule_idle_visible_long(ctx):
    behavior = _safe_dict(ctx.get("behavior"))
    duration = _safe_int(behavior.get("total_time_ms"), 0)
    if not duration:
        duration = _safe_int(behavior.get("time_on_page_ms"), 0)
    visible = _safe_int(behavior.get("visible_time_ms"), 0)
    events = _safe_dict(behavior.get("events"))

    if duration > 60000 and visible > duration * 0.95:
        mm = _safe_int(events.get("mousemove"), 0)
        cl = _safe_int(events.get("clicks"), 0)
        sc = _safe_int(events.get("scrolls"), 0)
        kd = _safe_int(events.get("keydown"), 0)
        ts = _safe_int(events.get("touchstart"), 0)
        if mm == 0 and cl == 0 and sc == 0 and kd == 0 and ts == 0:
            return {"severity": "critical", "score": 80,
                    "detail": f"Visible {visible/1000:.0f}s, zero interaction",
                    "category": "behavior"}
    return None


def rule_session_ending_before_starting(ctx):
    started = ctx.get("session_started_at")
    ended = ctx.get("session_ended_at")
    if not started or not ended:
        return None
    try:
        if ended < started:
            return {"severity": "high", "score": 60,
                    "detail": "Session end before start",
                    "category": "temporal"}
    except Exception:
        pass
    return None


# =========================================================
# RULE REGISTRY
# =========================================================
RULES = [
    # IMPOSSIBLE
    ("WINDOWS_UA_LINUX_PLATFORM", rule_windows_linux_platform),
    ("MACOS_UA_WINDOWS_PLATFORM", rule_macos_windows_platform),
    ("FIREFOX_CHROME_OBJ", rule_firefox_chrome_obj),
    ("SAFARI_CHROME_OBJ", rule_safari_chrome_obj),
    ("IOS_USER_AGENT_DATA", rule_ios_user_agent_data),
    ("MOBILE_NO_TOUCH", rule_mobile_no_touch),
    ("SEC_CH_UA_PLATFORM_MISMATCH", rule_sec_ch_ua_platform_mismatch),
    ("SEC_CH_UA_MOBILE_MISMATCH", rule_sec_ch_ua_mobile_mismatch),
    ("IPHONE_WIDE_SCREEN", rule_iphone_wide_screen),
    ("MOBILE_4K_SCREEN", rule_mobile_4k_screen),
    ("AVAIL_GREATER_THAN_SCREEN", rule_avail_greater_than_screen),
    ("INTERACTION_BEFORE_PAINT_IMPOSSIBLE", rule_interaction_before_paint),
    ("CLICK_NO_MOUSE_DESKTOP", rule_click_no_mouse_desktop),
    ("VIEWPORT_2X_SCREEN", rule_viewport_2x_screen),
    ("CHROME_LOW_WITH_UA_DATA", rule_chrome_low_version_with_ua_data),
    # CRITICAL
    ("CHROME_MISSING_SEC_CH_UA", rule_ua_chrome_missing_sec_ch_ua),
    ("UA_BRANDS_MISMATCH", rule_ua_brands_mismatch),
    ("IP_TZ_LANG_TRIPLE_MISMATCH", rule_ip_tz_lang_triple_mismatch),
    ("DESKTOP_NO_INPUT_LONG", rule_desktop_no_mouse_no_touch_long),
    ("CHROME_HTTP_1_0", rule_chrome_http_1_0),
    ("FIREFOX_SEC_CH_UA", rule_firefox_sec_ch_ua),
    ("SAFARI_SEC_CH_UA", rule_safari_sec_ch_ua),
    ("SPEECH_ZERO_CHROME_DESKTOP", rule_speech_zero_with_chrome_desktop),
    ("WEBGL2_NO_WEBGL1", rule_webgl2_no_webgl1),
    ("IDLE_VISIBLE_LONG", rule_idle_visible_long),
    # HIGH
    ("ACCEPT_LANGUAGE_JS_MISMATCH", rule_accept_language_js_mismatch),
    ("SCROLL_NO_WHEEL_DESKTOP", rule_scroll_no_wheel_desktop),
    ("ABSURD_CPU_MEMORY", rule_impossible_cpu_memory),
    ("ABSURD_HARDWARE_4K", rule_absurd_hardware_4k),
    ("MOBILE_HIGH_MEMORY", rule_mobile_high_memory),
    ("MOBILE_PIXEL_RATIO_1", rule_mobile_pixel_ratio_1),
    ("WEBGL_VENDOR_NO_RENDERER", rule_webgl_vendor_no_renderer),
    ("WEBGL_NO_VENDOR", rule_webgl_no_vendor),
    ("HEARTBEAT_BEYOND_SESSION", rule_heartbeat_beyond_session),
    ("SESSION_END_BEFORE_START", rule_session_ending_before_starting),
    # MEDIUM
    ("UA_CHROME_OUTDATED", rule_ua_chrome_outdated),
    ("TOUCH_DESKTOP_HIGH", rule_touch_desktop_high),
    ("LANGUAGE_LIST_TOO_LONG", rule_language_list_too_long),
    ("MULTI_LOCALE_CONFLICT", rule_multi_locale_conflict),
    ("DESKTOP_SMALL_SCREEN", rule_desktop_small_screen),
]