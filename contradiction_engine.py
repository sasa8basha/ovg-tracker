"""
contradiction_engine.py — Impossibility & Contradiction Detection (v3.4)
"""
import re

class ContradictionEngine:
    def __init__(self):
        self.findings = []

    def add(self, code, severity, score, detail, category=""):
        if severity not in ("impossible", "critical", "high", "medium", "low"):
            severity = "medium"
        self.findings.append({"code": code, "severity": severity, "score": int(score), "detail": detail[:200], "category": category, "source": "contradiction"})

    def run(self, ctx):
        for rule_name, rule in RULES:
            try:
                result = rule(ctx)
                if result:
                    self.add(rule_name, result["severity"], result["score"], result["detail"], result.get("category", ""))
            except Exception:
                continue
        return self.findings

    def has_impossible(self):
        return any(f["severity"] == "impossible" for f in self.findings)


def _safe_dict(v): return v if isinstance(v, dict) else {}
def _safe_list(v): return v if isinstance(v, list) else []
def _safe_int(v, default=0):
    try: return int(v)
    except (ValueError, TypeError): return default
def _safe_float(v, default=0.0):
    try:
        f = float(v)
        if f != f: return default
        return f
    except (ValueError, TypeError): return default
def _get(ctx, path, default=None):
    cur = ctx
    for part in path.split("."):
        if isinstance(cur, dict): cur = cur.get(part)
        else: return default
        if cur is None: return default
    return cur if cur is not None else default


# =========================================================
# IMPOSSIBILITY RULES (100% - True contradictions)
# =========================================================
def rule_windows_linux_platform(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    platform = (_get(ctx, "nav.platform") or "").lower()
    if "windows nt" in ua and platform:
        if "linux" in platform or "x11" in platform or "ubuntu" in platform:
            return {"severity": "impossible", "score": 100, "detail": f"Windows UA + platform='{platform}'", "category": "os"}
    return None

def rule_macos_windows_platform(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    platform = (_get(ctx, "nav.platform") or "").lower()
    if ("mac os" in ua or "macintosh" in ua) and platform:
        if "win" in platform:
            return {"severity": "impossible", "score": 100, "detail": f"macOS UA + platform='{platform}'", "category": "os"}
    return None

def rule_firefox_chrome_obj(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    chrome_check = _get(ctx, "fp.chrome_check")
    if "firefox" in ua and chrome_check == "full":
        return {"severity": "impossible", "score": 100, "detail": "Firefox UA + window.chrome", "category": "browser"}
    return None

def rule_safari_chrome_obj(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    chrome_check = _get(ctx, "fp.chrome_check")
    is_safari = ("safari" in ua and "chrome" not in ua and "chromium" not in ua)
    if is_safari and chrome_check == "full":
        return {"severity": "impossible", "score": 100, "detail": "Safari UA + window.chrome", "category": "browser"}
    return None

def rule_ios_user_agent_data(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    ua_data = _get(ctx, "nav.ua_data")
    is_ios_safari = ("iphone" in ua or "ipad" in ua) and "safari" in ua and "crios" not in ua
    if is_ios_safari and ua_data:
        return {"severity": "impossible", "score": 100, "detail": "iOS Safari + userAgentData", "category": "browser"}
    return None

def rule_sec_ch_ua_platform_mismatch(ctx):
    headers = _safe_dict(ctx.get("headers"))
    platform = (_get(ctx, "nav.platform") or "").lower()
    sec_platform_raw = headers.get("sec-ch-ua-platform", "")
    if not sec_platform_raw or not platform: return None
    sec_platform = str(sec_platform_raw).strip('"').strip("'").lower()
    js_is_win = "win" in platform
    js_is_mac = "mac" in platform
    js_is_linux = "linux" in platform or "x11" in platform
    sec_is_win = sec_platform == "windows"
    sec_is_mac = "macos" in sec_platform or "mac" in sec_platform
    sec_is_linux = sec_platform in ("linux", "android")

    if sec_is_win and (js_is_mac or js_is_linux):
        return {"severity": "impossible", "score": 100, "detail": f"sec-ch-ua=Windows vs JS={platform}", "category": "headers"}
    if sec_is_mac and (js_is_win or js_is_linux):
        return {"severity": "impossible", "score": 100, "detail": f"sec-ch-ua=macOS vs JS={platform}", "category": "headers"}
    if sec_is_linux and (js_is_win or js_is_mac):
        return {"severity": "impossible", "score": 100, "detail": f"sec-ch-ua=Linux vs JS={platform}", "category": "headers"}
    return None

def rule_avail_greater_than_screen(ctx):
    w = _safe_int(_get(ctx, "screen.width"), 0)
    aw = _safe_int(_get(ctx, "screen.availWidth"), 0)
    if w > 0 and aw > w:
        return {"severity": "impossible", "score": 100, "detail": f"availWidth({aw}) > width({w})", "category": "screen"}
    h = _safe_int(_get(ctx, "screen.height"), 0)
    ah = _safe_int(_get(ctx, "screen.availHeight"), 0)
    if h > 0 and ah > h:
        return {"severity": "impossible", "score": 100, "detail": f"availHeight({ah}) > height({h})", "category": "screen"}
    return None

def rule_interaction_before_paint(ctx):
    milestones = _safe_dict(ctx.get("milestones"))
    t_paint = milestones.get("t_first_paint")
    t_int = milestones.get("t_first_interaction")
    if t_paint is None or t_int is None: return None
    try: tp, ti = int(t_paint), int(t_int)
    except (ValueError, TypeError): return None
    if tp > 100 and ti < tp:
        diff = tp - ti
        if diff > 2000:
            return {"severity": "impossible", "score": 100, "detail": f"Interaction {diff}ms before paint", "category": "temporal"}
    return None

def rule_viewport_2x_screen(ctx):
    sw = _safe_int(_get(ctx, "screen.width"), 0)
    iw = _safe_int(_get(ctx, "screen.innerWidth"), 0)
    if sw > 0 and iw > sw * 2.5:
        return {"severity": "impossible", "score": 100, "detail": f"innerWidth({iw}) > 2.5x screen({sw})", "category": "screen"}
    return None


# =========================================================
# CRITICAL RULES (High Confidence)
# =========================================================
def rule_ua_chrome_missing_sec_ch_ua(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    headers = _safe_dict(ctx.get("headers"))
    m = re.search(r"chrome/(\d+)", ua)
    if not m: return None
    try: version = int(m.group(1))
    except (ValueError, TypeError): return None
    if version < 90: return None
    if "crios" in ua or "fxios" in ua: return None
    if "iphone" in ua or "ipad" in ua: return None
    if not headers.get("sec-ch-ua"):
        return {"severity": "critical", "score": 90, "detail": f"Chrome {version}+ missing sec-ch-ua", "category": "headers"}
    return None

def rule_chrome_http_1_0(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    http_ver = str(ctx.get("http_version") or "").strip()
    is_chrome = "chrome" in ua or "chromium" in ua
    if is_chrome and http_ver == "1.0":
        return {"severity": "critical", "score": 80, "detail": "Chrome + HTTP/1.0", "category": "headers"}
    return None

def rule_firefox_sec_ch_ua(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    headers = _safe_dict(ctx.get("headers"))
    if "firefox" in ua and headers.get("sec-ch-ua"):
        return {"severity": "critical", "score": 85, "detail": "Firefox + sec-ch-ua", "category": "headers"}
    return None

def rule_safari_sec_ch_ua(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    headers = _safe_dict(ctx.get("headers"))
    is_safari = ("safari" in ua and "chrome" not in ua and "chromium" not in ua)
    is_mobile_safari = ("iphone" in ua or "ipad" in ua)
    if (is_safari or is_mobile_safari) and headers.get("sec-ch-ua"):
        return {"severity": "critical", "score": 85, "detail": "Safari + sec-ch-ua", "category": "headers"}
    return None

def rule_speech_zero_with_chrome_desktop(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    speech = _safe_int(_get(ctx, "fp.speech_voices"), -1)
    is_chrome = "chrome" in ua and "edg/" not in ua and "opr/" not in ua
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)
    if is_chrome and not is_mobile and speech == 0:
        return {"severity": "critical", "score": 85, "detail": "Chrome desktop speech=0", "category": "browser"}
    return None


# =========================================================
# HIGH RULES (Strong Indicators)
# =========================================================
def rule_mobile_no_touch(ctx):
    # WebViews ممكن يكون فيها 0، فمش مستحيل، لكنه high
    ua = (_get(ctx, "ua") or "").lower()
    max_touch = _safe_int(_get(ctx, "nav.maxTouchPoints", -1), -1)
    if not max_touch: max_touch = _safe_int(_get(ctx, "nav.max_touch_points", -1), -1)
    is_mobile = ("mobile" in ua or "android" in ua or "iphone" in ua)
    if is_mobile and max_touch == 0:
        return {"severity": "high", "score": 70, "detail": f"Mobile UA + maxTouchPoints=0", "category": "hardware"}
    return None

def rule_iphone_wide_screen(ctx):
    # في وضع Desktop ممكن يكون 1170، فالعتبة 1200
    ua = (_get(ctx, "ua") or "").lower()
    screen_w = _safe_int(_get(ctx, "screen.width"), 0)
    is_iphone = "iphone" in ua
    if is_iphone and screen_w > 1200:
        return {"severity": "high", "score": 70, "detail": f"iPhone UA + screen.width={screen_w}", "category": "screen"}
    return None

def rule_impossible_cpu_memory(ctx):
    cores = _safe_int(_get(ctx, "fp.hardwareConcurrency"), 0)
    memory = _safe_float(_get(ctx, "fp.deviceMemory"), 0)
    if cores >= 16 and 0 < memory <= 2:
        return {"severity": "high", "score": 70, "detail": f"{cores} cores + {memory}GB RAM", "category": "hardware"}
    if cores >= 8 and 0 < memory <= 1:
        return {"severity": "high", "score": 65, "detail": f"{cores} cores + {memory}GB RAM", "category": "hardware"}
    return None

def rule_desktop_no_mouse_no_touch_long(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    events = _safe_dict(_get(ctx, "behavior.events"))
    duration = _safe_int(_get(ctx, "behavior.total_time_ms"), 0)
    if not duration: duration = _safe_int(_get(ctx, "behavior.time_on_page_ms"), 0)
    mm = _safe_int(events.get("mousemove"), 0)
    ts = _safe_int(events.get("touchstart"), 0)
    kd = _safe_int(events.get("keydown"), 0)
    is_desktop = ("windows nt" in ua or "mac os" in ua or "linux" in ua)
    is_mobile = ("mobile" in ua or "android" in ua)
    if is_desktop and not is_mobile and duration > 15000:
        if mm == 0 and ts == 0 and kd == 0:
            return {"severity": "critical", "score": 85, "detail": f"Desktop {duration/1000:.0f}s: zero input", "category": "behavior"}
    return None


# =========================================================
# MEDIUM RULES
# =========================================================
def rule_ua_chrome_outdated(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    m = re.search(r"chrome/(\d+)", ua)
    if not m: return None
    try: version = int(m.group(1))
    except (ValueError, TypeError): return None
    if 0 < version < 80:
        return {"severity": "medium", "score": 35, "detail": f"Chrome {version} outdated", "category": "browser"}
    return None

def rule_desktop_small_screen(ctx):
    ua = (_get(ctx, "ua") or "").lower()
    sw = _safe_int(_get(ctx, "screen.width"), 0)
    is_desktop = ("windows nt" in ua or "mac os" in ua)
    is_mobile = ("mobile" in ua or "android" in ua)
    if is_desktop and not is_mobile and 0 < sw < 800:
        return {"severity": "medium", "score": 35, "detail": f"Desktop {sw}px", "category": "screen"}
    return None


RULES = [
    ("WINDOWS_UA_LINUX_PLATFORM", rule_windows_linux_platform),
    ("MACOS_UA_WINDOWS_PLATFORM", rule_macos_windows_platform),
    ("FIREFOX_CHROME_OBJ", rule_firefox_chrome_obj),
    ("SAFARI_CHROME_OBJ", rule_safari_chrome_obj),
    ("IOS_USER_AGENT_DATA", rule_ios_user_agent_data),
    ("SEC_CH_UA_PLATFORM_MISMATCH", rule_sec_ch_ua_platform_mismatch),
    ("AVAIL_GREATER_THAN_SCREEN", rule_avail_greater_than_screen),
    ("INTERACTION_BEFORE_PAINT_IMPOSSIBLE", rule_interaction_before_paint),
    ("VIEWPORT_2X_SCREEN", rule_viewport_2x_screen),
    ("CHROME_MISSING_SEC_CH_UA", rule_ua_chrome_missing_sec_ch_ua),
    ("CHROME_HTTP_1_0", rule_chrome_http_1_0),
    ("FIREFOX_SEC_CH_UA", rule_firefox_sec_ch_ua),
    ("SAFARI_SEC_CH_UA", rule_safari_sec_ch_ua),
    ("SPEECH_ZERO_CHROME_DESKTOP", rule_speech_zero_with_chrome_desktop),
    ("MOBILE_NO_TOUCH", rule_mobile_no_touch),
    ("IPHONE_WIDE_SCREEN", rule_iphone_wide_screen),
    ("ABSURD_CPU_MEMORY", rule_impossible_cpu_memory),
    ("DESKTOP_NO_INPUT_LONG", rule_desktop_no_mouse_no_touch_long),
    ("UA_CHROME_OUTDATED", rule_ua_chrome_outdated),
    ("DESKTOP_SMALL_SCREEN", rule_desktop_small_screen),
]