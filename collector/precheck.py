"""
collector/precheck.py — Fast pre-check rules (v8.4)

CRITICAL FIXES in v8.4:
  1. CDP_DETECTED — REMOVED from CRITICAL_RULES
     Reason: getCDP() in the tracker was triggering on ANY user with
     DevTools open (F12), because console.debug() serializes Error
     objects which invokes the stack getter. This blocked every developer
     and power user. The new getCDP() (v8.4 tracker) uses a much more
     specific check (CDP Runtime.addBinding bindings), so CDP_DETECTED
     is now a normal bot signal, not a critical block.

  2. WRONGCHROMEORDER — REMOVED from CRITICAL_RULES
     Reason: Modern Chrome (v100+) has different key ordering in
     window.chrome. The check was firing for EVERY modern Chrome user.
     It's now a "high" severity signal, not critical.

  3. STEALTHDETECTION — reclassified from critical to high (in registry)
     Reason: It was a generic catch-all signal that could fire on
     innocent browser extensions.

PHILOSOPHY (unchanged):
  - `action: "block"` fires ONLY on has_critical (impossible signals
    that no real browser can produce).
  - Score is still computed for logging/reporting.
  - Non-critical signals flow into analyze_full() at final where full
    behavior data is available.
"""
from __future__ import annotations

from typing import List

from collector.signals import (
    SIGNAL_REGISTRY,
    normalize_signal,
)


# =========================================================
# CRITICAL RULES — only these block instantly
# =========================================================
# v8.4: Removed CDP_DETECTED and WRONGCHROMEORDER (false positives).
CRITICAL_RULES = frozenset([
    # Core
    "WEBDRIVER_FLAG",
    "PUPPETEER_DETECTED",
    "PLAYWRIGHT_DETECTED",
    "SELENIUM_DETECTED",
    "NIGHTMARE_DETECTED",
    "PHANTOM_DETECTED",
    "HONEYPOT_CLICK",
    "HONEYPOT_FORM_FILL",
    "HEADLESS_UA",

    # BotD — 100% impossible signals only
    "BOTD_DETECTWEBDRIVER",
    "BOTD_DETECTPROCESS",
    "BOTD_DETECTDISTINCTIVEPROPERTIES",
    "BOTD_DETECTDOCUMENTATTRIBUTES",
    "BOTD_DETECTWINDOWEXTERNAL",
    "BOTD_DETECTAPPVERSION",
    "BOTD_DETECTUSERAGENT",

    # vi-bot — 100% impossible signals only
    "WEBDRIVER",
    "CHROMEDRIVER",
    "CDPDETECTION",
    "PHANTOMWINDOW",
    "NIGHTMAREDETECTED",
    "FAKECREATEELEMENT",
    "TOSTRINGSPOOFED",
    "STEALTHCANVAS",
    "IFRAMECHROMERUNTIME",

    # Stack traps — all impossible
    "ERRORTRAPPUPPETEER",
    "ERRORTRAPPLAYWRIGHTCHROME",
    "ERRORTRAPPLAYWRIGHTFIREFOX",
    "ERRORTRAPSELENIUMCHROME",
    "ERRORTRAPNIGHTMARE",
    "ERRORTRAPCYPRESS",
    "ERRORTRAPPATCHRIGHT",
    "ERRORTRAPPPTRURL",
    "ERRORTRAPUTILITYSCRIPT",
    "ERRORTRAPPHANTOMJS",

    # rebrowser — ONLY 100% Playwright/Puppeteer signatures
    "RB_PW_INIT_SCRIPTS",
    "RB_PW_BINDING",
    "RB_HEADLESS_UA",
    "RB_EXPOSE_FUNCTION_LEAK",
    "RB_IFRAME_REALM_SHARED",
    "RB_AUTOMATION_FRAME",
])


# =========================================================
# HELPERS
# =========================================================
def _base(code: str, default: float = 0.9) -> float:
    reg = SIGNAL_REGISTRY.get(code)
    if reg:
        try:
            return float(reg.get("base", default))
        except (ValueError, TypeError):
            return default
    return default


def _severity(code: str, default: str = "critical") -> str:
    reg = SIGNAL_REGISTRY.get(code)
    if reg:
        return str(reg.get("sev", default))
    return default


def _make_reason(code: str, detail: str = "") -> dict:
    return {
        "code": code,
        "base_strength": _base(code),
        "severity": _severity(code),
        "direction": "bot",
        "detail": detail or code,
    }


def _safe_dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _iter_botd(botd: dict) -> List[str]:
    codes: List[str] = []
    if not isinstance(botd, dict):
        return codes
    mapping = {
        "webdriver":                 "BOTD_DETECTWEBDRIVER",
        "webdriverOwn":              "BOTD_DETECTWEBDRIVER",
        "webdriverSpoofed":          "BOTD_DETECTWEBDRIVER",
        "windowSize":                "BOTD_DETECTWINDOWSIZE",
        "appVersionHeadless":        "BOTD_DETECTAPPVERSION",
        "appVersionElectron":        "BOTD_DETECTAPPVERSION",
        "userAgentPhantom":          "BOTD_DETECTUSERAGENT",
        "userAgentHeadless":         "BOTD_DETECTUSERAGENT",
        "userAgentElectron":         "BOTD_DETECTUSERAGENT",
        "pluginsArray":              "BOTD_DETECTPLUGINSARRAY",
        "languagesEmpty":            "BOTD_DETECTLANGUAGESLENGTHINCONSISTENCY",
        "webglMesa":                 "BOTD_DETECTWEBGL",
        "processRenderer":           "BOTD_DETECTPROCESS",
        "processElectron":           "BOTD_DETECTPROCESS",
        "errorTracePhantom":         "BOTD_DETECTERRORTRACE",
        "functionBind":              "BOTD_DETECTFUNCTIONBIND",
        "distinctivePhantom":        "BOTD_DETECTDISTINCTIVEPROPERTIES",
        "distinctiveNightmare":      "BOTD_DETECTDISTINCTIVEPROPERTIES",
        "documentAttributes":        "BOTD_DETECTDOCUMENTATTRIBUTES",
        "productSub":                "BOTD_DETECTPRODUCTSUB",
        "notificationPermissions":   "BOTD_DETECTNOTIFICATIONPERMISSIONS",
        "evalLength":                "BOTD_DETECTEVALLENGTHINCONSISTENCY",
        "windowExternal":            "BOTD_DETECTWINDOWEXTERNAL",
    }
    for key, code in mapping.items():
        if botd.get(key):
            codes.append(code)
    return codes


def _iter_vib(vib: dict) -> List[str]:
    codes: List[str] = []
    if not isinstance(vib, dict):
        return codes
    mapping = {
        "webdriver":             "WEBDRIVER",
        "cdpDetected":           "CDPDETECTION",
        "puppeteer":             "CDPDETECTION",
        "playwright":            "CDPDETECTION",
        "nightmare":             "NIGHTMAREDETECTED",
        "phantom":               "PHANTOMWINDOW",
        "chromeDriver":          "CHROMEDRIVER",
        "fakeCreateElement":     "FAKECREATEELEMENT",
        "toStringSpoofed":       "TOSTRINGSPOOFED",
        "stealthNotification":   "STEALTHNOTIFICATION",
        "stealthPlugins":        "STEALTHPLUGINS",
        "stealthCanvas":         "STEALTHCANVAS",
        "wrongChromeOrder":      "WRONGCHROMEORDER",
        "playwrightOrientation": "PLAYWRIGHTORIENTATION",
        "iframeChromeRuntime":   "IFRAMECHROMERUNTIME",
        "screenZero":            "SCREENZERO",
        "screenAvail":           "SCREENAVAIL",
        "colorMismatch":         "COLORMISMATCH",
        "navLanguages":          "NAVLANGUAGES",
        "navPlugins":            "NAVPLUGINS",
        "navCores":              "NAVCORES",
        "hardwareZero":          "HARDWAREZERO",
        "hardwareAbsurd":        "HARDWAREABSURD",
        "performanceZero":       "PERFORMANCEZERO",
        "timingZero":            "TIMINGZERO",
        "fontFew":               "FONTFEW",
        "hiddenScroll":          "HIDDENSCROLL",
        "noHover":               "NOHOVER",
        "webglDisabled":         "WEBGLDISABLED",
    }
    for key, code in mapping.items():
        if vib.get(key):
            codes.append(code)
    return codes


def _iter_rebrowser(rb: dict) -> List[str]:
    """rebrowser signals. Only CRITICAL_RULES ones will trigger block."""
    codes: List[str] = []
    if not isinstance(rb, dict):
        return codes

    if rb.get("pwInitScripts"):
        codes.append("RB_PW_INIT_SCRIPTS")
    if rb.get("pwBinding"):
        codes.append("RB_PW_BINDING")
    if rb.get("documentInterception"):
        codes.append("RB_DOCUMENT_INTERCEPTION")
    if rb.get("iframeRealmShared"):
        codes.append("RB_IFRAME_REALM_SHARED")
    if rb.get("headlessNoChrome"):
        codes.append("RB_HEADLESS_NO_CHROME")
    if rb.get("headlessUA"):
        codes.append("RB_HEADLESS_UA")
    if rb.get("headlessNotificationDenied") == 0.5:
        codes.append("RB_HEADLESS_NOTIF_DENIED")
    if rb.get("headless800x600") == 0.5:
        codes.append("RB_HEADLESS_800X600")
    if rb.get("mobileTouch1") == 0.5:
        codes.append("RB_MOBILE_TOUCH_1")
    if rb.get("mobileTouch0") == 0.5:
        codes.append("RB_MOBILE_TOUCH_0")
    if rb.get("mobileIOSChromium") == 0.5:
        codes.append("RB_MOBILE_IOS_CHROMIUM")
    if rb.get("activeTextMismatch") == 0.5:
        codes.append("RB_ACTIVE_TEXT_MISMATCH")

    rl = rb.get("runtimeEnableLeak")
    if rl == 1:
        codes.append("RB_RUNTIME_ENABLE_LEAK")
    elif rl == 0.7:
        codes.append("RB_RUNTIME_ENABLE_SOFT")

    sl = rb.get("sourceUrlLeak")
    if sl == 1:
        codes.append("RB_SOURCE_URL_LEAK")
    elif sl == 0.5:
        codes.append("RB_SOURCE_URL_BARE_FILE")

    if isinstance(rb.get("nativeTampered"), list) and rb.get("nativeTampered"):
        codes.append("RB_NATIVE_TAMPERED")
    if isinstance(rb.get("automationFrames"), list) and rb.get("automationFrames"):
        codes.append("RB_AUTOMATION_FRAME")
    if isinstance(rb.get("cdpBindingGlobals"), list) and rb.get("cdpBindingGlobals"):
        codes.append("RB_CDP_BINDING_GLOBALS")
    if rb.get("exposeFunctionLeak"):
        codes.append("RB_EXPOSE_FUNCTION_LEAK")

    if isinstance(rb.get("platformMismatch"), dict):
        codes.append("RB_PLATFORM_MISMATCH")

    return codes


def _iter_trap_triggers(traps: dict) -> List[str]:
    codes: List[str] = []
    if not isinstance(traps, dict):
        return codes

    for trap_name, triggered in traps.items():
        if not triggered:
            continue
        upper = str(trap_name).upper()
        candidate = upper.replace("ERRORTRAP", "ERRORTRAP").replace("_", "")
        matched = None
        for reg_code in SIGNAL_REGISTRY:
            if reg_code.startswith("ERRORTRAP") and reg_code.replace("_", "") == candidate:
                matched = reg_code
                break
        if matched:
            codes.append(matched)
    return codes


# =========================================================
# MAIN PRECHECK
# =========================================================
def quick_precheck(nav: dict, fp: dict, threshold: int = 100) -> dict:
    """
    Fast pre-check. Reads the full tracker fingerprint.

    v8.4 BEHAVIOR:
        - `action: "block"` fires ONLY on has_critical (impossible signals).
        - CDP_DETECTED and WRONGCHROMEORDER are NO LONGER critical rules
          (they were causing false positives on devs and modern Chrome).
        - Score is still computed and returned for logging/reporting.
        - Non-critical signals flow into analyze_full() at final.
    """
    nav = nav or {}
    fp = fp or {}
    reasons: List[str] = []

    # ---------------------------------------------------------
    # 1) Direct nav checks
    # ---------------------------------------------------------
    if nav.get("webdriver") is True:
        reasons.append("WEBDRIVER_FLAG")

    automation = _safe_dict(fp.get("automation"))
    if automation.get("puppeteer"):
        reasons.append("PUPPETEER_DETECTED")
    if automation.get("playwright"):
        reasons.append("PLAYWRIGHT_DETECTED")
    if automation.get("selenium") or automation.get("cdc"):
        reasons.append("SELENIUM_DETECTED")
    if automation.get("nightmare"):
        reasons.append("NIGHTMARE_DETECTED")
    if automation.get("phantom"):
        reasons.append("PHANTOM_DETECTED")

    # v8.4: cdp_detected from getCDP() is no longer critical.
    # It's still recorded as a normal bot signal (score-based).
    if fp.get("cdp_detected") is True:
        reasons.append("CDP_DETECTED")

    if fp.get("honeypot_triggered") is True or fp.get("_honeypot") is True:
        reasons.append("HONEYPOT_CLICK")

    try:
        untrusted = int(fp.get("_untrusted_clicks") or 0)
    except (ValueError, TypeError):
        untrusted = 0
    if untrusted >= 1:
        reasons.append("UNTRUSTED_CLICK")

    ua_lower = str(nav.get("ua") or "").lower()
    if "headlesschrome" in ua_lower or "headless" in ua_lower:
        reasons.append("HEADLESS_UA")

    # ---------------------------------------------------------
    # 2) BotD, vi-bot, rebrowser, traps
    # ---------------------------------------------------------
    botd = _safe_dict(fp.get("botd"))
    for code in _iter_botd(botd):
        reasons.append(code)

    vib = _safe_dict(fp.get("vib"))
    for code in _iter_vib(vib):
        reasons.append(code)

    rb = _safe_dict(fp.get("rebrowser"))
    for code in _iter_rebrowser(rb):
        reasons.append(code)

    traps = _safe_dict(fp.get("trap_triggers"))
    for code in _iter_trap_triggers(traps):
        reasons.append(code)

    # ---------------------------------------------------------
    # 3) Behavior scores (client-side)
    # ---------------------------------------------------------
    behavior = _safe_dict(fp.get("behavioral"))
    behavior_scores = behavior.get("behavior_scores") if isinstance(behavior, dict) else None
    if isinstance(behavior_scores, dict):
        try:
            if float(behavior_scores.get("mouse", 0)) >= 0.85:
                reasons.append("MOUSE_UNIFORM_VELOCITY")
            if float(behavior_scores.get("keys", 0)) >= 0.85:
                reasons.append("TYPING_TOO_UNIFORM")
            if float(behavior_scores.get("scroll", 0)) >= 0.85:
                reasons.append("SCROLL_CONSTANT_VELOCITY")
        except (ValueError, TypeError):
            pass

    # ---------------------------------------------------------
    # 4) Deduplicate
    # ---------------------------------------------------------
    seen = set()
    deduped: List[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    reasons = deduped

    # ---------------------------------------------------------
    # 5) Build normalized signals
    # ---------------------------------------------------------
    signals: List[dict] = []
    for code in reasons:
        try:
            sig = normalize_signal(
                {"code": code, "severity": _severity(code), "direction": "bot"},
                evidence_quality=0.85,
                context_multiplier=1.0,
                source_override="precheck",
            )
            signals.append(sig)
        except Exception:
            signals.append(_make_reason(code))

    # ---------------------------------------------------------
    # 6) Score (for logging/reporting only — does NOT block)
    # ---------------------------------------------------------
    has_critical = any(code in CRITICAL_RULES for code in reasons)

    score = 0
    if has_critical:
        score = 100
    elif reasons:
        total_base = sum(float(s.get("base_strength", 0.5)) for s in signals)
        score = int(min(100, max(0, total_base * 100)))

    # ---------------------------------------------------------
    # 7) Counts
    # ---------------------------------------------------------
    counts = {"impossible": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
    for s in signals:
        sev = s.get("severity", "medium")
        if sev in counts:
            counts[sev] += 1

    # ---------------------------------------------------------
    # 8) ACTION
    # ---------------------------------------------------------
    # v8.4: Only block on impossible signals. Non-critical reasons
    # are recorded but don't trigger a redirect at handshake time.
    should_block = has_critical

    return {
        "score": score,
        "reasons": reasons,
        "signals": signals,
        "action": "block" if should_block else "redirect",
        "threshold": threshold,
        "counts": counts,
        "has_critical": has_critical,
    }