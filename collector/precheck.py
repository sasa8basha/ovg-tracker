"""
collector/precheck.py — Fast pre-check rules (v8.0)

Purpose: sub-100ms decision before redirect to Adsterra.
Reads the full `fp` dict from the tracker payload (botd, vib, rebrowser,
trap_triggers, honeypot_triggered) plus the classic nav checks.

Philosophy: False Positive costs more than False Negative here.
We only block on:
    - Impossible / critical signals (webdriver, puppeteer, patchright, ...)
    - Multiple high-severity signals

Anything ambiguous → redirect (safe default).
"""
from __future__ import annotations

from typing import List

from collector.signals import (
    SIGNAL_REGISTRY,
    normalize_signal,
)


# =========================================================
# CRITICAL RULES — any of these → instant block
# =========================================================
CRITICAL_RULES = frozenset([
    "WEBDRIVER_FLAG",
    "PUPPETEER_DETECTED",
    "PLAYWRIGHT_DETECTED",
    "SELENIUM_DETECTED",
    "NIGHTMARE_DETECTED",
    "PHANTOM_DETECTED",
    "CDP_DETECTED",
    "HONEYPOT_CLICK",
    "HONEYPOT_FORM_FILL",
    "HEADLESS_UA",
    # BotD / vi-bot
    "BOTD_DETECTWEBDRIVER",
    "BOTD_DETECTPROCESS",
    "BOTD_DETECTDISTINCTIVEPROPERTIES",
    "BOTD_DETECTDOCUMENTATTRIBUTES",
    "BOTD_DETECTWINDOWEXTERNAL",
    "WEBDRIVER",
    "CHROMEDRIVER",
    "CDPDETECTION",
    "PHANTOMWINDOW",
    "NIGHTMAREDETECTED",
    "FAKECREATEELEMENT",
    "TOSTRINGSPOOFED",
    "STEALTHDETECTION",
    "WRONGCHROMEORDER",
    "IFRAMECHROMERUNTIME",
    # Stack traps
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
    # rebrowser
    "RB_PW_INIT_SCRIPTS",
    "RB_PW_BINDING",
    "RB_DOCUMENT_INTERCEPTION",
    "RB_IFRAME_REALM_SHARED",
    "RB_HEADLESS_UA",
    "RB_EXPOSE_FUNCTION_LEAK",
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
    """Yield signal codes triggered by BotD detectors."""
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
    """Yield signal codes triggered by vi-bot detectors."""
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
    """Yield signal codes triggered by rebrowser-bot-detector tests."""
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
    if isinstance(rb.get("navOwnProps"), list) and rb.get("navOwnProps"):
        codes.append("RB_NAV_OWN_PROPS")
    if isinstance(rb.get("platformMismatch"), dict):
        codes.append("RB_PLATFORM_MISMATCH")

    return codes


def _iter_trap_triggers(traps: dict) -> List[str]:
    """Yield signal codes for fired stack-trace traps."""
    codes: List[str] = []
    if not isinstance(traps, dict):
        return codes

    for trap_name, triggered in traps.items():
        if not triggered:
            continue
        upper = str(trap_name).upper()
        candidate = upper.replace("ERRortrap", "ERRORTRAP").replace("_", "")
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

    Returns:
        {
            "score": 0-100,
            "reasons": [code, ...],
            "signals": [{code, base_strength, severity, direction}, ...],
            "action": "block" | "redirect",
            "threshold": int,
            "counts": {"impossible": int, "critical": int, "high": int, ...},
        }
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

    if fp.get("cdp_detected") is True:
        reasons.append("CDP_DETECTED")

    # Honeypot (top-level flag on fingerprint)
    if fp.get("honeypot_triggered") is True or fp.get("_honeypot") is True:
        reasons.append("HONEYPOT_CLICK")

    # Untrusted JS-injected clicks
    try:
        untrusted = int(fp.get("_untrusted_clicks") or 0)
    except (ValueError, TypeError):
        untrusted = 0
    if untrusted >= 1:
        reasons.append("UNTRUSTED_CLICK")

    # Headless UA in the nav payload
    ua_lower = str(nav.get("ua") or "").lower()
    if "headlesschrome" in ua_lower or "headless" in ua_lower:
        reasons.append("HEADLESS_UA")

    # ---------------------------------------------------------
    # 2) BotD detectors (18)
    # ---------------------------------------------------------
    botd = _safe_dict(fp.get("botd"))
    for code in _iter_botd(botd):
        reasons.append(code)

    # ---------------------------------------------------------
    # 3) vi-bot detectors (28)
    # ---------------------------------------------------------
    vib = _safe_dict(fp.get("vib"))
    for code in _iter_vib(vib):
        reasons.append(code)

    # ---------------------------------------------------------
    # 4) rebrowser-bot-detector tests (22)
    # ---------------------------------------------------------
    rb = _safe_dict(fp.get("rebrowser"))
    for code in _iter_rebrowser(rb):
        reasons.append(code)

    # ---------------------------------------------------------
    # 5) Stack trace traps (vi-bot style)
    # ---------------------------------------------------------
    traps = _safe_dict(fp.get("trap_triggers"))
    for code in _iter_trap_triggers(traps):
        reasons.append(code)

    # ---------------------------------------------------------
    # 6) Behavior scores (client-side quick check)
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
    # 7) Deduplicate reasons (keep first occurrence)
    # ---------------------------------------------------------
    seen = set()
    deduped: List[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    reasons = deduped

    # ---------------------------------------------------------
    # 8) Build normalized signals
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
    # 9) Score computation
    # ---------------------------------------------------------
    # Any critical rule → instant 100
    has_critical = any(code in CRITICAL_RULES for code in reasons)

    score = 0
    if has_critical:
        score = 100
    elif reasons:
        # Sum of base strengths, capped at 100, but any reasons list is
        # already significant — so minimum floor of 30
        total_base = sum(float(s.get("base_strength", 0.5)) for s in signals)
        score = int(min(100, max(30, total_base * 100)))

    # ---------------------------------------------------------
    # 10) Count by severity (for debugging / logging)
    # ---------------------------------------------------------
    counts = {"impossible": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0}
    for s in signals:
        sev = s.get("severity", "medium")
        if sev in counts:
            counts[sev] += 1

    should_block = score > 0 and score >= threshold

    return {
        "score": score,
        "reasons": reasons,
        "signals": signals,
        "action": "block" if should_block else "redirect",
        "threshold": threshold,
        "counts": counts,
    }