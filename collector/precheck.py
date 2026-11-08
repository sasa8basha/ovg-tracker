"""
collector/precheck.py — Fast pre-check (v6.0)

Checks all signals from tracker fingerprint.detections + trap_triggers.
"""
from collector.signals import SIGNAL_REGISTRY


CRITICAL_RULES = frozenset([
    "WEBDRIVER_FLAG", "PUPPETEER_DETECTED", "PLAYWRIGHT_DETECTED",
    "SELENIUM_DETECTED", "NIGHTMARE_DETECTED", "PHANTOM_DETECTED",
    "CDP_DETECTED", "HONEYPOT_CLICK", "HONEYPOT_FORM_FILL", "HEADLESS_UA",
])


def _base(code, default=0.9):
    reg = SIGNAL_REGISTRY.get(code)
    if reg:
        try: return float(reg.get("base", default))
        except (ValueError, TypeError): return default
    return default


def _make_reason(code):
    return {"code": code, "base_strength": _base(code), "severity": "critical", "direction": "bot"}


def quick_precheck(nav: dict, fp: dict, threshold: int = 100) -> dict:
    nav = nav or {}
    fp = fp or {}
    reasons = []

    # 1) WebDriver
    if nav.get("webdriver") is True:
        reasons.append("WEBDRIVER_FLAG")

    # 2) Automation globals
    automation = fp.get("automation") or {}
    if automation.get("puppeteer"): reasons.append("PUPPETEER_DETECTED")
    if automation.get("playwright"): reasons.append("PLAYWRIGHT_DETECTED")
    if automation.get("selenium") or automation.get("cdc"): reasons.append("SELENIUM_DETECTED")
    if automation.get("nightmare"): reasons.append("NIGHTMARE_DETECTED")
    if automation.get("phantom"): reasons.append("PHANTOM_DETECTED")

    # 3) CDP
    if fp.get("cdp_detected") is True:
        reasons.append("CDP_DETECTED")

    # 4) Honeypot
    if fp.get("_honeypot") is True or fp.get("honeypot_triggered") is True:
        reasons.append("HONEYPOT_CLICK")

    # 5) Untrusted clicks
    try: untrusted = int(fp.get("_untrusted_clicks") or 0)
    except (ValueError, TypeError): untrusted = 0
    if untrusted >= 1: reasons.append("UNTRUSTED_CLICK")

    # 6) Headless UA
    ua = str(nav.get("ua") or "").lower()
    if "headlesschrome" in ua or "headless" in ua:
        reasons.append("HEADLESS_UA")

    # 7) All 46 detections from vi-bot + BotD
    detections = fp.get("detections") or {}
    if isinstance(detections, dict):
        for det_name, det_val in detections.items():
            if not det_val: continue
            if isinstance(det_val, (int, float)) and det_val >= 0.5:
                code = det_name.upper().replace("DETECT", "DETECT")
                if code not in SIGNAL_REGISTRY:
                    code = "BOTD_" + code if det_name.startswith("detect") else code
                reasons.append(code)
            elif isinstance(det_val, str):
                # Bot kind (e.g. "headless_chrome", "phantomjs")
                code = "BOTD_" + det_name.upper().replace("DETECT", "DETECT")
                reasons.append(code)

    # 8) Stack trace traps (any trap triggered = automation)
    trap_triggers = fp.get("trap_triggers") or {}
    if isinstance(trap_triggers, dict):
        for trap_name in trap_triggers:
            reasons.append(trap_name.upper())

    # 9) Behavior scores
    behavior = fp.get("behavioral") or {}
    behavior_scores = behavior.get("behavior_scores") if isinstance(behavior, dict) else None
    if isinstance(behavior_scores, dict):
        if behavior_scores.get("mouse", 0) >= 0.7: reasons.append("MOUSE_UNIFORM_VELOCITY")
        if behavior_scores.get("keys", 0) >= 0.7: reasons.append("TYPING_TOO_UNIFORM")
        if behavior_scores.get("scroll", 0) >= 0.7: reasons.append("SCROLL_CONSTANT_VELOCITY")
        if behavior_scores.get("interaction", 0) >= 0.7: reasons.append("NO_MOUSE_NO_TOUCH")

    score = 100 if reasons else 0
    signals = [_make_reason(c) for c in reasons if c in CRITICAL_RULES or c.startswith("BOTD_") or c.startswith("ERRORTRAP_") or c.startswith("VI-")]
    should_block = score > 0 and score >= threshold

    return {
        "score": score,
        "reasons": reasons,
        "signals": signals,
        "action": "block" if should_block else "redirect",
        "threshold": threshold,
    }