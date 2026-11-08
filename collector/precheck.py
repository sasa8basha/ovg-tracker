"""
collector/precheck.py — Fast pre-check rules (v4.0)

Purpose: sub-100ms decision before redirect to Adsterra.
Only CRITICAL rules — anything ambiguous → redirect (safe default).

Philosophy: False Positive costs more than False Negative here.
We only block when we're 100% certain.

Fixes over v3.2:
  - Corrected indentation bug in return dict (v3.2 had syntax error)
  - Signals now carry direction + base_strength for consistency
  - Reasons preserved as list of codes (backward compat)
  - INTEGRATED BotD client-side detections
"""
from collector.signals import SIGNAL_REGISTRY


# =========================================================
# CRITICAL RULES — triggers immediate block
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


def _make_reason(code: str) -> dict:
    return {
        "code": code,
        "base_strength": _base(code),
        "severity": "critical",
        "direction": "bot",
    }


# =========================================================
# MAIN PRECHECK
# =========================================================
def quick_precheck(nav: dict, fp: dict, threshold: int = 100) -> dict:
    """
    Fast pre-check. Only critical rules.

    Returns:
        {
            "score": 0-100,
            "reasons": [code, ...],       # legacy compat
            "signals": [{code, ...}, ...] # new, for consistency
            "action": "block" | "redirect",
            "threshold": int,
        }
    """
    nav = nav or {}
    fp = fp or {}
    reasons = []

    # 1) WebDriver flag
    if nav.get("webdriver") is True:
        reasons.append("WEBDRIVER_FLAG")

    # 2) Automation globals
    automation = fp.get("automation") or {}
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

    # 3) CDP detection
    if fp.get("cdp_detected") is True:
        reasons.append("CDP_DETECTED")

    # 4) Honeypot
    if fp.get("_honeypot") is True:
        reasons.append("HONEYPOT_CLICK")

    # 5) Untrusted clicks
    try:
        untrusted = int(fp.get("_untrusted_clicks") or 0)
    except (ValueError, TypeError):
        untrusted = 0
    if untrusted >= 1:
        reasons.append("UNTRUSTED_CLICK")

    # 6) Headless UA
    ua = str(nav.get("ua") or "").lower()
    if "headlesschrome" in ua or "headless" in ua:
        reasons.append("HEADLESS_UA")

    # 7) BotD Client-Side Detections (أقوى وأسرع كشف)
    botd = fp.get("botd") or {}
    if isinstance(botd, dict):
        for detector_name, bot_kind in botd.items():
            if bot_kind:  # لو فيه أي كشف
                # تحويل اسم الدالة لحاجة تشبه الكود (detectWebDriver -> BOTD_WEBDRIVER)
                code = f"BOTD_{detector_name.replace('detect', '').upper()}"
                reasons.append(code)

    # Build score
    score = 100 if reasons else 0
    signals = [_make_reason(code) for code in reasons if code in CRITICAL_RULES or code.startswith("BOTD_")]

    should_block = score > 0 and score >= threshold

    return {
        "score": score,
        "reasons": reasons,
        "signals": signals,
        "action": "block" if should_block else "redirect",
        "threshold": threshold,
    }