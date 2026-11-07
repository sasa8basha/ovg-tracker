"""
precheck.py — Fast pre-check rules (Phase 1.3)

هدفها: قرار في أقل من 100ms قبل redirect لـ Adsterra.
قواعد critical فقط — أي شك → redirect (سيف).

الفلسفة: False Positive أغلى من False Negative، فبنحظر بس اللي مؤكد 100%.
"""

from collector.constants import (
    SIG_WEBDRIVER, SIG_CDP_DETECTED,
    SIG_PUPPETEER, SIG_PLAYWRIGHT, SIG_SELENIUM,
    SIG_NIGHTMARE, SIG_PHANTOM,
    SIG_HONEYPOT_CLICK,
)


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
])


def quick_precheck(nav: dict, fp: dict, threshold: int = 100) -> dict:
    """
    فحص سريع جداً — قواعد critical فقط.

    Returns:
        {
            "score": 0-100,
            "reasons": [...],
            "action": "block" | "redirect",
            "threshold": int,
        }
    """
    nav = nav or {}
    fp = fp or {}
    score = 0
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

    # 4) Honeypot (لو الـ JS بعتها)
    if fp.get("_honeypot") is True:
        reasons.append("HONEYPOT_CLICK")

    if reasons:
        score = 100

    should_block = score > 0 and score >= threshold

    return {
        "score": score,
        "reasons": reasons,
        "action": "block" if should_block else "redirect",
        "threshold": threshold,
  }
