"""
collector/signals.py — Signal Registry & Normalization (v6.0)

46 detections from BotD + vi-bot + HoneypotTraps + StackTraceTraps.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional


SEVERITY_BASE = {"impossible": 0.99, "critical": 0.90, "high": 0.75, "medium": 0.50, "low": 0.25, "human": 0.65}


SIGNAL_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ============ AUTOMATION / BOT FLAGS (impossible 100%) ============
    "WEBDRIVER_FLAG":            {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CDP_DETECTED":              {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PUPPETEER_DETECTED":        {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PLAYWRIGHT_DETECTED":       {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "SELENIUM_DETECTED":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "NIGHTMARE_DETECTED":        {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PHANTOM_DETECTED":          {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "HEADLESS_UA":               {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "ua"},
    "UNTRUSTED_CLICK":           {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "behavior"},
    "HONEYPOT_CLICK":            {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "honeypot"},
    "HONEYPOT_FORM_FILL":        {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "honeypot"},

    # ============ PHYSICAL CONTRADICTIONS (impossible) ============
    "WINDOWS_UA_LINUX_PLATFORM":  {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "os"},
    "MACOS_UA_WINDOWS_PLATFORM":  {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "os"},
    "FIREFOX_CHROME_OBJ":         {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "browser"},
    "SAFARI_CHROME_OBJ":          {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "browser"},
    "IOS_USER_AGENT_DATA":        {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "browser"},
    "MOBILE_NO_TOUCH":            {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "hardware"},
    "SEC_CH_UA_PLATFORM_MISMATCH":{"base": 0.96, "dir": "bot", "sev": "impossible", "cat": "headers"},
    "SEC_CH_UA_MOBILE_MISMATCH":  {"base": 0.92, "dir": "bot", "sev": "impossible", "cat": "headers"},
    "IPHONE_WIDE_SCREEN":         {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "screen"},
    "MOBILE_4K_SCREEN":           {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "screen"},
    "AVAIL_GREATER_THAN_SCREEN":  {"base": 0.96, "dir": "bot", "sev": "impossible", "cat": "screen"},
    "VIEWPORT_2X_SCREEN":         {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "screen"},
    "CLICK_NO_MOUSE_DESKTOP":     {"base": 0.92, "dir": "bot", "sev": "impossible", "cat": "behavior"},
    "INTERACTION_BEFORE_PAINT":   {"base": 0.90, "dir": "bot", "sev": "impossible", "cat": "temporal"},
    "CHROME_LOW_WITH_UA_DATA":    {"base": 0.94, "dir": "bot", "sev": "impossible", "cat": "browser"},

    # ============ BOTD DETECTIONS ============
    "BOTD_DETECTWEBDRIVER":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_DETECTWINDOWSIZE":         {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_DETECTAPPVERSION":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "ua"},
    "BOTD_DETECTUSERAGENT":          {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "ua"},
    "BOTD_DETECTPLUGINSARRAY":       {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "fingerprint"},
    "BOTD_DETECTLANGUAGESLENGTHINCONSISTENCY": {"base": 0.95, "dir": "bot", "sev": "critical", "cat": "fingerprint"},
    "BOTD_DETECTWEBGL":              {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "webgl"},
    "BOTD_DETECTPROCESS":            {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_DETECTERRORTRACE":         {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_DETECTFUNCTIONBIND":       {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_DETECTDISTINCTIVEPROPERTIES": {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_DETECTDOCUMENTATTRIBUTES":  {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_DETECTPRODUCTSUB":          {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "ua"},
    "BOTD_DETECTNOTIFICATIONPERMISSIONS": {"base": 0.90, "dir": "bot", "sev": "critical", "cat": "automation"},
    "BOTD_DETECTEVALLENGTHINCONSISTENCY": {"base": 0.95, "dir": "bot", "sev": "critical", "cat": "automation"},
    "BOTD_DETECTWINDOWEXTERNAL":      {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},

    # ============ VI-BOT DETECTIONS ============
    "WEBDRIVER":             {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CHROMEDRIVER":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CDPDETECTION":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PHANTOMWINDOW":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "NIGHTMAREDETECTED":     {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "FAKECREATEELEMENT":     {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "TOSTRINGSPOOFED":       {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "STEALTHDETECTION":      {"base": 0.92, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "WRONGCHROMEORDER":      {"base": 0.90, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PLAYWRIGHTORIENTATION": {"base": 0.85, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "IFRAMECHROMERUNTIME":   {"base": 0.90, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CANVASFINGERPRINT":     {"base": 0.70, "dir": "bot", "sev": "high",       "cat": "fingerprint"},
    "AUDIOFINGERPRINT":      {"base": 0.60, "dir": "bot", "sev": "medium",     "cat": "fingerprint"},
    "WEBGLFINGERPRINT":      {"base": 0.75, "dir": "bot", "sev": "high",       "cat": "webgl"},
    "SCREENANOMALIES":       {"base": 0.70, "dir": "bot", "sev": "high",       "cat": "screen"},
    "NAVIGATORINCONSISTENCIES": {"base": 0.65, "dir": "bot", "sev": "high",    "cat": "fingerprint"},
    "HARDWARECONCURRENCY":   {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "hardware"},
    "PERFORMANCEANOMALIES":  {"base": 0.60, "dir": "bot", "sev": "medium",     "cat": "performance"},
    "TIMINGANOMALIES":       {"base": 0.65, "dir": "bot", "sev": "high",       "cat": "performance"},
    "FONTENUMERATION":       {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "fingerprint"},
    "FINGERPRINTCONSISTENCY": {"base": 0.65, "dir": "bot", "sev": "high",      "cat": "fingerprint"},
    "HIDDENSCROLL":          {"base": 0.50, "dir": "bot", "sev": "medium",     "cat": "behavior"},
    "NOHOVERMQ":             {"base": 0.45, "dir": "bot", "sev": "medium",     "cat": "behavior"},
    "WEBGLDISABLED":         {"base": 0.40, "dir": "bot", "sev": "medium",     "cat": "webgl"},

    # ============ STACK TRACE TRAPS ============
    "ERRORTRAPPHANTOMJS":       {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPUPPETEER":       {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPLAYWRIGHTCHROME":{"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPLAYWRIGHTFIREFOX":{"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPLAYWRIGHTWEBKIT": {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPSELENIUMCHROME":  {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPNIGHTMARE":       {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPCYPRESS":         {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPATCHRIGHT":      {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},

    # ============ CRITICAL / HIGH ============
    "CHROME_MISSING_SEC_CH_UA":   {"base": 0.85, "dir": "bot", "sev": "critical", "cat": "headers"},
    "UA_BRANDS_MISMATCH":         {"base": 0.82, "dir": "bot", "sev": "critical", "cat": "headers"},
    "FIREFOX_SEC_CH_UA":          {"base": 0.85, "dir": "bot", "sev": "critical", "cat": "headers"},
    "SAFARI_SEC_CH_UA":           {"base": 0.85, "dir": "bot", "sev": "critical", "cat": "headers"},
    "SPEECH_ZERO_CHROME_DESKTOP": {"base": 0.80, "dir": "bot", "sev": "critical", "cat": "fingerprint"},
    "DESKTOP_NO_INPUT_LONG":      {"base": 0.82, "dir": "bot", "sev": "critical", "cat": "behavior"},
    "BOT_UA":                     {"base": 0.75, "dir": "bot", "sev": "high", "cat": "ua"},
    "VPN_DATACENTER":             {"base": 0.72, "dir": "bot", "sev": "high", "cat": "network"},
    "WEBRTC_LEAK":                {"base": 0.75, "dir": "bot", "sev": "high", "cat": "network"},
    "ROBOTIC_LINEAR":             {"base": 0.60, "dir": "bot", "sev": "high", "cat": "behavior"},
    "MOUSE_UNIFORM_VELOCITY":     {"base": 0.65, "dir": "bot", "sev": "high", "cat": "behavior"},
    "MOUSE_PERFECTLY_STRAIGHT":   {"base": 0.70, "dir": "bot", "sev": "high", "cat": "behavior"},
    "TYPING_TOO_FAST":            {"base": 0.70, "dir": "bot", "sev": "high", "cat": "behavior"},
    "TYPING_TOO_UNIFORM":         {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "SCROLL_CONSTANT_VELOCITY":   {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "SCROLL_NO_HUMAN_PATTERN":    {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "HEARTBEAT_TOO_REGULAR":      {"base": 0.70, "dir": "bot", "sev": "high", "cat": "session"},
    "HEARTBEAT_PERFECT_TIMING":   {"base": 0.75, "dir": "bot", "sev": "high", "cat": "session"},
    "SILENT_AFTER_INITIAL":       {"base": 0.70, "dir": "bot", "sev": "high", "cat": "session"},
    "NO_MOUSE_NO_TOUCH":          {"base": 0.65, "dir": "bot", "sev": "high", "cat": "behavior"},

    # ============ HUMAN SIGNALS ============
    "HUMAN_NATURAL_MOUSE":        {"base": 0.65, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_SCROLL_PHYSICS":       {"base": 0.60, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_TYPING_RHYTHM":        {"base": 0.65, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_RICH_INTERACTION":     {"base": 0.70, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_LONG_ENGAGEMENT":      {"base": 0.55, "dir": "human", "sev": "human", "cat": "human"},
}


def _sev_from_registry(code, fallback="medium"):
    e = SIGNAL_REGISTRY.get(code)
    return str(e.get("sev", fallback)) if e else fallback

def _base_from_registry(code, fallback=0.5):
    e = SIGNAL_REGISTRY.get(code)
    try: return float(e.get("base", fallback)) if e else fallback
    except (ValueError, TypeError): return fallback

def _dir_from_registry(code, fallback="bot"):
    e = SIGNAL_REGISTRY.get(code)
    return str(e.get("dir", fallback)) if e else fallback

def _cat_from_registry(code, fallback="unknown"):
    e = SIGNAL_REGISTRY.get(code)
    return str(e.get("cat", fallback)) if e else fallback


def normalize_signal(raw, *, evidence_quality=0.7, context_multiplier=1.0, source_override=None):
    if not isinstance(raw, dict):
        raw = {}
    code = str(raw.get("code") or "UNKNOWN").strip().upper()
    detail = str(raw.get("detail") or "")[:200]
    direction = str(raw.get("direction") or "").lower().strip()
    if direction not in ("bot", "human"):
        direction = _dir_from_registry(code, "bot")
    severity = str(raw.get("severity") or "").lower().strip()
    if not severity:
        severity = _sev_from_registry(code, "medium")
    if severity not in ("impossible", "critical", "high", "medium", "low", "human"):
        severity = "medium"
    category = str(raw.get("category") or "").strip() or _cat_from_registry(code, "unknown")
    source = source_override or str(raw.get("source") or "").strip() or "unknown"
    base = raw.get("base_strength")
    try:
        base_f = float(base) if base is not None else _base_from_registry(code)
    except (ValueError, TypeError):
        base_f = _base_from_registry(code)
    base_f = max(0.0, min(1.0, base_f))
    try: eq = float(evidence_quality)
    except (ValueError, TypeError): eq = 0.7
    eq = max(0.05, min(1.0, eq))
    try: cm = float(context_multiplier)
    except (ValueError, TypeError): cm = 1.0
    cm = max(0.0, min(2.5, cm))
    strength = max(0.0, min(1.0, base_f * eq * cm))
    return {
        "code": code, "category": category, "source": source,
        "direction": direction, "severity": severity,
        "base_strength": round(base_f, 4), "evidence_quality": round(eq, 4),
        "context_multiplier": round(cm, 3), "strength": round(strength, 4),
        "detail": detail,
    }


def normalize_signals(raw_signals, *, evidence_quality=0.7, context_multiplier=1.0, source_override=None):
    if not raw_signals: return []
    seen = {}
    for raw in raw_signals:
        try:
            norm = normalize_signal(raw, evidence_quality=evidence_quality, context_multiplier=context_multiplier, source_override=source_override)
        except Exception:
            continue
        existing = seen.get(norm["code"])
        if existing is None or norm["strength"] > existing["strength"]:
            seen[norm["code"]] = norm
    return list(seen.values())


def has_impossible(signals):
    return any(s.get("severity") == "impossible" for s in signals if isinstance(s, dict))

def strongest_bot(signals):
    bots = [s for s in (signals or []) if isinstance(s, dict) and s.get("direction") == "bot"]
    return max(bots, key=lambda s: float(s.get("strength", 0))) if bots else None

def strongest_human(signals):
    humans = [s for s in (signals or []) if isinstance(s, dict) and s.get("direction") == "human"]
    return max(humans, key=lambda s: float(s.get("strength", 0))) if humans else None