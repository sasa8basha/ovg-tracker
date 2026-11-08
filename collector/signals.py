"""
collector/signals.py — Signal Registry & Normalization.

Every signal — from any source (analysis, headers, temporal, behavior,
contradiction, fingerprint cache, botd) — MUST be normalized through this
module before it enters the fusion layer.

Canonical signal shape (produced by normalize_signal):
    {
        "code": str,                  # e.g. "WEBDRIVER_FLAG"
        "category": str,              # "automation" | "network" | "behavior" | ...
        "source": str,                # which collector produced it
        "direction": "bot" | "human",
        "severity": str,              # impossible|critical|high|medium|low|human
        "base_strength": float,       # 0..1 — signal's intrinsic weight
        "evidence_quality": float,    # 0..1 — how strong is the evidence
        "context_multiplier": float,  # >= 1.0 boost when context supports it
        "strength": float,            # final = base * quality * multiplier
        "detail": str,                # human-readable explanation
    }
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


# =========================================================
# SEVERITY → BASE STRENGTH MAP
# Used when a caller only supplies a severity and no explicit base.
# =========================================================
SEVERITY_BASE = {
    "impossible": 0.99,
    "critical":   0.90,
    "high":       0.75,
    "medium":     0.50,
    "low":        0.25,
    "human":      0.65,
}


# =========================================================
# SIGNAL REGISTRY
# Every known signal code → {base_strength, direction, severity, category}
# =========================================================
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

    # ============ IMPOSSIBLE PHYSICAL CONTRADICTIONS ============
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

    # ============ BOTD CLIENT-SIDE DETECTIONS (FingerprintJS) ============
    "BOTD_WEBDRIVER":               {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_WINDOW_SIZE":             {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_APP_VERSION":             {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "ua"},
    "BOTD_USER_AGENT":              {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "ua"},
    "BOTD_PLUGINS_ARRAY":           {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "fingerprint"},
    "BOTD_LANGUAGES_INCONSISTENCY": {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "fingerprint"},
    "BOTD_WEBGL":                   {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "webgl"},
    "BOTD_PROCESS":                 {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_ERROR_TRACE":             {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_FUNCTION_BIND":           {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_DISTINCTIVE_PROPS":       {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_DOCUMENT_ATTRIBUTES":     {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_PRODUCT_SUB":             {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "ua"},
    "BOTD_NOTIFICATION_PERM":       {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_EVAL_LENGTH":             {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_WINDOW_EXTERNAL":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_MIME_TYPES":              {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "fingerprint"},
    "BOTD_RTT":                     {"base": 0.85, "dir": "bot", "sev": "high",       "cat": "network"},

    # ============ CRITICAL ============
    "CHROME_MISSING_SEC_CH_UA":   {"base": 0.85, "dir": "bot", "sev": "critical", "cat": "headers"},
    "UA_BRANDS_MISMATCH":         {"base": 0.82, "dir": "bot", "sev": "critical", "cat": "headers"},
    "FIREFOX_SEC_CH_UA":          {"base": 0.85, "dir": "bot", "sev": "critical", "cat": "headers"},
    "SAFARI_SEC_CH_UA":           {"base": 0.85, "dir": "bot", "sev": "critical", "cat": "headers"},
    "CHROME_HTTP_1_0":            {"base": 0.82, "dir": "bot", "sev": "critical", "cat": "headers"},
    "SPEECH_ZERO_CHROME_DESKTOP": {"base": 0.80, "dir": "bot", "sev": "critical", "cat": "fingerprint"},
    "DESKTOP_NO_INPUT_LONG":      {"base": 0.82, "dir": "bot", "sev": "critical", "cat": "behavior"},
    "IP_TZ_LANG_TRIPLE_MISMATCH": {"base": 0.82, "dir": "bot", "sev": "critical", "cat": "locale"},
    "IDLE_VISIBLE_LONG":          {"base": 0.78, "dir": "bot", "sev": "critical", "cat": "behavior"},
    "WEBGL2_NO_WEBGL1":           {"base": 0.78, "dir": "bot", "sev": "critical", "cat": "webgl"},

    # ============ HIGH ============
    "BOT_UA":                     {"base": 0.75, "dir": "bot", "sev": "high", "cat": "ua"},
    "VPN_DATACENTER":             {"base": 0.72, "dir": "bot", "sev": "high", "cat": "network"},
    "DATACENTER_ASN":             {"base": 0.70, "dir": "bot", "sev": "high", "cat": "network"},
    "WEBRTC_LEAK":                {"base": 0.75, "dir": "bot", "sev": "high", "cat": "network"},
    "PLUGINS_ZERO":               {"base": 0.55, "dir": "bot", "sev": "high", "cat": "fingerprint"},
    "CHROME_NO_OBJ":              {"base": 0.55, "dir": "bot", "sev": "high", "cat": "fingerprint"},
    "CANVAS_MISSING":             {"base": 0.55, "dir": "bot", "sev": "high", "cat": "fingerprint"},
    "SPEECH_VOICES_ZERO":         {"base": 0.65, "dir": "bot", "sev": "high", "cat": "fingerprint"},
    "WEBGL_PRECISION_ZERO":       {"base": 0.55, "dir": "bot", "sev": "high", "cat": "webgl"},
    "FINGERPRINT_REUSE_HIGH":     {"base": 0.80, "dir": "bot", "sev": "high", "cat": "fingerprint_reuse"},
    "FINGERPRINT_MULTI_IP":       {"base": 0.65, "dir": "bot", "sev": "high", "cat": "cross_visit"},
    "IP_MULTI_FINGERPRINT":       {"base": 0.70, "dir": "bot", "sev": "high", "cat": "cross_visit"},
    "IP_VELOCITY_HIGH":           {"base": 0.70, "dir": "bot", "sev": "high", "cat": "cross_visit"},
    "FINGERPRINT_KNOWN_BAD":      {"base": 0.90, "dir": "bot", "sev": "high", "cat": "fingerprint_cache"},
    "FINGERPRINT_SUSPICIOUS":     {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "fingerprint_cache"},
    "HEADLESS_VIEWPORT":          {"base": 0.70, "dir": "bot", "sev": "high", "cat": "screen"},
    "ROBOTIC_LINEAR":             {"base": 0.60, "dir": "bot", "sev": "high", "cat": "behavior"},
    "ROBOTIC_CURVATURE":          {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "CLICK_BEFORE_MOVE":          {"base": 0.65, "dir": "bot", "sev": "high", "cat": "behavior"},
    "MOUSE_UNIFORM_VELOCITY":     {"base": 0.65, "dir": "bot", "sev": "high", "cat": "behavior"},
    "MOUSE_PERFECTLY_STRAIGHT":   {"base": 0.70, "dir": "bot", "sev": "high", "cat": "behavior"},
    "MOUSE_NO_TREMOR":            {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "MOUSE_ABNORMAL_ACCELERATION":{"base": 0.45, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "MOUSE_TOO_SMOOTH":           {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "MOUSE_TELEPORT":             {"base": 0.60, "dir": "bot", "sev": "high", "cat": "behavior"},
    "TYPING_TOO_FAST":            {"base": 0.70, "dir": "bot", "sev": "high", "cat": "behavior"},
    "TYPING_TOO_UNIFORM":         {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "SCROLL_CONSTANT_VELOCITY":   {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "SCROLL_NO_HUMAN_PATTERN":    {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "SCROLL_LINEAR":              {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "SCROLL_NO_WHEEL_DESKTOP":    {"base": 0.60, "dir": "bot", "sev": "high", "cat": "behavior"},
    "HEARTBEAT_TOO_REGULAR":      {"base": 0.70, "dir": "bot", "sev": "high", "cat": "session"},
    "HEARTBEAT_TOO_ERRATIC":      {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "session"},
    "HEARTBEAT_PERFECT_TIMING":   {"base": 0.75, "dir": "bot", "sev": "high", "cat": "session"},
    "ENGAGEMENT_COLLAPSE":        {"base": 0.55, "dir": "bot", "sev": "high", "cat": "session"},
    "HEARTBEAT_BEYOND_SESSION":   {"base": 0.65, "dir": "bot", "sev": "high", "cat": "session"},
    "SILENT_AFTER_INITIAL":       {"base": 0.70, "dir": "bot", "sev": "high", "cat": "session"},
    "ENGAGEMENT_ZERO":            {"base": 0.60, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "ENGAGEMENT_VERY_LOW":        {"base": 0.40, "dir": "bot", "sev": "low", "cat": "behavior"},
    "NO_MOUSE_NO_TOUCH":          {"base": 0.65, "dir": "bot", "sev": "high", "cat": "behavior"},
    "ABSURD_CPU_MEMORY":          {"base": 0.65, "dir": "bot", "sev": "high", "cat": "hardware"},
    "ABSURD_HARDWARE_4K":         {"base": 0.55, "dir": "bot", "sev": "high", "cat": "hardware"},
    "MOBILE_HIGH_MEMORY":         {"base": 0.65, "dir": "bot", "sev": "high", "cat": "hardware"},
    "MOBILE_PIXEL_RATIO_1":       {"base": 0.50, "dir": "bot", "sev": "high", "cat": "hardware"},
    "WEBGL_VENDOR_NO_RENDERER":   {"base": 0.55, "dir": "bot", "sev": "high", "cat": "webgl"},
    "WEBGL_NO_VENDOR":            {"base": 0.55, "dir": "bot", "sev": "high", "cat": "webgl"},
    "SESSION_END_BEFORE_START":   {"base": 0.55, "dir": "bot", "sev": "high", "cat": "session"},
    "ACCEPT_LANGUAGE_JS_MISMATCH":{"base": 0.55, "dir": "bot", "sev": "high", "cat": "headers"},
    "RAPID_REPEAT_CLICKS":        {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "INSTANT_FIRST_MOVE":         {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "IDLE_VISIBLE":               {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "AD_HIDDEN_AFTER_LOAD":       {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "ad_events"},
    "DRIVE_BY":                   {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "session"},
    "TAB_NEVER_FOCUSED":          {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "session"},

    # ============ MEDIUM / LOW ============
    "DATACENTER_IP":              {"base": 0.55, "dir": "bot", "sev": "high",   "cat": "network"},
    "VPN_PROXY":                  {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "network"},
    "WEBRTC_VPN_DIFF":            {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "network"},
    "LANGUAGES_EMPTY":            {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "fingerprint"},
    "SINGLE_LANG":                {"base": 0.12, "dir": "bot", "sev": "low",    "cat": "fingerprint"},
    "NO_MIME_TYPES":              {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "fingerprint"},
    "NO_PDF_VIEWER":              {"base": 0.15, "dir": "bot", "sev": "low",    "cat": "fingerprint"},
    "FINGERPRINT_REUSE_MED":      {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "fingerprint_reuse"},
    "FINGERPRINT_REUSE_LOW":      {"base": 0.25, "dir": "bot", "sev": "low",    "cat": "fingerprint_reuse"},
    "IP_VELOCITY_MED":            {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "cross_visit"},
    "CORES_ZERO":                 {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "hardware"},
    "CORES_LOW":                  {"base": 0.15, "dir": "bot", "sev": "low",    "cat": "hardware"},
    "LOW_MEMORY":                 {"base": 0.15, "dir": "bot", "sev": "low",    "cat": "hardware"},
    "CPU_MEMORY_MISMATCH":        {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "hardware"},
    "MOBILE_PIXEL_RATIO":         {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "hardware"},
    "LOW_COLOR_DEPTH":            {"base": 0.20, "dir": "bot", "sev": "low",    "cat": "hardware"},
    "VIEWPORT_ZERO":              {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "screen"},
    "MOBILE_WIDE_SCREEN":         {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "screen"},
    "TABLET_WIDE_SCREEN":         {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "screen"},
    "SCREEN_TINY":                {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "screen"},
    "INNER_WIDER_THAN_SCREEN":    {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "screen"},
    "INNER_TALLER_THAN_SCREEN":   {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "screen"},
    "OS_MISMATCH_WIN":            {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "os"},
    "OS_MISMATCH_MAC":            {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "os"},
    "TOUCH_UA_MISMATCH":          {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "contradictions"},
    "FIRST_LANG_MISMATCH":        {"base": 0.15, "dir": "bot", "sev": "low",    "cat": "contradictions"},
    "INTL_LOCALE_MISMATCH":       {"base": 0.18, "dir": "bot", "sev": "low",    "cat": "contradictions"},
    "WEBGL_VENDOR_RENDERER_MISMATCH": {"base": 0.45, "dir": "bot", "sev": "high", "cat": "webgl"},
    "UA_CHROME_OLD":              {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "browser"},
    "UA_CHROME_FUTURE":           {"base": 0.55, "dir": "bot", "sev": "high",   "cat": "browser"},
    "CLIENT_HINTS_MISMATCH":      {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "contradictions"},
    "LANG_COUNTRY_MISMATCH":      {"base": 0.18, "dir": "bot", "sev": "low",    "cat": "locale"},
    "UTC_TZ":                     {"base": 0.18, "dir": "bot", "sev": "low",    "cat": "timezone"},
    "TZ_MISMATCH":                {"base": 0.28, "dir": "bot", "sev": "low",    "cat": "timezone"},
    "ZOMBIE":                     {"base": 0.55, "dir": "bot", "sev": "high",   "cat": "behavior"},
    "CONNECTION_RTT_ZERO":        {"base": 0.15, "dir": "bot", "sev": "low",    "cat": "connection"},
    "CLOCK_DRIFT":                {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "session"},
    "LEGACY_SIGNAL":              {"base": 0.10, "dir": "bot", "sev": "low",    "cat": "legacy"},

    # ============ HEADER (from header_analyzer) ============
    "MISSING_SEC_CH_UA":          {"base": 0.55, "dir": "bot", "sev": "high",   "cat": "headers"},
    "SEC_CH_UA_VERSION_MISMATCH": {"base": 0.65, "dir": "bot", "sev": "high",   "cat": "headers"},
    "MISSING_SEC_FETCH":          {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "headers"},
    "ACCEPT_ENCODING_ODD":        {"base": 0.25, "dir": "bot", "sev": "medium", "cat": "headers"},
    "DNT_ON_CHROME":              {"base": 0.15, "dir": "bot", "sev": "low",    "cat": "headers"},
    "SEC_CH_UA_ON_FIREFOX":       {"base": 0.55, "dir": "bot", "sev": "high",   "cat": "headers"},
    "SEC_CH_UA_ON_SAFARI":        {"base": 0.55, "dir": "bot", "sev": "high",   "cat": "headers"},
    "HTTP_1_1_ON_HTTPS":          {"base": 0.30, "dir": "bot", "sev": "medium", "cat": "headers"},
    "MISSING_ACCEPT_LANGUAGE":    {"base": 0.35, "dir": "bot", "sev": "medium", "cat": "headers"},
    "MISSING_USER_AGENT_HEADER":  {"base": 0.65, "dir": "bot", "sev": "high",   "cat": "headers"},

    # ============ HUMAN SIGNALS (positive, strong) ============
    "HUMAN_NATURAL_MOUSE":        {"base": 0.65, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_SCROLL_PHYSICS":       {"base": 0.60, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_TYPING_RHYTHM":        {"base": 0.65, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_RICH_INTERACTION":     {"base": 0.70, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_LONG_ENGAGEMENT":      {"base": 0.55, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_DEEP_SCROLL":          {"base": 0.50, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_KEYBOARD":             {"base": 0.60, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_ENGAGED":              {"base": 0.45, "dir": "human", "sev": "human", "cat": "human"},

    # ============ CPM / AD (not risk, but quality-related) ============
    "CPM_BRAVE":                  {"base": 0.10, "dir": "bot", "sev": "low", "cat": "cpm"},
    "CPM_ADBLOCK_BROWSER":        {"base": 0.10, "dir": "bot", "sev": "low", "cat": "cpm"},
}


# =========================================================
# NORMALIZATION
# =========================================================
def _severity_from_registry(code: str, fallback: str = "medium") -> str:
    entry = SIGNAL_REGISTRY.get(code)
    if entry:
        return str(entry.get("sev", fallback))
    return fallback


def _base_from_registry(code: str, fallback: float = 0.5) -> float:
    entry = SIGNAL_REGISTRY.get(code)
    if entry:
        try:
            return float(entry.get("base", fallback))
        except (ValueError, TypeError):
            return fallback
    return fallback


def _direction_from_registry(code: str, fallback: str = "bot") -> str:
    entry = SIGNAL_REGISTRY.get(code)
    if entry:
        return str(entry.get("dir", fallback))
    return fallback


def _category_from_registry(code: str, fallback: str = "unknown") -> str:
    entry = SIGNAL_REGISTRY.get(code)
    if entry:
        return str(entry.get("cat", fallback))
    return fallback


def normalize_signal(
    raw: dict,
    *,
    evidence_quality: float = 0.7,
    context_multiplier: float = 1.0,
    source_override: Optional[str] = None,
) -> dict:
    if not isinstance(raw, dict):
        raw = {}

    code = str(raw.get("code") or "UNKNOWN").strip().upper()
    detail = str(raw.get("detail") or "")[:200]

    direction = str(raw.get("direction") or "").lower().strip()
    if direction not in ("bot", "human"):
        direction = _direction_from_registry(code, "bot")

    severity = str(raw.get("severity") or "").lower().strip()
    if not severity:
        severity = _severity_from_registry(code, "medium")
    if severity not in ("impossible", "critical", "high", "medium", "low", "human"):
        severity = "medium"

    category = str(raw.get("category") or "").strip()
    if not category:
        category = _category_from_registry(code, "unknown")

    source = source_override or str(raw.get("source") or "").strip() or "unknown"

    base = raw.get("base_strength")
    try:
        base_f = float(base) if base is not None else _base_from_registry(code)
    except (ValueError, TypeError):
        base_f = _base_from_registry(code)
    if base_f < 0.0:
        base_f = 0.0
    elif base_f > 1.0:
        base_f = 1.0

    if base is None and "score" in raw:
        try:
            sc = float(raw.get("score", 0))
            if direction == "human":
                base_f = min(1.0, abs(sc) / 40.0)
            else:
                base_f = min(1.0, abs(sc) / 100.0)
        except (ValueError, TypeError):
            pass

    try:
        eq = float(evidence_quality)
    except (ValueError, TypeError):
        eq = 0.7
    eq = max(0.05, min(1.0, eq))

    try:
        cm = float(context_multiplier)
    except (ValueError, TypeError):
        cm = 1.0
    if cm < 0.0:
        cm = 0.0
    elif cm > 2.5:
        cm = 2.5

    strength = base_f * eq * cm
    strength = max(0.0, min(1.0, strength))

    return {
        "code": code,
        "category": category,
        "source": source,
        "direction": direction,
        "severity": severity,
        "base_strength": round(base_f, 4),
        "evidence_quality": round(eq, 4),
        "context_multiplier": round(cm, 3),
        "strength": round(strength, 4),
        "detail": detail,
    }


def normalize_signals(
    raw_signals: List[dict],
    *,
    evidence_quality: float = 0.7,
    context_multiplier: float = 1.0,
    source_override: Optional[str] = None,
) -> List[dict]:
    if not raw_signals:
        return []
    seen: Dict[str, dict] = {}
    for raw in raw_signals:
        try:
            norm = normalize_signal(
                raw,
                evidence_quality=evidence_quality,
                context_multiplier=context_multiplier,
                source_override=source_override,
            )
        except Exception:
            continue
        existing = seen.get(norm["code"])
        if existing is None or norm["strength"] > existing["strength"]:
            seen[norm["code"]] = norm
    return list(seen.values())


# =========================================================
# SEVERITY HELPERS
# =========================================================
def has_impossible(signals: List[dict]) -> bool:
    return any(s.get("severity") == "impossible" for s in signals if isinstance(s, dict))


def has_critical_or_above(signals: List[dict]) -> bool:
    return any(
        s.get("severity") in ("impossible", "critical")
        for s in signals if isinstance(s, dict)
    )


def count_by_direction(signals: List[dict]) -> Dict[str, int]:
    out = {"bot": 0, "human": 0}
    for s in signals or []:
        d = s.get("direction")
        if d in out:
            out[d] += 1
    return out


def strongest_human(signals: List[dict]) -> Optional[dict]:
    humans = [s for s in (signals or []) if isinstance(s, dict) and s.get("direction") == "human"]
    if not humans:
        return None
    return max(humans, key=lambda s: float(s.get("strength", 0)))


def strongest_bot(signals: List[dict]) -> Optional[dict]:
    bots = [s for s in (signals or []) if isinstance(s, dict) and s.get("direction") == "bot"]
    if not bots:
        return None
    return max(bots, key=lambda s: float(s.get("strength", 0)))