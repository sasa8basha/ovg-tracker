"""
collector/signals.py — Signal Registry & Normalization (v8.2)

v8.2 FIX (2025-11):
  - Added OS_MISMATCH_LINUX (v3.3 analysis.py can now detect Linux UA
    with spoofed Win32/Mac platform).
  - All v8.1 fixes preserved (CDP_DETECTED downgrade, WRONGCHROMEORDER
    downgrade, BOTD_DETECTPLUGINSARRAY downgrade, BOT_UA upgrade,
    DATACENTER_IP base raise).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


SEVERITY_BASE = {
    "impossible": 0.99,
    "critical":   0.90,
    "high":       0.75,
    "medium":     0.50,
    "low":        0.25,
    "human":      0.65,
}


SIGNAL_REGISTRY: Dict[str, Dict[str, Any]] = {
    # =========================================================
    # AUTOMATION FLAGS
    # =========================================================
    "WEBDRIVER_FLAG":            {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CDP_DETECTED":              {"base": 0.85, "dir": "bot", "sev": "high",       "cat": "automation"},  # H-13: align with precheck,
    "PUPPETEER_DETECTED":        {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PLAYWRIGHT_DETECTED":       {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "SELENIUM_DETECTED":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "NIGHTMARE_DETECTED":        {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PHANTOM_DETECTED":          {"base": 0.97, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "HEADLESS_UA":               {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "ua"},
    "UNTRUSTED_CLICK":           {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "behavior"},
    "HONEYPOT_CLICK":            {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "honeypot"},
    "HONEYPOT_FORM_FILL":        {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "honeypot"},

    # =========================================================
    # PHYSICAL IMPOSSIBILITIES
    # =========================================================
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

    # =========================================================
    # BOTD DETECTIONS
    # =========================================================
    "BOTD_DETECTWEBDRIVER":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "BOTD_DETECTWINDOWSIZE":         {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "BOTD_DETECTAPPVERSION":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "ua"},
    "BOTD_DETECTUSERAGENT":          {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "ua"},
    "BOTD_DETECTPLUGINSARRAY":       {"base": 0.60, "dir": "bot", "sev": "high",       "cat": "fingerprint"},
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

    # =========================================================
    # VI-BOT DETECTIONS
    # =========================================================
    "WEBDRIVER":             {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CHROMEDRIVER":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "CDPDETECTION":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "PHANTOMWINDOW":         {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "NIGHTMAREDETECTED":     {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "FAKECREATEELEMENT":     {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "TOSTRINGSPOOFED":       {"base": 0.95, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "STEALTHDETECTION":      {"base": 0.75, "dir": "bot", "sev": "high",       "cat": "automation"},
    "STEALTHNOTIFICATION":   {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "STEALTHPLUGINS":        {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "STEALTHCANVAS":         {"base": 0.92, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "WRONGCHROMEORDER":      {"base": 0.70, "dir": "bot", "sev": "high",       "cat": "automation"},
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
    "NOHOVER":               {"base": 0.45, "dir": "bot", "sev": "medium",     "cat": "behavior"},
    "WEBGLDISABLED":         {"base": 0.40, "dir": "bot", "sev": "medium",     "cat": "webgl"},
    "SCREENZERO":            {"base": 0.85, "dir": "bot", "sev": "critical",   "cat": "screen"},
    "SCREENAVAIL":           {"base": 0.85, "dir": "bot", "sev": "critical",   "cat": "screen"},
    "COLORMISMATCH":         {"base": 0.45, "dir": "bot", "sev": "medium",     "cat": "screen"},
    "NAVLANGUAGES":          {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "fingerprint"},
    "NAVPLUGINS":            {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "fingerprint"},
    "NAVCORES":              {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "hardware"},
    "HARDWAREZERO":          {"base": 0.60, "dir": "bot", "sev": "high",       "cat": "hardware"},
    "HARDWAREABSURD":        {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "hardware"},
    "PERFORMANCEZERO":       {"base": 0.60, "dir": "bot", "sev": "medium",     "cat": "performance"},
    "TIMINGZERO":            {"base": 0.65, "dir": "bot", "sev": "high",       "cat": "performance"},
    "FONTFEW":               {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "fingerprint"},

    # =========================================================
    # REBROWSER-BOT-DETECTOR
    # =========================================================
    "RB_PW_INIT_SCRIPTS":        {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "RB_PW_BINDING":             {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "RB_DOCUMENT_INTERCEPTION":  {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "RB_RUNTIME_ENABLE_LEAK":    {"base": 0.85, "dir": "bot", "sev": "high",       "cat": "automation"},
    "RB_RUNTIME_ENABLE_SOFT":    {"base": 0.60, "dir": "bot", "sev": "medium",     "cat": "automation"},
    "RB_SOURCE_URL_LEAK":        {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "RB_SOURCE_URL_BARE_FILE":   {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "automation"},
    "RB_NATIVE_TAMPERED":        {"base": 0.85, "dir": "bot", "sev": "high",       "cat": "automation"},
    "RB_AUTOMATION_FRAME":       {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "RB_CDP_BINDING_GLOBALS":    {"base": 0.70, "dir": "bot", "sev": "medium",     "cat": "automation"},
    "RB_EXPOSE_FUNCTION_LEAK":   {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "automation"},
    "RB_HEADLESS_NO_CHROME":     {"base": 0.90, "dir": "bot", "sev": "critical",   "cat": "headless"},
    "RB_HEADLESS_NOTIF_DENIED":  {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "headless"},
    "RB_HEADLESS_800X600":       {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "headless"},
    "RB_HEADLESS_UA":            {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "headless"},
    "RB_MOBILE_TOUCH_1":         {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "mobile"},
    "RB_MOBILE_TOUCH_0":         {"base": 0.60, "dir": "bot", "sev": "medium",     "cat": "mobile"},
    "RB_MOBILE_IOS_CHROMIUM":    {"base": 0.70, "dir": "bot", "sev": "high",       "cat": "mobile"},
    "RB_PLATFORM_MISMATCH":      {"base": 0.95, "dir": "bot", "sev": "critical",   "cat": "os"},
    "RB_ACTIVE_TEXT_MISMATCH":   {"base": 0.55, "dir": "bot", "sev": "medium",     "cat": "os"},
    "RB_IFRAME_REALM_SHARED":    {"base": 0.98, "dir": "bot", "sev": "impossible", "cat": "automation"},
    "RB_NAV_OWN_PROPS":          {"base": 0.85, "dir": "bot", "sev": "high",       "cat": "stealth"},

    # =========================================================
    # STACK TRACE TRAPS
    # =========================================================
    "ERRORTRAPPHANTOMJS":        {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPUPPETEER":        {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPLAYWRIGHTCHROME": {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPLAYWRIGHTFIREFOX":{"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPSELENIUMCHROME":   {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPNIGHTMARE":        {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPCYPRESS":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPATCHRIGHT":       {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPPPTRURL":          {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},
    "ERRORTRAPUTILITYSCRIPT":    {"base": 0.99, "dir": "bot", "sev": "impossible", "cat": "trap"},

    # =========================================================
    # CRITICAL / HIGH
    # =========================================================
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

    "BOT_UA":                     {"base": 0.90, "dir": "bot", "sev": "critical", "cat": "ua"},
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

    # =========================================================
    # FLAGON-DERIVED
    # =========================================================
    "RAGE_CLICK_BURST":           {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "INTERVAL_SUSPICIOUS":        {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "MUTATION_ANOMALY":           {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "DETAILED_CLICK_NO_RECT":     {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "behavior"},
    "CLICK_OUTSIDE_VIEWPORT":     {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "behavior"},

    # =========================================================
    # ADVERIFY-INSPIRED
    # =========================================================
    "ML_FEATURE_ANOMALY":         {"base": 0.65, "dir": "bot", "sev": "high",   "cat": "ml"},
    "ML_FEATURE_SUSPICIOUS":      {"base": 0.45, "dir": "bot", "sev": "medium", "cat": "ml"},
    "NO_INTERACTION_HIGH_CONF":   {"base": 0.65, "dir": "bot", "sev": "high",   "cat": "behavior"},
    "MISSING_FP_CORE":            {"base": 0.55, "dir": "bot", "sev": "medium", "cat": "fingerprint"},
    "DNT_WITH_ZERO_INTERACTION":  {"base": 0.50, "dir": "bot", "sev": "medium", "cat": "evasion"},
    "SCREEN_UA_MISMATCH":         {"base": 0.60, "dir": "bot", "sev": "high",   "cat": "screen"},
    "PAID_APP_ADS_CONTEXT":       {"base": 0.25, "dir": "bot", "sev": "low",    "cat": "context"},

    # =========================================================
    # MEDIUM / LOW
    # =========================================================
    "DATACENTER_IP":              {"base": 0.65, "dir": "bot", "sev": "high",   "cat": "network"},
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
    # ✅ v8.2: new signal for Linux UA + Win32/Mac platform
    "OS_MISMATCH_LINUX":          {"base": 0.40, "dir": "bot", "sev": "medium", "cat": "os"},
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

    # =========================================================
    # HEADER
    # =========================================================
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

    # =========================================================
    # HUMAN
    # =========================================================
    "HUMAN_NATURAL_MOUSE":        {"base": 0.65, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_SCROLL_PHYSICS":       {"base": 0.60, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_TYPING_RHYTHM":        {"base": 0.65, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_RICH_INTERACTION":     {"base": 0.70, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_LONG_ENGAGEMENT":      {"base": 0.55, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_DEEP_SCROLL":          {"base": 0.50, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_KEYBOARD":             {"base": 0.60, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_ENGAGED":              {"base": 0.45, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_DIVERSE_INTERACTION":  {"base": 0.60, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_NATURAL_SCROLL":       {"base": 0.55, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_HOVER_ACTIVITY":       {"base": 0.40, "dir": "human", "sev": "human", "cat": "human"},
    "HUMAN_CLICK_ACCURACY":       {"base": 0.45, "dir": "human", "sev": "human", "cat": "human"},

    # =========================================================
    # CPM / AD
    # =========================================================
    "CPM_BRAVE":                  {"base": 0.10, "dir": "bot", "sev": "low", "cat": "cpm"},
    "CPM_ADBLOCK_BROWSER":        {"base": 0.10, "dir": "bot", "sev": "low", "cat": "cpm"},
}


# =========================================================
# INTERNAL HELPERS
# =========================================================
def _sev_from_registry(code: str, fallback: str = "medium") -> str:
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


def _dir_from_registry(code: str, fallback: str = "bot") -> str:
    entry = SIGNAL_REGISTRY.get(code)
    if entry:
        return str(entry.get("dir", fallback))
    return fallback


def _cat_from_registry(code: str, fallback: str = "unknown") -> str:
    entry = SIGNAL_REGISTRY.get(code)
    if entry:
        return str(entry.get("cat", fallback))
    return fallback


# =========================================================
# NORMALIZATION
# =========================================================
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
        direction = _dir_from_registry(code, "bot")

    severity = str(raw.get("severity") or "").lower().strip()
    if not severity:
        severity = _sev_from_registry(code, "medium")
    if severity not in ("impossible", "critical", "high", "medium", "low", "human"):
        severity = "medium"

    category = str(raw.get("category") or "").strip()
    if not category:
        category = _cat_from_registry(code, "unknown")

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
# HELPERS
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


# =========================================================
# REBROWSER → SIGNAL ADAPTER
# =========================================================
def convert_rebrowser_to_signals(rb: dict) -> List[dict]:
    if not isinstance(rb, dict):
        return []
    out = []

    if rb.get("pwInitScripts"):
        out.append({"code": "RB_PW_INIT_SCRIPTS", "detail": "Playwright's window.__pwInitScripts present"})
    if rb.get("pwBinding"):
        out.append({"code": "RB_PW_BINDING", "detail": "Playwright's window.__playwright__binding__ present"})
    if rb.get("documentInterception"):
        out.append({"code": "RB_DOCUMENT_INTERCEPTION", "detail": "Document served without network protocol (Patchright signature)"})
    if rb.get("iframeRealmShared"):
        out.append({"code": "RB_IFRAME_REALM_SHARED", "detail": "srcdoc iframe shares realm with parent (stealth plugin)"})
    if rb.get("headlessNoChrome"):
        out.append({"code": "RB_HEADLESS_NO_CHROME", "detail": "Desktop Chrome without window.chrome (chrome-headless-shell)"})
    if rb.get("headlessUA"):
        out.append({"code": "RB_HEADLESS_UA", "detail": "HeadlessChrome in user agent"})
    if rb.get("headlessNotificationDenied") == 0.5:
        out.append({"code": "RB_HEADLESS_NOTIF_DENIED", "detail": "Notification.permission denied on desktop"})
    if rb.get("headless800x600") == 0.5:
        out.append({"code": "RB_HEADLESS_800X600", "detail": "Default headless screen 800x600"})
    if rb.get("mobileTouch1") == 0.5:
        out.append({"code": "RB_MOBILE_TOUCH_1", "detail": "Mobile UA with maxTouchPoints=1 (CDP emulation)"})
    if rb.get("mobileTouch0") == 0.5:
        out.append({"code": "RB_MOBILE_TOUCH_0", "detail": "Mobile UA with maxTouchPoints=0"})
    if rb.get("mobileIOSChromium") == 0.5:
        out.append({"code": "RB_MOBILE_IOS_CHROMIUM", "detail": "iOS UA with Chromium engine"})
    if rb.get("activeTextMismatch") == 0.5:
        out.append({"code": "RB_ACTIVE_TEXT_MISMATCH", "detail": "Claims Windows but renders Linux/macOS ActiveText"})

    rl = rb.get("runtimeEnableLeak")
    if rl == 1:
        out.append({"code": "RB_RUNTIME_ENABLE_LEAK", "detail": "CDP Runtime.enable detected (console serialization)"})
    elif rl == 0.7:
        out.append({"code": "RB_RUNTIME_ENABLE_SOFT", "detail": "Possible Runtime.enable (stack lookup happened)"})

    sl = rb.get("sourceUrlLeak")
    if sl == 1:
        kind = rb.get("sourceUrlKind", "unknown")
        out.append({"code": "RB_SOURCE_URL_LEAK", "detail": f"Error stack has {kind} source URL"})
    elif sl == 0.5:
        bare = rb.get("bareFiles", [])
        out.append({"code": "RB_SOURCE_URL_BARE_FILE", "detail": f"Bare file names in stack: {bare[:3]}"})

    nt = rb.get("nativeTampered")
    if isinstance(nt, list) and nt:
        names = [t.get("name") for t in nt if isinstance(t, dict)]
        out.append({"code": "RB_NATIVE_TAMPERED", "detail": f"Tampered: {', '.join(names[:3])}"})

    af = rb.get("automationFrames")
    if isinstance(af, list) and af:
        out.append({"code": "RB_AUTOMATION_FRAME", "detail": f"Automation frames in: {', '.join(af[:3])}"})

    cb = rb.get("cdpBindingGlobals")
    if isinstance(cb, list) and cb:
        out.append({"code": "RB_CDP_BINDING_GLOBALS", "detail": f"Unnamed native globals: {cb[:3]}"})

    if rb.get("exposeFunctionLeak"):
        kind = rb.get("exposeKind", "unknown")
        out.append({"code": "RB_EXPOSE_FUNCTION_LEAK", "detail": f"exposeFunction leak ({kind})"})

    nop = rb.get("navOwnProps")
    if isinstance(nop, list) and nop:
        out.append({"code": "RB_NAV_OWN_PROPS", "detail": f"navigator has own props: {nop[:3]}"})

    pm = rb.get("platformMismatch")
    if isinstance(pm, dict):
        out.append({
            "code": "RB_PLATFORM_MISMATCH",
            "detail": f"UA says {pm.get('ua')}, platform says {pm.get('platform')}",
        })

    return out


# =========================================================
# GENERIC FINGERPRINT → SIGNALS ADAPTER
# =========================================================
def _iter_botd(botd: dict):
    if not isinstance(botd, dict):
        return
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
            yield code, f"BotD: {key}"


def _iter_vib(vib: dict):
    if not isinstance(vib, dict):
        return
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
            yield code, f"vi-bot: {key}"


def convert_fingerprint_to_signals(fp: dict) -> List[dict]:
    if not isinstance(fp, dict):
        return []

    out: List[dict] = []

    for code, detail in _iter_botd(fp.get("botd") or {}):
        out.append({"code": code, "detail": detail})

    for code, detail in _iter_vib(fp.get("vib") or {}):
        out.append({"code": code, "detail": detail})

    out.extend(convert_rebrowser_to_signals(fp.get("rebrowser") or {}))

    traps = fp.get("trap_triggers") or {}
    if isinstance(traps, dict):
        for trap_name, triggered in traps.items():
            if not triggered:
                continue
            code = str(trap_name).upper()
            code = code.replace("ERRortrap", "ERRORTRAP")
            registry_key = code if code in SIGNAL_REGISTRY else None
            if registry_key is None:
                candidate = code.upper().replace("_", "")
                for rk in SIGNAL_REGISTRY.keys():
                    if rk.startswith("ERRORTRAP") and rk.replace("_", "") == candidate:
                        registry_key = rk
                        break
            if registry_key:
                out.append({"code": registry_key, "detail": f"Stack trap fired: {trap_name}"})

    if fp.get("honeypot_triggered") is True:
        out.append({"code": "HONEYPOT_CLICK", "detail": "Hidden honeypot field interacted with"})

    return out