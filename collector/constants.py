"""
constants.py — كل أسماء الإشارات المتوقعة كـ constants.
عشان ما نستخدمش strings مبعترة في كل مكان.
"""

# =========================================================
# CRITICAL (بوت مؤكد 100%)
# =========================================================
SIG_WEBDRIVER = "WEBDRIVER_FLAG"
SIG_CDP_DETECTED = "CDP_DETECTED"
SIG_PUPPETEER = "PUPPETEER_DETECTED"
SIG_PLAYWRIGHT = "PLAYWRIGHT_DETECTED"
SIG_SELENIUM = "SELENIUM_DETECTED"
SIG_NIGHTMARE = "NIGHTMARE_DETECTED"
SIG_PHANTOM = "PHANTOM_DETECTED"
SIG_HONEYPOT_CLICK = "HONEYPOT_CLICK"
SIG_HONEYPOT_FORM = "HONEYPOT_FORM_FILL"
SIG_IMPOSSIBLE_SPEED = "IMPOSSIBLE_SPEED"

# =========================================================
# HIGH
# =========================================================
SIG_BOT_UA = "BOT_UA"
SIG_VPN_DATACENTER = "VPN_DATACENTER"
SIG_DATACENTER_ASN = "DATACENTER_ASN"
SIG_WEBRTC_LEAK = "WEBRTC_LEAK"
SIG_PLUGINS_ZERO = "PLUGINS_ZERO"
SIG_FINGERPRINT_REUSE_HIGH = "FINGERPRINT_REUSE_HIGH"
SIG_IP_VELOCITY_HIGH = "IP_VELOCITY_HIGH"
SIG_FINGERPRINT_MULTI_IP = "FINGERPRINT_MULTI_IP"
SIG_IP_MULTI_FINGERPRINT = "IP_MULTI_FINGERPRINT"
SIG_HEADLESS_VIEWPORT = "HEADLESS_VIEWPORT"
SIG_ROBOTIC_LINEAR = "ROBOTIC_LINEAR"
SIG_CLICK_BEFORE_MOVE = "CLICK_BEFORE_MOVE"

# =========================================================
# MEDIUM
# =========================================================
SIG_WINDOWS_UA_LINUX = "WINDOWS_UA_LINUX"
SIG_FIREFOX_CHROME_OBJ = "FIREFOX_CHROME_OBJ"
SIG_DATACENTER_IP = "DATACENTER_IP"
SIG_VPN_PROXY = "VPN_PROXY"
SIG_WEBRTC_VPN_DIFF = "WEBRTC_VPN_DIFF"
SIG_CANVAS_MISSING = "CANVAS_MISSING"
SIG_LANGUAGES_EMPTY = "LANGUAGES_EMPTY"
SIG_NO_MIME_TYPES = "NO_MIME_TYPES"
SIG_FINGERPRINT_REUSE_MED = "FINGERPRINT_REUSE_MED"
SIG_IP_VELOCITY_MED = "IP_VELOCITY_MED"
SIG_CORES_ZERO = "CORES_ZERO"
SIG_ABSURD_CORES = "ABSURD_CORES"
SIG_CPU_MEMORY_MISMATCH = "CPU_MEMORY_MISMATCH"
SIG_MOBILE_PIXEL_RATIO = "MOBILE_PIXEL_RATIO"
SIG_VIEWPORT_ZERO = "VIEWPORT_ZERO"
SIG_MOBILE_WIDE_SCREEN = "MOBILE_WIDE_SCREEN"
SIG_TABLET_WIDE_SCREEN = "TABLET_WIDE_SCREEN"
SIG_SCREEN_TINY = "SCREEN_TINY"
SIG_INNER_WIDER_THAN_SCREEN = "INNER_WIDER_THAN_SCREEN"
SIG_INNER_TALLER_THAN_SCREEN = "INNER_TALLER_THAN_SCREEN"
SIG_OS_MISMATCH_WIN = "OS_MISMATCH_WIN"
SIG_OS_MISMATCH_MAC = "OS_MISMATCH_MAC"
SIG_OS_MISMATCH_LINUX = "OS_MISMATCH_LINUX"  # L-07
SIG_TOUCH_UA_MISMATCH = "TOUCH_UA_MISMATCH"
SIG_TZ_MISMATCH = "TZ_MISMATCH"
SIG_ROBOTIC_CURVATURE = "ROBOTIC_CURVATURE"
SIG_ROBOTIC_VARIANCE = "ROBOTIC_VARIANCE"
SIG_INSTANT_FIRST_MOVE = "INSTANT_FIRST_MOVE"
SIG_IDLE_VISIBLE = "IDLE_VISIBLE"
SIG_RAPID_REPEAT_CLICKS = "RAPID_REPEAT_CLICKS"
SIG_SOFT_RENDERER = "SOFT_RENDERER"
SIG_CHROME_NO_OBJ = "CHROME_NO_OBJ"
SIG_LEFT_FAST = "LEFT_FAST"

# =========================================================
# LOW
# =========================================================
SIG_CANVAS_BLOCKED = "CANVAS_BLOCKED"
SIG_SINGLE_LANG = "SINGLE_LANG"
SIG_NO_PDF_VIEWER = "NO_PDF_VIEWER"
SIG_FINGERPRINT_REUSE_LOW = "FINGERPRINT_REUSE_LOW"
SIG_CORES_LOW = "CORES_LOW"
SIG_LOW_MEMORY = "LOW_MEMORY"
SIG_LOW_COLOR_DEPTH = "LOW_COLOR_DEPTH"
SIG_FIRST_LANG_MISMATCH = "FIRST_LANG_MISMATCH"
SIG_INTL_LOCALE_MISMATCH = "INTL_LOCALE_MISMATCH"
SIG_UA_CHROME_OLD = "UA_CHROME_OLD"
SIG_LANG_COUNTRY_MISMATCH = "LANG_COUNTRY_MISMATCH"
SIG_UTC_TZ = "UTC_TZ"
SIG_LEFT_FAST_HIDDEN = "LEFT_FAST_HIDDEN"
SIG_ZOMBIE = "ZOMBIE"

# =========================================================
# v3 — NEW signals (من الـ heartbeats والـ milestones)
# =========================================================
SIG_SILENT_AFTER_INITIAL = "SILENT_AFTER_INITIAL"      # handshake وخلاص، مفيش heartbeats
SIG_HEARTBEAT_GAP = "HEARTBEAT_GAP"                    # فجوة كبيرة بين heartbeats (> 60 ثانية)
SIG_CLOCK_DRIFT = "CLOCK_DRIFT"                        # ساعة المتصفح غلط > 30 ثانية
SIG_AD_HIDDEN_AFTER_LOAD = "AD_HIDDEN_AFTER_LOAD"      # إعلان اتحمل بس مش ظهر (bot cloaking)
SIG_ENGAGEMENT_ZERO = "ENGAGEMENT_ZERO"                # صفر تفاعل مع duration > 10s
SIG_TAB_NEVER_FOCUSED = "TAB_NEVER_FOCUSED"            # tab مفضلش focused خالص
SIG_SCROLL_LINEAR = "SCROLL_LINEAR"                    # scroll منتظم (بوت)
SIG_MOUSE_TOO_SMOOTH = "MOUSE_TOO_SMOOTH"              # حركة ماوس سلسة أوي (بوت)
SIG_MOUSE_TELEPORT = "MOUSE_TELEPORT"                  # قفزات كبيرة في الماوس (بوت)

# =========================================================
# HUMAN (إشارات إيجابية)
# =========================================================
SIG_HUMAN_RICH_INTERACTION = "HUMAN_RICH_INTERACTION"
SIG_HUMAN_NATURAL_MOUSE = "HUMAN_NATURAL_MOUSE"
SIG_HUMAN_LONG_ENGAGEMENT = "HUMAN_LONG_ENGAGEMENT"
SIG_HUMAN_DEEP_SCROLL = "HUMAN_DEEP_SCROLL"
SIG_HUMAN_KEYBOARD = "HUMAN_KEYBOARD"

# =========================================================
# CPM
# =========================================================
SIG_CPM_BRAVE = "CPM_BRAVE"
SIG_CPM_ADBLOCK_BROWSER = "CPM_ADBLOCK_BROWSER"

# =========================================================
# DATA QUALITY (بتأثر على الـ verdict)
# =========================================================
SIG_DATA_PARTIAL = "DATA_PARTIAL"
SIG_DATA_LEGACY = "DATA_LEGACY"

# =========================================================
# MAPPING: source لكل إشارة (للاستخدام في الـ explainability)
# =========================================================
CODE_TO_SOURCE = {
    # Critical
    SIG_WEBDRIVER: "critical",
    SIG_CDP_DETECTED: "critical",
    SIG_PUPPETEER: "automation",
    SIG_PLAYWRIGHT: "automation",
    SIG_SELENIUM: "automation",
    SIG_NIGHTMARE: "automation",
    SIG_PHANTOM: "automation",
    SIG_HONEYPOT_CLICK: "honeypot",
    SIG_HONEYPOT_FORM: "honeypot",
    SIG_IMPOSSIBLE_SPEED: "behavior_deep",

    # High
    SIG_BOT_UA: "ua",
    SIG_VPN_DATACENTER: "network",
    SIG_DATACENTER_ASN: "network",
    SIG_WEBRTC_LEAK: "network",
    SIG_PLUGINS_ZERO: "fingerprint",
    SIG_FINGERPRINT_REUSE_HIGH: "fingerprint_reuse",
    SIG_IP_VELOCITY_HIGH: "cross_visit",
    SIG_FINGERPRINT_MULTI_IP: "cross_visit",
    SIG_IP_MULTI_FINGERPRINT: "cross_visit",
    SIG_HEADLESS_VIEWPORT: "screen",
    SIG_ROBOTIC_LINEAR: "behavior",
    SIG_CLICK_BEFORE_MOVE: "behavior_deep",

    # Medium
    SIG_WINDOWS_UA_LINUX: "critical",
    SIG_FIREFOX_CHROME_OBJ: "critical",
    SIG_DATACENTER_IP: "network",
    SIG_VPN_PROXY: "network",
    SIG_WEBRTC_VPN_DIFF: "network",
    SIG_CANVAS_MISSING: "fingerprint",
    SIG_LANGUAGES_EMPTY: "fingerprint",
    SIG_NO_MIME_TYPES: "fingerprint",
    SIG_FINGERPRINT_REUSE_MED: "fingerprint_reuse",
    SIG_IP_VELOCITY_MED: "cross_visit",
    SIG_CORES_ZERO: "hardware",
    SIG_ABSURD_CORES: "hardware",
    SIG_CPU_MEMORY_MISMATCH: "hardware",
    SIG_MOBILE_PIXEL_RATIO: "hardware",
    SIG_VIEWPORT_ZERO: "screen",
    SIG_MOBILE_WIDE_SCREEN: "screen",
    SIG_TABLET_WIDE_SCREEN: "screen",
    SIG_SCREEN_TINY: "screen",
    SIG_INNER_WIDER_THAN_SCREEN: "screen",
    SIG_INNER_TALLER_THAN_SCREEN: "screen",
    SIG_OS_MISMATCH_WIN: "os",
    SIG_OS_MISMATCH_MAC: "os",
    SIG_OS_MISMATCH_LINUX: "os",  # L-07
    SIG_TOUCH_UA_MISMATCH: "contradictions",
    SIG_TZ_MISMATCH: "timezone",
    SIG_ROBOTIC_CURVATURE: "behavior",
    SIG_ROBOTIC_VARIANCE: "behavior",
    SIG_INSTANT_FIRST_MOVE: "behavior_deep",
    SIG_IDLE_VISIBLE: "behavior_deep",
    SIG_RAPID_REPEAT_CLICKS: "behavior_deep",
    SIG_SOFT_RENDERER: "webgl",
    SIG_CHROME_NO_OBJ: "fingerprint",
    SIG_LEFT_FAST: "behavior",

    # Low
    SIG_CANVAS_BLOCKED: "fingerprint",
    SIG_SINGLE_LANG: "fingerprint",
    SIG_NO_PDF_VIEWER: "fingerprint",
    SIG_FINGERPRINT_REUSE_LOW: "fingerprint_reuse",
    SIG_CORES_LOW: "hardware",
    SIG_LOW_MEMORY: "hardware",
    SIG_LOW_COLOR_DEPTH: "hardware",
    SIG_FIRST_LANG_MISMATCH: "contradictions",
    SIG_INTL_LOCALE_MISMATCH: "contradictions",
    SIG_UA_CHROME_OLD: "contradictions",
    SIG_LANG_COUNTRY_MISMATCH: "locale",
    SIG_UTC_TZ: "timezone",
    SIG_LEFT_FAST_HIDDEN: "behavior",
    SIG_ZOMBIE: "behavior",

    # v3 new
    SIG_SILENT_AFTER_INITIAL: "session",
    SIG_HEARTBEAT_GAP: "session",
    SIG_CLOCK_DRIFT: "session",
    SIG_AD_HIDDEN_AFTER_LOAD: "ad_events",
    SIG_ENGAGEMENT_ZERO: "behavior_deep",
    SIG_TAB_NEVER_FOCUSED: "session",
    SIG_SCROLL_LINEAR: "behavior",
    SIG_MOUSE_TOO_SMOOTH: "behavior",
    SIG_MOUSE_TELEPORT: "behavior",

    # Human
    SIG_HUMAN_RICH_INTERACTION: "human",
    SIG_HUMAN_NATURAL_MOUSE: "human",
    SIG_HUMAN_LONG_ENGAGEMENT: "human",
    SIG_HUMAN_DEEP_SCROLL: "human",
    SIG_HUMAN_KEYBOARD: "human",

    # CPM
    SIG_CPM_BRAVE: "cpm",
    SIG_CPM_ADBLOCK_BROWSER: "cpm",

    # Data quality
    SIG_DATA_PARTIAL: "data_quality",
    SIG_DATA_LEGACY: "data_quality",
}
