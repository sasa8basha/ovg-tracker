import secrets
import httpx
from urllib.parse import urlparse, parse_qs
from config import GEO_LOOKUP_TIMEOUT
from utils import ip_cache, _is_private_ip

# --- استيراد المكتبات الصحيحة ---
from ua_extract import DeviceDetector
from identify_browser import identify_browser

async def get_ip_info(ip: str):
    if not ip or _is_private_ip(ip):
        return {"country": "Local", "isp": "Local ISP", "type": "residential", "asn": "N/A", "security": {}, "lat": 0.0, "lon": 0.0}
    cached = ip_cache.get(ip)
    if cached is not None: return cached
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,as,proxy,hosting,lat,lon", timeout=GEO_LOOKUP_TIMEOUT)
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    is_vpn = bool(d.get("proxy") or d.get("hosting"))
                    out = {"country": d.get("country", "Unknown"), "isp": d.get("isp", "Unknown"), "type": "hosting" if is_vpn else "residential", "asn": (d.get("as") or "Unknown").split()[0], "security": {"vpn": is_vpn}, "lat": d.get("lat", 0.0), "lon": d.get("lon", 0.0)}
                    ip_cache.set(ip, out)
                    return out
    except Exception: pass
    return {"country": "Unknown", "isp": "Unknown", "type": "Unknown", "asn": "Unknown", "security": {}, "lat": 0.0, "lon": 0.0}

def parse_ua_advanced(ua: str, headers: dict = None):
    """تحليل دقيق جداً باستخدام Matomo + Client Hints"""
    try:
        # 1. استخدام Matomo (ua_extract) مع تمرير الهيدرات (مهم جداً لاكتشاف Client Hints)
        detector = DeviceDetector(ua, headers=headers)
        parsed = detector.parse()
        
        browser_name = parsed.client_name() or 'Unknown'
        browser_version = parsed.client_version() or 'Unknown'
        os_name = parsed.os_name() or 'Unknown'
        os_version = parsed.os_version() or 'Unknown'
        device_type = parsed.device_type() or 'Unknown'
        device_brand = parsed.device_brand_name() or 'Unknown'
        device_model = parsed.device_model() or 'Unknown'

        # 2. استخدام Client Hints لتصحيح الأخطاء (مثل Brave)
        sec_ch_ua = headers.get('sec-ch-ua', '') if headers else ''
        sec_ch_platform = headers.get('sec-ch-ua-platform', '') if headers else ''
        
        if sec_ch_ua or sec_ch_platform:
            hints = identify_browser(ua, sec_ch_ua, sec_ch_platform)
            if hints.get('name') and hints['name'] != 'Unknown': browser_name = hints['name']
            if hints.get('version') and hints['version'] != 'Unknown': browser_version = hints['version']
            if hints.get('platform') and hints['platform'] != 'Unknown': os_name = hints['platform']

        return {
            "os": os_name, "os_version": os_version,
            "device_type": device_type, "device_brand": device_brand, "device_model": device_model,
            "browser": browser_name, "browser_version": browser_version
        }
    except Exception as e:
        # خطة احتياطية في حال فشل المكتبات (طبعاً مع طباعة الخطأ في اللوجز لو أردت)
        return {"os": "Unknown", "os_version": "Unknown", "device_type": "Unknown", "device_brand": "Unknown", "device_model": "Unknown", "browser": "Unknown", "browser_version": "Unknown"}

def extract_zone_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        for k, v in parse_qs(parsed.query).items():
            if k.lower() == "zoneid" and v: return v[0]
    except Exception: pass
    return "unknown"

def new_site_key() -> str:
    return secrets.token_hex(8)

class RiskEngine:
    def __init__(self):
        self.hard_score = 0; self.soft_score = 0; self.behavioral_score = 0
        self.evidence = []; self.threat_types = set()
    def add_hard(self, points, reason, threat_type=None):
        self.hard_score += points; self.evidence.append(f"[Hard] {reason} (+{points})")
        if threat_type: self.threat_types.add(threat_type)
    def add_soft(self, points, reason):
        self.soft_score += points; self.evidence.append(f"[Soft] {reason} (+{points})")
    def add_behavioral(self, points, reason):
        self.behavioral_score += points; self.evidence.append(f"[Behavioral] {reason} (+{points})")
    def finalize(self):
        raw_score = self.hard_score + (self.soft_score * 0.6) + (self.behavioral_score * 0.8)
        final_score = min(100, max(0, raw_score))
        confidence = min(100.0, (self.hard_score * 0.5) + (len(self.evidence) * 5.0) + 20.0)
        if final_score >= 86: verdict = "invalid"
        elif final_score >= 66: verdict = "high_risk"
        elif final_score >= 46: verdict = "suspicious"
        elif final_score >= 26: verdict = "valid"
        else: verdict = "clean"
        return {"score": round(final_score, 1), "verdict": verdict, "confidence": round(confidence, 1), "threat_types": list(self.threat_types), "evidence": self.evidence, "breakdown": {"hard": self.hard_score, "soft": round(self.soft_score, 1), "behavioral": round(self.behavioral_score, 1)}}

def analyze_visit(data: dict, ip_info: dict) -> dict:
    engine = RiskEngine()
    nav = data.get("nav") or {}; fp = data.get("fingerprint") or {}; behavior = data.get("behavior") or {}
    events = behavior.get("events") or {}; mouse = behavior.get("mouse") or {}; timing = behavior.get("timing") or {}
    ua = str(nav.get("ua") or "").lower(); sec = ip_info.get("security", {}); country = ip_info.get("country", "Unknown")

    if nav.get("webdriver") is True: engine.add_hard(85, "WebDriver/Selenium Detected", "automation_tool")
    if not ua or any(x in ua for x in ("headless", "python", "curl", "wget", "phantom")): engine.add_hard(90, "Headless/Automation User-Agent", "automation_tool")
    webrtc = data.get("webrtc_ip")
    if webrtc and webrtc != "None" and not _is_private_ip(webrtc) and webrtc != data.get("client_ip"): engine.add_hard(80, f"WebRTC IP Leak ({webrtc})", "vpn_proxy")
    if str(ip_info.get("type", "")).lower() == "hosting": engine.add_hard(75, "Datacenter/Hosting IP", "datacenter_traffic")
    if sec.get("vpn") is True: engine.add_hard(70, "VPN/Proxy Detected", "vpn_proxy")
    canvas = fp.get("canvas_hash")
    if not canvas or len(str(canvas)) < 5 or canvas == "blocked": engine.add_hard(65, "Canvas Fingerprint Blocked/Missing", "emulator_virtual")
    renderer = str((fp.get("webgl") or {}).get("renderer") or "").lower()
    if any(x in renderer for x in ("swiftshader", "llvmpipe", "mesa offscreen")): engine.add_hard(60, "Virtual WebGL Renderer", "emulator_virtual")
    try:
        cores = int(fp.get("hardwareConcurrency") or 0)
        if cores <= 1: engine.add_hard(55, f"Low CPU Cores ({cores})", "emulator_virtual")
    except: pass

    tz = str(fp.get("timezone") or "").lower()
    if not tz or tz in ("utc", "etc/utc", "unknown"): engine.add_soft(30, "UTC/Unknown Timezone")
    elif country not in ("Unknown", "Local"):
        cmap = {"Egypt": ["cairo", "africa"], "US": ["america/"], "UK": ["london", "europe/london"], "India": ["asia/kolkata", "asia/calcutta"]}
        if country in cmap and not any(t in tz for t in cmap[country]): engine.add_soft(40, f"Timezone Mismatch (IP:{country} vs TZ:{tz})")
    platform = str(nav.get("platform") or "").lower()
    if "windows nt" in ua and "win" not in platform: engine.add_soft(35, "OS Mismatch (UA vs Platform)")

    try: t_on_page = int(behavior.get("time_on_page_ms") or 0)
    except: t_on_page = 0
    if t_on_page < 1500: engine.add_behavioral(35, "Left too fast (<1.5s)")
    
    avg_speed = float(mouse.get("avg_speed") or 0); curvature = float(mouse.get("curvature") or 0)
    pauses = int(mouse.get("pauses") or 0); moves = int(events.get("mousemove", 0))
    if moves > 10:
        if curvature < 0.1 and avg_speed > 0: engine.add_behavioral(50, "Robotic Mouse (Linear Path)"); engine.threat_types.add("bot_farm")
        if pauses == 0 and avg_speed > 1500: engine.add_behavioral(40, "Inhuman Mouse Speed (No pauses)")
        if avg_speed == 0 and moves > 0: engine.add_behavioral(30, "Zero Mouse Speed Variance")
    time_to_first_move = int(timing.get("time_to_first_move") or 0)
    if time_to_first_move > 0 and time_to_first_move < 50: engine.add_behavioral(20, "Instant Mouse Movement (Bot-like)")
    if t_on_page > 3000 and moves == 0 and events.get("touchstart", 0) == 0: engine.add_behavioral(30, "No Interaction (Zombie Visit)")

    return engine.finalize()
