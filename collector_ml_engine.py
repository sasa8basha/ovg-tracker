"""
collector/ml_engine.py — SYSTEM 8: Feature Engineering + ML

Self-contained. Pure-Python logistic regression (no external ML deps).

Approach:
  - 32 features extracted from live data OR from stored VisitModel
  - Standardization (z-score) using training means/stds
  - Model persisted as JSON: data/ml_model.json
  - Graceful degradation: if no model, returns neutral 0.5

Signals emitted:
  - ML_HIGH_RISK (high, 70): P(bot) >= 0.85
  - ML_ELEVATED_RISK (medium, 40): 0.65 <= P(bot) < 0.85
"""
import os
import sys
import json
import math
import time
import logging
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any

logger = logging.getLogger("ovg.ml_engine")


# =========================================================
# CONSTANTS
# =========================================================
FEATURE_NAMES: List[str] = [
    "f_cores", "f_memory", "f_screen_w", "f_screen_h", "f_pixel_ratio",
    "f_time_on_page_s", "f_events_total", "f_mousemove", "f_clicks",
    "f_scrolls", "f_keydowns", "f_touchstarts", "f_mouse_variance",
    "f_mouse_points", "f_heartbeats", "f_events_per_sec", "f_clicks_per_min",
    "f_screen_area",
    "b_webdriver", "b_is_datacenter", "b_is_tor", "b_is_vpn",
    "b_has_canvas", "b_has_webgl", "b_headless_ua", "b_empty_languages",
    "b_low_cores", "b_absurd_cores", "b_no_mouse_no_touch", "b_private_ip",
    "b_mobile_ua", "b_ios_ua",
]

MIN_TRAINING_SAMPLES = 100
DEFAULT_STORAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "ml_model.json"
)

HIGH_RISK_THRESHOLD = 0.85
ELEVATED_RISK_THRESHOLD = 0.65


# =========================================================
# SAFE HELPERS
# =========================================================
def _s_int(val, default=0):
    if val is None:
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError, OverflowError):
        return default


def _s_float(val, default=0.0):
    if val is None:
        return default
    try:
        f = float(val)
        if f != f or f in (float("inf"), float("-inf")):
            return default
        return f
    except (ValueError, TypeError, OverflowError):
        return default


def _s_dict(val):
    return val if isinstance(val, dict) else {}


def _s_list(val):
    return val if isinstance(val, list) else []


def _parse_cores_from_hardware(hw: str) -> int:
    if not hw:
        return 0
    try:
        parts = str(hw).split("/")
        if parts:
            return _s_int(parts[0].strip().split()[0], 0)
    except Exception:
        pass
    return 0


# =========================================================
# FEATURE EXTRACTION
# =========================================================
def _features_from_fields(fields: dict) -> Dict[str, float]:
    time_s = max(0.0, _s_float(fields.get("time_on_page_ms"), 0.0) / 1000.0)
    events_total = _s_int(fields.get("events_total"), 0)
    clicks = _s_int(fields.get("clicks"), 0)

    events_per_sec = (events_total / time_s) if time_s > 0 else 0.0
    clicks_per_min = (clicks / (time_s / 60.0)) if time_s > 0 else 0.0

    screen_w = _s_int(fields.get("screen_w"), 0)
    screen_h = _s_int(fields.get("screen_h"), 0)
    screen_area = float(screen_w * screen_h)
    cores = _s_int(fields.get("cores"), 0)

    return {
        "f_cores": float(cores),
        "f_memory": _s_float(fields.get("memory"), 0.0),
        "f_screen_w": float(screen_w),
        "f_screen_h": float(screen_h),
        "f_pixel_ratio": _s_float(fields.get("pixel_ratio"), 0.0),
        "f_time_on_page_s": time_s,
        "f_events_total": float(events_total),
        "f_mousemove": float(_s_int(fields.get("mousemove"), 0)),
        "f_clicks": float(clicks),
        "f_scrolls": float(_s_int(fields.get("scrolls"), 0)),
        "f_keydowns": float(_s_int(fields.get("keydowns"), 0)),
        "f_touchstarts": float(_s_int(fields.get("touchstarts"), 0)),
        "f_mouse_variance": _s_float(fields.get("mouse_variance"), 0.0),
        "f_mouse_points": float(_s_int(fields.get("mouse_points"), 0)),
        "f_heartbeats": float(_s_int(fields.get("heartbeats"), 0)),
        "f_events_per_sec": events_per_sec,
        "f_clicks_per_min": clicks_per_min,
        "f_screen_area": screen_area,
        "b_webdriver": 1.0 if fields.get("webdriver") else 0.0,
        "b_is_datacenter": 1.0 if fields.get("is_datacenter") else 0.0,
        "b_is_tor": 1.0 if fields.get("is_tor") else 0.0,
        "b_is_vpn": 1.0 if fields.get("is_vpn") else 0.0,
        "b_has_canvas": 1.0 if fields.get("has_canvas") else 0.0,
        "b_has_webgl": 1.0 if fields.get("has_webgl") else 0.0,
        "b_headless_ua": 1.0 if fields.get("headless_ua") else 0.0,
        "b_empty_languages": 1.0 if fields.get("empty_languages") else 0.0,
        "b_low_cores": 1.0 if 0 < cores <= 1 else 0.0,
        "b_absurd_cores": 1.0 if cores > 32 else 0.0,
        "b_no_mouse_no_touch": 1.0 if fields.get("no_mouse_no_touch") else 0.0,
        "b_private_ip": 1.0 if fields.get("private_ip") else 0.0,
        "b_mobile_ua": 1.0 if fields.get("mobile_ua") else 0.0,
        "b_ios_ua": 1.0 if fields.get("ios_ua") else 0.0,
    }


def extract_features_from_data(data: dict, ip_info: dict) -> Dict[str, float]:
    """Extract 32 features from live tracking data."""
    data = _s_dict(data)
    ip_info = _s_dict(ip_info)

    nav = _s_dict(data.get("nav"))
    fp = _s_dict(data.get("fingerprint"))
    behavior = _s_dict(data.get("behavior"))
    events = _s_dict(behavior.get("events"))
    screen = _s_dict(data.get("screen"))
    security = _s_dict(ip_info.get("security"))

    ua = str(nav.get("ua") or "").lower()

    time_ms = _s_int(behavior.get("total_time_ms"), 0)
    if time_ms == 0:
        time_ms = _s_int(behavior.get("time_on_page_ms"), 0)

    mousemove = _s_int(events.get("mousemove"), 0)
    clicks = _s_int(events.get("clicks"), 0)
    scrolls = _s_int(events.get("scrolls"), 0)
    keydowns = _s_int(events.get("keydown"), 0)
    touchstarts = _s_int(events.get("touchstart"), 0)
    events_total = mousemove + clicks + scrolls + keydowns + touchstarts

    canvas = fp.get("canvas_hash")
    has_canvas = bool(canvas) and str(canvas) not in ("blocked", "Unknown", "", "Unknown...", "blocked...")

    webgl = _s_dict(fp.get("webgl"))
    renderer = str(webgl.get("renderer") or "")
    has_webgl = bool(renderer) and renderer not in ("blocked", "Unknown")

    langs = _s_list(fp.get("languages"))
    empty_languages = len(langs) == 0

    mouse_points = _s_int(fp.get("mouse_points_count"), 0)
    if mouse_points == 0:
        mouse_points = _s_int(_s_dict(fp.get("mouse_analysis")).get("total_points"), 0)

    is_datacenter = (
        security.get("hosting") is True
        or str(ip_info.get("type", "")).lower() == "hosting"
    )

    fields = {
        "cores": _s_int(fp.get("hardwareConcurrency"), 0),
        "memory": _s_float(fp.get("deviceMemory"), 0.0),
        "screen_w": _s_int(screen.get("width"), 0),
        "screen_h": _s_int(screen.get("height"), 0),
        "pixel_ratio": _s_float(screen.get("pixelRatio"), 0.0),
        "time_on_page_ms": time_ms,
        "events_total": events_total,
        "mousemove": mousemove,
        "clicks": clicks,
        "scrolls": scrolls,
        "keydowns": keydowns,
        "touchstarts": touchstarts,
        "mouse_variance": _s_float(behavior.get("mouse_velocity_variance"), 0.0),
        "mouse_points": mouse_points,
        "heartbeats": _s_int(data.get("_heartbeat_count"), 0),
        "webdriver": nav.get("webdriver") is True,
        "is_datacenter": is_datacenter,
        "is_tor": False,
        "is_vpn": security.get("vpn") is True or security.get("proxy") is True,
        "has_canvas": has_canvas,
        "has_webgl": has_webgl,
        "headless_ua": "headless" in ua,
        "empty_languages": empty_languages,
        "no_mouse_no_touch": mousemove == 0 and touchstarts == 0,
        "private_ip": False,
        "mobile_ua": "mobile" in ua or "android" in ua or "iphone" in ua,
        "ios_ua": "iphone" in ua or "ipad" in ua or "ipod" in ua,
    }

    return _features_from_fields(fields)


def extract_features_from_visit(visit: Any) -> Dict[str, float]:
    """Extract features from stored VisitModel."""
    if visit is None:
        return {k: 0.0 for k in FEATURE_NAMES}

    evidence = _s_list(getattr(visit, "evidence", None))
    evidence_codes = set()
    for e in evidence:
        if isinstance(e, dict):
            c = e.get("code")
            if c:
                evidence_codes.add(str(c))

    clicks = _s_int(getattr(visit, "clicks", 0), 0)
    scrolls = _s_int(getattr(visit, "scrolls", 0), 0)

    hardware_str = str(getattr(visit, "hardware", "") or "")
    cores = _parse_cores_from_hardware(hardware_str)

    events_total = clicks + scrolls

    fields = {
        "cores": cores,
        "memory": 0.0,
        "screen_w": 0,
        "screen_h": 0,
        "pixel_ratio": 0.0,
        "time_on_page_ms": _s_int(getattr(visit, "time_on_page", 0), 0),
        "events_total": events_total,
        "mousemove": 0,
        "clicks": clicks,
        "scrolls": scrolls,
        "keydowns": 0,
        "touchstarts": 0,
        "mouse_variance": 0.0,
        "mouse_points": 0,
        "heartbeats": 0,
        "webdriver": "WEBDRIVER_FLAG" in evidence_codes,
        "is_datacenter": "DATACENTER_IP" in evidence_codes or "DATACENTER_ASN" in evidence_codes,
        "is_tor": "THREAT_TOR_EXIT" in evidence_codes,
        "is_vpn": bool(getattr(visit, "is_vpn", False)) or "VPN_PROXY" in evidence_codes,
        "has_canvas": bool(getattr(visit, "canvas_hash", "")) and getattr(visit, "canvas_hash", "") not in ("Unknown", "Unknown..."),
        "has_webgl": False,
        "headless_ua": "HEADLESS_UA" in evidence_codes,
        "empty_languages": "LANGUAGES_EMPTY" in evidence_codes,
        "no_mouse_no_touch": "NO_MOUSE_NO_TOUCH" in evidence_codes,
        "private_ip": False,
        "mobile_ua": "mobile" in str(getattr(visit, "device", "")).lower(),
        "ios_ua": str(getattr(visit, "os", "")).lower() == "ios",
    }

    return _features_from_fields(fields)


# =========================================================
# MODEL
# =========================================================
class MLModel:
    def __init__(self, data: Optional[dict] = None):
        self._lock = threading.RLock()
        self._data: Optional[dict] = data
        self._loaded_at: float = time.time() if data else 0.0

    def is_available(self) -> bool:
        with self._lock:
            return self._data is not None

    def info(self) -> dict:
        with self._lock:
            if not self._data:
                return {"available": False}
            return {
                "available": True,
                "version": self._data.get("version"),
                "trained_at": self._data.get("trained_at"),
                "samples": self._data.get("samples"),
                "feature_count": len(self._data.get("features", [])),
            }

    def predict(self, feats: Dict[str, float]) -> float:
        with self._lock:
            data = self._data
        if data is None:
            return 0.5
        try:
            z = float(data.get("intercept", 0.0))
            weights = data.get("weights") or {}
            means = data.get("means") or {}
            stds = data.get("stds") or {}
            for name in data.get("features", []):
                w = float(weights.get(name, 0.0))
                if abs(w) < 1e-12:
                    continue
                m = float(means.get(name, 0.0))
                s = float(stds.get(name, 1.0))
                if s <= 0:
                    s = 1.0
                x = float(feats.get(name, 0.0))
                z += w * ((x - m) / s)
            z = max(-500.0, min(500.0, z))
            return 1.0 / (1.0 + math.exp(-z))
        except Exception as e:
            logger.debug(f"[ML] predict failed: {e}")
            return 0.5


_model: Optional[MLModel] = None
_model_lock = threading.Lock()


def _get_model() -> MLModel:
    global _model
    if _model is None:
        with _model_lock:
            if _model is None:
                _model = MLModel(_load_from_disk())
    return _model


def _load_from_disk() -> Optional[dict]:
    if not os.path.exists(DEFAULT_STORAGE_PATH):
        return None
    try:
        with open(DEFAULT_STORAGE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None
        if "features" not in data or "weights" not in data:
            return None
        return data
    except Exception as e:
        logger.debug(f"[ML] load failed: {e}")
        return None


def reload_model():
    global _model
    with _model_lock:
        _model = MLModel(_load_from_disk())


# =========================================================
# TRAINING
# =========================================================
def train_from_visits(visits: List[Any], epochs: int = 500, lr: float = 0.1, l2: float = 0.01) -> Optional[dict]:
    labeled = [v for v in visits if getattr(v, "ground_truth", None) in ("bot", "human")]
    if len(labeled) < MIN_TRAINING_SAMPLES:
        logger.info(f"[ML] not enough samples: {len(labeled)} (need {MIN_TRAINING_SAMPLES})")
        return None

    X = []
    y = []
    for v in labeled:
        feats = extract_features_from_visit(v)
        X.append([feats.get(k, 0.0) for k in FEATURE_NAMES])
        y.append(1.0 if v.ground_truth == "bot" else 0.0)

    n = len(X)
    d = len(FEATURE_NAMES)

    means = {}
    stds = {}
    for j in range(d):
        col = [X[i][j] for i in range(n)]
        m = sum(col) / n
        var = sum((v - m) ** 2 for v in col) / n
        s = var ** 0.5
        means[FEATURE_NAMES[j]] = m
        stds[FEATURE_NAMES[j]] = s if s > 0 else 1.0

    Xz = []
    for i in range(n):
        Xz.append([(X[i][j] - means[FEATURE_NAMES[j]]) / stds[FEATURE_NAMES[j]] for j in range(d)])

    w = [0.0] * d
    b = 0.0

    for epoch in range(epochs):
        for i in range(n):
            z = b + sum(w[j] * Xz[i][j] for j in range(d))
            z = max(-500.0, min(500.0, z))
            p = 1.0 / (1.0 + math.exp(-z))
            err = p - y[i]
            for j in range(d):
                w[j] -= lr * (err * Xz[i][j] + l2 * w[j])
            b -= lr * err

    return {
        "version": "1.0",
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "samples": n,
        "features": list(FEATURE_NAMES),
        "means": means,
        "stds": stds,
        "weights": {FEATURE_NAMES[j]: w[j] for j in range(d)},
        "intercept": b,
    }


def save_model(model: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(DEFAULT_STORAGE_PATH), exist_ok=True)
        with open(DEFAULT_STORAGE_PATH, "w", encoding="utf-8") as f:
            json.dump(model, f, ensure_ascii=False, indent=2)
        reload_model()
        return True
    except Exception as e:
        logger.error(f"[ML] save failed: {e}")
        return False


# =========================================================
# MAIN CHECK
# =========================================================
def analyze_ml(data: dict, ip_info: dict) -> List[Tuple[str, str, int, str]]:
    items: List[Tuple[str, str, int, str]] = []
    try:
        model = _get_model()
        if not model.is_available():
            return items
        feats = extract_features_from_data(data, ip_info)
        p = model.predict(feats)
        if p >= HIGH_RISK_THRESHOLD:
            items.append(("ML_HIGH_RISK", "high", 70, f"ML model P(bot)={p:.3f}"))
        elif p >= ELEVATED_RISK_THRESHOLD:
            items.append(("ML_ELEVATED_RISK", "medium", 40, f"ML model P(bot)={p:.3f}"))
    except Exception as e:
        logger.debug(f"[ML] analyze_ml failed: {e}")
    return items


# =========================================================
# HEALTH
# =========================================================
def health_status() -> dict:
    try:
        info = _get_model().info()
        return {
            "system": "ml_engine",
            "status": "ok",
            **info,
            "high_risk_threshold": HIGH_RISK_THRESHOLD,
            "elevated_risk_threshold": ELEVATED_RISK_THRESHOLD,
            "feature_count_defined": len(FEATURE_NAMES),
        }
    except Exception as e:
        return {"system": "ml_engine", "status": "error", "error": str(e)}


# =========================================================
# SELF-TEST
# =========================================================
def run_self_test() -> Tuple[bool, List[str]]:
    import tempfile

    results: List[str] = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # Isolate storage path
    global DEFAULT_STORAGE_PATH
    orig_path = DEFAULT_STORAGE_PATH
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)
    os.unlink(tmp_path)
    DEFAULT_STORAGE_PATH = tmp_path
    reload_model()

    try:
        # Test 1: feature names count
        try:
            _chk(len(FEATURE_NAMES) == 32,
                 f"Test 1: 32 feature names defined (got {len(FEATURE_NAMES)})",
                 f"Test 1: expected 32, got {len(FEATURE_NAMES)}")
        except Exception as e:
            _chk(False, "", f"Test 1: crashed ({e})")

        # Test 2: empty data → all features extracted, no crash
        try:
            feats = extract_features_from_data({}, {})
            _chk(len(feats) == 32,
                 "Test 2: empty data → 32 features extracted",
                 f"Test 2: got {len(feats)}")
        except Exception as e:
            _chk(False, "", f"Test 2: crashed ({e})")

        # Test 3: all features are numeric
        try:
            feats = extract_features_from_data({}, {})
            all_numeric = all(isinstance(v, (int, float)) for v in feats.values())
            _chk(all_numeric, "Test 3: all features numeric",
                 "Test 3: non-numeric feature found")
        except Exception as e:
            _chk(False, "", f"Test 3: crashed ({e})")

        # Test 4: no model → predict returns 0.5
        try:
            m = MLModel(None)
            p = m.predict({"f_cores": 8.0})
            _chk(p == 0.5, "Test 4: no model → predict returns 0.5",
                 f"Test 4: got {p}")
        except Exception as e:
            _chk(False, "", f"Test 4: crashed ({e})")

        # Test 5: _parse_cores_from_hardware
        try:
            _chk(_parse_cores_from_hardware("8 cores / 8 GB") == 8,
                 "Test 5: _parse_cores_from_hardware('8 cores / 8 GB') == 8",
                 f"Test 5: got {_parse_cores_from_hardware('8 cores / 8 GB')}")
        except Exception as e:
            _chk(False, "", f"Test 5: crashed ({e})")

        # Test 6: _parse_cores empty
        try:
            _chk(_parse_cores_from_hardware("") == 0,
                 "Test 6: _parse_cores_from_hardware('') == 0",
                 "Test 6: failed")
        except Exception as e:
            _chk(False, "", f"Test 6: crashed ({e})")

        # Test 7: too few samples → train returns None
        try:
            visits = []
            for i in range(10):
                class V:
                    ground_truth = "bot" if i % 2 else "human"
                    evidence = []
                    clicks = 0
                    scrolls = 0
                    time_on_page = 1000
                    hardware = ""
                    is_vpn = False
                    canvas_hash = ""
                    device = "Desktop"
                    os = "Windows"
                visits.append(V())
            model = train_from_visits(visits)
            _chk(model is None, "Test 7: too few samples → None",
                 "Test 7: expected None")
        except Exception as e:
            _chk(False, "", f"Test 7: crashed ({e})")

        # Test 8: training on 100 balanced visits → returns dict
        try:
            visits = []
            for i in range(50):
                class BotV:
                    ground_truth = "bot"
                    evidence = [{"code": "WEBDRIVER_FLAG"}]
                    clicks = 0
                    scrolls = 0
                    time_on_page = 1000
                    hardware = "2 cores / 2 GB"
                    is_vpn = True
                    canvas_hash = "blocked..."
                    device = "Desktop"
                    os = "Linux"
                class HumanV:
                    ground_truth = "human"
                    evidence = []
                    clicks = 5
                    scrolls = 10
                    time_on_page = 30000
                    hardware = "8 cores / 16 GB"
                    is_vpn = False
                    canvas_hash = "abc123..."
                    device = "Desktop"
                    os = "Windows"
                visits.append(BotV())
                visits.append(HumanV())
            model = train_from_visits(visits, epochs=200, lr=0.2)
            _chk(model is not None and model["samples"] == 100,
                 "Test 8: training 100 visits → model returned",
                 f"Test 8: got {model is not None}, samples={model['samples'] if model else 0}")
        except Exception as e:
            _chk(False, "", f"Test 8: crashed ({e})")

        # Test 9: save + load roundtrip
        try:
            visits = []
            for i in range(50):
                class B:
                    ground_truth = "bot"
                    evidence = [{"code": "WEBDRIVER_FLAG"}]
                    clicks = 0
                    scrolls = 0
                    time_on_page = 500
                    hardware = ""
                    is_vpn = True
                    canvas_hash = ""
                    device = "Desktop"
                    os = "Linux"
                class H:
                    ground_truth = "human"
                    evidence = []
                    clicks = 5
                    scrolls = 10
                    time_on_page = 30000
                    hardware = ""
                    is_vpn = False
                    canvas_hash = "abc"
                    device = "Desktop"
                    os = "Windows"
                visits.append(B())
                visits.append(H())
            model = train_from_visits(visits, epochs=200)
            saved = save_model(model)
            _chk(saved and os.path.exists(tmp_path),
                 "Test 9: save_model creates file",
                 "Test 9: failed")
        except Exception as e:
            _chk(False, "", f"Test 9: crashed ({e})")

        # Test 10: prediction after training gives meaningful probability
        try:
            feats_bot = {"f_time_on_page_s": 0.5, "b_webdriver": 1.0, "b_is_vpn": 1.0,
                         "f_clicks": 0.0, "f_scrolls": 0.0}
            feats_human = {"f_time_on_page_s": 30.0, "b_webdriver": 0.0, "b_is_vpn": 0.0,
                          "f_clicks": 5.0, "f_scrolls": 10.0}
            m = _get_model()
            p_bot = m.predict(feats_bot)
            p_human = m.predict(feats_human)
            _chk(p_bot > p_human,
                 f"Test 10: trained model ranks bot > human (bot={p_bot:.2f} vs human={p_human:.2f})",
                 f"Test 10: bot={p_bot:.2f}, human={p_human:.2f}")
        except Exception as e:
            _chk(False, "", f"Test 10: crashed ({e})")

        # Test 11: analyze_ml returns signals when model says high risk
        try:
            r = analyze_ml(
                {"behavior": {"total_time_ms": 500, "events": {}},
                 "nav": {"webdriver": True},
                 "fingerprint": {"languages": ["en-US"]},
                 "screen": {},
                 "_heartbeat_count": 0},
                {"security": {"vpn": True, "proxy": True}},
            )
            codes = {item[0] for item in r}
            _chk("ML_HIGH_RISK" in codes or "ML_ELEVATED_RISK" in codes,
                 f"Test 11: analyze_ml fires for high-risk visit (got {codes})",
                 f"Test 11: got {codes}")
        except Exception as e:
            _chk(False, "", f"Test 11: crashed ({e})")

        # Test 12: analyze_ml returns [] on error (graceful)
        try:
            r = analyze_ml(None, None)
            _chk(isinstance(r, list),
                 "Test 12: analyze_ml(None, None) returns list",
                 f"Test 12: got {type(r)}")
        except Exception as e:
            _chk(False, "", f"Test 12: crashed ({e})")

        # Test 13: health_status works
        try:
            h = health_status()
            _chk(isinstance(h, dict) and h.get("system") == "ml_engine",
                 "Test 13: health_status valid",
                 f"Test 13: got {h}")
        except Exception as e:
            _chk(False, "", f"Test 13: crashed ({e})")

        # Test 14: missing feature in predict → treated as 0 (no crash)
        try:
            m = _get_model()
            p = m.predict({"unknown_feature": 999.0})
            _chk(0.0 <= p <= 1.0, "Test 14: missing features → no crash",
                 f"Test 14: got {p}")
        except Exception as e:
            _chk(False, "", f"Test 14: crashed ({e})")

        # Test 15: reload clears and loads from disk
        try:
            reload_model()
            m = _get_model()
            _chk(m.is_available(), "Test 15: reload_model loads saved model",
                 "Test 15: model not available after reload")
        except Exception as e:
            _chk(False, "", f"Test 15: crashed ({e})")

        # Test 16: no file → no model
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            reload_model()
            m = _get_model()
            _chk(not m.is_available(), "Test 16: missing file → no model",
                 "Test 16: model available after file deleted")
        except Exception as e:
            _chk(False, "", f"Test 16: crashed ({e})")

        # Test 17: extract_features_from_visit on None returns zeros
        try:
            feats = extract_features_from_visit(None)
            _chk(len(feats) == 32 and all(v == 0.0 for v in feats.values()),
                 "Test 17: extract_features_from_visit(None) → 32 zeros",
                 f"Test 17: got {len(feats)} features")
        except Exception as e:
            _chk(False, "", f"Test 17: crashed ({e})")

        # Test 18: thread safety in training
        try:
            visits = []
            for i in range(50):
                class B:
                    ground_truth = "bot"
                    evidence = []
                    clicks = 0
                    scrolls = 0
                    time_on_page = 500
                    hardware = ""
                    is_vpn = True
                    canvas_hash = ""
                    device = "Desktop"
                    os = "Linux"
                class H:
                    ground_truth = "human"
                    evidence = []
                    clicks = 5
                    scrolls = 10
                    time_on_page = 30000
                    hardware = ""
                    is_vpn = False
                    canvas_hash = "abc"
                    device = "Desktop"
                    os = "Windows"
                visits.append(B())
                visits.append(H())
            errors = []
            def worker():
                try:
                    train_from_visits(visits, epochs=50)
                except Exception as ex:
                    errors.append(str(ex))
            threads = [threading.Thread(target=worker) for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            _chk(len(errors) == 0, "Test 18: thread safety (3 concurrent trainings)",
                 f"Test 18: got {len(errors)} errors")
        except Exception as e:
            _chk(False, "", f"Test 18: crashed ({e})")

    finally:
        DEFAULT_STORAGE_PATH = orig_path
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        reload_model()

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 8: ML ENGINE — SELF TEST")
    print("=" * 70)
    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 8] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 8 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 8] ML engine self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 8 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 8] {r}")
    print("=" * 70 + "\n")
    return ok


_SELF_TEST_PASSED: Optional[bool] = None


def _should_run_self_test() -> bool:
    if os.getenv("OVG_SELF_TEST_ENABLED", "1") != "1":
        return False
    if "pytest" in sys.modules:
        return False
    return True


if _should_run_self_test():
    try:
        _SELF_TEST_PASSED = print_self_test()
    except Exception as e:
        print(f"⚠️  [SYSTEM 8] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False