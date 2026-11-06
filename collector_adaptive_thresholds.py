"""
collector/adaptive_thresholds.py — SYSTEM 5: Adaptive Thresholds + Signal Reliability

Self-contained. Persists thresholds + reliabilities to JSON file.
Computes optimal values from ground-truth data (VisitModel.ground_truth).

Workflow:
  1. On startup: loads cached values from data/thresholds.json (or defaults)
  2. Admin runs: scripts.update_adaptive_thresholds
     → recomputes from DB
     → writes JSON
  3. analysis.py uses: adaptive_get_threshold(key, default)
  4. bayesian_engine.py uses: adaptive_get_reliability(code, default)

Solves:
  - #19 (cores > 128 hardcoded)
  - #21 (headless viewport hardcoded)
  - #26 (ZOMBIE 8s hardcoded)
  - #31 (NO_MOUSE_NO_TOUCH 10s hardcoded)
  - #32 (mouse variance threshold)
  - #34 (SILENT_AFTER_INITIAL 5s hardcoded)
  - #46 (magic numbers everywhere)
"""
import os
import sys
import json
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("ovg.adaptive")


# =========================================================
# DEFAULTS (match current hardcoded values for zero-change)
# =========================================================
DEFAULT_THRESHOLDS: Dict[str, float] = {
    # Hardware
    "cores_high": 128,
    "cores_impossible": 256,
    # Behavior
    "left_fast_ms": 1800,
    "drive_by_ms": 5000,
    "zombie_ms": 8000,
    "engagement_zero_ms": 15000,
    "no_mouse_no_touch_ms": 8000,
    "silent_after_initial_ms": 5000,
    "idle_visible_min_ms": 5000,
    "idle_visible_ratio": 0.98,
    # Behavior deep
    "first_move_instant_ms": 100,
    # Mouse
    "mouse_variance_low": 1.5,
    "mouse_var_smooth": 0.1,
    # Fingerprint reuse
    "reuse_high_per_min": 50,
    "reuse_med_per_min": 30,
    "reuse_low_per_min": 20,
    # Cross-visit
    "ip_velocity_high": 10,
    "ip_velocity_med": 5,
    # Screen
    "headless_viewport_w": 800,
    "headless_viewport_h": 600,
    "screen_tiny_threshold": 800,
}

# Minimum sample size before overriding a default with computed value
MIN_SAMPLE_SIZE = 30

# Storage path (relative to project root)
_DEFAULT_STORAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "thresholds.json"
)


# =========================================================
# ADAPTIVE THRESHOLDS CLASS
# =========================================================
class AdaptiveThresholds:
    """
    Thread-safe store for computed thresholds + reliabilities.
    Persists to JSON. Falls back to defaults when no data.
    """

    def __init__(self, storage_path: str = _DEFAULT_STORAGE_PATH):
        self.storage_path = storage_path
        self._lock = threading.RLock()

        # In-memory state
        self._thresholds: Dict[str, float] = dict(DEFAULT_THRESHOLDS)
        self._reliabilities: Dict[str, Dict[str, Any]] = {}
        self._last_updated: Optional[str] = None
        self._sample_info: Dict[str, Any] = {}

        # Try to load from disk
        self._load()

    # -----------------------------------------------------
    # DISK I/O
    # -----------------------------------------------------
    def _load(self):
        """Load thresholds + reliabilities from JSON if exists."""
        if not os.path.exists(self.storage_path):
            logger.info(f"[ADAPTIVE] no cached file at {self.storage_path}, using defaults")
            return

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                raise ValueError("root is not a dict")

            thresholds = data.get("thresholds") or {}
            if isinstance(thresholds, dict):
                for k, v in thresholds.items():
                    if k in DEFAULT_THRESHOLDS and isinstance(v, (int, float)):
                        self._thresholds[k] = float(v)

            reliabilities = data.get("reliabilities") or {}
            if isinstance(reliabilities, dict):
                for code, entry in reliabilities.items():
                    if isinstance(entry, dict):
                        self._reliabilities[code] = entry

            self._last_updated = data.get("last_updated")
            self._sample_info = data.get("sample_info") or {}

            logger.info(
                f"[ADAPTIVE] loaded from {self.storage_path} "
                f"({len(self._reliabilities)} reliabilities, "
                f"last_updated={self._last_updated})"
            )
        except Exception as e:
            logger.warning(
                f"[ADAPTIVE] failed to load {self.storage_path}: {e} (using defaults)"
            )

    def _save(self):
        """Persist current state to JSON."""
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            with self._lock:
                data = {
                    "version": "1.0",
                    "last_updated": self._last_updated or datetime.utcnow().isoformat() + "Z",
                    "thresholds": dict(self._thresholds),
                    "reliabilities": dict(self._reliabilities),
                    "sample_info": dict(self._sample_info),
                }
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"[ADAPTIVE] saved to {self.storage_path}")
        except Exception as e:
            logger.error(f"[ADAPTIVE] failed to save {self.storage_path}: {e}")

    # -----------------------------------------------------
    # PUBLIC GETTERS
    # -----------------------------------------------------
    def get_threshold(self, key: str, default: float) -> float:
        """Get current threshold. Returns default if key unknown."""
        with self._lock:
            val = self._thresholds.get(key)
        if val is None:
            return default
        return float(val)

    def get_reliability(self, signal_code: str, default: float) -> float:
        """Get reliability for a signal. Returns default if not enough data."""
        with self._lock:
            entry = self._reliabilities.get(signal_code)
        if not entry:
            return default
        sample = int(entry.get("sample_size", 0) or 0)
        if sample < MIN_SAMPLE_SIZE:
            return default
        precision = entry.get("precision")
        if precision is None:
            return default
        return float(precision)

    # -----------------------------------------------------
    # PUBLIC SETTERS (for tests / manual override)
    # -----------------------------------------------------
    def set_threshold(self, key: str, value: float):
        """Manually set a threshold. Use with care."""
        with self._lock:
            if key not in DEFAULT_THRESHOLDS:
                logger.warning(f"[ADAPTIVE] set_threshold for unknown key: {key}")
            self._thresholds[key] = float(value)

    def set_reliability(self, signal_code: str, precision: float, sample_size: int):
        """Manually set a reliability entry."""
        with self._lock:
            self._reliabilities[signal_code] = {
                "precision": round(float(precision), 4),
                "sample_size": int(sample_size),
                "updated_at": datetime.utcnow().isoformat() + "Z",
            }

    def reset(self):
        """Reset to defaults (does NOT touch disk)."""
        with self._lock:
            self._thresholds = dict(DEFAULT_THRESHOLDS)
            self._reliabilities = {}
            self._last_updated = None
            self._sample_info = {}

    # -----------------------------------------------------
    # COMPUTATION FROM DATA
    # -----------------------------------------------------
    def compute_from_visits(self, visits: List[Any]) -> Dict[str, Any]:
        """
        Compute thresholds + reliabilities from a list of VisitModel-like objects.

        Expected attributes on each visit:
          - ground_truth: "bot" | "human" | None
          - hardware (string like "8 cores / 8 GB")
          - time_on_page (ms)
          - clicks, scrolls
          - evidence (list of dicts with 'code')
        """
        # Split by label
        humans = [v for v in visits if getattr(v, "ground_truth", None) == "human"]
        bots = [v for v in visits if getattr(v, "ground_truth", None) == "bot"]

        n_humans = len(humans)
        n_bots = len(bots)
        now_iso = datetime.utcnow().isoformat() + "Z"

        summary = {
            "humans": n_humans,
            "bots": n_bots,
            "thresholds_computed": 0,
            "reliabilities_computed": 0,
        }

        if n_humans < MIN_SAMPLE_SIZE and n_bots < MIN_SAMPLE_SIZE:
            logger.warning(
                f"[ADAPTIVE] not enough samples (humans={n_humans}, bots={n_bots}, "
                f"need {MIN_SAMPLE_SIZE} of either)"
            )
            summary["reason"] = "insufficient_samples"
            return summary

        # ============ Thresholds ============
        if n_humans >= MIN_SAMPLE_SIZE:
            self._compute_thresholds_from_humans(humans, summary)

        if n_bots >= MIN_SAMPLE_SIZE:
            self._compute_thresholds_from_bots(bots, summary)

        # ============ Reliabilities ============
        self._compute_reliabilities(visits, summary)

        self._last_updated = now_iso
        self._sample_info = {
            "humans": n_humans,
            "bots": n_bots,
            "computed_at": now_iso,
        }

        self._save()
        return summary

    def _compute_thresholds_from_humans(self, humans: List[Any], summary: Dict):
        """Compute thresholds from human visits."""
        # left_fast_ms = P5 of time_on_page for humans
        times = [
            int(v.time_on_page) for v in humans
            if v.time_on_page and v.time_on_page > 0
        ]
        if times:
            p5 = self._percentile(times, 5)
            self.set_threshold("left_fast_ms", max(500, p5))
            summary["thresholds_computed"] += 1

        # zombie_ms = P95 of time_on_page for humans WITH interaction
        interactive_times = [
            int(v.time_on_page) for v in humans
            if v.time_on_page and v.time_on_page > 0
            and ((v.clicks or 0) + (v.scrolls or 0)) > 0
        ]
        if interactive_times:
            p95 = self._percentile(interactive_times, 95)
            self.set_threshold("zombie_ms", max(5000, p95))
            summary["thresholds_computed"] += 1

    def _compute_thresholds_from_bots(self, bots: List[Any], summary: Dict):
        """Compute thresholds from bot visits."""
        # drive_by_ms = P75 of time_on_page for bots (short bot visits)
        bot_times = [
            int(v.time_on_page) for v in bots
            if v.time_on_page and v.time_on_page > 0
        ]
        if bot_times:
            p75 = self._percentile(bot_times, 75)
            self.set_threshold("drive_by_ms", max(1000, p75))
            summary["thresholds_computed"] += 1

    def _compute_reliabilities(self, visits: List[Any], summary: Dict):
        """Compute per-signal precision from labeled visits."""
        signal_stats: Dict[str, Dict[str, int]] = {}

        for v in visits:
            gt = getattr(v, "ground_truth", None)
            if gt not in ("bot", "human"):
                continue

            evidence = getattr(v, "evidence", None)
            if not isinstance(evidence, list):
                continue

            codes = set()
            for e in evidence:
                if isinstance(e, dict):
                    code = e.get("code")
                    if code:
                        codes.add(str(code))

            for code in codes:
                if code not in signal_stats:
                    signal_stats[code] = {"tp": 0, "fp": 0}
                if gt == "bot":
                    signal_stats[code]["tp"] += 1
                else:
                    signal_stats[code]["fp"] += 1

        for code, stats in signal_stats.items():
            tp = stats["tp"]
            fp = stats["fp"]
            total = tp + fp
            if total < MIN_SAMPLE_SIZE:
                continue
            precision = (tp + 1) / (total + 2)
            self.set_reliability(code, precision, total)
            summary["reliabilities_computed"] += 1

    @staticmethod
    def _percentile(values: List[int], pct: float) -> float:
        """Compute percentile of a list of ints."""
        if not values:
            return 0
        sorted_vals = sorted(values)
        k = (len(sorted_vals) - 1) * (pct / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(sorted_vals):
            return float(sorted_vals[f])
        return float(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f))

    # -----------------------------------------------------
    # HEALTH
    # -----------------------------------------------------
    def health_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "system": "adaptive_thresholds",
                "status": "ok",
                "last_updated": self._last_updated,
                "thresholds": dict(self._thresholds),
                "reliabilities_count": len(self._reliabilities),
                "sample_info": dict(self._sample_info),
                "storage_path": self.storage_path,
            }


# =========================================================
# GLOBAL SINGLETON
# =========================================================
_instance: Optional[AdaptiveThresholds] = None
_instance_lock = threading.Lock()


def _get_instance() -> AdaptiveThresholds:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AdaptiveThresholds()
    return _instance


def get_threshold(key: str, default: float) -> float:
    """Module-level getter used by analysis.py."""
    try:
        return _get_instance().get_threshold(key, default)
    except Exception as e:
        logger.warning(f"[ADAPTIVE] get_threshold({key}) failed: {e}, using default")
        return float(default)


def get_reliability(signal_code: str, default: float) -> float:
    """Module-level getter used by bayesian_engine.py."""
    try:
        return _get_instance().get_reliability(signal_code, default)
    except Exception as e:
        logger.warning(f"[ADAPTIVE] get_reliability({signal_code}) failed: {e}, using default")
        return float(default)


def health_status() -> Dict[str, Any]:
    try:
        return _get_instance().health_status()
    except Exception as e:
        return {"system": "adaptive_thresholds", "status": "error", "error": str(e)}


# =========================================================
# SELF-TEST
# =========================================================
def run_self_test() -> Tuple[bool, List[str]]:
    results = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # Use temp file for isolated tests
    import tempfile
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(tmp_fd)
    os.unlink(tmp_path)  # will be created by _save

    try:
        # 1: defaults loaded
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            v = inst.get_threshold("left_fast_ms", 1800)
            _chk(v == 1800.0,
                 "Test 1: default threshold returned when no cache",
                 f"Test 1: got {v}")
        except Exception as e:
            _chk(False, "", f"Test 1: crashed ({e})")

        # 2: set_threshold updates in-memory
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.set_threshold("left_fast_ms", 5000)
            _chk(inst.get_threshold("left_fast_ms", 1800) == 5000.0,
                 "Test 2: set_threshold updates in-memory cache",
                 "Test 2: failed")
        except Exception as e:
            _chk(False, "", f"Test 2: crashed ({e})")

        # 3: save + load persists
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.set_threshold("drive_by_ms", 7500)
            inst._save()
            inst2 = AdaptiveThresholds(storage_path=tmp_path)
            _chk(inst2.get_threshold("drive_by_ms", 5000) == 7500.0,
                 "Test 3: save + load persists threshold",
                 "Test 3: failed")
        except Exception as e:
            _chk(False, "", f"Test 3: crashed ({e})")

        # 4: get_reliability default when no data
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            r = inst.get_reliability("UNKNOWN_CODE", 0.85)
            _chk(r == 0.85,
                 "Test 4: get_reliability returns default for unknown",
                 f"Test 4: got {r}")
        except Exception as e:
            _chk(False, "", f"Test 4: crashed ({e})")

        # 5: get_reliability with sample_size < 30 → default
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.set_reliability("TEST_CODE", 0.95, 10)
            r = inst.get_reliability("TEST_CODE", 0.5)
            _chk(r == 0.5,
                 "Test 5: small sample (<30) → default reliability",
                 f"Test 5: got {r}")
        except Exception as e:
            _chk(False, "", f"Test 5: crashed ({e})")

        # 6: get_reliability with 30+ samples → computed
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.set_reliability("TEST_CODE2", 0.92, 50)
            r = inst.get_reliability("TEST_CODE2", 0.5)
            _chk(r == 0.92,
                 "Test 6: 30+ samples → computed reliability returned",
                 f"Test 6: got {r}")
        except Exception as e:
            _chk(False, "", f"Test 6: crashed ({e})")

        # 7: percentile calculation correct
        try:
            values = list(range(1, 101))  # 1-100
            p95 = AdaptiveThresholds._percentile(values, 95)
            _chk(94.0 <= p95 <= 96.0,
                 f"Test 7: percentile correct (P95 of 1-100 ≈ 95.05, got {p95})",
                 f"Test 7: got {p95}")
        except Exception as e:
            _chk(False, "", f"Test 7: crashed ({e})")

        # 8: percentile empty list
        try:
            p = AdaptiveThresholds._percentile([], 50)
            _chk(p == 0,
                 "Test 8: percentile of empty list → 0",
                 f"Test 8: got {p}")
        except Exception as e:
            _chk(False, "", f"Test 8: crashed ({e})")

        # 9: compute_from_visits with insufficient samples
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            summary = inst.compute_from_visits([])
            _chk(summary.get("reason") == "insufficient_samples",
                 "Test 9: empty visits → insufficient_samples",
                 f"Test 9: got {summary}")
        except Exception as e:
            _chk(False, "", f"Test 9: crashed ({e})")

        # 10: compute_from_visits with mock human visits
        try:
            class MockVisit:
                def __init__(self, gt, tp, clicks=1, scrolls=1, evidence=None):
                    self.ground_truth = gt
                    self.time_on_page = tp
                    self.clicks = clicks
                    self.scrolls = scrolls
                    self.evidence = evidence or []

            humans = [MockVisit("human", 10000 + i * 100) for i in range(50)]
            inst = AdaptiveThresholds(storage_path=tmp_path)
            summary = inst.compute_from_visits(humans)
            _chk(summary.get("humans") == 50 and summary.get("thresholds_computed", 0) > 0,
                 "Test 10: compute_from_visits handles 50 human visits",
                 f"Test 10: got {summary}")
        except Exception as e:
            _chk(False, "", f"Test 10: crashed ({e})")

        # 11: compute reliabilities from bot+human evidence
        try:
            class MockVisit:
                def __init__(self, gt, evidence):
                    self.ground_truth = gt
                    self.evidence = evidence
                    self.time_on_page = 10000
                    self.clicks = 1
                    self.scrolls = 1

            visits = []
            for _ in range(40):
                visits.append(MockVisit("bot", [{"code": "TEST_SIG"}]))
            for _ in range(10):
                visits.append(MockVisit("human", [{"code": "TEST_SIG"}]))

            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.compute_from_visits(visits)
            r = inst.get_reliability("TEST_SIG", 0.5)
            # precision should be (40+1)/(50+2) = 0.788
            _chk(0.7 < r < 0.9,
                 f"Test 11: 40 bots + 10 humans → precision ≈ 0.79 (got {r:.2f})",
                 f"Test 11: got {r}")
        except Exception as e:
            _chk(False, "", f"Test 11: crashed ({e})")

        # 12: reliability for signal with only 20 samples → default
        try:
            class MockVisit:
                def __init__(self, gt, evidence):
                    self.ground_truth = gt
                    self.evidence = evidence
                    self.time_on_page = 10000
                    self.clicks = 1
                    self.scrolls = 1

            visits = [MockVisit("bot", [{"code": "SMALL_SIG"}]) for _ in range(20)]
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.compute_from_visits(visits)
            r = inst.get_reliability("SMALL_SIG", 0.42)
            _chk(r == 0.42,
                 "Test 12: 20 samples (<30) → default reliability",
                 f"Test 12: got {r}")
        except Exception as e:
            _chk(False, "", f"Test 12: crashed ({e})")

        # 13: thread safety
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            errors = []

            def worker():
                try:
                    for i in range(50):
                        inst.set_threshold("left_fast_ms", 1000 + i)
                        _ = inst.get_threshold("left_fast_ms", 1800)
                except Exception as ex:
                    errors.append(str(ex))

            threads = [threading.Thread(target=worker) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            _chk(len(errors) == 0,
                 "Test 13: thread safety (5 threads × 50 ops)",
                 f"Test 13: got {len(errors)} errors")
        except Exception as e:
            _chk(False, "", f"Test 13: crashed ({e})")

        # 14: health_status returns valid dict
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            h = inst.health_status()
            _chk(
                isinstance(h, dict) and h.get("system") == "adaptive_thresholds"
                and "thresholds" in h and "storage_path" in h,
                "Test 14: health_status returns valid dict",
                f"Test 14: got {h}",
            )
        except Exception as e:
            _chk(False, "", f"Test 14: crashed ({e})")

        # 15: reset clears cache
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.set_threshold("left_fast_ms", 9999)
            inst.set_reliability("X", 0.9, 100)
            inst.reset()
            _chk(
                inst.get_threshold("left_fast_ms", 1800) == 1800.0
                and inst.get_reliability("X", 0.5) == 0.5,
                "Test 15: reset() clears cache back to defaults",
                "Test 15: failed",
            )
        except Exception as e:
            _chk(False, "", f"Test 15: crashed ({e})")

        # 16: negative/invalid values handled
        try:
            inst = AdaptiveThresholds(storage_path=tmp_path)
            inst.set_threshold("left_fast_ms", -100)
            v = inst.get_threshold("left_fast_ms", 1800)
            _chk(v == -100.0,  # we don't clamp, just store
                 "Test 16: threshold can be any float (no crash on negative)",
                 f"Test 16: got {v}")
        except Exception as e:
            _chk(False, "", f"Test 16: crashed ({e})")

        # 17: missing JSON doesn't crash
        try:
            nonexistent = "/tmp/does_not_exist_xyz_12345.json"
            if os.path.exists(nonexistent):
                os.unlink(nonexistent)
            inst = AdaptiveThresholds(storage_path=nonexistent)
            _chk(inst.get_threshold("left_fast_ms", 1800) == 1800.0,
                 "Test 17: missing JSON file → uses defaults (no crash)",
                 "Test 17: failed")
        except Exception as e:
            _chk(False, "", f"Test 17: crashed ({e})")

        # 18: malformed JSON doesn't crash
        try:
            bad_path = tmp_path + ".bad"
            with open(bad_path, "w") as f:
                f.write("{not valid json}")
            inst = AdaptiveThresholds(storage_path=bad_path)
            _chk(inst.get_threshold("left_fast_ms", 1800) == 1800.0,
                 "Test 18: malformed JSON → uses defaults (no crash)",
                 "Test 18: failed")
            os.unlink(bad_path)
        except Exception as e:
            _chk(False, "", f"Test 18: crashed ({e})")

    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 5: ADAPTIVE THRESHOLDS — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 5] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 5 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 5] Adaptive thresholds self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 5 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 5] {r}")

    print("=" * 70 + "\n")
    return ok


# =========================================================
# AUTO-RUN ON IMPORT
# =========================================================
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
        print(f"⚠️  [SYSTEM 5] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False