"""
collector/circuit_breaker.py — SYSTEM 1: Circuit Breaker + Observability

Self-contained. No imports from other project files (except standard lib).
Integrates with analysis.py via the `safe_call` wrapper.

Philosophy:
  - A single failing check must NEVER crash the entire analysis pipeline.
  - Every check is wrapped in its own circuit breaker.
  - When a check fails repeatedly, its breaker opens and subsequent calls
    are skipped instantly (returning empty result) until it recovers.
  - All activity is logged and queryable via `health_status()`.

States:
  CLOSED     — normal operation, all calls go through
  OPEN       — circuit is broken, calls are skipped instantly
  HALF_OPEN  — recovery trial, limited calls allowed to test
"""
import os
import sys
import time
import logging
import threading
from enum import Enum
from typing import Callable, Any, Optional, Dict, List, Tuple
from collections import deque
from datetime import datetime

logger = logging.getLogger("ovg.circuit_breaker")


# =========================================================
# STATE
# =========================================================
class BreakerState(Enum):
    CLOSED = "closed"
    HALF_OPEN = "half_open"
    OPEN = "open"


# =========================================================
# CIRCUIT BREAKER
# =========================================================
class CircuitBreaker:
    """
    Thread-safe circuit breaker.

    Args:
        name: unique identifier (used in logs / stats)
        failure_threshold: consecutive failures before opening
        recovery_timeout_s: seconds to wait before HALF_OPEN trial
        half_open_max_calls: max calls allowed in HALF_OPEN state
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout_s: float = 30.0,
        half_open_max_calls: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.half_open_max_calls = half_open_max_calls

        self._lock = threading.RLock()
        self._state = BreakerState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._total_calls = 0
        self._total_failures = 0
        self._total_skipped = 0
        self._last_failure_time = 0.0
        self._opened_at = 0.0
        self._half_open_calls = 0
        self._recent_errors = deque(maxlen=10)

    @property
    def state(self) -> BreakerState:
        with self._lock:
            if self._state == BreakerState.OPEN:
                if time.time() - self._opened_at >= self.recovery_timeout_s:
                    self._state = BreakerState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info(f"[BREAKER] {self.name} -> HALF_OPEN (trial)")
            return self._state

    def call(self, fn: Callable, *args, fallback=None, **kwargs) -> Any:
        """
        Execute fn with circuit breaker protection.

        Returns fn's result on success, fallback on failure/skip.
        Never raises.
        """
        current_state = self.state

        with self._lock:
            self._total_calls += 1

            if current_state == BreakerState.OPEN:
                self._total_skipped += 1
                logger.debug(f"[BREAKER] {self.name} skipped (state=OPEN)")
                return fallback

            if current_state == BreakerState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    self._total_skipped += 1
                    logger.debug(f"[BREAKER] {self.name} skipped (HALF_OPEN quota full)")
                    return fallback
                self._half_open_calls += 1

        try:
            result = fn(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            return fallback

    def _on_success(self):
        with self._lock:
            self._success_count += 1
            if self._state == BreakerState.HALF_OPEN:
                self._state = BreakerState.CLOSED
                self._failure_count = 0
                self._half_open_calls = 0
                logger.info(f"[BREAKER] {self.name} -> CLOSED (recovered)")
            else:
                self._failure_count = 0

    def _on_failure(self, error: Exception):
        with self._lock:
            self._failure_count += 1
            self._total_failures += 1
            self._last_failure_time = time.time()
            self._recent_errors.append({
                "time": datetime.utcnow().isoformat() + "Z",
                "type": type(error).__name__,
                "error": str(error)[:200],
            })

            if self._state == BreakerState.HALF_OPEN:
                self._state = BreakerState.OPEN
                self._opened_at = time.time()
                logger.warning(f"[BREAKER] {self.name} -> OPEN (trial failed)")
            elif self._failure_count >= self.failure_threshold:
                self._state = BreakerState.OPEN
                self._opened_at = time.time()
                logger.error(
                    f"[BREAKER] {self.name} -> OPEN "
                    f"({self._failure_count} consecutive failures)"
                )

    def reset(self):
        """Force-reset to CLOSED (for tests or manual recovery)."""
        with self._lock:
            self._state = BreakerState.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0
            logger.info(f"[BREAKER] {self.name} -> CLOSED (manual reset)")

    def stats(self) -> dict:
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "total_calls": self._total_calls,
                "total_failures": self._total_failures,
                "total_skipped": self._total_skipped,
                "failure_rate": round(
                    self._total_failures / self._total_calls, 4
                ) if self._total_calls > 0 else 0.0,
                "last_failure": self._recent_errors[-1] if self._recent_errors else None,
                "recent_errors": list(self._recent_errors),
            }


# =========================================================
# REGISTRY
# =========================================================
class BreakerRegistry:
    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.RLock()

    def register(self, name: str, **kwargs) -> CircuitBreaker:
        with self._lock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(name=name, **kwargs)
            return self._breakers[name]

    def get(self, name: str) -> Optional[CircuitBreaker]:
        return self._breakers.get(name)

    def all_stats(self) -> List[dict]:
        return [b.stats() for b in self._breakers.values()]

    def reset_all(self):
        for b in self._breakers.values():
            b.reset()


# Global registry
breakers = BreakerRegistry()


# Pre-register all the checks from analysis.py
# (this ensures /health/breakers shows them all even before first call)
_CHECK_NAMES = [
    "critical",
    "automation_globals",
    "honeypot",
    "bot_ua",
    "network",
    "fingerprint",
    "fingerprint_reuse",
    "cross_visit",
    "hardware",
    "screen",
    "os_mismatch",
    "contradictions",
    "locale",
    "timezone",
    "behavior",
    "behavior_deep",
    "v3_signals",
    "webgl",
    "cpm",
    "human",
]

for _name in _CHECK_NAMES:
    breakers.register(_name)


# =========================================================
# SAFE CALL — the wrapper used by analysis.py
# =========================================================
def safe_call(check_fn: Callable, *args, check_name: str = None, fallback=None) -> list:
    """
    Call a check function with circuit-breaker protection.

    ALWAYS returns a list (empty on failure or when breaker is open).
    NEVER raises.
    """
    name = check_name or getattr(check_fn, "__name__", "unknown")
    breaker = breakers.register(name)

    try:
        result = breaker.call(check_fn, *args, fallback=fallback)
    except Exception as e:
        logger.exception(f"[SAFE_CALL] breaker.call itself crashed for '{name}': {e}")
        return []

    if result is None:
        return []

    if not isinstance(result, (list, tuple)):
        logger.warning(
            f"[SAFE_CALL] '{name}' returned {type(result).__name__}, expected list"
        )
        return []

    return list(result)


# =========================================================
# HEALTH / OBSERVABILITY
# =========================================================
def health_status() -> dict:
    """Return current state of all breakers (for /health endpoint)."""
    all_stats = breakers.all_stats()
    open_count = sum(1 for s in all_stats if s["state"] == "open")
    return {
        "system": "circuit_breaker",
        "status": "degraded" if open_count > 0 else "ok",
        "open_breakers": open_count,
        "total_breakers": len(all_stats),
        "breakers": all_stats,
    }


# =========================================================
# SELF-TEST
# =========================================================
def run_self_test() -> Tuple[bool, List[str]]:
    """
    Run comprehensive self-tests on circuit breaker.
    Returns (success, list of result strings).
    """
    results: List[str] = []
    success = True

    def _check(cond: bool, msg_pass: str, msg_fail: str):
        nonlocal success
        if cond:
            results.append(f"✓ {msg_pass}")
        else:
            results.append(f"✗ {msg_fail}")
            success = False

    # --- Test 1: success case ---
    try:
        cb = CircuitBreaker("test_success", failure_threshold=3)
        r = cb.call(lambda: 42)
        _check(r == 42 and cb.state == BreakerState.CLOSED,
               "Test 1: success returns value & stays CLOSED",
               f"Test 1: failed (result={r}, state={cb.state.value})")
    except Exception as e:
        _check(False, "", f"Test 1: crashed ({e})")

    # --- Test 2: opens after threshold ---
    try:
        cb = CircuitBreaker("test_open", failure_threshold=3)
        for _ in range(3):
            cb.call(lambda: 1 / 0)
        _check(cb.state == BreakerState.OPEN,
               "Test 2: opens after 3 consecutive failures",
               f"Test 2: expected OPEN, got {cb.state.value}")
    except Exception as e:
        _check(False, "", f"Test 2: crashed ({e})")

    # --- Test 3: open skips calls ---
    try:
        cb = CircuitBreaker("test_skip", failure_threshold=1)
        cb.call(lambda: 1 / 0)  # open it
        call_count = {"n": 0}

        def counting():
            call_count["n"] += 1
            return "should not run"

        r = cb.call(counting, fallback="fallback")
        _check(r == "fallback" and call_count["n"] == 0,
               "Test 3: OPEN breaker skips call & returns fallback",
               f"Test 3: failed (result={r}, calls={call_count['n']})")
    except Exception as e:
        _check(False, "", f"Test 3: crashed ({e})")

    # --- Test 4: recovery via HALF_OPEN ---
    try:
        cb = CircuitBreaker("test_recover", failure_threshold=1, recovery_timeout_s=0.05)
        cb.call(lambda: 1 / 0)  # open
        time.sleep(0.06)
        _ = cb.state  # trigger HALF_OPEN transition
        was_half = cb.state == BreakerState.HALF_OPEN
        r = cb.call(lambda: "recovered")
        _check(
            was_half and r == "recovered" and cb.state == BreakerState.CLOSED,
            "Test 4: HALF_OPEN trial succeeds & recovers to CLOSED",
            f"Test 4: failed (was_half={was_half}, result={r}, final={cb.state.value})",
        )
    except Exception as e:
        _check(False, "", f"Test 4: crashed ({e})")

    # --- Test 5: HALF_OPEN failure reopens ---
    try:
        cb = CircuitBreaker("test_half_fail", failure_threshold=1, recovery_timeout_s=0.05)
        cb.call(lambda: 1 / 0)
        time.sleep(0.06)
        _ = cb.state  # HALF_OPEN
        cb.call(lambda: 1 / 0)  # trial fails
        _check(cb.state == BreakerState.OPEN,
               "Test 5: HALF_OPEN failure reopens breaker",
               f"Test 5: expected OPEN, got {cb.state.value}")
    except Exception as e:
        _check(False, "", f"Test 5: crashed ({e})")

    # --- Test 6: thread safety ---
    try:
        cb = CircuitBreaker("test_thread", failure_threshold=1000)
        results_list = []

        def worker():
            for _ in range(20):
                r = cb.call(lambda: 7)
                results_list.append(r)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        _check(len(results_list) == 100 and all(x == 7 for x in results_list),
               "Test 6: thread-safety (100 concurrent calls)",
               f"Test 6: failed (got {len(results_list)} calls)")
    except Exception as e:
        _check(False, "", f"Test 6: crashed ({e})")

    # --- Test 7: registry isolation ---
    try:
        breakers.reset_all()
        b1 = breakers.register("test_iso_1")
        b2 = breakers.register("test_iso_2")
        b1.call(lambda: 1 / 0)  # open b1 only
        r = b2.call(lambda: "ok")
        _check(r == "ok" and b2.state == BreakerState.CLOSED,
               "Test 7: registry isolation (independent breakers)",
               "Test 7: failed (breakers interfered)")
    except Exception as e:
        _check(False, "", f"Test 7: crashed ({e})")

    # --- Test 8: stats accuracy ---
    try:
        cb = CircuitBreaker("test_stats", failure_threshold=10)
        cb.call(lambda: 1)
        cb.call(lambda: 1)
        cb.call(lambda: 1 / 0)  # 1 failure
        stats = cb.stats()
        _check(
            stats["total_calls"] == 3
            and stats["total_failures"] == 1
            and stats["success_count"] == 2,
            "Test 8: stats accuracy (calls/failures/successes)",
            f"Test 8: wrong stats {stats}",
        )
    except Exception as e:
        _check(False, "", f"Test 8: crashed ({e})")

    breakers.reset_all()
    return success, results


def print_self_test():
    """Run self-tests and print results to stdout + logger."""
    print("\n" + "=" * 70)
    print("  SYSTEM 1: CIRCUIT BREAKER — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 1] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 1 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 1] Circuit breaker self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 1 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 1] {r}")
        logger.error(f"[SYSTEM 1] Circuit breaker self-test FAILED")

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
        print(f"⚠️  [SYSTEM 1] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False
