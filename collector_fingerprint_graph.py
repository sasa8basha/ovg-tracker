"""
collector/fingerprint_graph.py — SYSTEM 7: Fingerprint Graph (Redis)

Self-contained. Detects bot farms via shared fingerprints across many IPs.

Backend selection:
  - If REDIS_URL env var is set → try Redis (with fallback to memory)
  - Otherwise → in-memory (OrderedDict + TTL)

Detects:
  - FINGERPRINT_FARM_MASSIVE: 20+ distinct IPs for same fp in 1h (critical)
  - FINGERPRINT_FARM_LARGE:   10-19 distinct IPs (high)
  - FINGERPRINT_FARM_SMALL:   5-9 distinct IPs (medium)
  - IP_MANY_FPS:              10+ distinct fps from same IP in 1h (high)
  - FINGERPRINT_KNOWN_BAD:    Fingerprint confirmed as bot before (critical)

Solves:
  - #17 (FINGERPRINT_REUSE duplication)
  - #18 (thresholds static — now graph-based)
  - #30 (NO_MOUSE_NO_TOUCH farm detection)
  - #31 (IDLE_VISIBLE farm detection)
  - fingerprint_cache.py in-memory loss on restart

Never crashes. All errors logged at debug level.
"""
import os
import sys
import time
import logging
import threading
from typing import List, Tuple, Dict, Optional, Any
from collections import OrderedDict

logger = logging.getLogger("ovg.fingerprint_graph")


# =========================================================
# CONSTANTS
# =========================================================
FP_IPS_TTL = 3600            # 1 hour
IP_FPS_TTL = 3600            # 1 hour
KNOWN_BAD_TTL = 30 * 86400   # 30 days

FARM_MASSIVE_THRESHOLD = 20
FARM_LARGE_THRESHOLD = 10
FARM_SMALL_THRESHOLD = 5
IP_MANY_FPS_THRESHOLD = 10

MAX_IN_MEMORY_KEYS = 50000


# =========================================================
# IN-MEMORY BACKEND (fallback)
# =========================================================
class InMemoryBackend:
    """Thread-safe TTL-based in-memory store."""

    def __init__(self):
        self._lock = threading.RLock()
        self._fp_ips: Dict[str, Tuple[set, float]] = {}
        self._ip_fps: Dict[str, Tuple[set, float]] = {}
        self._known_bad: Dict[str, float] = {}

    def _evict_if_needed(self):
        while len(self._fp_ips) > MAX_IN_MEMORY_KEYS:
            oldest = min(self._fp_ips, key=lambda k: self._fp_ips[k][1])
            del self._fp_ips[oldest]
        while len(self._ip_fps) > MAX_IN_MEMORY_KEYS:
            oldest = min(self._ip_fps, key=lambda k: self._ip_fps[k][1])
            del self._ip_fps[oldest]
        now = time.time()
        expired = [k for k, exp in self._known_bad.items() if exp < now]
        for k in expired:
            del self._known_bad[k]

    def record(self, fp_hash: str, ip: str):
        now = time.time()
        with self._lock:
            # fp -> set of IPs
            if fp_hash in self._fp_ips:
                s, _ = self._fp_ips[fp_hash]
                s.add(ip)
                self._fp_ips[fp_hash] = (s, now)
            else:
                self._fp_ips[fp_hash] = ({ip}, now)

            # ip -> set of fps
            if ip in self._ip_fps:
                s, _ = self._ip_fps[ip]
                s.add(fp_hash)
                self._ip_fps[ip] = (s, now)
            else:
                self._ip_fps[ip] = ({fp_hash}, now)

            self._evict_if_needed()

    def fp_ips_count(self, fp_hash: str) -> int:
        now = time.time()
        with self._lock:
            if fp_hash not in self._fp_ips:
                return 0
            s, ts = self._fp_ips[fp_hash]
            if (now - ts) > FP_IPS_TTL:
                del self._fp_ips[fp_hash]
                return 0
            return len(s)

    def ip_fps_count(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            if ip not in self._ip_fps:
                return 0
            s, ts = self._ip_fps[ip]
            if (now - ts) > IP_FPS_TTL:
                del self._ip_fps[ip]
                return 0
            return len(s)

    def mark_known_bad(self, fp_hash: str):
        with self._lock:
            self._known_bad[fp_hash] = time.time() + KNOWN_BAD_TTL

    def is_known_bad(self, fp_hash: str) -> bool:
        now = time.time()
        with self._lock:
            exp = self._known_bad.get(fp_hash)
            if exp is None:
                return False
            if exp < now:
                del self._known_bad[fp_hash]
                return False
            return True

    def reset(self):
        with self._lock:
            self._fp_ips.clear()
            self._ip_fps.clear()
            self._known_bad.clear()

    def health(self) -> dict:
        with self._lock:
            return {
                "backend": "memory",
                "fp_entries": len(self._fp_ips),
                "ip_entries": len(self._ip_fps),
                "known_bad": len(self._known_bad),
            }


# =========================================================
# REDIS BACKEND
# =========================================================
class RedisBackend:
    """Redis-based store with graceful degradation."""

    def __init__(self, redis_client):
        self.r = redis_client

    def record(self, fp_hash: str, ip: str):
        try:
            fp_key = f"fp:{fp_hash}:ips"
            ip_key = f"ip:{ip}:fps"
            pipe = self.r.pipeline()
            pipe.sadd(fp_key, ip)
            pipe.expire(fp_key, FP_IPS_TTL)
            pipe.sadd(ip_key, fp_hash)
            pipe.expire(ip_key, IP_FPS_TTL)
            pipe.execute()
        except Exception as e:
            logger.debug(f"[FPG] redis record failed: {e}")

    def fp_ips_count(self, fp_hash: str) -> int:
        try:
            return int(self.r.scard(f"fp:{fp_hash}:ips") or 0)
        except Exception as e:
            logger.debug(f"[FPG] redis scard failed: {e}")
            return 0

    def ip_fps_count(self, ip: str) -> int:
        try:
            return int(self.r.scard(f"ip:{ip}:fps") or 0)
        except Exception as e:
            logger.debug(f"[FPG] redis scard failed: {e}")
            return 0

    def mark_known_bad(self, fp_hash: str):
        try:
            self.r.setex(f"bad:{fp_hash}", KNOWN_BAD_TTL, "1")
        except Exception as e:
            logger.debug(f"[FPG] redis setex failed: {e}")

    def is_known_bad(self, fp_hash: str) -> bool:
        try:
            return bool(self.r.exists(f"bad:{fp_hash}"))
        except Exception as e:
            logger.debug(f"[FPG] redis exists failed: {e}")
            return False

    def reset(self):
        # NO-OP for Redis to avoid accidental data loss
        pass

    def health(self) -> dict:
        try:
            info = {
                "backend": "redis",
                "connected": self.r.ping(),
                "dbsize": int(self.r.dbsize()),
            }
            return info
        except Exception:
            return {"backend": "redis", "connected": False}


# =========================================================
# MAIN GRAPH
# =========================================================
class FingerprintGraph:
    def __init__(self, force_backend: Optional[str] = None):
        """
        force_backend: "memory" | "redis" | None (auto)
        """
        self._backend = self._init_backend(force_backend)

    def _init_backend(self, force_backend: Optional[str]):
        chosen = (force_backend or os.getenv("FINGERPRINT_GRAPH_BACKEND", "auto")).lower()

        if chosen == "memory":
            logger.info("[FPG] using in-memory backend (forced)")
            return InMemoryBackend()

        if chosen == "redis":
            backend = self._try_redis()
            if backend is None:
                logger.warning("[FPG] redis forced but unavailable, using memory")
                return InMemoryBackend()
            return backend

        # auto
        if not os.getenv("REDIS_URL"):
            logger.info("[FPG] no REDIS_URL env — using in-memory backend")
            return InMemoryBackend()

        backend = self._try_redis()
        if backend is None:
            logger.warning("[FPG] REDIS_URL set but connection failed, using memory")
            return InMemoryBackend()
        return backend

    def _try_redis(self) -> Optional[RedisBackend]:
        try:
            import redis
            url = os.getenv("REDIS_URL") or "redis://localhost:6379/0"
            client = redis.Redis.from_url(
                url,
                socket_connect_timeout=1,
                socket_timeout=1,
                decode_responses=True,
            )
            client.ping()
            logger.info(f"[FPG] connected to Redis at {url}")
            return RedisBackend(client)
        except Exception as e:
            logger.debug(f"[FPG] Redis init failed: {e}")
            return None

    # -----------------------------------------------------
    # PUBLIC API
    # -----------------------------------------------------
    def record_and_analyze(self, fp_hash: str, ip: str) -> List[Tuple[str, str, int, str]]:
        """
        Record the visit AND return farm signals.
        Never raises.
        """
        items: List[Tuple[str, str, int, str]] = []

        if not fp_hash or not ip:
            return items

        # Guard against abuse
        if len(fp_hash) > 128 or len(ip) > 64:
            return items

        try:
            self._backend.record(fp_hash, ip)
        except Exception as e:
            logger.debug(f"[FPG] record failed: {e}")
            return items

        try:
            fp_ips = self._backend.fp_ips_count(fp_hash)
            ip_fps = self._backend.ip_fps_count(ip)
            known_bad = self._backend.is_known_bad(fp_hash)
        except Exception as e:
            logger.debug(f"[FPG] lookup failed: {e}")
            return items

        # Farm detection (same fp from many IPs)
        if fp_ips >= FARM_MASSIVE_THRESHOLD:
            items.append((
                "FINGERPRINT_FARM_MASSIVE",
                "critical",
                100,
                f"Same fingerprint from {fp_ips} distinct IPs in 1h",
            ))
        elif fp_ips >= FARM_LARGE_THRESHOLD:
            items.append((
                "FINGERPRINT_FARM_LARGE",
                "high",
                70,
                f"Same fingerprint from {fp_ips} distinct IPs in 1h",
            ))
        elif fp_ips >= FARM_SMALL_THRESHOLD:
            items.append((
                "FINGERPRINT_FARM_SMALL",
                "medium",
                40,
                f"Same fingerprint from {fp_ips} distinct IPs in 1h",
            ))

        # Same IP uses many fingerprints
        if ip_fps >= IP_MANY_FPS_THRESHOLD:
            items.append((
                "IP_MANY_FPS",
                "high",
                70,
                f"IP {ip} used {ip_fps} distinct fingerprints in 1h",
            ))

        # Known-bad
        if known_bad:
            items.append((
                "FINGERPRINT_KNOWN_BAD",
                "critical",
                100,
                "Fingerprint previously confirmed as bot",
            ))

        return items

    def mark_known_bad(self, fp_hash: str):
        """Mark fp as known-bad. Call when ground_truth=bot."""
        if not fp_hash:
            return
        try:
            self._backend.mark_known_bad(fp_hash)
        except Exception as e:
            logger.debug(f"[FPG] mark_known_bad failed: {e}")

    def reset(self):
        """Reset backend (for tests)."""
        try:
            self._backend.reset()
        except Exception:
            pass

    def health(self) -> dict:
        try:
            return self._backend.health()
        except Exception as e:
            return {"backend": "unknown", "error": str(e)}


# =========================================================
# GLOBAL SINGLETON
# =========================================================
_graph: Optional[FingerprintGraph] = None
_init_lock = threading.Lock()


def _get_graph() -> FingerprintGraph:
    global _graph
    if _graph is None:
        with _init_lock:
            if _graph is None:
                _graph = FingerprintGraph()
    return _graph


def record_and_analyze(fp_hash: str, ip: str) -> List[Tuple[str, str, int, str]]:
    try:
        return _get_graph().record_and_analyze(fp_hash, ip)
    except Exception as e:
        logger.debug(f"[FPG] record_and_analyze failed: {e}")
        return []


def mark_known_bad(fp_hash: str):
    try:
        _get_graph().mark_known_bad(fp_hash)
    except Exception as e:
        logger.debug(f"[FPG] mark_known_bad failed: {e}")


def reset():
    try:
        _get_graph().reset()
    except Exception:
        pass


def health_status() -> dict:
    try:
        h = _get_graph().health()
        h["system"] = "fingerprint_graph"
        h["status"] = "ok"
        return h
    except Exception as e:
        return {
            "system": "fingerprint_graph",
            "status": "error",
            "error": str(e),
        }


# =========================================================
# SELF-TEST
# =========================================================
def run_self_test() -> Tuple[bool, List[str]]:
    results: List[str] = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    def _fresh_graph() -> FingerprintGraph:
        g = FingerprintGraph(force_backend="memory")
        g.reset()
        return g

    def _codes(items):
        return {item[0] for item in items}

    # 1: empty fp → no signals
    try:
        g = _fresh_graph()
        r = g.record_and_analyze("", "1.2.3.4")
        _chk(r == [], "Test 1: empty fp → no signals", f"Test 1: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # 2: empty ip → no signals
    try:
        g = _fresh_graph()
        r = g.record_and_analyze("abcd1234", "")
        _chk(r == [], "Test 2: empty ip → no signals", f"Test 2: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # 3: single visit → no signals
    try:
        g = _fresh_graph()
        r = g.record_and_analyze("fp1", "1.1.1.1")
        _chk(r == [], "Test 3: single visit → no signals", f"Test 3: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # 4: 5 IPs same fp → FINGERPRINT_FARM_SMALL
    try:
        g = _fresh_graph()
        for i in range(5):
            g.record_and_analyze("fp_small", f"10.0.0.{i}")
        _chk(
            g._backend.fp_ips_count("fp_small") == 5,
            "Test 4: 5 IPs same fp → count = 5",
            "Test 4: failed",
        )
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # 5: 5-9 IPs → SMALL signal fires
    try:
        g = _fresh_graph()
        for i in range(5):
            r = g.record_and_analyze("fp_small_sig", f"10.1.0.{i}")
        _chk(
            "FINGERPRINT_FARM_SMALL" in _codes(r),
            "Test 5: 5 IPs → FINGERPRINT_FARM_SMALL fires",
            f"Test 5: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # 6: 10 IPs → LARGE
    try:
        g = _fresh_graph()
        for i in range(10):
            r = g.record_and_analyze("fp_large", f"10.2.0.{i}")
        _chk(
            "FINGERPRINT_FARM_LARGE" in _codes(r),
            "Test 6: 10 IPs → FINGERPRINT_FARM_LARGE fires",
            f"Test 6: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # 7: 20 IPs → MASSIVE
    try:
        g = _fresh_graph()
        for i in range(20):
            r = g.record_and_analyze("fp_massive", f"10.3.0.{i}")
        _chk(
            "FINGERPRINT_FARM_MASSIVE" in _codes(r),
            "Test 7: 20 IPs → FINGERPRINT_FARM_MASSIVE fires",
            f"Test 7: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # 8: same IP 10 fps → IP_MANY_FPS
    try:
        g = _fresh_graph()
        for i in range(10):
            r = g.record_and_analyze(f"fp_many_{i}", "11.11.11.11")
        _chk(
            "IP_MANY_FPS" in _codes(r),
            "Test 8: 10 fps from same IP → IP_MANY_FPS",
            f"Test 8: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # 9: known bad → FINGERPRINT_KNOWN_BAD
    try:
        g = _fresh_graph()
        g.mark_known_bad("fp_bad")
        r = g.record_and_analyze("fp_bad", "12.12.12.12")
        _chk(
            "FINGERPRINT_KNOWN_BAD" in _codes(r),
            "Test 9: known-bad fp → FINGERPRINT_KNOWN_BAD",
            f"Test 9: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # 10: fresh fp → not known bad
    try:
        g = _fresh_graph()
        r = g.record_and_analyze("fp_fresh", "13.13.13.13")
        _chk(
            "FINGERPRINT_KNOWN_BAD" not in _codes(r),
            "Test 10: fresh fp → not known-bad",
            f"Test 10: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # 11: isolation between fps
    try:
        g = _fresh_graph()
        for i in range(3):
            g.record_and_analyze("fp_iso_a", f"20.0.0.{i}")
        for i in range(3):
            g.record_and_analyze("fp_iso_b", f"20.1.0.{i}")
        _chk(
            g._backend.fp_ips_count("fp_iso_a") == 3
            and g._backend.fp_ips_count("fp_iso_b") == 3,
            "Test 11: isolation between different fps",
            "Test 11: failed",
        )
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # 12: reset clears state
    try:
        g = _fresh_graph()
        g.record_and_analyze("fp_reset", "21.21.21.21")
        g.reset()
        _chk(
            g._backend.fp_ips_count("fp_reset") == 0,
            "Test 12: reset() clears state",
            "Test 12: failed",
        )
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # 13: many fps from same IP → IP_MANY_FPS fires at 10
    try:
        g = _fresh_graph()
        r = None
        for i in range(10):
            r = g.record_and_analyze(f"fp_x_{i}", "22.22.22.22")
        _chk(
            r is not None and "IP_MANY_FPS" in _codes(r),
            "Test 13: 10 fps from same IP → IP_MANY_FPS fires",
            "Test 13: failed",
        )
    except Exception as e:
        _chk(False, "", f"Test 13: crashed ({e})")

    # 14: 9 fps → no IP_MANY_FPS (below threshold)
    try:
        g = _fresh_graph()
        r = None
        for i in range(9):
            r = g.record_and_analyze(f"fp_y_{i}", "23.23.23.23")
        _chk(
            r is not None and "IP_MANY_FPS" not in _codes(r),
            "Test 14: 9 fps from same IP → no IP_MANY_FPS (threshold=10)",
            f"Test 14: got {[i[0] for i in r] if r else []}",
        )
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # 15: force_backend="memory" works
    try:
        g = FingerprintGraph(force_backend="memory")
        h = g.health()
        _chk(h.get("backend") == "memory",
             "Test 15: force_backend='memory' works", "Test 15: failed")
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # 16: thread safety
    try:
        g = _fresh_graph()
        errors = []

        def worker(idx):
            try:
                for j in range(20):
                    g.record_and_analyze(f"fp_thr_{idx}", f"30.{idx}.0.{j}")
            except Exception as ex:
                errors.append(str(ex))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        _chk(len(errors) == 0,
             f"Test 16: thread safety (5 threads × 20 ops)",
             f"Test 16: got {len(errors)} errors")
    except Exception as e:
        _chk(False, "", f"Test 16: crashed ({e})")

    # 17: health_status includes required fields
    try:
        h = health_status()
        _chk(
            isinstance(h, dict)
            and h.get("system") == "fingerprint_graph"
            and "backend" in h,
            "Test 17: health_status valid",
            f"Test 17: got {h}",
        )
    except Exception as e:
        _chk(False, "", f"Test 17: crashed ({e})")

    # 18: mark_known_bad persists for subsequent visits
    try:
        g = _fresh_graph()
        g.mark_known_bad("fp_multi")
        r1 = g.record_and_analyze("fp_multi", "40.0.0.1")
        r2 = g.record_and_analyze("fp_multi", "40.0.0.2")
        _chk(
            "FINGERPRINT_KNOWN_BAD" in _codes(r1)
            and "FINGERPRINT_KNOWN_BAD" in _codes(r2),
            "Test 18: mark_known_bad persists across visits",
            "Test 18: failed",
        )
    except Exception as e:
        _chk(False, "", f"Test 18: crashed ({e})")

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 7: FINGERPRINT GRAPH — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 7] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 7 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 7] Fingerprint graph self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 7 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 7] {r}")

    print("=" * 70 + "\n")
    return ok


# =========================================================
# AUTO-RUN
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
        print(f"⚠️  [SYSTEM 7] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False