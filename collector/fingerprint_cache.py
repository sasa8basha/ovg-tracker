"""
fingerprint_cache.py — Known-bad fingerprint cache (v3.3)

v3.3 FIX:
  - `record()` no longer drops a new strike when the existing entry
    has expired. Previously:
        if self._is_expired(entry):
            self._cache.pop(fp_hash, None)
            return          # ← dropped the new strike
    Now: expired entry is removed, then a fresh entry is created with
    strikes=1, preserving the new signal.

In-memory cache of fingerprints that were confirmed as bots.
On repeat, boosts confidence dramatically.

Cache key: hash(canvas_hash + ASN + platform + hardware)
Value: {strikes, first_seen, last_seen, evidence_codes}
"""
import threading
import time
from collections import OrderedDict


class FingerprintCache:
    def __init__(self, maxsize=100000, ttl_seconds=86400 * 30):
        self._cache = OrderedDict()
        self._lock = threading.Lock()
        self.maxsize = maxsize
        self.ttl = ttl_seconds

    def _is_expired(self, entry):
        return (time.time() - entry["last_seen"]) > self.ttl

    def _evict(self):
        while len(self._cache) > self.maxsize:
            self._cache.popitem(last=False)

    def record(self, fp_hash, verdict, evidence_codes=None):
        if not fp_hash:
            return
        if verdict != "invalid":
            return

        with self._lock:
            now = time.time()

            if fp_hash in self._cache:
                entry = self._cache[fp_hash]
                if self._is_expired(entry):
                    # v3.3 FIX: remove expired entry, then fall through
                    # to create a fresh entry below (do NOT return).
                    self._cache.pop(fp_hash, None)
                else:
                    # Existing, non-expired entry → increment
                    entry["strikes"] += 1
                    entry["last_seen"] = now
                    if evidence_codes:
                        for code in evidence_codes[:10]:
                            if code not in entry["evidence_codes"]:
                                entry["evidence_codes"].append(code)
                        entry["evidence_codes"] = entry["evidence_codes"][:20]
                    self._cache.move_to_end(fp_hash)
                    self._evict()
                    return

            # Create fresh entry (either brand new or replacing expired)
            self._cache[fp_hash] = {
                "strikes": 1,
                "first_seen": now,
                "last_seen": now,
                "evidence_codes": list((evidence_codes or [])[:10]),
            }
            self._evict()

    def get_stats(self, fp_hash):
        if not fp_hash:
            return {"strikes": 0, "first_seen": None, "last_seen": None, "evidence_codes": []}
        with self._lock:
            entry = self._cache.get(fp_hash)
            if not entry:
                return {"strikes": 0, "first_seen": None, "last_seen": None, "evidence_codes": []}
            if self._is_expired(entry):
                self._cache.pop(fp_hash, None)
                return {"strikes": 0, "first_seen": None, "last_seen": None, "evidence_codes": []}
            return {
                "strikes": entry["strikes"],
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "evidence_codes": list(entry["evidence_codes"]),
            }

    def size(self):
        with self._lock:
            return len(self._cache)


_global_cache = FingerprintCache()


def record_strike(fp_hash, verdict, evidence_codes=None):
    _global_cache.record(fp_hash, verdict, evidence_codes)


def get_strikes(fp_hash):
    return _global_cache.get_stats(fp_hash)


def cache_size():
    return _global_cache.size()