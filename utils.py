import time
import ipaddress
from collections import OrderedDict
from urllib.parse import urlparse
from fastapi import HTTPException, Request
from config import TRACK_RATE_PER_MIN, GEO_CACHE_MAX, GEO_CACHE_TTL, PUBLIC_URL


class TTLCache:
    def __init__(self, maxsize: int = 10000, ttl: int = 3600):
        self.maxsize, self.ttl = maxsize, ttl
        self._data = OrderedDict()

    def get(self, key):
        e = self._data.get(key)
        if e is None:
            return None
        v, ts = e
        if time.time() - ts > self.ttl:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return v

    def set(self, key, val):
        self._data[key] = (val, time.time())
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def invalidate(self, key):
        self._data.pop(key, None)

    def invalidate_prefix(self, prefix):
        for k in list(self._data.keys()):
            if k.startswith(prefix):
                del self._data[k]

    def clear(self):
        self._data.clear()


class WindowRateLimiter:
    def __init__(self, max_req=120, window=60, maxsize=100000):
        self.max_req, self.window, self.maxsize = max_req, window, maxsize
        self._d = OrderedDict()

    def check(self, key: str):
        now = time.time()
        e = self._d.get(key)
        if e is None or now - e[1] > self.window:
            self._d[key] = (1, now)
            self._d.move_to_end(key)
        else:
            self._d[key] = (e[0] + 1, e[1])
            self._d.move_to_end(key)
        while len(self._d) > self.maxsize:
            self._d.popitem(last=False)
        if self._d[key][0] > self.max_req:
            raise HTTPException(status_code=429, detail="محاولات كتير — جرب بعد شوية",
                                headers={"Retry-After": str(self.window)})


# Caches
ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
stats_cache = TTLCache(maxsize=1000, ttl=15)
zone_evidence_cache = TTLCache(maxsize=500, ttl=60)

# Rate limiters (existing)
track_limiter = WindowRateLimiter(max_req=TRACK_RATE_PER_MIN, window=60)
signup_limiter = WindowRateLimiter(max_req=5, window=300)
login_limiter = WindowRateLimiter(max_req=15, window=300)

# Rate limiters (Phase 5 — Auth)
forgot_password_limiter = WindowRateLimiter(max_req=3, window=900)
reset_password_limiter = WindowRateLimiter(max_req=5, window=900)
verify_resend_limiter = WindowRateLimiter(max_req=3, window=900)

# =========================================================
# v3 — Collector rate limiters (Phase 1.1)
# =========================================================
from config import (
    HANDSHAKE_RATE_PER_MIN,
    HEARTBEAT_RATE_PER_MIN,
    FINAL_RATE_PER_MIN,
)

handshake_limiter = WindowRateLimiter(max_req=HANDSHAKE_RATE_PER_MIN, window=60)
heartbeat_limiter = WindowRateLimiter(max_req=HEARTBEAT_RATE_PER_MIN, window=60)
final_limiter = WindowRateLimiter(max_req=FINAL_RATE_PER_MIN, window=60)


def _is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip")
    if cf and cf.strip():
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        for p in parts:
            if not _is_private_ip(p):
                return p
        if parts:
            return parts[0]
    xri = request.headers.get("x-real-ip")
    if xri and xri.strip():
        return xri.strip()
    return request.client.host if request.client else "0.0.0.0"


def safe_origin(request: Request) -> str:
    origin = PUBLIC_URL
    if not origin:
        try:
            origin = str(request.base_url).rstrip("/")
        except Exception:
            origin = "https://ovg-tracker.de1.netrun.io"
    parsed = urlparse(origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        origin = "https://ovg-tracker.de1.netrun.io"
    for ch in ("'", '"', "<", ">", "`", "\\", "\n", "\r", "\t"):
        origin = origin.replace(ch, "")
    return origin.rstrip("/")
