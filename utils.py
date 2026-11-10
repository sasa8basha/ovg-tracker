import time
import threading
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
        self._lock = threading.Lock()  # H-17: atomic check

    def check(self, key: str):
        now = time.time()
        with self._lock:
            e = self._d.get(key)
            if e is None or now - e[1] > self.window:
                self._d[key] = (1, now)
                self._d.move_to_end(key)
            else:
                self._d[key] = (e[0] + 1, e[1])
                self._d.move_to_end(key)
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)
            count = self._d[key][0]
        if count > self.max_req:
            raise HTTPException(status_code=429, detail="محاولات كتير — جرب بعد شوية",
                                headers={"Retry-After": str(self.window)})


# Caches
ip_cache = TTLCache(maxsize=GEO_CACHE_MAX, ttl=GEO_CACHE_TTL)
stats_cache = TTLCache(maxsize=1000, ttl=15)
pulse_cache = TTLCache(maxsize=500, ttl=60)  # H-05: pulse polls every 30s
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

# =========================================================
# Anubis Challenge rate limiters (v1.0)
# =========================================================
challenge_limiter = WindowRateLimiter(max_req=30, window=60)
challenge_verify_limiter = WindowRateLimiter(max_req=30, window=60)


def _is_private_ip(ip: str) -> bool:
    # H-27: treat unspecified addresses as non-public
    if str(ip).strip() in ("0.0.0.0", "::", "::0"):
        return True
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_unspecified
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """
    C-06 FIX (v3): Correct client IP behind reverse proxies.

    Problem with v1: trusted XFF from anyone → spoofing.
    Problem with v2: ignored XFF unless peer is private → Netrun/some
    PaaS present a public peer IP, so every visitor shared the proxy IP.

    v3: Prefer CF-Connecting-IP always when valid. Then X-Real-IP /
    X-Forwarded-For **only when the connecting peer is private/loopback
    OR when config TRUST_PROXY_HEADERS is enabled** (default True for
    typical OVG deploys behind Netrun/Nginx). Direct public peers without
    proxy headers use request.client.host.
    """
    def _valid_ip(s: str) -> str | None:
        s = (s or "").strip()
        if not s:
            return None
        try:
            ipaddress.ip_address(s)
            return s
        except ValueError:
            return None

    peer = None
    if request.client and request.client.host:
        peer = _valid_ip(request.client.host)

    # Cloudflare edge always sets this to the real client
    cf = _valid_ip(request.headers.get("cf-connecting-ip", ""))
    if cf and not _is_private_ip(cf):
        return cf

    trust_proxy = True
    try:
        from config import TRUST_PROXY_HEADERS
        trust_proxy = bool(TRUST_PROXY_HEADERS)
    except Exception:
        trust_proxy = True

    behind_trusted_proxy = (peer is not None and _is_private_ip(peer)) or trust_proxy

    if behind_trusted_proxy:
        xri = _valid_ip(request.headers.get("x-real-ip", ""))
        if xri and not _is_private_ip(xri):
            return xri
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            # leftmost non-private hop = original client in typical proxy chains
            for p in parts:
                ip = _valid_ip(p)
                if ip and not _is_private_ip(ip):
                    return ip
            if parts:
                ip = _valid_ip(parts[0])
                if ip:
                    return ip
        if xri:
            return xri

    if peer:
        return peer
    return "0.0.0.0"




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