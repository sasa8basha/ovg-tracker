"""
collector/threat_intel.py — SYSTEM 6: Threat Intelligence Integration

Self-contained. Uses multiple intelligence sources to enrich IP reputation:
  1. TOR exit nodes (free, auto-refreshed every 6h from torproject.org)
  2. Datacenter CIDRs (free, hardcoded from AWS/GCP/Azure/DO/etc)
  3. AbuseIPDB (optional, requires ABUSEIPDB_API_KEY env var)
  4. IPQualityScore (optional, requires IPQS_API_KEY env var)

All external calls are wrapped in try/except (graceful degradation).
All results cached in-memory with TTL.

Solves:
  - #3 (ASN — extra datacenter detection layer)
  - #9, #10, #11 (WebRTC — alternative VPN/proxy detection)
  - #15 (plugins — better proxy signals)
"""
import os
import sys
import time
import ipaddress
import logging
import threading
from typing import List, Tuple, Dict, Optional, Set

logger = logging.getLogger("ovg.threat_intel")


# =========================================================
# CONSTANTS
# =========================================================
TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_LIST_TTL_SECONDS = 6 * 3600  # 6 hours

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TTL_SECONDS = 3600

IPQS_URL_TEMPLATE = "https://ipqualityscore.com/api/json/ip/{key}/{ip}"
IPQS_TTL_SECONDS = 3600

# Known TOR exit nodes (seed list + fallback if network fails)
KNOWN_TOR_EXITS: Set[str] = frozenset([
    # F3 Netze
    "185.220.100.240", "185.220.100.241", "185.220.100.242", "185.220.100.243",
    "185.220.100.244", "185.220.100.245", "185.220.100.246", "185.220.100.247",
    "185.220.101.1", "185.220.101.2", "185.220.101.5", "185.220.101.10",
    "185.220.102.8",
    # Quintex Alliance
    "199.249.230.100", "199.249.230.130", "199.249.230.150",
    "199.249.230.160",
    # CCC / individual
    "171.25.193.20", "171.25.193.25", "171.25.193.77", "171.25.193.78",
    # Frantech/BuyVM
    "23.129.64.131", "23.129.64.132", "23.129.64.190", "23.129.64.131",
])

# Known datacenter CIDRs (subset — most common providers)
# These are stable, well-known ranges. Used for fast pre-check before ASN lookup.
KNOWN_DATACENTER_CIDRS: List[str] = [
    # AWS
    "3.0.0.0/8", "13.32.0.0/15", "52.0.0.0/8", "54.0.0.0/8",
    # GCP
    "34.0.0.0/8", "35.0.0.0/8", "142.250.0.0/15", "172.217.0.0/16",
    # Azure
    "20.0.0.0/8", "40.0.0.0/8",
    # Cloudflare
    "104.16.0.0/12", "104.18.0.0/15",
    # DigitalOcean
    "143.198.0.0/16", "159.65.0.0/16", "165.227.0.0/16", "178.62.0.0/16",
    "139.59.0.0/16",
    # Vultr
    "95.179.0.0/16", "136.244.0.0/16",
    # Hetzner
    "5.9.0.0/16", "78.46.0.0/15",
    # Scaleway / OVH
    "51.15.0.0/16", "51.38.0.0/16", "51.68.0.0/16", "137.74.0.0/16",
    "147.135.0.0/16",
]

# Parse CIDRs once at import
try:
    _DATACENTER_NETWORKS = [ipaddress.ip_network(cidr) for cidr in KNOWN_DATACENTER_CIDRS]
except Exception as e:
    logger.error(f"[TI] failed to parse datacenter CIDRs: {e}")
    _DATACENTER_NETWORKS = []


# =========================================================
# CACHE
# =========================================================
class ThreatIntelCache:
    """Thread-safe cache for TOR list + IP reputation entries."""

    def __init__(self):
        self._lock = threading.RLock()
        self._tor_list: Set[str] = set(KNOWN_TOR_EXITS)
        # Pretend we just loaded the static list (so no fetch on first use)
        self._tor_last_fetch: float = time.time()
        self._ip_cache: Dict[str, Dict] = {}
        self._ip_cache_expiry: Dict[str, float] = {}

    def get_tor_list(self) -> Set[str]:
        with self._lock:
            return self._tor_list.copy()

    def set_tor_list(self, ips: Set[str]):
        with self._lock:
            self._tor_list = ips
            self._tor_last_fetch = time.time()

    def should_refresh_tor(self) -> bool:
        with self._lock:
            return (time.time() - self._tor_last_fetch) > TOR_LIST_TTL_SECONDS

    def get_cached(self, key: str) -> Optional[Dict]:
        with self._lock:
            if key in self._ip_cache:
                if time.time() < self._ip_cache_expiry.get(key, 0):
                    return self._ip_cache[key]
                self._ip_cache.pop(key, None)
                self._ip_cache_expiry.pop(key, None)
            return None

    def set_cached(self, key: str, value: Dict, ttl: int = 3600):
        with self._lock:
            self._ip_cache[key] = value
            self._ip_cache_expiry[key] = time.time() + ttl

    def clear(self):
        with self._lock:
            self._ip_cache.clear()
            self._ip_cache_expiry.clear()


_cache = ThreatIntelCache()


# =========================================================
# HELPERS
# =========================================================
def _is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except (ValueError, TypeError):
        return True  # invalid IP → treat as skip


def _is_datacenter_cidr(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for net in _DATACENTER_NETWORKS:
            if addr.version == net.version and addr in net:
                return True
    except (ValueError, TypeError):
        pass
    return False


def _is_tor(ip: str) -> bool:
    if not ip:
        return False
    # Refresh TOR list if stale (best-effort, never raises)
    if _cache.should_refresh_tor():
        _refresh_tor_list_sync()
    return ip in _cache.get_tor_list()


def _refresh_tor_list_sync():
    """Best-effort TOR list refresh. Never raises."""
    try:
        import httpx
        with httpx.Client(timeout=5) as client:
            resp = client.get(TOR_LIST_URL)
            if resp.status_code == 200:
                ips = set()
                for line in resp.text.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            ipaddress.ip_address(line)  # validate
                            ips.add(line)
                        except ValueError:
                            continue
                if len(ips) > 100:
                    _cache.set_tor_list(ips)
                    logger.info(f"[TI] refreshed TOR list ({len(ips)} exits)")
    except Exception as e:
        logger.debug(f"[TI] TOR refresh failed (non-fatal): {e}")


# =========================================================
# ABUSEIPDB
# =========================================================
def _check_abuseipdb(ip: str) -> Optional[Dict]:
    """Query AbuseIPDB. Returns dict or None."""
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None

    cache_key = f"abuse:{ip}"
    cached = _cache.get_cached(cache_key)
    if cached is not None:
        return cached

    try:
        import httpx
        with httpx.Client(timeout=5) as client:
            resp = client.get(
                ABUSEIPDB_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}) or {}
                entry = {
                    "abuse_score": int(data.get("abuseConfidenceScore", 0) or 0),
                    "total_reports": int(data.get("totalReports", 0) or 0),
                    "country": str(data.get("countryCode", "") or ""),
                }
                _cache.set_cached(cache_key, entry, ttl=ABUSEIPDB_TTL_SECONDS)
                return entry
            else:
                logger.debug(f"[TI] AbuseIPDB status {resp.status_code} for {ip}")
    except Exception as e:
        logger.debug(f"[TI] AbuseIPDB failed for {ip}: {e}")
    return None


# =========================================================
# IPQS
# =========================================================
def _check_ipqs(ip: str) -> Optional[Dict]:
    """Query IPQualityScore. Returns dict or None."""
    api_key = os.getenv("IPQS_API_KEY", "").strip()
    if not api_key:
        return None

    cache_key = f"ipqs:{ip}"
    cached = _cache.get_cached(cache_key)
    if cached is not None:
        return cached

    try:
        import httpx
        url = IPQS_URL_TEMPLATE.format(key=api_key, ip=ip)
        with httpx.Client(timeout=5) as client:
            resp = client.get(url, params={"strictness": 1})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    entry = {
                        "proxy_score": int(data.get("fraud_score", 0) or 0),
                        "is_proxy": bool(data.get("proxy", False)),
                        "is_vpn": bool(data.get("vpn", False)),
                        "is_tor": bool(data.get("tor", False)),
                        "recent_abuse": bool(data.get("recent_abuse", False)),
                    }
                    _cache.set_cached(cache_key, entry, ttl=IPQS_TTL_SECONDS)
                    return entry
    except Exception as e:
        logger.debug(f"[TI] IPQS failed for {ip}: {e}")
    return None


# =========================================================
# MAIN ENTRY POINT
# =========================================================
def analyze_threat_intel(ip: str, ip_info: Optional[dict] = None) -> List[Tuple[str, str, int, str]]:
    """
    Analyze an IP address against multiple threat intel sources.

    Returns:
        list of (code, severity, score, detail) tuples — same format as
        analysis.py check functions.
    """
    items: List[Tuple[str, str, int, str]] = []

    if not ip or not isinstance(ip, str):
        return items

    # Skip private / reserved IPs
    if _is_private_or_reserved(ip):
        return items

    # ===== TOR detection (free) =====
    try:
        if _is_tor(ip):
            items.append((
                "THREAT_TOR_EXIT",
                "impossible",
                100,
                f"IP is a TOR exit node: {ip}",
            ))
    except Exception as e:
        logger.warning(f"[TI] TOR check failed for {ip}: {e}")

    # ===== Datacenter CIDR detection (free) =====
    try:
        if _is_datacenter_cidr(ip):
            items.append((
                "THREAT_DATACENTER_CIDR",
                "high",
                60,
                f"IP is in known datacenter CIDR: {ip}",
            ))
    except Exception as e:
        logger.warning(f"[TI] CIDR check failed for {ip}: {e}")

    # ===== AbuseIPDB (optional) =====
    try:
        abuse = _check_abuseipdb(ip)
        if abuse:
            score = abuse.get("abuse_score", 0)
            if score >= 50:
                items.append((
                    "THREAT_ABUSE_HIGH",
                    "high",
                    70,
                    f"AbuseIPDB score: {score}/100",
                ))
            elif score >= 25:
                items.append((
                    "THREAT_ABUSE_MED",
                    "medium",
                    40,
                    f"AbuseIPDB score: {score}/100",
                ))
    except Exception as e:
        logger.warning(f"[TI] AbuseIPDB check failed for {ip}: {e}")

    # ===== IPQS (optional) =====
    try:
        ipqs = _check_ipqs(ip)
        if ipqs:
            proxy_score = ipqs.get("proxy_score", 0)
            if ipqs.get("is_tor"):
                items.append((
                    "THREAT_IPQS_TOR",
                    "impossible",
                    100,
                    "IPQS confirms TOR exit node",
                ))
            elif ipqs.get("is_vpn") and proxy_score >= 75:
                items.append((
                    "THREAT_IPQS_VPN_HIGH",
                    "high",
                    65,
                    f"IPQS VPN detected (score {proxy_score}/100)",
                ))
            elif proxy_score >= 75:
                items.append((
                    "THREAT_IPQS_PROXY_HIGH",
                    "high",
                    65,
                    f"IPQS proxy detected (score {proxy_score}/100)",
                ))
            elif proxy_score >= 50:
                items.append((
                    "THREAT_IPQS_PROXY_MED",
                    "medium",
                    40,
                    f"IPQS proxy detected (score {proxy_score}/100)",
                ))
    except Exception as e:
        logger.warning(f"[TI] IPQS check failed for {ip}: {e}")

    return items


# =========================================================
# HEALTH
# =========================================================
def health_status() -> dict:
    return {
        "system": "threat_intel",
        "status": "ok",
        "tor_list_size": len(_cache.get_tor_list()),
        "datacenter_cidrs": len(_DATACENTER_NETWORKS),
        "abuseipdb_configured": bool(os.getenv("ABUSEIPDB_API_KEY", "").strip()),
        "ipqs_configured": bool(os.getenv("IPQS_API_KEY", "").strip()),
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

    def _codes(items):
        return {item[0] for item in items}

    # 1: empty IP → empty
    try:
        r = analyze_threat_intel("")
        _chk(r == [], "Test 1: empty IP → no signals", f"Test 1: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # 2: None IP → empty
    try:
        r = analyze_threat_intel(None)
        _chk(r == [], "Test 2: None IP → no signals", f"Test 2: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # 3: private IP → empty
    try:
        r = analyze_threat_intel("192.168.1.1")
        _chk(r == [], "Test 3: private IP → no signals", f"Test 3: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # 4: loopback → empty
    try:
        r = analyze_threat_intel("127.0.0.1")
        _chk(r == [], "Test 4: loopback IP → no signals", f"Test 4: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # 5: invalid IP string → empty
    try:
        r = analyze_threat_intel("not-an-ip")
        _chk(r == [], "Test 5: invalid IP string → no signals", f"Test 5: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # 6: known TOR exit → THREAT_TOR_EXIT
    try:
        r = analyze_threat_intel("185.220.100.240")
        _chk("THREAT_TOR_EXIT" in _codes(r),
             "Test 6: known TOR exit → THREAT_TOR_EXIT signal",
             f"Test 6: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # 7: AWS CIDR IP → THREAT_DATACENTER_CIDR
    try:
        r = analyze_threat_intel("3.5.5.5")
        _chk("THREAT_DATACENTER_CIDR" in _codes(r),
             "Test 7: AWS IP (3.5.5.5) → THREAT_DATACENTER_CIDR",
             f"Test 7: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # 8: GCP CIDR IP → THREAT_DATACENTER_CIDR
    try:
        r = analyze_threat_intel("34.10.20.30")
        _chk("THREAT_DATACENTER_CIDR" in _codes(r),
             "Test 8: GCP IP (34.10.20.30) → THREAT_DATACENTER_CIDR",
             f"Test 8: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # 9: Cloudflare CIDR → THREAT_DATACENTER_CIDR
    try:
        r = analyze_threat_intel("104.16.5.5")
        _chk("THREAT_DATACENTER_CIDR" in _codes(r),
             "Test 9: Cloudflare IP (104.16.5.5) → THREAT_DATACENTER_CIDR",
             f"Test 9: got {[i[0] for i in r]}")
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # 10: residential IP → no datacenter/TOR
    try:
        r = analyze_threat_intel("190.5.5.5")
        _chk(
            "THREAT_TOR_EXIT" not in _codes(r)
            and "THREAT_DATACENTER_CIDR" not in _codes(r),
            "Test 10: residential IP → no datacenter/TOR signals",
            f"Test 10: got {[i[0] for i in r]}",
        )
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # 11: AbuseIPDB mock (high score) → THREAT_ABUSE_HIGH
    try:
        from collector import threat_intel as ti
        original = ti._check_abuseipdb
        try:
            ti._check_abuseipdb = lambda ip: {"abuse_score": 85, "total_reports": 50, "country": "US"}
            r = analyze_threat_intel("8.8.8.8")
            _chk("THREAT_ABUSE_HIGH" in _codes(r),
                 "Test 11: AbuseIPDB high score (85) → THREAT_ABUSE_HIGH",
                 f"Test 11: got {[i[0] for i in r]}")
        finally:
            ti._check_abuseipdb = original
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # 12: AbuseIPDB mock (medium score) → THREAT_ABUSE_MED
    try:
        from collector import threat_intel as ti
        original = ti._check_abuseipdb
        try:
            ti._check_abuseipdb = lambda ip: {"abuse_score": 30, "total_reports": 10, "country": "US"}
            r = analyze_threat_intel("8.8.4.4")
            _chk("THREAT_ABUSE_MED" in _codes(r),
                 "Test 12: AbuseIPDB medium score (30) → THREAT_ABUSE_MED",
                 f"Test 12: got {[i[0] for i in r]}")
        finally:
            ti._check_abuseipdb = original
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # 13: IPQS mock (TOR) → THREAT_IPQS_TOR (impossible)
    try:
        from collector import threat_intel as ti
        original = ti._check_ipqs
        try:
            ti._check_ipqs = lambda ip: {
                "proxy_score": 95, "is_proxy": True,
                "is_vpn": True, "is_tor": True, "recent_abuse": True,
            }
            r = analyze_threat_intel("1.2.3.4")
            codes = _codes(r)
            # Check impossible severity
            tor_sig = [i for i in r if i[0] == "THREAT_IPQS_TOR"]
            _chk(len(tor_sig) == 1 and tor_sig[0][1] == "impossible",
                 "Test 13: IPQS TOR → THREAT_IPQS_TOR (impossible)",
                 f"Test 13: got {[i[0:2] for i in r]}")
        finally:
            ti._check_ipqs = original
    except Exception as e:
        _chk(False, "", f"Test 13: crashed ({e})")

    # 14: IPQS mock (high proxy, no TOR) → THREAT_IPQS_PROXY_HIGH
    try:
        from collector import threat_intel as ti
        original = ti._check_ipqs
        try:
            ti._check_ipqs = lambda ip: {
                "proxy_score": 85, "is_proxy": True,
                "is_vpn": False, "is_tor": False, "recent_abuse": False,
            }
            r = analyze_threat_intel("5.6.7.8")
            _chk("THREAT_IPQS_PROXY_HIGH" in _codes(r),
                 "Test 14: IPQS proxy score 85 → THREAT_IPQS_PROXY_HIGH",
                 f"Test 14: got {[i[0] for i in r]}")
        finally:
            ti._check_ipqs = original
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # 15: No API keys → AbuseIPDB/IPQS skipped (return None)
    try:
        saved_abuse = os.getenv("ABUSEIPDB_API_KEY")
        saved_ipqs = os.getenv("IPQS_API_KEY")
        try:
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            os.environ.pop("IPQS_API_KEY", None)
            # Clear any cache entries
            _cache.clear()
            r = analyze_threat_intel("8.8.8.8")
            # No THREAT_ABUSE_* or THREAT_IPQS_* signals should appear
            codes = _codes(r)
            _chk(
                "THREAT_ABUSE_HIGH" not in codes
                and "THREAT_ABUSE_MED" not in codes
                and "THREAT_IPQS_PROXY_HIGH" not in codes,
                "Test 15: no API keys → AbuseIPDB/IPQS signals skipped",
                f"Test 15: got {codes}",
            )
        finally:
            if saved_abuse:
                os.environ["ABUSEIPDB_API_KEY"] = saved_abuse
            if saved_ipqs:
                os.environ["IPQS_API_KEY"] = saved_ipqs
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # 16: cache hit on second call (use monkeypatch to count calls)
    try:
        from collector import threat_intel as ti
        _cache.clear()
        call_count = {"n": 0}
        original = ti._check_abuseipdb

        def counted(ip):
            call_count["n"] += 1
            return {"abuse_score": 60, "total_reports": 20, "country": "US"}

        try:
            ti._check_abuseipdb = counted
            # First call
            r1 = analyze_threat_intel("9.9.9.9")
            # Second call — should hit cache
            r2 = analyze_threat_intel("9.9.9.9")
            _chk(call_count["n"] == 1,
                 f"Test 16: cache hit on second call (calls={call_count['n']})",
                 f"Test 16: expected 1 call, got {call_count['n']}")
        finally:
            ti._check_abuseipdb = original
            _cache.clear()
    except Exception as e:
        _chk(False, "", f"Test 16: crashed ({e})")

    # 17: health_status returns valid dict
    try:
        h = health_status()
        _chk(
            isinstance(h, dict)
            and h.get("system") == "threat_intel"
            and "tor_list_size" in h
            and "datacenter_cidrs" in h,
            "Test 17: health_status returns valid dict",
            f"Test 17: got {h}",
        )
    except Exception as e:
        _chk(False, "", f"Test 17: crashed ({e})")

    # 18: TOR + datacenter both fire on overlapping IP
    try:
        # 185.220.100.240 is TOR exit — not in datacenter CIDR
        # But we can test that multiple signals can accumulate
        from collector import threat_intel as ti
        _cache.clear()
        original_abuse = ti._check_abuseipdb
        try:
            ti._check_abuseipdb = lambda ip: {"abuse_score": 80, "total_reports": 30, "country": "US"}
            r = analyze_threat_intel("185.220.100.240")  # TOR
            codes = _codes(r)
            # Should have THREAT_TOR_EXIT + THREAT_ABUSE_HIGH
            _chk(
                "THREAT_TOR_EXIT" in codes and "THREAT_ABUSE_HIGH" in codes,
                "Test 18: TOR + AbuseIPDB both fire (multiple signals accumulate)",
                f"Test 18: got {codes}",
            )
        finally:
            ti._check_abuseipdb = original_abuse
            _cache.clear()
    except Exception as e:
        _chk(False, "", f"Test 18: crashed ({e})")

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 6: THREAT INTEL — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 6] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 6 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 6] Threat intel self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 6 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 6] {r}")

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
        print(f"⚠️  [SYSTEM 6] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False
