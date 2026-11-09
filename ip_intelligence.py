"""
ip_intelligence.py — IP Classification Engine (5 layers).
Independent of PopAds macros — uses real IP from server.
"""
import ipaddress
import httpx
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from database import SessionLocal
from models import IPIntelligence, VisitModel, IPReputationCache

MMDB_PATH = "data/ip-index.mmdb"

try:
    import maxminddb
    _MAXMIND_OK = True
except ImportError:
    _MAXMIND_OK = False
    print("⚠️ maxminddb not installed — Layer 1 (ASN) will be limited")


def _safe_float(v):
    try:
        f = float(v)
        if f != f:
            return None
        return f
    except (ValueError, TypeError):
        return None


def _safe_int(v):
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _layer1_asn_geo(ip: str) -> Dict[str, Any]:
    """Layer 1: ASN & hosting via local MMDB."""
    if not _MAXMIND_OK:
        return {}
    try:
        with maxminddb.open_database(MMDB_PATH) as reader:
            data = reader.get(ip)
            if not data:
                return {}
            return {
                "asn": data.get("asn"),
                "asn_description": data.get("asn_description") or data.get("autonomous_system_organization"),
                "country": (data.get("country_code") or data.get("country", {}).get("iso_code") or "").upper()[:2] or None,
                "is_hosting": bool(data.get("is_hosting", False)),
            }
    except Exception as e:
        print(f"[IP-Intel-L1] MMDB fail for {ip}: {e}")
        return {}


def _check_ip_in_feed(ip: str, feed_data: list, feed_type: str) -> bool:
    """Check if IP is in a feed (list of IPs or CIDRs)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not feed_data:
        return False
    if feed_type == "ip_list":
        return ip in feed_data
    elif feed_type == "cidr_list":
        for cidr in feed_data:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if addr in net:
                    return True
            except ValueError:
                continue
    return False


def _layer2_reputation(ip: str, db) -> List[Dict[str, str]]:
    """Layer 2: check IP against cached reputation feeds."""
    reasons = []
    try:
        feeds = db.query(IPReputationCache).all()
    except Exception:
        return reasons

    feed_meta = {
        "is-vpn": ("VPN/Datacenter (is-vpn)", "cidr_list", "high"),
        "blackshield_ips": ("Malicious IP (Blackshield)", "ip_list", "high"),
        "blackshield_cidrs": ("Hostile CIDR (Blackshield)", "cidr_list", "high"),
    }

    for feed in feeds:
        name = feed.source_name
        if name not in feed_meta:
            continue
        label, ftype, severity = feed_meta[name]
        data = feed.data or []
        if _check_ip_in_feed(ip, data, ftype):
            reasons.append({
                "source": f"reputation:{name}",
                "reason": label,
                "severity": severity,
            })
    return reasons


def _layer3_rtt_gap(tcp_rtt: Optional[float], ws_echo: Optional[float]) -> Optional[Dict[str, Any]]:
    """Layer 3: RTT gap detection for residential proxy."""
    if tcp_rtt is None or ws_echo is None:
        return None
    gap = ws_echo - tcp_rtt
    if gap > 25:
        return {
            "is_proxied": True,
            "gap_ms": gap,
            "reason": f"RTT gap {gap:.1f}ms (TCP vs WS echo)",
            "severity": "high" if gap > 60 else "medium",
        }
    return {"is_proxied": False, "gap_ms": gap}


def _layer4_behavioral(ip: str, db) -> List[Dict[str, str]]:
    """Layer 4: cross-visit velocity & fingerprint reuse."""
    reasons = []
    try:
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        count = db.query(VisitModel).filter(
            VisitModel.ip == ip,
            VisitModel.timestamp > cutoff,
        ).count()
        if count >= 20:
            reasons.append({
                "source": "behavioral",
                "reason": f"IP velocity: {count} visits/10min",
                "severity": "high",
            })
        elif count >= 10:
            reasons.append({
                "source": "behavioral",
                "reason": f"IP velocity: {count} visits/10min",
                "severity": "medium",
            })
    except Exception as e:
        print(f"[IP-Intel-L4] fail: {e}")
    return reasons


async def _layer5_fallback(ip: str) -> Dict[str, Any]:
    """Layer 5: ip-api.com fallback for unknown IPs."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,countryCode,isp,as,proxy,hosting"
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    return {
                        "country": (d.get("countryCode") or "").upper()[:2] or None,
                        "isp": d.get("isp") or None,
                        "asn_raw": d.get("as"),
                        "is_proxy": bool(d.get("proxy", False)),
                        "is_hosting": bool(d.get("hosting", False)),
                    }
    except Exception:
        pass
    return {}


def _parse_asn(as_str: Optional[str]) -> Optional[str]:
    if not as_str:
        return None
    parts = str(as_str).strip().split()
    return parts[0] if parts else None


async def classify_ip(
    ip: str,
    *,
    tcp_rtt_ms: Optional[float] = None,
    ws_echo_ms: Optional[float] = None,
    db=None,
    force: bool = False,
) -> Dict[str, Any]:
    """Classify an IP across 5 layers. Returns classification dict."""
    if not ip:
        return {
            "classification": "unknown", "risk_score": 0, "reasons": [],
            "asn": None, "asn_description": None, "country": None, "isp": None,
            "rtt_gap_ms": None, "last_checked": None,
        }

    if db is None:
        db = SessionLocal()
        close_db = True
    else:
        close_db = False

    try:
        cached = db.query(IPIntelligence).filter(
            IPIntelligence.ip_address == ip
        ).first()

        if cached and not force:
            if (datetime.utcnow() - (cached.last_checked or datetime.utcnow())) < timedelta(hours=1):
                return {
                    "classification": cached.classification,
                    "risk_score": cached.risk_score or 0,
                    "reasons": cached.reasons or [],
                    "asn": cached.asn,
                    "asn_description": cached.asn_description,
                    "country": cached.country,
                    "isp": cached.isp,
                    "rtt_gap_ms": cached.rtt_gap_ms,
                    "last_checked": cached.last_checked.isoformat() if cached.last_checked else None,
                }

        all_reasons: List[Dict[str, Any]] = []
        risk_score = 0
        classification = "unknown"

        # Layer 1: ASN
        l1 = _layer1_asn_geo(ip)
        if l1.get("is_hosting"):
            all_reasons.append({
                "source": "asn", "reason": "Datacenter/Hosting IP",
                "severity": "high",
            })
            risk_score = max(risk_score, 80)
            classification = "datacenter"

        # Layer 2: Reputation
        l2 = _layer2_reputation(ip, db)
        if l2:
            all_reasons.extend(l2)
            risk_score = max(risk_score, 90)
            classification = "vpn"

        # Layer 3: RTT
        l3 = _layer3_rtt_gap(tcp_rtt_ms, ws_echo_ms)
        if l3 and l3.get("is_proxied"):
            all_reasons.append({
                "source": "rtt", "reason": l3["reason"],
                "severity": l3.get("severity", "high"),
            })
            risk_score = max(risk_score, 85 if l3.get("severity") == "high" else 60)
            if classification in ("unknown", "residential"):
                classification = "proxy"

        # Layer 4: Behavioral
        l4 = _layer4_behavioral(ip, db)
        if l4:
            all_reasons.extend(l4)
            for r in l4:
                if r["severity"] == "high":
                    risk_score = max(risk_score, 70)
                else:
                    risk_score = max(risk_score, 50)

        # Layer 5: Fallback API (only if nothing else fired)
        final_country = l1.get("country")
        final_isp = None
        final_asn = l1.get("asn")
        final_asn_desc = l1.get("asn_description")

        if not all_reasons and classification == "unknown":
            l5 = await _layer5_fallback(ip)
            if l5:
                final_country = final_country or l5.get("country")
                final_isp = l5.get("isp")
                final_asn = final_asn or _parse_asn(l5.get("asn_raw"))
                if l5.get("is_proxy") or l5.get("is_hosting"):
                    all_reasons.append({
                        "source": "api",
                        "reason": "Proxy/Hosting (ip-api.com)",
                        "severity": "medium",
                    })
                    risk_score = max(risk_score, 60)
                    classification = "proxy" if l5.get("is_proxy") else "datacenter"

        if not all_reasons:
            classification = "residential"
            risk_score = 0
        elif risk_score >= 90 and classification in ("vpn", "unknown"):
            classification = "vpn"
        elif classification == "unknown":
            classification = "suspicious"

        rtt_gap = l3.get("gap_ms") if l3 else None

        result = {
            "classification": classification,
            "risk_score": risk_score,
            "reasons": all_reasons,
            "asn": final_asn,
            "asn_description": final_asn_desc,
            "country": final_country,
            "isp": final_isp,
            "rtt_gap_ms": rtt_gap,
            "last_checked": datetime.utcnow().isoformat(),
        }

        if cached:
            cached.classification = classification
            cached.risk_score = risk_score
            cached.reasons = all_reasons
            cached.asn = final_asn
            cached.asn_description = final_asn_desc
            cached.country = final_country
            cached.isp = final_isp
            cached.last_checked = datetime.utcnow()
            if tcp_rtt_ms is not None:
                cached.tcp_rtt_ms = tcp_rtt_ms
            if ws_echo_ms is not None:
                cached.ws_echo_ms = ws_echo_ms
            if rtt_gap is not None:
                cached.rtt_gap_ms = rtt_gap
        else:
            new_row = IPIntelligence(
                ip_address=ip,
                classification=classification,
                risk_score=risk_score,
                reasons=all_reasons,
                asn=final_asn,
                asn_description=final_asn_desc,
                country=final_country,
                isp=final_isp,
                tcp_rtt_ms=tcp_rtt_ms,
                ws_echo_ms=ws_echo_ms,
                rtt_gap_ms=rtt_gap,
                last_checked=datetime.utcnow(),
            )
            db.add(new_row)
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"[IP-Intel] DB write failed for {ip}: {e}")

        return result
    finally:
        if close_db:
            db.close()


async def intelligence_worker_loop():
    """Background: classify unclassified IPs every 30 sec."""
    import asyncio
    while True:
        try:
            await asyncio.sleep(30)
            db = SessionLocal()
            try:
                subq = db.query(IPIntelligence.ip_address).subquery()
                rows = db.query(VisitModel.ip).filter(
                    VisitModel.ip.isnot(None),
                    VisitModel.ip.notin_(subq),
                ).distinct().limit(50).all()

                for (ip,) in rows:
                    if not ip:
                        continue
                    try:
                        await classify_ip(ip, db=db)
                    except Exception as e:
                        print(f"[IP Worker] classify {ip} failed: {e}")
            finally:
                db.close()
        except Exception as e:
            print(f"[IP Worker] loop error: {e}")