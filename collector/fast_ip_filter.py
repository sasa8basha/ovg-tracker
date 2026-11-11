"""
collector/fast_ip_filter.py — Zero-Latency IP Filter (Sub-30ms)
"""
import ipaddress
from database import SessionLocal
from models import IPReputationCache
import maxminddb

try:
    import pytricia
    HAS_PYTRICIA = True
except ImportError:
    HAS_PYTRICIA = False
    print("⚠️ pytricia not installed. Falling back to basic sets.")

# هياكل البيانات في الذاكرة
_VPN_DATACENTER_RADIX = None
_MALICIOUS_IPS = set()
_MMDB_READER = None

def init_fast_filter(mmdb_path="data/ip-index.mmdb"):
    """تشغيل الفلتر وتحميل الداتا في الـ RAM (بتتنفذ مرة واحدة عند تشغيل السيرفر)"""
    global _VPN_DATACENTER_RADIX, _MALICIOUS_IPS, _MMDB_READER
    
    print("🚀 Initializing Fast IP Filter (In-Memory)...")
    
    # 1. فتح MaxMind DB في وضع MMAP (أسرع بمراحل)
    try:
        _MMDB_READER = maxminddb.open_database(mmdb_path, maxminddb.MODE_MMAP)
        print("✅ MMDB loaded via MMAP")
    except Exception as e:
        print(f"❌ MMDB failed to load: {e}")

    # 2. تحميل قوائم السمعة من الداتابيز للذاكرة
    db = SessionLocal()
    try:
        feeds = db.query(IPReputationCache).all()
        
        if HAS_PYTRICIA:
            _VPN_DATACENTER_RADIX = pytricia.PyTricia()
        else:
            _VPN_DATACENTER_RADIX = set()

        for feed in feeds:
            data = feed.data or []
            if feed.source_name in ("is-vpn", "blackshield_cidrs"):
                for cidr in data:
                    try:
                        if HAS_PYTRICIA:
                            _VPN_DATACENTER_RADIX.insert(cidr, True)
                        else:
                            _VPN_DATACENTER_RADIX.add(ipaddress.ip_network(cidr, strict=False))
                    except Exception:
                        pass
            elif feed.source_name == "blackshield_ips":
                _MALICIOUS_IPS.update(data)
        
        print(f"✅ Loaded {len(_MALICIOUS_IPS)} malicious IPs and {len(_VPN_DATACENTER_RADIX)} CIDRs into RAM")
    except Exception as e:
        print(f"❌ Failed to load DB feeds: {e}")
    finally:
        db.close()

def check_ip_fast(ip_str: str) -> dict:
    """
    الدالة دي بتاخد أقل من 2 مللي ثانية.
    بترجع: {"blocked": bool, "reason": str}
    """
    if not ip_str:
        return {"blocked": False, "reason": ""}

    # 1. فحص الـ Malicious IPs (سريع جداً)
    if ip_str in _MALICIOUS_IPS:
        return {"blocked": True, "reason": "MALICIOUS_IP"}

    # 2. فحص قوائم الـ VPN والـ Datacenter (Radix Tree)
    if _VPN_DATACENTER_RADIX:
        try:
            if HAS_PYTRICIA:
                if _VPN_DATACENTER_RADIX.has_key(ip_str):
                    return {"blocked": True, "reason": "VPN_DATACENTER_RADIX"}
            else:
                ip_obj = ipaddress.ip_address(ip_str)
                for net in _VPN_DATACENTER_RADIX:
                    if ip_obj in net:
                        return {"blocked": True, "reason": "VPN_DATACENTER_RADIX"}
        except Exception:
            pass

    # 3. فحص الـ ASN من MaxMind (سريع جداً مع MMAP)
    if _MMDB_READER:
        try:
            data = _MMDB_READER.get(ip_str)
            if data:
                if data.get("is_hosting") or data.get("is_anycast"):
                    return {"blocked": True, "reason": "DATACENTER_ASN_MMDB"}
                
                asn = str(data.get("asn", ""))
                DATACENTER_ASNS = {"AS16509", "AS14618", "AS8987", "AS396982", "AS15169", "AS8075", "AS13335", "AS14061", "AS24940", "AS16276"}
                if asn in DATACENTER_ASNS:
                    return {"blocked": True, "reason": f"DATACENTER_ASN_{asn}"}
        except Exception:
            pass

    return {"blocked": False, "reason": ""}
