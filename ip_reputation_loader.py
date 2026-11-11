"""
ip_reputation_loader.py — Download IP reputation feeds + MMDB daily.
"""
import asyncio
import os
import httpx
import ipaddress
from datetime import datetime

from database import SessionLocal
from models import IPReputationCache

MMDB_URL = "https://github.com/Umkus/ip-index/releases/latest/download/ip-index.mmdb"
MMDB_DIR = "data"
MMDB_PATH = os.path.join(MMDB_DIR, "ip-index.mmdb")

FEEDS = {
    "is-vpn": {
        "url": "https://raw.githubusercontent.com/josephrocca/is-vpn/main/vpn-or-datacenter-ipv4-ranges.txt",
        "type": "cidr_list",
    },
    "blackshield_ips": {
        "url": "https://raw.githubusercontent.com/WinterGate-IC/blackshield-threat-intel/main/ips/malicious_ips.txt",
        "type": "ip_list",
    },
    "blackshield_cidrs": {
        "url": "https://raw.githubusercontent.com/WinterGate-IC/blackshield-threat-intel/main/cidrs/hostile_cidrs.txt",
        "type": "cidr_list",
    },
}


def _parse_feed(text: str, feed_type: str) -> list:
    """Parse feed text into a list of validated IPs/CIDRs."""
    lines = [line.strip() for line in text.split("\n") if line.strip() and not line.startswith("#")]
    valid = []
    if feed_type == "ip_list":
        for line in lines:
            try:
                ipaddress.ip_address(line)
                valid.append(line)
            except ValueError:
                continue
    elif feed_type == "cidr_list":
        for line in lines:
            try:
                ipaddress.ip_network(line, strict=False)
                valid.append(line)
            except ValueError:
                continue
    return valid


async def download_feed(name: str, url: str, feed_type: str) -> list:
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(url)
            if r.status_code == 200:
                return _parse_feed(r.text, feed_type)
            print(f"[RepLoader] {name}: HTTP {r.status_code}")
    except Exception as e:
        print(f"[RepLoader] {name} download failed: {e}")
    return []


async def download_mmdb():
    """Download Umkus/ip-index MMDB if missing or stale."""
    try:
        os.makedirs(MMDB_DIR, exist_ok=True)
        # Skip if freshly downloaded (< 24h)
        if os.path.exists(MMDB_PATH):
            age = datetime.utcnow().timestamp() - os.path.getmtime(MMDB_PATH)
            if age < 86400:
                print(f"[RepLoader] MMDB is fresh ({age/3600:.1f}h old) — skipping")
                return
        print(f"[RepLoader] Downloading MMDB from {MMDB_URL}...")
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            r = await client.get(MMDB_URL)
            if r.status_code == 200:
                tmp_path = MMDB_PATH + ".tmp"
                with open(tmp_path, "wb") as f:
                    f.write(r.content)
                os.replace(tmp_path, MMDB_PATH)
                size_mb = len(r.content) / (1024 * 1024)
                print(f"[RepLoader] MMDB saved ({size_mb:.1f} MB)")
            else:
                print(f"[RepLoader] MMDB download HTTP {r.status_code}")
    except Exception as e:
        print(f"[RepLoader] MMDB download failed: {e}")


async def update_all_feeds():
    db = SessionLocal()
    try:
        for name, config in FEEDS.items():
            data = await download_feed(name, config["url"], config["type"])
            if not data:
                continue
            cache = db.query(IPReputationCache).filter(
                IPReputationCache.source_name == name
            ).first()
            if cache:
                cache.data = data
                cache.record_count = len(data)
                cache.last_updated = datetime.utcnow()
            else:
                db.add(IPReputationCache(
                    source_name=name,
                    data=data,
                    record_count=len(data),
                    last_updated=datetime.utcnow(),
                ))
            db.commit()
            print(f"[RepLoader] {name}: {len(data)} entries")
    except Exception as e:
        print(f"[RepLoader] update_all_feeds failed: {e}")
        db.rollback()
    finally:
        db.close()
        
    # ✅ التحديث الجديد: إبلاغ الفلتر السريع إن في داتا جديدة نزلت
    try:
        from collector.fast_ip_filter import reload_feeds_into_ram
        reload_feeds_into_ram()
    except Exception as e:
        print(f"⚠️ Failed to reload fast filter: {e}")


async def reputation_loader_loop():
    """Download feeds + MMDB every 24h. First run immediately."""
    first_run = True
    while True:
        try:
            if first_run:
                await download_mmdb()
            await update_all_feeds()
            first_run = False
        except Exception as e:
            print(f"[RepLoader] loop error: {e}")
        await asyncio.sleep(86400)
