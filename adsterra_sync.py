"""
adsterra_sync.py — Background sync: update visit-level impressions/revenue.
"""
import asyncio
import httpx
from datetime import datetime, timedelta

from database import SessionLocal
from utils import stats_cache  # M-33
from models import CampaignModel, VisitModel


API_BASE = "https://api3.adsterratools.com/publisher"
SYNC_DAYS_BACK = 1  # M-31/M-34: reduced from 3  # H-21: was 3 days → expensive


def _sync_campaign_sync(campaign_id: int, api_key: str, db) -> dict:
    now = datetime.utcnow()
    fd = (now - timedelta(days=SYNC_DAYS_BACK)).strftime("%Y-%m-%d")
    td = now.strftime("%Y-%m-%d")
    url = (
        f"{API_BASE}/stats?format=json"
        f"&start_date={fd}&finish_date={td}&group_by[]=placement_sub_id"
    )
    try:
        with httpx.Client(timeout=20) as client:
            r = client.get(url, headers={"X-API-Key": api_key, "Accept": "application/json"})
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "updated": 0, "skipped": 0}
            data = r.json()
    except Exception as e:
        return {"error": str(e)[:150], "updated": 0, "skipped": 0}

    items = data.get("items", []) or []
    updated = 0
    skipped = 0
    for item in items:
        sub_id = str(item.get("placement_sub_id") or item.get("sub_id") or "").strip()
        if not sub_id:
            skipped += 1
            continue
        impressions = int(item.get("impression", 0) or 0)
        revenue = float(item.get("revenue", 0) or 0)
        clicks = int(item.get("clicks", 0) or 0)
        if impressions <= 0 and revenue <= 0:
            continue
        v = db.query(VisitModel).filter(
            VisitModel.campaign_id == campaign_id,
            (VisitModel.session_id == sub_id) | (VisitModel.click_id == sub_id),
        ).first()
        if not v:
            skipped += 1
            continue
        v.impressions = impressions
        # H-22: never overwrite with lower revenue (non-monotonic API)
        if revenue > float(v.revenue or 0):
            v.revenue = round(revenue, 6)
        if clicks > 0:
            v.clicks = clicks
        updated += 1

    if updated > 0:
        db.commit()
        try:
            stats_cache.invalidate_prefix("stats:")
        except Exception:
            pass  # M-33

    return {"updated": updated, "skipped": skipped, "error": None, "items": len(items)}


async def sync_adsterra_loop():
    while True:
        await asyncio.sleep(1800)  # H-21: 5min → 30min
        db = SessionLocal()
        try:
            campaigns = (
                db.query(CampaignModel)
                .filter(CampaignModel.adsterra_api_key.isnot(None))
                .filter(CampaignModel.status == "active")
                .all()
            )
            if not campaigns:
                continue
            for c in campaigns:
                try:
                    result = await asyncio.to_thread(
                        _sync_campaign_sync, c.id, c.adsterra_api_key, db
                    )
                    if result.get("error"):
                        print(f"[Adsterra Sync] campaign {c.id}: {result['error']}")
                    elif result["updated"] > 0:
                        print(
                            f"[Adsterra Sync] campaign {c.id}: "
                            f"updated={result['updated']} skipped={result['skipped']} items={result['items']}"
                        )
                except Exception as e:
                    print(f"[Adsterra Sync] campaign {c.id} failed: {e}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Adsterra Sync] Loop error: {e}")
        finally:
            db.close()