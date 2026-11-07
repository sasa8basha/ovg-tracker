"""
adsterra_sync.py — Background task to sync Adsterra stats.
"""
import asyncio
import httpx
from datetime import datetime, timedelta
from database import SessionLocal
from models import CampaignModel, VisitModel

async def sync_adsterra_loop():
    while True:
        await asyncio.sleep(300) # كل 5 دقائق
        db = SessionLocal()
        try:
            campaigns = db.query(CampaignModel).filter(CampaignModel.adsterra_api_key.isnot(None)).all()
            for c in campaigns:
                today = datetime.utcnow().strftime("%Y-%m-%d")
                yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
                url = f"https://api3.adsterratools.com/publisher/stats?start_date={yesterday}&finish_date={today}&group_by=placement_sub_id&format=json"
                headers = {"X-API-Key": c.adsterra_api_key}
                
                async with httpx.AsyncClient() as client:
                    try:
                        res = await client.get(url, headers=headers, timeout=10)
                        if res.status_code == 200:
                            items = res.json().get("items", [])
                            for item in items:
                                sub_id = item.get("placement_sub_id") or item.get("sub_id")
                                if sub_id:
                                    v = db.query(VisitModel).filter(VisitModel.click_id == sub_id).first()
                                    if v:
                                        v.impressions = item.get("impression", 0)
                                        v.revenue = item.get("revenue", 0.0)
                            db.commit()
                    except Exception as e:
                        print(f"[Adsterra Sync] Failed for campaign {c.id}: {e}")
        except Exception as e:
            print(f"[Adsterra Sync] Loop error: {e}")
        finally:
            db.close()
