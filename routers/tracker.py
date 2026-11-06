"""
routers/tracker.py — Tracking routes + tracker JS templates.
"""
import json
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, CampaignModel
from schemas import TrackPayload
from auth import current_user
from analysis import get_ip_info, parse_ua, extract_zone_id, analyze_visit
from utils import get_client_ip, safe_origin, track_limiter, stats_cache
from collector.tracker_v3_template import TRACKER_V3_JS
from datetime import datetime, timedelta
from sqlalchemy import func, distinct

router = APIRouter()

@router.get("/campaigns/{campaign_id}/tracker-code-v3")
def get_tracker_code_v3(campaign_id: int, request: Request, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    c = db.query(CampaignModel).filter(CampaignModel.id == campaign_id, CampaignModel.user_id == user.id).first()
    if not c: raise HTTPException(404, "الحملة مش موجودة")
    if c.type == "direct": raise HTTPException(400, "حملات الـ Direct ملهاش كود تتبع، ليها رابط.")

    origin = safe_origin(request)
    js_inner = TRACKER_V3_JS \
        .replace("__OVG_CAMPAIGN_KEY__", c.campaign_key) \
        .replace("__OVG_ENDPOINT_BASE__", origin)

    full_code = "<script>\n" + js_inner + "\n</script>"
    
    # Split logic for easier copying
    total = len(full_code); mid = total // 2; search_start = max(0, mid - 4000); search_end = min(total, mid + 4000)
    candidates = []; idx = search_start
    while idx < search_end:
        found = full_code.find("\n  function ", idx)
        if found == -1 or found >= search_end: break
        candidates.append(found); idx = found + 1
    if candidates:
        best = min(candidates, key=lambda x: abs(x - mid))
        part1, part2 = full_code[:best].rstrip() + "\n", full_code[best:].lstrip()
    else:
        idx = full_code.find('\n', mid); idx = idx if idx != -1 else mid
        part1, part2 = full_code[:idx].rstrip() + "\n", full_code[idx:].lstrip()

    return Response(content=json.dumps({"part1": part1, "part2": part2, "full": full_code, "version": "v3", "campaign_key": c.campaign_key, "size_bytes": len(full_code.encode("utf-8")), "lines": full_code.count("\n") + 1}), media_type="application/json", headers={"Cache-Control": "no-store, max-age=0"})

@router.post("/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    # Legacy V2 - disabled for sites, but keeping route to not break old scripts
    return {"status": "success", "warning": "V2 tracking is deprecated. Please use V3 campaign tracking."}
