"""
routers/tracker.py — Tracking routes + tracker JS templates (v7.1)

Endpoints:
    GET /campaigns/{id}/tracker-code-v3         — JSON {part1, part2, full, ...}
    GET /campaigns/{id}/tracker-code-v3/download — Full .txt file (browser download)
    POST /track                                  — Legacy v2 (deprecated)
"""
import json
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, CampaignModel
from schemas import TrackPayload
from auth import current_user
from analysis import get_ip_info, parse_ua, extract_zone_id, analyze_visit
from utils import get_client_ip, safe_origin, track_limiter, stats_cache
from collector.tracker_v3_template import TRACKER_V3_JS


router = APIRouter()


# =========================================================
# HELPERS
# =========================================================
def _build_tracker_code(campaign: CampaignModel, origin: str) -> str:
    """Build the full tracker code for a campaign."""
    js_inner = TRACKER_V3_JS \
        .replace("__OVG_CAMPAIGN_KEY__", campaign.campaign_key) \
        .replace("__OVG_ENDPOINT_BASE__", json.dumps(origin)[1:-1])  # H-29: JS-safe escape
    return "<script>\n" + js_inner + "\n</script>"


def _split_code(full_code: str) -> tuple:
    """Split the code at a safe boundary (H-28: prefer PART-BOUNDARY markers)."""
    marker = "// PART-BOUNDARY"
    if marker in full_code:
        i = full_code.find(marker)
        return full_code[:i].rstrip() + "\n", full_code[i:].lstrip()
    total = len(full_code)
    mid = total // 2
    search_start = max(0, mid - 4000)
    search_end = min(total, mid + 4000)

    candidates = []
    idx = search_start
    while idx < search_end:
        found = full_code.find("\n  function ", idx)
        if found == -1 or found >= search_end:
            break
        candidates.append(found)
        idx = found + 1

    if candidates:
        best = min(candidates, key=lambda x: abs(x - mid))
        return full_code[:best].rstrip() + "\n", full_code[best:].lstrip()

    idx = full_code.find("\n", mid)
    idx = idx if idx != -1 else mid
    return full_code[:idx].rstrip() + "\n", full_code[idx:].lstrip()


def _safe_filename(campaign_name: str, campaign_key: str) -> str:
    """Generate a safe filename for download."""
    base = "ovg-tracker-v3"
    safe_name = "".join(
        c if (c.isalnum() or c in "-_") else "_"
        for c in (campaign_name or "")
    )[:30]
    key_part = (campaign_key or "unknown")[:8]
    if safe_name:
        return f"{base}_{safe_name}_{key_part}.txt"
    return f"{base}_{key_part}.txt"


# =========================================================
# GET TRACKER CODE (JSON — for display in HTML)
# =========================================================
@router.get("/campaigns/{campaign_id}/tracker-code-v3")
def get_tracker_code_v3(
    campaign_id: int,
    request: Request,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = db.query(CampaignModel).filter(
        CampaignModel.id == campaign_id,
        CampaignModel.user_id == user.id,
    ).first()
    if not c:
        raise HTTPException(404, "الحملة مش موجودة")
    if c.type == "direct":
        raise HTTPException(400, "حملات الـ Direct ملهاش كود تتبع، ليها رابط.")

    origin = safe_origin(request)
    full_code = _build_tracker_code(c, origin)
    part1, part2 = _split_code(full_code)

    return Response(
        content=json.dumps({
            "part1": part1,
            "part2": part2,
            "full": full_code,
            "version": "v7.1",
            "campaign_key": c.campaign_key,
            "size_bytes": len(full_code.encode("utf-8")),
            "lines": full_code.count("\n") + 1,
            "download_url": f"/api/campaigns/{c.id}/tracker-code-v3/download",
        }),
        media_type="application/json",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


# =========================================================
# DOWNLOAD TRACKER CODE (TXT file — browser download)
# =========================================================
@router.get("/campaigns/{campaign_id}/tracker-code-v3/download")
def download_tracker_code_v3(
    campaign_id: int,
    request: Request,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = db.query(CampaignModel).filter(
        CampaignModel.id == campaign_id,
        CampaignModel.user_id == user.id,
    ).first()
    if not c:
        raise HTTPException(404, "الحملة مش موجودة")
    if c.type == "direct":
        raise HTTPException(400, "حملات الـ Direct ملهاش كود تتبع، ليها رابط.")

    origin = safe_origin(request)
    full_code = _build_tracker_code(c, origin)

    # Add header comment for clarity
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = (
        "<!-- OVG Tracker v7.1 -->\n"
        f"<!-- Campaign: {c.name} -->\n"
        f"<!-- Campaign Key: {c.campaign_key} -->\n"
        f"<!-- Generated: {timestamp} -->\n"
        "<!-- Instructions: -->\n"
        "<!-- 1. Paste this ENTIRE file into your landing page HTML -->\n"
        "<!-- 2. Place it inside <head> or right before </body> -->\n"
        "<!-- 3. Make sure the page URL includes ?zone=XXX for zone tracking -->\n\n"
    )
    final_content = header + full_code + "\n"

    filename = _safe_filename(c.name, c.campaign_key)
    buffer = io.BytesIO(final_content.encode("utf-8"))

    return StreamingResponse(
        buffer,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


# =========================================================
# LEGACY V2 TRACK ENDPOINT (kept for backward compat)
# =========================================================
@router.post("/track")
async def track_visit(payload: TrackPayload, request: Request, db: Session = Depends(get_db)):
    """
    Legacy V2 tracking endpoint.
    Kept to not break old scripts — but no longer used by the new tracker.
    """
    return {
        "status": "success",
        "warning": "V2 tracking is deprecated. Please use V3 campaign tracking.",
    }