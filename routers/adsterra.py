"""
routers/adsterra.py — Adsterra Publisher API proxy + caching.
Endpoints from https://docs.adsterratools.com
"""
import httpx
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, CampaignModel, VisitModel
from auth import current_user
from utils import TTLCache


router = APIRouter()
API_BASE = "https://api3.adsterratools.com/publisher"

_domains_cache = TTLCache(maxsize=200, ttl=3600)
_placements_cache = TTLCache(maxsize=500, ttl=3600)
_smartlinks_cache = TTLCache(maxsize=200, ttl=3600)
_stats_cache = TTLCache(maxsize=1000, ttl=300)


def _resolve_campaign(cid, user, db):
    c = db.query(CampaignModel).filter(
        CampaignModel.id == cid,
        CampaignModel.user_id == user.id,
    ).first()
    if not c:
        raise HTTPException(404, "الحملة مش موجودة")
    return c


def _require_key(c):
    if not c.adsterra_api_key:
        raise HTTPException(400, "الحملة مفيهاش Adsterra API key مسجل")


async def _http_get(api_key: str, path: str, params: dict = None):
    """Hit Adsterra endpoint with X-API-Key header."""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(
                f"{API_BASE}{path}",
                headers={"X-API-Key": api_key, "Accept": "application/json"},
                params=params or {},
            )
            if r.status_code == 200:
                return r.json()
            if r.status_code in (401, 403):
                raise HTTPException(401, "Adsterra API key غير صالح")
            raise HTTPException(502, f"Adsterra HTTP {r.status_code}: {r.text[:200]}")
    except httpx.TimeoutException:
        raise HTTPException(504, "Adsterra API timeout")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Adsterra error: {str(e)[:200]}")


@router.post("/verify")
async def verify(payload: dict, user: UserModel = Depends(current_user)):
    """Validate an Adsterra API key by listing domains."""
    key = (payload.get("api_key") or "").strip()
    if not key:
        raise HTTPException(400, "API key مطلوب")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                f"{API_BASE}/domains?format=json",
                headers={"X-API-Key": key, "Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json()
                items = data.get("items", []) or []
                return {
                    "ok": True,
                    "domains_count": data.get("itemCount", len(items)),
                    "sample": [d.get("title") for d in items[:5] if d.get("title")],
                }
            if r.status_code in (401, 403):
                return {"ok": False, "error": "API key غير صالح"}
            return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


@router.get("/{campaign_id}/domains")
async def list_domains(
    campaign_id: int,
    force: bool = Query(False),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    _require_key(c)
    cache_key = f"domains:{c.id}:{hash(c.adsterra_api_key)}"
    if not force:
        cached = _domains_cache.get(cache_key)
        if cached:
            return cached
    data = await _http_get(c.adsterra_api_key, "/domains", {"format": "json"})
    result = {
        "count": data.get("itemCount", 0),
        "items": [
            {"id": d.get("id"), "title": d.get("title")}
            for d in (data.get("items") or [])
        ],
    }
    _domains_cache.set(cache_key, result)
    return result


@router.get("/{campaign_id}/placements")
async def list_placements(
    campaign_id: int,
    domain_id: int = Query(None),
    force: bool = Query(False),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    _require_key(c)
    cache_key = f"placements:{c.id}:{domain_id or 'all'}"
    if not force:
        cached = _placements_cache.get(cache_key)
        if cached:
            return cached
    if domain_id:
        data = await _http_get(c.adsterra_api_key, f"/domains/{domain_id}/placements", {"format": "json"})
    else:
        data = await _http_get(c.adsterra_api_key, "/placements", {"format": "json"})
    result = {
        "count": data.get("itemCount", 0),
        "items": [
            {
                "id": p.get("id"),
                "title": p.get("title"),
                "alias": p.get("alias"),
                "direct_url": p.get("direct_url"),
                "domain_id": p.get("domain_id"),
            }
            for p in (data.get("items") or [])
        ],
    }
    _placements_cache.set(cache_key, result)
    return result


@router.get("/{campaign_id}/smartlinks")
async def list_smartlinks(
    campaign_id: int,
    force: bool = Query(False),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    c = _resolve_campaign(campaign_id, user, db)
    _require_key(c)
    cache_key = f"smartlinks:{c.id}"
    if not force:
        cached = _smartlinks_cache.get(cache_key)
        if cached:
            return cached
    data = await _http_get(c.adsterra_api_key, "/smartlinks", {"format": "json"})
    inner = data.get("data", {}) if isinstance(data, dict) else {}
    items = inner.get("items", []) or data.get("items", []) or []
    result = {
        "count": len(items),
        "items": [
            {
                "id": s.get("id"),
                "title": s.get("title"),
                "alias": s.get("alias"),
                "url": s.get("url"),
                "traffic_type": s.get("traffic_type"),
                "status": s.get("status"),
            }
            for s in items
        ],
    }
    _smartlinks_cache.set(cache_key, result)
    return result


@router.get("/{campaign_id}/stats")
async def get_stats(
    campaign_id: int,
    from_date: str = Query(None),
    to_date: str = Query(None),
    group_by: str = Query("date"),
    force: bool = Query(False),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    Get stats grouped by date/country/placement/placement_sub_id.
    group_by can be comma-separated (e.g., "date,country").
    """
    c = _resolve_campaign(campaign_id, user, db)
    _require_key(c)

    now = datetime.utcnow()
    fd = from_date or (now - timedelta(days=7)).strftime("%Y-%m-%d")
    td = to_date or now.strftime("%Y-%m-%d")

    allowed = {"date", "country", "placement", "placement_sub_id", "domain"}
    groups = [g.strip() for g in group_by.split(",") if g.strip() in allowed]
    if not groups:
        groups = ["date"]

    cache_key = f"stats:{c.id}:{fd}:{td}:{','.join(groups)}"
    if not force:
        cached = _stats_cache.get(cache_key)
        if cached:
            return cached

    # Build query with multiple group_by[] params
    query_parts = [f"format=json", f"start_date={fd}", f"finish_date={td}"]
    for g in groups:
        query_parts.append(f"group_by[]={g}")
    url = f"{API_BASE}/stats?" + "&".join(query_parts)

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            r = await client.get(
                url,
                headers={"X-API-Key": c.adsterra_api_key, "Accept": "application/json"},
            )
            if r.status_code != 200:
                raise HTTPException(502, f"Adsterra HTTP {r.status_code}: {r.text[:200]}")
            data = r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Adsterra error: {str(e)[:200]}")

    items = data.get("items", []) or []
    total_impressions = sum(int(i.get("impression", 0) or 0) for i in items)
    total_clicks = sum(int(i.get("clicks", 0) or 0) for i in items)
    total_revenue = sum(float(i.get("revenue", 0) or 0) for i in items)
    cpm = (total_revenue / total_impressions * 1000) if total_impressions > 0 else 0
    ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0

    result = {
        "from_date": fd,
        "to_date": td,
        "group_by": groups,
        "items": items,
        "totals": {
            "impressions": total_impressions,
            "clicks": total_clicks,
            "revenue": round(total_revenue, 6),
            "cpm": round(cpm, 4),
            "ctr": round(ctr, 4),
        },
        "itemCount": len(items),
        "fetched_at": datetime.utcnow().isoformat(),
    }
    _stats_cache.set(cache_key, result)
    return result


@router.get("/{campaign_id}/overview")
async def overview(
    campaign_id: int,
    days: int = Query(7, ge=1, le=90),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Summary with series + top countries + top placements."""
    c = _resolve_campaign(campaign_id, user, db)
    _require_key(c)
    now = datetime.utcnow()
    fd = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    td = now.strftime("%Y-%m-%d")

    series = await get_stats(campaign_id, from_date=fd, to_date=td, group_by="date", user=user, db=db)
    try:
        countries = await get_stats(campaign_id, from_date=fd, to_date=td, group_by="country", user=user, db=db)
    except HTTPException:
        countries = {"items": []}
    try:
        placements_data = await get_stats(campaign_id, from_date=fd, to_date=td, group_by="placement", user=user, db=db)
    except HTTPException:
        placements_data = {"items": []}

    top_countries = sorted(
        countries.get("items", []),
        key=lambda x: float(x.get("revenue", 0) or 0),
        reverse=True,
    )[:15]
    top_placements = sorted(
        placements_data.get("items", []),
        key=lambda x: float(x.get("revenue", 0) or 0),
        reverse=True,
    )[:20]

    return {
        "campaign": {"id": c.id, "name": c.name, "type": c.type},
        "period": {"from": fd, "to": td, "days": days},
        "totals": series.get("totals", {}),
        "series": series.get("items", []),
        "top_countries": top_countries,
        "top_placements": top_placements,
    }


@router.post("/{campaign_id}/sync-visits")
async def sync_visits(
    campaign_id: int,
    days: int = Query(3, ge=1, le=30),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    Force sync of visit-level impressions/revenue from Adsterra using
    placement_sub_id → session_id matching.
    """
    c = _resolve_campaign(campaign_id, user, db)
    _require_key(c)
    now = datetime.utcnow()
    fd = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    td = now.strftime("%Y-%m-%d")

    data = await get_stats(
        campaign_id,
        from_date=fd,
        to_date=td,
        group_by="placement_sub_id",
        force=True,
        user=user,
        db=db,
    )
    items = data.get("items", [])
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
        v = db.query(VisitModel).filter(
            VisitModel.campaign_id == c.id,
            (VisitModel.session_id == sub_id) | (VisitModel.click_id == sub_id),
        ).first()
        if not v:
            skipped += 1
            continue
        v.impressions = impressions
        v.revenue = round(revenue, 6)
        if clicks > 0:
            v.clicks = clicks
        updated += 1

    if updated > 0:
        db.commit()

    return {
        "ok": True,
        "period": {"from": fd, "to": td},
        "updated": updated,
        "skipped": skipped,
        "total_items": len(items),
    }