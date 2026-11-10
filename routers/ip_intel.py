"""
routers/ip_intel.py — IP White/Black lists + PopAds plain-text export.
IPs are filtered to those that appeared in actual visits (per campaign).
"""
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, VisitModel, CampaignModel, IPIntelligence
from auth import current_user

router = APIRouter()

WHITELIST_RISK_MAX = 20
BLACKLIST_RISK_MIN = 60


def _ips_for_campaign(campaign_id, user, db):
    """Return set of IPs that hit visits for a campaign (or all user campaigns)."""
    q = db.query(VisitModel.ip).filter(VisitModel.ip.isnot(None))
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    return {row[0] for row in q.distinct().all() if row[0]}


@router.get("/whitelist")
def get_whitelist(
    campaign_id: int = Query(None),
    limit: int = Query(2000, ge=1, le=10000),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    ips = _ips_for_campaign(campaign_id, user, db)
    if not ips:
        return {"count": 0, "items": []}

    rows = db.query(IPIntelligence).filter(
        IPIntelligence.ip_address.in_(ips),
        IPIntelligence.classification == "residential",
        IPIntelligence.risk_score < WHITELIST_RISK_MAX,
    ).limit(limit).all()

    return {
        "count": len(rows),
        "items": [
            {
                "ip": r.ip_address,
                "country": r.country,
                "isp": r.isp,
                "asn": r.asn,
                "risk_score": r.risk_score,
                "last_checked": r.last_checked.isoformat() if r.last_checked else None,
            }
            for r in rows
        ],
    }


@router.get("/blacklist")
def get_blacklist(
    campaign_id: int = Query(None),
    limit: int = Query(2000, ge=1, le=10000),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    ips = _ips_for_campaign(campaign_id, user, db)
    if not ips:
        return {"count": 0, "items": []}

    rows = db.query(IPIntelligence).filter(
        IPIntelligence.ip_address.in_(ips),
        IPIntelligence.risk_score >= BLACKLIST_RISK_MIN,
    ).limit(limit).all()

    return {
        "count": len(rows),
        "items": [
            {
                "ip": r.ip_address,
                "classification": r.classification,
                "country": r.country,
                "isp": r.isp,
                "asn": r.asn,
                "risk_score": r.risk_score,
                "reasons": r.reasons or [],
            }
            for r in rows
        ],
    }


@router.get("/stats")
def ip_stats(
    campaign_id: int = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    ips = _ips_for_campaign(campaign_id, user, db)
    if not ips:
        return {"total": 0, "residential": 0, "datacenter": 0, "vpn": 0, "proxy": 0, "tor": 0, "unknown": 0}

    rows = db.query(
        IPIntelligence.classification,
        func.count(IPIntelligence.id),
    ).filter(
        IPIntelligence.ip_address.in_(ips)
    ).group_by(IPIntelligence.classification).all()

    result = {"total": len(ips), "residential": 0, "datacenter": 0, "vpn": 0, "proxy": 0, "tor": 0, "unknown": 0, "suspicious": 0}
    for cls, cnt in rows:
        key = cls or "unknown"
        if key in result:
            result[key] = int(cnt)
    return result


@router.get("/export/whitelist")
def export_whitelist(
    campaign_id: int = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Export whitelist as plain text — one IP per line (PopAds IP Targeting format)."""
    ips = _ips_for_campaign(campaign_id, user, db)
    rows = []
    if ips:
        rows = db.query(IPIntelligence).filter(
            IPIntelligence.ip_address.in_(ips),
            IPIntelligence.classification == "residential",
            IPIntelligence.risk_score < WHITELIST_RISK_MAX,
        ).all()

    def iter_txt():
        for r in rows:
            ip = (r.ip_address or "").strip()
            if ip:
                yield ip + "\n"

    fn = f"ovg_whitelist_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.txt"
    return StreamingResponse(
        iter_txt(),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fn}"'},
    )


@router.get("/export/blacklist")
def export_blacklist(
    campaign_id: int = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Export blacklist as plain text — one IP per line (PopAds IP Targeting format)."""
    ips = _ips_for_campaign(campaign_id, user, db)
    rows = []
    if ips:
        rows = db.query(IPIntelligence).filter(
            IPIntelligence.ip_address.in_(ips),
            IPIntelligence.risk_score >= BLACKLIST_RISK_MIN,
        ).all()

    def iter_txt():
        for r in rows:
            ip = (r.ip_address or "").strip()
            if ip:
                yield ip + "\n"

    fn = f"ovg_blacklist_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.txt"
    return StreamingResponse(
        iter_txt(),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fn}"'},
    )
