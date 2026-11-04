"""
routers/stats.py — Stats, visits listing, visit detail, CSV export.
"""
import io
import csv
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, SiteModel, VisitModel
from auth import current_user
from analysis import calc_confidence, count_categories, normalize_stored_evidence
from helpers import (
    _resolve_user_site, _apply_date_filter, _parse_date, _safe_filename, csv_safe,
)
from utils import stats_cache

router = APIRouter()


@router.get("/stats")
def get_stats(site: str = Query(None), user: UserModel = Depends(current_user),
              db: Session = Depends(get_db)):
    if site:
        s = _resolve_user_site(site, user, db)
        cache_key = f"stats:site:{s.id}"
        site_id_filter = s.id
    else:
        cache_key = f"stats:user:{user.id}:all"
        site_id_filter = None

    cached = stats_cache.get(cache_key)
    if cached is not None:
        return cached

    def _build():
        q = db.query(VisitModel)
        if site_id_filter is not None:
            q = q.filter(VisitModel.site_id == site_id_filter)
        else:
            q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
                SiteModel.user_id == user.id
            )
        return q

    agg = _build().with_entities(
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    ).one()

    total = int(agg.total or 0)
    valid = int(agg.valid or 0)
    invalid = int(agg.invalid or 0)
    suspicious = int(agg.suspicious or 0)

    recent = _build().order_by(VisitModel.id.desc()).limit(15).all()
    recent_visits = [{
        "id": v.id, "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
        "zone": v.zone_id, "verdict": v.verdict, "country": v.country, "score": v.score,
        "evidence": v.evidence, "timezone": v.timezone, "hardware": v.hardware,
        "conn_type": v.connection_type, "asn": v.asn, "is_vpn": v.is_vpn, "webrtc": v.webrtc_ip,
    } for v in recent]

    result = {"total": total, "valid": valid, "invalid": invalid,
              "suspicious": suspicious, "recent": recent_visits}
    stats_cache.set(cache_key, result)
    return result


@router.get("/visits")
def get_visits(
    site: str = Query(None), verdict: str = Query(None), country: str = Query(None),
    zone: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    page: int = Query(1, ge=1), per_page: int = Query(20, ge=10, le=100),
    cursor: int = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    if verdict:
        q = q.filter(VisitModel.verdict == verdict)
    if country:
        q = q.filter((VisitModel.country_code == country) | (VisitModel.country == country))
    if zone:
        q = q.filter(VisitModel.zone_id == zone)
    q = _apply_date_filter(q, from_date, to_date)

    if cursor is not None:
        q = q.filter(VisitModel.id < cursor)
        visits = q.order_by(VisitModel.id.desc()).limit(per_page + 1).all()
        has_more = len(visits) > per_page
        visits = visits[:per_page]
        next_cursor = visits[-1].id if has_more else None
        total = None; pages = None; page = None
    else:
        try:
            rows = q.with_entities(
                VisitModel, func.count().over().label("tc")
            ).order_by(VisitModel.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
            if rows:
                total = int(rows[0][1])
                visits = [r[0] for r in rows]
            else:
                total = q.count()
                visits = []
        except Exception:
            total = q.count()
            visits = q.order_by(VisitModel.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
        pages = (total + per_page - 1) // per_page if total else 0
        next_cursor = None

    items = [{
        "id": v.id, "time": v.timestamp.strftime("%Y-%m-%d %H:%M") if v.timestamp else "",
        "ip": v.ip, "zone": v.zone_id, "verdict": v.verdict, "score": v.score,
        "country": v.country, "country_code": v.country_code,
        "device": v.device, "browser": v.browser,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls,
    } for v in visits]
    return {"items": items, "total": total, "page": page,
            "pages": pages, "next_cursor": next_cursor}


@router.get("/visits/{visit_id}")
def get_visit_detail(visit_id: int, user: UserModel = Depends(current_user),
                     db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(SiteModel).filter(
        VisitModel.id == visit_id, SiteModel.user_id == user.id
    ).first()
    if not v:
        raise HTTPException(404, "غير مصرح لك بعرض هذه الزيارة")
    evidence = v.evidence or []
    signals = normalize_stored_evidence(evidence)
    return {
        "id": v.id, "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        "ip": v.ip, "zone_id": v.zone_id, "score": v.score, "verdict": v.verdict,
        "evidence": evidence,
        "os": v.os, "device": v.device, "browser": v.browser,
        "country": v.country, "country_code": v.country_code, "isp": v.isp,
        "timezone": v.timezone, "canvas_hash": v.canvas_hash, "hardware": v.hardware,
        "connection_type": v.connection_type, "asn": v.asn,
        "is_vpn": v.is_vpn, "webrtc_ip": v.webrtc_ip,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks, "scrolls": v.scrolls,
        "confidence": calc_confidence(signals),
        "raw_score": sum(s.get("score", 0) for s in signals),
        "categories": count_categories(signals),
    }


@router.get("/export/visits")
def export_visits(
    site: str = Query(None), verdict: str = Query(None), zone: str = Query(None),
    from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    if verdict:
        q = q.filter(VisitModel.verdict == verdict)
    if zone:
        q = q.filter(VisitModel.zone_id == zone)
    q = _apply_date_filter(q, from_date, to_date).order_by(VisitModel.id.desc()).limit(5000)

    fd = _parse_date(from_date)
    td = _parse_date(to_date)
    parts = []
    if verdict:
        parts.append(verdict)
    if fd:
        parts.append(fd.strftime("%Y%m%d"))
    if td:
        parts.append(td.strftime("%Y%m%d"))
    filename = _safe_filename("ovg_visits", *parts) if parts else "ovg_visits_export.csv"

    def iter_csv():
        try:
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow(["ID", "Time", "IP", "Country", "Country Code", "Zone",
                        "Verdict", "Score", "OS", "Browser", "Device",
                        "Time on Page (s)", "Clicks", "Scrolls", "ISP", "ASN", "VPN"])
            yield out.getvalue()
            out.seek(0); out.truncate(0)
            for v in q.yield_per(500):
                row = [v.id, v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
                       v.ip, v.country, v.country_code or "", v.zone_id, v.verdict, v.score,
                       v.os, v.browser, v.device,
                       round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
                       v.clicks, v.scrolls, v.isp, v.asn, v.is_vpn]
                w.writerow([csv_safe(x) for x in row])
                yield out.getvalue()
                out.seek(0); out.truncate(0)
        except GeneratorExit:
            return
        except Exception as e:
            print(f"Export error: {e}")

    return StreamingResponse(
        iter_csv(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
             )
