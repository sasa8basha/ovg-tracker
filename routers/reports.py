"""
routers/reports.py — Zone reports, smart P&L report, countries, tech, map.
"""
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, and_, not_
from sqlalchemy.orm import Session

from database import get_db
from models import UserModel, SiteModel, VisitModel
from auth import current_user
from helpers import (
    _resolve_user_site, _apply_date_filter, _country_key,
)
from metrics import ( # <--- استخدام المحرك الموحد
    extract_source, compute_pl, compute_zone_score,
    compute_zone_lifecycle, is_wasted_visit,
)

router = APIRouter()


@router.get("/reports/zones")
def get_zone_reports(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    inv = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    sus = func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0))
    val = func.sum(case((VisitModel.verdict == "valid", 1), else_=0))
    q = db.query(VisitModel.zone_id,
                 func.count(VisitModel.id).label("total"),
                 val.label("valid"), inv.label("invalid"), sus.label("suspicious"))
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.zone_id).all()

    report = []
    for z in rows:
        if not z.zone_id or z.zone_id == "unknown":
            continue
        total = int(z.total or 0)
        invalid = int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = "?" if total < 10 else ("A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F")
        report.append({
            "zone": z.zone_id, "total": total, "valid": int(z.valid or 0),
            "invalid": invalid, "suspicious": int(z.suspicious or 0),
            "bot_rate": rate, "grade": grade, "min_sample_met": total >= 10,
            "top_evidence": [],
        })
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report


@router.get("/reports/smart")
def smart_report(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    buy_cpm = float(user.cpm_buy or 1.0)
    sell_cpm = float(user.cpm_sell or 1.5)

    q = db.query(VisitModel.zone_id, VisitModel.verdict, VisitModel.evidence)
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    q = _apply_date_filter(q, from_date, to_date).limit(100000)

    zones = {}
    total_all = 0
    valid_all = 0
    invalid_all = 0
    suspicious_all = 0
    wasted_all = 0

    for row in q.all():
        total_all += 1
        zid = row.zone_id or "unknown"
        if zid not in zones:
            zones[zid] = {"total": 0, "valid": 0, "invalid": 0, "suspicious": 0, "wasted": 0}
        z = zones[zid]
        z["total"] += 1
        verdict = row.verdict or "unknown"
        if verdict == "valid":
            z["valid"] += 1
            valid_all += 1
            if is_wasted_visit(row.evidence):
                z["wasted"] += 1
                wasted_all += 1
        elif verdict == "invalid":
            z["invalid"] += 1
            invalid_all += 1
        elif verdict == "suspicious":
            z["suspicious"] += 1
            suspicious_all += 1

    summary_pl = compute_pl(total_all, valid_all, wasted_all, buy_cpm, sell_cpm)
    summary = {
        "total": total_all,
        "valid": valid_all,
        "invalid": invalid_all,
        "suspicious": suspicious_all,
        "wasted": wasted_all,
        "bot_rate": round(invalid_all / total_all * 100.0, 2) if total_all > 0 else 0.0,
        "wasted_rate": round(wasted_all / total_all * 100.0, 2) if total_all > 0 else 0.0,
        "cpm_buy": buy_cpm,
        "cpm_sell": sell_cpm,
        "pl": summary_pl,
    }

    result_zones = []
    for zid, z in zones.items():
        if zid == "unknown":
            continue
        total = z["total"]
        bot_rate = round(z["invalid"] / total * 100.0, 2) if total > 0 else 0.0
        wasted_rate = round(z["wasted"] / total * 100.0, 2) if total > 0 else 0.0
        pl = compute_pl(total, z["valid"], z["wasted"], buy_cpm, sell_cpm)
        score = compute_zone_score(pl["profit"], pl["roi"], bot_rate, wasted_rate, total)
        lifecycle = compute_zone_lifecycle(total, score["grade"], pl["roi"])
        result_zones.append({
            "zone": zid,
            "source": extract_source(zid),
            "total": total,
            "valid": z["valid"],
            "invalid": z["invalid"],
            "suspicious": z["suspicious"],
            "wasted": z["wasted"],
            "bot_rate": bot_rate,
            "wasted_rate": wasted_rate,
            "pl": pl,
            "score": score,
            "lifecycle": lifecycle,
            "min_sample_met": total >= 200,
        })

    result_zones.sort(key=lambda x: x["pl"]["profit"], reverse=True)
    return {
        "summary": summary,
        "zones": result_zones,
        "generated_at": datetime.utcnow().isoformat(),
    }


@router.get("/reports/countries")
def report_countries(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    q = db.query(
        VisitModel.country_code, VisitModel.country,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"),
        func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"),
    )
    if site:
        s = _resolve_user_site(site, user, db)
        q = q.filter(VisitModel.site_id == s.id)
    else:
        q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
            SiteModel.user_id == user.id
        )
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.country_code, VisitModel.country).all()

    cmap = {}
    for r in rows:
        k = _country_key(r.country_code, r.country)
        if k not in cmap:
            cmap[k] = {
                "code": r.country_code or None,
                "name": r.country or "Unknown",
                "total": 0, "valid": 0, "invalid": 0, "suspicious": 0,
            }
        cmap[k]["total"] += int(r.total or 0)
        cmap[k]["valid"] += int(r.valid or 0)
        cmap[k]["invalid"] += int(r.invalid or 0)
        cmap[k]["suspicious"] += int(r.suspicious or 0)
    result = list(cmap.values())
    for c in result:
        c["bot_rate"] = round(c["invalid"] / c["total"] * 100, 1) if c["total"] else 0.0
    result.sort(key=lambda x: x["total"], reverse=True)
    return result[:15]


@router.get("/reports/tech")
def report_tech(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
    user: UserModel = Depends(current_user), db: Session = Depends(get_db),
):
    def _q(col):
        q = db.query(col, VisitModel.verdict, func.count(VisitModel.id).label("count"))
        if site:
            s = _resolve_user_site(site, user, db)
            q = q.filter(VisitModel.site_id == s.id)
        else:
            q = q.join(SiteModel, VisitModel.site_id == SiteModel.id).filter(
                SiteModel.user_id == user.id
            )
        q = _apply_date_filter(q, from_date, to_date)
        return q.group_by(col, VisitModel.verdict).all()

    def _agg(rows, attr):
        m = {}
        for r in rows:
            n = getattr(r, attr, None) or "Unknown"
            if n not in m:
                m[n] = {"name": n, "total": 0, "valid": 0, "invalid": 0, "suspicious": 0}
            m[n][r.verdict] = int(r.count or 0)
            m[n]["total"] += int(r.count or 0)
        return sorted(m.values(), key=lambda x: x["total"], reverse=True)

    return {
        "devices": _agg(_q(VisitModel.device), "device"),
        "browsers": _agg(_q(VisitModel.browser), "browser"),
    }


@router.get("/map/visits")
def map_visits(
    site: str = Query(None), from_date: str = Query(None), to_date: str = Query(None),
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
    q = _apply_date_filter(q, from_date, to_date)
    visits = q.filter(
        not_(and_(VisitModel.latitude == 0.0, VisitModel.longitude == 0.0))
    ).order_by(VisitModel.id.desc()).limit(1000).all()
    return [{
        "id": v.id, "lat": v.latitude, "lng": v.longitude,
        "verdict": v.verdict, "country": v.country, "ip": v.ip,
    } for v in visits]
