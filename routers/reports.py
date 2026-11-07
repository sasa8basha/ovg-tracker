"""
routers/reports.py — Zone reports, smart P&L, countries, tech, map, and specific Proof/Refund reports.
"""
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, and_, not_
from sqlalchemy.orm import Session
from database import get_db
from models import UserModel, VisitModel, CampaignModel
from auth import current_user
from helpers import _apply_date_filter, _country_key
from metrics import extract_source, compute_pl, compute_zone_score, compute_zone_lifecycle, is_wasted_visit

router = APIRouter()

@router.get("/reports/zones")
def get_zone_reports(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    inv = func.sum(case((VisitModel.verdict == "invalid", 1), else_=0))
    sus = func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0))
    val = func.sum(case((VisitModel.verdict == "valid", 1), else_=0))
    q = db.query(VisitModel.zone_id, func.count(VisitModel.id).label("total"), val.label("valid"), inv.label("invalid"), sus.label("suspicious"))
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.zone_id).all()

    report = []
    for z in rows:
        if not z.zone_id or z.zone_id == "unknown": continue
        total = int(z.total or 0); invalid = int(z.invalid or 0)
        rate = round(invalid / total * 100, 1) if total else 0.0
        grade = "?" if total < 10 else ("A" if rate < 5 else "B" if rate < 15 else "C" if rate < 30 else "F")
        report.append({"zone": z.zone_id, "total": total, "valid": int(z.valid or 0), "invalid": invalid, "suspicious": int(z.suspicious or 0), "bot_rate": rate, "grade": grade, "min_sample_met": total >= 10})
    report.sort(key=lambda x: x["bot_rate"], reverse=True)
    return report

@router.get("/reports/smart")
def smart_report(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    # (نفس الكود القديم مع إضافة حساب التكلفة الفعلية من BID والإيراد من Revenue)
    buy_cpm = float(user.cpm_buy or 1.0); sell_cpm = float(user.cpm_sell or 1.5)
    q = db.query(VisitModel.zone_id, VisitModel.verdict, VisitModel.evidence, VisitModel.bid, VisitModel.revenue)
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date).limit(100000)

    zones = {}; total_all = 0; valid_all = 0; invalid_all = 0; suspicious_all = 0; wasted_all = 0
    total_cost = 0.0; total_revenue = 0.0

    for row in q.all():
        total_all += 1; zid = row.zone_id or "unknown"
        total_cost += float(row.bid or 0); total_revenue += float(row.revenue or 0)

        if zid not in zones: zones[zid] = {"total": 0, "valid": 0, "invalid": 0, "suspicious": 0, "wasted": 0, "cost": 0.0, "revenue": 0.0}
        z = zones[zid]; z["total"] += 1; z["cost"] += float(row.bid or 0); z["revenue"] += float(row.revenue or 0)
        verdict = row.verdict or "unknown"
        
        if verdict == "valid":
            z["valid"] += 1; valid_all += 1
            if is_wasted_visit(row.evidence): z["wasted"] += 1; wasted_all += 1
        elif verdict == "invalid": z["invalid"] += 1; invalid_all += 1
        elif verdict == "suspicious": z["suspicious"] += 1; suspicious_all += 1

    # Use exact P&L if any bid exists, else fallback to CPM
    if total_cost > 0:
        summary_pl = {"cost": round(total_cost, 4), "revenue": round(total_revenue, 4), "profit": round(total_revenue - total_cost, 4), "roi": round((total_revenue - total_cost) / total_cost * 100, 2) if total_cost > 0 else 0, "is_profitable": total_revenue >= total_cost, "source": "exact"}
    else:
        summary_pl = compute_pl(total_all, valid_all, wasted_all, buy_cpm, sell_cpm); summary_pl["source"] = "cpm"

    summary = {"total": total_all, "valid": valid_all, "invalid": invalid_all, "suspicious": suspicious_all, "wasted": wasted_all, "bot_rate": round(invalid_all / total_all * 100.0, 2) if total_all > 0 else 0.0, "wasted_rate": round(wasted_all / total_all * 100.0, 2) if total_all > 0 else 0.0, "pl": summary_pl}

    result_zones = []
    for zid, z in zones.items():
        if zid == "unknown": continue
        total = z["total"]; bot_rate = round(z["invalid"] / total * 100.0, 2) if total > 0 else 0.0; wasted_rate = round(z["wasted"] / total * 100.0, 2) if total > 0 else 0.0
        
        if z["cost"] > 0:
            pl = {"cost": round(z["cost"], 4), "revenue": round(z["revenue"], 4), "profit": round(z["revenue"] - z["cost"], 4), "roi": round((z["revenue"] - z["cost"]) / z["cost"] * 100, 2) if z["cost"] > 0 else 0, "is_profitable": z["revenue"] >= z["cost"], "source": "exact"}
        else:
            pl = compute_pl(total, z["valid"], z["wasted"], buy_cpm, sell_cpm); pl["source"] = "cpm"

        score = compute_zone_score(pl["profit"], pl["roi"], bot_rate, wasted_rate, total)
        lifecycle = compute_zone_lifecycle(total, score["grade"], pl["roi"])
        result_zones.append({"zone": zid, "source": extract_source(zid), "total": total, "valid": z["valid"], "invalid": z["invalid"], "suspicious": z["suspicious"], "wasted": z["wasted"], "bot_rate": bot_rate, "wasted_rate": wasted_rate, "pl": pl, "score": score, "lifecycle": lifecycle, "min_sample_met": total >= 200})

    result_zones.sort(key=lambda x: x["pl"]["profit"], reverse=True)
    return {"summary": summary, "zones": result_zones, "generated_at": datetime.utcnow().isoformat()}

@router.get("/reports/popads-refund")
def popads_refund_report(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    """تقرير يوضح الفلوس اللي اتصرفت على البوتات من PopAds عشان تطلب تعويض."""
    q = db.query(
        VisitModel.popads_website_id,
        func.count(VisitModel.id).label("total"),
        func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("bot_visits"),
        func.sum(VisitModel.bid).label("total_cost"),
        func.sum(case((VisitModel.verdict == "invalid", VisitModel.bid), else_=0.0)).label("wasted_cost")
    ).filter(VisitModel.popads_website_id.isnot(None), VisitModel.popads_website_id != "")
    
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    
    rows = q.group_by(VisitModel.popads_website_id).all()
    
    report = []
    for r in rows:
        total = int(r.total or 0); bots = int(r.bot_visits or 0)
        if bots == 0: continue # We only care about websites sending bots
        
        bot_rate = round(bots / total * 100, 2) if total > 0 else 0
        report.append({
            "website_id": r.popads_website_id,
            "total_visits": total,
            "bot_visits": bots,
            "bot_rate": bot_rate,
            "total_cost": round(float(r.total_cost or 0), 6),
            "wasted_cost": round(float(r.wasted_cost or 0), 6)
        })
    
    report.sort(key=lambda x: x["wasted_cost"], reverse=True)
    
    total_wasted = sum(x["wasted_cost"] for x in report)
    total_bots = sum(x["bot_visits"] for x in report)
    
    return {
        "summary": {
            "total_wasted_amount": round(total_wasted, 6),
            "total_bot_visits": total_bots,
            "suspicious_websites_count": len(report)
        },
        "websites": report,
        "generated_at": datetime.utcnow().isoformat()
    }

@router.get("/reports/adsterra-proof")
def adsterra_proof_report(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    """تقرير إثبات جودة الترافيك لـ Adsterra."""
    q = db.query(VisitModel).select_from(VisitModel)
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    
    total = q.count()
    if total == 0: return {"error": "No data"}
    
    valid = q.filter(VisitModel.verdict == "valid").count()
    invalid = q.filter(VisitModel.verdict == "invalid").count()
    suspicious = q.filter(VisitModel.verdict == "suspicious").count()
    
    # Human signals
    human_quality = q.filter(VisitModel.evidence.like('%HUMAN%')).count()
    
    total_revenue = q.with_entities(func.sum(VisitModel.revenue)).scalar() or 0.0
    
    return {
        "summary": {
            "total_visits": total,
            "valid_visits": valid,
            "blocked_bots": invalid,
            "suspicious_visits": suspicious,
            "human_traffic_rate": round(valid / total * 100, 2) if total > 0 else 0,
            "bot_block_rate": round(invalid / total * 100, 2) if total > 0 else 0,
            "total_revenue": round(float(total_revenue), 4),
            "human_quality_events": human_quality
        },
        "generated_at": datetime.utcnow().isoformat()
    }

@router.get("/reports/countries")
def report_countries(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    # (نفس الكود)
    q = db.query(VisitModel.country_code, VisitModel.country, func.count(VisitModel.id).label("total"), func.sum(case((VisitModel.verdict == "valid", 1), else_=0)).label("valid"), func.sum(case((VisitModel.verdict == "invalid", 1), else_=0)).label("invalid"), func.sum(case((VisitModel.verdict == "suspicious", 1), else_=0)).label("suspicious"))
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    rows = q.group_by(VisitModel.country_code, VisitModel.country).all()
    cmap = {}
    for r in rows:
        k = _country_key(r.country_code, r.country)
        if k not in cmap: cmap[k] = {"code": r.country_code or None, "name": r.country or "Unknown", "total": 0, "valid": 0, "invalid": 0, "suspicious": 0}
        cmap[k]["total"] += int(r.total or 0); cmap[k]["valid"] += int(r.valid or 0); cmap[k]["invalid"] += int(r.invalid or 0); cmap[k]["suspicious"] += int(r.suspicious or 0)
    result = list(cmap.values())
    for c in result: c["bot_rate"] = round(c["invalid"] / c["total"] * 100, 1) if c["total"] else 0.0
    result.sort(key=lambda x: x["total"], reverse=True)
    return result[:15]

@router.get("/reports/tech")
def report_tech(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    # (نفس الكود)
    def _q(col):
        q = db.query(col, VisitModel.verdict, func.count(VisitModel.id).label("count"))
        if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
        else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
        q = _apply_date_filter(q, from_date, to_date)
        return q.group_by(col, VisitModel.verdict).all()
    def _agg(rows, attr):
        m = {}
        for r in rows:
            n = getattr(r, attr, None) or "Unknown"
            if n not in m: m[n] = {"name": n, "total": 0, "valid": 0, "invalid": 0, "suspicious": 0}
            m[n][r.verdict] = int(r.count or 0); m[n]["total"] += int(r.count or 0)
        return sorted(m.values(), key=lambda x: x["total"], reverse=True)
    return {"devices": _agg(_q(VisitModel.device), "device"), "browsers": _agg(_q(VisitModel.browser), "browser")}

@router.get("/map/visits")
def map_visits(campaign_id: int = Query(None), from_date: str = Query(None), to_date: str = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    # (نفس الكود)
    q = db.query(VisitModel)
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    q = _apply_date_filter(q, from_date, to_date)
    visits = q.filter(not_(and_(VisitModel.latitude == 0.0, VisitModel.longitude == 0.0))).order_by(VisitModel.id.desc()).limit(1000).all()
    return [{"id": v.id, "lat": v.latitude, "lng": v.longitude, "verdict": v.verdict, "country": v.country, "ip": v.ip} for v in visits]
