"""
routers/stats.py — Stats, visits, visit detail (with IP intelligence), CSV export.
Phase 2: enriched visit detail with full_payload / decision / fusion / signals.
"""
import io
import csv
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import case, func
from sqlalchemy.orm import Session
from database import get_db
from models import UserModel, VisitModel, CampaignModel, IPIntelligence
from auth import current_user
from analysis import calc_confidence, count_categories, normalize_stored_evidence, build_explainability_trace
from helpers import _apply_date_filter, _parse_date, _safe_filename, csv_safe
from utils import stats_cache
from ip_intelligence import classify_ip

router = APIRouter()


@router.get("/stats")
def get_stats(campaign_id: int = Query(None), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    cache_key = f"stats:campaign:{campaign_id}" if campaign_id else f"stats:user:{user.id}:all"
    cached = stats_cache.get(cache_key)
    if cached is not None:
        return cached

    def _build():
        q = db.query(VisitModel)
        if campaign_id:
            q = q.filter(VisitModel.campaign_id == campaign_id)
        else:
            q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
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

    recent_visits = [
        {
            "id": v.id,
            "time": v.timestamp.strftime("%H:%M:%S") if v.timestamp else "",
            "zone": v.zone_id,
            "verdict": v.verdict,
            "country": v.country,
            "score": v.score,
            "evidence": v.evidence,
            "timezone": v.timezone,
            "hardware": v.hardware,
            "conn_type": v.connection_type,
            "asn": v.asn,
            "is_vpn": v.is_vpn,
            "webrtc": v.webrtc_ip,
        }
        for v in recent
    ]

    result = {"total": total, "valid": valid, "invalid": invalid, "suspicious": suspicious, "recent": recent_visits}
    stats_cache.set(cache_key, result)
    return result


@router.get("/visits")
def get_visits(
    campaign_id: int = Query(None),
    verdict: str = Query(None),
    country: str = Query(None),
    zone: str = Query(None),
    website_id: str = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    if verdict:
        q = q.filter(VisitModel.verdict == verdict)
    if country:
        q = q.filter((VisitModel.country_code == country) | (VisitModel.country == country))
    if zone:
        q = q.filter(VisitModel.zone_id == zone)
    if website_id:
        q = q.filter(VisitModel.popads_website_id == website_id)
    q = _apply_date_filter(q, from_date, to_date)

    total = q.count()
    pages = (total + per_page - 1) // per_page if total else 0
    visits = q.order_by(VisitModel.id.desc()).offset((page - 1) * per_page).limit(per_page).all()

    items = [
        {
            "id": v.id,
            "time": v.timestamp.strftime("%Y-%m-%d %H:%M") if v.timestamp else "",
            "campaign_id": v.campaign_id,
            "ip": v.ip,
            "zone": v.zone_id,
            "verdict": v.verdict,
            "score": v.score,
            "country": v.country,
            "country_code": v.country_code,
            "device": v.device,
            "browser": v.browser,
            "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
            "clicks": v.clicks,
            "scrolls": v.scrolls,
            "ground_truth": v.ground_truth,
            "bid": float(v.bid or 0),
            "revenue": float(v.revenue or 0),
            "popads_website_id": v.popads_website_id,
        }
        for v in visits
    ]
    return {"items": items, "total": total, "page": page, "pages": pages}


# =========================================================
# VISIT DETAIL — Phase 2: full payload + decision + fusion + signals
# =========================================================
@router.get("/visits/{visit_id}")
async def get_visit_detail(
    visit_id: int,
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    v = db.query(VisitModel).join(CampaignModel).filter(
        VisitModel.id == visit_id, CampaignModel.user_id == user.id
    ).first()
    if not v:
        raise HTTPException(404, "غير مصرح لك بعرض هذه الزيارة")

    evidence = v.evidence or []
    signals_legacy = normalize_stored_evidence(evidence)
    trace = build_explainability_trace(evidence)

    # ---- PopAds macros normalization ----
    popads_data = v.popads_data or {}
    popads_known = {}
    if isinstance(popads_data, dict):
        lowered = {
            str(k).strip().lower(): val
            for k, val in popads_data.items()
            if val is not None and str(val) != ""
        }
        aliases_map = (
            ("bid", ("bid",)),
            ("impressionid", ("impressionid", "impid", "impression_id")),
            ("websiteid", ("websiteid", "website_id")),
            ("categoryid", ("categoryid", "category_id")),
            ("categoryname", ("categoryname", "category_name")),
            ("ispid", ("ispid", "isp_id")),
            ("ispname", ("ispname", "isp_name", "isp")),
            ("country", ("country",)),
            ("quality", ("quality",)),
            ("screenresolution", ("screenresolution", "screen_resolution")),
            ("osname", ("osname", "os_name")),
            ("browsername", ("browsername", "browser_name")),
            ("formfactorname", ("formfactorname", "form_factor")),
            ("devicename", ("devicename", "device_name")),
            ("campaignid", ("campaignid", "campaign_id")),
            ("campaignname", ("campaignname", "campaign_name")),
            ("osid", ("osid", "os_id")),
            ("browserid", ("browserid", "browser_id")),
            ("formfactorid", ("formfactorid", "form_factor_id")),
            ("deviceid", ("deviceid", "device_id")),
            ("adblock", ("adblock",)),
            ("ip", ("ip",)),
            ("ipv6", ("ipv6",)),
            ("useragent", ("useragent", "ua")),
            ("lang", ("lang",)),
        )
        for canonical, aliases in aliases_map:
            for alias in aliases:
                if alias in lowered:
                    popads_known[canonical] = lowered[alias]
                    break

    # ---- IP intelligence ----
    ip_intel = None
    try:
        ip_intel = await classify_ip(v.ip or "", db=db)
    except Exception as e:
        print(f"[Visit Detail] classify_ip failed for {v.ip}: {e}")
        ip_intel = {
            "classification": "unknown", "risk_score": 0, "reasons": [],
            "asn": None, "asn_description": None, "country": None, "isp": None,
            "rtt_gap_ms": None, "last_checked": None,
        }

    # ---- Mismatch detection ----
    mismatches = []
    if ip_intel and popads_known:
        our_country = (ip_intel.get("country") or "").upper().strip()
        popads_country = str(popads_known.get("country") or "").upper().strip()
        if our_country and popads_country and our_country != popads_country:
            mismatches.append({
                "field": "country",
                "ours": our_country,
                "popads": popads_country,
                "severity": "high",
                "detail": f"PopAds says {popads_country}, our IP lookup says {our_country}",
            })

        our_isp_raw = ip_intel.get("isp") or ""
        popads_isp_raw = popads_known.get("ispname") or popads_known.get("isp") or ""
        if our_isp_raw and popads_isp_raw:
            a = our_isp_raw.strip().lower()
            b = str(popads_isp_raw).strip().lower()
            if a and b and a != b and a not in b and b not in a:
                mismatches.append({
                    "field": "isp",
                    "ours": our_isp_raw,
                    "popads": str(popads_isp_raw),
                    "severity": "medium",
                    "detail": f"PopAds says '{popads_isp_raw}', ours says '{our_isp_raw}'",
                })

    # ---- Phase 2: unpack full_payload ----
    fp = v.full_payload if isinstance(v.full_payload, dict) else {}
    decision = fp.get("decision") if isinstance(fp.get("decision"), dict) else {}
    fusion = fp.get("fusion") if isinstance(fp.get("fusion"), dict) else {}
    dq_report = fp.get("data_quality_report") if isinstance(fp.get("data_quality_report"), dict) else (v.data_quality_report if isinstance(v.data_quality_report, dict) else {})
    rich_signals = fp.get("signals") if isinstance(fp.get("signals"), list) else []
    fp_strikes = fp.get("fingerprint_strikes")

    return {
        "id": v.id,
        "session_id": v.session_id,
        "timestamp": v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
        "ip": v.ip,
        "zone_id": v.zone_id,
        "score": v.score,
        "verdict": v.verdict,
        "evidence": evidence,
        "trace": trace,
        "os": v.os,
        "device": v.device,
        "browser": v.browser,
        "country": v.country,
        "country_code": v.country_code,
        "isp": v.isp,
        "timezone": v.timezone,
        "canvas_hash": v.canvas_hash,
        "hardware": v.hardware,
        "connection_type": v.connection_type,
        "asn": v.asn,
        "is_vpn": v.is_vpn,
        "webrtc_ip": v.webrtc_ip,
        "time_on_page": round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
        "clicks": v.clicks,
        "scrolls": v.scrolls,
        # Confidence: stored (decision engine) + recomputed (legacy)
        "confidence": float(v.confidence) if v.confidence is not None else None,
        "confidence_recomputed": calc_confidence(signals_legacy),
        "bot_probability": float(v.bot_probability) if v.bot_probability is not None else None,
        "mode": v.mode,
        "reason": v.reason,
        "filter_reason": v.filter_reason,
        "raw_score": sum(s.get("score", 0) for s in signals_legacy),
        "categories": count_categories(signals_legacy),
        "ground_truth": v.ground_truth,
        "ground_truth_at": v.ground_truth_at.isoformat() if v.ground_truth_at else None,
        "ground_truth_by": v.ground_truth_by,
        "bid": float(v.bid or 0),
        "revenue": float(v.revenue or 0),
        "impressions": int(v.impressions or 0),
        "counting_type": v.counting_type,
        "popads_impression_id": v.popads_impression_id,
        "popads_website_id": v.popads_website_id,
        "popads_quality": v.popads_quality,
        "popads_adblock": bool(v.popads_adblock),
        "popads_data": popads_data,
        "popads_known": popads_known,
        "ip_intel": ip_intel,
        "mismatches": mismatches,
        # ===== Phase 2: enriched fields =====
        "data_quality": v.data_quality,
        "data_quality_report": dq_report,
        "decision": decision,
        "fusion": fusion,
        "full_payload": fp,
        "signals": rich_signals,
        "fingerprint_strikes": fp_strikes,
        "behavioral": v.behavioral,
        "first_30s": v.first_30s,
        "milestones": v.milestones,
        "ad_events": v.ad_events,
        "clock_drift_ms": int(v.clock_drift_ms or 0),
        "is_honeypot_triggered": bool(v.is_honeypot_triggered),
        "consent_state": v.consent_state,
    }


@router.get("/export/visits")
def export_visits(
    campaign_id: int = Query(None),
    verdict: str = Query(None),
    zone: str = Query(None),
    from_date: str = Query(None),
    to_date: str = Query(None),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    q = db.query(VisitModel)
    if campaign_id:
        q = q.filter(VisitModel.campaign_id == campaign_id)
    else:
        q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    if verdict:
        q = q.filter(VisitModel.verdict == verdict)
    if zone:
        q = q.filter(VisitModel.zone_id == zone)
    q = _apply_date_filter(q, from_date, to_date).order_by(VisitModel.id.desc()).limit(5000)

    fd = _parse_date(from_date)
    td = _parse_date(to_date)
    parts = [verdict] if verdict else []
    if fd:
        parts.append(fd.strftime("%Y%m%d"))
    if td:
        parts.append(td.strftime("%Y%m%d"))
    filename = _safe_filename("ovg_visits", *parts) if parts else "ovg_visits_export.csv"

    def iter_csv():
        try:
            out = io.StringIO()
            w = csv.writer(out)
            w.writerow([
                "ID", "Time", "IP", "Country", "Country Code", "Zone",
                "Verdict", "Score", "OS", "Browser", "Device",
                "Time on Page (s)", "Clicks", "Scrolls", "ISP", "ASN", "VPN",
                "Ground Truth", "BID", "Revenue", "Website ID",
            ])
            yield out.getvalue()
            out.seek(0); out.truncate(0)
            for v in q.yield_per(500):
                row = [
                    v.id,
                    v.timestamp.strftime("%Y-%m-%d %H:%M:%S") if v.timestamp else "",
                    v.ip, v.country, v.country_code or "", v.zone_id,
                    v.verdict, v.score, v.os, v.browser, v.device,
                    round(v.time_on_page / 1000, 1) if v.time_on_page else 0,
                    v.clicks, v.scrolls, v.isp, v.asn, v.is_vpn,
                    v.ground_truth or "",
                    round(float(v.bid or 0), 6),
                    round(float(v.revenue or 0), 6),
                    v.popads_website_id or "",
                ]
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