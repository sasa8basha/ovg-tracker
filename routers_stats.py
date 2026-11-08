@router.get("/visits/{visit_id}")
def get_visit_detail(visit_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(CampaignModel).filter(
        VisitModel.id == visit_id, CampaignModel.user_id == user.id,
    ).first()
    if not v:
        raise HTTPException(404, "غير مصرح لك بعرض هذه الزيارة")

    evidence = v.evidence or []
    signals = normalize_stored_evidence(evidence)
    trace = build_explainability_trace(evidence)

    # 🔴 نستخرج الماكروز المنظمة من popads_data
    popads_data = v.popads_data or {}
    popads_known = {}
    if isinstance(popads_data, dict):
        # نحاول نطابق الـ aliases تاني عشان نطلع قيم منظمة
        lowered = {str(k).strip().lower(): val for k, val in popads_data.items() if val is not None and str(val) != ""}
        for canonical, aliases in (
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
        ):
            for alias in aliases:
                if alias in lowered:
                    popads_known[canonical] = lowered[alias]
                    break

    return {
        "id": v.id,
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
        "confidence": calc_confidence(signals),
        "raw_score": sum(s.get("score", 0) for s in signals),
        "categories": count_categories(signals),
        "ground_truth": v.ground_truth,
        "ground_truth_at": v.ground_truth_at.isoformat() if v.ground_truth_at else None,
        "ground_truth_by": v.ground_truth_by,
        # 🔴 بيانات PopAds
        "bid": float(v.bid or 0),
        "revenue": float(v.revenue or 0),
        "popads_impression_id": v.popads_impression_id,
        "popads_website_id": v.popads_website_id,
        "popads_quality": v.popads_quality,
        "popads_adblock": bool(v.popads_adblock),
        "popads_data": popads_data,           # 🔴 كل الـ raw
        "popads_known": popads_known,          # 🔴 الأسماء الموحدة
    }