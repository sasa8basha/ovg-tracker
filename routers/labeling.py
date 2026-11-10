"""
routers/labeling.py — Ground truth + Manual review queue + Rule performance.
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from models import UserModel, VisitModel, CampaignModel
from schemas import GroundTruthIn
from auth import current_user
from helpers import verify_campaign_access
from analysis import CODE_TO_SOURCE
from utils import stats_cache

router = APIRouter()
BULK_MAX = 200  # H-12: match UI expectation

@router.post("/visits/{visit_id}/ground-truth")
def set_ground_truth(visit_id: int, payload: GroundTruthIn, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(CampaignModel).filter(VisitModel.id == visit_id, CampaignModel.user_id == user.id).first()
    if not v: raise HTTPException(404, "الزيارة مش موجودة")
    v.ground_truth = payload.label
    v.ground_truth_at = datetime.utcnow()
    v.ground_truth_by = user.username
    db.commit(); db.refresh(v)
    stats_cache.invalidate(f"labeling:stats:{user.id}")
    stats_cache.invalidate(f"labeling:rules:{user.id}")
    return {"ok": True, "visit_id": v.id, "ground_truth": v.ground_truth, "labeled_at": v.ground_truth_at.isoformat() if v.ground_truth_at else None}

@router.delete("/visits/{visit_id}/ground-truth")
def delete_ground_truth(visit_id: int, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    v = db.query(VisitModel).join(CampaignModel).filter(VisitModel.id == visit_id, CampaignModel.user_id == user.id).first()
    if not v: raise HTTPException(404, "الزيارة مش موجودة")
    v.ground_truth = None; v.ground_truth_at = None; v.ground_truth_by = None
    db.commit()
    stats_cache.invalidate(f"labeling:stats:{user.id}")
    stats_cache.invalidate(f"labeling:rules:{user.id}")
    return {"ok": True, "visit_id": v.id}

@router.post("/visits/bulk-label")
def bulk_label(payload: dict, user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    visit_ids = payload.get("visit_ids")
    label = (payload.get("label") or "").strip().lower()
    if not isinstance(visit_ids, list): raise HTTPException(400, "visit_ids لازم تكون قائمة")
    if label not in ("bot", "human"): raise HTTPException(400, "label لازم تكون bot أو human")
    if len(visit_ids) == 0: return {"ok": True, "updated": 0, "skipped": 0, "invalid_ids": 0}
    if len(visit_ids) > BULK_MAX: raise HTTPException(400, f"الحد الأقصى {BULK_MAX} زيارة في المرة")
    
    clean_ids = []; invalid_ids = 0
    for vid in visit_ids:
        try:
            n = int(vid)
            if n <= 0: invalid_ids += 1; continue
            clean_ids.append(n)
        except (ValueError, TypeError): invalid_ids += 1
    if not clean_ids: return {"ok": True, "updated": 0, "skipped": 0, "invalid_ids": invalid_ids}

    visits = db.query(VisitModel).join(CampaignModel, VisitModel.campaign_id == CampaignModel.id).filter(VisitModel.id.in_(clean_ids), CampaignModel.user_id == user.id).all()
    now = datetime.utcnow(); updated = 0
    for v in visits:
        v.ground_truth = label; v.ground_truth_at = now; v.ground_truth_by = user.username
        updated += 1
    db.commit()
    stats_cache.invalidate(f"labeling:stats:{user.id}")
    stats_cache.invalidate(f"labeling:rules:{user.id}")
    return {"ok": True, "updated": updated, "skipped": len(clean_ids) - updated, "invalid_ids": invalid_ids, "label": label}

@router.get("/labeling/queue")
def get_labeling_queue(campaign_id: int = Query(None), limit: int = Query(20, ge=1, le=100), order: str = Query("uncertainty"), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    verify_campaign_access(campaign_id, user, db)
    q = db.query(VisitModel)
    if campaign_id: q = q.filter(VisitModel.campaign_id == campaign_id)
    else: q = q.join(CampaignModel).filter(CampaignModel.user_id == user.id)
    
    q = q.filter(VisitModel.ground_truth.is_(None), VisitModel.score >= 30, VisitModel.score <= 80)  # H-11
    if order == "uncertainty": q = q.order_by(func.abs(VisitModel.score - 60).asc(), VisitModel.id.desc())
    elif order == "oldest": q = q.order_by(VisitModel.id.asc())
    else: q = q.order_by(VisitModel.id.desc())
    
    visits = q.limit(limit).all()
    items = []
    for v in visits:
        ev = v.evidence or []; top_ev = []
        if isinstance(ev, list):
            dicts = [e for e in ev if isinstance(e, dict)]
            dicts.sort(key=lambda e: abs(int(e.get("score", 0) or 0)), reverse=True)
            for e in dicts[:5]: top_ev.append({"code": e.get("code", "UNKNOWN"), "severity": e.get("severity", "medium"), "score": int(e.get("score", 0) or 0), "detail": e.get("detail", "")})
        items.append({"id": v.id, "score": v.score, "verdict": v.verdict, "time": v.timestamp.strftime("%Y-%m-%d %H:%M") if v.timestamp else "", "zone": v.zone_id, "country": v.country, "country_code": v.country_code, "browser": v.browser, "os": v.os, "device": v.device, "asn": v.asn, "is_vpn": bool(v.is_vpn), "evidence_count": len(ev) if isinstance(ev, list) else 0, "top_evidence": top_ev})
    return {"items": items, "count": len(items)}

@router.get("/labeling/stats")
def get_labeling_stats(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    cached = stats_cache.get(f"labeling:stats:{user.id}")
    if cached is not None: return cached
    base = db.query(VisitModel).join(CampaignModel).filter(CampaignModel.user_id == user.id)
    
    total = base.count(); labeled = base.filter(VisitModel.ground_truth.isnot(None)).count()
    labeled_human = base.filter(VisitModel.ground_truth == "human").count(); labeled_bot = base.filter(VisitModel.ground_truth == "bot").count()
    unlabeled = total - labeled
    pending_review = base.filter(VisitModel.ground_truth.is_(None), VisitModel.score >= 30, VisitModel.score <= 80).count()  # H-11
    
    tp = base.filter(VisitModel.verdict == "invalid", VisitModel.ground_truth == "bot").count()
    fp = base.filter(VisitModel.verdict == "invalid", VisitModel.ground_truth == "human").count()
    fn_strict = base.filter(VisitModel.verdict == "valid", VisitModel.ground_truth == "bot").count()
    fn_suspicious = base.filter(VisitModel.verdict == "suspicious", VisitModel.ground_truth == "bot").count()
    tn = base.filter(VisitModel.verdict == "valid", VisitModel.ground_truth == "human").count()
    
    precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else None
    recall_strict = round(tp / (tp + fn_strict) * 100, 2) if (tp + fn_strict) > 0 else None
    recall_loose = round(tp / (tp + fn_strict + fn_suspicious) * 100, 2) if (tp + fn_strict + fn_suspicious) > 0 else None
    agreement = round((tp + tn) / labeled * 100, 2) if labeled > 0 else None
    
    result = {"total": total, "labeled": labeled, "labeled_human": labeled_human, "labeled_bot": labeled_bot, "unlabeled": unlabeled, "pending_review": pending_review, "progress_percent": round(labeled / total * 100, 2) if total > 0 else 0.0, "tp": tp, "fp": fp, "tn": tn, "fn_strict": fn_strict, "fn_suspicious": fn_suspicious, "precision": precision, "recall_strict": recall_strict, "recall_loose": recall_loose, "agreement": agreement, "reliable": labeled >= 30}
    stats_cache.set(f"labeling:stats:{user.id}", result)
    return result

@router.get("/labeling/rule-performance")
def get_rule_performance(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    cached = stats_cache.get(f"labeling:rules:{user.id}")
    if cached is not None: return cached
    LIMIT = 20000
    labeled = db.query(VisitModel).join(CampaignModel).filter(CampaignModel.user_id == user.id, VisitModel.ground_truth.isnot(None)).order_by(VisitModel.id.desc()).limit(LIMIT).all()
    unlabeled = db.query(VisitModel).join(CampaignModel).filter(CampaignModel.user_id == user.id, VisitModel.ground_truth.is_(None)).order_by(VisitModel.id.desc()).limit(LIMIT).all()
    stats = {}
    for v in labeled:
        ev = v.evidence or []
        if not isinstance(ev, list): continue
        seen = set()
        for e in ev:
            if not isinstance(e, dict): continue
            code = e.get("code")
            if not code or code in seen: continue
            seen.add(code)
            if code not in stats: stats[code] = {"tp": 0, "fp": 0, "unlabeled": 0}
            if v.ground_truth == "bot": stats[code]["tp"] += 1
            elif v.ground_truth == "human": stats[code]["fp"] += 1
    for v in unlabeled:
        ev = v.evidence or []
        if not isinstance(ev, list): continue
        seen = set()
        for e in ev:
            if not isinstance(e, dict): continue
            code = e.get("code")
            if not code or code in seen: continue
            seen.add(code)
            if code not in stats: stats[code] = {"tp": 0, "fp": 0, "unlabeled": 0}
            stats[code]["unlabeled"] += 1
    rules = []
    for code, s in stats.items():
        total_labeled = s["tp"] + s["fp"]; precision = round(s["tp"] / total_labeled * 100, 2) if total_labeled > 0 else None
        rules.append({"code": code, "source": CODE_TO_SOURCE.get(code, "unknown"), "tp": s["tp"], "fp": s["fp"], "unlabeled": s["unlabeled"], "total_labeled": total_labeled, "precision": precision, "reliable": total_labeled >= 30})
    rules.sort(key=lambda r: (r["precision"] is None, r["precision"] if r["precision"] is not None else 999, -r["total_labeled"]))
    result = {"rules": rules, "labeled_sample_size": len(labeled), "unlabeled_sample_size": len(unlabeled), "truncated": len(labeled) >= LIMIT or len(unlabeled) >= LIMIT}
    stats_cache.set(f"labeling:rules:{user.id}", result)
    return result
