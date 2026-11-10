"""
routers/radar.py — Ban Risk Radar
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import cast, String,  func
from sqlalchemy.orm import Session
from database import get_db
from models import UserModel, CampaignModel, VisitModel, BanRiskSnapshot
from auth import current_user
from metrics import extract_source
from utils import TTLCache

router = APIRouter()
radar_cache = TTLCache(maxsize=500, ttl=60); radar_history_cache = TTLCache(maxsize=200, ttl=300)
MIN_VISITS_24H = 30
BOT_RATE_SAFE = 5.0; BOT_RATE_OK = 15.0; BOT_RATE_WARN = 25.0; BOT_RATE_BAD = 40.0
WASTED_SAFE = 5.0; WASTED_OK = 15.0
HUMAN_GOOD = 70.0; HUMAN_OK = 50.0; HUMAN_WARN = 30.0
ZONES_GOOD = 10; ZONES_OK = 5; ZONES_MIN = 3
SOURCES_GOOD = 3; SOURCES_OK = 2

def _level_from_score(score):
    if score is None: return "unknown"
    if score < 20: return "low"
    if score < 45: return "medium"
    if score < 70: return "high"
    return "critical"

def _aggregate_window(campaign_ids, start, end, db: Session):
    base = db.query(VisitModel).filter(VisitModel.campaign_id.in_(campaign_ids), VisitModel.timestamp >= start, VisitModel.timestamp < end)
    total = base.with_entities(func.count(VisitModel.id)).scalar() or 0
    if total == 0: return {"total": 0, "invalid": 0, "valid": 0, "suspicious": 0, "wasted": 0, "human": 0, "zone_ids": [], "source_set": set()}
    invalid = base.with_entities(func.count(VisitModel.id)).filter(VisitModel.verdict == "invalid").scalar() or 0
    valid = base.with_entities(func.count(VisitModel.id)).filter(VisitModel.verdict == "valid").scalar() or 0
    suspicious = base.with_entities(func.count(VisitModel.id)).filter(VisitModel.verdict == "suspicious").scalar() or 0
    wasted = base.with_entities(func.count(VisitModel.id)).filter(VisitModel.verdict == "valid", (cast(VisitModel.evidence, String).like('%CPM_BRAVE%')) | (cast(VisitModel.evidence, String).like('%CPM_ADBLOCK_BROWSER%'))).scalar() or 0  # H-06
    human = base.with_entities(func.count(VisitModel.id)).filter((cast(VisitModel.evidence, String).like('%HUMAN_NATURAL_MOUSE%')) | (cast(VisitModel.evidence, String).like('%HUMAN_RICH_INTERACTION%')) | (cast(VisitModel.evidence, String).like('%HUMAN_LONG_ENGAGEMENT%'))).scalar() or 0
    zone_rows = base.with_entities(VisitModel.zone_id).filter(VisitModel.zone_id.isnot(None), VisitModel.zone_id != "unknown").distinct().all()
    zone_ids = [r.zone_id for r in zone_rows if r.zone_id]
    source_set = set()
    for zid in zone_ids:
        src = extract_source(zid)
        if src and src != "unknown": source_set.add(src)
    return {"total": total, "invalid": invalid, "valid": valid, "suspicious": suspicious, "wasted": wasted, "human": human, "zone_ids": zone_ids, "source_set": source_set}

def _factor(name, score, weight, value, threshold, label, unit, status=None):
    if status is None: status = "good" if score >= 80 else "warn" if score >= 50 else "bad"
    return {"name": name, "score": round(score, 1), "weight": weight, "value": round(value, 2) if isinstance(value, (int, float)) else value, "threshold": threshold, "label": label, "unit": unit, "status": status}

def _compute_radar(user_id: int, db: Session) -> dict:
    campaigns = db.query(CampaignModel.id).filter(CampaignModel.user_id == user_id).all()
    campaign_ids = [c.id for c in campaigns]
    if not campaign_ids: return {"score": None, "level": "unknown", "insufficient_data": True, "reason": "no_campaigns", "message": "أضف حملة الأول عشان نبدأ نحسب مؤشر الخطر.", "factors": [], "metrics": None, "recommendations": []}
    now = datetime.utcnow(); start_24h = now - timedelta(hours=24); start_48h = now - timedelta(hours=48)
    cur = _aggregate_window(campaign_ids, start_24h, now, db)
    if cur["total"] < MIN_VISITS_24H: return {"score": None, "level": "unknown", "insufficient_data": True, "reason": "low_sample", "message": f"محتاج {MIN_VISITS_24H} زيارة على الأقل في آخر 24 ساعة. عندك {cur['total']}.", "factors": [], "metrics": {"total_24h": cur["total"]}, "recommendations": []}
    prev = _aggregate_window(campaign_ids, start_48h, start_24h, db)
    total = cur["total"]; bot_rate = cur["invalid"] / total * 100.0; wasted_rate = cur["wasted"] / total * 100.0; human_quality = cur["human"] / total * 100.0; zone_diversity = len(cur["zone_ids"]); source_diversity = len(cur["source_set"])
    factors = []
    factors.append(_factor("bot_rate", 100.0 if bot_rate <= BOT_RATE_SAFE else 80.0 if bot_rate <= BOT_RATE_OK else 55.0 if bot_rate <= BOT_RATE_WARN else 25.0 if bot_rate <= BOT_RATE_BAD else 0.0, 30, bot_rate, f"≤ {BOT_RATE_OK:.0f}%", "Bot Rate", "%"))
    factors.append(_factor("wasted_rate", 100.0 if wasted_rate <= WASTED_SAFE else 70.0 if wasted_rate <= WASTED_OK else max(0.0, 100.0 - (wasted_rate - WASTED_OK) * 3.0), 15, wasted_rate, f"≤ {WASTED_OK:.0f}%", "Wasted Rate", "%"))
    factors.append(_factor("human_quality", 100.0 if human_quality >= HUMAN_GOOD else 70.0 if human_quality >= HUMAN_OK else 40.0 if human_quality >= HUMAN_WARN else 20.0, 20, human_quality, f"≥ {HUMAN_GOOD:.0f}%", "Human Quality", "%"))
    factors.append(_factor("zone_diversity", 100.0 if zone_diversity >= ZONES_GOOD else 70.0 if zone_diversity >= ZONES_OK else 40.0 if zone_diversity >= ZONES_MIN else 20.0, 15, zone_diversity, f"≥ {ZONES_GOOD}", "Zone Diversity", ""))
    factors.append(_factor("source_diversity", 100.0 if source_diversity >= SOURCES_GOOD else 60.0 if source_diversity >= SOURCES_OK else 30.0, 10, source_diversity, f"≥ {SOURCES_GOOD}", "Source Diversity", ""))
    volume_included = False
    if prev["total"] >= 10:
        ratio = total / prev["total"]; vol_score = 100.0 if 0.7 <= ratio <= 1.3 else 70.0 if 0.5 <= ratio <= 1.5 else 40.0
        factors.append(_factor("volume_stability", vol_score, 10, ratio, "0.7 – 1.3", "Volume Stability", "×")); volume_included = True
    total_weight = sum(f["weight"] for f in factors)
    if total_weight <= 0: return {"score": None, "level": "unknown", "insufficient_data": True, "reason": "no_factors", "message": "معندناش بيانات كافية لحساب المؤشر.", "factors": [], "metrics": None, "recommendations": []}
    safety = sum(f["score"] * f["weight"] for f in factors) / total_weight; ban_risk = max(0, min(100, round(100.0 - safety))); level = _level_from_score(ban_risk)
    recommendations = []
    if bot_rate > BOT_RATE_WARN: recommendations.append({"severity": "high", "title": "Bot rate عالي", "text": f"Bot rate {bot_rate:.1f}%. Adsterra ممكن تشك. الهدف < {BOT_RATE_OK:.0f}%.", "action": "راجع Zone Analytics", "link": "/zone-analytics"})
    if wasted_rate > WASTED_OK: recommendations.append({"severity": "medium", "title": "Wasted traffic مرتفع", "text": f"Wasted {wasted_rate:.1f}%. ده ترافيك Brave/AdBlock — مش بيدفع.", "action": "راجع الزونات", "link": "/smart-reports"})
    if zone_diversity < ZONES_MIN: recommendations.append({"severity": "medium", "title": "تنويع ضعيف", "text": f"عندك {zone_diversity} zone بس. Adsterra بتحب التنويع.", "action": "أضف زونات", "link": "/campaigns"})
    if source_diversity < SOURCES_OK: recommendations.append({"severity": "medium", "title": "مصدر واحد", "text": f"كل الترافيك من {source_diversity} مصدر. جرب Galaksion أو Propeller.", "action": "التقارير", "link": "/smart-reports"})
    if human_quality < HUMAN_WARN: recommendations.append({"severity": "high", "title": "جودة بشرية منخفضة", "text": f"Human signals {human_quality:.1f}% فقط. Adsterra بتعتبر ده red flag.", "action": "راجع الزيارات", "link": "/visits"})
    if not recommendations: recommendations.append({"severity": "good", "title": "كل حاجة تمام", "text": "مفيش عوامل خطر. استمر في المراقبة.", "action": None, "link": None})
    return {"score": ban_risk, "level": level, "insufficient_data": False, "reason": "ok", "factors": factors, "metrics": {"total_24h": total, "bot_rate": round(bot_rate, 1), "wasted_rate": round(wasted_rate, 1), "human_quality": round(human_quality, 1), "zone_diversity": zone_diversity, "source_diversity": source_diversity, "volume_stability": round(total / prev["total"], 2) if volume_included else None}, "recommendations": recommendations, "computed_at": now.isoformat()}

def _maybe_save_snapshot(user_id: int, result: dict, db: Session):
    try:
        last = db.query(BanRiskSnapshot).filter(BanRiskSnapshot.user_id == user_id).order_by(BanRiskSnapshot.timestamp.desc()).first()
        if last and (datetime.utcnow() - last.timestamp) < timedelta(hours=1): return False
        m = result.get("metrics") or {}; snap = BanRiskSnapshot(user_id=user_id, timestamp=datetime.utcnow(), score=result.get("score"), level=result.get("level", "unknown"), factors=result.get("factors") or [], total_24h=m.get("total_24h", 0) or 0, bot_rate=m.get("bot_rate", 0.0) or 0.0, wasted_rate=m.get("wasted_rate", 0.0) or 0.0, human_quality=m.get("human_quality", 0.0) or 0.0, zone_diversity=m.get("zone_diversity", 0) or 0, source_diversity=m.get("source_diversity", 0) or 0)
        db.add(snap); db.commit(); return True
    except Exception as e: print(f"[RADAR] snapshot save failed: {e}"); db.rollback(); return False

@router.get("/radar")
def get_radar(force: bool = Query(False), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    cache_key = f"radar:{user.id}"
    if not force:
        cached = radar_cache.get(cache_key)
        if cached is not None: return cached
    result = _compute_radar(user.id, db)
    if not result.get("insufficient_data"): _maybe_save_snapshot(user.id, result, db)
    radar_cache.set(cache_key, result); return result

@router.get("/radar/history")
def get_radar_history(days: int = Query(30, ge=1, le=90), user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    cache_key = f"radar_hist:{user.id}:{days}"
    cached = radar_history_cache.get(cache_key)
    if cached is not None: return cached
    cutoff = datetime.utcnow() - timedelta(days=days)
    rows = db.query(BanRiskSnapshot).filter(BanRiskSnapshot.user_id == user.id, BanRiskSnapshot.timestamp >= cutoff).order_by(BanRiskSnapshot.timestamp.asc()).all()
    series = [{"t": r.timestamp.isoformat() if r.timestamp else None, "score": r.score, "level": r.level, "bot_rate": round(r.bot_rate or 0.0, 1), "wasted_rate": round(r.wasted_rate or 0.0, 1), "human_quality": round(r.human_quality or 0.0, 1)} for r in rows]
    result = {"days": days, "count": len(series), "series": series, "has_enough_data": len(series) >= 3}
    radar_history_cache.set(cache_key, result); return result

@router.post("/radar/snapshot")
def save_snapshot(user: UserModel = Depends(current_user), db: Session = Depends(get_db)):
    result = _compute_radar(user.id, db)
    if result.get("insufficient_data"): raise HTTPException(400, result.get("message") or "بيانات غير كافية")
    m = result.get("metrics") or {}
    snap = BanRiskSnapshot(user_id=user.id, timestamp=datetime.utcnow(), score=result.get("score"), level=result.get("level", "unknown"), factors=result.get("factors") or [], total_24h=m.get("total_24h", 0) or 0, bot_rate=m.get("bot_rate", 0.0) or 0.0, wasted_rate=m.get("wasted_rate", 0.0) or 0.0, human_quality=m.get("human_quality", 0.0) or 0.0, zone_diversity=m.get("zone_diversity", 0) or 0, source_diversity=m.get("source_diversity", 0) or 0)
    db.add(snap); db.commit(); db.refresh(snap)
    radar_cache.invalidate(f"radar:{user.id}"); radar_history_cache.invalidate(f"radar_hist:{user.id}:30")
    return {"ok": True, "snapshot_id": snap.id, "timestamp": snap.timestamp.isoformat(), "score": snap.score}
