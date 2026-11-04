"""
routers/radar.py — Ban Risk Radar (v8)

The Radar: مؤشر واحد 0-100 لاحتمالية حظر Adsterra خلال الأسبوع الجاي.
بيتحسب من 6 عوامل:
  1. Bot rate          (weight 30%)
  2. Wasted rate       (weight 15%)
  3. Human quality     (weight 20%)
  4. Zone diversity    (weight 15%)
  5. Source diversity  (weight 10%)
  6. Volume stability  (weight 10% — optional)

الـ endpoint الأساسي: GET /api/radar (cache 60s)
التاريخ:            GET /api/radar/history?days=30
لقطة يدوية:          POST /api/radar/snapshot
الصفحة:              GET /radar
"""
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, distinct
from sqlalchemy.orm import Session

from database import get_db
from models import (
    UserModel, SiteModel, VisitModel, BanRiskSnapshot,
)
from auth import current_user, _optional_user
from helpers import _extract_source
from utils import TTLCache

router = APIRouter()

# Cache منفصل للـ radar (60s)
radar_cache = TTLCache(maxsize=500, ttl=60)
radar_history_cache = TTLCache(maxsize=200, ttl=300)

# حد أدنى للعينة عشان نحسب score موثوق
MIN_VISITS_24H = 30

# عتبات العوامل (higher safety score = better)
# bot_rate
BOT_RATE_SAFE = 5.0
BOT_RATE_OK = 15.0
BOT_RATE_WARN = 25.0
BOT_RATE_BAD = 40.0

# wasted_rate
WASTED_SAFE = 5.0
WASTED_OK = 15.0

# human_quality
HUMAN_GOOD = 70.0
HUMAN_OK = 50.0
HUMAN_WARN = 30.0

# zone_diversity
ZONES_GOOD = 10
ZONES_OK = 5
ZONES_MIN = 3

# source_diversity
SOURCES_GOOD = 3
SOURCES_OK = 2


# =========================================================
# HELPERS
# =========================================================
def read_template(name: str) -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base_dir, "templates", name), "r", encoding="utf-8") as f:
        return f.read()


def _level_from_score(score):
    if score is None:
        return "unknown"
    if score < 20:
        return "low"
    if score < 45:
        return "medium"
    if score < 70:
        return "high"
    return "critical"


def _get_site_ids(user_id: int, db: Session):
    rows = db.query(SiteModel.id).filter(SiteModel.user_id == user_id).all()
    return [r.id for r in rows]


def _aggregate_24h(site_ids, cutoff_start, cutoff_end, db: Session):
    """يجمع كل مؤشرات نافذة زمنية معينة."""
    base = db.query(VisitModel).filter(
        VisitModel.site_id.in_(site_ids),
        VisitModel.timestamp >= cutoff_start,
        VisitModel.timestamp < cutoff_end,
    )

    total = base.with_entities(func.count(VisitModel.id)).scalar() or 0
    if total == 0:
        return {
            "total": 0, "invalid": 0, "valid": 0, "suspicious": 0,
            "wasted": 0, "human": 0, "zone_ids": [], "source_set": set(),
        }

    invalid = base.with_entities(func.count(VisitModel.id)).filter(
        VisitModel.verdict == "invalid"
    ).scalar() or 0

    valid = base.with_entities(func.count(VisitModel.id)).filter(
        VisitModel.verdict == "valid"
    ).scalar() or 0

    suspicious = base.with_entities(func.count(VisitModel.id)).filter(
        VisitModel.verdict == "suspicious"
    ).scalar() or 0

    # wasted = valid + evidence contains CPM_BRAVE or CPM_ADBLOCK_BROWSER
    # (SQLite stores JSON as TEXT, LIKE works)
    wasted = base.with_entities(func.count(VisitModel.id)).filter(
        VisitModel.verdict == "valid",
        (VisitModel.evidence.like('%CPM_BRAVE%')) |
        (VisitModel.evidence.like('%CPM_ADBLOCK_BROWSER%')),
    ).scalar() or 0

    # human = evidence contains any HUMAN_* code
    human = base.with_entities(func.count(VisitModel.id)).filter(
        (VisitModel.evidence.like('%HUMAN_NATURAL_MOUSE%')) |
        (VisitModel.evidence.like('%HUMAN_RICH_INTERACTION%')) |
        (VisitModel.evidence.like('%HUMAN_LONG_ENGAGEMENT%')),
    ).scalar() or 0

    zone_rows = base.with_entities(VisitModel.zone_id).filter(
        VisitModel.zone_id.isnot(None),
        VisitModel.zone_id != "unknown",
    ).distinct().all()
    zone_ids = [r.zone_id for r in zone_rows if r.zone_id]

    source_set = set()
    for zid in zone_ids:
        src = _extract_source(zid)
        if src and src != "unknown":
            source_set.add(src)

    return {
        "total": total,
        "invalid": invalid,
        "valid": valid,
        "suspicious": suspicious,
        "wasted": wasted,
        "human": human,
        "zone_ids": zone_ids,
        "source_set": source_set,
    }


def _score_factor(name, score, weight, value, threshold, label, unit):
    """يبني dict عامل واحد."""
    if score >= 80:
        status = "good"
    elif score >= 50:
        status = "warn"
    else:
        status = "bad"
    return {
        "name": name,
        "score": round(score, 1),
        "weight": weight,
        "value": round(value, 2) if isinstance(value, (int, float)) else value,
        "threshold": threshold,
        "label": label,
        "unit": unit,
        "status": status,
    }


def _compute_radar(user_id: int, db: Session) -> dict:
    """
    الدالة الأساسية: بتحسب الـ Radar من بيانات 24 ساعة.
    بترجع dict فيه: score, level, factors, metrics, recommendations, insufficient_data.
    """
    site_ids = _get_site_ids(user_id, db)
    if not site_ids:
        return {
            "score": None,
            "level": "unknown",
            "insufficient_data": True,
            "reason": "no_sites",
            "message": "أضف موقع الأول عشان نبدأ نحسب مؤشر الخطر.",
            "factors": [],
            "metrics": None,
            "recommendations": [],
        }

    now = datetime.utcnow()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_48h = now - timedelta(hours=48)

    cur = _aggregate_24h(site_ids, cutoff_24h, now, db)
    if cur["total"] < MIN_VISITS_24H:
        return {
            "score": None,
            "level": "unknown",
            "insufficient_data": True,
            "reason": "low_sample",
            "message": f"محتاج {MIN_VISITS_24H} زيارة على الأقل في آخر 24 ساعة. عندك {cur['total']}.",
            "factors": [],
            "metrics": {
                "total_24h": cur["total"],
            },
            "recommendations": [],
        }

    prev = _aggregate_24h(site_ids, cutoff_48h, cutoff_24h, db)

    total = cur["total"]
    bot_rate = cur["invalid"] / total * 100.0
    wasted_rate = cur["wasted"] / total * 100.0
    human_quality = cur["human"] / total * 100.0
    zone_diversity = len(cur["zone_ids"])
    source_diversity = len(cur["source_set"])

    factors = []

    # 1. Bot rate (30%)
    if bot_rate <= BOT_RATE_SAFE:
        bot_score = 100.0
    elif bot_rate <= BOT_RATE_OK:
        bot_score = 80.0
    elif bot_rate <= BOT_RATE_WARN:
        bot_score = 55.0
    elif bot_rate <= BOT_RATE_BAD:
        bot_score = 25.0
    else:
        bot_score = 0.0
    factors.append(_score_factor(
        "bot_rate", bot_score, 30, bot_rate,
        f"≤ {BOT_RATE_OK:.0f}%", "Bot Rate", "%"
    ))

    # 2. Wasted rate (15%)
    if wasted_rate <= WASTED_SAFE:
        wasted_score = 100.0
    elif wasted_rate <= WASTED_OK:
        wasted_score = 70.0
    else:
        wasted_score = max(0.0, 100.0 - (wasted_rate - WASTED_OK) * 3.0)
    factors.append(_score_factor(
        "wasted_rate", wasted_score, 15, wasted_rate,
        f"≤ {WASTED_OK:.0f}%", "Wasted Rate", "%"
    ))

    # 3. Human quality (20%)
    if human_quality >= HUMAN_GOOD:
        human_score = 100.0
    elif human_quality >= HUMAN_OK:
        human_score = 70.0
    elif human_quality >= HUMAN_WARN:
        human_score = 40.0
    else:
        human_score = 20.0
    factors.append(_score_factor(
        "human_quality", human_score, 20, human_quality,
        f"≥ {HUMAN_GOOD:.0f}%", "Human Quality", "%"
    ))

    # 4. Zone diversity (15%)
    if zone_diversity >= ZONES_GOOD:
        zone_score = 100.0
    elif zone_diversity >= ZONES_OK:
        zone_score = 70.0
    elif zone_diversity >= ZONES_MIN:
        zone_score = 40.0
    else:
        zone_score = 20.0
    factors.append(_score_factor(
        "zone_diversity", zone_score, 15, zone_diversity,
        f"≥ {ZONES_GOOD}", "Zone Diversity", ""
    ))

    # 5. Source diversity (10%)
    if source_diversity >= SOURCES_GOOD:
        src_score = 100.0
    elif source_diversity >= SOURCES_OK:
        src_score = 60.0
    else:
        src_score = 30.0
    factors.append(_score_factor(
        "source_diversity", src_score, 10, source_diversity,
        f"≥ {SOURCES_GOOD}", "Source Diversity", ""
    ))

    # 6. Volume stability (10%) — فقط لو عندنا baseline
    volume_included = False
    if prev["total"] >= 10:
        ratio = total / prev["total"]
        if 0.7 <= ratio <= 1.3:
            vol_score = 100.0
        elif 0.5 <= ratio <= 1.5:
            vol_score = 70.0
        else:
            vol_score = 40.0
        factors.append(_score_factor(
            "volume_stability", vol_score, 10, ratio,
            "0.7 – 1.3", "Volume Stability", "×"
        ))
        volume_included = True

    # Weighted safety score (0-100, higher = safer)
    total_weight = sum(f["weight"] for f in factors)
    if total_weight <= 0:
        return {
            "score": None,
            "level": "unknown",
            "insufficient_data": True,
            "reason": "no_factors",
            "message": "معندناش بيانات كافية لحساب المؤشر.",
            "factors": [],
            "metrics": None,
            "recommendations": [],
        }

    safety = sum(f["score"] * f["weight"] for f in factors) / total_weight
    ban_risk = round(100.0 - safety)
    ban_risk = max(0, min(100, ban_risk))
    level = _level_from_score(ban_risk)

    # Recommendations
    recommendations = []

    if bot_rate > BOT_RATE_WARN:
        recommendations.append({
            "severity": "high",
            "title": "Bot rate عالي",
            "text": f"Bot rate {bot_rate:.1f}%. Adsterra ممكن تشك. الهدف < {BOT_RATE_OK:.0f}%.",
            "action": "راجع Zone Analytics",
            "link": "/zone-analytics",
        })

    if wasted_rate > WASTED_OK:
        recommendations.append({
            "severity": "medium",
            "title": "Wasted traffic مرتفع",
            "text": f"Wasted {wasted_rate:.1f}%. ده ترافيك Brave/AdBlock — مش بيدفع.",
            "action": "راجع الزونات",
            "link": "/smart-reports",
        })

    if zone_diversity < ZONES_MIN:
        recommendations.append({
            "severity": "medium",
            "title": "تنويع ضعيف",
            "text": f"عندك {zone_diversity} zone بس. Adsterra بتحب التنويع.",
            "action": "أضف زونات",
            "link": "/sites",
        })

    if source_diversity < SOURCES_OK:
        recommendations.append({
            "severity": "medium",
            "title": "مصدر واحد",
            "text": f"كل الترافيك من {source_diversity} مصدر. جرب Galaksion أو Propeller.",
            "action": "التقارير",
            "link": "/smart-reports",
        })

    if human_quality < HUMAN_WARN:
        recommendations.append({
            "severity": "high",
            "title": "جودة بشرية منخفضة",
            "text": f"Human signals {human_quality:.1f}% فقط. Adsterra بتعتبر ده red flag.",
            "action": "راجع الزيارات",
            "link": "/visits",
        })

    if not recommendations:
        recommendations.append({
            "severity": "good",
            "title": "كل حاجة تمام",
            "text": "مفيش عوامل خطر. استمر في المراقبة.",
            "action": None,
            "link": None,
        })

    return {
        "score": ban_risk,
        "level": level,
        "insufficient_data": False,
        "reason": "ok",
        "factors": factors,
        "metrics": {
            "total_24h": total,
            "bot_rate": round(bot_rate, 1),
            "wasted_rate": round(wasted_rate, 1),
            "human_quality": round(human_quality, 1),
            "zone_diversity": zone_diversity,
            "source_diversity": source_diversity,
            "volume_stability": round(total / prev["total"], 2) if volume_included else None,
        },
        "recommendations": recommendations,
        "computed_at": now.isoformat(),
    }


def _maybe_save_snapshot(user_id: int, result: dict, db: Session):
    """يحفظ snapshot لو مر ساعة على آخر واحد (أو مفيش)."""
    try:
        last = db.query(BanRiskSnapshot).filter(
            BanRiskSnapshot.user_id == user_id,
        ).order_by(BanRiskSnapshot.timestamp.desc()).first()

        if last and (datetime.utcnow() - last.timestamp) < timedelta(hours=1):
            return False

        snap = BanRiskSnapshot(
            user_id=user_id,
            timestamp=datetime.utcnow(),
            score=result.get("score"),
            level=result.get("level", "unknown"),
            factors=result.get("factors") or [],
            total_24h=(result.get("metrics") or {}).get("total_24h", 0) or 0,
            bot_rate=(result.get("metrics") or {}).get("bot_rate", 0.0) or 0.0,
            wasted_rate=(result.get("metrics") or {}).get("wasted_rate", 0.0) or 0.0,
            human_quality=(result.get("metrics") or {}).get("human_quality", 0.0) or 0.0,
            zone_diversity=(result.get("metrics") or {}).get("zone_diversity", 0) or 0,
            source_diversity=(result.get("metrics") or {}).get("source_diversity", 0) or 0,
        )
        db.add(snap)
        db.commit()
        return True
    except Exception as e:
        print(f"[RADAR] snapshot save failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return False


# =========================================================
# API ENDPOINTS
# =========================================================
@router.get("/radar")
def get_radar(
    force: bool = Query(False),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """
    المؤشر الحالي. Cache 60s.
    لو `force=true`، بيتجاهل الكاش.
    """
    cache_key = f"radar:{user.id}"
    if not force:
        cached = radar_cache.get(cache_key)
        if cached is not None:
            return cached

    result = _compute_radar(user.id, db)

    # نحاول نحفظ snapshot (لو مر ساعة)
    if not result.get("insufficient_data"):
        _maybe_save_snapshot(user.id, result, db)

    radar_cache.set(cache_key, result)
    return result


@router.get("/radar/history")
def get_radar_history(
    days: int = Query(30, ge=1, le=90),
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """سلسلة زمنية من الـ snapshots المحفوظة."""
    cache_key = f"radar_hist:{user.id}:{days}"
    cached = radar_history_cache.get(cache_key)
    if cached is not None:
        return cached

    cutoff = datetime.utcnow() - timedelta(days=days)
    rows = db.query(BanRiskSnapshot).filter(
        BanRiskSnapshot.user_id == user.id,
        BanRiskSnapshot.timestamp >= cutoff,
    ).order_by(BanRiskSnapshot.timestamp.asc()).all()

    series = []
    for r in rows:
        series.append({
            "t": r.timestamp.isoformat() if r.timestamp else None,
            "score": r.score,
            "level": r.level,
            "bot_rate": round(r.bot_rate or 0.0, 1),
            "wasted_rate": round(r.wasted_rate or 0.0, 1),
            "human_quality": round(r.human_quality or 0.0, 1),
        })

    result = {
        "days": days,
        "count": len(series),
        "series": series,
        "has_enough_data": len(series) >= 3,
    }
    radar_history_cache.set(cache_key, result)
    return result


@router.post("/radar/snapshot")
def save_snapshot(
    user: UserModel = Depends(current_user),
    db: Session = Depends(get_db),
):
    """يحفظ snapshot يدوياً (اختياري)."""
    result = _compute_radar(user.id, db)
    if result.get("insufficient_data"):
        raise HTTPException(400, result.get("message") or "بيانات غير كافية")

    snap = BanRiskSnapshot(
        user_id=user.id,
        timestamp=datetime.utcnow(),
        score=result.get("score"),
        level=result.get("level", "unknown"),
        factors=result.get("factors") or [],
        total_24h=(result.get("metrics") or {}).get("total_24h", 0) or 0,
        bot_rate=(result.get("metrics") or {}).get("bot_rate", 0.0) or 0.0,
        wasted_rate=(result.get("metrics") or {}).get("wasted_rate", 0.0) or 0.0,
        human_quality=(result.get("metrics") or {}).get("human_quality", 0.0) or 0.0,
        zone_diversity=(result.get("metrics") or {}).get("zone_diversity", 0) or 0,
        source_diversity=(result.get("metrics") or {}).get("source_diversity", 0) or 0,
    )
    db.add(snap)
    db.commit()
    db.refresh(snap)

    radar_cache.invalidate(f"radar:{user.id}")
    radar_history_cache.invalidate(f"radar_hist:{user.id}:30")

    return {
        "ok": True,
        "snapshot_id": snap.id,
        "timestamp": snap.timestamp.isoformat(),
        "score": snap.score,
    }


# =========================================================
# PAGE
# =========================================================
@router.get("/radar-page", response_class=HTMLResponse)
def radar_page(request: Request, db: Session = Depends(get_db)):
    """صفحة /radar (HTML). مُسجّلة على مسار منفصل عشان مايتعارضش مع /api/radar."""
    if not _optional_user(request, db):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(read_template("radar.html"))
