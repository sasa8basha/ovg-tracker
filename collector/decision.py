"""
collector/decision.py — Decision Policy Layer (v4.1)

Turns a fusion result into a final verdict, respecting:
    - Data quality report (max confidence cap, can_decide flag)
    - Campaign mode (strict / balanced / permissive)
    - Impossible contradictions (override data quality gate)

Three modes:
    strict      — invalid threshold 0.55, suspicious threshold 0.30
    balanced    — invalid threshold 0.65, suspicious threshold 0.40
    permissive  — invalid threshold 0.75, suspicious threshold 0.50

Pure module — no DB, no network, no side effects.
"""
from __future__ import annotations

from typing import Optional

from collector.data_quality import (
    DataQualityReport,
    LEVEL_FAILED,
    LEVEL_LEGACY,
)


VALID_MODES = ("strict", "balanced", "permissive")
DEFAULT_MODE = "balanced"


MODE_THRESHOLDS = {
    "strict": {
        "invalid":    0.55,
        "suspicious": 0.30,
    },
    "balanced": {
        "invalid":    0.65,
        "suspicious": 0.40,
    },
    "permissive": {
        "invalid":    0.75,
        "suspicious": 0.50,
    },
}


def _normalize_mode(mode: Optional[str]) -> str:
    if not mode:
        return DEFAULT_MODE
    m = str(mode).lower().strip()
    return m if m in VALID_MODES else DEFAULT_MODE


def _compute_local_confidence(
    bot_probability: float,
    reference_threshold: float,
    data_quality: DataQualityReport,
) -> float:
    """
    Confidence = distance from decision boundary, scaled by data reliability.

    Linear ramp:
        - distance 0.00 → 50% local confidence
        - distance 0.25+ → 100% local confidence
    Then blended with data reliability and clamped to [0,1].

    FIX (v4.1): previous version returned 0.33 for bp=0.75/th=0.65,
    which was absurdly low. New linear ramp is more reasonable.
    """
    try:
        bp = float(bot_probability)
        th = float(reference_threshold)
    except (ValueError, TypeError):
        return 0.0

    distance = abs(bp - th)

    if distance >= 0.25:
        local_conf = 1.0
    else:
        local_conf = 0.5 + (distance / 0.25) * 0.5

    reliability = float(getattr(data_quality, "reliability", 0.7) or 0.7)
    conf = local_conf * (0.5 + 0.5 * reliability)

    return max(0.0, min(1.0, conf))  # L-22: explicit edge clamp


def decide(
    fusion_result: dict,
    data_quality: DataQualityReport,
    *,
    campaign_mode: str = DEFAULT_MODE,
    has_impossible: Optional[bool] = None,
) -> dict:
    """
    Produce a final decision from the fusion result.

    Returns
    -------
    dict with keys:
        verdict, score, confidence, raw_confidence, bot_probability,
        reason, reason_detail, mode, thresholds, capped,
        max_confidence_cap, has_impossible, data_quality_level
    """
    mode = _normalize_mode(campaign_mode)
    thresholds = MODE_THRESHOLDS[mode]
    invalid_th = thresholds["invalid"]
    suspicious_th = thresholds["suspicious"]

    try:
        bp = float(fusion_result.get("bot_probability", 0.0))
    except (ValueError, TypeError):
        bp = 0.0
    bp = max(0.0, min(1.0, bp))

    if has_impossible is None:
        has_impossible = bool(fusion_result.get("has_impossible", False))
    else:
        has_impossible = bool(has_impossible)

    dq_level = getattr(data_quality, "level", LEVEL_FAILED)
    dq_can_decide = bool(getattr(data_quality, "can_decide", False))
    dq_cap = float(getattr(data_quality, "max_confidence_cap", 0.30) or 0.30)

    score = max(0, min(100, int(round(bp * 100))))

    raw_confidence = 0.0
    verdict = "unknown"
    reason = "unknown"
    reason_detail = ""

    # RULE 1: Impossible contradiction overrides everything
    if has_impossible:
        verdict = "invalid"
        reason = "impossible_contradiction"
        reason_detail = "Physical impossibility detected — bypasses data quality gate."
        raw_confidence = 0.99

    # RULE 2: Data quality blocks a confident decision
    elif not dq_can_decide:
        sb = fusion_result.get("strongest_bot") or {}
        sb_sev = sb.get("severity") if isinstance(sb, dict) else None

        if sb_sev in ("critical", "impossible"):
            verdict = "invalid"
            reason = "critical_evidence_despite_low_quality"
            reason_detail = "Critical bot signal found even with limited data."
            raw_confidence = 0.85
        elif dq_level == LEVEL_LEGACY:
            verdict = "unknown"
            reason = "legacy_data"
            reason_detail = "Legacy v2 data — insufficient for a real verdict."
            raw_confidence = 0.0
        else:
            verdict = "unknown"
            reason = "insufficient_data"
            reason_detail = "Not enough data to decide — confidence too low."
            raw_confidence = 0.0

    # RULE 3: Normal probabilistic decision
    else:
        if bp >= invalid_th:
            verdict = "invalid"
            reason = "high_bot_probability"
            reason_detail = (
                f"bot_probability={bp:.2f} >= {mode} invalid threshold {invalid_th:.2f}"
            )
            raw_confidence = _compute_local_confidence(bp, invalid_th, data_quality)

        elif bp >= suspicious_th:
            verdict = "suspicious"
            reason = "ambiguous_signals"
            reason_detail = (
                f"bot_probability={bp:.2f} in ambiguous band "
                f"[{suspicious_th:.2f}, {invalid_th:.2f})"
            )
            mid = (invalid_th + suspicious_th) / 2.0
            raw_confidence = _compute_local_confidence(bp, mid, data_quality)

        else:
            verdict = "valid"
            he = float(fusion_result.get("human_evidence", 0.0) or 0.0)
            if he >= 0.4:
                reason = "human_signals_dominant"
                reason_detail = (
                    f"Human evidence strong ({he:.2f}), bot_probability={bp:.2f}"
                )
            else:
                reason = "no_bot_signals"
                reason_detail = f"No meaningful bot signals (bot_probability={bp:.2f})"
            raw_confidence = _compute_local_confidence(bp, suspicious_th, data_quality)

    # Cap confidence
    # H-14 FIX: impossible contradictions must not be capped by failed DQ
    capped = False
    confidence = raw_confidence
    if has_impossible:
        confidence = max(confidence, 0.99)
        dq_cap = 0.99
    elif confidence > dq_cap:
        confidence = dq_cap
        capped = True

    confidence = max(0.0, min(1.0, confidence))
    raw_confidence = max(0.0, min(1.0, raw_confidence))

    return {
        "verdict": verdict,
        "score": score,
        "confidence": round(confidence, 4),
        "raw_confidence": round(raw_confidence, 4),
        "bot_probability": round(bp, 4),
        "reason": reason,
        "reason_detail": reason_detail,
        "mode": mode,
        "thresholds": {
            "invalid": invalid_th,
            "suspicious": suspicious_th,
        },
        "capped": capped,
        "max_confidence_cap": round(dq_cap, 4),
        "has_impossible": has_impossible,
        "data_quality_level": dq_level,
    }


def is_blocked(decision: dict) -> bool:
    return decision.get("verdict") == "invalid"


def verdict_label(verdict: str) -> str:
    return {
        "valid": "Valid",
        "suspicious": "Suspicious",
        "invalid": "Invalid (Bot)",
        "unknown": "Unknown",
    }.get(str(verdict).lower(), "Unknown")


def mode_from_block_threshold(threshold: int) -> str:
    try:
        t = int(threshold)
    except (ValueError, TypeError):
        return DEFAULT_MODE

    # M-22: explicit bands (avoid 89→90 cliff surprise in docs)
    if t >= 85:
        return "permissive"
    if t < 60:
        return "strict"
    return "balanced"