"""
collector/decision.py — Decision Policy Layer (v4.0)

Turns a fusion result into a final verdict, respecting:
    • Data quality report (max confidence cap, can_decide flag)
    • Campaign mode (strict / balanced / permissive)
    • Impossible contradictions (override data quality gate)

Three modes:

    strict      — invalid threshold 0.55, suspicious threshold 0.30
                  Use for high-value traffic (Adsterra strict publishers).
    balanced    — invalid threshold 0.65, suspicious threshold 0.40
                  Default. Good balance of FP vs FN.
    permissive  — invalid threshold 0.75, suspicious threshold 0.50
                  Use when you cannot afford false positives
                  (small campaigns, cold start).

This module is PURE. No DB, no network, no side effects.
"""
from __future__ import annotations

from typing import Optional

from collector.data_quality import (
    DataQualityReport,
    LEVEL_FAILED,
    LEVEL_LEGACY,
    LEVEL_POOR,
    LEVEL_PARTIAL,
)


# =========================================================
# CAMPAIGN MODES
# =========================================================
VALID_MODES = ("strict", "balanced", "permissive")
DEFAULT_MODE = "balanced"


# Bot probability boundaries per mode.
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


# =========================================================
# HELPERS
# =========================================================
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

    A distance of 0.30+ from the boundary → 100% local confidence.
    Then blended with data reliability and capped.
    """
    try:
        bp = float(bot_probability)
        th = float(reference_threshold)
    except (ValueError, TypeError):
        return 0.0

    distance = abs(bp - th)
    local_conf = min(1.0, distance / 0.30)

    reliability = float(getattr(data_quality, "reliability", 0.7) or 0.7)
    conf = local_conf * (0.5 + 0.5 * reliability)

    return max(0.0, min(1.0, conf))


# =========================================================
# CORE DECISION
# =========================================================
def decide(
    fusion_result: dict,
    data_quality: DataQualityReport,
    *,
    campaign_mode: str = DEFAULT_MODE,
    has_impossible: Optional[bool] = None,
) -> dict:
    """
    Produce a final decision from the fusion result.

    Parameters
    ----------
    fusion_result : dict
        Output of `fuse_signals`.
    data_quality : DataQualityReport
        Output of `evaluate_data_quality`.
    campaign_mode : str
        "strict" | "balanced" | "permissive".
    has_impossible : bool | None
        If None, inferred from fusion_result["has_impossible"].

    Returns
    -------
    dict with keys:
        verdict              "valid" | "suspicious" | "invalid" | "unknown"
        score                int 0..100 (compat with legacy `score`)
        confidence           float 0..1 — already capped
        raw_confidence       float 0..1 — before cap
        bot_probability      float 0..1
        reason               str — machine code
        reason_detail        str — human-readable
        mode                 str — mode actually used
        thresholds           dict
        capped               bool — True if cap reduced confidence
        max_confidence_cap   float
        has_impossible       bool
        data_quality_level   str
    """
    # ---------- Setup ----------
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

    # ---------- Score (0..100) ----------
    score = max(0, min(100, int(round(bp * 100))))

    # ---------- Decision flow ----------
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
            # Critical evidence bypasses the low-quality gate
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
                f"bot_probability={bp:.2f} ≥ {mode} invalid threshold {invalid_th:.2f}"
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

    # ---------- Cap confidence ----------
    capped = False
    confidence = raw_confidence
    if confidence > dq_cap:
        confidence = dq_cap
        capped = True

    confidence = max(0.0, min(1.0, confidence))
    raw_confidence = max(0.0, min(1.0, raw_confidence))

    # ---------- Return ----------
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


# =========================================================
# CONVENIENCE HELPERS
# =========================================================
def is_blocked(decision: dict) -> bool:
    """True if this visit should be blocked from reaching the destination."""
    return decision.get("verdict") == "invalid"


def verdict_label(verdict: str) -> str:
    """Human-readable verdict label."""
    return {
        "valid": "Valid",
        "suspicious": "Suspicious",
        "invalid": "Invalid (Bot)",
        "unknown": "Unknown",
    }.get(str(verdict).lower(), "Unknown")


def mode_from_block_threshold(threshold: int) -> str:
    """
    Map a numeric block threshold (legacy campaign setting) to a mode.

    Legacy thresholds:
        >= 90 → permissive  (block only near-certain bots)
        60-89 → balanced    (default)
        < 60  → strict      (block aggressively)
    """
    try:
        t = int(threshold)
    except (ValueError, TypeError):
        return DEFAULT_MODE

    if t >= 90:
        return "permissive"
    if t < 60:
        return "strict"
    return "balanced"