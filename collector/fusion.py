"""
collector/fusion.py — Probabilistic Fusion Layer (v4.0)

Takes a heterogeneous list of raw signals (from any source) and produces
a calibrated `bot_probability` — NOT a linear score sum.

Mathematical model
------------------
For each signal with strength s ∈ [0,1] and severity factor f ∈ [0,1]:

    contribution = s × f

Bot evidence accumulates independently:

    bot_evidence ← 1 − (1 − bot_evidence) × (1 − contribution)

Same accumulation for human evidence.

Posterior probability of "bot" given prior:

    posterior = prior + (1 − prior) × bot_evidence

Human evidence then reduces the posterior by a *severity-aware* factor:

    reduction_max = cap based on bot evidence severity
    reduction     = human_evidence × reduction_max
    posterior     ← posterior × (1 − reduction)

The reduction cap is intentional:
    - Impossible contradiction   → only 10% reduction possible
    - 2+ critical signals        → max 30% reduction
    - 1 critical signal          → max 55% reduction
    - 3+ high signals            → max 70% reduction
    - Otherwise                  → max 85% reduction

This prevents a single "HUMAN_NATURAL_MOUSE" signal from saving a bot
that produced a physical impossibility.

This module is PURE. No DB, no network, no side effects.
"""
from __future__ import annotations

from typing import List, Optional

from collector.signals import (
    normalize_signals,
    has_impossible as signals_has_impossible,
    strongest_bot,
    strongest_human,
)


# =========================================================
# SEVERITY → FUSION FACTOR
# =========================================================
# Multiplied with `signal.strength` to get the effective contribution.
SEVERITY_FACTOR = {
    "impossible": 1.00,
    "critical":   0.90,
    "high":       0.75,
    "medium":     0.50,
    "low":        0.25,
    "human":      1.00,   # M-21: weight for HUMAN evidence path (not bot reduction)erridden by direction
}

# Human signals carry severity="human"; their factor is uniform.
HUMAN_SIGNAL_FACTOR = 0.75


# =========================================================
# HUMAN REDUCTION POLICY
# =========================================================
# How much can human evidence cancel bot evidence?
# Rule: the stronger / more impossible the bot evidence,
# the less a human signal can save the visit.

HUMAN_REDUCTION_DEFAULT = 0.85               # baseline max reduction
HUMAN_REDUCTION_WITH_HIGHS = 0.70            # 3+ highs
HUMAN_REDUCTION_WITH_ONE_HIGH = 0.80         # 1-2 highs
HUMAN_REDUCTION_WITH_CRITICAL = 0.55         # 1 critical
HUMAN_REDUCTION_WITH_MULTI_CRITICAL = 0.30   # 2+ criticals
HUMAN_REDUCTION_WITH_IMPOSSIBLE = 0.10       # impossible → almost no reduction


# =========================================================
# PRIOR CLAMP
# =========================================================
# Prior is supplied by the orchestrator (IP + fingerprint strikes).
PRIOR_MIN = 0.0
PRIOR_MAX = 0.90


# =========================================================
# CORE FUSION
# =========================================================
def fuse_signals(
    raw_signals: List[dict],
    *,
    data_completeness: float = 1.0,
    prior_risk: float = 0.15,
    evidence_quality: float = 0.70,
    context_multiplier: float = 1.0,
    source_override: Optional[str] = None,
) -> dict:
    """
    Fuse raw signals into a calibrated `bot_probability`.

    Parameters
    ----------
    raw_signals : list[dict]
        Any mix of legacy and new signal formats — all normalized internally.
    data_completeness : float in [0,1]
        Data quality score. Sparse payloads reduce single-signal impact.
    prior_risk : float in [0,1]
        Prior probability — supplied by orchestrator.
    evidence_quality : float in [0,1]
        Fallback per-signal evidence quality.
    context_multiplier : float ≥ 0
        Default multiplier for signals that need contextual boost.

    Returns
    -------
    dict with keys:
        bot_probability    float in [0,1]
        bot_evidence       float in [0,1]
        human_evidence     float in [0,1]
        prior_risk         float in [0,1]
        has_impossible     bool
        strongest_bot      dict | None
        strongest_human    dict | None
        signals            list[dict] — normalized signals actually used
        dropped            int
        reasoning          dict — full trace
    """
    # ---------- 1) Normalize ----------
    raw_list = raw_signals or []
    normalized: List[dict] = normalize_signals(
        raw_list,
        evidence_quality=evidence_quality,
        context_multiplier=context_multiplier,
        source_override=source_override,
    )
    dropped = len(raw_list) - len(normalized)

    # ---------- 2) Clamp inputs ----------
    try:
        dc = float(data_completeness)
    except (ValueError, TypeError):
        dc = 0.7
    dc = max(0.0, min(1.0, dc))

    try:
        prior = float(prior_risk)
    except (ValueError, TypeError):
        prior = 0.15
    prior = max(PRIOR_MIN, min(PRIOR_MAX, prior))

    # ---------- 3) Split ----------
    bot_signals = [s for s in normalized if s.get("direction") == "bot"]
    human_signals = [s for s in normalized if s.get("direction") == "human"]

    # ---------- 4) Accumulate bot evidence ----------
    bot_evidence = 0.0
    bot_contributions: List[dict] = []
    for s in bot_signals:
        strength = float(s.get("strength", 0.0))
        if strength <= 0.0:
            continue
        sev = s.get("severity", "medium")
        factor = SEVERITY_FACTOR.get(sev, 0.50)
        contribution = strength * factor

        # Sparse payloads cap single-signal contribution
        if dc < 0.5:
            contribution *= 0.70

        contribution = max(0.0, min(0.99, contribution))

        before = bot_evidence
        bot_evidence = 1.0 - (1.0 - bot_evidence) * (1.0 - contribution)

        bot_contributions.append({
            "code": s.get("code"),
            "severity": sev,
            "contribution": round(contribution, 4),
            "evidence_before": round(before, 4),
            "evidence_after": round(bot_evidence, 4),
        })

    # ---------- 5) Accumulate human evidence ----------
    human_evidence = 0.0
    human_contributions: List[dict] = []
    for s in human_signals:
        strength = float(s.get("strength", 0.0))
        if strength <= 0.0:
            continue
        contribution = strength * HUMAN_SIGNAL_FACTOR

        # Sparse payloads → human signals also lose impact
        if dc < 0.5:
            contribution *= 0.50

        contribution = max(0.0, min(0.99, contribution))

        before = human_evidence
        human_evidence = 1.0 - (1.0 - human_evidence) * (1.0 - contribution)

        human_contributions.append({
            "code": s.get("code"),
            "contribution": round(contribution, 4),
            "evidence_before": round(before, 4),
            "evidence_after": round(human_evidence, 4),
        })

    # ---------- 6) Pre-human posterior ----------
    pre_human_posterior = prior + (1.0 - prior) * bot_evidence

    # ---------- 7) Severity-aware human reduction cap ----------
    impossible = signals_has_impossible(normalized)
    critical_count = sum(1 for s in bot_signals if s.get("severity") == "critical")
    high_count = sum(1 for s in bot_signals if s.get("severity") == "high")

    # H-15 FIX: strong human evidence can still reduce multi-critical false positives
    if impossible:
        reduction_max = HUMAN_REDUCTION_WITH_IMPOSSIBLE
    elif critical_count >= 2 and human_evidence > 0.95:
        reduction_max = 0.70  # escape hatch
    elif critical_count >= 2:
        reduction_max = HUMAN_REDUCTION_WITH_MULTI_CRITICAL
    elif critical_count == 1:
        reduction_max = HUMAN_REDUCTION_WITH_CRITICAL
    elif high_count >= 3:
        reduction_max = HUMAN_REDUCTION_WITH_HIGHS
    elif high_count >= 1:
        reduction_max = HUMAN_REDUCTION_WITH_ONE_HIGH
    else:
        reduction_max = HUMAN_REDUCTION_DEFAULT

    # ---------- 8) Apply human reduction ----------
    reduction = human_evidence * reduction_max
    posterior = pre_human_posterior * (1.0 - reduction)

    # ---------- 9) Clamp ----------
    posterior = max(0.0, min(1.0, posterior))
    bot_evidence = max(0.0, min(1.0, bot_evidence))
    human_evidence = max(0.0, min(1.0, human_evidence))

    # ---------- 10) Extract strongest ----------
    sb = strongest_bot(normalized)
    sh = strongest_human(normalized)

    # ---------- 11) Build reasoning trace ----------
    reasoning = {
        "data_completeness": round(dc, 3),
        "prior_risk": round(prior, 3),
        "signals_total": len(normalized),
        "signals_dropped": dropped,
        "bot_signals_count": len(bot_signals),
        "human_signals_count": len(human_signals),
        "critical_count": critical_count,
        "high_count": high_count,
        "has_impossible": impossible,
        "human_reduction_max": round(reduction_max, 3),
        "human_reduction_applied": round(reduction, 4),
        "pre_human_posterior": round(pre_human_posterior, 4),
        "final_posterior": round(posterior, 4),
        "bot_contributions": bot_contributions,
        "human_contributions": human_contributions,
    }

    return {
        "bot_probability": round(posterior, 4),
        "bot_evidence": round(bot_evidence, 4),
        "human_evidence": round(human_evidence, 4),
        "prior_risk": round(prior, 4),
        "has_impossible": impossible,
        "strongest_bot": sb,
        "strongest_human": sh,
        "signals": normalized,
        "dropped": dropped,
        "reasoning": reasoning,
    }


# =========================================================
# PRIOR RISK BUILDER
# =========================================================
def compute_prior_risk(
    *,
    ip_type: str = "",
    ip_proxy: bool = False,
    ip_hosting: bool = False,
    ip_datacenter_asn: bool = False,
    fingerprint_strikes: int = 0,
    campaign_type: str = "",
) -> float:
    """
    Compute a prior risk in [0,1] from context.

    Conservative by design — the prior alone never decides the verdict,
    it just moves the baseline.

    Parameters
    ----------
    ip_type : str
        "hosting" | "residential" | "unknown" (from ip_info).
    ip_proxy, ip_hosting : bool
        From ip_info["security"].
    ip_datacenter_asn : bool
        True if ASN is in DATACENTER_ASNS.
    fingerprint_strikes : int
        Number of past invalid strikes for this fingerprint hash.
    campaign_type : str
        "landing" | "direct" | "hybrid".
    """
    prior = 0.10  # base rate

    # ---- IP signals ----
    if ip_proxy and ip_hosting:
        prior += 0.35
    elif ip_hosting:
        prior += 0.20
    elif ip_proxy:
        prior += 0.15

    if ip_datacenter_asn:
        prior += 0.10

    t = str(ip_type or "").lower()
    if t == "hosting":
        prior += 0.15
    elif t == "residential":
        prior -= 0.03  # small human-prior boost

    # ---- Fingerprint strike history ----
    if fingerprint_strikes >= 10:
        prior += 0.40
    elif fingerprint_strikes >= 5:
        prior += 0.25
    elif fingerprint_strikes >= 3:
        prior += 0.12
    elif fingerprint_strikes >= 1:
        prior += 0.05

    # ---- Campaign type nudge ----
    ct = str(campaign_type or "").lower()
    if ct == "direct":
        prior += 0.03

    return max(PRIOR_MIN, min(PRIOR_MAX, prior))