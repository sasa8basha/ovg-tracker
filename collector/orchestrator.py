"""
collector/orchestrator.py — Full analysis pipeline (v4.0)

The orchestrator is the SINGLE entry point for visit analysis.
It replaces the old threshold-based `_recompute_verdict` with the new
Multi-Layer Probabilistic Risk Engine.

Pipeline:
    1. evaluate_data_quality      → understand how much we trust the data
    2. analyze_visit              → base signals from analysis.py (legacy)
    3. analyze_headers            → HTTP header contradictions
    4. analyze_temporal_rhythm    → heartbeat timing signals
    5. ContradictionEngine.run    → physical impossibilities
    6. analyze_behavior_deep      → mouse / typing / scroll physics
    7. fingerprint cache lookup   → historical strikes
    8. compute_prior_risk         → IP + strikes based baseline
    9. fuse_signals               → probabilistic fusion
    10. decide                    → verdict with data-quality cap
    11. record_strike             → feed the fingerprint cache on invalid
"""
from __future__ import annotations

from analysis import (
    analyze_visit,
    _duration_ms,
    _safe_dict,
    _safe_list,
    safe_int,
)
from collector.header_analyzer import analyze_headers
from collector.temporal_analyzer import analyze_temporal_rhythm
from collector.fingerprint_cache import get_strikes, record_strike
from collector.contradiction_engine import ContradictionEngine
from collector.behavior_deep import analyze_behavior_deep
from collector.data_quality import evaluate_data_quality
from collector.fusion import fuse_signals, compute_prior_risk
from collector.decision import decide
from collector.signals import SIGNAL_REGISTRY


# =========================================================
# DB-COMPAT DATA QUALITY MAP
# =========================================================
# The `visits.data_quality` column is a String(20), but the UI styles
# expect "full" | "partial" | "legacy" | "pending" | "unknown".
_DB_DQ_MAP = {
    "full":    "full",
    "good":    "full",       # compat
    "partial": "partial",
    "poor":    "partial",    # compat
    "failed":  "partial",    # compat
    "legacy":  "legacy",
    "unknown": "unknown",
}


def _to_db_quality(level: str) -> str:
    return _DB_DQ_MAP.get(str(level).lower(), "partial")


# =========================================================
# BASE-SIGNAL PREPARATION
# =========================================================
def _prep_base_signals(base_evidence: list) -> list:
    """
    Convert analyze_visit()'s legacy evidence (with `score` field)
    into the new signal format that fusion understands.

    Registry strength wins over score-derived strength when the code
    is registered — this prevents legacy scoring from inflating values.
    """
    out = []
    for e in base_evidence or []:
        if not isinstance(e, dict):
            continue
        code = e.get("code")
        if not code:
            continue
        severity = e.get("severity", "medium")
        direction = "human" if severity == "human" else "bot"

        reg = SIGNAL_REGISTRY.get(str(code).upper())
        if reg:
            base_strength = float(reg.get("base", 0.5))
        else:
            score = abs(float(e.get("score", 0) or 0))
            if direction == "human":
                base_strength = min(1.0, score / 40.0)
            else:
                base_strength = min(1.0, score / 100.0)

        out.append({
            "code": code,
            "severity": severity,
            "direction": direction,
            "base_strength": base_strength,
            "detail": str(e.get("detail", ""))[:200],
        })
    return out


# =========================================================
# CONTRADICTION CONTEXT BUILDER
# =========================================================
def _build_contradiction_context(data: dict, ip_info: dict) -> dict:
    nav = _safe_dict(data.get("nav"))
    fp = _safe_dict(data.get("fingerprint"))
    screen = _safe_dict(data.get("screen"))
    behavior = _safe_dict(data.get("behavior"))
    return {
        "ua": str(nav.get("ua") or ""),
        "nav": nav,
        "fp": fp,
        "screen": screen,
        "behavior": behavior,
        "headers": _safe_dict(data.get("_headers")),
        "http_version": data.get("_http_version") or "1.1",
        "ip_info": ip_info or {},
        "heartbeats": _safe_list(data.get("_heartbeats_list")),
        "first_30s": _safe_dict(data.get("_first_30s")),
        "milestones": _safe_dict(data.get("_milestones")),
        "ad_events": _safe_list(data.get("_ad_events")),
        "session_started_at": data.get("_session_started_at"),
        "session_ended_at": data.get("_session_ended_at"),
    }


# =========================================================
# LEGACY-EVIDENCE ADAPTER (for storage / UI)
# =========================================================
def _to_legacy_evidence(signals: list) -> list:
    """
    Convert the new unified signals back to the shape stored in
    `visits.evidence` so the existing UI keeps working.

    Each item keeps BOTH:
      - `score`     (legacy field — positive for bot, negative for human)
      - `strength`  (new field — 0..1)
      - `direction` (new field — "bot" | "human")
    """
    out = []
    for s in signals or []:
        try:
            strength = float(s.get("strength", 0) or 0)
        except (ValueError, TypeError):
            strength = 0.0
        direction = str(s.get("direction", "bot")).lower()
        if direction == "human":
            score = -int(round(strength * 100))
        else:
            score = int(round(strength * 100))
        out.append({
            "code": s.get("code", "UNKNOWN"),
            "severity": s.get("severity", "medium"),
            "score": score,
            "detail": str(s.get("detail", ""))[:200],
            "category": s.get("category", ""),
            "strength": round(strength, 4),
            "direction": direction,
        })
    return out


# =========================================================
# FINGERPRINT STRIKE LOOKUP
# =========================================================
def _fingerprint_cache_signals(fp_hash: str | None) -> tuple[int, list]:
    """
    Return (strikes, extra_signals) for the given fingerprint hash.

    strikes ≥ 10 → critical signal
    strikes ≥ 5  → high signal
    strikes ≥ 3  → medium signal
    """
    if not fp_hash:
        return 0, []
    try:
        stats = get_strikes(fp_hash)
    except Exception:
        return 0, []

    strikes = int(stats.get("strikes") or 0)
    signals = []
    if strikes >= 10:
        signals.append({
            "code": "FINGERPRINT_KNOWN_BAD",
            "severity": "critical",
            "direction": "bot",
            "detail": f"Fingerprint seen {strikes}+ times as bot",
        })
    elif strikes >= 5:
        signals.append({
            "code": "FINGERPRINT_KNOWN_BAD",
            "severity": "high",
            "direction": "bot",
            "detail": f"Fingerprint seen {strikes} times as bot",
        })
    elif strikes >= 3:
        signals.append({
            "code": "FINGERPRINT_SUSPICIOUS",
            "severity": "medium",
            "direction": "bot",
            "detail": f"Fingerprint seen {strikes} times as bot",
        })
    return strikes, signals


# =========================================================
# SAFE COLLECTOR WRAPPERS
# =========================================================
def _collect_base(data: dict, ip_info: dict) -> tuple[dict, list]:
    """Run analyze_visit but neutralize its verdict gate."""
    try:
        analysis_data = dict(data)
        # Force the gate open — we only want the raw evidence list
        analysis_data["_data_quality"] = "full"
        result = analyze_visit(analysis_data, ip_info)
        return result, _prep_base_signals(result.get("evidence", []))
    except Exception as e:
        print(f"[ORCHESTRATOR] analyze_visit failed: {e}")
        return (
            {
                "evidence": [],
                "categories": {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0},
                "privacy_browser": None,
                "cpm_quality": "standard",
                "wasted_impression": False,
                "raw_score": 0,
            },
            [],
        )


def _collect_headers(data: dict) -> list:
    try:
        headers = _safe_dict(data.get("_headers"))
        http_version = data.get("_http_version") or "1.1"
        nav = _safe_dict(data.get("nav"))
        ua = str(nav.get("ua") or "")
        return analyze_headers(headers, ua, http_version) or []
    except Exception as e:
        print(f"[ORCHESTRATOR] header analysis failed: {e}")
        return []


def _collect_temporal(data: dict) -> list:
    try:
        heartbeats = _safe_list(data.get("_heartbeats_list"))
        behavior = _safe_dict(data.get("behavior"))
        t = _duration_ms(behavior)
        return analyze_temporal_rhythm(heartbeats, t) or []
    except Exception as e:
        print(f"[ORCHESTRATOR] temporal analysis failed: {e}")
        return []


def _collect_contradictions(ctx: dict) -> tuple[list, bool]:
    try:
        engine = ContradictionEngine()
        findings = engine.run(ctx) or []
        return findings, bool(engine.has_impossible())
    except Exception as e:
        print(f"[ORCHESTRATOR] contradiction engine failed: {e}")
        return [], False


def _collect_behavior(ctx: dict) -> list:
    try:
        return analyze_behavior_deep(ctx) or []
    except Exception as e:
        print(f"[ORCHESTRATOR] behavior deep failed: {e}")
        return []


# =========================================================
# PRIOR RISK FROM IP + STRIKES
# =========================================================
def _compute_prior(data: dict, ip_info: dict, strikes: int) -> float:
    try:
        sec = _safe_dict(ip_info.get("security"))
        ip_type = str(ip_info.get("type") or "").lower()
        return compute_prior_risk(
            ip_type=ip_type,
            ip_proxy=bool(sec.get("proxy")),
            ip_hosting=bool(sec.get("hosting")),
            fingerprint_strikes=strikes,
        )
    except Exception:
        return 0.15


# =========================================================
# MAIN ENTRY
# =========================================================
def analyze_full(
    data: dict,
    ip_info: dict,
    campaign_mode: str = "balanced",
) -> dict:
    """
    Full analysis pipeline. Returns a rich result dict.

    Backward-compatible keys:
        verdict, score, final_score, confidence, evidence, categories,
        data_quality, filter_reason, privacy_browser, cpm_quality,
        wasted_impression, raw_score, contradiction_impossible

    New keys:
        bot_probability, reason, reason_detail, mode,
        data_quality_report, fusion, decision, signals, fingerprint_strikes
    """
    # ---------- 1) Data quality ----------
    dq = evaluate_data_quality(data)

    # ---------- 2) Base signals from analysis.py ----------
    base_result, base_signals = _collect_base(data, ip_info)

    # ---------- 3) Headers ----------
    header_signals = _collect_headers(data)

    # ---------- 4) Temporal ----------
    temporal_signals = _collect_temporal(data)

    # ---------- 5) Contradictions ----------
    ctx = _build_contradiction_context(data, ip_info)
    contradiction_signals, has_impossible = _collect_contradictions(ctx)

    # ---------- 6) Behavior deep ----------
    behavior_signals = _collect_behavior(ctx)

    # ---------- 7) Fingerprint cache ----------
    fp_hash = data.get("_fp_hash")
    fp_strikes, cache_signals = _fingerprint_cache_signals(fp_hash)

    # ---------- 8) Merge ----------
    all_signals = (
        base_signals
        + header_signals
        + temporal_signals
        + contradiction_signals
        + behavior_signals
        + cache_signals
    )

    # ---------- 9) Prior risk ----------
    prior = _compute_prior(data, ip_info, fp_strikes)

    # ---------- 10) Fusion ----------
    fusion = fuse_signals(
        all_signals,
        data_completeness=dq.completeness,
        prior_risk=prior,
        evidence_quality=dq.reliability,
    )

    # ---------- 11) Decision ----------
    decision = decide(
        fusion,
        dq,
        campaign_mode=campaign_mode,
        has_impossible=has_impossible,
    )

    # ---------- 12) Record strike on invalid ----------
    if decision["verdict"] == "invalid" and fp_hash:
        try:
            codes = [
                s.get("code")
                for s in fusion.get("signals", [])
                if s.get("direction") == "bot"
            ]
            record_strike(fp_hash, "invalid", codes)
        except Exception as e:
            print(f"[ORCHESTRATOR] strike record failed: {e}")

    # ---------- 13) Prepare output ----------
    legacy_evidence = _to_legacy_evidence(fusion.get("signals", []))

    strongest_bot = fusion.get("strongest_bot") or {}
    filter_reason = None
    if decision["verdict"] == "invalid":
        filter_reason = (
            strongest_bot.get("code")
            if isinstance(strongest_bot, dict) and strongest_bot.get("code")
            else decision["reason"]
        )

    return {
        # ===== Legacy compat =====
        "raw_score":        base_result.get("raw_score", 0),
        "score":            decision["score"],
        "final_score":      decision["score"],
        "verdict":          decision["verdict"],
        "confidence":       decision["confidence"],
        "evidence":         legacy_evidence,
        "categories":       base_result.get("categories", {}),
        "privacy_browser":  base_result.get("privacy_browser"),
        "cpm_quality":      base_result.get("cpm_quality", "standard"),
        "wasted_impression": base_result.get("wasted_impression", False),
        "data_quality":     _to_db_quality(dq.level),
        "filter_reason":    filter_reason,
        "contradiction_impossible": has_impossible,

        # ===== New fields =====
        "bot_probability":  decision["bot_probability"],
        "reason":           decision["reason"],
        "reason_detail":    decision["reason_detail"],
        "mode":             decision["mode"],
        "data_quality_report": dq.to_dict(),
        "signals":          fusion.get("signals", []),
        "fusion": {
            "bot_evidence":   fusion.get("bot_evidence", 0.0),
            "human_evidence": fusion.get("human_evidence", 0.0),
            "prior_risk":     fusion.get("prior_risk", 0.15),
            "has_impossible": has_impossible,
            "reasoning":      fusion.get("reasoning", {}),
        },
        "decision":         decision,
        "fingerprint_strikes": fp_strikes,
    }