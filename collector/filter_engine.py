"""
collector/filter_engine.py — Bridge between collector and orchestrator (v4.0)

Wraps `analyze_full` and adds:
    - campaign_mode passthrough
    - filter_reason extraction (single primary reason for rejection)
    - backward-compatible return shape

The filter_reason is ONLY populated for invalid visits.
For valid/suspicious/unknown it stays None.
"""
from collector.orchestrator import analyze_full


# =========================================================
# CONFIG
# =========================================================
DEFAULT_MODE = "balanced"


# =========================================================
# HELPERS
# =========================================================
def _pick_filter_reason(result: dict) -> str | None:
    """
    Choose a single human-readable reason for rejection.
    Prefer the strongest bot signal; fallback to decision reason.
    """
    evidence = result.get("evidence") or []
    # Filter only positive scores (bot indicators)
    risks = [e for e in evidence if isinstance(e, dict) and e.get("score", 0) > 0]
    if risks:
        risks.sort(key=lambda x: x.get("score", 0), reverse=True)
        return risks[0].get("code")

    # Fallback to explicit decision reason
    decision_reason = result.get("reason")
    if decision_reason:
        return str(decision_reason).upper()

    # Final fallback for impossible contradictions
    if result.get("contradiction_impossible"):
        return "IMPOSSIBLE_CONTRADICTION"

    return None


# =========================================================
# MAIN ENTRY
# =========================================================
def evaluate_visit(
    data: dict,
    ip_info: dict,
    campaign_mode: str = DEFAULT_MODE,
) -> dict:
    """
    Run the full analysis pipeline via the new probabilistic engine.

    Parameters
    ----------
    data : dict
        Merged visit payload (same shape `analyze_full` expects).
    ip_info : dict
        From `get_ip_info`.
    campaign_mode : str
        "strict" | "balanced" | "permissive".

    Returns
    -------
    dict — the full `analyze_full` result, plus:
        - `filter_reason` (str | None): primary reason for rejection
    """
    result = analyze_full(data, ip_info, campaign_mode=campaign_mode)

    verdict = result.get("verdict", "unknown")

    # Only compute a filter_reason for rejected visits
    if verdict == "invalid":
        existing = result.get("filter_reason")
        if not existing:
            result["filter_reason"] = _pick_filter_reason(result)
    else:
        # Explicitly clear for non-invalid
        result["filter_reason"] = None

    return result