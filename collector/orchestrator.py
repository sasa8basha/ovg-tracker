"""
orchestrator.py — Full analysis pipeline (v3.3)

Pipeline:
  1. Base analysis (v3.1 analysis.py)
  2. Header analysis (v3.2)
  3. Temporal rhythm (v3.2)
  4. Fingerprint cache (v3.2)
  5. Contradiction engine (v3.3) ← NEW
  6. Behavior deep (v3.3) ← NEW
  7. Merge + verdict
"""
from analysis import analyze_visit, _duration_ms, safe_int, safe_float, _safe_dict, _safe_list
from collector.header_analyzer import analyze_headers
from collector.temporal_analyzer import analyze_temporal_rhythm
from collector.fingerprint_cache import get_strikes as fp_get_strikes, record_strike as fp_record
from collector.contradiction_engine import ContradictionEngine
from collector.behavior_deep import analyze_behavior_deep


def _merge_signals(base_evidence, new_signals):
    seen_codes = set()
    merged = []
    for e in base_evidence:
        if isinstance(e, dict):
            code = e.get("code")
            if code and code not in seen_codes:
                merged.append(e)
                seen_codes.add(code)
    for sig in new_signals:
        if not isinstance(sig, dict):
            continue
        code = sig.get("code")
        if code and code not in seen_codes:
            merged.append(sig)
            seen_codes.add(code)
    return merged


def _recompute_verdict(evidence, data_quality, contradiction_has_impossible):
    """Recompute verdict with contradiction priority."""
    if data_quality in ("legacy", "failed"):
        return "unknown", 0

    # IMPOSSIBLE contradiction → instant invalid (override data_quality gate)
    if contradiction_has_impossible:
        total_score = sum(int(e.get("score", 0) or 0) for e in evidence if isinstance(e, dict))
        return "invalid", max(100, min(150, total_score))

    has_critical = any(
        e.get("severity") == "critical" for e in evidence if isinstance(e, dict)
    )
    total_score = sum(int(e.get("score", 0) or 0) for e in evidence if isinstance(e, dict))
    total_score = max(0, min(150, total_score))

    if data_quality == "partial" and not has_critical:
        return "unknown", total_score

    if has_critical or total_score >= 80:
        return "invalid", total_score
    if total_score >= 40:
        return "suspicious", total_score
    return "valid", total_score


def analyze_full(data: dict, ip_info: dict) -> dict:
    """
    Full analysis pipeline.
    """
    # ============ Step 1: Base analysis (v3.1) ============
    try:
        base = analyze_visit(data, ip_info)
    except Exception as e:
        print(f"[ORCHESTRATOR] base analysis failed: {e}")
        base = {
            "score": 50, "verdict": "suspicious", "evidence": [],
            "raw_score": 50, "final_score": 50, "confidence": 0.0,
            "categories": {"critical": 0, "high": 0, "medium": 0, "low": 0, "human": 0},
            "data_quality": data.get("_data_quality", "unknown"),
            "cpm_quality": "standard", "wasted_impression": False,
            "privacy_browser": None,
        }

    new_signals = []

    # ============ Step 2: Header analysis ============
    headers = data.get("_headers") or {}
    http_version = data.get("_http_version") or "1.1"
    ua = str((data.get("nav") or {}).get("ua") or "")
    try:
        header_sigs = analyze_headers(headers, ua, http_version)
        new_signals.extend(header_sigs)
    except Exception as e:
        print(f"[ORCHESTRATOR] header analysis failed: {e}")

    # ============ Step 3: Temporal rhythm ============
    heartbeats = data.get("_heartbeats_list") or []
    behavior = data.get("behavior") or {}
    t_on_page = _duration_ms(behavior)
    try:
        temporal_sigs = analyze_temporal_rhythm(heartbeats, t_on_page)
        new_signals.extend(temporal_sigs)
    except Exception as e:
        print(f"[ORCHESTRATOR] temporal analysis failed: {e}")

    # ============ Step 4: Fingerprint cache ============
    fp_hash = data.get("_fp_hash")
    if fp_hash:
        try:
            stats = fp_get_strikes(fp_hash)
            strikes = int(stats.get("strikes") or 0)
            if strikes >= 10:
                new_signals.append({
                    "code": "FINGERPRINT_KNOWN_BAD",
                    "severity": "critical",
                    "score": 100,
                    "detail": f"Fingerprint seen {strikes}+ times as bot",
                })
            elif strikes >= 5:
                new_signals.append({
                    "code": "FINGERPRINT_KNOWN_BAD",
                    "severity": "high",
                    "score": 85,
                    "detail": f"Fingerprint seen {strikes} times as bot",
                })
            elif strikes >= 3:
                new_signals.append({
                    "code": "FINGERPRINT_SUSPICIOUS",
                    "severity": "medium",
                    "score": 55,
                    "detail": f"Fingerprint seen {strikes} times as bot",
                })
        except Exception as e:
            print(f"[ORCHESTRATOR] cache lookup failed: {e}")

    # ============ Step 5: Contradiction engine ============
    contradiction_has_impossible = False
    try:
        ctx = _build_contradiction_context(data, ip_info)
        engine = ContradictionEngine()
        contradictions = engine.run(ctx)
        contradiction_has_impossible = engine.has_impossible()
        new_signals.extend(contradictions)
    except Exception as e:
        print(f"[ORCHESTRATOR] contradiction engine failed: {e}")
        import traceback as _tb
        _tb.print_exc()

    # ============ Step 6: Behavior deep ============
    try:
        ctx = _build_contradiction_context(data, ip_info)
        behavior_sigs = analyze_behavior_deep(ctx)
        new_signals.extend(behavior_sigs)
    except Exception as e:
        print(f"[ORCHESTRATOR] behavior deep failed: {e}")

    # ============ Step 7: Merge + verdict ============
    merged = _merge_signals(base.get("evidence", []), new_signals)
    data_quality = str(data.get("_data_quality") or base.get("data_quality") or "unknown")

    new_verdict, new_score = _recompute_verdict(
        merged, data_quality, contradiction_has_impossible
    )

    # ============ Step 8: Update cache ============
    if fp_hash and new_verdict == "invalid":
        try:
            codes = [e.get("code") for e in merged if isinstance(e, dict) and e.get("code")]
            fp_record(fp_hash, "invalid", codes)
        except Exception as e:
            print(f"[ORCHESTRATOR] cache record failed: {e}")

    # ============ Recompute confidence ============
    confidence = base.get("confidence", 0.0)
    if contradiction_has_impossible:
        confidence = 1.0
    elif new_verdict == "invalid" and confidence < 0.9:
        confidence = max(confidence, 0.9)

    return {
        "raw_score": base.get("raw_score", 0),
        "score": new_score,
        "final_score": new_score,
        "verdict": new_verdict,
        "confidence": confidence,
        "evidence": merged,
        "categories": base.get("categories", {}),
        "privacy_browser": base.get("privacy_browser"),
        "cpm_quality": base.get("cpm_quality", "standard"),
        "wasted_impression": base.get("wasted_impression", False),
        "data_quality": data_quality,
        "contradiction_impossible": contradiction_has_impossible,
    }


def _build_contradiction_context(data, ip_info):
    """Build unified context for all analyzers."""
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
