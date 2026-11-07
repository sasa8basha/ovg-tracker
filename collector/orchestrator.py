"""
orchestrator.py — OVG Tracker (v10.0 FINAL)

Integration layer between collector_v3.py and analysis.py.

CONTRACT:
  Input:  data (dict from collector), ip_info (dict from get_ip_info)
  Output: dict with all fields:
    - Legacy: raw_score, score, final_score, verdict, confidence, evidence,
              categories, privacy_browser, cpm_quality, wasted_impression, data_quality
    - System 2-8: probability, log_odds, bayesian_confidence, bayesian_contributions,
                  verdict_v2, verdict_metadata, safety_triggered, gate_code
    - Diagnostics: contradiction_impossible, _base_analysis_failed, _analysis_error

KEY PRINCIPLES:
  1. NEVER recompute verdict from scratch — use verdict_engine (System 3)
  2. Merge signals from base + external analyzers with dedupe by severity
  3. Preserve ALL fields from analysis.py
  4. If base analysis fails → insufficient_data (NOT valid/suspicious)
  5. IMPOSSIBLE severity anywhere → confirmed_bot (via System 3)
  6. Mark fingerprint known-bad ONLY for fingerprint-related invalid
  7. Header analysis: System 4 only (header_analyzer removed)
  8. Fingerprint cache: System 7 only (fingerprint_cache removed)
"""
import os
import sys
import logging
from typing import Optional, List, Dict, Any, Tuple

from analysis import (
    analyze_visit,
    _duration_ms,
    safe_int,
    safe_float,
    _safe_dict,
    _safe_list,
    calc_confidence,
)
from collector.bayesian_engine import compute_probability as bayes_compute
from collector.verdict_engine import (
    VerdictV2,
    classify_verdict_v2,
    to_legacy_verdict,
    verdict_metadata,
)
from collector.contradiction_engine import ContradictionEngine
from collector.behavior_deep import analyze_behavior_deep
from collector.temporal_analyzer import analyze_temporal_rhythm
from collector.fingerprint_graph import mark_known_bad as fp_graph_mark_bad


logger = logging.getLogger("ovg.orchestrator")


# =========================================================
# CONSTANTS
# =========================================================
_SEVERITY_RANK = {
    "impossible": 100,
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
    "human": 0,
}

# Only fingerprint-related signals trigger fp_graph.mark_known_bad.
# Context signals (TOR, datacenter, VPN) do NOT — the fingerprint may be legit.
_FP_RELATED_CODES = frozenset([
    # Automation
    "WEBDRIVER_FLAG", "CDP_DETECTED", "HEADLESS_UA",
    "PUPPETEER_DETECTED", "PLAYWRIGHT_DETECTED",
    "SELENIUM_DETECTED", "NIGHTMARE_DETECTED", "PHANTOM_DETECTED",
    # Fingerprint
    "CANVAS_MISSING", "CANVAS_INVALID",
    "SPEECH_VOICES_ZERO", "WEBGL_PRECISION_ZERO",
    # Honeypot
    "HONEYPOT_CLICK", "HONEYPOT_FORM_FILL",
    "UNTRUSTED_CLICK",
    # Impossible
    "WINDOWS_UA_LINUX", "FIREFOX_CHROME_OBJ",
    "WINDOWS_UA_LINUX_PLATFORM", "MACOS_UA_WINDOWS_PLATFORM",
    "IOS_USER_AGENT_DATA", "MOBILE_NO_TOUCH",
    # Prior known-bad
    "FINGERPRINT_KNOWN_BAD",
    "FINGERPRINT_FARM_MASSIVE",
    "FINGERPRINT_FARM_LARGE",
])


# =========================================================
# SIGNAL MERGING
# =========================================================
def _normalize_signal(item: Any) -> Optional[Dict[str, Any]]:
    """Normalize a signal dict. Returns None if invalid."""
    if not isinstance(item, dict):
        return None

    code = item.get("code")
    if not code:
        return None

    sev = str(item.get("severity", "medium")).lower()
    if sev not in _SEVERITY_RANK:
        sev = "medium"

    try:
        score = int(item.get("score", 0) or 0)
    except (ValueError, TypeError, OverflowError):
        score = 0

    detail = str(item.get("detail", ""))[:200]

    return {
        "code": str(code)[:50],
        "severity": sev,
        "score": score,
        "detail": detail,
    }


def _merge_signals(
    base_evidence: Optional[List],
    new_signals: Optional[List],
) -> List[Dict[str, Any]]:
    """
    Merge signals from multiple sources.

    Rules:
      - Deduplicate by code
      - Keep the signal with HIGHEST severity
      - On severity tie, keep the one with highest |score|
      - Truncate detail to 200 chars
      - Result sorted: impossible first, then critical, ..., human last
    """
    by_code: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}

    for source in (base_evidence, new_signals):
        if not source:
            continue
        for e in source:
            norm = _normalize_signal(e)
            if not norm:
                continue

            code = norm["code"]
            rank = _SEVERITY_RANK.get(norm["severity"], 40)
            abs_score = abs(norm["score"])

            if code not in by_code:
                by_code[code] = (rank, abs_score, norm)
                continue

            curr_rank, curr_score, _ = by_code[code]

            if rank > curr_rank:
                by_code[code] = (rank, abs_score, norm)
            elif rank == curr_rank and abs_score > curr_score:
                by_code[code] = (rank, abs_score, norm)

    result = [v[2] for v in by_code.values()]
    result.sort(
        key=lambda x: (
            -_SEVERITY_RANK.get(x["severity"], 40),
            -abs(x["score"]),
        )
    )
    return result


# =========================================================
# CONTEXT BUILDER
# =========================================================
def _build_contradiction_context(data: Any, ip_info: Any) -> Dict[str, Any]:
    """Build unified context for external analyzers. Called ONCE per analysis."""
    data = _safe_dict(data)
    ip_info = _safe_dict(ip_info)

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
        "ip_info": ip_info,
        "heartbeats": _safe_list(data.get("_heartbeats_list")),
        "first_30s": _safe_dict(data.get("_first_30s")),
        "milestones": _safe_dict(data.get("_milestones")),
        "ad_events": _safe_list(data.get("_ad_events")),
        "session_started_at": data.get("_session_started_at"),
        "session_ended_at": data.get("_session_ended_at"),
    }


# =========================================================
# DEFAULT BASE
# =========================================================
def _default_base(error_msg: Optional[str] = None) -> Dict[str, Any]:
    """Full fallback dict when analyze_visit fails."""
    return {
        "raw_score": 0,
        "score": 0,
        "final_score": 0,
        "verdict": "unknown",
        "confidence": 0.0,
        "evidence": [],
        "categories": {
            "impossible": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "human": 0,
        },
        "privacy_browser": None,
        "cpm_quality": "unknown",
        "wasted_impression": False,
        "data_quality": "unknown",
        "probability": 0.5,
        "log_odds": 0.0,
        "bayesian_confidence": 0.0,
        "bayesian_contributions": [],
        "verdict_v2": "insufficient_data",
        "verdict_metadata": verdict_metadata(VerdictV2.INSUFFICIENT_DATA),
        "safety_triggered": None,
        "gate_code": "BASE_ANALYSIS_FAILED",
    }


# =========================================================
# MAIN PIPELINE
# =========================================================
def analyze_full(data: Any, ip_info: Any) -> Dict[str, Any]:
    """
    Full analysis pipeline. Never raises. Always returns valid dict.
    """
    data = _safe_dict(data)
    ip_info = _safe_dict(ip_info)

    # ============ STEP 1: Base analysis (System 1-8) ============
    base_failed = False
    base_error: Optional[str] = None

    try:
        base = analyze_visit(data, ip_info)
        if not isinstance(base, dict):
            base = _default_base("analyze_visit returned non-dict")
            base_failed = True
    except Exception as e:
        logger.exception(f"[ORCH] analyze_visit failed: {e}")
        base = _default_base(str(e))
        base_failed = True
        base_error = str(e)[:500]

    # ============ STEP 2: Build context ONCE ============
    try:
        ctx = _build_contradiction_context(data, ip_info)
    except Exception as e:
        logger.exception(f"[ORCH] context build failed: {e}")
        ctx = {}

    # ============ STEP 3: Contradiction engine ============
    contradictions: List[Dict[str, Any]] = []
    try:
        if ctx:
            engine = ContradictionEngine()
            contradictions = engine.run(ctx) or []
    except Exception as e:
        logger.exception(f"[ORCH] contradiction engine failed: {e}")

    # ============ STEP 4: Behavior deep (mouse/typing/scroll) ============
    behavior_sigs: List[Dict[str, Any]] = []
    try:
        if ctx:
            behavior_sigs = analyze_behavior_deep(ctx) or []
    except Exception as e:
        logger.exception(f"[ORCH] behavior deep failed: {e}")

    # ============ STEP 5: Temporal analyzer (heartbeat rhythm) ============
    temporal_sigs: List[Dict[str, Any]] = []
    try:
        heartbeats = _safe_list(data.get("_heartbeats_list"))
        behavior_for_time = _safe_dict(data.get("behavior"))
        t_on_page = _duration_ms(behavior_for_time)
        temporal_sigs = analyze_temporal_rhythm(heartbeats, t_on_page) or []
    except Exception as e:
        logger.exception(f"[ORCH] temporal analyzer failed: {e}")

    # ============ STEP 6: Merge signals ============
    try:
        new_signals = (
            list(contradictions)
            + list(behavior_sigs)
            + list(temporal_sigs)
        )
        merged = _merge_signals(base.get("evidence", []), new_signals)
    except Exception as e:
        logger.exception(f"[ORCH] merge failed: {e}")
        merged = base.get("evidence", []) or []

    # ============ STEP 7: Recompute verdict (System 2 + 3) ============
    data_quality = str(data.get("_data_quality") or base.get("data_quality") or "unknown")

    if base_failed:
        # Base analysis crashed → insufficient_data
        prob_result = {
            "probability": 0.5, "log_odds": 0.0, "confidence": 0.0,
            "contributions": [], "signal_count": 0,
        }
        verdict_result = {
            "verdict": VerdictV2.INSUFFICIENT_DATA,
            "probability": 0.5,
            "log_odds": 0.0,
            "confidence": 0.0,
            "contributions": [],
            "signal_count": 0,
            "safety": None,
            "gate_code": "BASE_ANALYSIS_FAILED",
        }
    else:
        # Recompute probability on merged signals
        try:
            prob_result = bayes_compute(merged)
        except Exception as e:
            logger.exception(f"[ORCH] bayes_compute failed: {e}")
            prob_result = {
                "probability": 0.5, "log_odds": 0.0, "confidence": 0.0,
                "contributions": [], "signal_count": 0,
            }

        # Recompute verdict with System 3
        try:
            verdict_result = classify_verdict_v2(
                merged, data_quality, probability=prob_result["probability"],
            )
        except Exception as e:
            logger.exception(f"[ORCH] classify_verdict_v2 failed: {e}")
            verdict_result = {
                "verdict": VerdictV2.INSUFFICIENT_DATA,
                "probability": prob_result["probability"],
                "log_odds": prob_result["log_odds"],
                "confidence": prob_result["confidence"],
                "contributions": prob_result["contributions"],
                "signal_count": prob_result["signal_count"],
                "safety": None,
                "gate_code": "VERDICT_ENGINE_FAILED",
            }

    verdict_v2 = verdict_result["verdict"]
    final_verdict = to_legacy_verdict(verdict_v2)

    # ============ STEP 8: Compute final score + confidence ============
    if verdict_v2 == VerdictV2.INSUFFICIENT_DATA:
        final_score = 0
        confidence = 0.0

        # Add gate marker to evidence (unless already present)
        gate_code = verdict_result.get("gate_code") or "DATA_INSUFFICIENT"
        if not any(
            isinstance(e, dict) and e.get("code") == gate_code
            for e in merged
        ):
            merged.append({
                "code": gate_code,
                "severity": "medium",
                "score": 0,
                "detail": f"Data quality: {data_quality}",
            })
    else:
        try:
            final_score = max(0, min(150, sum(
                int(e.get("score", 0) or 0)
                for e in merged
                if isinstance(e, dict)
            )))
        except Exception:
            final_score = 0

        try:
            confidence = calc_confidence(merged)
        except Exception:
            confidence = 0.0

    # ============ STEP 9: Mark known-bad fingerprint ============
    # ONLY if invalid caused by fingerprint-related signals (not context like TOR).
    if final_verdict == "invalid":
        try:
            fp_hash = data.get("_fp_hash")
            if fp_hash:
                merged_codes = {
                    e.get("code") for e in merged if isinstance(e, dict)
                }
                if merged_codes & _FP_RELATED_CODES:
                    fp_graph_mark_bad(fp_hash)
        except Exception as e:
            logger.warning(f"[ORCH] fp_graph_mark_bad failed: {e}")

    # ============ STEP 10: Recompute categories ============
    try:
        categories = {
            "impossible": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "human": 0,
        }
        for e in merged:
            if isinstance(e, dict):
                sev = e.get("severity", "medium")
                if sev in categories:
                    categories[sev] += 1
    except Exception:
        categories = base.get("categories") or {
            "impossible": 0, "critical": 0, "high": 0,
            "medium": 0, "low": 0, "human": 0,
        }

    # ============ STEP 11: Build return dict ============
    contradiction_impossible = any(
        isinstance(e, dict) and e.get("severity") == "impossible"
        for e in contradictions
    )

    return {
        # Legacy fields (backward compat)
        "raw_score": base.get("raw_score", 0),
        "score": final_score,
        "final_score": final_score,
        "verdict": final_verdict,
        "confidence": confidence,
        "evidence": merged,
        "categories": categories,
        "privacy_browser": base.get("privacy_browser"),
        "cpm_quality": base.get("cpm_quality", "standard"),
        "wasted_impression": bool(base.get("wasted_impression", False)),
        "data_quality": data_quality,

        # System 2-8 fields (preserved + recomputed)
        "probability": prob_result.get("probability", 0.5),
        "log_odds": prob_result.get("log_odds", 0.0),
        "bayesian_confidence": prob_result.get("confidence", 0.0),
        "bayesian_contributions": prob_result.get("contributions", []),
        "verdict_v2": (
            verdict_v2.value if hasattr(verdict_v2, "value") else str(verdict_v2)
        ),
        "verdict_metadata": verdict_metadata(verdict_v2),
        "safety_triggered": verdict_result.get("safety"),
        "gate_code": verdict_result.get("gate_code"),

        # Diagnostics
        "contradiction_impossible": contradiction_impossible,
        "_base_analysis_failed": base_failed,
        "_analysis_error": base_error,
    }


# =========================================================
# HEALTH
# =========================================================
def health_status() -> Dict[str, Any]:
    return {
        "system": "orchestrator",
        "status": "ok",
        "version": "10.0",
        "severity_rank": dict(_SEVERITY_RANK),
        "fp_related_codes": sorted(_FP_RELATED_CODES),
    }


# =========================================================
# SELF-TESTS
# =========================================================
def _make_clean_visit() -> Tuple[dict, dict]:
    """Build a clean (human-like) visit for tests."""
    data = {
        "nav": {"ua": "Mozilla/5.0 Chrome/120.0.0.0", "platform": "Win32"},
        "fingerprint": {
            "hardwareConcurrency": 8, "deviceMemory": 8,
            "canvas_hash": "abc123def456789",
            "languages": ["en-US", "en"],
            "timezone": "America/New_York",
        },
        "behavior": {
            "events": {"mousemove": 100, "clicks": 3, "scrolls": 6},
            "total_time_ms": 25000,
            "mouse_variance": 2.5,
        },
        "screen": {"width": 1920, "height": 1080, "availWidth": 1920, "availHeight": 1040},
        "_data_quality": "full",
        "_heartbeat_count": 3,
    }
    ip = {
        "country": "US", "country_code": "US", "isp": "Comcast",
        "type": "residential", "asn": "AS7922", "security": {},
    }
    return data, ip


def run_self_test() -> Tuple[bool, List[str]]:
    results: List[str] = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # --- 1: _merge_signals empty ---
    try:
        r = _merge_signals([], [])
        _chk(r == [], "Test 1: merge empty → []", f"Test 1: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # --- 2: merge dedup keeps higher severity ---
    try:
        base = [{"code": "X", "severity": "medium", "score": 40, "detail": "m"}]
        new = [{"code": "X", "severity": "critical", "score": 85, "detail": "c"}]
        r = _merge_signals(base, new)
        _chk(
            len(r) == 1 and r[0]["severity"] == "critical" and r[0]["score"] == 85,
            "Test 2: dedup keeps higher severity",
            f"Test 2: got {r}",
        )
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # --- 3: merge tie on severity, keeps higher score ---
    try:
        base = [{"code": "X", "severity": "high", "score": 60, "detail": ""}]
        new = [{"code": "X", "severity": "high", "score": 90, "detail": ""}]
        r = _merge_signals(base, new)
        _chk(len(r) == 1 and r[0]["score"] == 90,
             "Test 3: dedup tie keeps higher score",
             f"Test 3: got {r}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # --- 4: merge sorts by severity ---
    try:
        base = [
            {"code": "A", "severity": "low", "score": 10, "detail": ""},
            {"code": "B", "severity": "critical", "score": 80, "detail": ""},
        ]
        new = [
            {"code": "C", "severity": "impossible", "score": 100, "detail": ""},
            {"code": "D", "severity": "high", "score": 60, "detail": ""},
        ]
        r = _merge_signals(base, new)
        sev_order = [x["severity"] for x in r]
        _chk(
            sev_order == ["impossible", "critical", "high", "low"],
            "Test 4: sorted by severity (impossible → critical → high → low)",
            f"Test 4: got {sev_order}",
        )
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # --- 5: merge truncates detail ---
    try:
        long_detail = "x" * 500
        r = _merge_signals(
            [{"code": "X", "severity": "medium", "score": 40, "detail": long_detail}],
            [],
        )
        _chk(len(r) == 1 and len(r[0]["detail"]) == 200,
             "Test 5: detail truncated to 200 chars",
             f"Test 5: detail length = {len(r[0]['detail']) if r else 0}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # --- 6: merge skips invalid items ---
    try:
        r = _merge_signals(
            [
                {"code": None, "severity": "high", "score": 60, "detail": ""},
                "not a dict",
                {"severity": "high", "score": 60},
                {"code": "VALID", "severity": "high", "score": 60, "detail": ""},
            ],
            [],
        )
        _chk(
            len(r) == 1 and r[0]["code"] == "VALID",
            "Test 6: invalid items skipped",
            f"Test 6: got {r}",
        )
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # --- 7: _default_base has all fields ---
    try:
        base = _default_base("test")
        required_legacy = [
            "raw_score", "score", "final_score", "verdict", "confidence",
            "evidence", "categories", "privacy_browser", "cpm_quality",
            "wasted_impression", "data_quality",
        ]
        required_new = [
            "probability", "log_odds", "bayesian_confidence",
            "bayesian_contributions", "verdict_v2", "verdict_metadata",
            "safety_triggered", "gate_code",
        ]
        missing = [k for k in (required_legacy + required_new) if k not in base]
        _chk(missing == [], "Test 7: _default_base has all fields",
             f"Test 7: missing {missing}")
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # --- 8: context builder with empty data ---
    try:
        ctx = _build_contradiction_context({}, {})
        _chk(isinstance(ctx, dict) and "ua" in ctx and "nav" in ctx,
             "Test 8: context builder handles empty data",
             "Test 8: failed")
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # --- 9: analyze_full with empty data (no crash) ---
    try:
        r = analyze_full({}, {})
        _chk(isinstance(r, dict) and "verdict" in r,
             "Test 9: analyze_full({}, {}) no crash",
             "Test 9: failed")
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # --- 10: analyze_full on clean visit → valid ---
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        _chk(r["verdict"] == "valid",
             f"Test 10: clean visit → valid (got {r['verdict']})",
             f"Test 10: got {r['verdict']}, P={r.get('probability')}")
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # --- 11: analyze_full with webdriver=true → invalid ---
    try:
        data, ip = _make_clean_visit()
        data["nav"]["webdriver"] = True
        r = analyze_full(data, ip)
        _chk(r["verdict"] == "invalid",
             f"Test 11: webdriver → invalid (got {r['verdict']})",
             f"Test 11: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # --- 12: legacy quality → unknown ---
    try:
        data, ip = _make_clean_visit()
        data["_data_quality"] = "legacy"
        r = analyze_full(data, ip)
        _chk(r["verdict"] == "unknown",
             f"Test 12: legacy → unknown (got {r['verdict']})",
             f"Test 12: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # --- 13: verdict consistency ---
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        expected = to_legacy_verdict(r["verdict_v2"])
        _chk(r["verdict"] == expected,
             "Test 13: verdict consistent with verdict_v2",
             f"Test 13: {r['verdict']} vs {expected}")
    except Exception as e:
        _chk(False, "", f"Test 13: crashed ({e})")

    # --- 14: all fields present in analyze_full return ---
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        required = [
            "raw_score", "score", "final_score", "verdict", "confidence",
            "evidence", "categories", "probability", "log_odds",
            "bayesian_confidence", "bayesian_contributions",
            "verdict_v2", "verdict_metadata", "safety_triggered",
            "gate_code", "data_quality",
        ]
        missing = [k for k in required if k not in r]
        _chk(missing == [],
             "Test 14: all fields present in return",
             f"Test 14: missing {missing}")
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # --- 15: impossible in base → invalid ---
    try:
        from analysis import _is_headless_ua
        data, ip = _make_clean_visit()
        data["nav"]["ua"] = "Mozilla/5.0 (compatible; HeadlessChrome/120)"
        r = analyze_full(data, ip)
        _chk(r["verdict"] == "invalid",
             f"Test 15: HeadlessChrome UA → invalid (got {r['verdict']})",
             f"Test 15: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # --- 16: TOR IP → invalid (via threat_intel) ---
    try:
        data, ip = _make_clean_visit()
        data["client_ip"] = "185.220.100.240"
        r = analyze_full(data, ip)
        _chk(r["verdict"] == "invalid",
             f"Test 16: TOR → invalid (got {r['verdict']})",
             f"Test 16: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 16: crashed ({e})")

    # --- 17: base analysis failure → insufficient (NOT valid) ---
    try:
        import analysis as _analysis_mod
        original = _analysis_mod.analyze_visit
        _analysis_mod.analyze_visit = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("forced fail"))
        # orchestrator imports analyze_visit at module load — need to patch orchestrator's ref too
        import orchestrator as _orch_mod
        orig_orch = _orch_mod.analyze_visit
        _orch_mod.analyze_visit = _analysis_mod.analyze_visit

        try:
            data, ip = _make_clean_visit()
            r = analyze_full(data, ip)
            _chk(
                r["verdict"] == "unknown" and r["verdict_v2"] == "insufficient_data"
                and r["_base_analysis_failed"] is True,
                "Test 17: base analysis failure → insufficient_data",
                f"Test 17: verdict={r['verdict']}, v2={r['verdict_v2']}, failed={r['_base_analysis_failed']}",
            )
        finally:
            _orch_mod.analyze_visit = orig_orch
            _analysis_mod.analyze_visit = original
    except Exception as e:
        _chk(False, "", f"Test 17: crashed ({e})")

    # --- 18: analyze_full with missing nav/behavior (no crash) ---
    try:
        r = analyze_full({"foo": "bar"}, {"ip": "1.2.3.4"})
        _chk(isinstance(r, dict) and "verdict" in r,
             "Test 18: missing nav/behavior → no crash",
             "Test 18: failed")
    except Exception as e:
        _chk(False, "", f"Test 18: crashed ({e})")

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  ORCHESTRATOR — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[ORCH] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ ORCHESTRATOR PASSED — {passed}/{total} tests")
        logger.info(f"[ORCH] self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ ORCHESTRATOR FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[ORCH] {r}")

    print("=" * 70 + "\n")
    return ok


# =========================================================
# INTEGRATION TESTS
# =========================================================
def _integration_test():
    print("\n" + "=" * 70)
    print("  ORCHESTRATOR: INTEGRATION TEST")
    print("=" * 70)

    results: List[str] = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # 1: end-to-end works
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        _chk(r is not None and "verdict" in r,
             "Test 1: analyze_full works end-to-end",
             "Test 1: failed")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # 2: probability in [0, 1]
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        _chk(0.0 <= r["probability"] <= 1.0,
             "Test 2: probability in [0, 1]",
             f"Test 2: got {r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # 3: categories has all keys
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        required_keys = {"impossible", "critical", "high", "medium", "low", "human"}
        _chk(required_keys.issubset(r["categories"].keys()),
             "Test 3: categories has all 6 keys",
             f"Test 3: got {set(r['categories'].keys())}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # 4: impossible in contradiction → invalid
    try:
        data, ip = _make_clean_visit()
        data["nav"]["ua"] = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/... Firefox/120"
        data["nav"]["platform"] = "Linux x86_64"  # impossible with Windows UA
        r = analyze_full(data, ip)
        _chk(r["verdict"] == "invalid",
             f"Test 4: Windows UA + Linux platform → invalid (got {r['verdict']})",
             f"Test 4: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # 5: no crash on garbage payload
    try:
        r = analyze_full(
            {"nav": "not a dict", "behavior": 12345, "fingerprint": None},
            {"security": "invalid"},
        )
        _chk(isinstance(r, dict) and "verdict" in r,
             "Test 5: garbage payload → no crash",
             "Test 5: failed")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # 6: verdict_metadata is complete
    try:
        data, ip = _make_clean_visit()
        r = analyze_full(data, ip)
        meta = r["verdict_metadata"]
        _chk(
            isinstance(meta, dict) and "action" in meta and "color" in meta,
            "Test 6: verdict_metadata complete",
            f"Test 6: got {meta}",
        )
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)
    if success:
        print(f"  ✅ ORCHESTRATOR INTEGRATION PASSED — {passed}/{total} tests")
    else:
        print(f"  ❌ ORCHESTRATOR INTEGRATION FAILED — {passed}/{total} passed")
    print("=" * 70 + "\n")
    return success


# =========================================================
# AUTO-RUN
# =========================================================
_SELF_TEST_PASSED: Optional[bool] = None


def _should_run_self_test() -> bool:
    if os.getenv("OVG_SELF_TEST_ENABLED", "1") != "1":
        return False
    if "pytest" in sys.modules:
        return False
    return True


if _should_run_self_test():
    try:
        _SELF_TEST_PASSED = print_self_test()
    except Exception as e:
        print(f"⚠️  [ORCH] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False

    try:
        _integration_test()
    except Exception as e:
        print(f"⚠️  [ORCH] integration test crashed at import: {e}")