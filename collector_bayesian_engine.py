"""
collector/bayesian_engine.py — SYSTEM 2: Bayesian Evidence Engine

Self-contained. No dependencies on project files (except adaptive_thresholds
for reliability lookup, which is wrapped in try/except).

Replaces naive score-summing with probabilistic inference.

SYSTEM 5 INTEGRATION:
  - Reliability now comes from adaptive_thresholds.get_reliability()
  - Falls back to SEVERITY_LOG_ODDS defaults when no ground truth data
"""
import os
import sys
import math
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("ovg.bayesian")


# =========================================================
# ADAPTIVE INTEGRATION (safe import)
# =========================================================
try:
    from collector.adaptive_thresholds import get_reliability as _adaptive_get_rel
    _ADAPTIVE_AVAILABLE = True
except Exception:
    _ADAPTIVE_AVAILABLE = False
    def _adaptive_get_rel(code, default):
        return default


# =========================================================
# SEVERITY → LOG-ODDS MAPPING
# =========================================================
# (base_log_odds, default_reliability)
SEVERITY_LOG_ODDS = {
    "impossible": (8.0, 0.98),
    "critical":   (6.0, 0.90),
    "high":       (3.5, 0.75),
    "medium":     (1.5, 0.55),
    "low":        (0.5, 0.35),
    "human":      (-1.5, 0.60),
}

INVALID_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.65


# =========================================================
# SIGNAL DATACLASS
# =========================================================
@dataclass
class Signal:
    code: str
    severity: str
    base_log_odds: float
    reliability: float
    detail: str = ""

    @property
    def effective_log_odds(self) -> float:
        return self.base_log_odds * self.reliability


def _make_signal(item: dict, reliability_override: Optional[float] = None) -> Signal:
    """Build a Signal from a raw evidence dict."""
    code = str(item.get("code", "UNKNOWN"))[:50]
    severity = str(item.get("severity", "medium")).lower()
    detail = str(item.get("detail", ""))[:200]

    if severity not in SEVERITY_LOG_ODDS:
        severity = "medium"

    base_lo, default_rel = SEVERITY_LOG_ODDS[severity]

    # SYSTEM 5: try adaptive reliability first
    if reliability_override is not None:
        rel = reliability_override
    elif _ADAPTIVE_AVAILABLE:
        try:
            rel = _adaptive_get_rel(code, default_rel)
        except Exception:
            rel = default_rel
    else:
        rel = default_rel

    return Signal(
        code=code,
        severity=severity,
        base_log_odds=base_lo,
        reliability=rel,
        detail=detail,
    )


# =========================================================
# PROBABILITY COMPUTATION
# =========================================================
def compute_probability(items: List[dict]) -> Dict[str, Any]:
    """Compute the Bayesian probability that a visit is a bot."""
    if not items:
        return {
            "probability": 0.5,
            "log_odds": 0.0,
            "confidence": 0.0,
            "contributions": [],
            "signal_count": 0,
        }

    total_log_odds = 0.0
    contributions = []

    for item in items:
        if not isinstance(item, dict):
            continue
        signal = _make_signal(item)
        eff = signal.effective_log_odds
        total_log_odds += eff
        contributions.append({
            "code": signal.code,
            "severity": signal.severity,
            "base_log_odds": round(signal.base_log_odds, 3),
            "reliability": round(signal.reliability, 3),
            "effective_log_odds": round(eff, 3),
            "detail": signal.detail,
        })

    clamped = max(-50.0, min(50.0, total_log_odds))
    try:
        probability = 1.0 / (1.0 + math.exp(-clamped))
    except OverflowError:
        probability = 1.0 if total_log_odds > 0 else 0.0

    confidence = abs(probability - 0.5) * 2.0

    return {
        "probability": round(probability, 4),
        "log_odds": round(total_log_odds, 3),
        "confidence": round(confidence, 4),
        "contributions": contributions,
        "signal_count": len(contributions),
    }


# =========================================================
# VERDICT EVALUATION
# =========================================================
def bayesian_evaluate(items: List[dict], data_quality: str = "full") -> Dict[str, Any]:
    """Full Bayesian evaluation with safety rules."""
    dq = (data_quality or "unknown").lower()

    has_critical = any(
        isinstance(e, dict) and e.get("severity") in ("critical", "impossible")
        for e in items
    )
    has_impossible = any(
        isinstance(e, dict) and e.get("severity") == "impossible"
        for e in items
    )

    if dq in ("legacy", "failed"):
        return {
            "verdict": "unknown",
            "probability": 0.5,
            "log_odds": 0.0,
            "confidence": 0.0,
            "contributions": [],
            "signal_count": 0,
            "gate_code": "DATA_LEGACY" if dq == "legacy" else "DATA_INSUFFICIENT",
            "safety": None,
        }

    if dq == "partial" and not has_critical:
        return {
            "verdict": "unknown",
            "probability": 0.5,
            "log_odds": 0.0,
            "confidence": 0.0,
            "contributions": [],
            "signal_count": 0,
            "gate_code": "DATA_INSUFFICIENT",
            "safety": None,
        }

    result = compute_probability(items)
    p = result["probability"]

    if has_impossible:
        result["verdict"] = "invalid"
        result["gate_code"] = None
        result["safety"] = "impossible"
        return result

    if p >= INVALID_THRESHOLD:
        verdict = "invalid"
        safety = None
    elif p >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
        safety = None
    elif has_critical:
        verdict = "suspicious"
        safety = "critical_floor"
    else:
        verdict = "valid"
        safety = None

    result["verdict"] = verdict
    result["gate_code"] = None
    result["safety"] = safety
    return result


# =========================================================
# HEALTH
# =========================================================
def health_status() -> dict:
    return {
        "system": "bayesian_engine",
        "status": "ok",
        "adaptive_available": _ADAPTIVE_AVAILABLE,
        "severity_map": {
            k: {"base_log_odds": v[0], "default_reliability": v[1]}
            for k, v in SEVERITY_LOG_ODDS.items()
        },
        "thresholds": {
            "invalid": INVALID_THRESHOLD,
            "suspicious": SUSPICIOUS_THRESHOLD,
        },
    }


# =========================================================
# SELF-TEST
# =========================================================
def _make_items(*severity_with_code):
    return [
        {"code": code, "severity": sev, "score": 0, "detail": ""}
        for code, sev in severity_with_code
    ]


def run_self_test() -> Tuple[bool, List[str]]:
    results = []
    success = True

    def _chk(cond, ok_msg, fail_msg):
        nonlocal success
        if cond:
            results.append(f"✓ {ok_msg}")
        else:
            results.append(f"✗ {fail_msg}")
            success = False

    # 1: empty → valid
    try:
        r = bayesian_evaluate([], "full")
        _chk(r["verdict"] == "valid" and r["probability"] == 0.5,
             "Test 1: empty items → P=0.5, verdict=valid",
             f"Test 1: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # 2: IMPOSSIBLE → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "impossible")), "full")
        _chk(r["verdict"] == "invalid" and r["probability"] > 0.99,
             "Test 2: single IMPOSSIBLE → invalid, P>0.99",
             f"Test 2: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # 3: CRITICAL → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "critical")), "full")
        _chk(r["verdict"] == "invalid" and r["probability"] >= 0.85,
             "Test 3: single CRITICAL → invalid",
             f"Test 3: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # 4: HIGH → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "high")), "full")
        _chk(r["verdict"] == "invalid" and 0.85 <= r["probability"] < 0.99,
             "Test 4: single HIGH → invalid (P≈0.93)",
             f"Test 4: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # 5: MEDIUM → suspicious
    try:
        r = bayesian_evaluate(_make_items(("X", "medium")), "full")
        _chk(r["verdict"] == "suspicious" and 0.65 <= r["probability"] < 0.85,
             "Test 5: single MEDIUM → suspicious",
             f"Test 5: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # 6: LOW → valid
    try:
        r = bayesian_evaluate(_make_items(("X", "low")), "full")
        _chk(r["verdict"] == "valid" and 0.5 <= r["probability"] < 0.65,
             "Test 6: single LOW → valid",
             f"Test 6: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # 7: 5 LOW → suspicious
    try:
        items = _make_items(("A", "low"), ("B", "low"), ("C", "low"), ("D", "low"), ("E", "low"))
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "suspicious" and 0.65 <= r["probability"] < 0.85,
             "Test 7: 5 LOW → suspicious (not invalid)",
             f"Test 7: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # 8: 3 MEDIUM → invalid
    try:
        items = _make_items(("A", "medium"), ("B", "medium"), ("C", "medium"))
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "invalid",
             "Test 8: 3 MEDIUM → invalid",
             f"Test 8: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # 9: HUMAN + LOW → valid
    try:
        items = _make_items(("HUMAN_X", "human"), ("LOW_X", "low"))
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "valid" and r["probability"] < 0.5,
             "Test 9: 1 HUMAN + 1 LOW → valid",
             f"Test 9: got P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # 10: legacy → unknown
    try:
        r = bayesian_evaluate(_make_items(("X", "critical")), "legacy")
        _chk(r["verdict"] == "unknown" and r["gate_code"] == "DATA_LEGACY",
             "Test 10: legacy quality → unknown",
             f"Test 10: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # 11: partial + no critical → unknown
    try:
        r = bayesian_evaluate(_make_items(("X", "medium")), "partial")
        _chk(r["verdict"] == "unknown",
             "Test 11: partial + no critical → unknown",
             f"Test 11: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # 12: partial + critical → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "critical")), "partial")
        _chk(r["verdict"] == "invalid",
             "Test 12: partial + critical → invalid",
             f"Test 12: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # 13: CRITICAL + many HUMAN → suspicious (safety floor)
    try:
        items = _make_items(
            ("CDP", "critical"),
            ("H1", "human"), ("H2", "human"), ("H3", "human"),
            ("H4", "human"), ("H5", "human"), ("H6", "human"),
        )
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "suspicious" and r["safety"] == "critical_floor",
             "Test 13: CRITICAL + 6 HUMAN → suspicious (safety floor)",
             f"Test 13: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 13: crashed ({e})")

    # 14: IMPOSSIBLE + many HUMAN → still invalid
    try:
        items = _make_items(
            ("WD", "impossible"),
            ("H1", "human"), ("H2", "human"), ("H3", "human"),
            ("H4", "human"), ("H5", "human"), ("H6", "human"),
        )
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "invalid" and r["safety"] == "impossible",
             "Test 14: IMPOSSIBLE + many HUMAN → invalid",
             f"Test 14: got {r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # 15: log_odds summation
    try:
        items = _make_items(("A", "high"), ("B", "low"))
        r = compute_probability(items)
        # Expected: 3.5×0.75 + 0.5×0.35 = 2.625 + 0.175 = 2.8
        _chk(abs(r["log_odds"] - 2.8) < 0.01,
             "Test 15: log_odds summation accurate (2.8)",
             f"Test 15: got {r['log_odds']}")
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # 16: contributions array
    try:
        items = _make_items(("SIG_A", "high"), ("SIG_B", "medium"))
        r = compute_probability(items)
        c = r["contributions"]
        _chk(len(c) == 2 and c[0]["code"] == "SIG_A" and c[1]["severity"] == "medium",
             "Test 16: contributions has per-signal breakdown",
             f"Test 16: got {len(c)}")
    except Exception as e:
        _chk(False, "", f"Test 16: crashed ({e})")

    # 17: unknown severity → medium default
    try:
        items = [{"code": "X", "severity": "garbage", "score": 0, "detail": ""}]
        r = compute_probability(items)
        _chk(r["contributions"][0]["severity"] == "medium",
             "Test 17: unknown severity defaults to medium",
             f"Test 17: got {r['contributions'][0]['severity']}")
    except Exception as e:
        _chk(False, "", f"Test 17: crashed ({e})")

    # 18: HUMAN reduces probability
    try:
        r_alone = compute_probability(_make_items(("X", "low")))
        r_with_human = compute_probability(
            _make_items(("X", "low"), ("H", "human"))
        )
        _chk(r_with_human["probability"] < r_alone["probability"],
             "Test 18: HUMAN signal reduces probability",
             f"Test 18: alone={r_alone['probability']}, with={r_with_human['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 18: crashed ({e})")

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 2: BAYESIAN ENGINE — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 2] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 2 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 2] Bayesian engine self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 2 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 2] {r}")

    print("=" * 70 + "\n")
    return ok


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
        print(f"⚠️  [SYSTEM 2] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False