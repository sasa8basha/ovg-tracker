"""
collector/bayesian_engine.py — SYSTEM 2: Bayesian Evidence Engine

Self-contained. No dependencies on project files.

Replaces naive score-summing with probabilistic inference:
  - Each signal has base_log_odds (theoretical weight)
  - Each signal has reliability (0-1, from ground truth)
  - effective_log_odds = base_log_odds × reliability
  - Total log_odds → convert to probability via sigmoid
  - Verdict based on probability thresholds, not raw sum

Solves:
  - Verdict by sum wrong (5 weak signals should NOT equal 1 strong signal)
  - "impossible" severity not recognized
  - Raw score not exposed
  - Reliability of each signal tracked separately

Auto-runs 18 self-tests on import. Prints results to server log.
"""
import os
import sys
import math
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("ovg.bayesian")


# =========================================================
# SEVERITY → LOG-ODDS MAPPING
# =========================================================
# (base_log_odds, default_reliability)
#
# Probability interpretation:
#   log_odds = 0.0  → P = 0.50
#   log_odds = 0.4  → P = 0.60
#   log_odds = 2.2  → P = 0.90
#   log_odds = 4.6  → P = 0.99
#
# Calibration (verified against old score thresholds):
#   - Single HIGH (log_odds≈2.6, P≈0.93) → invalid (old: score 60-90)
#   - Single MEDIUM (log_odds≈0.8, P≈0.70) → suspicious (old: score 40-50)
#   - Single LOW (log_odds≈0.2, P≈0.54) → valid (old: score 15)
#   - 5 LOW (log_odds≈0.88, P≈0.71) → suspicious (old: score 75)
#   - 3 MEDIUM (log_odds≈2.5, P≈0.92) → invalid (old: score 120+)

SEVERITY_LOG_ODDS = {
    "impossible": (8.0, 0.98),
    "critical":   (6.0, 0.90),
    "high":       (3.5, 0.75),
    "medium":     (1.5, 0.55),
    "low":        (0.5, 0.35),
    "human":      (-1.5, 0.60),
}

# Verdict thresholds on probability
INVALID_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.65


# =========================================================
# SIGNAL DATACLASS
# =========================================================
@dataclass
class Signal:
    """Represents one piece of evidence."""
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
    rel = reliability_override if reliability_override is not None else default_rel

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
    """
    Compute the Bayesian probability that a visit is a bot.

    Args:
        items: list of evidence dicts, each with {code, severity, score, detail}

    Returns:
        {
            "probability": float (0-1),
            "log_odds": float,
            "confidence": float (0-1),
            "contributions": [list of per-signal contributions],
            "signal_count": int,
        }
    """
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

    # Convert log-odds → probability (sigmoid)
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
# VERDICT EVALUATION (WITH SAFETY RULES)
# =========================================================
def bayesian_evaluate(items: List[dict], data_quality: str = "full") -> Dict[str, Any]:
    """
    Full Bayesian evaluation:
      1. Data quality gate (legacy/failed → unknown)
      2. Compute probability from log-odds
      3. Safety rules:
         - IMPOSSIBLE signal → invalid (regardless of prob)
         - CRITICAL signal + Bayesian says valid → suspicious (floor)
      4. Verdict based on probability thresholds

    Returns:
        {
            "verdict": "valid" | "suspicious" | "invalid" | "unknown",
            "probability": float,
            "log_odds": float,
            "confidence": float,
            "contributions": [...],
            "signal_count": int,
            "gate_code": str | None,
            "safety": str | None,
        }
    """
    dq = (data_quality or "unknown").lower()

    # --- Detect severities present ---
    has_critical = any(
        isinstance(e, dict) and e.get("severity") in ("critical", "impossible")
        for e in items
    )
    has_impossible = any(
        isinstance(e, dict) and e.get("severity") == "impossible"
        for e in items
    )

    # --- Data quality gate ---
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

    # --- Compute probability ---
    result = compute_probability(items)
    p = result["probability"]

    # --- Safety rule 1: IMPOSSIBLE → always invalid ---
    if has_impossible:
        result["verdict"] = "invalid"
        result["gate_code"] = None
        result["safety"] = "impossible"
        return result

    # --- Bayesian verdict + critical floor ---
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
def _make_items(*severities_with_code):
    return [
        {"code": code, "severity": sev, "score": 0, "detail": ""}
        for code, sev in severities_with_code
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

    # 1: empty items → valid
    try:
        r = bayesian_evaluate([], "full")
        _chk(r["verdict"] == "valid" and r["probability"] == 0.5,
             "Test 1: empty items → P=0.5, verdict=valid",
             f"Test 1: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # 2: single IMPOSSIBLE → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "impossible")), "full")
        _chk(r["verdict"] == "invalid" and r["probability"] > 0.99,
             "Test 2: single IMPOSSIBLE → invalid, P>0.99",
             f"Test 2: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # 3: single CRITICAL → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "critical")), "full")
        _chk(r["verdict"] == "invalid" and r["probability"] >= 0.85,
             "Test 3: single CRITICAL → invalid",
             f"Test 3: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # 4: single HIGH → invalid (P≈0.93)
    try:
        r = bayesian_evaluate(_make_items(("X", "high")), "full")
        _chk(r["verdict"] == "invalid" and 0.85 <= r["probability"] < 0.99,
             "Test 4: single HIGH → invalid (P≈0.93)",
             f"Test 4: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # 5: single MEDIUM → suspicious (P≈0.70)
    try:
        r = bayesian_evaluate(_make_items(("X", "medium")), "full")
        _chk(r["verdict"] == "suspicious" and 0.65 <= r["probability"] < 0.85,
             "Test 5: single MEDIUM → suspicious (P≈0.70)",
             f"Test 5: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # 6: single LOW → valid (P≈0.54)
    try:
        r = bayesian_evaluate(_make_items(("X", "low")), "full")
        _chk(r["verdict"] == "valid" and 0.5 <= r["probability"] < 0.65,
             "Test 6: single LOW → valid (P≈0.54)",
             f"Test 6: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # 7: 5 LOW → suspicious (old would be invalid!)
    try:
        items = _make_items(
            ("A", "low"), ("B", "low"), ("C", "low"), ("D", "low"), ("E", "low"),
        )
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "suspicious" and 0.65 <= r["probability"] < 0.85,
             "Test 7: 5 LOW → suspicious (old=invalid, fixed!)",
             f"Test 7: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # 8: 3 MEDIUM → invalid
    try:
        items = _make_items(("A", "medium"), ("B", "medium"), ("C", "medium"))
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "invalid" and r["probability"] >= 0.85,
             "Test 8: 3 MEDIUM → invalid (P≈0.92)",
             f"Test 8: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # 9: 1 HUMAN + 1 LOW → valid
    try:
        items = _make_items(("HUMAN_X", "human"), ("LOW_X", "low"))
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "valid" and r["probability"] < 0.5,
             "Test 9: 1 HUMAN + 1 LOW → valid (P≈0.33)",
             f"Test 9: got P={r['probability']}, verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # 10: legacy → unknown
    try:
        r = bayesian_evaluate(_make_items(("X", "critical")), "legacy")
        _chk(r["verdict"] == "unknown" and r["gate_code"] == "DATA_LEGACY",
             "Test 10: legacy quality → unknown",
             f"Test 10: got verdict={r['verdict']}, gate={r['gate_code']}")
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # 11: partial + no critical → unknown
    try:
        r = bayesian_evaluate(_make_items(("X", "medium")), "partial")
        _chk(r["verdict"] == "unknown" and r["gate_code"] == "DATA_INSUFFICIENT",
             "Test 11: partial + no critical → unknown",
             f"Test 11: got verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # 12: partial + critical → invalid
    try:
        r = bayesian_evaluate(_make_items(("X", "critical")), "partial")
        _chk(r["verdict"] == "invalid",
             "Test 12: partial + critical → invalid",
             f"Test 12: got verdict={r['verdict']}")
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # 13: CRITICAL + 6 HUMAN → suspicious (safety floor)
    try:
        items = _make_items(
            ("CDP", "critical"),
            ("H1", "human"), ("H2", "human"), ("H3", "human"),
            ("H4", "human"), ("H5", "human"), ("H6", "human"),
        )
        r = bayesian_evaluate(items, "full")
        _chk(r["verdict"] == "suspicious" and r["safety"] == "critical_floor",
             "Test 13: CRITICAL + 6 HUMAN → suspicious (safety floor)",
             f"Test 13: got verdict={r['verdict']}, safety={r['safety']}")
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
             "Test 14: IMPOSSIBLE + many HUMAN → invalid (impossible overrides)",
             f"Test 14: got verdict={r['verdict']}, safety={r['safety']}")
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # 15: log_odds summation accuracy
    try:
        items = _make_items(("A", "high"), ("B", "low"))
        r = compute_probability(items)
        # Expected: 3.5×0.75 + 0.5×0.35 = 2.625 + 0.175 = 2.8
        _chk(abs(r["log_odds"] - 2.8) < 0.01,
             "Test 15: log_odds summation accurate (2.8)",
             f"Test 15: expected 2.8, got {r['log_odds']}")
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # 16: contributions array correctness
    try:
        items = _make_items(("SIG_A", "high"), ("SIG_B", "medium"))
        r = compute_probability(items)
        c = r["contributions"]
        _chk(len(c) == 2 and c[0]["code"] == "SIG_A" and c[1]["severity"] == "medium",
             "Test 16: contributions array has per-signal breakdown",
             f"Test 16: got {c}")
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

    # 18: HUMAN signal reduces probability
    try:
        r_alone = compute_probability(_make_items(("X", "low")))
        r_with_human = compute_probability(
            _make_items(("X", "low"), ("H", "human"))
        )
        _chk(r_with_human["probability"] < r_alone["probability"],
             "Test 18: HUMAN signal reduces probability",
             f"Test 18: alone={r_alone['probability']}, with_human={r_with_human['probability']}")
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
        logger.error("[SYSTEM 2] Bayesian engine self-test FAILED")

    print("=" * 70 + "\n")
    return ok


# =========================================================
# AUTO-RUN ON IMPORT
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
        print(f"⚠️  [SYSTEM 2] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False
