"""
collector/verdict_engine.py — SYSTEM 3: Confidence-tiered Verdict

Self-contained logic + 18 self-tests run on import.

Extends System 2's 4-tier verdict into 6 tiers:
  - CONFIRMED_BOT   → block + log
  - LIKELY_BOT      → block + alert
  - SUSPICIOUS      → redirect with warning
  - INSUFFICIENT_DATA → redirect (data missing)
  - LIKELY_VALID    → redirect
  - CONFIRMED_HUMAN → redirect + whitelist

Fixes:
  - Problem 36: impossible recognized BEFORE data_quality gate
  - Problem 37: confidence from probability, not sum
  - Problem 41: verdict from probability, not score sum
  - Problem 51: suspicious threshold 0.60 instead of score=40

Backward compatible: legacy 4-tier verdict derived via mapping.
"""
import os
import sys
import logging
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple

logger = logging.getLogger("ovg.verdict")


# =========================================================
# 6-TIER VERDICT
# =========================================================
class VerdictV2(str, Enum):
    CONFIRMED_BOT = "confirmed_bot"
    LIKELY_BOT = "likely_bot"
    SUSPICIOUS = "suspicious"
    INSUFFICIENT_DATA = "insufficient_data"
    LIKELY_VALID = "likely_valid"
    CONFIRMED_HUMAN = "confirmed_human"


# Thresholds (spec)
BOT_CONFIRM_THRESHOLD = 0.995
BOT_LIKELY_THRESHOLD = 0.90
SUSPICIOUS_THRESHOLD_V2 = 0.60
HUMAN_CONFIRM_THRESHOLD = 0.30


# =========================================================
# LEGACY MAPPING
# =========================================================
_VERDICT_TO_LEGACY = {
    VerdictV2.CONFIRMED_BOT: "invalid",
    VerdictV2.LIKELY_BOT: "invalid",
    VerdictV2.SUSPICIOUS: "suspicious",
    VerdictV2.INSUFFICIENT_DATA: "unknown",
    VerdictV2.LIKELY_VALID: "valid",
    VerdictV2.CONFIRMED_HUMAN: "valid",
}


_VERDICT_METADATA = {
    VerdictV2.CONFIRMED_BOT: {
        "legacy": "invalid",
        "action": "block",
        "color": "#F43F5E",
        "severity": "critical",
        "label_ar": "بوت مؤكد",
        "label_en": "Confirmed Bot",
    },
    VerdictV2.LIKELY_BOT: {
        "legacy": "invalid",
        "action": "block_alert",
        "color": "#F43F5E",
        "severity": "high",
        "label_ar": "بوت شبه مؤكد",
        "label_en": "Likely Bot",
    },
    VerdictV2.SUSPICIOUS: {
        "legacy": "suspicious",
        "action": "redirect_warning",
        "color": "#F59E0B",
        "severity": "medium",
        "label_ar": "مريب",
        "label_en": "Suspicious",
    },
    VerdictV2.INSUFFICIENT_DATA: {
        "legacy": "unknown",
        "action": "redirect",
        "color": "#7B8496",
        "severity": "low",
        "label_ar": "بيانات ناقصة",
        "label_en": "Insufficient Data",
    },
    VerdictV2.LIKELY_VALID: {
        "legacy": "valid",
        "action": "redirect",
        "color": "#10B981",
        "severity": "low",
        "label_ar": "يرجح سليم",
        "label_en": "Likely Valid",
    },
    VerdictV2.CONFIRMED_HUMAN: {
        "legacy": "valid",
        "action": "redirect_whitelist",
        "color": "#22D3EE",
        "severity": "none",
        "label_ar": "سليم مؤكد",
        "label_en": "Confirmed Human",
    },
}


def to_legacy_verdict(verdict_v2) -> str:
    """Map 6-tier verdict to legacy 4-tier string."""
    if isinstance(verdict_v2, str):
        try:
            verdict_v2 = VerdictV2(verdict_v2)
        except ValueError:
            return "unknown"
    return _VERDICT_TO_LEGACY.get(verdict_v2, "unknown")


def verdict_metadata(verdict_v2) -> dict:
    """Get UI metadata for a verdict."""
    if isinstance(verdict_v2, str):
        try:
            verdict_v2 = VerdictV2(verdict_v2)
        except ValueError:
            verdict_v2 = VerdictV2.INSUFFICIENT_DATA
    return dict(_VERDICT_METADATA.get(
        verdict_v2, _VERDICT_METADATA[VerdictV2.INSUFFICIENT_DATA]
    ))


# =========================================================
# SIGNAL DETECTION
# =========================================================
def _detect_signals(items: List[dict]) -> dict:
    """Detect which signal types are present (fast pass)."""
    has_impossible = False
    has_critical = False
    has_human = False

    for item in items:
        if not isinstance(item, dict):
            continue
        sev = (item.get("severity") or "").lower()
        if sev == "impossible":
            has_impossible = True
        elif sev == "critical":
            has_critical = True
        elif sev == "human":
            has_human = True

    return {
        "impossible": has_impossible,
        "critical": has_critical,
        "human": has_human,
        "hard": has_impossible or has_critical,
    }


# =========================================================
# MAIN CLASSIFIER
# =========================================================
def classify_verdict_v2(
    items: List[dict],
    data_quality: str = "full",
    probability: Optional[float] = None,
) -> dict:
    """
    Classify visit into 6-tier verdict.

    Priority order:
      1. IMPOSSIBLE signal → CONFIRMED_BOT (overrides data_quality gate)
      2. data_quality legacy/failed → INSUFFICIENT_DATA
      3. data_quality partial + no hard signal → INSUFFICIENT_DATA
      4. P >= 0.90 → LIKELY_BOT
      5. CRITICAL floor → at least SUSPICIOUS
      6. P >= 0.60 → SUSPICIOUS
      7. P < 0.30 + human signal → CONFIRMED_HUMAN
      8. Otherwise → LIKELY_VALID

    Returns:
        {
            "verdict": VerdictV2,
            "probability": float,
            "safety": str | None,
            "gate_code": str | None,
        }
    """
    if probability is None:
        from collector.bayesian_engine import compute_probability
        probability = compute_probability(items)["probability"]

    signals = _detect_signals(items)

    # 1) IMPOSSIBLE overrides everything (even bad data_quality)
    if signals["impossible"]:
        return {
            "verdict": VerdictV2.CONFIRMED_BOT,
            "probability": probability,
            "safety": "impossible",
            "gate_code": None,
        }

    # 2) Data quality gate
    dq = (data_quality or "unknown").lower()
    if dq in ("legacy", "failed"):
        gate = "DATA_LEGACY" if dq == "legacy" else "DATA_INSUFFICIENT"
        return {
            "verdict": VerdictV2.INSUFFICIENT_DATA,
            "probability": probability,
            "safety": None,
            "gate_code": gate,
        }

    if dq == "partial" and not signals["hard"]:
        return {
            "verdict": VerdictV2.INSUFFICIENT_DATA,
            "probability": probability,
            "safety": None,
            "gate_code": "DATA_INSUFFICIENT",
        }

    # 3) Probability tiers
    if probability >= BOT_LIKELY_THRESHOLD:
        return {
            "verdict": VerdictV2.LIKELY_BOT,
            "probability": probability,
            "safety": None,
            "gate_code": None,
        }

    # 4) CRITICAL floor: even low P → SUSPICIOUS (never VALID)
    if signals["critical"]:
        return {
            "verdict": VerdictV2.SUSPICIOUS,
            "probability": probability,
            "safety": "critical_floor",
            "gate_code": None,
        }

    if probability >= SUSPICIOUS_THRESHOLD_V2:
        return {
            "verdict": VerdictV2.SUSPICIOUS,
            "probability": probability,
            "safety": None,
            "gate_code": None,
        }

    # 5) Human signals → CONFIRMED_HUMAN (if P < 0.30)
    if probability < HUMAN_CONFIRM_THRESHOLD and signals["human"]:
        return {
            "verdict": VerdictV2.CONFIRMED_HUMAN,
            "probability": probability,
            "safety": None,
            "gate_code": None,
        }

    # 6) Default
    return {
        "verdict": VerdictV2.LIKELY_VALID,
        "probability": probability,
        "safety": None,
        "gate_code": None,
    }


# =========================================================
# HEALTH
# =========================================================
def health_status() -> dict:
    return {
        "system": "verdict_engine",
        "status": "ok",
        "thresholds": {
            "bot_confirm": BOT_CONFIRM_THRESHOLD,
            "bot_likely": BOT_LIKELY_THRESHOLD,
            "suspicious": SUSPICIOUS_THRESHOLD_V2,
            "human_confirm": HUMAN_CONFIRM_THRESHOLD,
        },
        "verdicts": [v.value for v in VerdictV2],
    }


# =========================================================
# SELF-TEST
# =========================================================
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

    def _classify(*severity_pairs, dq="full", prob=None):
        items = [
            {"code": c, "severity": s, "score": 0, "detail": ""}
            for c, s in severity_pairs
        ]
        return classify_verdict_v2(items, data_quality=dq, probability=prob)

    # Test 1: empty + full → LIKELY_VALID
    try:
        r = _classify(dq="full")
        _chk(r["verdict"] == VerdictV2.LIKELY_VALID and r["probability"] == 0.5,
             "Test 1: empty + full → LIKELY_VALID (P=0.5)",
             f"Test 1: got {r['verdict'].value}, P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 1: crashed ({e})")

    # Test 2: IMPOSSIBLE → CONFIRMED_BOT
    try:
        r = _classify(("X", "impossible"), dq="full")
        _chk(r["verdict"] == VerdictV2.CONFIRMED_BOT and r["safety"] == "impossible",
             "Test 2: IMPOSSIBLE → CONFIRMED_BOT",
             f"Test 2: got {r['verdict'].value}, safety={r['safety']}")
    except Exception as e:
        _chk(False, "", f"Test 2: crashed ({e})")

    # Test 3: IMPOSSIBLE overrides bad data_quality
    try:
        r = _classify(("X", "impossible"), dq="legacy")
        _chk(r["verdict"] == VerdictV2.CONFIRMED_BOT,
             "Test 3: IMPOSSIBLE overrides legacy quality",
             f"Test 3: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 3: crashed ({e})")

    # Test 4: single CRITICAL → LIKELY_BOT (P≈0.995)
    try:
        r = _classify(("X", "critical"), dq="full")
        _chk(r["verdict"] == VerdictV2.LIKELY_BOT and r["probability"] > 0.99,
             "Test 4: single CRITICAL → LIKELY_BOT",
             f"Test 4: got {r['verdict'].value}, P={r['probability']}")
    except Exception as e:
        _chk(False, "", f"Test 4: crashed ({e})")

    # Test 5: P=0.92 → LIKELY_BOT
    try:
        r = _classify(dq="full", prob=0.92)
        _chk(r["verdict"] == VerdictV2.LIKELY_BOT,
             "Test 5: P=0.92 → LIKELY_BOT",
             f"Test 5: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 5: crashed ({e})")

    # Test 6: P=0.75 → SUSPICIOUS
    try:
        r = _classify(dq="full", prob=0.75)
        _chk(r["verdict"] == VerdictV2.SUSPICIOUS,
             "Test 6: P=0.75 → SUSPICIOUS",
             f"Test 6: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 6: crashed ({e})")

    # Test 7: P=0.45 no human → LIKELY_VALID
    try:
        r = _classify(dq="full", prob=0.45)
        _chk(r["verdict"] == VerdictV2.LIKELY_VALID,
             "Test 7: P=0.45 no human → LIKELY_VALID",
             f"Test 7: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 7: crashed ({e})")

    # Test 8: P=0.15 + HUMAN → CONFIRMED_HUMAN
    try:
        r = _classify(("H", "human"), dq="full", prob=0.15)
        _chk(r["verdict"] == VerdictV2.CONFIRMED_HUMAN,
             "Test 8: P=0.15 + HUMAN → CONFIRMED_HUMAN",
             f"Test 8: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 8: crashed ({e})")

    # Test 9: P=0.15 no human → LIKELY_VALID
    try:
        r = _classify(dq="full", prob=0.15)
        _chk(r["verdict"] == VerdictV2.LIKELY_VALID,
             "Test 9: P=0.15 no human → LIKELY_VALID",
             f"Test 9: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 9: crashed ({e})")

    # Test 10: legacy quality → INSUFFICIENT_DATA
    try:
        r = _classify(("X", "low"), dq="legacy")
        _chk(r["verdict"] == VerdictV2.INSUFFICIENT_DATA and r["gate_code"] == "DATA_LEGACY",
             "Test 10: legacy quality → INSUFFICIENT_DATA (DATA_LEGACY)",
             f"Test 10: got {r['verdict'].value}, gate={r['gate_code']}")
    except Exception as e:
        _chk(False, "", f"Test 10: crashed ({e})")

    # Test 11: failed quality → INSUFFICIENT_DATA
    try:
        r = _classify(("X", "low"), dq="failed")
        _chk(r["verdict"] == VerdictV2.INSUFFICIENT_DATA,
             "Test 11: failed quality → INSUFFICIENT_DATA",
             f"Test 11: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 11: crashed ({e})")

    # Test 12: partial + no critical → INSUFFICIENT_DATA
    try:
        r = _classify(("X", "medium"), dq="partial")
        _chk(r["verdict"] == VerdictV2.INSUFFICIENT_DATA,
             "Test 12: partial + no critical → INSUFFICIENT_DATA",
             f"Test 12: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 12: crashed ({e})")

    # Test 13: partial + critical → bot tier (not gated)
    try:
        r = _classify(("X", "critical"), dq="partial")
        _chk(r["verdict"] in (VerdictV2.LIKELY_BOT, VerdictV2.CONFIRMED_BOT),
             "Test 13: partial + critical → LIKELY_BOT (bypasses gate)",
             f"Test 13: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 13: crashed ({e})")

    # Test 14: legacy mapping for all 6
    try:
        mappings = [
            (VerdictV2.CONFIRMED_BOT, "invalid"),
            (VerdictV2.LIKELY_BOT, "invalid"),
            (VerdictV2.SUSPICIOUS, "suspicious"),
            (VerdictV2.INSUFFICIENT_DATA, "unknown"),
            (VerdictV2.LIKELY_VALID, "valid"),
            (VerdictV2.CONFIRMED_HUMAN, "valid"),
        ]
        all_ok = all(to_legacy_verdict(v) == exp for v, exp in mappings)
        _chk(all_ok, "Test 14: legacy mapping correct for all 6 tiers",
             f"Test 14: mapping mismatch")
    except Exception as e:
        _chk(False, "", f"Test 14: crashed ({e})")

    # Test 15: metadata complete for all 6
    try:
        required = {"legacy", "action", "color", "severity", "label_ar", "label_en"}
        all_ok = all(required.issubset(verdict_metadata(v).keys()) for v in VerdictV2)
        _chk(all_ok, "Test 15: metadata complete for all 6 tiers",
             "Test 15: metadata missing keys")
    except Exception as e:
        _chk(False, "", f"Test 15: crashed ({e})")

    # Test 16: boundary P=0.90 → LIKELY_BOT
    try:
        r = _classify(dq="full", prob=0.90)
        _chk(r["verdict"] == VerdictV2.LIKELY_BOT,
             "Test 16: boundary P=0.90 → LIKELY_BOT",
             f"Test 16: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 16: crashed ({e})")

    # Test 17: boundary P=0.60 → SUSPICIOUS
    try:
        r = _classify(dq="full", prob=0.60)
        _chk(r["verdict"] == VerdictV2.SUSPICIOUS,
             "Test 17: boundary P=0.60 → SUSPICIOUS",
             f"Test 17: got {r['verdict'].value}")
    except Exception as e:
        _chk(False, "", f"Test 17: crashed ({e})")

    # Test 18: CRITICAL floor overrides low P
    try:
        r = _classify(("C", "critical"), dq="full", prob=0.20)
        _chk(r["verdict"] == VerdictV2.SUSPICIOUS and r["safety"] == "critical_floor",
             "Test 18: CRITICAL floor overrides low P",
             f"Test 18: got {r['verdict'].value}, safety={r['safety']}")
    except Exception as e:
        _chk(False, "", f"Test 18: crashed ({e})")

    return success, results


def print_self_test():
    print("\n" + "=" * 70)
    print("  SYSTEM 3: VERDICT ENGINE — SELF TEST")
    print("=" * 70)

    try:
        ok, results = run_self_test()
    except Exception as e:
        logger.exception(f"[SYSTEM 3] self-test crashed: {e}")
        print(f"  ✗ Self-test crashed: {e}")
        print("=" * 70 + "\n")
        return False

    for r in results:
        print(f"  {r}")

    print("-" * 70)
    passed = sum(1 for r in results if r.startswith("✓"))
    total = len(results)

    if ok:
        print(f"  ✅ SYSTEM 3 PASSED — {passed}/{total} tests")
        logger.info(f"[SYSTEM 3] Verdict engine self-test PASSED ({passed}/{total})")
    else:
        print(f"  ❌ SYSTEM 3 FAILED — {passed}/{total} passed")
        for r in results:
            if r.startswith("✗"):
                logger.error(f"[SYSTEM 3] {r}")
        logger.error("[SYSTEM 3] Verdict engine self-test FAILED")

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
        print(f"⚠️  [SYSTEM 3] self-test crashed at import: {e}")
        _SELF_TEST_PASSED = False
