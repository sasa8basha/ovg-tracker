"""
collector/data_quality.py — Data Completeness & Reliability Layer.

Philosophy:
    A verdict is only as trustworthy as the data behind it.
    A weak dataset MUST cap our confidence — no matter how many
    signals fired. This module is the guardrail against false precision.

Responsibilities:
    1. Inspect the merged payload for structural completeness.
    2. Estimate reliability (not just presence, but quality).
    3. Assign a discrete level (full / good / partial / poor / failed / legacy).
    4. Provide `max_confidence_cap` so the decision layer can never
       claim more confidence than the data allows.

Pure module — no DB, no network, no side effects.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


# =========================================================
# LEVELS
# =========================================================
LEVEL_FULL = "full"
LEVEL_GOOD = "good"
LEVEL_PARTIAL = "partial"
LEVEL_POOR = "poor"
LEVEL_FAILED = "failed"
LEVEL_LEGACY = "legacy"

VALID_LEVELS = frozenset([
    LEVEL_FULL, LEVEL_GOOD, LEVEL_PARTIAL,
    LEVEL_POOR, LEVEL_FAILED, LEVEL_LEGACY,
])

# Even a perfect signal set MUST NOT report confidence above this ceiling.
MAX_CONFIDENCE_BY_LEVEL = {
    LEVEL_FULL:    0.96,
    LEVEL_GOOD:    0.92,  # M-29: was 0.87 impossible to reach with partial
    LEVEL_PARTIAL: 0.71,
    LEVEL_POOR:    0.50,
    LEVEL_FAILED:  0.30,
    LEVEL_LEGACY:  0.40,
}

# Whether the decision layer is allowed to emit a definitive verdict.
# When False → decision layer returns "unknown" (unless has_impossible).
CAN_DECIDE_BY_LEVEL = {
    LEVEL_FULL:    True,
    LEVEL_GOOD:    True,
    LEVEL_PARTIAL: True,    # allowed, but with capped confidence
    LEVEL_POOR:    False,
    LEVEL_FAILED:  False,
    LEVEL_LEGACY:  False,
}


# =========================================================
# REPORT DATACLASS
# =========================================================
@dataclass
class DataQualityReport:
    level: str = LEVEL_FAILED
    completeness: float = 0.0           # 0..1 — how much data we have
    reliability: float = 0.0            # 0..1 — how much we trust it
    can_decide: bool = False
    max_confidence_cap: float = 0.30
    duration_ms: int = 0
    mouse_points: int = 0
    total_events: int = 0
    heartbeats: int = 0
    missing: List[str] = field(default_factory=list)
    weak: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================
# SAFE ACCESSORS
# =========================================================
def _safe_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _safe_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def _duration_ms(behavior: dict) -> int:
    if not behavior:
        return 0
    t = _safe_int(behavior.get("time_on_page_ms"), 0)
    if t == 0:
        t = _safe_int(behavior.get("total_time_ms"), 0)
    return max(0, t)


def _mouse_points_count(behavior: dict) -> int:
    if not behavior:
        return 0
    ma = _safe_dict(behavior.get("mouse_analysis"))
    if not ma.get("too_few", True):
        n = _safe_int(ma.get("total_points"), 0)
        if n > 0:
            return n
    return len(_safe_list(behavior.get("mouse_points")))


def _total_events(behavior: dict) -> int:
    if not behavior:
        return 0
    ev = _safe_dict(behavior.get("events"))
    if ev:
        return (
            _safe_int(ev.get("mousemove"), 0)
            + _safe_int(ev.get("clicks"), 0)
            + _safe_int(ev.get("scrolls"), 0)
            + _safe_int(ev.get("touchstart"), 0)
            + _safe_int(ev.get("keydown"), 0)
        )
    return _mouse_points_count(behavior)


# =========================================================
# CORE EVALUATOR
# =========================================================
def evaluate_data_quality(data: dict) -> DataQualityReport:
    """
    Inspect the merged visit payload and produce a DataQualityReport.

    `data` uses the same schema that `analyze_full` receives:
        {
            "nav": {...},
            "fingerprint": {...},
            "behavior": {...},
            "screen": {...},
            "_data_quality": "full" | "partial" | "legacy" | ...,
            "_heartbeat_count": int,
            ...
        }
    """
    report = DataQualityReport()

    if not isinstance(data, dict):
        report.reasons.append("payload_not_dict")
        return report

    declared = str(data.get("_data_quality") or "").lower().strip()

    # ---------- legacy short-circuit ----------
    if declared == LEVEL_LEGACY:
        report.level = LEVEL_LEGACY
        report.can_decide = CAN_DECIDE_BY_LEVEL[LEVEL_LEGACY]
        report.max_confidence_cap = MAX_CONFIDENCE_BY_LEVEL[LEVEL_LEGACY]
        report.reasons.append("declared_legacy")
        return report

    nav = _safe_dict(data.get("nav"))
    fp = _safe_dict(data.get("fingerprint"))
    behavior = _safe_dict(data.get("behavior"))
    screen = _safe_dict(data.get("screen"))

    has_nav = bool(nav.get("ua"))
    has_fp = bool(fp.get("canvas_hash") or fp.get("webgl") or fp.get("timezone"))
    has_screen = bool(screen.get("width") and screen.get("height"))
    has_behavior = bool(behavior) and (_duration_ms(behavior) > 0 or _mouse_points_count(behavior) > 0 or bool(behavior.get('scroll_pattern')))  # M-28

    duration_ms = _duration_ms(behavior)
    mouse_points = _mouse_points_count(behavior)
    events = _total_events(behavior)
    heartbeats = _safe_int(data.get("_heartbeat_count"), 0)

    report.duration_ms = duration_ms
    report.mouse_points = mouse_points
    report.total_events = events
    report.heartbeats = heartbeats

    if not has_nav:
        report.missing.append("nav.ua")
    if not has_fp:
        report.missing.append("fingerprint.core")
    if not has_screen:
        report.missing.append("screen")
    if not has_behavior:
        report.missing.append("behavior")

    # ---------- reliability scoring ----------
    pts = 0.0
    max_pts = 0.0

    # 1) Nav (weight 0.15)
    max_pts += 0.15
    if has_nav and nav.get("platform") and nav.get("language"):
        pts += 0.15
    elif has_nav:
        pts += 0.08
        report.weak.append("nav.partial")

    # 2) Fingerprint (weight 0.20)
    max_pts += 0.20
    if has_fp:
        parts = 0
        ch = fp.get("canvas_hash")
        if ch and ch != "blocked":
            parts += 1
        if fp.get("webgl"):
            parts += 1
        tz = fp.get("timezone")
        if tz and tz != "Unknown":
            parts += 1
        if fp.get("hardwareConcurrency"):
            parts += 1
        if fp.get("deviceMemory"):
            parts += 1
        pts += 0.20 * (parts / 5.0)
        if parts < 3:
            report.weak.append("fingerprint.sparse")

    # 3) Screen (weight 0.05)
    max_pts += 0.05
    if has_screen:
        pts += 0.05
    else:
        report.weak.append("screen.missing")

    # 4) Behavior depth (weight 0.35)
    max_pts += 0.35
    if has_behavior:
        # Duration
        if duration_ms >= 5000:
            pts += 0.12
        elif duration_ms >= 3000:
            pts += 0.08
        elif duration_ms >= 1000:
            pts += 0.03
        else:
            report.weak.append("behavior.duration_too_short")

        # Mouse points
        if mouse_points >= 30:
            pts += 0.12
        elif mouse_points >= 10:
            pts += 0.08
        elif mouse_points >= 3:
            pts += 0.03
        else:
            report.weak.append("behavior.mouse_points_low")

        # Events
        if events >= 30:
            pts += 0.11
        elif events >= 10:
            pts += 0.07
        elif events >= 3:
            pts += 0.03
        else:
            report.weak.append("behavior.events_low")

    # 5) Heartbeats (weight 0.15, v3 only)
    max_pts += 0.15
    if declared in (LEVEL_FULL, LEVEL_PARTIAL):
        if heartbeats >= 3:
            pts += 0.15
        elif heartbeats >= 1:
            pts += 0.10
        elif duration_ms >= 10000:
            pts += 0.02
            report.weak.append("behavior.no_heartbeats")
        else:
            report.weak.append("behavior.no_heartbeats_short")

    # 6) Rich interaction bonus (weight 0.10)
    max_pts += 0.10
    if has_behavior:
        rich = (
            (mouse_points >= 20 and duration_ms >= 3000)
            or (events >= 20 and duration_ms >= 2000)
        )
        if rich:
            pts += 0.10
        elif mouse_points >= 10:
            pts += 0.05

    completeness = (pts / max_pts) if max_pts > 0 else 0.0
    report.completeness = round(min(1.0, max(0.0, completeness)), 3)
    report.reliability = report.completeness  # unified scale for now

    # ---------- level assignment ----------
    # Priority: quantitative strength → declared → downgrade on gaps
    score = report.completeness

    # Absolute floor
    if not has_nav and not has_fp:
        report.level = LEVEL_FAILED
        report.reasons.append("no_nav_no_fp")
        report.can_decide = False
        report.max_confidence_cap = MAX_CONFIDENCE_BY_LEVEL[LEVEL_FAILED]
        return report

    if duration_ms < 800 and events < 3:
        report.level = LEVEL_FAILED
        report.reasons.append("no_meaningful_session")
        report.can_decide = False
        report.max_confidence_cap = MAX_CONFIDENCE_BY_LEVEL[LEVEL_FAILED]
        return report

    # Declared vs measured — take the MINIMUM (never trust declarations
    # that overstate quality)
    declared_cap = None
    if declared == LEVEL_FULL:
        declared_cap = LEVEL_FULL
    elif declared in (LEVEL_PARTIAL, LEVEL_POOR):
        declared_cap = declared

    # Score-driven classification
    if score >= 0.85 and has_nav and has_fp and has_behavior:
        measured = LEVEL_FULL
    elif score >= 0.65 and has_nav and has_fp:
        measured = LEVEL_GOOD
    elif score >= 0.40:
        measured = LEVEL_PARTIAL
    elif score >= 0.20:
        measured = LEVEL_POOR
    else:
        measured = LEVEL_FAILED

    # Downgrade to declared if declared is weaker
    order = [LEVEL_FULL, LEVEL_GOOD, LEVEL_PARTIAL, LEVEL_POOR, LEVEL_FAILED]
    final = measured
    if declared_cap and order.index(declared_cap) > order.index(measured):
        final = declared_cap
        report.reasons.append(f"downgraded_to_{declared_cap}")

    # Extra guardrails — even strong data can't claim "full" without heartbeats
    if final == LEVEL_FULL and heartbeats < 2 and duration_ms > 8000:
        final = LEVEL_GOOD
        report.weak.append("full_without_heartbeats")

    # Zero mouse with long session on desktop-like data → downgrade
    if has_behavior and duration_ms >= 8000 and mouse_points == 0 and events == 0:
        if final in (LEVEL_FULL, LEVEL_GOOD):
            final = LEVEL_PARTIAL
            report.weak.append("no_interaction_long_session")

    report.level = final
    report.can_decide = CAN_DECIDE_BY_LEVEL.get(final, False)
    report.max_confidence_cap = MAX_CONFIDENCE_BY_LEVEL.get(final, 0.30)

    return report


# =========================================================
# QUICK HELPERS (used by decision / orchestrator)
# =========================================================
def is_decidable(report: DataQualityReport) -> bool:
    return bool(report and report.can_decide)


def get_cap(report: DataQualityReport, default: float = 0.30) -> float:
    if not report:
        return default
    return float(report.max_confidence_cap or default)