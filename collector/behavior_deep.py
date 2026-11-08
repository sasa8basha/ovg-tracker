"""
collector/behavior_deep.py — Deep behavioral analysis (v4.0)

Rewritten from scratch. Produces BOTH:
    • Strong BOT signals (mouse uniformity, typing speed, scroll bot patterns)
    • Strong HUMAN signals (natural CoV, tremor presence, typing rhythm,
      scroll physics, rich interaction, long engagement)

The old module was bot-only — the new one treats human evidence as
first-class, using the rich `mouse_points` (100 pts) and `key_intervals`
already collected by tracker v3.

Every signal carries an explicit `base_strength` computed from the
strength of the underlying evidence, so fusion can distinguish
"CoV=0.35 with 50 points" from "CoV=0.35 with 8 points".

Signals returned (subset — severity determines actual fusion weight):

    BOT:
        MOUSE_UNIFORM_VELOCITY
        MOUSE_PERFECTLY_STRAIGHT
        MOUSE_NO_TREMOR
        MOUSE_ABNORMAL_ACCELERATION
        MOUSE_TOO_SMOOTH
        MOUSE_TELEPORT
        TYPING_TOO_FAST
        TYPING_TOO_UNIFORM
        SCROLL_NO_HUMAN_PATTERN
        RAPID_REPEAT_CLICKS

    HUMAN:
        HUMAN_NATURAL_MOUSE
        HUMAN_TYPING_RHYTHM
        HUMAN_SCROLL_PHYSICS
        HUMAN_RICH_INTERACTION
        HUMAN_LONG_ENGAGEMENT
"""
from __future__ import annotations

import math
from typing import Any, Dict, List


# =========================================================
# HELPERS
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


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")):
            return default
        return f
    except (ValueError, TypeError):
        return default


def _mean(arr: list) -> float:
    return sum(arr) / len(arr) if arr else 0.0


def _std(arr: list) -> float:
    if len(arr) < 2:
        return 0.0
    m = _mean(arr)
    return math.sqrt(sum((x - m) ** 2 for x in arr) / len(arr))


def _cov(arr: list) -> float:
    m = _mean(arr)
    if m <= 0:
        return 0.0
    return _std(arr) / m


# =========================================================
# MOUSE PATH ANALYSIS
# =========================================================
def _extract_clean_points(raw_points: list) -> list:
    """Return [(x, y, t), ...] from [{x, y, t}, ...]."""
    clean = []
    for p in raw_points:
        if not isinstance(p, dict):
            continue
        try:
            x = float(p.get("x", 0))
            y = float(p.get("y", 0))
            t = float(p.get("t", 0))
            clean.append((x, y, t))
        except (ValueError, TypeError):
            continue
    return clean


def _velocities(points: list) -> List[float]:
    """Pixel-ms velocities between consecutive points."""
    out = []
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        dy = points[i][1] - points[i - 1][1]
        dt = points[i][2] - points[i - 1][2]
        if 0 < dt < 2000:
            out.append(math.sqrt(dx * dx + dy * dy) / dt)
    return out


def _curvature(points: list) -> float:
    """Average angle change per step (radians). High = curvy (human)."""
    if len(points) < 5:
        return 0.0
    step = max(1, len(points) // 20)
    sampled = points[::step][:20]

    angles = []
    for i in range(2, len(sampled)):
        x1 = sampled[i - 1][0] - sampled[i - 2][0]
        y1 = sampled[i - 1][1] - sampled[i - 2][1]
        x2 = sampled[i][0] - sampled[i - 1][0]
        y2 = sampled[i][1] - sampled[i - 1][1]

        mag1 = math.hypot(x1, y1)
        mag2 = math.hypot(x2, y2)
        if mag1 < 1 or mag2 < 1:
            continue

        dot = (x1 * x2 + y1 * y2) / (mag1 * mag2)
        dot = max(-1.0, min(1.0, dot))
        angles.append(math.acos(dot))

    return _mean(angles) if angles else 0.0


def _tremor_residual(points: list) -> float:
    """
    Human hands produce 8-12 Hz micro-tremor → the point deviates
    from the linear interpolation of its neighbors.
    Bots (puppeteer / selenium MoveMouse) produce ~0 residual.
    """
    if len(points) < 15:
        return 0.0
    residuals = []
    for i in range(2, len(points) - 2):
        x1, y1, _ = points[i - 2]
        x2, y2, _ = points[i + 2]
        px, py, _ = points[i]
        dx = x2 - x1
        dy = y2 - y1
        line_len = math.hypot(dx, dy)
        if line_len < 1:
            continue
        num = abs(dy * px - dx * py + x2 * y1 - y2 * x1)
        residuals.append(num / line_len)
    return _mean(residuals) if residuals else 0.0


def _acceleration_is_bell(velocities: List[float]) -> bool:
    """Human velocity peaks in the middle (bell curve)."""
    n = len(velocities)
    if n < 9:
        return False
    third = n // 3
    early = _mean(velocities[:third]) if third else 0
    mid = _mean(velocities[third:2 * third]) if third else 0
    late = _mean(velocities[2 * third:]) if third else 0
    return mid > 0 and mid >= early and mid >= late


def _detect_teleports(points: list) -> int:
    """Jumps > 500px within < 10ms — suspicious."""
    count = 0
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        dy = points[i][1] - points[i - 1][1]
        dt = points[i][2] - points[i - 1][2]
        if dt < 10 and math.hypot(dx, dy) > 500:
            count += 1
    return count


def _analyze_mouse(behavior: dict) -> list:
    """Emit bot + human mouse signals."""
    signals = []
    raw_points = _safe_list(behavior.get("mouse_points"))
    points = _extract_clean_points(raw_points)
    n = len(points)

    if n < 10:
        return signals

    velocities = _velocities(points)
    if len(velocities) < 5:
        return signals

    v_cov = _cov(velocities)
    v_mean = _mean(velocities)
    curvature = _curvature(points)
    tremor = _tremor_residual(points)
    bell = _acceleration_is_bell(velocities)
    teleports = _detect_teleports(points)

    # ---------- BOT signals ----------
    if n >= 20 and v_mean > 0.05 and v_cov < 0.10:
        signals.append({
            "code": "MOUSE_UNIFORM_VELOCITY",
            "severity": "high",
            "direction": "bot",
            "base_strength": 0.75 if v_cov < 0.05 else 0.60,
            "detail": f"Mouse CoV={v_cov:.3f} (uniform, {n} pts)",
        })

    if n >= 20 and curvature < 0.01:
        signals.append({
            "code": "MOUSE_PERFECTLY_STRAIGHT",
            "severity": "high",
            "direction": "bot",
            "base_strength": 0.70,
            "detail": f"Curvature={curvature:.5f} (perfectly straight, {n} pts)",
        })

    if n >= 30 and tremor < 0.05:
        signals.append({
            "code": "MOUSE_NO_TREMOR",
            "severity": "medium",
            "direction": "bot",
            "base_strength": 0.55,
            "detail": f"Tremor residual={tremor:.3f} (no human micro-tremor)",
        })

    if n >= 30 and not bell and v_cov < 0.30:
        signals.append({
            "code": "MOUSE_ABNORMAL_ACCELERATION",
            "severity": "medium",
            "direction": "bot",
            "base_strength": 0.45,
            "detail": "Velocity profile not bell-curve",
        })

    if teleports >= 2:
        signals.append({
            "code": "MOUSE_TELEPORT",
            "severity": "high",
            "direction": "bot",
            "base_strength": 0.65 if teleports >= 5 else 0.50,
            "detail": f"{teleports} teleport jumps (>500px in <10ms)",
        })

    # ---------- HUMAN signals ----------
    # Score each human condition
    human_score = 0.0
    human_reasons = []

    if v_cov > 0.30:
        human_score += 0.30
        human_reasons.append(f"CoV={v_cov:.2f}")
    elif v_cov > 0.15:
        human_score += 0.15
        human_reasons.append(f"CoV={v_cov:.2f}")

    if tremor > 0.10:
        human_score += 0.30
        human_reasons.append(f"tremor={tremor:.2f}")
    elif tremor > 0.05:
        human_score += 0.15
        human_reasons.append(f"tremor={tremor:.2f}")

    if curvature > 0.05:
        human_score += 0.20
        human_reasons.append(f"curv={curvature:.3f}")
    elif curvature > 0.01:
        human_score += 0.10
        human_reasons.append(f"curv={curvature:.3f}")

    if bell:
        human_score += 0.20
        human_reasons.append("bell_accel")

    if n >= 30:
        human_score *= 1.05

    human_score = min(1.0, human_score)

    if human_score >= 0.60 and n >= 20:
        signals.append({
            "code": "HUMAN_NATURAL_MOUSE",
            "severity": "human",
            "direction": "human",
            "base_strength": round(0.45 + 0.50 * human_score, 3),
            "detail": f"Natural mouse ({n} pts): " + ", ".join(human_reasons[:3]),
        })

    return signals


# =========================================================
# TYPING RHYTHM ANALYSIS
# =========================================================
def _analyze_typing(behavior: dict) -> list:
    signals = []
    intervals = _safe_list(behavior.get("key_intervals"))
    clean = [float(x) for x in intervals if isinstance(x, (int, float)) and x > 0]

    if len(clean) < 5:
        return signals

    mean_ms = _mean(clean)
    cov = _cov(clean)

    # ---------- BOT signals ----------
    if mean_ms < 20:
        signals.append({
            "code": "TYPING_TOO_FAST",
            "severity": "high",
            "direction": "bot",
            "base_strength": 0.70,
            "detail": f"Mean keystroke interval={mean_ms:.1f}ms (superhuman)",
        })
    elif len(clean) >= 10 and cov < 0.15:
        signals.append({
            "code": "TYPING_TOO_UNIFORM",
            "severity": "medium",
            "direction": "bot",
            "base_strength": 0.55,
            "detail": f"Typing CoV={cov:.3f} (mechanical rhythm)",
        })

    # ---------- HUMAN signals ----------
    # Human typing is log-normal:
    #   - typical mean 80-300ms
    #   - CoV 0.35-0.90
    human_score = 0.0
    human_reasons = []

    if 80 <= mean_ms <= 300:
        human_score += 0.35
        human_reasons.append(f"mean={mean_ms:.0f}ms")

    if cov > 0.35:
        human_score += 0.35
        human_reasons.append(f"CoV={cov:.2f}")
    elif cov > 0.20:
        human_score += 0.15
        human_reasons.append(f"CoV={cov:.2f}")

    if len(clean) >= 10:
        human_score += 0.15
        human_reasons.append(f"{len(clean)} intervals")

    if 80 <= mean_ms <= 300 and cov > 0.35 and len(clean) >= 10:
        signals.append({
            "code": "HUMAN_TYPING_RHYTHM",
            "severity": "human",
            "direction": "human",
            "base_strength": round(0.55 + 0.30 * min(1.0, human_score), 3),
            "detail": "Natural typing rhythm: " + ", ".join(human_reasons[:3]),
        })

    return signals


# =========================================================
# SCROLL ANALYSIS
# =========================================================
def _analyze_scroll(behavior: dict, events: dict) -> list:
    signals = []

    scrolls = _safe_int(events.get("scrolls"), 0)
    depth = _safe_float(behavior.get("scroll_depth_pct"), 0)
    dir_changes = _safe_int(behavior.get("scroll_direction_changes"), 0)
    pauses = _safe_int(behavior.get("scroll_pauses"), 0)

    if scrolls < 3:
        return signals

    # ---------- BOT signals ----------
    if scrolls >= 10 and dir_changes == 0 and pauses == 0:
        signals.append({
            "code": "SCROLL_NO_HUMAN_PATTERN",
            "severity": "medium",
            "direction": "bot",
            "base_strength": 0.55 if scrolls >= 20 else 0.45,
            "detail": f"{scrolls} scrolls, 0 reversals, 0 pauses",
        })

    # ---------- HUMAN signals ----------
    # Humans typically reverse, pause, and scroll deep
    human_score = 0.0
    human_reasons = []

    if dir_changes > 0:
        human_score += 0.30
        human_reasons.append(f"{dir_changes} reversals")

    if pauses > 0:
        human_score += 0.30
        human_reasons.append(f"{pauses} pauses")

    if depth >= 30:
        human_score += 0.25
        human_reasons.append(f"depth={depth:.0f}%")
    elif depth >= 15:
        human_score += 0.15
        human_reasons.append(f"depth={depth:.0f}%")

    if scrolls >= 5:
        human_score += 0.10

    human_score = min(1.0, human_score)

    if human_score >= 0.55:
        signals.append({
            "code": "HUMAN_SCROLL_PHYSICS",
            "severity": "human",
            "direction": "human",
            "base_strength": round(0.45 + 0.45 * human_score, 3),
            "detail": "Natural scroll: " + ", ".join(human_reasons[:3]),
        })

    return signals


# =========================================================
# INTERACTION / ENGAGEMENT
# =========================================================
def _analyze_engagement(behavior: dict, events: dict) -> list:
    signals = []

    duration = _safe_int(behavior.get("total_time_ms"), 0)
    if duration == 0:
        duration = _safe_int(behavior.get("time_on_page_ms"), 0)

    mousemove = _safe_int(events.get("mousemove"), 0)
    clicks = _safe_int(events.get("clicks"), 0)
    scrolls = _safe_int(events.get("scrolls"), 0)
    keydown = _safe_int(events.get("keydown"), 0)
    touchstart = _safe_int(events.get("touchstart"), 0)

    # ---------- RAPID_REPEAT_CLICKS ----------
    click_points = _safe_list(behavior.get("clicks_points") or behavior.get("click_points"))
    if isinstance(click_points, list) and len(click_points) >= 5:
        coords = set()
        for cp in click_points[:20]:
            if isinstance(cp, dict):
                try:
                    coords.add((int(cp.get("x", 0)), int(cp.get("y", 0))))
                except (ValueError, TypeError):
                    pass
        if len(click_points) >= 5 and len(coords) == 1:
            signals.append({
                "code": "RAPID_REPEAT_CLICKS",
                "severity": "medium",
                "direction": "bot",
                "base_strength": 0.50,
                "detail": f"{len(click_points)} clicks at same point",
            })

    # ---------- HUMAN_RICH_INTERACTION ----------
    types_present = 0
    if mousemove >= 30:
        types_present += 1
    if clicks >= 2:
        types_present += 1
    if scrolls >= 3:
        types_present += 1
    if keydown >= 5:
        types_present += 1
    if touchstart > 0:
        types_present += 1

    if duration >= 15000 and types_present >= 3:
        signals.append({
            "code": "HUMAN_RICH_INTERACTION",
            "severity": "human",
            "direction": "human",
            "base_strength": 0.75 if types_present >= 4 else 0.60,
            "detail": (
                f"Rich interaction: {types_present} types "
                f"over {duration/1000:.0f}s"
            ),
        })

    # ---------- HUMAN_LONG_ENGAGEMENT ----------
    total_events = (
        mousemove
        + clicks * 3
        + scrolls * 2
        + keydown * 2
        + touchstart
    )
    if duration >= 30000 and total_events >= 25:
        signals.append({
            "code": "HUMAN_LONG_ENGAGEMENT",
            "severity": "human",
            "direction": "human",
            "base_strength": 0.65 if duration >= 60000 else 0.50,
            "detail": (
                f"Engaged {duration/1000:.0f}s with {total_events} events"
            ),
        })

    return signals


# =========================================================
# MAIN ENTRY
# =========================================================
def analyze_behavior_deep(ctx: dict) -> list:
    """
    Analyze mouse path, typing, scroll, and engagement.

    Returns a list of bot + human signals — fusion decides weight.

    The orchestrator passes ctx via _build_contradiction_context(),
    so `ctx["behavior"]` is the visit's behavior payload.
    """
    try:
        behavior = _safe_dict(ctx.get("behavior")) if isinstance(ctx, dict) else {}
    except Exception:
        behavior = {}

    if not behavior:
        return []

    events = _safe_dict(behavior.get("events"))

    signals: List[dict] = []
    signals.extend(_analyze_mouse(behavior))
    signals.extend(_analyze_typing(behavior))
    signals.extend(_analyze_scroll(behavior, events))
    signals.extend(_analyze_engagement(behavior, events))

    return signals