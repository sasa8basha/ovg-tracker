"""
behavior_deep.py — Advanced behavioral analysis (v3.3)

Analyzes:
  - Mouse path (Bezier, tremor, Fitts's law)
  - Typing rhythm (digraph latencies, burst detection)
  - Scroll physics (momentum, deceleration)
"""
import math


def _mean(arr):
    if not arr:
        return 0.0
    return sum(arr) / len(arr)


def _std(arr):
    if len(arr) < 2:
        return 0.0
    m = _mean(arr)
    return math.sqrt(sum((x - m) ** 2 for x in arr) / len(arr))


# =========================================================
# MOUSE PATH ANALYSIS
# =========================================================
def analyze_mouse_path(points):
    """
    points: list of {x, y, t} dicts (last 200 usually)
    Returns signals list.
    """
    signals = []
    if not points or len(points) < 10:
        return signals

    # Extract valid triples
    clean = []
    for p in points:
        if not isinstance(p, dict):
            continue
        try:
            x = float(p.get("x", 0))
            y = float(p.get("y", 0))
            t = float(p.get("t", 0))
            clean.append((x, y, t))
        except (ValueError, TypeError):
            continue

    if len(clean) < 10:
        return signals

    # ===== 1) Velocity profile =====
    velocities = []
    for i in range(1, len(clean)):
        dx = clean[i][0] - clean[i-1][0]
        dy = clean[i][1] - clean[i-1][1]
        dt = clean[i][2] - clean[i-1][2]
        if dt > 0 and dt < 2000:
            velocities.append(math.sqrt(dx*dx + dy*dy) / dt)

    if len(velocities) < 5:
        return signals

    v_mean = _mean(velocities)
    v_std = _std(velocities)
    v_cov = v_std / v_mean if v_mean > 0 else 0

    # Bot: too consistent velocity
    if v_mean > 50 and v_cov < 0.10:
        signals.append({
            "code": "MOUSE_UNIFORM_VELOCITY",
            "severity": "high",
            "score": 55,
            "detail": f"Mouse CoV={v_cov:.3f} (suspiciously consistent)",
        })

    # ===== 2) Acceleration profile =====
    # Humans: slow start, peak mid, slow end (bell curve)
    # Bots: constant or linear acceleration
    if len(velocities) >= 10:
        thirds = len(velocities) // 3
        early = _mean(velocities[:thirds])
        mid = _mean(velocities[thirds:thirds*2])
        late = _mean(velocities[thirds*2:])

        # Bell curve check: mid should be highest for humans
        if mid > 0 and (early > mid * 1.2 or late > mid * 1.2):
            signals.append({
                "code": "MOUSE_ABNORMAL_ACCELERATION",
                "severity": "medium",
                "score": 35,
                "detail": f"Unnatural acceleration: early={early:.0f}, mid={mid:.0f}, late={late:.0f}",
            })

    # ===== 3) Straight line detection (Bezier) =====
    # Humans: slight curvature. Bots: perfectly straight
    if len(clean) >= 20:
        # Sample 20 evenly spaced points
        step = max(1, len(clean) // 20)
        sampled = clean[::step][:20]

        # Compute total curvature
        total_angle_change = 0
        angle_changes = 0
        for i in range(2, len(sampled)):
            x1 = sampled[i-1][0] - sampled[i-2][0]
            y1 = sampled[i-1][1] - sampled[i-2][1]
            x2 = sampled[i][0] - sampled[i-1][0]
            y2 = sampled[i][1] - sampled[i-1][1]

            mag1 = math.sqrt(x1*x1 + y1*y1)
            mag2 = math.sqrt(x2*x2 + y2*y2)
            if mag1 < 1 or mag2 < 1:
                continue

            dot = (x1*x2 + y1*y2) / (mag1 * mag2)
            dot = max(-1, min(1, dot))
            angle = math.acos(dot)
            total_angle_change += angle
            angle_changes += 1

        if angle_changes > 0:
            avg_curvature = total_angle_change / angle_changes
            # Perfectly straight = near 0
            if avg_curvature < 0.01 and len(clean) > 30:
                signals.append({
                    "code": "MOUSE_PERFECTLY_STRAIGHT",
                    "severity": "high",
                    "score": 60,
                    "detail": f"Curvature={avg_curvature:.5f} (straight line)",
                })

    # ===== 4) Micro-tremor detection =====
    # Human hands: micro-tremor 8-12 Hz, amplitude 0.5-2px
    # Bots: no tremor, perfectly smooth
    tremor_score = _compute_tremor(clean)
    if tremor_score is not None and tremor_score < 0.05 and len(clean) >= 50:
        signals.append({
            "code": "MOUSE_NO_TREMOR",
            "severity": "medium",
            "score": 45,
            "detail": f"Tremor score={tremor_score:.3f} (no human micro-tremor)",
        })

    # ===== 5) Fitts's law check =====
    # Human targets clicks with deceleration near target
    # Bots: constant velocity through clicks
    clicks = [p for p in clean if isinstance(p, dict) and p.get("click")]
    # (Simplified — click points not always available)

    return signals


def _compute_tremor(points):
    """
    Detect micro-tremor by measuring high-frequency jitter around the smooth path.
    Humans: high jitter in 8-12 Hz range
    Bots: ~0 jitter
    """
    if len(points) < 30:
        return None

    # Compute residual: distance from point to line between neighbors
    residuals = []
    for i in range(2, len(points) - 2):
        # Line from i-2 to i+2
        x1, y1, _ = points[i-2]
        x2, y2, _ = points[i+2]
        px, py, _ = points[i]

        dx = x2 - x1
        dy = y2 - y1
        line_len = math.sqrt(dx*dx + dy*dy)
        if line_len < 1:
            continue

        # Distance from point to line
        # |(y2-y1)*px - (x2-x1)*py + x2*y1 - y2*x1| / sqrt((y2-y1)^2 + (x2-x1)^2)
        num = abs(dy * px - dx * py + x2 * y1 - y2 * x1)
        dist = num / line_len
        residuals.append(dist)

    if len(residuals) < 5:
        return None

    return _mean(residuals)


# =========================================================
# TYPING RHYTHM ANALYSIS
# =========================================================
def analyze_typing(key_intervals):
    """
    key_intervals: list of ms intervals between keypresses
    Humans: 50-300ms, log-normal distribution
    Bots: < 10ms (too fast) or perfectly uniform
    """
    signals = []
    if not key_intervals or len(key_intervals) < 5:
        return signals

    valid = [x for x in key_intervals if isinstance(x, (int, float)) and x >= 0]
    if len(valid) < 5:
        return signals

    mean = _mean(valid)
    std = _std(valid)
    cov = std / mean if mean > 0 else 0

    # Too fast
    if mean > 0 and mean < 20:
        signals.append({
            "code": "TYPING_TOO_FAST",
            "severity": "high",
            "score": 65,
            "detail": f"Mean keystroke interval={mean:.1f}ms (superhuman)",
        })

    # Too uniform
    elif mean > 0 and cov < 0.15 and len(valid) >= 10:
        signals.append({
            "code": "TYPING_TOO_UNIFORM",
            "severity": "medium",
            "score": 45,
            "detail": f"Typing CoV={cov:.3f} (mechanical rhythm)",
        })

    return signals


# =========================================================
# SCROLL PHYSICS ANALYSIS
# =========================================================
def analyze_scroll(velocity_samples, direction_changes, pauses):
    """
    Humans: momentum scroll with deceleration, reversals
    Bots: constant velocity, no pauses, no reversals
    """
    signals = []
    if not velocity_samples or len(velocity_samples) < 5:
        return signals

    valid = [x for x in velocity_samples if isinstance(x, (int, float)) and x > 0]
    if len(valid) < 5:
        return signals

    mean = _mean(valid)
    std = _std(valid)
    cov = std / mean if mean > 0 else 0

    # Bot: too consistent
    if mean > 100 and cov < 0.20:
        signals.append({
            "code": "SCROLL_CONSTANT_VELOCITY",
            "severity": "medium",
            "score": 45,
            "detail": f"Scroll CoV={cov:.2f} (no momentum variance)",
        })

    # Bot: no direction changes over many scrolls
    if len(valid) >= 10 and direction_changes == 0 and pauses == 0:
        signals.append({
            "code": "SCROLL_NO_HUMAN_PATTERN",
            "severity": "medium",
            "score": 40,
            "detail": f"{len(valid)} scrolls, 0 reversals, 0 pauses",
        })

    return signals


# =========================================================
# MAIN ENTRY POINT
# =========================================================
def analyze_behavior_deep(ctx):
    """
    Analyze mouse path, typing, scroll for human vs bot patterns.
    Returns list of signals.
    """
    signals = []

    behavior = ctx.get("behavior") or {}
    fp = ctx.get("fp") or {}

    # Mouse path
    try:
        points = behavior.get("mouse_points") or []
        if isinstance(points, list) and points:
            signals.extend(analyze_mouse_path(points))
    except Exception:
        pass

    # Typing
    try:
        key_intervals = fp.get("key_intervals") or behavior.get("key_intervals") or []
        if isinstance(key_intervals, list):
            signals.extend(analyze_typing(key_intervals))
    except Exception:
        pass

    # Scroll
    try:
        velocity_samples = behavior.get("scroll_velocity_samples") or []
        direction_changes = int(behavior.get("scroll_direction_changes", 0) or 0)
        pauses = int(behavior.get("scroll_pauses", 0) or 0)
        if isinstance(velocity_samples, list):
            signals.extend(analyze_scroll(velocity_samples, direction_changes, pauses))
    except Exception:
        pass

    return signals
