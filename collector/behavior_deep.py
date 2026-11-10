"""
collector/behavior_deep.py — Deep behavioral analysis (v8.0)

Produces BOTH:
    • Strong BOT signals (mouse uniformity, typing speed, scroll bot patterns)
    • Strong HUMAN signals (natural CoV, tremor presence, typing rhythm,
      scroll physics, rich interaction, long engagement)
    • Flagon-derived signals (rage clicks, interval logs, mutation anomalies,
      detailed-event anomalies)
    • AdVerify-inspired ML features (16-feature heuristic score adapted to
      the web context) with logistic-regression-style weighting.

Signals emitted (subset):
    BOT:
        MOUSE_UNIFORM_VELOCITY, MOUSE_PERFECTLY_STRAIGHT, MOUSE_NO_TREMOR,
        MOUSE_ABNORMAL_ACCELERATION, MOUSE_TOO_SMOOTH, MOUSE_TELEPORT,
        TYPING_TOO_FAST, TYPING_TOO_UNIFORM,
        SCROLL_CONSTANT_VELOCITY, SCROLL_NO_HUMAN_PATTERN,
        RAPID_REPEAT_CLICKS,
        RAGE_CLICK_BURST, INTERVAL_SUSPICIOUS, MUTATION_ANOMALY,
        DETAILED_CLICK_NO_RECT, CLICK_OUTSIDE_VIEWPORT,
        ML_FEATURE_ANOMALY, ML_FEATURE_SUSPICIOUS,
        NO_INTERACTION_HIGH_CONF, DNT_WITH_ZERO_INTERACTION,
        SCREEN_UA_MISMATCH, MISSING_FP_CORE,

    HUMAN:
        HUMAN_NATURAL_MOUSE, HUMAN_TYPING_RHYTHM, HUMAN_SCROLL_PHYSICS,
        HUMAN_RICH_INTERACTION, HUMAN_LONG_ENGAGEMENT,
        HUMAN_DIVERSE_INTERACTION, HUMAN_NATURAL_SCROLL, HUMAN_HOVER_ACTIVITY
"""
from __future__ import annotations

import math
from typing import Any, Dict, List


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


def _sigmoid(x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 1.0 if x > 0 else 0.0


# =========================================================
# MOUSE PATH ANALYSIS
# =========================================================
def _extract_clean_points(raw_points: list) -> list:
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
    out = []
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        dy = points[i][1] - points[i - 1][1]
        dt = points[i][2] - points[i - 1][2]
        if 0 < dt < 2000:
            out.append(math.sqrt(dx * dx + dy * dy) / dt)
    return out


def _curvature(points: list) -> float:
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
    n = len(velocities)
    if n < 9:
        return False
    third = n // 3
    early = _mean(velocities[:third]) if third else 0.0
    mid = _mean(velocities[third:2 * third]) if third else 0.0
    late = _mean(velocities[2 * third:]) if third else 0.0
    return mid > 0 and mid >= early and mid >= late


def _detect_teleports(points: list) -> int:
    count = 0
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        dy = points[i][1] - points[i - 1][1]
        dt = points[i][2] - points[i - 1][2]
        if dt < 10 and math.hypot(dx, dy) > 500:
            count += 1
    return count


def _analyze_mouse(behavior: dict) -> list:
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

    # -------- BOT signals --------
    if n >= 20 and v_mean > 0.05 and v_cov < 0.10:
        signals.append({
            "code": "MOUSE_UNIFORM_VELOCITY",
            "base_strength": 0.75 if v_cov < 0.05 else 0.60,
            "detail": f"Mouse CoV={v_cov:.3f} (uniform, {n} pts)",
        })

    if n >= 20 and curvature < 0.01:
        signals.append({
            "code": "MOUSE_PERFECTLY_STRAIGHT",
            "base_strength": 0.70,
            "detail": f"Curvature={curvature:.5f} (perfectly straight, {n} pts)",
        })

    if n >= 30 and tremor < 0.05:
        signals.append({
            "code": "MOUSE_NO_TREMOR",
            "base_strength": 0.55,
            "detail": f"Tremor residual={tremor:.3f} (no human micro-tremor)",
        })

    if n >= 30 and not bell and v_cov < 0.30:
        signals.append({
            "code": "MOUSE_ABNORMAL_ACCELERATION",
            "base_strength": 0.45,
            "detail": "Velocity profile not bell-curve",
        })

    if teleports >= 2:
        signals.append({
            "code": "MOUSE_TELEPORT",
            "base_strength": 0.65 if teleports >= 5 else 0.50,
            "detail": f"{teleports} teleport jumps (>500px in <10ms)",
        })

    # -------- HUMAN signals --------
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
            "base_strength": round(0.45 + 0.50 * human_score, 3),
            "detail": f"Natural mouse ({n} pts): " + ", ".join(human_reasons[:3]),
        })

    return signals


# =========================================================
# TYPING ANALYSIS
# =========================================================
def _analyze_typing(behavior: dict) -> list:
    signals = []
    intervals = _safe_list(behavior.get("key_intervals"))
    clean = [float(x) for x in intervals if isinstance(x, (int, float)) and x > 0]

    # M-05: paste events produce near-zero intervals — skip bot flags if paste observed
    if behavior.get("paste_detected") or behavior.get("had_paste"):
        return signals

    if len(clean) < 5:
        return signals

    mean_ms = _mean(clean)
    cov = _cov(clean)

    # -------- BOT --------
    if mean_ms < 15:  # M-05: was 20; paste residual can sit 15-25ms
        signals.append({
            "code": "TYPING_TOO_FAST",
            "base_strength": 0.70,
            "detail": f"Mean keystroke interval={mean_ms:.1f}ms (superhuman)",
        })
    elif len(clean) >= 12 and cov < 0.12:  # M-05: stricter sample + CoV
        signals.append({
            "code": "TYPING_TOO_UNIFORM",
            "base_strength": 0.55,
            "detail": f"Typing CoV={cov:.3f} (mechanical rhythm)",
        })

    # -------- HUMAN --------
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

    # -------- BOT --------
    if scrolls >= 10 and dir_changes == 0 and pauses == 0:
        signals.append({
            "code": "SCROLL_NO_HUMAN_PATTERN",
            "base_strength": 0.55 if scrolls >= 20 else 0.45,
            "detail": f"{scrolls} scrolls, 0 reversals, 0 pauses",
        })

    # Velocity-based bot signal
    velocities = _safe_list(behavior.get("scroll_velocity_samples"))
    clean_v = [float(x) for x in velocities if isinstance(x, (int, float)) and x > 0]
    if len(clean_v) >= 5:
        v_mean = _mean(clean_v)
        v_cov = _cov(clean_v)
        if v_mean > 100 and v_cov < 0.12:  # M-06: was 0.20 human FP on fast scroll
            signals.append({
                "code": "SCROLL_CONSTANT_VELOCITY",
                "base_strength": 0.45,
                "detail": f"Scroll CoV={v_cov:.2f} (no momentum variance)",
            })

    # -------- HUMAN --------
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
            "base_strength": round(0.45 + 0.45 * human_score, 3),
            "detail": "Natural scroll: " + ", ".join(human_reasons[:3]),
        })

    return signals


# =========================================================
# ENGAGEMENT / INTERACTION
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

    # -------- RAPID_REPEAT_CLICKS --------
    click_points = _safe_list(behavior.get("clicks_points") or behavior.get("click_points"))
    if isinstance(click_points, list) and len(click_points) >= 5:
        coords = set()
        for cp in click_points[:20]:
            if isinstance(cp, dict):
                try:
                    coords.add((int(cp.get("x", 0)), int(cp.get("y", 0))))
                except (ValueError, TypeError):
                    pass
        if len(coords) == 1:
            signals.append({
                "code": "RAPID_REPEAT_CLICKS",
                "base_strength": 0.50,
                "detail": f"{len(click_points)} clicks at same point",
            })

    # -------- HUMAN_RICH_INTERACTION --------
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
            "base_strength": 0.75 if types_present >= 4 else 0.60,
            "detail": f"Rich interaction: {types_present} types over {duration/1000:.0f}s",
        })

    # -------- HUMAN_LONG_ENGAGEMENT --------
    total_events = mousemove + clicks * 3 + scrolls * 2 + keydown * 2 + touchstart
    if duration >= 30000 and total_events >= 25:
        signals.append({
            "code": "HUMAN_LONG_ENGAGEMENT",
            "base_strength": 0.65 if duration >= 60000 else 0.50,
            "detail": f"Engaged {duration/1000:.0f}s with {total_events} events",
        })

    # -------- HUMAN_DIVERSE_INTERACTION (AdVerify-inspired) --------
    if types_present >= 4 and duration >= 20000:
        signals.append({
            "code": "HUMAN_DIVERSE_INTERACTION",
            "base_strength": 0.65,
            "detail": f"{types_present} interaction types over {duration/1000:.0f}s",
        })

    # -------- HUMAN_HOVER_ACTIVITY (many small mousemoves) --------
    if mousemove >= 50 and duration >= 5000:
        # Count mousemoves per second
        mps = mousemove / max(1.0, duration / 1000.0)
        if 0.5 <= mps <= 30.0:
            signals.append({
                "code": "HUMAN_HOVER_ACTIVITY",
                "base_strength": 0.35,
                "detail": f"Natural hover rate ({mps:.1f} moves/sec)",
            })

    return signals


# =========================================================
# FLAGON-DERIVED ANALYSIS
# =========================================================
def _analyze_flagon(behavior: dict) -> list:
    """Analyze rage clicks, interval logs, mutations, detailed events."""
    signals = []

    # -------- Rage clicks --------
    rage = _safe_list(behavior.get("rage_clicks"))
    # M-07: single frustrated burst is human; require stronger pattern
    if len(rage) >= 2 or (len(rage) == 1 and _safe_int((rage[0] if isinstance(rage[0], dict) else {}).get("count"), 0) >= 8):
        first = rage[0] if isinstance(rage[0], dict) else {}
        cnt = _safe_int(first.get("count"), 0)
        signals.append({
            "code": "RAGE_CLICK_BURST",
            "base_strength": 0.60 if cnt >= 8 else 0.45,
            "detail": f"{len(rage)} rage-click bursts (max count={cnt})",
        })

    # -------- Interval logs (rapid aggregated events) --------
    intervals = _safe_list(behavior.get("interval_logs"))
    suspicious_intervals = 0
    for iv in intervals:
        if not isinstance(iv, dict):
            continue
        count = _safe_int(iv.get("count"), 0)
        dur = _safe_int(iv.get("duration"), 0)
        if count >= 5 and dur < 2000:
            # 5+ rapid events in <2s on the same target = suspicious
            suspicious_intervals += 1
    if suspicious_intervals >= 1:
        signals.append({
            "code": "INTERVAL_SUSPICIOUS",
            "base_strength": 0.55 if suspicious_intervals >= 2 else 0.45,
            "detail": f"{suspicious_intervals} suspicious interval bursts",
        })

    # -------- Mutation anomalies --------
    mut = _safe_dict(behavior.get("mutation_summary"))
    if mut:
        added = _safe_int(mut.get("added"), 0)
        removed = _safe_int(mut.get("removed"), 0)
        attributes = _safe_int(mut.get("attributes"), 0)
        total = _safe_int(mut.get("total_events"), 0)
        # Bots that erase their traces produce huge removal counts
        if removed > 0 and added > 0 and removed > added * 3:
            signals.append({
                "code": "MUTATION_ANOMALY",
                "base_strength": 0.55,
                "detail": f"DOM teardown: {removed} removed vs {added} added",
            })
        # Massive attribute churn
        elif attributes > 200:
            signals.append({
                "code": "MUTATION_ANOMALY",
                "base_strength": 0.45,
                "detail": f"Massive attribute churn ({attributes} mutations)",
            })

    # -------- Detailed events anomalies --------
    detailed = _safe_list(behavior.get("detailed_events"))
    clicks_without_rect = 0
    clicks_outside_viewport = 0
    for ev in detailed:
        if not isinstance(ev, dict):
            continue
        if ev.get("type") != "click":
            continue
        rect = ev.get("rect")
        if rect is None:
            clicks_without_rect += 1
        else:
            try:
                rx = int(rect.get("x", 0))
                ry = int(rect.get("y", 0))
                rw = int(rect.get("width", 0))
                rh = int(rect.get("height", 0))
                if rw <= 0 or rh <= 0:
                    clicks_without_rect += 1
                elif rx < -100 or ry < -100:
                    clicks_outside_viewport += 1
            except (ValueError, TypeError):
                pass
    if clicks_without_rect >= 2:
        signals.append({
            "code": "DETAILED_CLICK_NO_RECT",
            "base_strength": 0.45,
            "detail": f"{clicks_without_rect} clicks without valid target rect",
        })
    if clicks_outside_viewport >= 2:
        signals.append({
            "code": "CLICK_OUTSIDE_VIEWPORT",
            "base_strength": 0.55,
            "detail": f"{clicks_outside_viewport} clicks outside viewport",
        })

    return signals


# =========================================================
# ADVERIFY-INSPIRED ML FEATURES
# =========================================================
# The 16 features are adapted from AdVerify's FeatureExtractor (which
# originally worked on OpenRTB bid requests). We map each one to a
# web-visit equivalent. The final score is a logistic-regression-style
# weighted sum, then squashed via sigmoid to produce a probability.
#
# Weights were tuned on the assumption that "anomalous = +weight".
# Positive weights increase the fraud probability; negative weights
# (for "present + normal") slightly decrease it.

def _compute_ml_features(behavior: dict, nav: dict, fp: dict, screen: dict) -> Dict[str, float]:
    """
    Extracts 16 features from the web-visit payload, each normalized to 0..1
    where 0 = normal/human-like and 1 = anomalous/bot-like (except for the
    "presence" features which are simply 0 or 1).

    Features (mirroring AdVerify's 16-element vector):
        0.  has_nav            (presence bonus)
        1.  has_fingerprint    (presence bonus)
        2.  has_behavior       (presence bonus)
        3.  events_density     (events per second, clipped + normalized)
        4.  dnt_flag           (Do-Not-Track set = 1)
        5.  lang_anomaly       (0 languages OR > 10 languages)
        6.  tz_anomaly         (missing / UTC / Unknown)
        7.  platform_type      (desktop=0, mobile=0.4, tablet=0.7, unknown=1)
        8.  os_ua_mismatch     (OS in UA doesn't match platform)
        9.  conn_anomaly       (rtt<=0 or missing effective type)
        10. canvas_anomaly     (blocked / missing canvas)
        11. webgl_anomaly      (blocked / Mesa / SwiftShader)
        12. webgl_vendor_mismatch (vendor + renderer contradicts)
        13. client_contradictions (count of UA/fp contradictions)
        14. lang_country_mismatch
        15. screen_area_log    (normalized log of screen area; small = anomaly)
    """
    f = {}

    # 0..2 presence
    f["has_nav"] = 1.0 if nav.get("ua") else 0.0
    has_fp = bool(fp.get("canvas_hash") or fp.get("webgl") or fp.get("timezone"))
    f["has_fingerprint"] = 1.0 if has_fp else 0.0
    f["has_behavior"] = 1.0 if behavior else 0.0

    # 3 events density
    events = _safe_dict(behavior.get("events"))
    total_events = (
        _safe_int(events.get("mousemove"), 0)
        + _safe_int(events.get("clicks"), 0)
        + _safe_int(events.get("scrolls"), 0)
        + _safe_int(events.get("keydown"), 0)
        + _safe_int(events.get("touchstart"), 0)
    )
    dur_s = max(1.0, _safe_float(behavior.get("total_time_ms"), 0) / 1000.0)
    density = total_events / dur_s
    # Normalize to 0..1 via a soft cap (density > 5/sec is unusual)
    f["events_density"] = min(1.0, density / 5.0)

    # 4 DNT
    dnt = nav.get("do_not_track")
    if isinstance(dnt, str):
        f["dnt_flag"] = 1.0 if dnt.strip() == "1" else 0.0
    else:
        f["dnt_flag"] = 1.0 if dnt is True else 0.0

    # 5 languages anomaly
    langs = _safe_list(fp.get("languages"))
    if len(langs) == 0:
        f["lang_anomaly"] = 1.0
    elif len(langs) > 10:
        f["lang_anomaly"] = 0.7
    else:
        f["lang_anomaly"] = 0.0

    # 6 timezone anomaly
    tz = str(fp.get("timezone") or "").lower().strip()
    if not tz or tz in ("utc", "etc/utc", "unknown"):
        f["tz_anomaly"] = 1.0
    else:
        f["tz_anomaly"] = 0.0

    # 7 platform type
    platform = str(nav.get("platform") or "").lower()
    ua_lower = str(nav.get("ua") or "").lower()
    if "iphone" in platform or "ipad" in platform or "android" in platform or "linux arm" in platform:
        f["platform_type"] = 0.4
    elif "win" in platform or "mac" in platform or platform == "linux x86_64":
        f["platform_type"] = 0.0
    elif "linux" in platform:
        f["platform_type"] = 0.7
    else:
        f["platform_type"] = 1.0

    # 8 OS/UA mismatch
    os_mismatch = 0.0
    if "windows nt" in ua_lower and ("mac" in platform or "linux" in platform and "android" not in platform):
        os_mismatch = 1.0
    elif ("mac os" in ua_lower or "macintosh" in ua_lower) and "win" in platform:
        os_mismatch = 1.0
    elif ("iphone" in ua_lower or "ipad" in ua_lower) and ("win" in platform or "macintel" in platform):
        os_mismatch = 1.0
    f["os_ua_mismatch"] = os_mismatch

    # 9 connection anomaly
    conn = _safe_dict(fp.get("connection"))
    rtt = _safe_int(conn.get("rtt"), -1)
    et = str(conn.get("effective_type") or "Unknown").lower()
    if rtt < 0 or et in ("unknown", ""):
        f["conn_anomaly"] = 0.5
    elif rtt == 0:
        f["conn_anomaly"] = 1.0
    else:
        f["conn_anomaly"] = 0.0

    # 10 canvas
    ch = str(fp.get("canvas_hash") or "").lower()
    if not ch or ch == "blocked" or ch == "unknown":
        f["canvas_anomaly"] = 1.0
    elif "data:image" in ch:
        # Raw base64 leak — highly suspicious
        f["canvas_anomaly"] = 0.9
    else:
        f["canvas_anomaly"] = 0.0

    # 11 webgl
    wg = _safe_dict(fp.get("webgl"))
    vendor = str(wg.get("vendor") or "").lower()
    renderer = str(wg.get("renderer") or "").lower()
    if "blocked" in vendor or "blocked" in renderer:
        f["webgl_anomaly"] = 1.0
    elif "swiftshader" in renderer or "llvmpipe" in renderer or "mesa offscreen" in renderer:
        f["webgl_anomaly"] = 1.0
    elif "brian paul" in vendor:
        f["webgl_anomaly"] = 1.0
    else:
        f["webgl_anomaly"] = 0.0

    # 12 webgl vendor/renderer mismatch
    mismatch = 0.0
    if "nvidia" in vendor and ("intel" in renderer or "amd" in renderer):
        mismatch = 1.0
    elif "amd" in vendor and ("nvidia" in renderer or "intel" in renderer):
        mismatch = 1.0
    elif "intel" in vendor and ("nvidia" in renderer or "amd" in renderer):
        mismatch = 1.0
    f["webgl_vendor_mismatch"] = mismatch

    # 13 client contradictions (rough count)
    contradictions = 0
    # UA says mobile but no touch
    is_mobile_ua = "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower
    has_touch = bool(nav.get("has_touch")) or _safe_int(nav.get("maxTouchPoints"), 0) > 0
    if is_mobile_ua and not has_touch:
        contradictions += 1
    # UA says desktop but has touch > 0 on non-mobile
    if not is_mobile_ua and has_touch:
        contradictions += 0
    # Languages empty but UA says English
    if not langs and "en" in ua_lower:
        contradictions += 1
    # Platform is empty/unknown
    if not platform or platform == "unknown":
        contradictions += 1
    # Hardware concurrency zero
    if _safe_int(fp.get("hardwareConcurrency"), 0) == 0:
        contradictions += 1
    f["client_contradictions"] = min(1.0, contradictions / 3.0)

    # 14 language/country mismatch
    # We can't know the IP country here without the caller passing it — the
    # orchestrator already adds LANG_COUNTRY_MISMATCH separately. So we set
    # this to 0 here and let the header analyzer handle it.
    f["lang_country_mismatch"] = 0.0

    # 15 screen area (log)
    sw = _safe_int(screen.get("width"), 0)
    sh = _safe_int(screen.get("height"), 0)
    if sw > 0 and sh > 0:
        area = float(sw) * float(sh)
        log_area = math.log(area) if area > 0 else 0.0
        # Small screens (log < 13 → <~440k px) or huge (log > 16 → >8.8M px) suspicious
        if log_area < 13.0:
            f["screen_area_log"] = 1.0
        elif log_area > 16.0:
            f["screen_area_log"] = 0.5
        else:
            f["screen_area_log"] = 0.0
    else:
        f["screen_area_log"] = 1.0

    return f


# Weight vector (hand-tuned, logistic-regression style).
# Positive = increases bot probability. Negative = decreases.
_ML_WEIGHTS = {
    "has_nav":                -0.10,
    "has_fingerprint":        -0.30,
    "has_behavior":           -0.20,
    "events_density":          0.40,
    "dnt_flag":                0.25,
    "lang_anomaly":            0.45,
    "tz_anomaly":              0.30,
    "platform_type":           0.50,
    "os_ua_mismatch":          0.90,
    "conn_anomaly":            0.25,
    "canvas_anomaly":          0.55,
    "webgl_anomaly":           0.65,
    "webgl_vendor_mismatch":   0.70,
    "client_contradictions":   0.60,
    "lang_country_mismatch":   0.35,
    "screen_area_log":         0.45,
}

_ML_BIAS = -1.2  # Negative bias = most visits look human by default


def _compute_ml_score(features: Dict[str, float]) -> float:
    z = _ML_BIAS
    for k, w in _ML_WEIGHTS.items():
        z += w * float(features.get(k, 0.0))
    return _sigmoid(z)


def _analyze_ml(behavior: dict, nav: dict, fp: dict, screen: dict) -> list:
    """
    Compute the 16-feature ML-inspired bot probability and emit signals.
    Score > 0.75 → ML_FEATURE_ANOMALY (high)
    Score > 0.55 → ML_FEATURE_SUSPICIOUS (medium)
    """
    signals = []
    try:
        feats = _compute_ml_features(behavior, nav, fp, screen)
        score = _compute_ml_score(feats)
    except Exception:
        return signals

    # M-08: raise thresholds so presence-only vectors don't dominate
    if score >= 0.82:
        signals.append({
            "code": "ML_FEATURE_ANOMALY",
            "base_strength": 0.75,
            "detail": f"ML feature score={score:.2f} (anomalous combination)",
        })
    elif score >= 0.65:
        signals.append({
            "code": "ML_FEATURE_SUSPICIOUS",
            "base_strength": 0.50,
            "detail": f"ML feature score={score:.2f} (borderline)",
        })

    # --- AdVerify-inspired heuristics ---

    # NO_INTERACTION_HIGH_CONF
    dur_ms = _safe_int(behavior.get("total_time_ms"), 0) or _safe_int(behavior.get("time_on_page_ms"), 0)
    ev = _safe_dict(behavior.get("events"))
    total_interactions = (
        _safe_int(ev.get("mousemove"), 0)
        + _safe_int(ev.get("clicks"), 0)
        + _safe_int(ev.get("scrolls"), 0)
        + _safe_int(ev.get("keydown"), 0)
        + _safe_int(ev.get("touchstart"), 0)
    )
    if dur_ms >= 5000 and total_interactions == 0:
        signals.append({
            "code": "NO_INTERACTION_HIGH_CONF",
            "base_strength": 0.65 if dur_ms >= 15000 else 0.55,
            "detail": f"No interaction over {dur_ms/1000:.0f}s",
        })

    # DNT_WITH_ZERO_INTERACTION
    if feats.get("dnt_flag", 0) >= 1.0 and total_interactions == 0 and dur_ms >= 3000:
        signals.append({
            "code": "DNT_WITH_ZERO_INTERACTION",
            "base_strength": 0.55,
            "detail": "DNT set + zero interaction (evasive profile)",
        })

    # MISSING_FP_CORE
    fp_core_present = sum(1 for k in ("canvas_hash", "timezone", "hardwareConcurrency", "webgl")
                          if fp.get(k))
    if fp_core_present <= 1 and dur_ms >= 3000:
        signals.append({
            "code": "MISSING_FP_CORE",
            "base_strength": 0.55,
            "detail": f"Only {fp_core_present}/4 fingerprint fields present",
        })

    # SCREEN_UA_MISMATCH (mobile UA + absurdly wide screen)
    sw = _safe_int(screen.get("width"), 0)
    ua_lower = str(nav.get("ua") or "").lower()
    is_mobile_ua = "mobile" in ua_lower or "android" in ua_lower
    if is_mobile_ua and sw > 2000:
        signals.append({
            "code": "SCREEN_UA_MISMATCH",
            "base_strength": 0.60,
            "detail": f"Mobile UA but screen.width={sw}px",
        })

    return signals


# =========================================================
# MAIN ENTRY
# =========================================================
def analyze_behavior_deep(ctx: dict) -> list:
    """
    Full behavioral analysis.
    `ctx` must contain: behavior, nav, fp, screen (all optional).
    """
    try:
        behavior = _safe_dict(ctx.get("behavior")) if isinstance(ctx, dict) else {}
        nav = _safe_dict(ctx.get("nav")) if isinstance(ctx, dict) else {}
        fp = _safe_dict(ctx.get("fp")) if isinstance(ctx, dict) else {}
        screen = _safe_dict(ctx.get("screen")) if isinstance(ctx, dict) else {}
    except Exception:
        behavior, nav, fp, screen = {}, {}, {}, {}

    events = _safe_dict(behavior.get("events"))

    signals: List[dict] = []
    if behavior:
        signals.extend(_analyze_mouse(behavior))
        signals.extend(_analyze_typing(behavior))
        signals.extend(_analyze_scroll(behavior, events))
        signals.extend(_analyze_engagement(behavior, events))
        signals.extend(_analyze_flagon(behavior))

    # ML + AdVerify-inspired checks run even if behavior is minimal
    signals.extend(_analyze_ml(behavior, nav, fp, screen))

    return signals