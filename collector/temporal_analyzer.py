"""
temporal_analyzer.py — Heartbeat rhythm analysis (v3.2)

Humans have organic heartbeat variance.
Bots: either too regular (timer) or too random (jitter simulator).

Uses coefficient of variation (CoV) of heartbeat gaps.
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
    var = sum((x - m) ** 2 for x in arr) / len(arr)
    return math.sqrt(var)


def analyze_temporal_rhythm(heartbeats, total_duration_ms):
    """
    heartbeats: list of dicts with 't_ms' and 'received_at' (datetime)
    total_duration_ms: overall session duration

    Returns list of signals.
    """
    signals = []
    if not heartbeats or len(heartbeats) < 2:
        return signals

    # Extract time deltas between heartbeats
    gaps_ms = []
    prev = None
    for hb in heartbeats:
        try:
            if isinstance(hb, dict):
                t = int(hb.get("t_ms") or 0)
            else:
                t = int(getattr(hb, "t_ms", 0) or 0)
        except (ValueError, TypeError):
            continue
        if prev is not None and t > prev:
            gaps_ms.append(t - prev)
        prev = t

    if len(gaps_ms) < 2:
        return signals

    # Filter extreme outliers (network hiccups)
    sorted_gaps = sorted(gaps_ms)
    if len(sorted_gaps) >= 4:
        p10 = sorted_gaps[max(0, len(sorted_gaps) // 10)]
        p90 = sorted_gaps[min(len(sorted_gaps) - 1, (len(sorted_gaps) * 9) // 10)]
        filtered = [g for g in gaps_ms if p10 <= g <= p90]
        if len(filtered) >= 2:
            gaps_ms = filtered

    m = _mean(gaps_ms)
    s = _std(gaps_ms)

    if m <= 0:
        return signals

    cov = s / m

    # CoV too low = timer-based bot
    if cov < 0.10:
        signals.append({
            "code": "HEARTBEAT_TOO_REGULAR",
            "severity": "high",
            "score": 65,
            "detail": f"Heartbeat CoV={cov:.3f} (timer-based bot)",
        })

    # CoV extremely high = fake randomness
    elif cov > 1.80:
        signals.append({
            "code": "HEARTBEAT_TOO_ERRATIC",
            "severity": "medium",
            "score": 35,
            "detail": f"Heartbeat CoV={cov:.2f} (synthetic jitter)",
        })

    # Perfect regularity check (all gaps within 200ms)
    if len(gaps_ms) >= 3:
        gap_range = max(gaps_ms) - min(gaps_ms)
        if gap_range < 200:
            signals.append({
                "code": "HEARTBEAT_PERFECT_TIMING",
                "severity": "high",
                "score": 70,
                "detail": f"All gaps within {gap_range}ms (impossible for human)",
            })

    # Ramp analysis (engagement pattern over time)
    if total_duration_ms > 30000 and len(heartbeats) >= 4:
        try:
            half = len(heartbeats) // 2
            first_half = heartbeats[:half]
            second_half = heartbeats[half:]

            def _sum_events(hbs):
                total = 0
                for hb in hbs:
                    if isinstance(hb, dict):
                        total += (int(hb.get("clicks") or 0) * 3
                                  + int(hb.get("scrolls") or 0) * 2
                                  + int(hb.get("mousemoves") or 0) // 10
                                  + int(hb.get("keydowns") or 0) * 3)
                    else:
                        total += (int(getattr(hb, "clicks", 0) or 0) * 3
                                  + int(getattr(hb, "scrolls", 0) or 0) * 2
                                  + int(getattr(hb, "mousemoves", 0) or 0) // 10
                                  + int(getattr(hb, "keydowns", 0) or 0) * 3)
                return total

            early = _sum_events(first_half)
            late = _sum_events(second_half)

            if early >= 10 and late == 0:
                signals.append({
                    "code": "ENGAGEMENT_COLLAPSE",
                    "severity": "high",
                    "score": 55,
                    "detail": f"Active early ({early}) then dead ({late})",
                })
        except Exception:
            pass

    return signals
