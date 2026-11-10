"""
collector/temporal_analyzer.py — Heartbeat rhythm analysis (v4.1)

v4.1 FIX:
  - `_sum_events` now ignores heartbeats with `is_visible=False`.
    After the tracker fix (v8.5), users who minimize/switch tabs will
    send hidden heartbeats with zero events. Without this filter, the
    late-half of such sessions would register 0 events, tripping
    ENGAGEMENT_COLLAPSE for real users.

Humans have organic heartbeat variance.
Bots: either too regular (timer) or too random (jitter simulator).

Produces signals in the unified format.
Uses coefficient of variation (CoV) of heartbeat gaps.
"""
import math

from collector.signals import SIGNAL_REGISTRY


# =========================================================
# HELPERS
# =========================================================
def _mean(arr):
    return sum(arr) / len(arr) if arr else 0.0


def _std(arr):
    if len(arr) < 2:
        return 0.0
    m = _mean(arr)
    return math.sqrt(sum((x - m) ** 2 for x in arr) / len(arr))


def _base(code: str, default: float = 0.5) -> float:
    reg = SIGNAL_REGISTRY.get(code)
    if reg:
        try:
            return float(reg.get("base", default))
        except (ValueError, TypeError):
            return default
    return default


def _severity(code: str, default: str = "medium") -> str:
    reg = SIGNAL_REGISTRY.get(code)
    if reg:
        return str(reg.get("sev", default))
    return default


def _make_signal(code: str, detail: str, default_sev: str = "medium") -> dict:
    """Build a unified signal dict for temporal findings."""
    sev = _severity(code, default_sev)
    strength = _base(code, 0.5)
    return {
        "code": code,
        "severity": sev,
        "direction": "bot",
        "category": "session",
        "base_strength": strength,
        "score": int(round(strength * 100)),
        "detail": detail[:200],
    }


def _extract_gaps(heartbeats) -> list:
    """Extract time deltas between heartbeats (ms)."""
    gaps_ms = []
    prev = None
    for hb in heartbeats or []:
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
    return gaps_ms


def _sum_events(hbs) -> int:
    """
    Weighted event sum across heartbeat samples.

    v4.1 FIX: Ignore heartbeats where `is_visible=False`.
      When a user minimizes or switches tabs, the tracker sends a
      "hidden" heartbeat with zero event counts. Without this filter,
      any user who leaves the tab for >30s would register as
      ENGAGEMENT_COLLAPSE (high severity, 0.55).
    """
    total = 0
    for hb in hbs or []:
        if isinstance(hb, dict):
            if not hb.get("is_visible", True):
                continue
            total += (
                int(hb.get("clicks") or 0) * 3
                + int(hb.get("scrolls") or 0) * 2
                + int(hb.get("mousemoves") or 0) // 10
                + int(hb.get("keydowns") or 0) * 3
            )
        else:
            # Handle ORM objects
            try:
                is_visible = getattr(hb, "is_visible", True)
                if not is_visible:
                    continue
            except Exception:
                pass
            total += (
                int(getattr(hb, "clicks", 0) or 0) * 3
                + int(getattr(hb, "scrolls", 0) or 0) * 2
                + int(getattr(hb, "mousemoves", 0) or 0) // 10
                + int(getattr(hb, "keydowns", 0) or 0) * 3
            )
    return total


# =========================================================
# MAIN ANALYZER
# =========================================================
def analyze_temporal_rhythm(heartbeats, total_duration_ms):
    """
    Analyze heartbeat gap rhythm. Returns unified signals.

    heartbeats: list of dicts with 't_ms' and 'is_visible'
    total_duration_ms: overall session duration
    """
    signals = []
    if not heartbeats or len(heartbeats) < 2:
        return signals

    gaps_ms = _extract_gaps(heartbeats)
    # C-13 FIX: need at least 4 gaps for stable CoV; 2 gaps → random FP on short sessions
    if len(gaps_ms) < 4:
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

    # ---------- BOT signals ----------
    # v8.5: with jitter ±4000ms, human CoV is ~0.23 (raw) / ~0.18 (filtered).
    # Threshold 0.10 only catches bots with near-perfect timers.
    if cov < 0.10:
        signals.append(_make_signal(
            "HEARTBEAT_TOO_REGULAR",
            f"Heartbeat CoV={cov:.3f} (timer-based bot)",
        ))
    elif cov > 1.80:
        signals.append(_make_signal(
            "HEARTBEAT_TOO_ERRATIC",
            f"Heartbeat CoV={cov:.2f} (synthetic jitter)",
        ))

    if len(gaps_ms) >= 3:
        gap_range = max(gaps_ms) - min(gaps_ms)
        if gap_range < 200:
            signals.append(_make_signal(
                "HEARTBEAT_PERFECT_TIMING",
                f"All gaps within {gap_range}ms (impossible for human)",
            ))

    # ---------- Engagement collapse ----------
    try:
        duration = int(total_duration_ms or 0)
    except (ValueError, TypeError):
        duration = 0

    # H-16 FIX: reading an article can look like collapse; require longer session + stronger early activity
    if duration >= 60000 and len(heartbeats) >= 4:
        half = len(heartbeats) // 2
        first_half = heartbeats[:half]
        second_half = heartbeats[half:]
        early = _sum_events(first_half)
        late = _sum_events(second_half)
        if early >= 30 and late == 0:
            signals.append(_make_signal(
                "ENGAGEMENT_COLLAPSE",
                f"Active early ({early}) then dead ({late})",
            ))

    return signals