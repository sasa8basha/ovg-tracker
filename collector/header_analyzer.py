"""
collector/header_analyzer.py — HTTP header analysis (v4.0)

Pre-JS layer — cannot be spoofed easily.
Produces signals in the new unified format:
    {
        "code", "severity", "direction", "category",
        "base_strength",   # from SIGNAL_REGISTRY
        "score",           # legacy compat (positive int)
        "detail"
    }

Checks:
  - UA vs sec-ch-ua consistency
  - Missing sec-fetch-* headers
  - HTTP/1.0 over HTTPS
  - Accept-Encoding patterns
  - Contradictions (Firefox + sec-ch-ua, Safari + sec-ch-ua)
"""
import re

from collector.signals import SIGNAL_REGISTRY


# =========================================================
# HELPERS
# =========================================================
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
    """Build a unified signal dict for header findings."""
    sev = _severity(code, default_sev)
    strength = _base(code, 0.5)
    return {
        "code": code,
        "severity": sev,
        "direction": "bot",
        "category": "headers",
        "base_strength": strength,
        "score": int(round(strength * 100)),
        "detail": detail[:200],
    }


def _normalize_headers(headers) -> dict:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        try:
            return {str(k).lower(): str(v) for k, v in headers.items()}
        except Exception:
            return {}
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    return {}


# =========================================================
# MAIN ANALYZER
# =========================================================
def analyze_headers(headers, ua, http_version):
    """
    Analyze HTTP headers. Returns list of unified signals.
    """
    h = _normalize_headers(headers)
    ua_lower = (ua or "").lower()
    signals = []

    is_chrome = ("chrome" in ua_lower or "chromium" in ua_lower) and "edg/" not in ua_lower
    is_edge = "edg/" in ua_lower
    is_firefox = "firefox" in ua_lower
    is_safari = "safari" in ua_lower and "chrome" not in ua_lower
    is_mobile = "mobile" in ua_lower or "android" in ua_lower
    is_ios = "iphone" in ua_lower or "ipad" in ua_lower

    chrome_major = 0
    m = re.search(r"chrome/(\d+)", ua_lower)
    if m:
        try:
            chrome_major = int(m.group(1))
        except (ValueError, TypeError):
            chrome_major = 0

    # ===== 1) Chrome/Edge ≥ 90 should send sec-ch-ua =====
    if (is_chrome or is_edge) and chrome_major >= 90 and not is_ios:
        if "sec-ch-ua" not in h:
            signals.append(_make_signal(
                "MISSING_SEC_CH_UA",
                f"Chrome {chrome_major}+ missing sec-ch-ua header",
            ))
        else:
            sec_ch = h.get("sec-ch-ua", "").lower()
            if f'v="{chrome_major}"' not in sec_ch and f"v={chrome_major}" not in sec_ch:
                if not (chrome_major >= 130 and str(chrome_major)[:2] in sec_ch):
                    signals.append(_make_signal(
                        "SEC_CH_UA_VERSION_MISMATCH",
                        f"UA Chrome {chrome_major}, sec-ch-ua: {sec_ch[:60]}",
                    ))

        if "sec-fetch-mode" not in h:
            signals.append(_make_signal(
                "MISSING_SEC_FETCH",
                "Chrome missing sec-fetch-mode header",
            ))

        ae = h.get("accept-encoding", "").lower()
        if ae and "br" not in ae and "zstd" not in ae:
            signals.append(_make_signal(
                "ACCEPT_ENCODING_ODD",
                f"Chrome Accept-Encoding without br/zstd: {ae[:50]}",
            ))

        if h.get("dnt") == "1":
            signals.append(_make_signal(
                "DNT_ON_CHROME",
                "Chrome + DNT:1 (unusual)",
            ))

    # ===== 2) Firefox should NOT send sec-ch-ua =====
    if is_firefox and "sec-ch-ua" in h:
        signals.append(_make_signal(
            "SEC_CH_UA_ON_FIREFOX",
            "Firefox UA + sec-ch-ua present (contradiction)",
        ))

    # ===== 3) Safari should NOT send sec-ch-ua =====
    if is_safari and not is_ios and "sec-ch-ua" in h:
        signals.append(_make_signal(
            "SEC_CH_UA_ON_SAFARI",
            "Safari UA + sec-ch-ua present (contradiction)",
        ))

    # ===== 4) HTTP version check =====
    hv = str(http_version or "").strip()
    if hv in ("1.0", "1.1") and (is_chrome or is_firefox or is_safari or is_edge):
        signals.append(_make_signal(
            "HTTP_1_1_ON_HTTPS",
            f"Modern browser using HTTP/{hv} (bot likely)",
        ))

    # ===== 5) sec-ch-ua-mobile vs UA =====
    if "sec-ch-ua-mobile" in h:
        scm = h["sec-ch-ua-mobile"].strip()
        if scm == "?0" and is_mobile and not is_ios:
            signals.append(_make_signal(
                "SEC_CH_UA_MOBILE_MISMATCH",
                "UA says mobile, sec-ch-ua-mobile=?0",
            ))
        elif scm == "?1" and not is_mobile:
            signals.append(_make_signal(
                "SEC_CH_UA_MOBILE_MISMATCH",
                "UA says desktop, sec-ch-ua-mobile=?1",
            ))

    # ===== 6) Missing Accept-Language =====
    if not is_mobile and is_chrome and chrome_major >= 90:
        if "accept-language" not in h:
            signals.append(_make_signal(
                "MISSING_ACCEPT_LANGUAGE",
                "Chrome missing Accept-Language header",
            ))

    # ===== 7) User-Agent header missing =====
    if "user-agent" not in h:
        signals.append(_make_signal(
            "MISSING_USER_AGENT_HEADER",
            "No User-Agent HTTP header (not a real browser)",
        ))

    return signals


def get_ua_from_headers(headers):
    """Extract UA from headers (fallback if JS didn't send)."""
    if headers is None:
        return ""
    try:
        if hasattr(headers, "get"):
            v = headers.get("user-agent") or headers.get("User-Agent")
            return str(v) if v else ""
    except Exception:
        pass
    return ""