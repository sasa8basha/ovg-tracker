"""
collector/header_analyzer.py — HTTP header analysis (v4.1)

FIX in v4.1:
    - Removed HTTP_1_1_ON_HTTPS false positive
      Behind reverse proxies (Cloudflare, Netrun, Nginx, etc.) every request
      arrives as HTTP/1.1 even when the client uses HTTP/2. Emitting a signal
      for this resulted in blocking 100% of legit users.
    - Only HTTP/1.0 is flagged now (truly suspicious).
"""
import re

from collector.signals import SIGNAL_REGISTRY


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


def analyze_headers(headers, ua, http_version):
    """
    Analyze HTTP headers. Returns list of unified signals.

    NOTE: http_version reflects the connection between the reverse proxy
    and this server — NOT the client-to-proxy connection. Therefore
    HTTP/1.1 is normal and MUST NOT be flagged. Only HTTP/1.0 is suspicious.
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
    # H-02: Electron apps use Chrome UA but typically omit sec-ch-ua
    is_electron = "electron" in ua_lower

    chrome_major = 0
    m = re.search(r"chrome/(\d+)", ua_lower)
    if m:
        try:
            chrome_major = int(m.group(1))
        except (ValueError, TypeError):
            chrome_major = 0

    # ===== 1) Chrome/Edge >= 90 should send sec-ch-ua =====
    # H-01 FIX: sec-ch-ua is HTTPS-only; skip on plain HTTP
    proto = (h.get("x-forwarded-proto") or h.get("x-forwarded-protocol") or "").lower()
    is_https = proto == "https" or h.get("cf-visitor", "").find("https") >= 0
    if (is_chrome or is_edge) and chrome_major >= 90 and not is_ios and is_https and not is_electron:
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

    # ===== 4) HTTP version check — ONLY flag 1.0 now =====
    # FIX v4.1: HTTP/1.1 is the normal case behind any reverse proxy
    # (Cloudflare, Netrun, Nginx, HAProxy, AWS ELB...). The `http_version`
    # from uvicorn reflects proxy→server, not client→proxy.
    # Flagging HTTP/1.1 caused 100% false positive on all legit users.
    hv = str(http_version or "").strip()
    if hv == "1.0" and (is_chrome or is_firefox or is_safari or is_edge):
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
    if headers is None:
        return ""
    try:
        if hasattr(headers, "get"):
            v = headers.get("user-agent") or headers.get("User-Agent")
            return str(v) if v else ""
    except Exception:
        pass
    return ""