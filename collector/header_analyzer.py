"""
header_analyzer.py — HTTP header analysis (v3.2)

Pre-JS layer — cannot be spoofed easily.
Checks:
  - UA vs sec-ch-ua consistency
  - Missing sec-fetch-* headers
  - HTTP/1.1 over HTTPS
  - Accept-Encoding patterns
  - Contradictions (Firefox + sec-ch-ua)
"""
import re


def analyze_headers(headers, ua, http_version):
    """
    headers: dict (lowercase keys) or Starlette Headers
    ua: user agent string
    http_version: "1.0" | "1.1" | "2" | "2.0"
    """
    if headers is None:
        headers = {}
    if hasattr(headers, "items"):
        try:
            h = {str(k).lower(): str(v) for k, v in headers.items()}
        except Exception:
            h = {}
    elif isinstance(headers, dict):
        h = {str(k).lower(): str(v) for k, v in headers.items()}
    else:
        h = {}

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

    # ===== 1) Chrome/Edge >= 90 should send sec-ch-ua =====
    if (is_chrome or is_edge) and chrome_major >= 90 and not is_ios:
        if "sec-ch-ua" not in h:
            signals.append({
                "code": "MISSING_SEC_CH_UA",
                "severity": "high",
                "score": 70,
                "detail": f"Chrome {chrome_major}+ missing sec-ch-ua header",
            })
        else:
            sec_ch = h.get("sec-ch-ua", "").lower()
            if f'v="{chrome_major}"' not in sec_ch and f"v={chrome_major}" not in sec_ch:
                if not (chrome_major >= 130 and str(chrome_major)[:2] in sec_ch):
                    signals.append({
                        "code": "SEC_CH_UA_VERSION_MISMATCH",
                        "severity": "high",
                        "score": 80,
                        "detail": f"UA Chrome {chrome_major}, sec-ch-ua: {sec_ch[:60]}",
                    })

        # sec-fetch-mode should always be present (Chrome 80+)
        if "sec-fetch-mode" not in h:
            signals.append({
                "code": "MISSING_SEC_FETCH",
                "severity": "medium",
                "score": 45,
                "detail": "Chrome missing sec-fetch-mode header",
            })

        # Accept-Encoding should include br
        ae = h.get("accept-encoding", "").lower()
        if ae and "br" not in ae and "zstd" not in ae:
            signals.append({
                "code": "ACCEPT_ENCODING_ODD",
                "severity": "medium",
                "score": 40,
                "detail": f"Chrome Accept-Encoding without br/zstd: {ae[:50]}",
            })

        # DNT on Chrome (Firefox thing)
        if h.get("dnt") == "1":
            signals.append({
                "code": "DNT_ON_CHROME",
                "severity": "low",
                "score": 20,
                "detail": "Chrome + DNT:1 (unusual)",
            })

    # ===== 2) Firefox should NOT send sec-ch-ua =====
    if is_firefox and "sec-ch-ua" in h:
        signals.append({
            "code": "SEC_CH_UA_ON_FIREFOX",
            "severity": "high",
            "score": 70,
            "detail": "Firefox UA + sec-ch-ua present (contradiction)",
        })

    # ===== 3) Safari should NOT send sec-ch-ua =====
    if is_safari and not is_ios and "sec-ch-ua" in h:
        signals.append({
            "code": "SEC_CH_UA_ON_SAFARI",
            "severity": "high",
            "score": 70,
            "detail": "Safari UA + sec-ch-ua present (contradiction)",
        })

    # ===== 4) HTTP version check =====
    hv = str(http_version or "").strip()
    is_https_likely = h.get("x-forwarded-proto", "").lower() == "https" or True
    if hv in ("1.0", "1.1") and (is_chrome or is_firefox or is_safari or is_edge):
        signals.append({
            "code": "HTTP_1_1_ON_HTTPS",
            "severity": "medium",
            "score": 35,
            "detail": f"Modern browser using HTTP/{hv} (bot likely)",
        })

    # ===== 5) sec-ch-ua-mobile vs UA =====
    if "sec-ch-ua-mobile" in h:
        scm = h["sec-ch-ua-mobile"].strip()
        if scm == "?0" and is_mobile and not is_ios:
            signals.append({
                "code": "SEC_CH_UA_MOBILE_MISMATCH",
                "severity": "medium",
                "score": 40,
                "detail": "UA says mobile, sec-ch-ua-mobile=?0",
            })
        elif scm == "?1" and not is_mobile:
            signals.append({
                "code": "SEC_CH_UA_MOBILE_MISMATCH",
                "severity": "medium",
                "score": 40,
                "detail": "UA says desktop, sec-ch-ua-mobile=?1",
            })

    # ===== 6) Missing Accept-Language =====
    if not is_mobile and is_chrome and chrome_major >= 90:
        if "accept-language" not in h:
            signals.append({
                "code": "MISSING_ACCEPT_LANGUAGE",
                "severity": "medium",
                "score": 35,
                "detail": "Chrome missing Accept-Language header",
            })

    # ===== 7) User-Agent header missing =====
    if "user-agent" not in h:
        signals.append({
            "code": "MISSING_USER_AGENT_HEADER",
            "severity": "high",
            "score": 60,
            "detail": "No User-Agent HTTP header (not a real browser)",
        })

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
