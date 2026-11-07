"""
_shared.py — Helpers مشتركة بين سكريبتات Phase 0.
"""
import json
from pathlib import Path


def load_json(path, default=None):
    p = Path(path)
    if not p.exists():
        return default
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def safe_div(a, b, default=None):
    return a / b if b > 0 else default


def normalize_evidence(evidence):
    """
    evidence ممكن يكون list of dicts (v3) أو list of strings (legacy).
    بيرجع list of dicts مرتبة بالأهمية.
    """
    if not evidence:
        return []
    result = []
    for e in evidence:
        if isinstance(e, dict):
            try:
                score = int(e.get("score", 0) or 0)
            except (ValueError, TypeError):
                score = 0
            result.append({
                "code": str(e.get("code", "UNKNOWN"))[:50],
                "severity": str(e.get("severity", "medium"))[:20],
                "score": score,
                "detail": str(e.get("detail", ""))[:200],
            })
        elif isinstance(e, str):
            result.append({
                "code": "LEGACY_SIGNAL",
                "severity": "medium",
                "score": 0,
                "detail": e[:200],
            })
    result.sort(key=lambda x: abs(x["score"]), reverse=True)
    return result


def country_flag(code):
    if not code or len(code) != 2:
        return "🏴"
    code = code.upper()
    return chr(0x1F1E6 + ord(code[0]) - ord("A")) + chr(0x1F1E6 + ord(code[1]) - ord("A"))
