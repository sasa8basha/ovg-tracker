"""
ground_truth_tool.py — Phase 0.2
CLI تفاعلي لتسجيل ground truth.

Usage:
    python -m scripts.ground_truth_tool
    python -m scripts.ground_truth_tool --stats
    python -m scripts.ground_truth_tool --no-color
"""
import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

from scripts._shared import load_json, save_json, normalize_evidence, country_flag

DEFAULT_INPUT = Path("data/audit_sample.json")
DEFAULT_OUTPUT = Path("data/ground_truth_v0.json")

SEVERITY_EMOJI = {
    "critical": "🚨",
    "high": "🚨",
    "medium": "⚠️",
    "low": "⚡",
    "human": "✅",
}


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"


def _c(text, color_code, enabled=True):
    return f"{color_code}{text}{C.RESET}" if enabled else str(text)


def _format_visit(visit, index, total, color=True):
    lines = []
    bar_w = 50
    filled = int(bar_w * index / total) if total else 0
    bar = "█" * filled + "░" * (bar_w - filled)

    lines.append("")
    lines.append(_c("═" * 60, C.CYAN, color))
    lines.append(_c(f"  OVG Ground Truth — Visit {index}/{total}", C.BOLD, color))
    lines.append(f"  [{bar}]")
    lines.append(_c("═" * 60, C.CYAN, color))
    lines.append("")

    cc = visit.get("country_code") or ""
    lines.append(f"  {_c('ID:', C.DIM, color)}        #{visit.get('id')}")
    lines.append(f"  {_c('Time:', C.DIM, color)}      {visit.get('timestamp', '—')}")
    lines.append(
        f"  {_c('Country:', C.DIM, color)}   {country_flag(cc)} {visit.get('country', '—')}  |  "
        f"{visit.get('isp', '—')}  |  {visit.get('asn', '—')}"
    )
    lines.append(f"  {_c('IP:', C.DIM, color)}        {visit.get('ip', '—')}")
    lines.append(
        f"  {_c('Browser:', C.DIM, color)}   {visit.get('browser', '—')}  |  "
        f"{visit.get('os', '—')}  |  {visit.get('device', '—')}"
    )
    lines.append(f"  {_c('Zone:', C.DIM, color)}      {visit.get('zone_id', '—')}")
    lines.append("")

    verdict = (visit.get("verdict") or "unknown").upper()
    score = visit.get("score", 0)
    v_color = {"INVALID": C.RED, "SUSPICIOUS": C.YELLOW, "VALID": C.GREEN}.get(verdict, C.DIM)

    lines.append("  " + _c("─" * 56, C.DIM, color))
    lines.append(
        f"  {_c('Original Verdict:', C.BOLD, color)} "
        f"{_c(verdict, v_color, color)}  (score: {score})"
    )
    lines.append("")

    evidence = normalize_evidence(visit.get("evidence"))
    if evidence:
        lines.append(f"  {_c('Top Signals:', C.BOLD, color)}")
        for e in evidence[:7]:
            emoji = SEVERITY_EMOJI.get(e["severity"], "•")
            sign = "+" if e["score"] >= 0 else ""
            code_padded = f"{e['code']:36s}"
            lines.append(
                f"    {emoji} {_c(code_padded, C.MAGENTA, color)} {sign}{e['score']:>4}  "
                f"{_c(e['detail'][:55], C.DIM, color)}"
            )
    else:
        lines.append(f"  {_c('No signals recorded', C.DIM, color)}")
    lines.append("")

    lines.append("  " + _c("─" * 56, C.DIM, color))
    lines.append(f"  {_c('Session:', C.DIM, color)}")
    top_ms = visit.get("time_on_page", 0) or 0
    lines.append(
        f"    time_on_page: {top_ms/1000:.1f}s  |  "
        f"clicks: {visit.get('clicks', 0)}  |  scrolls: {visit.get('scrolls', 0)}"
    )
    lines.append(
        f"    VPN: {visit.get('is_vpn')}  |  "
        f"WebRTC: {visit.get('webrtc_ip', 'None')}  |  "
        f"TZ: {visit.get('timezone', '—')}"
    )
    lines.append(
        f"    Canvas: {visit.get('canvas_hash', '—')}  |  "
        f"HW: {visit.get('hardware', '—')}"
    )
    lines.append("")
    lines.append(_c("═" * 60, C.CYAN, color))
    lines.append("")
    lines.append(
        f"  {_c('[H]', C.GREEN, color)} Human    "
        f"{_c('[B]', C.RED, color)} Bot    "
        f"{_c('[U]', C.YELLOW, color)} Unknown    "
        f"{_c('[S]', C.DIM, color)} Skip    "
        f"{_c('[Q]', C.DIM, color)} Quit"
    )
    lines.append("")
    return "\n".join(lines)


def _prompt(color=True):
    try:
        return input(_c("  > ", C.BOLD, color)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "q"


def _save_state(output_path, input_data, labels, auditor):
    visits_by_id = {v["id"]: v for v in input_data["visits"]}

    enriched = []
    for label in labels:
        visit = visits_by_id.get(label["visit_id"])
        if not visit:
            continue
        enriched.append({
            **label,
            "original_verdict": visit.get("verdict"),
            "original_score": visit.get("score"),
            "original_evidence_count": len(visit.get("evidence", []) or []),
        })

    state = {
        "version": "0.1",
        "created_at": input_data.get("created_at"),
        "updated_at": datetime.utcnow().isoformat(),
        "auditor": auditor,
        "period": input_data.get("period"),
        "seed": input_data.get("seed"),
        "counts": {
            "total": input_data["total"],
            "labeled": len(labels),
            "remaining": input_data["total"] - len(labels),
        },
        "labels": enriched,
    }
    save_json(output_path, state)


def _print_stats(output_path, input_data, color=True):
    data = load_json(output_path, None)
    if not data:
        print("  مفيش ملف ground truth لسه.")
        print("  ابدأ بـ: python -m scripts.ground_truth_tool")
        return

    labels = data.get("labels", [])
    label_counts = Counter(l["label"] for l in labels)

    print()
    print(_c("═" * 60, C.CYAN, color))
    print(_c("  Ground Truth Stats", C.BOLD, color))
    print(_c("═" * 60, C.CYAN, color))
    print(f"  Total in sample:  {input_data.get('total', '?')}")
    print(f"  Labeled:          {len(labels)}")
    print(f"  Remaining:        {input_data.get('total', 0) - len(labels)}")
    print()
    print(_c("  Labels:", C.BOLD, color))
    for label, count in label_counts.most_common():
        print(f"    {label:<10}  {count}")
    print()
    print(_c("  Original verdict × label:", C.BOLD, color))
    print(f"    {'Verdict':<12} {'human':>6} {'bot':>6} {'unknown':>8}")
    for verdict in ("invalid", "suspicious", "valid", "unknown"):
        h = sum(1 for l in labels if l.get("original_verdict") == verdict and l["label"] == "human")
        b = sum(1 for l in labels if l.get("original_verdict") == verdict and l["label"] == "bot")
        u = sum(1 for l in labels if l.get("original_verdict") == verdict and l["label"] == "unknown")
        if h + b + u > 0:
            print(f"    {verdict:<12} {h:>6} {b:>6} {u:>8}")
    print(_c("═" * 60, C.CYAN, color))
    print()


def main():
    parser = argparse.ArgumentParser(description="CLI لتسجيل ground truth")
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--auditor", default="admin", help="اسم المراجع")
    parser.add_argument("--stats", action="store_true", help="اطبع إحصائيات فقط")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    color = (not args.no_color) and sys.stdout.isatty()
    input_path = Path(args.input)
    output_path = Path(args.output)

    input_data = load_json(input_path, None)
    if not input_data:
        print(f"  ❌ ملف العينة مش موجود: {input_path}")
        print("  شغّل أول: python -m scripts.baseline_audit")
        sys.exit(1)

    if args.stats:
        _print_stats(output_path, input_data, color=color)
        return

    existing = load_json(output_path, None)
    labels = existing.get("labels", []) if existing else []
    labeled_ids = {l["visit_id"] for l in labels}
    remaining = [v for v in input_data["visits"] if v["id"] not in labeled_ids]

    if not remaining:
        print(_c("  🎉 كل الزيارات اتصنفت!", C.GREEN, color))
        _print_stats(output_path, input_data, color=color)
        print("  👉 الخطوة التالية: python -m scripts.compute_baseline_metrics")
        return

    print()
    print(_c(f"  📋 متبقي {len(remaining)} زيارة من أصل {input_data['total']}", C.BOLD, color))
    print(_c("  💾 حفظ تلقائي كل 10 زيارات + عند الخروج", C.DIM, color))
    print()

    processed = 0
    for visit in remaining:
        index = len(labels) + 1
        total = input_data["total"]

        print(_format_visit(visit, index, total, color=color))

        while True:
            choice = _prompt(color)
            if choice in ("h", "human"):
                labels.append({
                    "visit_id": visit["id"],
                    "label": "human",
                    "labeled_at": datetime.utcnow().isoformat(),
                })
                break
            elif choice in ("b", "bot"):
                labels.append({
                    "visit_id": visit["id"],
                    "label": "bot",
                    "labeled_at": datetime.utcnow().isoformat(),
                })
                break
            elif choice in ("u", "unknown"):
                labels.append({
                    "visit_id": visit["id"],
                    "label": "unknown",
                    "labeled_at": datetime.utcnow().isoformat(),
                })
                break
            elif choice in ("s", "skip"):
                break
            elif choice in ("q", "quit"):
                _save_state(output_path, input_data, labels, args.auditor)
                print()
                print(_c(f"  💾 تم حفظ {len(labels)} تصنيف", C.GREEN, color))
                print(_c("  ✅ كمّل بعدين بنفس الأمر", C.GREEN, color))
                return
            else:
                print(_c("  ❌ اختيار غير صحيح. H/B/U/S/Q فقط", C.RED, color))

        processed += 1
        if processed % 10 == 0:
            _save_state(output_path, input_data, labels, args.auditor)
            print(_c(f"  💾 auto-saved ({len(labels)}/{total})", C.DIM, color))

    _save_state(output_path, input_data, labels, args.auditor)
    print()
    print(_c("═" * 60, C.GREEN, color))
    print(_c(f"  🎉 خلصت كل الزيارات! إجمالي {len(labels)} تصنيف", C.BOLD, color))
    print(_c("═" * 60, C.GREEN, color))
    print()
    print(_c("  👉 الخطوة التالية:", C.BOLD, color))
    print("     python -m scripts.compute_baseline_metrics")
    print()


if __name__ == "__main__":
    main()
