"""
compute_baseline_metrics.py — Phase 0.3
حساب TPR/FPR/F1 من ground truth مقابل verdicts الحالية.

Usage:
    python -m scripts.compute_baseline_metrics
    python -m scripts.compute_baseline_metrics --output data/baseline_metrics_v0.json
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

from scripts._shared import load_json, save_json, safe_div

DEFAULT_GROUND_TRUTH = Path("data/ground_truth_v0.json")
DEFAULT_OUTPUT = Path("data/baseline_metrics_v0.json")


def compute_metrics(labels):
    usable = [l for l in labels if l["label"] in ("human", "bot")]
    excluded = [l for l in labels if l["label"] == "unknown"]

    tp = fp = tn = fn = 0
    for l in usable:
        original = (l.get("original_verdict") or "").lower()
        predicted_bot = original == "invalid"
        actual_bot = l["label"] == "bot"

        if predicted_bot and actual_bot:
            tp += 1
        elif predicted_bot and not actual_bot:
            fp += 1
        elif not predicted_bot and actual_bot:
            fn += 1
        else:
            tn += 1

    total = len(usable)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall) if (precision is not None and recall is not None) else None
    fpr = safe_div(fp, fp + tn)
    accuracy = safe_div(tp + tn, total)
    specificity = safe_div(tn, tn + fp)

    invalid_sample = [l for l in usable if (l.get("original_verdict") or "").lower() == "invalid"]
    invalid_precision = safe_div(
        sum(1 for l in invalid_sample if l["label"] == "bot"),
        len(invalid_sample),
    )
    valid_sample = [l for l in usable if (l.get("original_verdict") or "").lower() == "valid"]
    valid_precision = safe_div(
        sum(1 for l in valid_sample if l["label"] == "human"),
        len(valid_sample),
    )

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "sample_sizes": {
            "total_labeled": len(labels),
            "usable": total,
            "excluded_unknown": len(excluded),
            "invalid_sample": len(invalid_sample),
            "valid_sample": len(valid_sample),
        },
        "metrics": {
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "fpr": round(fpr, 4) if fpr is not None else None,
            "specificity": round(specificity, 4) if specificity is not None else None,
            "accuracy": round(accuracy, 4) if accuracy is not None else None,
            "invalid_precision": round(invalid_precision, 4) if invalid_precision is not None else None,
            "valid_precision": round(valid_precision, 4) if valid_precision is not None else None,
        },
    }


def _pct(value):
    if value is None:
        return "—"
    return f"{value * 100:.2f}%"


def _diagnose(metrics):
    out = []
    f1 = metrics["f1"]
    precision = metrics["precision"]
    recall = metrics["recall"]
    fpr = metrics["fpr"]

    if f1 is not None:
        if f1 >= 0.95:
            out.append(("✅", f"F1 = {_pct(f1)} — ممتاز"))
        elif f1 >= 0.85:
            out.append(("👍", f"F1 = {_pct(f1)} — جيد، يحتاج تحسين"))
        elif f1 >= 0.70:
            out.append(("⚠️", f"F1 = {_pct(f1)} — متوسط، يحتاج عمل"))
        else:
            out.append(("🚨", f"F1 = {_pct(f1)} — ضعيف جداً، Collector v3 إجباري"))

    if fpr is not None:
        if fpr <= 0.01:
            out.append(("✅", f"FPR = {_pct(fpr)} — تحت 1%، ممتاز"))
        elif fpr <= 0.05:
            out.append(("⚠️", f"FPR = {_pct(fpr)} — فوق 1%، بشر بيتحظروا غلط"))
        else:
            out.append(("🚨", f"FPR = {_pct(fpr)} — فوق 5%، خطر حظر كبير"))

    if recall is not None and recall < 0.90:
        out.append(("⚠️", f"Recall = {_pct(recall)} — بيسيب بوتات كتير تعدي"))

    if precision is not None and precision < 0.85:
        out.append(("⚠️", f"Precision = {_pct(precision)} — false positives كتير"))

    return out


def _print_report(result, filename):
    cm = result["confusion_matrix"]
    s = result["sample_sizes"]
    m = result["metrics"]

    print()
    print("═" * 60)
    print("  BASELINE METRICS (v0)")
    print("═" * 60)
    print(f"  Source: {filename}")
    print(f"  Generated: {result['generated_at']}")
    print()
    print("  📊 Sample:")
    print(f"     Total labeled:      {s['total_labeled']}")
    print(f"     Usable (h/b):       {s['usable']}")
    print(f"     Excluded (unknown): {s['excluded_unknown']}")
    print(f"     invalid sample:     {s['invalid_sample']}")
    print(f"     valid sample:       {s['valid_sample']}")
    print()
    print("  📋 Confusion Matrix:")
    print(f"                       Predicted Bot    Predicted Not-Bot")
    print(f"     Actual Bot        TP = {cm['tp']:<10}  FN = {cm['fn']}")
    print(f"     Actual Human      FP = {cm['fp']:<10}  TN = {cm['tn']}")
    print()
    print("  🎯 Metrics:")
    print(f"     Precision:          {_pct(m['precision'])}")
    print(f"     Recall (TPR):       {_pct(m['recall'])}")
    print(f"     F1 Score:           {_pct(m['f1'])}")
    print(f"     FPR:                {_pct(m['fpr'])}")
    print(f"     Specificity:        {_pct(m['specificity'])}")
    print(f"     Accuracy:           {_pct(m['accuracy'])}")
    print()
    print("  🔍 Sub-metrics:")
    print(f"     invalid precision:  {_pct(m['invalid_precision'])}  (كام من invalid هم فعلاً بوت)")
    print(f"     valid precision:    {_pct(m['valid_precision'])}  (كام من valid هم فعلاً بشر)")
    print()
    print("  🩺 Diagnosis:")
    for emoji, text in _diagnose(result["metrics"]):
        print(f"     {emoji}  {text}")
    print()
    print("═" * 60)
    print()


def main():
    parser = argparse.ArgumentParser(description="حساب TPR/FPR من ground truth")
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    gt_path = Path(args.ground_truth)
    data = load_json(gt_path, None)
    if not data:
        print(f"  ❌ ملف ground truth مش موجود: {gt_path}")
        print("  شغّل أول: python -m scripts.ground_truth_tool")
        sys.exit(1)

    labels = data.get("labels", [])
    if not labels:
        print("  ❌ مفيش تصنيفات. شغّل: python -m scripts.ground_truth_tool")
        sys.exit(1)

    result = compute_metrics(labels)
    result["generated_at"] = datetime.utcnow().isoformat()
    result["source"] = str(gt_path)

    save_json(args.output, result)
    _print_report(result, gt_path.name)

    print(f"  💾 Report saved to: {args.output}")
    print()
    print("  👉 الخطوة التالية:")
    print("     قول لي إنك خلصت Phase 0، وأنا أبدأ Phase 0.5 (Campaign Foundation)")
    print()


if __name__ == "__main__":
    main()
