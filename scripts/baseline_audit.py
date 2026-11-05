"""
baseline_audit.py — Phase 0.1
سحب عينة stratified من الزيارات للمراجعة اليدوية.

Usage:
    python -m scripts.baseline_audit
    python -m scripts.baseline_audit --invalid 200 --valid 200 --suspicious 100
    python -m scripts.baseline_audit --from-date 2025-10-01 --seed 42
"""
import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

from database import SessionLocal
from models import VisitModel
from scripts._shared import save_json

DEFAULT_OUTPUT = Path("data/audit_sample.json")
DEFAULT_SEED = 42


def _pick_sample(session, verdict, count, start, end, seed):
    """عينة deterministic (reproducible) لكل verdict."""
    query = session.query(VisitModel).filter(
        VisitModel.verdict == verdict,
        VisitModel.timestamp >= start,
        VisitModel.timestamp <= end,
    )
    total = query.count()
    if total < count:
        print(f"  ⚠️  verdict='{verdict}': مطلوب {count}، متاح {total}. هناخد الكل.")
        count = total
    if count <= 0:
        return []

    rng = random.Random(seed + hash(verdict))
    max_offset = max(0, total - count)
    offset = rng.randint(0, max_offset)

    return query.order_by(VisitModel.id).offset(offset).limit(count).all()


def _visit_to_dict(v):
    return {
        "id": v.id,
        "timestamp": v.timestamp.isoformat() if v.timestamp else None,
        "ip": v.ip,
        "country": v.country,
        "country_code": v.country_code,
        "isp": v.isp,
        "asn": v.asn,
        "zone_id": v.zone_id,
        "user_agent": v.user_agent,
        "os": v.os,
        "browser": v.browser,
        "device": v.device,
        "score": v.score,
        "verdict": v.verdict,
        "evidence": v.evidence or [],
        "time_on_page": v.time_on_page,
        "clicks": v.clicks,
        "scrolls": v.scrolls,
        "is_vpn": bool(v.is_vpn),
        "webrtc_ip": v.webrtc_ip,
        "timezone": v.timezone,
        "canvas_hash": v.canvas_hash,
        "hardware": v.hardware,
        "connection_type": v.connection_type,
        "original_ground_truth": v.ground_truth,
    }


def main():
    parser = argparse.ArgumentParser(description="سحب عينة للمراجعة اليدوية")
    parser.add_argument("--from-date", default=None, help="YYYY-MM-DD (افتراضي: قبل 30 يوم)")
    parser.add_argument("--to-date", default=None, help="YYYY-MM-DD (افتراضي: النهارده)")
    parser.add_argument("--invalid", type=int, default=200)
    parser.add_argument("--valid", type=int, default=200)
    parser.add_argument("--suspicious", type=int, default=100)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    if args.from_date:
        start = datetime.strptime(args.from_date, "%Y-%m-%d")
    else:
        start = datetime.utcnow() - timedelta(days=30)

    if args.to_date:
        end = datetime.strptime(args.to_date, "%Y-%m-%d") + timedelta(days=1)
    else:
        end = datetime.utcnow()

    print()
    print("═" * 60)
    print("  OVG Baseline Audit — Phase 0.1")
    print("═" * 60)
    print(f"  📅 الفترة:  {start.date()} → {end.date()}")
    print(f"  🎯 العينة:  {args.invalid} invalid + {args.valid} valid + {args.suspicious} suspicious")
    print(f"  🎲 Seed:    {args.seed}")
    print("═" * 60)
    print()

    session = SessionLocal()
    try:
        samples = {
            "invalid": _pick_sample(session, "invalid", args.invalid, start, end, args.seed),
            "valid": _pick_sample(session, "valid", args.valid, start, end, args.seed),
            "suspicious": _pick_sample(session, "suspicious", args.suspicious, start, end, args.seed),
        }
    finally:
        session.close()

    total = sum(len(v) for v in samples.values())
    if total == 0:
        print("  ❌ مفيش زيارات في الفترة دي. وسّع الفترة بـ --from-date")
        sys.exit(1)

    all_visits = []
    for verdict, visits in samples.items():
        for v in visits:
            d = _visit_to_dict(v)
            d["_sample_group"] = verdict
            all_visits.append(d)

    random.Random(args.seed).shuffle(all_visits)

    output_data = {
        "version": "0.1",
        "created_at": datetime.utcnow().isoformat(),
        "period": {"from": start.isoformat(), "to": end.isoformat()},
        "seed": args.seed,
        "counts": {k: len(v) for k, v in samples.items()},
        "total": total,
        "visits": all_visits,
    }

    save_json(args.output, output_data)

    print(f"  ✅ تم حفظ {total} زيارة في: {args.output}")
    print(f"     - invalid:    {len(samples['invalid'])}")
    print(f"     - valid:      {len(samples['valid'])}")
    print(f"     - suspicious: {len(samples['suspicious'])}")
    print()
    print("  👉 الخطوة التالية:")
    print("     python -m scripts.ground_truth_tool")
    print()


if __name__ == "__main__":
    main()
