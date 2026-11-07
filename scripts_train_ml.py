"""
scripts/train_ml.py — Train the ML model from labeled visits.

Usage:
    python -m scripts.train_ml
    python -m scripts.train_ml --epochs 1000 --lr 0.05
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Train ML bot-detection model")
    parser.add_argument("--epochs", type=int, default=500)
    parser.add_argument("--lr", type=float, default=0.1)
    parser.add_argument("--l2", type=float, default=0.01)
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--limit", type=int, default=50000)
    args = parser.parse_args()

    try:
        from database import SessionLocal
        from models import VisitModel
        from collector.ml_engine import train_from_visits, save_model
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return 1

    db = SessionLocal()
    try:
        total = db.query(VisitModel).filter(VisitModel.ground_truth.isnot(None)).count()
        print(f"📊 Labeled visits in DB: {total}")

        if total < args.min_samples:
            print(f"❌ Need at least {args.min_samples} labeled visits.")
            print("   → Go to /labeling and label more visits first.")
            return 1

        visits = db.query(VisitModel).filter(
            VisitModel.ground_truth.isnot(None)
        ).order_by(VisitModel.id.desc()).limit(args.limit).all()

        print(f"🚀 Training on {len(visits)} visits (epochs={args.epochs}, lr={args.lr})...")
        model = train_from_visits(visits, epochs=args.epochs, lr=args.lr, l2=args.l2)

        if model is None:
            print("❌ Training returned None")
            return 1

        if save_model(model):
            print(f"✅ Model trained and saved")
            print(f"   Samples: {model['samples']}")
            print(f"   Features: {len(model['features'])}")
            print(f"   Intercept: {model['intercept']:.4f}")
            top = sorted(model["weights"].items(), key=lambda kv: abs(kv[1]), reverse=True)[:5]
            print(f"   Top 5 features by |weight|:")
            for name, w in top:
                print(f"     {name}: {w:+.4f}")
            print()
            print("👉 Restart the server to load the new model.")
            return 0
        else:
            print("❌ Failed to save model")
            return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())