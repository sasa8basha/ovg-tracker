from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =========================================================
# SAFE MIGRATIONS — runs before create_all
# =========================================================
_MIGRATIONS = {
    "visits": {
        "full_payload":        "JSON",
        "confidence":          "FLOAT",
        "bot_probability":     "FLOAT",
        "mode":                "VARCHAR(20)",
        "reason":              "VARCHAR(100)",
        "data_quality_report": "JSON",
    },
    "sessions": {
        "confidence":      "FLOAT",
        "bot_probability": "FLOAT",
    },
}

_INDEXES = [
    ("ix_visits_bot_prob_ts",    "visits",   "bot_probability, timestamp"),
    ("ix_visits_confidence_ts",  "visits",   "confidence, timestamp"),
    ("ix_visits_mode",           "visits",   "mode"),
    ("ix_visits_reason",         "visits",   "reason"),
    ("ix_sessions_pending",      "sessions", "visit_id, started_at"),
]


def apply_safe_migrations():
    """Add missing columns/indexes to existing tables (SQLite-safe)."""
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    if not tables:
        return

    with engine.connect() as conn:
        for table, cols in _MIGRATIONS.items():
            if table not in tables:
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for col_name, col_type in cols.items():
                if col_name in existing:
                    continue
                try:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"))
                    conn.commit()
                    print(f"✅ Migration: added {table}.{col_name} ({col_type})")
                except Exception as e:
                    print(f"⚠️ Migration failed {table}.{col_name}: {e}")

        for idx_name, table, cols in _INDEXES:
            if table not in tables:
                continue
            try:
                conn.execute(text(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} ({cols})"))
                conn.commit()
                print(f"✅ Index: {idx_name} on {table}({cols})")
            except Exception as e:
                print(f"⚠️ Index failed {idx_name}: {e}")


# =========================================================
# SEEDING
# =========================================================
def seed_traffic_sources():
    try:
        insp = inspect(engine)
        if "traffic_sources" not in insp.get_table_names(): return
        builtin = [("popads", "PopAds", 1.0), ("propeller", "PropellerAds", 1.0),
                   ("galaksion", "Galaksion", 1.0), ("custom", "Custom Source", 0.0)]
        with engine.connect() as conn:
            for slug, name, cpm in builtin:
                existing = conn.execute(text("SELECT id FROM traffic_sources WHERE slug = :slug"), {"slug": slug}).first()
                if not existing:
                    conn.execute(text("INSERT INTO traffic_sources (slug, name, default_cpm, notes, is_builtin) VALUES (:slug, :name, :cpm, '', 1)"),
                                 {"slug": slug, "name": name, "cpm": cpm})
            conn.commit()
        print("✅ Seed: traffic_sources")
    except Exception as e:
        print(f"⚠️ seed_traffic_sources skipped: {e}")


def seed_destinations():
    try:
        insp = inspect(engine)
        if "destinations" not in insp.get_table_names(): return
        builtin = [("adsterra", "Adsterra", 0), ("monetag", "Monetag", 0),
                   ("kdm", "KDM", 0), ("custom", "Custom Destination", 0)]
        with engine.connect() as conn:
            for slug, name, postback in builtin:
                existing = conn.execute(text("SELECT id FROM destinations WHERE slug = :slug"), {"slug": slug}).first()
                if not existing:
                    conn.execute(text("INSERT INTO destinations (slug, name, postback_supported, notes, is_builtin) VALUES (:slug, :name, :postback, '', 1)"),
                                 {"slug": slug, "name": name, "postback": postback})
            conn.commit()
        print("✅ Seed: destinations")
    except Exception as e:
        print(f"⚠️ seed_destinations skipped: {e}")


def backfill_legacy_data_quality():
    """
    القديم (NULL) → 'legacy'. النظام الجديد هيحوّلها لـ 'partial' عند التحليل.
    """
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names(): return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "data_quality" not in cols: return
        with engine.connect() as conn:
            n = conn.execute(text("SELECT COUNT(*) FROM visits WHERE data_quality IS NULL")).scalar() or 0
            if n == 0: return
            conn.execute(text("UPDATE visits SET data_quality = 'legacy' WHERE data_quality IS NULL"))
            conn.commit()
            print(f"✅ Backfill: {n} legacy visits tagged")
    except Exception as e:
        print(f"⚠️ backfill_legacy_data_quality skipped: {e}")


def backfill_counting_type():
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names(): return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "counting_type" not in cols: return
        with engine.connect() as conn:
            n = conn.execute(text("SELECT COUNT(*) FROM visits WHERE counting_type IS NULL")).scalar() or 0
            if n == 0: return
            conn.execute(text("UPDATE visits SET counting_type = 'standalone' WHERE counting_type IS NULL"))
            conn.commit()
            print(f"✅ Backfill: {n} visits tagged as standalone")
    except Exception as e:
        print(f"⚠️ backfill_counting_type skipped: {e}")


def backfill_engine_fields():
    """
    Backfill confidence/bot_probability for old visits (from full_payload if present).
    Prevents UI crashes when filtering on NULL confidence.
    """
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names(): return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "confidence" not in cols or "bot_probability" not in cols: return

        with engine.connect() as conn:
            # Existing visits with verdict → assign default confidence based on verdict
            n = conn.execute(text(
                "SELECT COUNT(*) FROM visits WHERE confidence IS NULL AND verdict IS NOT NULL"
            )).scalar() or 0
            if n > 0:
                conn.execute(text(
                    "UPDATE visits SET confidence = CASE "
                    "WHEN verdict = 'invalid' THEN 0.85 "
                    "WHEN verdict = 'valid' THEN 0.70 "
                    "WHEN verdict = 'suspicious' THEN 0.50 "
                    "ELSE 0.30 END "
                    "WHERE confidence IS NULL AND verdict IS NOT NULL"
                ))
                conn.execute(text(
                    "UPDATE visits SET bot_probability = CASE "
                    "WHEN verdict = 'invalid' THEN 0.90 "
                    "WHEN verdict = 'valid' THEN 0.20 "
                    "WHEN verdict = 'suspicious' THEN 0.55 "
                    "ELSE 0.50 END "
                    "WHERE bot_probability IS NULL AND verdict IS NOT NULL"
                ))
                conn.commit()
                print(f"✅ Backfill: {n} visits got default confidence/bot_probability")
    except Exception as e:
        print(f"⚠️ backfill_engine_fields skipped: {e}")


def run_data_seeding_and_backfills():
    seed_traffic_sources()
    seed_destinations()
    backfill_legacy_data_quality()
    backfill_counting_type()
    backfill_engine_fields()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
