from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _safe_alter(conn, sql: str, label: str):
    try:
        conn.execute(text(sql))
        conn.commit()
        print(f"✅ Migration: {label}")
    except Exception as e:
        print(f"⚠️ Migration '{label}' skipped: {e}")


def migrate_auth_columns():
    try:
        insp = inspect(engine)
        if "users" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("users")]
        with engine.connect() as conn:
            if "email" not in cols:
                _safe_alter(conn, "ALTER TABLE users ADD COLUMN email VARCHAR(255)", "users.email")
                _safe_alter(conn, "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)", "ix_users_email")
            if "email_verified" not in cols:
                _safe_alter(conn, "ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0", "users.email_verified")
            if "token_version" not in cols:
                _safe_alter(conn, "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1", "users.token_version")
    except Exception as e:
        print(f"⚠️ migrate_auth_columns skipped: {e}")


def migrate_cpm_columns():
    try:
        insp = inspect(engine)
        if "users" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("users")]
        with engine.connect() as conn:
            if "cpm_buy" not in cols:
                _safe_alter(conn, "ALTER TABLE users ADD COLUMN cpm_buy FLOAT NOT NULL DEFAULT 1.0", "users.cpm_buy")
            if "cpm_sell" not in cols:
                _safe_alter(conn, "ALTER TABLE users ADD COLUMN cpm_sell FLOAT NOT NULL DEFAULT 1.5", "users.cpm_sell")
    except Exception as e:
        print(f"⚠️ migrate_cpm_columns skipped: {e}")


def migrate_ground_truth_columns():
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        with engine.connect() as conn:
            if "ground_truth" not in cols:
                _safe_alter(conn, "ALTER TABLE visits ADD COLUMN ground_truth VARCHAR(10)", "visits.ground_truth")
                _safe_alter(conn, "CREATE INDEX IF NOT EXISTS ix_visits_ground_truth ON visits (ground_truth)", "ix_visits_ground_truth")
            if "ground_truth_at" not in cols:
                _safe_alter(conn, "ALTER TABLE visits ADD COLUMN ground_truth_at TIMESTAMP", "visits.ground_truth_at")
            if "ground_truth_by" not in cols:
                _safe_alter(conn, "ALTER TABLE visits ADD COLUMN ground_truth_by VARCHAR(64)", "visits.ground_truth_by")
            _safe_alter(conn, "CREATE INDEX IF NOT EXISTS ix_visits_gt_verdict ON visits (ground_truth, verdict)", "ix_visits_gt_verdict")
    except Exception as e:
        print(f"⚠️ migrate_ground_truth_columns skipped: {e}")


def migrate_country_code():
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "country_code" in cols:
            return
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE visits ADD COLUMN country_code VARCHAR(2)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_visits_country_code ON visits (country_code)"))
            conn.commit()
        print("✅ Migration: added visits.country_code column")
    except Exception as e:
        print(f"⚠️ Migration skipped: {e}")


def run_migrations():
    migrate_auth_columns()
    migrate_cpm_columns()
    migrate_ground_truth_columns()
    migrate_country_code()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
