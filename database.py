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
    """Phase 5 — adds email, email_verified, token_version to users."""
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
    migrate_country_code()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
