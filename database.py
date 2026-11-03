from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import DATABASE_URL

# =========================================================
# DATABASE SETUP
# =========================================================
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =========================================================
# MIGRATIONS (idempotent — آمنة للتشغيل المتكرر)
# =========================================================
def migrate_country_code():
    """
    Phase R3 — Fix [R14]: add country_code column if missing.
    - آمن على قواعد جديدة (table مش موجود → skip)
    - آمن على قواعد شغالة من قبل (column مش موجود → add)
    - آمن على إعادة التشغيل (column موجود → skip)
    """
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names():
            return  # جدول مش موجود — Base.metadata.create_all هيعمله

        cols = [c["name"] for c in insp.get_columns("visits")]
        if "country_code" in cols:
            return  # موجود بالفعل

        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE visits ADD COLUMN country_code VARCHAR(2)"))
            # استخدام IF NOT EXISTS يمنع أي خطأ لو الفهرس موجود
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_visits_country_code ON visits (country_code)"
            ))
            conn.commit()
        print("✅ Migration: added visits.country_code column")
    except Exception as e:
        print(f"⚠️ Migration skipped (will retry on next start): {e}")


def run_migrations():
    """يُستدعى بعد Base.metadata.create_all."""
    migrate_country_code()


# =========================================================
# DB SESSION
# =========================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
