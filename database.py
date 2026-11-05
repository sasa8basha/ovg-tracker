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


# =========================================================
# v3 — Campaign Foundation (Phase 0.5)
# =========================================================
def migrate_visit_campaign_column():
    """إضافة campaign_id لجدول visits (nullable، backward compatible)."""
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "campaign_id" in cols:
            return
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE visits ADD COLUMN campaign_id INTEGER"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_visits_campaign_id ON visits (campaign_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_visits_campaign_timestamp ON visits (campaign_id, timestamp)"))
            conn.commit()
        print("✅ Migration: added visits.campaign_id column")
    except Exception as e:
        print(f"⚠️ migrate_visit_campaign_column skipped: {e}")


def seed_traffic_sources():
    """يزرع المصادر الافتراضية لو مش موجودة."""
    try:
        insp = inspect(engine)
        if "traffic_sources" not in insp.get_table_names():
            return
        builtin = [
            ("popads", "PopAds", 1.0),
            ("propeller", "PropellerAds", 1.0),
            ("galaksion", "Galaksion", 1.0),
            ("custom", "Custom Source", 0.0),
        ]
        with engine.connect() as conn:
            for slug, name, cpm in builtin:
                existing = conn.execute(
                    text("SELECT id FROM traffic_sources WHERE slug = :slug"),
                    {"slug": slug},
                ).first()
                if not existing:
                    conn.execute(
                        text(
                            "INSERT INTO traffic_sources "
                            "(slug, name, default_cpm, notes, is_builtin) "
                            "VALUES (:slug, :name, :cpm, '', 1)"
                        ),
                        {"slug": slug, "name": name, "cpm": cpm},
                    )
            conn.commit()
        print("✅ Seed: traffic_sources")
    except Exception as e:
        print(f"⚠️ seed_traffic_sources skipped: {e}")


def seed_destinations():
    """يزرع الوجهات الافتراضية."""
    try:
        insp = inspect(engine)
        if "destinations" not in insp.get_table_names():
            return
        builtin = [
            ("adsterra", "Adsterra", 0),
            ("monetag", "Monetag", 0),
            ("kdm", "KDM", 0),
            ("custom", "Custom Destination", 0),
        ]
        with engine.connect() as conn:
            for slug, name, postback in builtin:
                existing = conn.execute(
                    text("SELECT id FROM destinations WHERE slug = :slug"),
                    {"slug": slug},
                ).first()
                if not existing:
                    conn.execute(
                        text(
                            "INSERT INTO destinations "
                            "(slug, name, postback_supported, notes, is_builtin) "
                            "VALUES (:slug, :name, :postback, '', 1)"
                        ),
                        {"slug": slug, "name": name, "postback": postback},
                    )
            conn.commit()
        print("✅ Seed: destinations")
    except Exception as e:
        print(f"⚠️ seed_destinations skipped: {e}")


def backfill_campaigns_from_sites():
    """
    كل site موجود → campaign (legacy).
    campaign_key = site.site_key عشان الـ tracker القديم يفضل شغال.
    """
    try:
        insp = inspect(engine)
        if "campaigns" not in insp.get_table_names():
            return
        if "sites" not in insp.get_table_names():
            return

        with engine.connect() as conn:
            # عدد الـ sites والـ campaigns
            sites_count = conn.execute(text("SELECT COUNT(*) FROM sites")).scalar() or 0
            if sites_count == 0:
                return

            campaigns_count = conn.execute(text("SELECT COUNT(*) FROM campaigns")).scalar() or 0
            if campaigns_count >= sites_count:
                return  # متزامن بالفعل

            # backfill
            rows = conn.execute(
                text(
                    "SELECT s.id, s.user_id, s.name, s.domain, s.site_key "
                    "FROM sites s "
                    "LEFT JOIN campaigns c ON c.site_id = s.id "
                    "WHERE c.id IS NULL"
                )
            ).fetchall()

            for row in rows:
                site_id = row[0]
                user_id = row[1]
                name = row[2]
                domain = row[3] or ""
                site_key = row[4]

                # تحقق إن الـ key مش مستخدم
                existing = conn.execute(
                    text("SELECT id FROM campaigns WHERE campaign_key = :k"),
                    {"k": site_key},
                ).first()
                if existing:
                    continue

                conn.execute(
                    text(
                        "INSERT INTO campaigns "
                        "(user_id, name, type, traffic_source_slug, buy_cpm, "
                        " destination_slug, sell_cpm, site_id, campaign_key, "
                        " redirect_delay_ms, bot_block_threshold, status, notes) "
                        "VALUES "
                        "(:uid, :name, 'landing', 'custom', 0.0, "
                        " 'custom', 0.0, :sid, :key, 500, 100, 'active', :notes)"
                    ),
                    {
                        "uid": user_id,
                        "name": name,
                        "sid": site_id,
                        "key": site_key,
                        "notes": f"Auto-created from site #{site_id} ({domain})" if domain else f"Auto-created from site #{site_id}",
                    },
                )

            conn.commit()
            print(f"✅ Backfill: {len(rows)} campaigns created from sites")
    except Exception as e:
        print(f"⚠️ backfill_campaigns_from_sites skipped: {e}")


def backfill_visits_campaign_id():
    """ربط الزيارات القديمة بالـ campaigns عن طريق site_id."""
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names() or "campaigns" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "campaign_id" not in cols:
            return

        with engine.connect() as conn:
            # كم زيارة عندها site_id بس مش campaign_id
            unlinked = conn.execute(
                text(
                    "SELECT COUNT(*) FROM visits "
                    "WHERE site_id IS NOT NULL AND campaign_id IS NULL"
                )
            ).scalar() or 0

            if unlinked == 0:
                return

            conn.execute(
                text(
                    "UPDATE visits "
                    "SET campaign_id = ("
                    "  SELECT c.id FROM campaigns c WHERE c.site_id = visits.site_id LIMIT 1"
                    ") "
                    "WHERE site_id IS NOT NULL AND campaign_id IS NULL"
                )
            )
            conn.commit()
            print(f"✅ Backfill: {unlinked} visits linked to campaigns")
    except Exception as e:
        print(f"⚠️ backfill_visits_campaign_id skipped: {e}")


def run_migrations():
    migrate_auth_columns()
    migrate_cpm_columns()
    migrate_ground_truth_columns()
    migrate_country_code()
    # v3
    migrate_visit_campaign_column()
    seed_traffic_sources()
    seed_destinations()
    backfill_campaigns_from_sites()
    backfill_visits_campaign_id()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
