from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from config import DATABASE_URL

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def seed_traffic_sources():
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
    try:
        insp = inspect(engine)
        if "campaigns" not in insp.get_table_names():
            return
        if "sites" not in insp.get_table_names():
            return

        with engine.connect() as conn:
            sites_count = conn.execute(text("SELECT COUNT(*) FROM sites")).scalar() or 0
            if sites_count == 0:
                return

            campaigns_count = conn.execute(text("SELECT COUNT(*) FROM campaigns")).scalar() or 0
            if campaigns_count >= sites_count:
                return

            rows = conn.execute(
                text(
                    "SELECT s.id, s.user_id, s.name, s.domain, s.site_key "
                    "FROM sites s "
                    "LEFT JOIN campaigns c ON c.site_id = s.id "
                    "WHERE c.id IS NULL"
                )
            ).fetchall()

            for row in rows:
                site_id, user_id, name, domain, site_key = row[0], row[1], row[2], row[3] or "", row[4]
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
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names() or "campaigns" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "campaign_id" not in cols:
            return

        with engine.connect() as conn:
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


def backfill_legacy_data_quality():
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "data_quality" not in cols:
            return

        with engine.connect() as conn:
            n = conn.execute(
                text("SELECT COUNT(*) FROM visits WHERE data_quality IS NULL")
            ).scalar() or 0

            if n == 0:
                return

            conn.execute(
                text("UPDATE visits SET data_quality = 'legacy' WHERE data_quality IS NULL")
            )
            conn.commit()
            print(f"✅ Backfill: {n} legacy visits tagged")
    except Exception as e:
        print(f"⚠️ backfill_legacy_data_quality skipped: {e}")


def backfill_counting_type():
    try:
        insp = inspect(engine)
        if "visits" not in insp.get_table_names():
            return
        cols = [c["name"] for c in insp.get_columns("visits")]
        if "counting_type" not in cols:
            return

        with engine.connect() as conn:
            n = conn.execute(
                text("SELECT COUNT(*) FROM visits WHERE counting_type IS NULL")
            ).scalar() or 0

            if n == 0:
                return

            conn.execute(
                text("UPDATE visits SET counting_type = 'standalone' WHERE counting_type IS NULL")
            )
            conn.commit()
            print(f"✅ Backfill: {n} visits tagged as standalone (counting_type)")
    except Exception as e:
        print(f"⚠️ backfill_counting_type skipped: {e}")


def run_data_seeding_and_backfills():
    """
    بتشغل تعبئة البيانات الأولية والـ backfills.
    دوال التعديل (ALTER TABLE) اتشالت خلاص واتنقلت لـ Alembic.
    """
    seed_traffic_sources()
    seed_destinations()
    backfill_campaigns_from_sites()
    backfill_visits_campaign_id()
    backfill_legacy_data_quality()
    backfill_counting_type()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
