"""Explicitly seed the configured database with simulated demo data.

Usage:
    python -m app.seed_demo
    python -m app.seed_demo --yes

This command is never called automatically by the application. It creates any
missing tables, inserts one deterministic demo dataset, and records the seed in
demo_seed_runs. Re-running the command is a no-op.

A non-SQLite target requires --yes as an explicit production safety check.
"""

import argparse

from sqlalchemy.orm import sessionmaker

from app.core.database import (
    Base,
    create_database_engine,
    initialization_database_url,
    is_sqlite_url,
)

from app.models.alert import Alert
from app.models.demo_seed import DemoSeedRun
from app.models.reputation import IPReputationCache
from app.models.traffic import Traffic
from app.services.demo_seed import seed_demo_data


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Insert simulated SentinelX dashboard data into the configured "
            "database. Re-running is safe and inserts no duplicates."
        )
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Required for non-SQLite databases. Confirms that simulated demo "
            "data should be inserted into the configured PostgreSQL database."
        )
    )

    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    database_url = initialization_database_url()

    if not is_sqlite_url(database_url) and not args.yes:
        print(
            "Refusing to seed a non-SQLite database without --yes."
        )
        print("Re-run with: python -m app.seed_demo --yes")
        return 2

    engine = create_database_engine(database_url)

    try:
        Base.metadata.create_all(bind=engine)

        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine
        )

        db = SessionLocal()

        try:
            result = seed_demo_data(db)
        finally:
            db.close()
    finally:
        engine.dispose()

    if result["seeded"]:
        print("Simulated demo data seeded successfully.")
    else:
        print("Simulated demo data already present; no changes were made.")

    print(f"Seed key: {result['seed_key']}")
    print(f"Dataset version: {result['dataset_version']}")
    print(f"Traffic records inserted: {result['traffic_created']}")
    print(f"Alert records inserted: {result['alerts_created']}")
    print(f"Traffic records total: {result['traffic_total']}")
    print(f"Alert records total: {result['alerts_total']}")
    print("Simulated alerts are marked with the [SIMULATED] prefix.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
