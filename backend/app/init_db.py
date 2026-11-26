from app.core.database import (
    Base,
    create_database_engine,
    initialization_database_url
)

from app.models.traffic import Traffic
from app.models.alert import Alert
from app.models.reputation import IPReputationCache


def initialize_database():
    engine = create_database_engine(initialization_database_url())

    try:
        Base.metadata.create_all(bind=engine)
    finally:
        engine.dispose()

    print("SentinelX database tables created successfully!")
    print("Network traffic table: Ready")
    print("Security alerts table: Ready")


if __name__ == "__main__":
    initialize_database()
