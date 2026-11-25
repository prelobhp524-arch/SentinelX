from app.core.database import Base, engine

from app.models.traffic import Traffic
from app.models.alert import Alert
from app.models.reputation import IPReputationCache


def initialize_database():
    Base.metadata.create_all(bind=engine)

    print("SentinelX database tables created successfully!")
    print("Network traffic table: Ready")
    print("Security alerts table: Ready")


if __name__ == "__main__":
    initialize_database()