from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.core.config import settings


POSTGRESQL_POOL_RECYCLE_SECONDS = 300

POSTGRESQL_CONNECT_ARGS = {
    "options": "-c timezone=utc"
}


def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return (
            "postgresql+psycopg://"
            + database_url[len("postgres://"):]
        )

    if database_url.startswith("postgresql://"):
        return (
            "postgresql+psycopg://"
            + database_url[len("postgresql://"):]
        )

    return database_url


def is_sqlite_url(database_url: str) -> bool:
    return database_url.startswith("sqlite")


def is_postgresql_url(database_url: str) -> bool:
    return database_url.startswith("postgresql")


def database_engine_options(database_url: str, echo=None):
    normalized_url = normalize_database_url(database_url)

    if echo is None:
        echo = settings.SQLALCHEMY_ECHO

    options = {"echo": echo}

    if is_sqlite_url(normalized_url):
        options["connect_args"] = {"check_same_thread": False}
    elif is_postgresql_url(normalized_url):
        options["pool_pre_ping"] = True
        options["pool_recycle"] = POSTGRESQL_POOL_RECYCLE_SECONDS
        options["connect_args"] = dict(POSTGRESQL_CONNECT_ARGS)

    return normalized_url, options


def create_database_engine(database_url=None, echo=None):
    url = settings.DATABASE_URL if database_url is None else database_url
    normalized_url, options = database_engine_options(url, echo=echo)

    return create_engine(normalized_url, **options)


def initialization_database_url() -> str:
    return settings.DATABASE_URL_UNPOOLED or settings.DATABASE_URL


# Create database engine
engine = create_database_engine()


# Create database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# Base class for database models
class Base(DeclarativeBase):
    pass


# Database dependency
def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
