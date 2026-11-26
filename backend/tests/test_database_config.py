import os

from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.core import database
from app.core.config import settings
from app.core.types import UTCDateTime
from app.models.alert import Alert
from app.models.reputation import IPReputationCache
from app.models.traffic import Traffic


POSTGRES_TEST_URL_ENV = "TEST_POSTGRES_DATABASE_URL"


@pytest.mark.parametrize(
    ("raw_url", "expected_url"),
    [
        (
            "sqlite:///./sentinelx.db",
            "sqlite:///./sentinelx.db"
        ),
        (
            "postgres://user:pass@example.test/sentinelx",
            "postgresql+psycopg://user:pass@example.test/sentinelx"
        ),
        (
            "postgresql://user:pass@example.test/sentinelx"
            "?sslmode=require",
            "postgresql+psycopg://user:pass@example.test/sentinelx"
            "?sslmode=require"
        ),
        (
            "postgresql+psycopg://user:pass@example.test/sentinelx",
            "postgresql+psycopg://user:pass@example.test/sentinelx"
        ),
    ]
)
def test_normalize_database_url(raw_url, expected_url):
    assert database.normalize_database_url(raw_url) == expected_url


def test_sqlite_engine_options_preserve_local_defaults(monkeypatch):
    monkeypatch.setattr(settings, "SQLALCHEMY_ECHO", False)

    url, options = database.database_engine_options(
        "sqlite:///./sentinelx.db"
    )

    assert url == "sqlite:///./sentinelx.db"
    assert options == {
        "echo": False,
        "connect_args": {"check_same_thread": False}
    }


def test_postgres_engine_options(monkeypatch):
    monkeypatch.setattr(settings, "SQLALCHEMY_ECHO", True)

    url, options = database.database_engine_options(
        "postgres://user:pass@example.test/sentinelx"
    )

    assert url == (
        "postgresql+psycopg://user:pass@example.test/sentinelx"
    )
    assert options["echo"] is True
    assert options["pool_pre_ping"] is True
    assert options["pool_recycle"] == (
        database.POSTGRESQL_POOL_RECYCLE_SECONDS
    )
    assert options["connect_args"] == {
        "options": "-c timezone=utc"
    }
    assert "check_same_thread" not in options["connect_args"]


def test_create_database_engine_uses_psycopg_dialect(monkeypatch):
    captured = {}
    sentinel = object()

    def fake_create_engine(url, **options):
        captured["url"] = url
        captured["options"] = options
        return sentinel

    monkeypatch.setattr(database, "create_engine", fake_create_engine)

    result = database.create_database_engine(
        "postgresql://user:pass@example.test/sentinelx",
        echo=False
    )

    assert result is sentinel
    assert captured["url"] == (
        "postgresql+psycopg://user:pass@example.test/sentinelx"
    )
    assert captured["options"]["echo"] is False
    assert captured["options"]["pool_pre_ping"] is True


def test_initialization_database_url_prefers_unpooled(monkeypatch):
    monkeypatch.setattr(
        settings,
        "DATABASE_URL",
        "postgresql://pooled.example.test/sentinelx"
    )
    monkeypatch.setattr(
        settings,
        "DATABASE_URL_UNPOOLED",
        "postgresql://direct.example.test/sentinelx"
    )

    assert database.initialization_database_url() == (
        "postgresql://direct.example.test/sentinelx"
    )


def test_initialization_database_url_falls_back_to_pooled(monkeypatch):
    monkeypatch.setattr(
        settings,
        "DATABASE_URL",
        "postgresql://pooled.example.test/sentinelx"
    )
    monkeypatch.setattr(settings, "DATABASE_URL_UNPOOLED", None)

    assert database.initialization_database_url() == (
        "postgresql://pooled.example.test/sentinelx"
    )


def test_reputation_count_columns_compile_to_bigint_for_postgresql():
    table_ddl = str(
        CreateTable(IPReputationCache.__table__).compile(
            dialect=postgresql.dialect()
        )
    )

    for column in ("total_reports", "num_distinct_users"):
        assert f"{column} BIGINT" in table_ddl

    assert "checked_at TIMESTAMP WITH TIME ZONE" in table_ddl
    assert "last_reported_at TIMESTAMP WITH TIME ZONE" in table_ddl


def test_timestamp_columns_keep_timezone_for_postgresql():
    for table in (
        Traffic.__table__,
        Alert.__table__,
        IPReputationCache.__table__,
    ):
        table_ddl = str(
            CreateTable(table).compile(
                dialect=postgresql.dialect()
            )
        )

        assert "TIMESTAMP WITH TIME ZONE" in table_ddl


@pytest.mark.parametrize(
    "column_name",
    [
        "timestamp",
    ]
)
@pytest.mark.parametrize("model", [Traffic, Alert])
def test_traffic_and_alert_timestamps_use_utc_type(model, column_name):
    assert isinstance(
        model.__table__.c[column_name].type,
        UTCDateTime
    )


@pytest.mark.parametrize(
    "column_name",
    [
        "last_reported_at",
        "checked_at",
        "expires_at",
    ]
)
def test_reputation_timestamps_use_utc_type(column_name):
    assert isinstance(
        IPReputationCache.__table__.c[column_name].type,
        UTCDateTime
    )


def test_utc_datetime_normalizes_values_to_naive_utc():
    utc_type = UTCDateTime()
    naive_utc = datetime(2026, 1, 1, 12, 0, 0)
    aware_utc = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc
    )
    aware_offset = datetime(
        2026,
        1,
        1,
        14,
        0,
        0,
        tzinfo=timezone(timedelta(hours=2))
    )

    for value in (naive_utc, aware_utc, aware_offset):
        assert utc_type.process_bind_param(value, None) == naive_utc
        assert utc_type.process_result_value(value, None) == naive_utc

    assert utc_type.process_bind_param(None, None) is None
    assert utc_type.process_result_value(None, None) is None


@pytest.mark.skipif(
    not os.getenv(POSTGRES_TEST_URL_ENV),
    reason=f"{POSTGRES_TEST_URL_ENV} is not configured"
)
def test_postgres_connection_uses_psycopg_and_utc():
    engine = database.create_database_engine(
        os.environ[POSTGRES_TEST_URL_ENV],
        echo=False
    )

    try:
        with engine.connect() as connection:
            timezone_name = connection.exec_driver_sql(
                "SHOW TimeZone"
            ).scalar_one()
    finally:
        engine.dispose()

    assert engine.dialect.name == "postgresql"
    assert engine.dialect.driver == "psycopg"
    assert timezone_name == "UTC"
