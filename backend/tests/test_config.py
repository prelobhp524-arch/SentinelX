import pytest

from pydantic import ValidationError

from app.core.config import Settings


CONFIG_ENV_NAMES = (
    "PROJECT_NAME",
    "PROJECT_VERSION",
    "DEBUG",
    "SQLALCHEMY_ECHO",
    "PUBLIC_DEMO_MODE",
    "CORS_ALLOW_ORIGINS",
    "DATABASE_URL",
    "DATABASE_URL_UNPOOLED",
    "IP_REPUTATION_ENABLED",
    "ABUSEIPDB_API_KEY",
    "IP_REPUTATION_CACHE_TTL_HOURS",
    "ABUSEIPDB_TIMEOUT_SECONDS",
    "IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS",
    "IP_REPUTATION_RATE_LIMIT_REQUESTS",
    "IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES",
    "IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS",
)


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in CONFIG_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def test_debug_defaults_to_false_without_environment_override():
    config = Settings(_env_file=None)

    assert config.DEBUG is False


def test_debug_can_be_enabled_explicitly(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")

    config = Settings(_env_file=None)

    assert config.DEBUG is True


def test_sqlalchemy_echo_defaults_to_false():
    config = Settings(_env_file=None)

    assert config.SQLALCHEMY_ECHO is False


def test_sqlalchemy_echo_does_not_follow_debug(monkeypatch):
    monkeypatch.setenv("DEBUG", "true")

    config = Settings(_env_file=None)

    assert config.DEBUG is True
    assert config.SQLALCHEMY_ECHO is False


def test_sqlalchemy_echo_can_be_enabled_explicitly(monkeypatch):
    monkeypatch.setenv("SQLALCHEMY_ECHO", "true")

    config = Settings(_env_file=None)

    assert config.SQLALCHEMY_ECHO is True
    assert config.DEBUG is False


def test_production_configuration_keeps_sqlalchemy_echo_disabled(
    monkeypatch
):
    monkeypatch.setenv("DEBUG", "false")

    config = Settings(_env_file=None)

    assert config.DEBUG is False
    assert config.SQLALCHEMY_ECHO is False


def test_public_demo_mode_defaults_to_false():
    config = Settings(_env_file=None)

    assert config.PUBLIC_DEMO_MODE is False


def test_public_demo_mode_can_be_enabled(monkeypatch):
    monkeypatch.setenv("PUBLIC_DEMO_MODE", "true")

    config = Settings(_env_file=None)

    assert config.PUBLIC_DEMO_MODE is True


def test_cors_origins_default_to_local_development():
    config = Settings(_env_file=None)

    assert config.cors_allow_origins_list == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


def test_cors_origins_are_parsed_from_comma_separated_values(monkeypatch):
    monkeypatch.setenv(
        "CORS_ALLOW_ORIGINS",
        "https://sentinelx.example, https://www.sentinelx.example"
    )

    config = Settings(_env_file=None)

    assert config.cors_allow_origins_list == [
        "https://sentinelx.example",
        "https://www.sentinelx.example",
    ]


def test_cors_origins_ignore_blank_entries():
    config = Settings(
        _env_file=None,
        CORS_ALLOW_ORIGINS="https://sentinelx.example, ,"
    )

    assert config.cors_allow_origins_list == [
        "https://sentinelx.example",
    ]


@pytest.mark.parametrize(
    "field",
    ["DEBUG", "SQLALCHEMY_ECHO", "PUBLIC_DEMO_MODE"]
)
def test_invalid_boolean_settings_are_rejected(field):
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            **{field: "not-a-boolean"}
        )


@pytest.mark.parametrize(
    "field",
    [
        "IP_REPUTATION_CACHE_TTL_HOURS",
        "ABUSEIPDB_TIMEOUT_SECONDS",
        "IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS",
        "IP_REPUTATION_RATE_LIMIT_REQUESTS",
        "IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES",
        "IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS",
    ]
)
def test_invalid_reputation_settings_are_rejected(field):
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            **{field: 0}
        )


def test_api_key_is_excluded_from_settings_representations(
    monkeypatch
):
    secret = "test-super-secret-api-key"
    monkeypatch.setenv("ABUSEIPDB_API_KEY", secret)

    config = Settings(_env_file=None)

    assert config.ABUSEIPDB_API_KEY == secret
    assert secret not in repr(config)
    assert secret not in str(config)


def test_database_urls_are_excluded_from_settings_representations(
    monkeypatch
):
    pooled = "postgresql://user:pooled-secret@host/pooled"
    unpooled = "postgresql://user:unpooled-secret@host/unpooled"
    monkeypatch.setenv("DATABASE_URL", pooled)
    monkeypatch.setenv("DATABASE_URL_UNPOOLED", unpooled)

    config = Settings(_env_file=None)

    assert config.DATABASE_URL == pooled
    assert config.DATABASE_URL_UNPOOLED == unpooled
    assert "pooled-secret" not in repr(config)
    assert "unpooled-secret" not in repr(config)
    assert "pooled-secret" not in str(config)
    assert "unpooled-secret" not in str(config)


def test_database_url_unpooled_defaults_to_none():
    config = Settings(_env_file=None)

    assert config.DATABASE_URL_UNPOOLED is None


def test_existing_environment_configuration_is_loaded(monkeypatch):
    monkeypatch.setenv("IP_REPUTATION_ENABLED", "true")
    monkeypatch.setenv("IP_REPUTATION_CACHE_TTL_HOURS", "12")
    monkeypatch.setenv("ABUSEIPDB_TIMEOUT_SECONDS", "7.5")
    monkeypatch.setenv(
        "IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS",
        "120"
    )
    monkeypatch.setenv("IP_REPUTATION_RATE_LIMIT_REQUESTS", "50")
    monkeypatch.setenv(
        "IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES",
        "4"
    )
    monkeypatch.setenv(
        "IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS",
        "20"
    )

    config = Settings(_env_file=None)

    assert config.IP_REPUTATION_ENABLED is True
    assert config.IP_REPUTATION_CACHE_TTL_HOURS == 12
    assert config.ABUSEIPDB_TIMEOUT_SECONDS == 7.5
    assert config.IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS == 120
    assert config.IP_REPUTATION_RATE_LIMIT_REQUESTS == 50
    assert config.IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES == 4
    assert config.IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS == 20
