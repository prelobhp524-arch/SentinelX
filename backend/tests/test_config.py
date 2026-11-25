import pytest

from pydantic import ValidationError

from app.core.config import Settings


CONFIG_ENV_NAMES = (
    "PROJECT_NAME",
    "PROJECT_VERSION",
    "DEBUG",
    "SQLALCHEMY_ECHO",
    "DATABASE_URL",
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


@pytest.mark.parametrize(
    "field",
    ["DEBUG", "SQLALCHEMY_ECHO"]
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
