from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelX"
    PROJECT_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SQLALCHEMY_ECHO: bool = False
    PUBLIC_DEMO_MODE: bool = False
    CORS_ALLOW_ORIGINS: str = (
        "http://localhost:5173,http://127.0.0.1:5173"
    )
    DATABASE_URL: str = Field(
        default="sqlite:///./sentinelx.db",
        repr=False
    )
    DATABASE_URL_UNPOOLED: str | None = Field(
        default=None,
        repr=False
    )

    IP_REPUTATION_ENABLED: bool = False
    ABUSEIPDB_API_KEY: str | None = Field(default=None, repr=False)
    IP_REPUTATION_CACHE_TTL_HOURS: int = Field(default=24, gt=0)
    ABUSEIPDB_TIMEOUT_SECONDS: float = Field(default=5, gt=0)

    IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        gt=0
    )
    IP_REPUTATION_RATE_LIMIT_REQUESTS: int = Field(
        default=60,
        gt=0
    )
    IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES: int = Field(
        default=5,
        gt=0
    )
    IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS: int = Field(
        default=30,
        gt=0
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_allow_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.CORS_ALLOW_ORIGINS.split(",")
            if origin.strip()
        ]


settings = Settings()