import pytest

from app.services.rate_limiter import reputation_rate_limiter


@pytest.fixture(autouse=True)
def reset_reputation_rate_limiter():
    reputation_rate_limiter.reset()

    yield

    reputation_rate_limiter.reset()
