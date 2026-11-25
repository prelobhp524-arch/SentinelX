import math
import threading
import time

from app.core.config import settings


MAX_TRACKED_CLIENTS = 1024


class ProviderQuotaExceeded(Exception):
    category = "rate_limited"

    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__(
            "IP reputation provider rate limit exceeded"
        )


class _WindowEntry:
    __slots__ = ("started_at", "count")

    def __init__(self, started_at):
        self.started_at = started_at
        self.count = 0


class FixedWindowLimiter:
    def __init__(
        self,
        limit,
        window_seconds,
        max_keys=MAX_TRACKED_CLIENTS,
        clock=time.monotonic
    ):
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
        ):
            raise ValueError("limit must be a positive integer")

        if (
            not isinstance(window_seconds, (int, float))
            or isinstance(window_seconds, bool)
            or window_seconds <= 0
        ):
            raise ValueError("window_seconds must be greater than zero")

        if (
            not isinstance(max_keys, int)
            or isinstance(max_keys, bool)
            or max_keys < 1
        ):
            raise ValueError("max_keys must be a positive integer")

        self._limit = limit
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._entries = {}

    def _purge_expired(self, now):
        deadline_offset = self._window_seconds
        expired = [
            key
            for key, entry in self._entries.items()
            if now >= entry.started_at + deadline_offset
        ]

        for key in expired:
            del self._entries[key]

    def _evict_oldest(self):
        oldest_key = min(
            self._entries,
            key=lambda key: self._entries[key].started_at
        )

        del self._entries[oldest_key]

    def try_acquire(self, key, now=None):
        current_time = self._clock() if now is None else now

        with self._lock:
            self._purge_expired(current_time)
            entry = self._entries.get(key)

            if entry is None:
                if len(self._entries) >= self._max_keys:
                    self._evict_oldest()

                entry = _WindowEntry(current_time)
                self._entries[key] = entry

            if entry.count >= self._limit:
                retry_after = (
                    entry.started_at
                    + self._window_seconds
                    - current_time
                )

                return max(1, math.ceil(retry_after))

            entry.count += 1

            return 0

    def cleanup(self, now=None):
        current_time = self._clock() if now is None else now

        with self._lock:
            self._purge_expired(current_time)

    def active_keys(self):
        with self._lock:
            return len(self._entries)

    def reset(self):
        with self._lock:
            self._entries.clear()


class ReputationRateLimiter:
    def __init__(
        self,
        request_limit=None,
        force_refresh_limit=None,
        provider_limit=None,
        window_seconds=None,
        max_clients=MAX_TRACKED_CLIENTS,
        clock=time.monotonic
    ):
        effective_window = (
            settings.IP_REPUTATION_RATE_LIMIT_WINDOW_SECONDS
            if window_seconds is None
            else window_seconds
        )

        effective_request_limit = (
            settings.IP_REPUTATION_RATE_LIMIT_REQUESTS
            if request_limit is None
            else request_limit
        )

        effective_force_limit = (
            settings.IP_REPUTATION_RATE_LIMIT_FORCE_REFRESHES
            if force_refresh_limit is None
            else force_refresh_limit
        )

        effective_provider_limit = (
            settings.IP_REPUTATION_RATE_LIMIT_PROVIDER_CALLS
            if provider_limit is None
            else provider_limit
        )

        self._request_limiter = FixedWindowLimiter(
            effective_request_limit,
            effective_window,
            max_keys=max_clients,
            clock=clock
        )
        self._force_refresh_limiter = FixedWindowLimiter(
            effective_force_limit,
            effective_window,
            max_keys=max_clients,
            clock=clock
        )
        self._provider_limiter = FixedWindowLimiter(
            effective_provider_limit,
            effective_window,
            max_keys=1,
            clock=clock
        )

    def check_client(
        self,
        client_key,
        force_refresh=False,
        now=None
    ):
        request_retry_after = self._request_limiter.try_acquire(
            client_key,
            now=now
        )

        if request_retry_after:
            return request_retry_after

        if force_refresh:
            return self._force_refresh_limiter.try_acquire(
                client_key,
                now=now
            )

        return 0

    def allow_provider_request(self, now=None):
        return self._provider_limiter.try_acquire(
            "provider",
            now=now
        )

    def cleanup(self, now=None):
        self._request_limiter.cleanup(now=now)
        self._force_refresh_limiter.cleanup(now=now)
        self._provider_limiter.cleanup(now=now)

    def reset(self):
        self._request_limiter.reset()
        self._force_refresh_limiter.reset()
        self._provider_limiter.reset()


reputation_rate_limiter = ReputationRateLimiter()
