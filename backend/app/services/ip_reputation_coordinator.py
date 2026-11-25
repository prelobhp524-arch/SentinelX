import threading

from contextlib import contextmanager


class _RefreshSlot:
    __slots__ = (
        "lock",
        "users",
        "generation",
        "last_error",
        "last_response",
    )

    def __init__(self):
        self.lock = threading.Lock()
        self.users = 0
        self.generation = 0
        self.last_error = None
        self.last_response = None


class RefreshLease:
    def __init__(self, slot, start_generation):
        self._slot = slot
        self._start_generation = start_generation

    def refresh_completed(self):
        return self._slot.generation != self._start_generation

    @property
    def last_error(self):
        return self._slot.last_error

    @property
    def last_response(self):
        return self._slot.last_response

    def record_success(self, response):
        self._slot.generation += 1
        self._slot.last_error = None
        self._slot.last_response = response

    def record_error(self, error):
        self._slot.generation += 1
        self._slot.last_error = error
        self._slot.last_response = None


class IPRefreshCoordinator:
    def __init__(self):
        self._mutex = threading.Lock()
        self._slots = {}

    @contextmanager
    def acquire(self, ip_address, before_wait=None):
        with self._mutex:
            slot = self._slots.get(ip_address)

            if slot is None:
                slot = _RefreshSlot()
                self._slots[ip_address] = slot

            slot.users += 1
            start_generation = slot.generation

        acquired = False

        try:
            if slot.lock.acquire(blocking=False):
                acquired = True
            else:
                if before_wait is not None:
                    before_wait()

                slot.lock.acquire()
                acquired = True

            yield RefreshLease(slot, start_generation)
        finally:
            if acquired:
                slot.lock.release()

            with self._mutex:
                slot.users -= 1

                if slot.users == 0:
                    self._slots.pop(ip_address, None)

    def active_count(self):
        with self._mutex:
            return len(self._slots)

    def active_requests(self, ip_address):
        with self._mutex:
            slot = self._slots.get(ip_address)

            return slot.users if slot is not None else 0


refresh_coordinator = IPRefreshCoordinator()
