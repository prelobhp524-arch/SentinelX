import queue
import threading

from app.core.config import settings
from app.core.database import SessionLocal
from app.services.ip_reputation_service import get_reputation
from app.services.ip_validation import canonicalize_public_ip


MAX_QUEUE_CAPACITY = 1000

ENQUEUE_QUEUED = "queued"
ENQUEUE_DUPLICATE = "duplicate"
ENQUEUE_FULL = "full"
ENQUEUE_DISABLED = "disabled"
ENQUEUE_NOT_RUNNING = "not_running"

QUEUE_POLL_INTERVAL_SECONDS = 0.05
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 5.0


class IPReputationWorker:
    def __init__(
        self,
        queue_capacity=MAX_QUEUE_CAPACITY,
        session_factory=SessionLocal,
        reputation_getter=get_reputation
    ):
        if (
            not isinstance(queue_capacity, int)
            or isinstance(queue_capacity, bool)
            or not 1 <= queue_capacity <= MAX_QUEUE_CAPACITY
        ):
            raise ValueError(
                "queue_capacity must be an integer from 1 to 1000"
            )

        self._queue = queue.Queue(maxsize=queue_capacity)
        self._session_factory = session_factory
        self._reputation_getter = reputation_getter
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._tracked_ips = set()
        self._thread = None
        self._running = False

    def start(self):
        with self._lock:
            if (
                self._thread is not None
                and self._thread.is_alive()
            ):
                return False

            self._stop_event.clear()
            self._running = True
            self._thread = threading.Thread(
                target=self._run,
                name="ip-reputation-worker",
                daemon=True
            )
            self._thread.start()

            return True

    def enqueue(self, ip_address):
        if not settings.IP_REPUTATION_ENABLED:
            return ENQUEUE_DISABLED

        canonical_ip = canonicalize_public_ip(ip_address)

        with self._lock:
            if not self._running or self._stop_event.is_set():
                return ENQUEUE_NOT_RUNNING

            if canonical_ip in self._tracked_ips:
                return ENQUEUE_DUPLICATE

            self._tracked_ips.add(canonical_ip)

            try:
                self._queue.put_nowait(canonical_ip)
            except queue.Full:
                self._tracked_ips.discard(canonical_ip)
                return ENQUEUE_FULL
            except Exception:
                self._tracked_ips.discard(canonical_ip)
                raise

        return ENQUEUE_QUEUED

    def stop(self, timeout=DEFAULT_SHUTDOWN_TIMEOUT_SECONDS):
        with self._lock:
            self._running = False
            self._stop_event.set()

            while True:
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
                else:
                    self._queue.task_done()

            self._tracked_ips.clear()
            thread = self._thread

        if thread is not None:
            thread.join(timeout=timeout)

            if thread.is_alive():
                return False

        with self._lock:
            if self._thread is thread:
                self._thread = None

        return True

    def is_running(self):
        with self._lock:
            return (
                self._thread is not None
                and self._thread.is_alive()
            )

    def status(self):
        with self._lock:
            thread = self._thread
            running = self._running
            queue_size = self._queue.qsize()
            queue_capacity = self._queue.maxsize
            tracked_count = len(self._tracked_ips)

        thread_alive = (
            thread is not None
            and thread.is_alive()
        )

        return {
            "running": running and thread_alive,
            "thread_alive": thread_alive,
            "thread_name": thread.name if thread is not None else None,
            "queue_size": queue_size,
            "queue_capacity": queue_capacity,
            "tracked_count": tracked_count,
        }

    def _run(self):
        try:
            while True:
                try:
                    ip_address = self._queue.get(
                        timeout=QUEUE_POLL_INTERVAL_SECONDS
                    )
                except queue.Empty:
                    if self._stop_event.is_set():
                        break

                    continue

                try:
                    if self._stop_event.is_set():
                        continue

                    self._process(ip_address)
                except Exception:
                    pass
                finally:
                    self._release(ip_address)
                    self._queue.task_done()
        finally:
            with self._lock:
                self._running = False

                if self._thread is threading.current_thread():
                    self._thread = None

    def _process(self, ip_address):
        if not settings.IP_REPUTATION_ENABLED:
            return

        db = self._session_factory()

        try:
            self._reputation_getter(db, ip_address)
        finally:
            db.close()

    def _release(self, ip_address):
        with self._lock:
            self._tracked_ips.discard(ip_address)
