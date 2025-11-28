import logging, threading
# from transport_base import BaseTransport
from aegnix_core.transport.transport_base import BaseTransport

log = logging.getLogger(__name__)

class LocalAdapter(BaseTransport):
    """Thread-safe in-memory pub/sub adapter for local testing."""

    def __init__(self):
        self.handlers = {}
        self.lock = threading.Lock()

    def publish(self, subject, message):
        log.info(f"[LOCAL PUB] {subject}: {str(message)[:80]}...")
        with self.lock:
            subscribers = self.handlers.get(subject, []).copy()
        for handler in subscribers:
            try:
                handler(message)
                log.debug(f"[LOCAL DELIVER] {subject} → {handler.__name__}")
            except Exception as e:
                log.error(f"[LOCAL ERROR] {subject}: {e}")

    def subscribe(self, subject, handler):
        with self.lock:
            self.handlers.setdefault(subject, []).append(handler)
        log.info(f"[LOCAL SUB] {handler.__name__} subscribed to {subject}")
