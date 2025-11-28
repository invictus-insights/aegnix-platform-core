class BaseTransport:
    """Abstract interface for all message bus adapters."""
    def publish(self, subject: str, message: str):
        raise NotImplementedError

    def subscribe(self, subject: str, handler):
        raise NotImplementedError
