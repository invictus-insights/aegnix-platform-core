from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Iterable
import json
import time

Headers = Dict[str, str]


class TransportError(Exception):
    pass


class TransportTransientError(TransportError):
    pass


class TransportPermanentError(TransportError):
    pass


@dataclass
class TransportMessage:
    topic: str
    payload: bytes
    headers: Optional[Headers] = None
    message_id: Optional[str] = None
    ts_ms: int = int(time.time() * 1000)

    _ack: Optional[Callable[[], None]] = None
    _nack: Optional[Callable[[bool], None]] = None

    def ack(self) -> None:
        if self._ack:
            self._ack()

    def nack(self, requeue: bool = True) -> None:
        if self._nack:
            self._nack(requeue)


class BaseTransport:
    """
    Phase 8.1 Contract (Mesh Transport)

    Canonical payload at the transport boundary is bytes.
    Legacy adapters may still accept dict; the adapter should convert.
    """
    name: str = "base"

    def publish(
        self,
        topic: str,
        payload: bytes | dict,
        headers: Optional[Headers] = None,
        key: Optional[str] = None,
    ) -> Any:
        raise NotImplementedError

    def subscribe(
        self,
        topics: list[str] | str,
        handler: Optional[Callable] = None,
        group: Optional[str] = None,
        options: Optional[dict[str, Any]] = None,
    ) -> Any:
        """
        Backward-compatible signature:
        - Old: subscribe(subject: str, handler: fn)
        - New: subscribe(topics: list[str], group=?, options=?) -> iterable/messages (Phase 8.2+)
        """
        raise NotImplementedError

    def healthz(self) -> dict:
        return {"status": "ok", "transport": self.name}

    def readyz(self) -> dict:
        return {"status": "ok", "transport": self.name}

    def close(self) -> None:
        return

    # ---------------------------
    # Helpers for legacy adapters
    # ---------------------------
    @staticmethod
    def to_bytes(payload: bytes | dict) -> bytes:
        if isinstance(payload, bytes):
            return payload
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")
