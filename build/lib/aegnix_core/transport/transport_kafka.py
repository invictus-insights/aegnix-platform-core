# aegnix_core/transport/transport_kafka.py
import logging
import json
from typing import Optional, Any
from aegnix_core.transport.transport_base import BaseTransport

log = logging.getLogger("AE.Transport.Kafka")


class KafkaAdapter(BaseTransport):
    """
    Mesh transport adapter (Phase 8).

    • Producer-only
    • ABI-owned
    • Subject == Kafka topic
    • Durability plane ONLY
    """

    name = "kafka"

    def __init__(self, brokers="localhost:9092", enabled=True):
        self.brokers = brokers
        self.enabled = enabled
        self._producer = None

        if not self.enabled:
            log.warning("[KAFKA] disabled")
            return

        try:
            from kafka import KafkaProducer

            self._producer = KafkaProducer(
                bootstrap_servers=self.brokers,
                # value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                linger_ms=5,
                acks="all",
            )

            log.info(f"[KAFKA] connected brokers={self.brokers}")

        except Exception:
            log.exception("[KAFKA] init failed — disabling transport")
            self.enabled = False

    def publish(
        self,
        topic: str,
        payload: bytes | dict,
        headers=None,
        key: Optional[str] = None,
    ) -> Any:
        """
        Mesh egress only.

        topic maps 1:1 to Kafka topic.
        payload is canonical bytes at the boundary.
        headers/key are accepted for forward compatibility.
        """
        if not self.enabled:
            log.info(f"[KAFKA-SKIP] {topic}")
            return

        data = self.to_bytes(payload)

        log.info({
            "event": "mesh_publish",
            "transport": "kafka",
            "topic": topic,
            "bytes": len(data),
        })

        try:

            self._producer.send(
                topic,
                value=data,
                key=key.encode("utf-8") if key else None,
                headers=[(k, v.encode("utf-8")) for k, v in (headers or {}).items()],
            )
            self._producer.flush(timeout=1.0)
            log.debug(f"[KAFKA PUB] topic={topic}")

        except Exception:
            log.exception(f"[KAFKA PUB ERROR] topic={topic}")
