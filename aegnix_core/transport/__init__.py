# aegnix_core/transport/__init__.py
import os
from aegnix_core.transport.transport_local import LocalAdapter
from aegnix_core.transport.transport_http import HTTPAdapter
from aegnix_core.transport.transport_gcp_pubsub import GcpPubSubAdapter
from aegnix_core.transport.transport_kafka import KafkaAdapter


def transport_factory(role: str = "mesh"):
    """
    role:
      - "mesh"   → ABI egress (Kafka / HTTP / PubSub)
      - "client" → AE → ABI communication
    """
    if role == "mesh":
        mode = os.getenv("ABI_MESH_TRANSPORT", "http").lower()
    else:
        mode = os.getenv("AE_TRANSPORT", "http").lower()

    if mode == "gcp":
        return GcpPubSubAdapter()

    if mode == "kafka":
        return KafkaAdapter(
            brokers=os.getenv("KAFKA_BROKERS", "localhost:9092"),
            enabled=os.getenv("KAFKA_ENABLED", "1") == "1",
        )

    if mode == "http":
        return HTTPAdapter(os.getenv("ABI_URL", "http://localhost:8080"))

    return LocalAdapter()
