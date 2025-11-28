# aegnix_core/transport/__init__.py
import os
from aegnix_core.transport.transport_local import LocalAdapter
from aegnix_core.transport.transport_http import HTTPAdapter
from aegnix_core.transport.transport_gcp_pubsub import GcpPubSubAdapter
from aegnix_core.transport.transport_kafka import KafkaAdapter


def transport_factory():
    """Return best-fit transport adapter based on environment or config."""
    mode = os.getenv("AE_TRANSPORT", "local").lower()
    if mode == "gcp":
        return GcpPubSubAdapter()
    if mode == "http":
        return HTTPAdapter(os.getenv("ABI_URL", "http://localhost:8080"))
    if mode == "kafka":
        return KafkaAdapter(mock=os.getenv("KAFKA_MOCK", "1") == "1")
    return LocalAdapter()
