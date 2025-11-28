import os
import pytest
from aegnix_core.transport.transport_local import LocalAdapter
from aegnix_core.transport import transport_factory
from aegnix_core.transport.transport_http import HTTPAdapter
from aegnix_core.transport.transport_gcp_pubsub import GcpPubSubAdapter

# CMD Line Usage: pytest -v -s --log-cli-level=DEBUG .\tests\test_transport_factory.py

def test_local_pubsub_loopback(caplog):
    """Ensure LocalAdapter can publish and immediately receive messages."""
    bus = LocalAdapter()
    received = []

    def on_fusion(msg):
        received.append(msg)

    bus.subscribe("fusion.topic", on_fusion)
    bus.publish("fusion.topic", {"track_id": "TEST123"})

    assert received and received[0]["track_id"] == "TEST123"
    assert "LOCAL PUB" in caplog.text


def test_transport_factory_modes(monkeypatch):
    """Verify that transport_factory returns correct adapter per AE_TRANSPORT."""
    # Local mode (default)
    monkeypatch.delenv("AE_TRANSPORT", raising=False)
    assert isinstance(transport_factory(), LocalAdapter)

    # HTTP mode
    monkeypatch.setenv("AE_TRANSPORT", "http")
    assert isinstance(transport_factory(), HTTPAdapter)

    # GCP mode
    monkeypatch.setenv("AE_TRANSPORT", "gcp")
    assert isinstance(transport_factory(), GcpPubSubAdapter)
