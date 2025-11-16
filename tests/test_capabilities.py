# tests/test_capabilities.py

import json
from aegnix_core.storage import SQLiteStorage
from aegnix_core.capabilities import AECapability
from datetime import datetime


def test_capability_basic_roundtrip():
    cap = AECapability(
        ae_id="fusion_ae",
        publishes=["fusion.topic"],
        subscribes=["fused.track"],
        meta={"version": "0.1.0"},
        status="active",
    )

    d = cap.to_dict()
    restored = AECapability.from_dict(d)

    assert restored.ae_id == "fusion_ae"
    assert restored.publishes == ["fusion.topic"]
    assert restored.subscribes == ["fused.track"]
    assert restored.meta == {"version": "0.1.0"}
    assert restored.status == "active"
    # updated_at should exist and be ISO timestamp
    assert "T" in restored.updated_at


def test_storage_capability_crud(tmp_path):
    db = tmp_path / "abi_state.db"
    store = SQLiteStorage(str(db))

    cap = AECapability(
        ae_id="fusion_ae",
        publishes=["fusion.topic"],
        subscribes=["fused.track"],
        meta={"note": "test"},
        status="active",
    )

    store.upsert_capability(cap)

    # Fetch back
    got = store.get_capability("fusion_ae")
    assert got is not None
    assert got.ae_id == "fusion_ae"
    assert got.publishes == ["fusion.topic"]
    assert got.subscribes == ["fused.track"]
    assert got.meta == {"note": "test"}
    assert got.status == "active"

    # List should contain it
    caps = store.list_capabilities()
    assert any(c.ae_id == "fusion_ae" for c in caps)


def test_capability_schema_exists(tmp_path):
    db = tmp_path / "abi_state.db"
    store = SQLiteStorage(str(db))

    cur = store.db.execute("PRAGMA table_info(ae_capabilities)")
    cols = [row[1] for row in cur.fetchall()]

    expected = {"ae_id", "publishes", "subscribes", "meta", "status", "updated_at"}

    # Make sure all expected columns exist
    for col in expected:
        assert col in cols
