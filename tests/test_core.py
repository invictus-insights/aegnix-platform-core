from aegnix_core.envelope import Envelope
from aegnix_core.crypto import (
    ed25519_generate, sign_envelope, verify_envelope,
    x25519_generate, derive_key, encrypt_payload_json, decrypt_payload_json
)
from aegnix_core.storage import SQLiteStorage, KeyRecord


def test_sign_verify():
    priv, pub = ed25519_generate()
    env = Envelope(producer="fusion-ae", subject="fused.track", payload={"x": 1})
    env = sign_envelope(env, priv, "fusion-ed25519-1")
    assert verify_envelope(env, pub)


def test_encrypt_decrypt():
    s_priv, s_pub = x25519_generate()
    r_priv, r_pub = x25519_generate()
    key1 = derive_key(s_priv, r_pub)
    key2 = derive_key(r_priv, s_pub)
    payload = {"msg": "hi"}
    enc = encrypt_payload_json(payload, key1, aad_fields={"subject": "t"})
    dec = decrypt_payload_json(enc, key2, aad_fields={"subject": "t"})
    assert dec == payload


def test_storage_roundtrip(tmp_path):
    db_path = tmp_path / "state.db"
    s = SQLiteStorage(str(db_path))
    rec = KeyRecord(ae_id="test-ae", pubkey_b64="abcd")
    s.upsert_key(rec)
    got = s.get_key("test-ae")
    assert got and got.pubkey_b64 == "abcd"
    s.mark_msg("123")
    assert s.seen_msg("123")
