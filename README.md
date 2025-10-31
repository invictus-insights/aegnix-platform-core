# AEGNIX Core

Lightweight, portable cryptographic and messaging primitives shared by all components of the **AEGNIX Swarm Framework**.

## Overview

`aegnix_core` provides the foundational building blocks for secure, decentralized communication between **Atomic Experts (AEs)** and the **Agent Bridge Interface (ABI)**.

It includes:

* **Envelope schema** for structured, signed, replay-safe messages
* **Crypto primitives** (Ed25519, X25519 + HKDF + AES-GCM) for signing and encryption
* **Pluggable storage** interface (SQLite by default) for keyrings, audit logs, and replay guards

All components are vendor-neutral, DoD-ready, and deployable inside air-gapped or cloud environments.

---

## Installation

```bash
pip install -e .
```

Requires Python ≥ 3.10 and the `cryptography` library.

---

## Quick Example

```python
from aegnix_core.envelope import Envelope
from aegnix_core.crypto import ed25519_generate, sign_envelope, verify_envelope

# Generate an AE identity keypair
priv, pub = ed25519_generate()

# Create a message
env = Envelope(producer="fusion-ae", subject="fused.track", payload={"msg": "hello"})

# Sign and verify
env = sign_envelope(env, priv, key_id="fusion-ed25519-1")
print("Verified:", verify_envelope(env, pub))
```

---

## Encryption Example

```python
from aegnix_core.crypto import (
    x25519_generate, derive_key, encrypt_payload_json, decrypt_payload_json
)

# Generate sender & receiver keys
s_priv, s_pub = x25519_generate()
r_priv, r_pub = x25519_generate()

# Derive symmetric key via ECDH + HKDF
k_send = derive_key(s_priv, r_pub)
k_recv = derive_key(r_priv, s_pub)

payload = {"data": "classified"}
enc = encrypt_payload_json(payload, k_send, aad_fields={"subject": "demo"})
dec = decrypt_payload_json(enc, k_recv, aad_fields={"subject": "demo"})
assert dec == payload
```

---

## Storage Interface

```python
from aegnix_core.storage import SQLiteStorage, KeyRecord

store = SQLiteStorage("abi_state.db")
store.upsert_key(KeyRecord(ae_id="fusion-ae", pubkey_b64="abcd"))
print(store.get_key("fusion-ae"))
```

---

## Design Goals

| Goal                     | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| **Zero Vendor Lock**     | Runs in GCP, on bare metal, or in classified enclaves |
| **Deterministic Crypto** | Stable Ed25519 / X25519 primitives                    |
| **Modular Storage**      | Default SQLite + pluggable adapters                   |
| **Replay Protection**    | Built-in message tracking                             |
| **Audit Ready**          | Schema-controlled envelope signatures                 |

---

## Testing

```bash
pytest -v
```

All core functionality (signing, encryption, storage) is covered by tests in `/tests`.

---

## License

MIT © Invictus Insights LLC R&D
