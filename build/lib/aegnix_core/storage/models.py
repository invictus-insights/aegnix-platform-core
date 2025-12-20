# aegnix_core/storage/models.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass
class KeyRecord:
    """
    Storage-level representation of an AE keyring entry.

    This is intentionally storage-agnostic and can be used by any provider
    (SQLite, memory, Firestore, enclave, etc.).
    """
    ae_id: str
    pubkey_b64: str
    roles: str = ""
    status: str = "trusted"   # trusted | revoked | pending | untrusted
    expires_at: Optional[str] = None
    pub_key_fpr: str = ""
