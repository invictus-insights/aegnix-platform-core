from typing import Optional, Dict, Any, List
from aegnix_core.storage.models import KeyRecord
from aegnix_core.storage.provider import StorageProvider

class InMemoryStorage(StorageProvider):
    def __init__(self):
        self.keys = {}
        self.audit = []
        self.replay = set()
        self.capabilities = {}

    def upsert_key(self, rec: KeyRecord):
        self.keys[rec.ae_id] = rec

    def get_key(self, ae_id: str):
        return self.keys.get(ae_id)

    def revoke_key(self, ae_id: str):
        rec = self.keys.get(ae_id)
        if rec: rec.status = "revoked"

    def fetch_by_fingerprint(self, fpr: str):
        return next((rec for rec in self.keys.values() if rec.pub_key_fpr == fpr), None)

    def fetch_by_pubkey(self, pubkey_b64: str):
        return next((rec for rec in self.keys.values() if rec.pubkey_b64 == pubkey_b64), None)

    def list_keys(self):
        return [vars(rec) for rec in self.keys.values()]

    # audit
    def log_event(self, event_type: str, payload: Dict[str, Any]):
        self.audit.append((event_type, payload))

    # replay guard
    def seen_msg(self, msg_id: str) -> bool:
        return msg_id in self.replay

    def mark_msg(self, msg_id: str):
        self.replay.add(msg_id)

    # capability storage
    def upsert_capability(self, cap):
        self.capabilities[cap.ae_id] = cap

    def get_capability(self, ae_id: str):
        return self.capabilities.get(ae_id)

    def list_capabilities(self):
        return list(self.capabilities.values())

    # generic ops not needed — no SQL
    def execute(self, *args, **kwargs): pass
    def insert(self, *args, **kwargs): pass
    def fetch_one(self, *args, **kwargs): pass
