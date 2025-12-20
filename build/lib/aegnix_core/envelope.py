"""
aegnix_core.envelope
--------------------
Defines the Envelope class — the canonical message container for AEGNIX.
Every AE-to-AE or AE-to-ABI message uses this structure.

Key features:
- Deterministic canonicalization for signing
- Replay-safe identifiers (msg_id, ts)
- Support for labels, payload types, and optional encryption metadata
"""

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from .constants import SCHEMA_VERSION, DEFAULT_SENSITIVITY
from .utils import new_id, now_ts
import json


@dataclass
class Envelope:
    schema_ver: str = SCHEMA_VERSION
    msg_id: str = field(default_factory=new_id)
    corr_id: Optional[str] = None
    ts: str = field(default_factory=now_ts)
    producer: str = ""          # ae_id
    subject: str = ""           # e.g., "fused.track"
    key_id: str = ""            # identifies signing key/pubkey
    sig: Optional[str] = None   # base64 signature (over canonical header+payload)
    sensitivity: str = DEFAULT_SENSITIVITY  # "UNCLASS"|"CUI"|...
    labels: List[str] = field(default_factory=list)
    payload_type: str = "json"  # "json"|"bytes"
    payload: Any = None         # dict for json; base64 str for bytes if needed
    # optional AAD for encryption policies
    aad: Optional[Dict[str, Any]] = None

    def to_dict(self, include_sig: bool = True) -> Dict[str, Any]:
        d = asdict(self)
        if not include_sig:
            d["sig"] = None
        return d


    def to_signing_bytes(self) -> bytes:
        import json
        body = {
            "producer": self.producer,
            "subject": self.subject,
            "payload": self.payload,
            "labels": self.labels,
        }
        # enforce deterministic serialization
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # def to_signing_bytes(self) -> bytes:
    #     # We sign the envelope with sig=None (canonical header+payload)
    #     return canonical_json(self.to_dict(include_sig=False))

    def to_bytes(self) -> bytes:
        """Convert the envelope (without signature) to bytes for signing."""
        data = asdict(self).copy()
        data["sig"] = None  # don't sign the signature itself
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def to_json(self) -> str:
        """Full JSON serialization (including signature)."""
        return json.dumps(asdict(self), sort_keys=True)

    def to_json_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    @staticmethod
    def make(producer, subject, payload, labels, key_id, sensitivity="UNCLASS"):
        """Factory to create a properly structured envelope."""
        return Envelope(
            schema_ver="1.0",
            msg_id=new_id(),
            corr_id=None,
            ts=datetime.utcnow().isoformat() + "Z",
            producer=producer,
            subject=subject,
            key_id=key_id,
            sig=None,
            sensitivity=sensitivity,
            labels=labels,
            payload_type="json",
            payload=payload,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Envelope":
        """Reconstruct Envelope from dict (inverse of to_dict).

        This is used by the ABI /emit endpoint to rebuild an envelope
        from a JSON payload before signature verification.
        """
        env = cls(
            schema_ver=data.get("schema_ver", "1.0"),
            msg_id=data.get("msg_id"),
            corr_id=data.get("corr_id"),
            ts=data.get("ts", now_ts()),
            producer=data.get("producer", ""),
            subject=data.get("subject", ""),
            key_id=data.get("key_id", ""),
            sig=data.get("sig"),
            sensitivity=data.get("sensitivity", DEFAULT_SENSITIVITY),
            labels=data.get("labels", []),
            payload_type=data.get("payload_type", "json"),
            payload=data.get("payload"),
            aad=data.get("aad"),
        )
        return env
