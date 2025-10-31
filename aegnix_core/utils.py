"""
aegnix_core.utils
-----------------
Lightweight helpers for UUID generation, timestamping, base64 utilities, and canonical JSON serialization.
These functions keep all envelope signing deterministic and replay-safe.
"""

from __future__ import annotations
import base64, json, time, uuid, hashlib
from typing import Any, Dict

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def now_ts() -> str:
    # RFC3339 / ISO 8601 in UTC, second precision
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def new_id() -> str:
    return uuid.uuid4().hex

def canonical_json(obj: Dict[str, Any]) -> bytes:
    # Deterministic, minimal JSON for signing
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
