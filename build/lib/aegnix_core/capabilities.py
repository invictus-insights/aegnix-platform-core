# aegnix_core/protocol/capabilities.py

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Dict, Any


@dataclass
class AECapability:
    """
    Shared capability descriptor for an Atomic Expert.

    This is the *requested* participation:
    - which subjects it wants to publish to
    - which subjects it wants to subscribe to
    - optional metadata
    """
    ae_id: str
    publishes: List[str] = field(default_factory=list)
    subscribes: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    status: str = "active"  # reserved for future use (requested/approved/disabled)
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AECapability":
        return cls(
            ae_id=data["ae_id"],
            publishes=list(data.get("publishes", [])),
            subscribes=list(data.get("subscribes", [])),
            meta=dict(data.get("meta", {})),
            status=data.get("status", "active"),
            updated_at=data.get("updated_at") or datetime.utcnow().isoformat() + "Z",
        )
