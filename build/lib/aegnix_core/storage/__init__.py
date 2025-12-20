# aegnix_core/storage/__init__.py

from .models import KeyRecord
from .provider import StorageProvider
from .providers.memory_provider import InMemoryStorage
from .providers.sqlite_provider import SQLiteStorage
from pathlib import Path
import os


def load_storage_provider(config: dict | None = None) -> StorageProvider:
    """
    Factory resolver for selecting the runtime storage backend.

    For now:
        - sqlite (default)
        - memory
    """
    config = config or {}
    provider = config.get("provider") or os.getenv("AEGNIX_STORAGE_PROVIDER", "sqlite")

    if provider == "memory":
        return InMemoryStorage()

    if provider == "sqlite":
        db_path = config.get("sqlite_path") or os.getenv("AEGNIX_DB_PATH", "db/abi_state.db")

    # if provider == "sqlite":
    #     raw_path = (config.get("sqlite_path") or os.getenv("AEGNIX_DB_PATH") or "db/abi_state.db")
    #
    #     # Normalize path (this is the fix)
    #     db_path = Path(raw_path).expanduser().resolve()

        return SQLiteStorage(db_path)
    raise ValueError(f"Unknown storage provider: {provider}")


__all__ = [
    "KeyRecord",
    "StorageProvider",
    "InMemoryStorage",
    "SQLiteStorage",
    "load_storage_provider",
]
