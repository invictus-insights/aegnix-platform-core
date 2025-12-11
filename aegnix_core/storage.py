# aegnix_core/storage.py

"""
DEPRECATED SHIM — scheduled for removal.
This module exists temporarily to preserve backward import compatibility
while storage components are being refactored into /storage/*.
"""

from aegnix_core.storage.models import KeyRecord
from aegnix_core.storage.provider import StorageProvider
from aegnix_core.storage.providers.sqlite_provider import SQLiteStorage
from aegnix_core.storage.providers.memory_provider import InMemoryStorage

__all__ = [
    "KeyRecord",
    "StorageProvider",
    "SQLiteStorage",
    "InMemoryStorage",
]
