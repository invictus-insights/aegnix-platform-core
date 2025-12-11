from __future__ import annotations
from typing import Optional, Dict, Any, List
import json, sqlite3, os
from aegnix_core.capabilities import AECapability
from aegnix_core.storage.provider import StorageProvider
from aegnix_core.storage.models import KeyRecord


class SQLiteStorage(StorageProvider):
    def __init__(self, path="db/abi_state.db"):
        # If no directory, default to current working directory
        dir_path = os.path.dirname(path) or "."
        os.makedirs(dir_path, exist_ok=True)
        # self.db = sqlite3.connect(path)
        self.db = sqlite3.connect(path, check_same_thread=False)

        self._init()

    def execute(self, sql: str, params: tuple = None):
        if params:
            return self.db.execute(sql, params)
        return self.db.execute(sql)

    def fetch_one(self, sql: str, params: tuple = None):
        cur = self.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        # Turn sqlite3.Row into dict
        if isinstance(row, sqlite3.Row):
            return dict(row)
        # Otherwise map tuple to column names
        columns = [col[0] for col in cur.description]
        return {columns[i]: row[i] for i in range(len(columns))}

    def insert(self, table: str, record: dict):
        keys = ", ".join(record.keys())
        placeholders = ", ".join(["?"] * len(record))
        values = tuple(record.values())
        self.db.execute(
            f"INSERT INTO {table} ({keys}) VALUES ({placeholders})",
            values
        )
        self.db.commit()

    def _init(self) -> None:
        c = self.db.cursor()
        cur = self.db.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS keyring(
            ae_id TEXT PRIMARY KEY,
            pubkey_b64 TEXT NOT NULL,
            roles TEXT,
            status TEXT,
            expires_at TEXT,
            pub_key_fpr TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS audit(
            ts TEXT,
            event_type TEXT,
            payload TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS replay_guard(
            msg_id TEXT PRIMARY KEY
        )""")

        # NEW: capabilities table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ae_capabilities (
              ae_id TEXT PRIMARY KEY,
              publishes TEXT NOT NULL,
              subscribes TEXT NOT NULL,
              meta TEXT,
              status TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        # self.db.commit()

        self.db.commit()

    def upsert_key(self, rec: KeyRecord) -> None:
        self.db.execute(
            "INSERT INTO keyring(ae_id,pubkey_b64,roles,status,expires_at,pub_key_fpr) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(ae_id) DO UPDATE SET pubkey_b64=excluded.pubkey_b64, roles=excluded.roles, "
            "status=excluded.status, expires_at=excluded.expires_at, pub_key_fpr=excluded.pub_key_fpr",
            (rec.ae_id, rec.pubkey_b64, rec.roles, rec.status, rec.expires_at, rec.pub_key_fpr)
        )
        self.db.commit()

    def get_key(self, ae_id: str) -> Optional[KeyRecord]:
        cur = self.db.execute("SELECT ae_id,pubkey_b64,roles,status,expires_at,pub_key_fpr FROM keyring WHERE ae_id=?", (ae_id,))
        row = cur.fetchone()
        if not row: return None
        return KeyRecord(*row)

    def revoke_key(self, ae_id: str) -> None:
        self.db.execute("UPDATE keyring SET status='revoked' WHERE ae_id=?", (ae_id,))
        self.db.commit()

    def log_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        from aegnix_core.utils import now_ts

        self.db.execute("INSERT INTO audit(ts,event_type,payload) VALUES(?,?,?)",
                        (now_ts(), event_type, json.dumps(payload, separators=(",", ":"), sort_keys=True)))
        self.db.commit()

    def seen_msg(self, msg_id: str) -> bool:
        cur = self.db.execute("SELECT 1 FROM replay_guard WHERE msg_id=?", (msg_id,))
        return cur.fetchone() is not None

    def mark_msg(self, msg_id: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO replay_guard(msg_id) VALUES(?)", (msg_id,))
        self.db.commit()

    # --- NEW Capability helpers ---

    def upsert_capability(self, cap: AECapability) -> None:
        cur = self.db.cursor()
        cur.execute(
            """
            INSERT INTO ae_capabilities (ae_id, publishes, subscribes, meta, status, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ae_id) DO UPDATE SET
              publishes = excluded.publishes,
              subscribes = excluded.subscribes,
              meta = excluded.meta,
              status = excluded.status,
              updated_at = excluded.updated_at
            """,
            (
                cap.ae_id,
                json.dumps(cap.publishes),
                json.dumps(cap.subscribes),
                json.dumps(cap.meta),
                cap.status,
                cap.updated_at,
            ),
        )
        self.db.commit()

    def get_capability(self, ae_id: str) -> Optional[AECapability]:
        cur = self.db.cursor()
        cur.execute(
            "SELECT ae_id, publishes, subscribes, meta, status, updated_at FROM ae_capabilities WHERE ae_id = ?",
            (ae_id,),
        )
        row = cur.fetchone()
        if not row:
            return None
        ae_id, publishes, subscribes, meta, status, updated_at = row
        return AECapability(
            ae_id=ae_id,
            publishes=json.loads(publishes),
            subscribes=json.loads(subscribes),
            meta=json.loads(meta) if meta else {},
            status=status,
            updated_at=updated_at,
        )

    def list_capabilities(self) -> List[AECapability]:
        cur = self.db.cursor()
        cur.execute("SELECT ae_id, publishes, subscribes, meta, status, updated_at FROM ae_capabilities")
        caps = []
        for row in cur.fetchall():
            ae_id, publishes, subscribes, meta, status, updated_at = row
            caps.append(
                AECapability(
                    ae_id=ae_id,
                    publishes=json.loads(publishes),
                    subscribes=json.loads(subscribes),
                    meta=json.loads(meta) if meta else {},
                    status=status,
                    updated_at=updated_at,
                )
            )
        return caps

    def fetch_by_fingerprint(self, fpr: str):
        cur = self.db.execute(
            "SELECT ae_id, pubkey_b64, roles, status, expires_at, pub_key_fpr "
            "FROM keyring WHERE pub_key_fpr = ?",
            (fpr,)
        )
        row = cur.fetchone()
        return KeyRecord(*row) if row else None

    def fetch_by_pubkey(self, pubkey_b64: str):
        cur = self.db.execute(
            "SELECT ae_id, pubkey_b64, roles, status, expires_at, pub_key_fpr "
            "FROM keyring WHERE pubkey_b64 = ?",
            (pubkey_b64,)
        )
        row = cur.fetchone()
        return KeyRecord(*row) if row else None

    def list_keys(self):
        cur = self.db.execute(
            "SELECT ae_id, pubkey_b64, roles, status, expires_at "
            "FROM keyring"
        )
        return [
            dict(zip(["ae_id", "pubkey_b64", "roles", "status", "expires_at"], r))
            for r in cur.fetchall()
        ]

    def flush(self):
        self.db.commit()

    def close(self):
        self.db.close()
