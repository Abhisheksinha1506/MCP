"""Append-only snapshot storage. No update or delete API."""
import json
import sqlite3
from pathlib import Path
from .privacy import redact
from .schema import Snapshot


class SnapshotStore:
    def __init__(self, path: str | Path):
        self._db = sqlite3.connect(str(path))
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS snapshots "
            "(id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL)"
        )
        self._db.commit()

    def save(self, snapshot: Snapshot) -> str:
        payload = snapshot.to_dict()
        with self._db:
            self._db.execute(
                "INSERT INTO snapshots (id, created_at, payload) VALUES (?, ?, ?)",
                (payload["id"], payload["created_at"], json.dumps(payload, allow_nan=False)),
            )
        return payload["id"]

    def get(self, snapshot_id: str) -> dict | None:
        row = self._db.execute("SELECT payload FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        return redact(json.loads(row[0])) if row else None

    def latest(self) -> dict | None:
        row = self._db.execute(
            "SELECT payload FROM snapshots ORDER BY created_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return redact(json.loads(row[0])) if row else None

    def close(self) -> None:
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
