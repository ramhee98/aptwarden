"""Feed cache in SQLite. Everything in here can be re-downloaded, so the file
can be deleted at any time."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

# Bump when a table layout changes: the cache is then rebuilt from scratch.
CACHE_VERSION = 2


class Cache:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        if self.db.execute("PRAGMA user_version").fetchone()[0] != CACHE_VERSION:
            tables = [r[0] for r in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'")]
            for t in tables:
                self.db.execute(f'DROP TABLE "{t}"')
            self.db.execute(f"PRAGMA user_version={CACHE_VERSION}")
        self.db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        self.db.commit()

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.db.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def get_time(self, key: str) -> float | None:
        v = self.get_meta(key)
        return float(v) if v is not None else None

    def set_time(self, key: str, ts: float | None = None) -> None:
        self.set_meta(key, str(time.time() if ts is None else ts))

    def close(self) -> None:
        self.db.close()
