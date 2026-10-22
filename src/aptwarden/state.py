"""Persistent run history in SQLite (state.db)."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from aptwarden.models import Finding

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    data TEXT
);
CREATE TABLE IF NOT EXISTS host_results (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    address TEXT,
    ok INTEGER NOT NULL,
    error TEXT,
    summary TEXT,
    warnings TEXT,
    scanned_at TEXT NOT NULL,
    PRIMARY KEY (run_id, host)
);
CREATE TABLE IF NOT EXISTS findings (
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    source_package TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity INTEGER NOT NULL,
    kev INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (run_id, host, source_package, installed_version, vuln_id),
    FOREIGN KEY (run_id, host) REFERENCES host_results(run_id, host) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS seen (
    host TEXT NOT NULL,
    source_package TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    alerted_at TEXT,
    PRIMARY KEY (host, source_package, vuln_id)
);
CREATE INDEX IF NOT EXISTS host_results_host ON host_results (host, scanned_at);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class HostRecord:
    run_id: str
    host: str
    address: str | None
    ok: bool
    error: str | None
    summary: dict
    warnings: list[str]
    scanned_at: str
    findings: list[Finding] = field(default_factory=list)


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"{path} was written by a newer aptwarden (schema {version})")
        self.db.executescript(_SCHEMA)
        if version == 1:
            self.db.execute("ALTER TABLE seen ADD COLUMN alerted_at TEXT")
        self.db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.db.commit()

    def start_run(self, run_id: str, command: str) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO runs (id, command, started_at, status) VALUES (?, ?, ?, 'running')",
                (run_id, command, utcnow()),
            )

    def finish_run(self, run_id: str, status: str, data: dict) -> None:
        with self.db:
            self.db.execute(
                "UPDATE runs SET finished_at = ?, status = ?, data = ? WHERE id = ?",
                (utcnow(), status, json.dumps(data), run_id),
            )

    def save_host(self, run_id: str, record: HostRecord) -> None:
        with self.db:
            self.db.execute(
                "INSERT INTO host_results VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, record.host, record.address, int(record.ok), record.error,
                 json.dumps(record.summary), json.dumps(record.warnings), record.scanned_at),
            )
            self.db.executemany(
                "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (run_id, record.host, f.source_package, f.installed_version, f.vuln_id,
                     str(f.status), int(f.severity), int(f.kev), json.dumps(f.to_dict()))
                    for f in record.findings
                ],
            )

    def mark_seen(self, host: str, findings: list[Finding], now: str | None = None) -> None:
        """Record first/last seen and set ``first_seen`` on the findings."""
        now = now or utcnow()
        with self.db:
            for f in findings:
                self.db.execute(
                    "INSERT INTO seen (host, source_package, vuln_id, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(host, source_package, vuln_id) "
                    "DO UPDATE SET last_seen = excluded.last_seen",
                    (host, f.source_package, f.vuln_id, now, now),
                )
                row = self.db.execute(
                    "SELECT first_seen FROM seen WHERE host = ? AND source_package = ? "
                    "AND vuln_id = ?",
                    (host, f.source_package, f.vuln_id),
                ).fetchone()
                f.first_seen = row[0]

    def alert_due(self, host: str, findings: list[Finding], remind_after: int,
                  now: str | None = None) -> list[Finding]:
        """Findings never alerted, or last alerted more than ``remind_after``
        seconds ago (0 disables reminders)."""
        now_dt = datetime.fromisoformat(now or utcnow())
        due = []
        for f in findings:
            row = self.db.execute(
                "SELECT alerted_at FROM seen WHERE host = ? AND source_package = ? "
                "AND vuln_id = ?", (host, f.source_package, f.vuln_id)).fetchone()
            alerted = row[0] if row else None
            if alerted is None or (
                remind_after
                and now_dt - datetime.fromisoformat(alerted) >= timedelta(seconds=remind_after)
            ):
                due.append(f)
        return due

    def mark_alerted(self, host: str, findings: list[Finding], now: str | None = None) -> None:
        now = now or utcnow()
        with self.db:
            for f in findings:
                self.db.execute(
                    "INSERT INTO seen VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(host, source_package, vuln_id) "
                    "DO UPDATE SET alerted_at = excluded.alerted_at",
                    (host, f.source_package, f.vuln_id, now, now, now),
                )

    def latest(self, host: str, ok_only: bool = False) -> HostRecord | None:
        sql = (
            "SELECT run_id, host, address, ok, error, summary, warnings, scanned_at "
            "FROM host_results WHERE host = ?"
            + (" AND ok = 1" if ok_only else "")
            + " ORDER BY scanned_at DESC, run_id DESC LIMIT 1"
        )
        row = self.db.execute(sql, (host,)).fetchone()
        if not row:
            return None
        rec = HostRecord(row[0], row[1], row[2], bool(row[3]), row[4], json.loads(row[5] or "{}"),
                         json.loads(row[6] or "[]"), row[7])
        rec.findings = [
            Finding.from_dict(json.loads(r[0]))
            for r in self.db.execute(
                "SELECT data FROM findings WHERE run_id = ? AND host = ?", (rec.run_id, host)
            )
        ]
        return rec

    def get(self, key: str, default=None):
        row = self.db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, **values) -> None:
        """Store JSON values atomically, keys with "." passed as ``**{"a.b": v}``."""
        with self.db:
            self.db.executemany(
                "INSERT INTO kv VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [(k, json.dumps(v)) for k, v in values.items()],
            )

    def run_info(self, run_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT id, command, started_at, finished_at, status, data FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if not row:
            return None
        return {"id": row[0], "command": row[1], "started_at": row[2], "finished_at": row[3],
                "status": row[4], "data": json.loads(row[5] or "{}")}

    def prune(self, keep_runs: int) -> int:
        """Delete all but the newest ``keep_runs`` runs. Returns deleted count."""
        with self.db:
            cur = self.db.execute(
                "DELETE FROM runs WHERE id NOT IN "
                "(SELECT id FROM runs ORDER BY started_at DESC, id DESC LIMIT ?)",
                (keep_runs,),
            )
        return cur.rowcount

    def close(self) -> None:
        self.db.close()
