"""CISA Known Exploited Vulnerabilities catalog."""

from __future__ import annotations

import json
import logging
import time

from aptwarden.cache import Cache
from aptwarden.config import parse_duration
from aptwarden.http import HttpClient, HttpError
from aptwarden.sources import SourceStatus

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kev (
    cve TEXT PRIMARY KEY,
    date_added TEXT,
    ransomware TEXT
) WITHOUT ROWID;
"""


class Kev:
    name = "kev"

    def __init__(self, settings: dict, cache: Cache, http: HttpClient, offline: bool = False):
        self.settings = settings
        self.cache = cache
        self.http = http
        self.offline = offline
        self.cache.db.executescript(_SCHEMA)
        self._ids: set[str] | None = None

    def refresh(self, force: bool = False) -> SourceStatus:
        status = SourceStatus(self.name)
        checked_at = self.cache.get_time("kev.checked_at")
        interval = parse_duration(self.settings["refresh_interval"])
        due = checked_at is None or time.time() - checked_at >= interval
        if not self.offline and (force or due):
            try:
                self._download(force)
            except (HttpError, ValueError, KeyError) as e:
                status.ok = self.count() > 0
                status.message = f"refresh failed: {e}"
                log.warning("kev refresh failed", extra={"error": str(e)})
        status.checked_at = self.cache.get_time("kev.checked_at")
        status.updated_at = self.cache.get_time("kev.updated_at")
        return status

    def _download(self, force: bool) -> None:
        headers = {}
        etag = self.cache.get_meta("kev.etag")
        if etag and not force and self.count():
            headers["If-None-Match"] = etag
        resp = self.http.get(self.settings["url"], headers=headers)
        if resp.status == 304:
            self.cache.set_time("kev.checked_at")
            self.cache.db.commit()
            return
        if resp.status != 200:
            raise HttpError(self.settings["url"], f"HTTP {resp.status}", resp.status)
        self.load(json.loads(resp.body))
        if resp.headers.get("etag"):
            self.cache.set_meta("kev.etag", resp.headers["etag"])
        self.cache.set_time("kev.checked_at")
        self.cache.set_time("kev.updated_at")
        self.cache.db.commit()

    def load(self, data: dict) -> int:
        rows = [
            (v["cveID"], v.get("dateAdded"), v.get("knownRansomwareCampaignUse"))
            for v in data["vulnerabilities"]
        ]
        if not rows:
            raise ValueError("KEV catalog is empty")
        with self.cache.db:
            self.cache.db.execute("DELETE FROM kev")
            self.cache.db.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?)", rows)
        self._ids = None
        log.info("kev updated", extra={"entries": len(rows)})
        return len(rows)

    def count(self) -> int:
        return self.cache.db.execute("SELECT COUNT(*) FROM kev").fetchone()[0]

    def contains(self, cve: str) -> bool:
        if self._ids is None:
            self._ids = {r[0] for r in self.cache.db.execute("SELECT cve FROM kev")}
        return cve in self._ids
