"""Debian Security Tracker (security-tracker.debian.org/tracker/data/json).

The feed is keyed by source package, then vulnerability id, then release. It is
about 85 MB, so it is only downloaded when Last-Modified changes and is stored
in the cache reduced to one row per (source, release, vulnerability).
"""

from __future__ import annotations

import json
import logging
import time

from aptwarden import debversion
from aptwarden.config import parse_duration
from aptwarden.http import HttpError
from aptwarden.models import Finding, FindingStatus, HostInventory
from aptwarden.sources import Source, SourceStatus

log = logging.getLogger(__name__)

# A healthy feed covers several thousand source packages. Anything far below
# that is a broken response and must not replace good cached data.
MIN_SOURCE_PACKAGES = 1000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS debian_tracker (
    source TEXT NOT NULL,
    release TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    status TEXT NOT NULL,
    fixed_version TEXT,
    urgency TEXT,
    nodsa INTEGER NOT NULL DEFAULT 0,
    repositories TEXT NOT NULL,
    PRIMARY KEY (source, release, vuln_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS debian_tracker_desc (
    vuln_id TEXT PRIMARY KEY,
    description TEXT NOT NULL
) WITHOUT ROWID;
"""


class DebianTrackerSource(Source):
    name = "debian_tracker"
    priority = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache.db.executescript(_SCHEMA)
        self.host_warnings: dict[str, list[str]] = {}

    def _meta(self, key: str) -> str:
        return f"{self.name}.{key}"

    def has_data(self) -> bool:
        return self.cache.db.execute("SELECT 1 FROM debian_tracker LIMIT 1").fetchone() is not None

    def releases(self) -> set[str]:
        rows = self.cache.db.execute("SELECT DISTINCT release FROM debian_tracker")
        return {r[0] for r in rows}

    def refresh(self, force: bool = False) -> SourceStatus:
        status = SourceStatus(self.name)
        has_data = self.has_data()
        checked_at = self.cache.get_time(self._meta("checked_at"))
        interval = parse_duration(self.settings["refresh_interval"])

        due = checked_at is None or time.time() - checked_at >= interval
        if not self.offline and (force or not has_data or due):
            self._download(status, has_data, force)

        status.updated_at = self.cache.get_time(self._meta("updated_at"))
        status.checked_at = self.cache.get_time(self._meta("checked_at"))
        if not self.has_data():
            status.ok = False
            status.message = status.message or "no tracker data available"
        elif status.checked_at is not None:
            max_age = parse_duration(self.settings["max_age"])
            if time.time() - status.checked_at > max_age:
                status.warnings.append(
                    f"tracker data not verified for more than {self.settings['max_age']}"
                )
        return status

    def _download(self, status: SourceStatus, has_data: bool, force: bool) -> None:
        url = self.settings["url"]
        headers = {}
        last_modified = self.cache.get_meta(self._meta("last_modified"))
        if last_modified and has_data and not force:
            headers["If-Modified-Since"] = last_modified
        started = time.monotonic()
        try:
            resp = self.http.get(url, headers=headers)
            if resp.status == 304:
                self.cache.set_time(self._meta("checked_at"))
                self.cache.db.commit()
                log.info("debian tracker unchanged", extra={"source": self.name})
                return
            if resp.status != 200:
                raise HttpError(url, f"HTTP {resp.status}", resp.status)
            new_last_modified = resp.headers.get("last-modified")
            data = json.loads(resp.body)
            del resp  # the raw body is large, free it before loading
            if not isinstance(data, dict) or len(data) < MIN_SOURCE_PACKAGES:
                raise ValueError(f"feed looks truncated ({len(data)} source packages)")
            rows = self.load(data)
        except (HttpError, ValueError) as e:
            status.message = f"refresh failed: {e}"
            log.warning("debian tracker refresh failed", extra={"error": str(e)})
            return
        if new_last_modified:
            self.cache.set_meta(self._meta("last_modified"), new_last_modified)
        self.cache.set_time(self._meta("checked_at"))
        self.cache.set_time(self._meta("updated_at"))
        self.cache.db.commit()
        log.info(
            "debian tracker updated",
            extra={"rows": rows, "seconds": round(time.monotonic() - started, 1)},
        )

    def load(self, data: dict) -> int:
        """Replace the cached tracker data with ``data`` (the parsed feed)."""
        rows = []
        descriptions: dict[str, str] = {}
        for source, vulns in data.items():
            if not isinstance(vulns, dict):
                continue
            for vuln_id, info in vulns.items():
                desc = info.get("description")
                if desc and vuln_id not in descriptions:
                    descriptions[vuln_id] = desc
                for release, r in info.get("releases", {}).items():
                    rows.append(
                        (
                            source,
                            release,
                            vuln_id,
                            r.get("status", ""),
                            r.get("fixed_version"),
                            r.get("urgency"),
                            1 if r.get("nodsa") else 0,
                            json.dumps(r.get("repositories", {}), separators=(",", ":")),
                        )
                    )
        with self.cache.db:
            self.cache.db.execute("DELETE FROM debian_tracker")
            self.cache.db.execute("DELETE FROM debian_tracker_desc")
            self.cache.db.executemany(
                "INSERT INTO debian_tracker VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows
            )
            self.cache.db.executemany(
                "INSERT INTO debian_tracker_desc VALUES (?, ?)", descriptions.items()
            )
        return len(rows)

    def match(self, inventories: list[HostInventory]) -> dict[str, list[Finding]]:
        self.host_warnings = {}
        known_releases = self.releases()
        result = {}
        for inv in inventories:
            if inv.codename not in known_releases:
                self.host_warnings.setdefault(inv.host, []).append(
                    f"release {inv.codename!r} is not covered by the Debian tracker"
                )
                result[inv.host] = []
                continue
            result[inv.host] = self._match_host(inv)
        return result

    def _match_host(self, inv: HostInventory) -> list[Finding]:
        db = self.cache.db
        findings = []
        for (source, version), binaries in sorted(inv.source_packages().items()):
            rows = db.execute(
                "SELECT vuln_id, status, fixed_version, urgency, nodsa, repositories "
                "FROM debian_tracker WHERE source = ? AND release = ?",
                (source, inv.codename),
            ).fetchall()
            for vuln_id, status, fixed, urgency, nodsa, repos in rows:
                try:
                    finding_status = _classify(version, status, fixed, json.loads(repos))
                except ValueError as e:
                    log.warning(
                        "skipping unparsable version",
                        extra={"host": inv.host, "source_package": source, "vuln": vuln_id,
                               "error": str(e)},
                    )
                    continue
                if finding_status is None:
                    continue
                findings.append(
                    Finding(
                        vuln_id=vuln_id,
                        source_package=source,
                        installed_version=version,
                        status=finding_status,
                        fixed_version=fixed if status == "resolved" else None,
                        binaries=sorted(binaries),
                        origins=[self.name],
                        urgency=urgency,
                        nodsa=bool(nodsa),
                        description=self._description(vuln_id),
                    )
                )
        return findings

    def _description(self, vuln_id: str) -> str:
        row = self.cache.db.execute(
            "SELECT description FROM debian_tracker_desc WHERE vuln_id = ?", (vuln_id,)
        ).fetchone()
        return row[0] if row else ""


def _classify(
    installed: str, status: str, fixed: str | None, repositories: dict[str, str]
) -> FindingStatus | None:
    """Decide what a tracker row means for an installed source version.
    Returns None if the installed version is not affected."""
    if status == "resolved":
        if not fixed or fixed == "0":
            return None  # this release was never affected
        if debversion.compare(installed, fixed) >= 0:
            return None
        newest = debversion.max_version(v for v in repositories.values() if v)
        if newest is not None and debversion.compare(newest, fixed) >= 0:
            return FindingStatus.FIXABLE
        return FindingStatus.FIX_PENDING
    if status == "open":
        return FindingStatus.NO_FIX
    if status == "undetermined":
        return FindingStatus.UNDETERMINED
    return None
