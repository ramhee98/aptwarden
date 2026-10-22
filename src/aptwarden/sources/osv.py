"""OSV.dev (api.osv.dev).

For Debian, OSV's ``DEBIAN-CVE-*`` records are generated from the Debian
tracker, so this source mostly adds redundancy. Queries go through
``/v1/querybatch`` (ids only). Every vulnerability is then hydrated once and
cached by (id, modified).
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from aptwarden import debversion
from aptwarden.http import HttpError
from aptwarden.models import Finding, FindingStatus, HostInventory
from aptwarden.sources import Source, SourceStatus

log = logging.getLogger(__name__)

BATCH_SIZE = 1000  # OSV querybatch limit

# DSA/DLA/DTSA advisories bundle CVEs that OSV also publishes as individual
# DEBIAN-CVE-* records, so they would only duplicate findings.
_SKIP_PREFIXES = ("DSA-", "DLA-", "DTSA-")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS osv_vulns (
    id TEXT PRIMARY KEY,
    modified TEXT NOT NULL,
    data TEXT NOT NULL,
    fetched_at REAL NOT NULL
) WITHOUT ROWID;
"""

Query = tuple[str, str, str]  # (ecosystem, package, version)


def ecosystem(inv: HostInventory) -> str | None:
    if inv.os_id == "debian" and inv.os_version_id:
        return f"Debian:{inv.os_version_id}"
    return None


def normalize_id(osv_id: str) -> str:
    """DEBIAN-CVE-2025-1234 -> CVE-2025-1234, matching the tracker's ids."""
    return osv_id.removeprefix("DEBIAN-")


def evaluate_ranges(record: dict, eco: str, package: str, version: str):
    """Return (affected, fixed_version) for one package version.

    Uses the ECOSYSTEM ranges of the record with Debian version semantics. A
    record without ranges for the package (versions list only) is treated as
    affected without a known fix.
    """
    saw_range = False
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != eco or pkg.get("name") != package:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") != "ECOSYSTEM":
                continue
            saw_range = True
            introduced = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    if debversion.in_range(version, introduced, fixed=event["fixed"]):
                        return True, event["fixed"]
                    introduced = None
                elif "last_affected" in event and introduced is not None:
                    if debversion.in_range(version, introduced,
                                           last_affected=event["last_affected"]):
                        return True, None
                    introduced = None
            if introduced is not None and debversion.in_range(version, introduced):
                return True, None
    return (not saw_range), None


def _urgency(record: dict, eco: str, package: str) -> str | None:
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") == eco and pkg.get("name") == package:
            return (affected.get("ecosystem_specific") or {}).get("urgency")
    return None


class OsvSource(Source):
    name = "osv"
    priority = 50

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache.db.executescript(_SCHEMA)
        self.host_warnings: dict[str, list[str]] = {}
        self.last_status = SourceStatus(self.name)

    @property
    def url(self) -> str:
        return self.settings["url"].rstrip("/")

    def refresh(self, force: bool = False) -> SourceStatus:
        # OSV is queried live during match(), there is nothing to prefetch.
        self.last_status = SourceStatus(self.name, checked_at=time.time())
        if self.offline:
            self.last_status.message = "skipped (offline)"
        return self.last_status

    def match(self, inventories: list[HostInventory]) -> dict[str, list[Finding]]:
        self.host_warnings = {}
        if self.offline:
            return {}
        wanted: dict[Query, None] = {}
        for inv in inventories:
            eco = ecosystem(inv)
            if eco is None:
                self.host_warnings.setdefault(inv.host, []).append(
                    "no OSV ecosystem for this host (needs Debian with VERSION_ID)"
                )
                continue
            for source, version in inv.source_packages():
                wanted[(eco, source, version)] = None
        try:
            results = self._querybatch(list(wanted))
            records = self._hydrate({vid: mod for ids in results.values() for vid, mod in ids})
        except HttpError as e:
            self.last_status.ok = False
            self.last_status.message = f"query failed: {e}"
            log.warning("osv query failed", extra={"error": str(e)})
            return {}

        per_query: dict[Query, list[Finding]] = {}
        for query, ids in results.items():
            eco, package, version = query
            for vid, _ in ids:
                record = records.get(vid)
                if record is None or vid.startswith(_SKIP_PREFIXES):
                    continue
                affected, fixed = evaluate_ranges(record, eco, package, version)
                if not affected:
                    continue
                per_query.setdefault(query, []).append(
                    Finding(
                        vuln_id=normalize_id(vid),
                        source_package=package,
                        installed_version=version,
                        status=FindingStatus.FIXABLE if fixed else FindingStatus.NO_FIX,
                        fixed_version=fixed,
                        origins=[self.name],
                        aliases=sorted(set(record.get("upstream", []))
                                       | set(record.get("aliases", [])) | {vid}),
                        urgency=_urgency(record, eco, package),
                        description=record.get("summary") or record.get("details", ""),
                    )
                )

        out: dict[str, list[Finding]] = {}
        for inv in inventories:
            eco = ecosystem(inv)
            findings = []
            for (source, version), binaries in inv.source_packages().items():
                for f in per_query.get((eco, source, version), []):
                    findings.append(_with_binaries(f, binaries))
            out[inv.host] = findings
        return out

    def _querybatch(self, queries: list[Query]) -> dict[Query, list[tuple[str, str]]]:
        results: dict[Query, list[tuple[str, str]]] = {}
        for start in range(0, len(queries), BATCH_SIZE):
            chunk = queries[start:start + BATCH_SIZE]
            body = {"queries": [_query_body(q) for q in chunk]}
            data = self._post("/v1/querybatch", body)
            for query, res in zip(chunk, data.get("results", []), strict=False):
                ids = [(v["id"], v.get("modified", "")) for v in res.get("vulns", [])]
                token = res.get("next_page_token")
                while token:
                    page = self._post("/v1/querybatch",
                                      {"queries": [_query_body(query, token)]})["results"][0]
                    ids += [(v["id"], v.get("modified", "")) for v in page.get("vulns", [])]
                    token = page.get("next_page_token")
                results[query] = ids
        log.info("osv queried", extra={"queries": len(queries),
                                       "with_vulns": sum(1 for v in results.values() if v)})
        return results

    def _post(self, path: str, body: dict) -> dict:
        resp = self.http.post_json(self.url + path, body)
        if resp.status != 200:
            raise HttpError(self.url + path, f"HTTP {resp.status}", resp.status)
        return resp.json()

    def _hydrate(self, wanted: dict[str, str]) -> dict[str, dict]:
        """Return full records for ``{id: modified}``, from cache where current."""
        records: dict[str, dict] = {}
        missing = []
        for vid, modified in wanted.items():
            row = self.cache.db.execute(
                "SELECT modified, data FROM osv_vulns WHERE id = ?", (vid,)
            ).fetchone()
            if row and row[0] == modified:
                records[vid] = json.loads(row[1])
            else:
                missing.append(vid)

        def fetch(vid: str):
            resp = self.http.get(f"{self.url}/v1/vulns/{vid}")
            if resp.status == 404:
                return vid, None
            if resp.status != 200:
                raise HttpError(f"{self.url}/v1/vulns/{vid}", f"HTTP {resp.status}", resp.status)
            return vid, resp.json()

        if missing:
            with ThreadPoolExecutor(max_workers=self.settings.get("workers", 8)) as pool:
                fetched = list(pool.map(fetch, missing))
            now = time.time()
            with self.cache.db:
                for vid, record in fetched:
                    if record is None:
                        continue
                    records[vid] = record
                    # Key on querybatch's "modified": the record itself carries
                    # the same timestamp with nanosecond precision.
                    self.cache.db.execute(
                        "INSERT OR REPLACE INTO osv_vulns VALUES (?, ?, ?, ?)",
                        (vid, wanted[vid], json.dumps(record), now),
                    )
        log.info("osv records hydrated", extra={"total": len(wanted), "fetched": len(missing)})
        return records


def _query_body(query: Query, page_token: str | None = None) -> dict:
    eco, name, version = query
    body = {"package": {"ecosystem": eco, "name": name}, "version": version}
    if page_token:
        body["page_token"] = page_token
    return body


def _with_binaries(f: Finding, binaries: list[str]) -> Finding:
    return replace(f, binaries=sorted(binaries), origins=list(f.origins),
                   aliases=list(f.aliases))
