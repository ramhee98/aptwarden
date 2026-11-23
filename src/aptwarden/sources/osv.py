"""OSV.dev (api.osv.dev).

For Debian, OSV's ``DEBIAN-CVE-*`` records are generated from the Debian
tracker, so this source mostly adds redundancy. For Ubuntu, Canonical publishes
``UBUNTU-CVE-*`` records (ecosystems ``Ubuntu:24.04:LTS``, ``Ubuntu:25.10``): one
record per CVE with an entry per release and source package, the Ubuntu priority
as severity, and a fixed version once the fix is released. Queries go through
``/v1/querybatch`` (ids only). Every vulnerability is then hydrated once and
cached by (id, modified).
"""

from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from urllib.parse import parse_qs, quote, urlsplit

from aptwarden import debversion
from aptwarden.http import HttpError
from aptwarden.models import Finding, FindingStatus, HostInventory
from aptwarden.sources import Source, SourceStatus

log = logging.getLogger(__name__)

BATCH_SIZE = 1000  # OSV querybatch limit

# Advisories bundle CVEs that OSV also publishes as individual DEBIAN-CVE-* or
# UBUNTU-CVE-* records, so they would only duplicate findings. Livepatch notices
# (LSN) concern the running kernel, not packages.
_SKIP_PREFIXES = ("DSA-", "DLA-", "DTSA-", "LSN-")
# Ubuntu security notices are the exception: some fix an issue without a CVE (or
# with one whose record has no entry for the package, e.g. a kmod mitigation for a
# kernel CVE), and nothing else reports those. A USN counts only where no CVE record
# of the same package covers one of its CVEs, since a USN lists the CVEs of all
# releases it covers (USN-8124-1 names CVE-2026-3104, which does not affect noble).
# "<package> regression" notices only repair an earlier update.
_FALLBACK_PREFIXES = ("USN-",)
_ID_PREFIXES = ("DEBIAN-", "UBUNTU-")
_UBUNTU_VERSION = re.compile(r"(\d{2})\.(\d{2})")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS osv_vulns (
    id TEXT PRIMARY KEY,
    modified TEXT NOT NULL,
    data TEXT NOT NULL,
    fetched_at REAL NOT NULL
) WITHOUT ROWID;
"""

Query = tuple[str, str, str]  # (ecosystem, package, version)


def _ubuntu_lts(inv: HostInventory) -> bool | None:
    """Whether an Ubuntu host runs an LTS release; None if not Ubuntu or the version
    is unknown. LTS releases come every two years in April; os-release does not say
    so reliably (26.04 has "LTS" only in PRETTY_NAME)."""
    if inv.distro != "ubuntu" or not (m := _UBUNTU_VERSION.fullmatch(inv.os_version_id)):
        return None
    return m.group(2) == "04" and int(m.group(1)) % 2 == 0


def ecosystem(inv: HostInventory) -> str | None:
    if inv.os_id == "debian" and inv.os_version_id:
        return f"Debian:{inv.os_version_id}"
    lts = _ubuntu_lts(inv)
    if lts is not None:
        return f"Ubuntu:{inv.os_version_id}" + (":LTS" if lts else "")
    return None


def pro_ecosystem(inv: HostInventory) -> str | None:
    """Ubuntu Pro (ESM) of an LTS release. Not an addition to ``ecosystem``: it
    covers other packages (universe in esm-apps, e.g. 7zip on 24.04) and, after the
    end of standard support, the fixes of the release itself (esm-infra)."""
    return f"Ubuntu:Pro:{inv.os_version_id}:LTS" if _ubuntu_lts(inv) else None


def _pro_kind(record: dict, eco: str, package: str) -> str | None:
    """``apps`` or ``infra``, from the entry's purl (``distro=esm-apps/noble``)."""
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") == eco and pkg.get("name") == package:
            distro = parse_qs(urlsplit(pkg.get("purl") or "").query).get("distro", [""])[0]
            kind = distro.partition("/")[0].removeprefix("esm-")
            if kind in ("apps", "infra"):
                return kind
    return None


def pro_missing_source(inv: HostInventory, kind: str | None) -> str | None:
    """The Ubuntu Pro pocket a fix needs, unless the host's apt sources have it."""
    suites = inv.apt_suites() or set()
    kinds = [kind] if kind else ["apps", "infra"]
    if any(f"{inv.codename}-{k}-{p}" in suites for k in kinds for p in ("security", "updates")):
        return None
    return f"{inv.codename}-{kind}-security (Ubuntu Pro)" if kind else "Ubuntu Pro"


def normalize_id(osv_id: str) -> str:
    """DEBIAN-CVE-2025-1234 and UBUNTU-CVE-2025-1234 -> CVE-2025-1234, matching
    the tracker's ids."""
    for prefix in _ID_PREFIXES:
        if osv_id.startswith(prefix):
            return osv_id[len(prefix):]
    return osv_id


def evaluate_ranges(record: dict, eco: str, package: str, version: str):
    """Return (affected, fixed_version) for one package version.

    Uses the ECOSYSTEM ranges of the record with Debian version semantics. An
    entry for the package without ranges (versions list only) is treated as
    affected without a known fix. A record without any entry for the ecosystem and
    package does not affect it: OSV matches ecosystems loosely (a query for
    ``Ubuntu:26.04`` also returns ``Ubuntu:26.04:LTS`` records).
    """
    saw_entry = saw_range = False
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != eco or pkg.get("name") != package:
            continue
        saw_entry = True
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
    return (saw_entry and not saw_range), None


def _urgency(record: dict, eco: str, package: str) -> str | None:
    """Debian's urgency of the package, or Ubuntu's priority of the CVE."""
    if eco.startswith("Ubuntu:"):
        for sev in record.get("severity", []):
            if sev.get("type") == "Ubuntu" and isinstance(sev.get("score"), str):
                return sev["score"]
        return None
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") == eco and pkg.get("name") == package:
            return (affected.get("ecosystem_specific") or {}).get("urgency")
    return None


class OsvSource(Source):
    name = "osv"
    priority = 50
    live = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache.db.executescript(_SCHEMA)
        self.host_warnings: dict[str, list[str]] = {}
        self.last_status = SourceStatus(self.name)

    @property
    def url(self) -> str:
        return self.settings["url"].rstrip("/")

    def covers(self, inv: HostInventory) -> bool:
        return ecosystem(inv) is not None

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
                    "no OSV ecosystem for this host (needs Debian or Ubuntu with VERSION_ID)"
                )
                continue
            for e in filter(None, (eco, pro_ecosystem(inv))):
                for source, version in inv.source_packages():
                    wanted[(e, source, version)] = None
        try:
            results = self._querybatch(list(wanted))
            records = self._hydrate({vid: mod for ids in results.values() for vid, mod in ids})
        except HttpError as e:
            self.last_status.ok = False
            self.last_status.message = f"query failed: {e}"
            log.warning("osv query failed", extra={"error": str(e)})
            return {}

        # findings per query, with the Ubuntu Pro kind (apps, infra) for Pro queries
        per_query: dict[Query, list[tuple[Finding, str | None]]] = {}
        for query, ids in results.items():
            findings, notices = [], []
            for vid, _ in ids:
                record = records.get(vid)
                if record is None or vid.startswith(_SKIP_PREFIXES) or record.get("withdrawn"):
                    continue
                if vid.startswith(_FALLBACK_PREFIXES):
                    notices.append((vid, record))
                elif (f := self._finding(query, vid, record)) is not None:
                    findings.append(f)
            covered = {f.vuln_id for f in findings}
            for vid, record in notices:
                cves = {normalize_id(c)
                        for c in record.get("upstream", []) + record.get("related", [])}
                if cves & covered or (record.get("summary") or "").endswith(" regression"):
                    continue
                if (f := self._finding(query, vid, record, cves)) is not None:
                    findings.append(f)
            if findings:
                eco, package, _ = query
                records_by_id = {normalize_id(v): records[v] for v, _ in ids if v in records}
                per_query[query] = [
                    (f, _pro_kind(records_by_id[f.vuln_id], eco, package)
                     if eco.startswith("Ubuntu:Pro:") else None) for f in findings]

        out: dict[str, list[Finding]] = {}
        for inv in inventories:
            eco, pro = ecosystem(inv), pro_ecosystem(inv)
            findings = []
            for (source, version), binaries in inv.source_packages().items():
                merged = _merge_pro(inv, per_query.get((eco, source, version), []),
                                    per_query.get((pro, source, version), []) if pro else [])
                findings += [_with_binaries(f, binaries) for f in merged]
            out[inv.host] = findings
        return out

    def _finding(self, query: Query, vid: str, record: dict,
                 cves: set[str] | None = None) -> Finding | None:
        eco, package, version = query
        affected, fixed = evaluate_ranges(record, eco, package, version)
        if not affected:
            return None
        if cves is None:  # a vulnerability record
            aliases = set(record.get("upstream", [])) | set(record.get("aliases", []))
            description = record.get("summary") or record.get("details", "")
        else:  # a notice: its summary only says "<package> vulnerability"
            aliases = cves
            description = record.get("details") or record.get("summary", "")
        return Finding(
            vuln_id=normalize_id(vid),
            source_package=package,
            installed_version=version,
            status=FindingStatus.FIXABLE if fixed else FindingStatus.NO_FIX,
            fixed_version=fixed,
            origins=[self.name],
            aliases=sorted(aliases | {vid}),
            urgency=_urgency(record, eco, package),
            description=description,
        )

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
            # the ids come from OSV's own answer; quoted so they cannot change the path
            url = f"{self.url}/v1/vulns/{quote(vid, safe='')}"
            resp = self.http.get(url)
            if resp.status == 404:
                return vid, None
            if resp.status != 200:
                raise HttpError(url, f"HTTP {resp.status}", resp.status)
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


def _merge_pro(inv: HostInventory, standard: list[tuple[Finding, str | None]],
               pro: list[tuple[Finding, str | None]]) -> list[Finding]:
    """The release's own findings, plus what Ubuntu Pro knows beyond them: its
    vulnerabilities of packages the release does not track, and its fixes for
    vulnerabilities the release leaves open. A Pro fix keeps the status fixable and
    names the Pro pocket as missing source unless the host's apt sources have it."""
    by_id = {f.vuln_id: f for f, _ in standard}
    known = set(by_id) | {a for f in by_id.values() for a in f.aliases}
    extra = []
    for f, kind in pro:
        if f.vuln_id in by_id:
            if by_id[f.vuln_id].status == FindingStatus.FIXABLE \
                    or f.status != FindingStatus.FIXABLE:
                continue
            del by_id[f.vuln_id]  # open in the release, fixed in Pro
        elif f.vuln_id.startswith(_FALLBACK_PREFIXES) and known & set(f.aliases):
            continue  # a Pro notice for CVEs the release's records already cover
        if f.status == FindingStatus.FIXABLE:
            f = replace(f, missing_source=pro_missing_source(inv, kind))
        extra.append(f)
    return list(by_id.values()) + extra


def _with_binaries(f: Finding, binaries: list[str]) -> Finding:
    return replace(f, binaries=sorted(binaries), origins=list(f.origins),
                   aliases=list(f.aliases))
