"""Custom definitions from a Git repository (see aptwarden.definitions).

Highest priority: for every vulnerability a definition covers (its aliases),
the definition decides. Where it says the installed version is not affected,
it emits a NOT_AFFECTED finding that removes other sources' findings in the
matcher.

The active definitions are kept in state.db, not in the cache, so neither a
cache wipe nor a broken upstream can drop or roll them back.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from aptwarden import debversion
from aptwarden.config import parse_duration
from aptwarden.definitions import Definition
from aptwarden.definitions.sync import GitSync, SyncError
from aptwarden.models import Finding, FindingStatus, HostInventory, Severity
from aptwarden.sources import Source, SourceStatus
from aptwarden.state import State, utcnow

log = logging.getLogger(__name__)

K_DEFS, K_REF, K_COMMIT = "definitions.data", "definitions.ref", "definitions.commit"
K_ACCEPTED, K_CHECKED, K_REJECTED = ("definitions.accepted_at", "definitions.checked_at",
                                     "definitions.rejected")


class CustomSource(Source):
    name = "custom"
    priority = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state: State = self.context["state"]
        base_dir: Path | None = self.context.get("base_dir")
        signers = self.settings.get("allowed_signers_file")
        if signers and base_dir and not Path(signers).is_absolute():
            signers = str(base_dir / signers)
        self.git = GitSync(self.settings, self.cache.path.parent / "definitions.git",
                           Path(signers) if signers else None)

    def definitions(self) -> list[Definition]:
        return [Definition.from_dict(d) for d in self.state.get(K_DEFS, [])]

    def refresh(self, force: bool = False) -> SourceStatus:
        status = SourceStatus(self.name)
        checked_at = self.state.get(K_CHECKED)
        due = checked_at is None or time.time() - checked_at >= parse_duration(
            self.settings["refresh_interval"])
        if not self.offline and (force or due):
            self._sync(status)
        defs = self.definitions()
        ref = self.state.get(K_REF)
        status.checked_at = self.state.get(K_CHECKED)
        status.message = (f"{ref} ({str(self.state.get(K_COMMIT, ''))[:12]}), "
                          f"{len(defs)} definitions" if ref else "no definitions accepted yet")
        return status

    def _sync(self, status: SourceStatus) -> None:
        rejected = set(self.state.get(K_REJECTED, []))
        try:
            result = self.git.sync(self.state.get(K_COMMIT), rejected)
        except SyncError as e:
            status.warnings.append(f"sync failed, keeping the active definitions: {e}")
            log.warning("definitions sync failed", extra={"error": str(e)})
            return
        status.warnings += result.warnings
        status.alerts += result.problems
        for p in result.problems:
            log.error("definitions problem", extra={"problem": p})
        values = {K_CHECKED: time.time(), K_REJECTED: sorted(rejected | set(result.rejected))}
        if result.changed:
            values.update({
                K_DEFS: [d.to_dict() for d in result.definitions],
                K_REF: result.ref, K_COMMIT: result.commit, K_ACCEPTED: utcnow(),
            })
            log.info("definitions updated", extra={"ref": result.ref,
                                                   "definitions": len(result.definitions)})
        self.state.set(**values)

    def _newest_repo_version(self, source: str, release: str) -> str | None:
        """Newest version of the source in the release's repositories, from
        the Debian tracker cache (if that source is in use)."""
        try:
            rows = self.cache.db.execute(
                "SELECT repositories FROM debian_tracker WHERE source = ? AND release = ?",
                (source, release)).fetchall()
        except Exception:  # noqa: BLE001 - table absent when the tracker is disabled
            return None
        versions = {v for (r,) in rows for v in json.loads(r).values() if v}
        return debversion.max_version(versions)

    def match(self, inventories: list[HostInventory]) -> dict[str, list[Finding]]:
        defs = [d for d in self.definitions() if not d.expired()]
        by_package: dict[str, list[Definition]] = {}
        for d in defs:
            by_package.setdefault(d.package, []).append(d)
        out: dict[str, list[Finding]] = {}
        for inv in inventories:
            findings = []
            for (source, version), binaries in inv.source_packages().items():
                for d in by_package.get(source, []):
                    verdict = d.evaluate(inv.codename, version)
                    if verdict is None:
                        continue
                    affected, fixed = verdict
                    status = self._status(affected, fixed, source, inv.codename)
                    for vid in d.vuln_ids():
                        findings.append(Finding(
                            vuln_id=vid, source_package=source, installed_version=version,
                            status=status, fixed_version=fixed if affected else None,
                            binaries=sorted(binaries), origins=[self.name],
                            aliases=[d.id], description=d.summary,
                            severity=Severity.parse(d.severity),
                            severity_reason=f"definition {d.id}",
                            definition=d.id, action=d.action,
                        ))
            out[inv.host] = findings
        return out

    def _status(self, affected: bool, fixed: str | None, source: str,
                release: str) -> FindingStatus:
        if not affected:
            return FindingStatus.NOT_AFFECTED
        if fixed is None:
            return FindingStatus.NO_FIX
        newest = self._newest_repo_version(source, release)
        if newest is not None and debversion.compare(newest, fixed) < 0:
            return FindingStatus.FIX_PENDING
        return FindingStatus.FIXABLE
