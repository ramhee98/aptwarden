"""Orchestrates a run: refresh sources, inventory hosts, match, enrich, persist."""

from __future__ import annotations

import fcntl
import logging
import secrets
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aptwarden import inventory, statuspage
from aptwarden import log as aplog
from aptwarden.cache import Cache
from aptwarden.config import Config, HostConfig, parse_duration
from aptwarden.enrich import enrich
from aptwarden.enrich.cvss import CvssLookup
from aptwarden.enrich.kev import Kev
from aptwarden.http import HttpClient
from aptwarden.matcher import merge
from aptwarden.models import Finding, HostInventory
from aptwarden.notify import Dispatcher, HostChanges, Notifier
from aptwarden.patch import window
from aptwarden.patch.runner import (
    ALERT_STATUSES,
    NEEDS_SNAPSHOT_STATUSES,
    HostPatchResult,
    PatchRunner,
)
from aptwarden.snapshot import NoSnapshots, SnapshotError, SnapshotProvider, SnapshotRef
from aptwarden.sources import CORE_SOURCES, Source, SourceStatus, build_sources
from aptwarden.state import HostRecord, State, utcnow
from aptwarden.transport import TransportFactory

log = logging.getLogger(__name__)


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(2)


@dataclass
class RunReport:
    run_id: str
    command: str
    started_at: str
    finished_at: str = ""
    status: str = "running"  # ok | partial | failed
    sources: list[SourceStatus] = field(default_factory=list)
    hosts: list[HostRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    changes: dict[str, HostChanges] = field(default_factory=dict)
    patches: list[HostPatchResult] = field(default_factory=list)
    inventories: dict[str, HostInventory] = field(default_factory=dict)  # not persisted

    @property
    def data_available(self) -> bool:
        return any(s.ok for s in self.sources if s.name in CORE_SOURCES)


def host_notes(inv: HostInventory) -> list[str]:
    notes = []
    if inv.facts.get("reboot_required") == "yes":
        notes.append("reboot required")
    if inv.facts.get("unattended_upgrade_periodic", "0") not in ("", "0"):
        notes.append("unattended-upgrades is active (patches bypass aptwarden's safety net)")
    return notes


class Runner:
    def __init__(self, cfg: Config, *, offline: bool = False, http: HttpClient | None = None,
                 transports: TransportFactory | None = None,
                 notifiers: list[Notifier] | None = None,
                 providers: Callable[[HostConfig], SnapshotProvider] | None = None,
                 patch_runner: PatchRunner | None = None):
        self.cfg = cfg
        self._notifiers = notifiers
        self._providers = providers
        self._patch_runner = patch_runner
        self._proxmox = None
        self.offline = offline
        self.http = http or HttpClient()
        self._transports = transports
        self.cache = Cache(cfg.cache_dir / "cache.db")
        self.state = State(cfg.state_dir / "state.db")
        self.sources: list[Source] = build_sources(cfg.sources, self.cache, self.http, offline,
                                                   state=self.state, base_dir=cfg.base_dir)
        cvss_cfg = cfg.enrich["cvss"]
        self.cvss = (CvssLookup(cvss_cfg, self.cache, self.http, offline, cfg.base_dir)
                     if cvss_cfg.get("enabled", True) else None)
        kev_cfg = cfg.enrich["kev"]
        self.kev = Kev(kev_cfg, self.cache, self.http, offline) if kev_cfg.get("enabled") else None

    def close(self) -> None:
        self.cache.close()
        self.state.close()

    def refresh(self, force: bool = False) -> list[SourceStatus]:
        statuses = [s.refresh(force) for s in self.sources]
        if self.kev is not None:
            statuses.append(self.kev.refresh(force))
        return statuses

    def collect(self, hosts: list[HostConfig]) -> dict[str, HostInventory | Exception]:
        factory = self._transports or TransportFactory()

        def one(h: HostConfig):
            transport = factory.create(h)
            try:
                return inventory.collect(transport)
            except Exception as e:  # noqa: BLE001 - one broken host must not stop the run
                if not isinstance(e, inventory.InventoryError):
                    log.exception("inventory crashed", extra={"host": h.name})
                return e
            finally:
                transport.close()

        try:
            with ThreadPoolExecutor(max_workers=self.cfg.max_parallel) as pool:
                return dict(zip([h.name for h in hosts], pool.map(one, hosts), strict=True))
        finally:
            if self._transports is None:
                factory.cleanup()

    def report(self, hosts: list[HostConfig], *, force_refresh: bool = False,
               notify: bool = True) -> RunReport:
        return self._lifecycle(RunReport(new_run_id(), "report", utcnow()), notify,
                               lambda run: self._report(run, hosts, force_refresh))

    def patch(self, hosts: list[HostConfig], *, dry_run: bool = False,
              ignore_window: bool = False, notify: bool = True,
              now: datetime | None = None) -> RunReport:
        command = "patch --dry-run" if dry_run else "patch"
        return self._lifecycle(RunReport(new_run_id(), command, utcnow()), notify,
                               lambda run: self._patch(run, hosts, dry_run, ignore_window, now))

    def _lifecycle(self, run: RunReport, notify: bool, body) -> RunReport:
        token = aplog.run_id_var.set(run.run_id)
        self.state.start_run(run.run_id, run.command)
        try:
            body(run)
            if notify:
                errors = Dispatcher(self.cfg, self.state, self._notifiers).dispatch(run)
                if errors:
                    run.notes += [f"notification failed: {e}" for e in errors]
                    if run.status == "ok":
                        run.status = "partial"
        except BaseException:
            run.status = "failed"
            raise
        finally:
            run.finished_at = utcnow()
            self.state.finish_run(run.run_id, run.status, {
                "sources": [s.to_dict() for s in run.sources],
                "notes": run.notes,
                "hosts": [h.host for h in run.hosts],
                "patches": [{"host": p.host, "status": p.status} for p in run.patches],
            })
            self.state.prune(self.cfg.keep_runs)
            statuspage.write(self.cfg, self.state)
            aplog.run_id_var.reset(token)
        return run

    def _report(self, run: RunReport, hosts: list[HostConfig], force_refresh: bool) -> None:
        log.info("run started", extra={"command": run.command, "hosts": len(hosts)})
        run.sources = self.refresh(force_refresh)
        for s in run.sources:
            if not s.ok:
                log.error("source unavailable", extra={"source": s.name, "error": s.message})

        collected = self.collect(hosts)
        inventories = [v for v in collected.values() if isinstance(v, HostInventory)]
        run.inventories = {inv.host: inv for inv in inventories}

        # Live sources (OSV) update the status object returned by refresh() while
        # matching, so run.sources reflects query failures too.
        per_source = [(src.priority, src.match(inventories)) for src in self.sources]

        findings = {
            inv.host: merge([(prio, res.get(inv.host, [])) for prio, res in per_source])
            for inv in inventories
        }
        enrich(findings, self.cvss, self.kev)
        if self.cvss is not None and self.cvss.pending:
            run.notes.append(f"{self.cvss.pending} CVEs still waiting for a CVSS lookup "
                             "(NVD rate limit, continues next run; an NVD API key speeds this up)")

        by_name = {h.name: h for h in hosts}
        for name, result in collected.items():
            h = by_name[name]
            run.changes[name] = self._changes(name, None if isinstance(result, Exception)
                                              else findings[name])
            if isinstance(result, Exception):
                record = HostRecord(run.run_id, name, h.address, False, str(result), {}, [],
                                    utcnow())
                log.error("host failed", extra={"host": name, "error": str(result)})
            else:
                warnings = [w for src in self.sources
                            for w in getattr(src, "host_warnings", {}).get(name, [])]
                self.state.mark_seen(name, findings[name])
                record = HostRecord(run.run_id, name, h.address, True, None, result.summary(),
                                    warnings + host_notes(result), result.collected_at,
                                    findings[name])
            self.state.save_host(run.run_id, record)
            run.hosts.append(record)

        failed_hosts = sum(1 for h in run.hosts if not h.ok)
        if not run.data_available or (run.hosts and failed_hosts == len(run.hosts)):
            run.status = "failed"
        elif failed_hosts or any(not s.ok for s in run.sources):
            run.status = "partial"
        else:
            run.status = "ok"
        log.info("run finished", extra={"status": run.status, "hosts": len(run.hosts),
                                        "failed_hosts": failed_hosts})

    def _changes(self, host: str, findings: list[Finding] | None) -> HostChanges:
        """Compare with the stored history. ``findings`` is None if the scan failed.
        Findings are compared by (source package, vulnerability), so an upgrade
        that leaves a vulnerability open is not reported as new."""
        previous = self.state.latest(host)
        if findings is None:
            return HostChanges(newly_failed=previous is None or previous.ok)
        last_ok = previous if previous is not None and previous.ok \
            else self.state.latest(host, ok_only=True)
        if last_ok is None:
            return HostChanges(first_scan=True)
        before = {(f.source_package, f.vuln_id) for f in last_ok.findings}
        now = {(f.source_package, f.vuln_id) for f in findings}
        return HostChanges(
            new=[f for f in findings if (f.source_package, f.vuln_id) not in before],
            resolved=[f for f in last_ok.findings if (f.source_package, f.vuln_id) not in now],
            recovered=previous is not None and not previous.ok,
        )

    # --- patching ---------------------------------------------------------------

    def provider(self, host: HostConfig) -> SnapshotProvider:
        if self._providers is not None:
            return self._providers(host)
        snap = host.snapshot
        if snap["provider"] == "none":
            return NoSnapshots()
        from aptwarden.snapshot.proxmox import ProxmoxClient, ProxmoxSnapshots

        if self._proxmox is None:
            self._proxmox = ProxmoxClient(self.cfg.proxmox, self.cfg.base_dir)
        return ProxmoxSnapshots(self._proxmox, snap.get("node") or self.cfg.proxmox["node"],
                                snap["type"], snap["vmid"], self.cfg.snapshots["vmstate"])

    def definitions(self):
        custom = next((s for s in self.sources if s.name == "custom"), None)
        return custom.definitions() if custom is not None else []

    def _eligible(self, hosts: list[HostConfig], dry_run: bool, ignore_window: bool,
                  now: datetime | None) -> tuple[list[HostConfig], list[tuple[str, str]]]:
        eligible, skipped = [], []
        for h in hosts:
            modes = set(h.policy["modes"])
            if dry_run and not modes & {"dry-run", "patch"}:
                skipped.append((h.name, "dry-run not enabled for this host (policy.modes)"))
            elif not dry_run and "patch" not in modes:
                skipped.append((h.name, "patching not enabled for this host (policy.modes)"))
            elif not dry_run and not ignore_window and not window.in_any(h.policy["window"], now):
                skipped.append((h.name, "outside the maintenance window"))
            else:
                eligible.append(h)
        return eligible, skipped

    def _patch(self, run: RunReport, hosts: list[HostConfig], dry_run: bool,
               ignore_window: bool, now: datetime | None) -> None:
        eligible, skipped = self._eligible(hosts, dry_run, ignore_window, now)
        for name, reason in skipped:
            run.patches.append(HostPatchResult(name, run.run_id, dry_run, "skipped",
                                               reason=reason))
        if not eligible:
            run.status = "ok"
            return
        lock = None if dry_run else _PatchLock(self.cfg.state_dir / "patch.lock")
        try:
            self._report(run, eligible, False)
            runner = self._patch_runner or PatchRunner(self.state, self.definitions())
            factory = self._transports or TransportFactory()
            try:
                for h in eligible:
                    run.patches.append(self._patch_host(run, h, runner, factory, dry_run))
            finally:
                if self._transports is None:
                    factory.cleanup()
            if not dry_run:
                run.notes += self.cleanup_snapshots(eligible)
        finally:
            if lock:
                lock.release()
        if any(p.status in ALERT_STATUSES for p in run.patches) and run.status == "ok":
            run.status = "partial"

    def _patch_host(self, run: RunReport, h: HostConfig, runner: PatchRunner,
                    factory: TransportFactory, dry_run: bool) -> HostPatchResult:
        record = next((r for r in run.hosts if r.host == h.name), None)
        inv = run.inventories.get(h.name)
        if record is None or not record.ok or inv is None:
            return HostPatchResult(h.name, run.run_id, dry_run, "skipped",
                                   reason=f"scan failed: {record.error if record else '?'}")
        if not run.data_available:
            return HostPatchResult(h.name, run.run_id, dry_run, "skipped",
                                   reason="no vulnerability data available")
        transport = factory.create(h)
        try:
            provider = self.provider(h)
            return runner.run(h, inv, record.findings, run.run_id, transport, provider, dry_run)
        except SnapshotError as e:
            return HostPatchResult(h.name, run.run_id, dry_run, "aborted", "preflight",
                                   reason=str(e))
        finally:
            transport.close()

    def cleanup_snapshots(self, hosts: list[HostConfig], dry_run: bool = False,
                          now: datetime | None = None) -> list[str]:
        """Delete aptwarden's own snapshots older than snapshots.keep. A snapshot
        still needed for a manual rollback is kept."""
        keep = parse_duration(self.cfg.snapshots["keep"])
        now = now or datetime.now(UTC)
        notes = []
        for h in hosts:
            # Rolled-back snapshots still exist on the provider and age out too.
            snaps = self.state.snapshots(h.name, ("active", "rolled-back"))
            if not snaps:
                continue
            latest_patch = (self.state.patches(h.name, 1) or [{}])[0]
            needed = (latest_patch.get("status") in NEEDS_SNAPSHOT_STATUSES
                      and latest_patch.get("snapshot"))
            try:
                provider = self.provider(h)
                existing = set(provider.list())
            except SnapshotError as e:
                notes.append(f"{h.name}: snapshot cleanup skipped: {e}")
                continue
            for snap in snaps:
                ref = SnapshotRef(snap["provider"], snap["target"], snap["name"])
                if needed and latest_patch["snapshot"].get("name") == ref.name:
                    continue
                if ref.name not in existing:
                    self.state.set_snapshot_state(ref.provider, ref.target, ref.name, "gone")
                    continue
                age = (now - datetime.fromisoformat(snap["created_at"])).total_seconds()
                if age < keep:
                    continue
                if dry_run:
                    notes.append(f"{h.name}: would delete snapshot {ref.name}")
                    continue
                try:
                    provider.delete(ref)
                    self.state.set_snapshot_state(ref.provider, ref.target, ref.name, "deleted")
                    notes.append(f"{h.name}: deleted snapshot {ref.name}")
                except SnapshotError as e:
                    notes.append(f"{h.name}: could not delete snapshot {ref.name}: {e}")
        return notes


class _PatchLock:
    """Only one patch run at a time (the timer and a manual run must not overlap)."""

    def __init__(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(path, "w")  # noqa: SIM115 - held for the lifetime of the run
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.fh.close()
            raise RuntimeError("another patch run is active") from None

    def release(self) -> None:
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()
