"""The patch pipeline for one host.

plan -> preflight -> simulate -> snapshot -> apply -> restart/reboot ->
healthcheck -> done, or rollback (auto) / alert (manual).

Nothing changes on the host before the snapshot exists, except refreshed
package lists. Every step that runs as root goes through aptwarden-helper.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from aptwarden import health
from aptwarden.config import HostConfig, parse_duration
from aptwarden.definitions import Definition
from aptwarden.models import Finding, HostInventory
from aptwarden.patch import apt, planner
from aptwarden.snapshot import (
    NoSnapshots,
    SnapshotError,
    SnapshotProvider,
    SnapshotRef,
    snapshot_name,
)
from aptwarden.state import State, utcnow
from aptwarden.transport import Transport, TransportError

log = logging.getLogger(__name__)

HELPER_VERSION = "1"

# Statuses that need a human: they raise an immediate alert.
ALERT_STATUSES = frozenset({"rolled-back", "needs-manual-rollback", "failed", "rollback-failed"})
# The host is in a broken patched state: its snapshot is needed for a rollback.
NEEDS_SNAPSHOT_STATUSES = frozenset({"needs-manual-rollback", "failed", "rollback-failed"})
# Stages before anything on the host changes (package lists aside).
UNCHANGED_STAGES = frozenset({"plan", "preflight", "simulate", "preflight-health", "snapshot"})
# Statuses after which the host was changed.
CHANGED_STATUSES = frozenset({"patched", "rolled-back", "needs-manual-rollback", "failed",
                              "rollback-failed"})


HELPER_HINT = "see README: Target hosts: helper and sudo"


def explain_helper_failure(r, helper: str) -> str | None:
    """None if ``sudo -n <helper> version`` worked, else what is wrong."""
    out = r.stdout.strip()
    if out == f"aptwarden-helper {HELPER_VERSION}":
        return None
    raw = (r.stderr or r.stdout).strip()
    if out.startswith("aptwarden-helper "):
        reason = (f"outdated helper ({out}, expected version {HELPER_VERSION}): reinstall it "
                  f"from 'aptwarden helper show'")
    elif "'sudo': No such file" in raw or "‘sudo’: No such file" in raw or (
            "sudo" in raw and "not found" in raw and helper not in raw):
        reason = "sudo is not installed on the host"
    elif helper in raw and ("not found" in raw or "No such file" in raw):
        reason = f"the helper is not installed at {helper}"
    elif "password is required" in raw or "not allowed" in raw or "sudoers" in raw:
        reason = ("no sudo rule for the helper: /etc/sudoers.d/aptwarden is missing, has a "
                  "wrong mode, or its file name contains a '.' (then sudo ignores it); "
                  f"or the helper is not at {helper}")
    else:
        reason = f"helper not usable via sudo ({raw or 'no output'})"
    return f"{reason}; {HELPER_HINT}"


class PatchAbort(Exception):
    """Stop before anything was changed."""


@dataclass
class HostPatchResult:
    host: str
    run_id: str
    dry_run: bool = False
    status: str = "pending"
    stage: str = "plan"
    reason: str = ""
    items: list[dict] = field(default_factory=list)
    skipped_items: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    snapshot: dict | None = None  # SnapshotRef as dict
    restarted: list[str] = field(default_factory=list)
    rebooted: bool = False
    health_before: list[str] = field(default_factory=list)
    health_after: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    repeated: bool = False  # same status and reason as the host's previous patch run
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""

    @property
    def alert(self) -> bool:
        return self.status in ALERT_STATUSES

    def to_dict(self) -> dict:
        return asdict(self)


class PatchRunner:
    def __init__(self, state: State, definitions: list[Definition], *,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.state = state
        self.definitions = definitions
        self.sleep = sleep
        self.clock = clock

    # --- helpers -------------------------------------------------------------

    def _helper(self, t: Transport, host: HostConfig, *args: str, timeout: float = 1800):
        return t.run(["sudo", "-n", host.ssh.helper, *args], timeout=timeout)

    def _marker(self, t: Transport) -> str:
        """Changes on every (re)boot, also for LXC containers sharing the host
        kernel: kernel boot id plus the start time of PID 1."""
        r = t.run(["cat", "/proc/sys/kernel/random/boot_id", "/proc/1/stat"], timeout=15)
        boot_id, _, stat = r.check().stdout.partition("\n")
        start = stat.rpartition(")")[2].split()[19] if ")" in stat else ""
        return f"{boot_id.strip()}/{start}"

    def _wait_back(self, t: Transport, old_marker: str, timeout: float = 900) -> bool:
        t.close()  # the multiplexed connection died with the old system
        deadline = self.clock() + timeout
        self.sleep(5)
        while self.clock() < deadline:
            try:
                if self._marker(t) != old_marker:
                    return True
            except TransportError:
                pass
            t.close()
            self.sleep(5)
        return False

    def _health(self, t: Transport, host: HostConfig) -> list[health.CheckResult]:
        h = host.health
        return health.wait_healthy(host.healthchecks, t, grace=parse_duration(h["grace"]),
                                   retries=h["retries"], interval=parse_duration(h["interval"]),
                                   sleep=self.sleep)

    # --- pipeline --------------------------------------------------------------

    def run(self, host: HostConfig, inv: HostInventory, findings: list[Finding], run_id: str,
            transport: Transport, provider: SnapshotProvider, dry_run: bool = False
            ) -> HostPatchResult:
        result = HostPatchResult(host.name, run_id, dry_run)
        try:
            self._run(result, host, inv, findings, transport, provider)
        except PatchAbort as e:
            result.status, result.reason = "aborted", str(e)
        except (TransportError, SnapshotError) as e:
            self._failure(result, host, transport, provider, f"{result.stage}: {e}")
        result.finished_at = utcnow()
        log.log(logging.ERROR if result.alert else logging.INFO, "patch result",
                extra={"host": host.name, "status": result.status, "stage": result.stage,
                       "reason": result.reason})
        if not dry_run:
            previous = self.state.patches(host.name, 1)
            result.repeated = bool(previous) and previous[0]["status"] == result.status \
                and previous[0]["reason"] == result.reason
            self.state.save_patch(run_id, host.name, result.status, result.started_at,
                                  result.to_dict())
        return result

    def _run(self, result: HostPatchResult, host: HostConfig, inv: HostInventory,
             findings: list[Finding], t: Transport, provider: SnapshotProvider) -> None:
        policy = host.policy
        items = planner.group(planner.select(findings, policy))
        if not items:
            result.status = "nothing-to-do"
            result.reason = "no fixable vulnerability allowed by policy"
            return

        result.stage = "preflight"
        r = self._helper(t, host, "version", timeout=30)
        if problem := explain_helper_failure(r, host.ssh.helper):
            raise PatchAbort(problem)
        if not result.dry_run and not host.healthchecks:
            raise PatchAbort("no healthchecks configured; auto-patching requires them")
        snapshots = not isinstance(provider, NoSnapshots)
        if not snapshots and not policy["allow_without_snapshot"]:
            raise PatchAbort("no snapshot provider; set policy.allow_without_snapshot to patch "
                             "without a safety net")
        if snapshots and (problems := provider.check()):
            raise PatchAbort("; ".join(problems))

        result.stage = "plan"
        self._helper(t, host, "update", timeout=600).check()
        binaries = sorted({b for i in items for b in i.binaries})
        candidates = apt.parse_policy(t.run(["apt-cache", "policy", *binaries]).check().stdout)
        installed = {p.name: p.version for p in inv.packages}
        specs = [f"{apt.base_name(b)}={c}" for b, c in candidates.items() if c]
        sources = planner.parse_show(
            t.run(["apt-cache", "show", "--no-all-versions", *specs]).stdout) if specs else {}
        for item in items:
            planner.resolve(item, candidates, installed, sources, self.definitions,
                            inv.codename)
        active = [i for i in items if not i.skipped]
        result.items = [i.to_dict() for i in active]
        result.skipped_items = [i.to_dict() for i in items if i.skipped]
        if not active:
            result.status = "nothing-to-do"
            result.reason = "; ".join(f"{i.source_package}: {i.skipped}" for i in items)
            return

        result.stage = "simulate"
        targets = {b: v for i in active for b, v in i.targets.items()}
        args = [f"{b}={v}" for b, v in sorted(targets.items())]
        sim_out = self._helper(t, host, "simulate", *args, timeout=600)
        sim = apt.parse_simulation(sim_out.stdout + "\n" + sim_out.stderr)
        if sim_out.returncode != 0 and not sim.errors:
            sim.errors.append((sim_out.stderr or sim_out.stdout).strip()[-500:] or "apt failed")
        planned = {apt.base_name(b): v for b, v in targets.items()}
        result.problems = apt.check_simulation(
            sim, planned, allow_extra_upgrades=policy["allow_extra_upgrades"],
            allow_new_packages=tuple(policy["allow_new_packages"]))
        for name, (_, new) in sim.upgrades.items():
            if name not in planned:
                result.notes.append(f"dependency upgrade {name} -> {new}")
        if result.problems:
            raise PatchAbort("simulation: " + "; ".join(result.problems))

        if result.dry_run:
            result.health_before = [str(c) for c in health.run_all(host.healthchecks, t)]
            if not host.healthchecks:
                result.notes.append("no healthchecks configured: a real run would abort")
            result.status = "dry-run"
            result.reason = f"would upgrade {len(targets)} packages"
            return

        result.stage = "preflight-health"
        before = health.run_all(host.healthchecks, t)
        result.health_before = [str(c) for c in before]
        if not all(c.ok for c in before):
            raise PatchAbort("healthchecks fail before patching: "
                             + "; ".join(str(c) for c in before if not c.ok))

        ref = None
        if snapshots:
            result.stage = "snapshot"
            name = snapshot_name(result.run_id)
            ref = provider.create(name, f"aptwarden {result.run_id}: "
                                  + ", ".join(i.source_package for i in active)[:200])
            self.state.add_snapshot(ref.provider, ref.target, ref.name, host.name, result.run_id)
            result.snapshot = asdict(ref)

        result.stage = "apply"
        out = self._helper(t, host, "install", *args, timeout=3600)
        if out.returncode != 0:
            raise TransportError("apt-get install failed: "
                                 + (out.stderr or out.stdout).strip()[-800:])
        self._verify(t, targets)

        result.stage = "restart"
        self._restart(result, host, t)

        result.stage = "healthcheck"
        after = self._health(t, host)
        result.health_after = [str(c) for c in after]
        if all(c.ok for c in after):
            result.status = "patched"
            result.reason = f"upgraded {len(targets)} packages"
            return
        failed = "; ".join(str(c) for c in after if not c.ok)
        self._after_failure(result, host, t, provider, ref, f"healthchecks failed: {failed}")

    def manual_rollback(self, host: HostConfig, t: Transport, provider: SnapshotProvider,
                        ref: SnapshotRef, run_id: str) -> HostPatchResult:
        result = HostPatchResult(host.name, run_id, stage="rollback", snapshot=asdict(ref),
                                 reason=f"manual rollback to {ref.name}")
        try:
            marker = self._marker(t)
        except TransportError:
            marker = ""
        try:
            provider.rollback(ref)
            self.state.set_snapshot_state(ref.provider, ref.target, ref.name, "rolled-back")
            if not self._wait_back(t, marker):
                raise TransportError("host not reachable after rollback")
            if host.healthchecks:
                result.health_after = [str(c) for c in self._health(t, host)]
            result.status = "rolled-back"
        except (TransportError, SnapshotError) as e:
            result.status = "rollback-failed"
            result.reason += f": {e}"
        result.finished_at = utcnow()
        self.state.save_patch(run_id, host.name, result.status, result.started_at,
                              result.to_dict())
        return result

    def _verify(self, t: Transport, targets: dict[str, str]) -> None:
        out = t.run(["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\n",
                     *sorted(targets)]).check().stdout
        now = dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)
        wrong = [f"{b} is {now.get(b, now.get(apt.base_name(b), 'missing'))}, expected {v}"
                 for b, v in targets.items() if now.get(b, now.get(apt.base_name(b))) != v]
        if wrong:
            raise TransportError("versions after install differ: " + "; ".join(wrong))

    def _restart(self, result: HostPatchResult, host: HostConfig, t: Transport) -> None:
        mode = host.policy["restart"]
        reboot_needed = t.run(["test", "-e", "/run/reboot-required"]).returncode == 0
        if mode != "off":
            r = self._helper(t, host, "needrestart", "restart" if mode == "auto" else "list",
                             timeout=900)
            if r.returncode == 3:
                result.notes.append("needrestart not installed: services were not restarted")
            elif r.returncode == 0:
                services, kernel = apt.parse_needrestart(r.stdout)
                reboot_needed = reboot_needed or kernel
                if mode == "auto":
                    result.restarted = services
                elif services:
                    result.notes.append("services need a restart: " + ", ".join(services))
            else:
                result.notes.append(f"needrestart failed: {(r.stderr or r.stdout).strip()}")
        if not reboot_needed:
            return
        if host.policy["reboot"] != "if-required":
            result.notes.append("reboot required, not allowed by policy")
            return
        marker = self._marker(t)
        with contextlib.suppress(TransportError):  # the connection may drop while rebooting
            self._helper(t, host, "reboot", timeout=60)
        if not self._wait_back(t, marker):
            raise TransportError("host did not come back after reboot")
        result.rebooted = True

    def _failure(self, result: HostPatchResult, host: HostConfig, t: Transport,
                 provider: SnapshotProvider, message: str) -> None:
        if result.snapshot is None and result.stage in UNCHANGED_STAGES:
            result.status, result.reason = "aborted", message
            return
        ref = SnapshotRef(**result.snapshot) if result.snapshot else None
        self._after_failure(result, host, t, provider, ref, message)

    def _after_failure(self, result: HostPatchResult, host: HostConfig, t: Transport,
                       provider: SnapshotProvider, ref: SnapshotRef | None,
                       message: str) -> None:
        result.reason = message
        if ref is None:
            result.status = "failed"
            result.reason += " (no snapshot to roll back to)"
            return
        if host.policy["rollback"] != "auto":
            result.status = "needs-manual-rollback"
            result.reason += f" (run: aptwarden rollback --host {host.name})"
            return
        result.stage = "rollback"
        try:
            marker = self._marker(t)
        except TransportError:
            marker = ""
        try:
            provider.rollback(ref)
            self.state.set_snapshot_state(ref.provider, ref.target, ref.name, "rolled-back")
            if not self._wait_back(t, marker):
                raise TransportError("host not reachable after rollback")
            after = self._health(t, host)
            result.health_after = [str(c) for c in after]
            result.status = "rolled-back"
            if not all(c.ok for c in after):
                result.reason += "; healthchecks still fail after rollback"
        except (TransportError, SnapshotError) as e:
            result.status = "rollback-failed"
            result.reason += f"; rollback failed: {e}"
