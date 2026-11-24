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
from aptwarden.inventory import DPKG_FORMAT, InventoryError, parse_dpkg_query
from aptwarden.log import safe
from aptwarden.models import Finding, HostInventory
from aptwarden.patch import apt, planner
from aptwarden.snapshot import (
    NoSnapshots,
    SnapshotError,
    SnapshotProvider,
    SnapshotRef,
    identity_problem,
    snapshot_name,
)
from aptwarden.state import State, utcnow
from aptwarden.transport import Transport, TransportError

log = logging.getLogger(__name__)

# The version `aptwarden helper show` installs. Hosts may run an older one: each
# feature only needs the version that introduced what it relies on (HELPER_FEATURES),
# so raising this does not force every host to update at once. Newer is accepted.
HELPER_VERSION = 4
# feature -> minimum helper version. patch: v2 binds install to its own simulation,
# v3 fixes the needrestart restart. pin: v4 adds the pin command.
HELPER_FEATURES = {"patch": 3, "pin": 4}
_FEATURE_NAMES = {"patch": "patching", "pin": "enforce_block: pin"}
# The helper's exit status when it refuses a call. It only exits so before running apt, so
# nothing on the host changed.
HELPER_REFUSED = 2

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


def helper_version(out: str) -> int | None:
    """The version in the helper's ``version`` output, None if it is not one."""
    prefix, _, number = out.strip().partition(" ")
    if prefix == "aptwarden-helper" and number.isascii() and number.isdigit():
        return int(number)
    return None


def missing_helper_features(version: int) -> dict[str, int]:
    """{feature: minimum version} for the features this helper version lacks."""
    return {f: need for f, need in HELPER_FEATURES.items() if version < need}


def explain_helper_failure(r, helper: str, feature: str = "patch") -> str | None:
    """None if ``sudo -n <helper> version`` worked and the helper is recent enough
    for ``feature`` (a key of HELPER_FEATURES), else what is wrong."""
    out = r.stdout.strip()
    need = HELPER_FEATURES[feature]
    version = helper_version(out)
    if version is not None and version >= need:
        return None
    raw = (r.stderr or r.stdout).strip()
    if out.startswith("aptwarden-helper "):
        return (f"outdated helper ({out}; {_FEATURE_NAMES[feature]} needs version {need} "
                f"or newer): update it to version {HELPER_VERSION}; {HELPER_HINT}")
    if "'sudo': No such file" in raw or "‘sudo’: No such file" in raw or (
            "sudo" in raw and "not found" in raw and helper not in raw):
        reason = "sudo is not installed on the host"
    elif helper in raw and ("not found" in raw or "No such file" in raw):
        reason = f"the helper is not installed at {helper}"
    elif "password is required" in raw or "not allowed" in raw or "sudoers" in raw:
        reason = ("no sudo rule for the helper: /etc/sudoers.d/aptwarden is missing, has a "
                  "wrong mode, or its file name contains a '.' (then sudo ignores it); "
                  f"or the helper is not at {helper}")
    else:
        return f"helper not usable via sudo ({raw or 'no output'}); {HELPER_HINT}"
    # keep the original message: the classification above is only a heuristic
    return f"{reason} (host said: {raw or out or 'no output'}); {HELPER_HINT}"


def guest_problem(t: Transport, provider: SnapshotProvider) -> str | None:
    """None if the provider's guest is the host behind ``t`` (or the provider cannot
    tell), else why not. A wrong VMID would otherwise snapshot one guest, patch
    another and, on a failure, roll back the first one."""
    guest = provider.identity()
    if guest is None:
        return None
    # /sys/class/net/lo always exists, so the glob matches
    out = t.run(["sh", "-c", "uname -n; cat /sys/class/net/*/address"], timeout=15)
    hostname, _, rest = out.check().stdout.partition("\n")
    macs = {line.strip().lower() for line in rest.splitlines()}
    return identity_problem(guest, hostname.strip(), macs)


def policy_skip_reason(findings: list[Finding], policy: dict) -> str:
    """Why nothing was selected although the host may have fixable findings."""
    from collections import Counter

    from aptwarden.models import FindingStatus

    fixable = [f for f in findings if f.status == FindingStatus.FIXABLE and f.fixed_version]
    if not fixable:
        return "no fixable vulnerabilities"
    restricted = sum(1 for f in fixable if f.action == "report")
    counts = Counter(str(f.severity) for f in fixable if f.action != "report")
    allowed = ", ".join(policy["auto_patch_severities"]) + (
        " + KEV" if policy["auto_patch_kev"] else "")
    parts = [f"{n} {sev}" for sev, n in sorted(counts.items())]
    if restricted:
        parts.append(f"{restricted} restricted to report by a definition")
    return (f"{len(fixable)} fixable, none allowed by policy (auto-patch: {allowed}): "
            + ", ".join(parts))


class PatchAbort(Exception):
    """Stop before anything was changed."""

    def __init__(self, message: str):
        super().__init__(safe(message, keep_newlines=True))  # may contain the host's stderr


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
    # healthchecks still fail after a rollback: rolled back, but the host is not well
    unhealthy_after_rollback: bool = False
    notes: list[str] = field(default_factory=list)
    repeated: bool = False  # same status and reason as the host's previous patch run
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""

    @property
    def alert(self) -> bool:
        return self.status in ALERT_STATUSES

    def to_dict(self) -> dict:
        return asdict(self)


def save_result(state: State, result: HostPatchResult) -> None:
    """Store a patch result in the history. ``repeated`` compares with the host's
    last run that actually ran: a skip in between does not make an abort new."""
    previous = state.patches(result.host, 1, skipped=result.status == "skipped")
    result.repeated = bool(previous) and previous[0]["status"] == result.status \
        and previous[0]["reason"] == result.reason
    state.save_patch(result.run_id, result.host, result.status, result.started_at,
                     result.to_dict())


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
        fields = stat.rpartition(")")[2].split() if ")" in stat else []
        start = fields[19] if len(fields) > 19 else ""
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
        except Exception as e:  # noqa: BLE001 - see below
            # A bug or an answer nobody expected. After the snapshot the host may be
            # half patched, so this must end like any other failure (rollback or alert)
            # and be stored; propagating would skip both and stop the whole run.
            log.exception("patch crashed", extra={"host": host.name, "stage": result.stage})
            self._failure(result, host, transport, provider,
                          safe(f"{result.stage}: unexpected error: {type(e).__name__}: {e}"))
        result.finished_at = utcnow()
        log.log(logging.ERROR if result.alert else logging.INFO, "patch result",
                extra={"host": host.name, "status": result.status, "stage": result.stage,
                       "reason": result.reason})
        if not dry_run:
            save_result(self.state, result)
        return result

    def _run(self, result: HostPatchResult, host: HostConfig, inv: HostInventory,
             findings: list[Finding], t: Transport, provider: SnapshotProvider) -> None:
        policy = host.policy
        if policy.get("severity_override"):
            result.notes.append("manual severity override: auto-patch "
                                + ", ".join(policy["auto_patch_severities"]))
        items = planner.group(planner.select(findings, policy))
        if not items:
            result.status = "nothing-to-do"
            result.reason = policy_skip_reason(findings, policy)
            return

        result.stage = "preflight"
        r = self._helper(t, host, "version", timeout=30)
        if problem := explain_helper_failure(r, host.ssh.helper, "patch"):
            raise PatchAbort(problem)
        if not result.dry_run and not host.healthchecks:
            raise PatchAbort("no healthchecks configured; auto-patching requires them")
        snapshots = not isinstance(provider, NoSnapshots)
        if not snapshots and not policy["allow_without_snapshot"]:
            raise PatchAbort("no snapshot provider; set policy.allow_without_snapshot to patch "
                             "without a safety net")
        if snapshots and (problems := provider.check()):
            raise PatchAbort("; ".join(problems))
        if snapshots and (problem := guest_problem(t, provider)):
            raise PatchAbort(problem)

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
                            inv.codename, distro=inv.distro)
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
        for name, (old, new) in sim.upgrades.items():
            if name not in planned:
                result.notes.append(f"dependency upgrade {name} {old} -> {new}")
        if result.problems:
            raise PatchAbort("simulation: " + "; ".join(result.problems))
        # The helper installs only what it is given explicitly, so the extra upgrades and new
        # packages the policy allowed are named with the version from the simulation.
        install_args = args + apt.allowed_extras(sim, planned)

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
        # compared with the packages after the install, see _verify
        packages_before = self._installed(t)

        ref = None
        if snapshots:
            result.stage = "snapshot"
            name = snapshot_name(result.run_id)
            ref = provider.create(name, f"aptwarden {result.run_id}: "
                                  + ", ".join(i.source_package for i in active)[:200])
            self.state.add_snapshot(ref.provider, ref.target, ref.name, host.name, result.run_id)
            result.snapshot = asdict(ref)

        result.stage = "apply"
        out = self._helper(t, host, "install", *install_args, timeout=3600)
        if out.returncode == HELPER_REFUSED:
            # e.g. the package lists changed since the simulation; the snapshot is unused
            raise PatchAbort("helper refused the install, nothing changed: "
                             + (out.stderr or out.stdout).strip()[-800:])
        if out.returncode != 0:
            raise TransportError("apt-get install failed: "
                                 + (out.stderr or out.stdout).strip()[-800:])
        self._verify(t, targets, install_args, packages_before)

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
        except Exception:  # noqa: BLE001 - host unreachable or odd output: any marker will do
            marker = ""
        try:
            provider.rollback(ref)
            self.state.set_snapshot_state(ref.provider, ref.target, ref.name, "rolled-back")
            if not self._wait_back(t, marker):
                raise TransportError("host not reachable after rollback")
            if host.healthchecks:
                self._health_after_rollback(result, t, host)
            result.status = "rolled-back"
        except (TransportError, SnapshotError) as e:
            result.status = "rollback-failed"
            result.reason += f": {e}"
        except Exception as e:  # noqa: BLE001 - the result must still be stored
            log.exception("rollback crashed", extra={"host": host.name})
            result.status = "rollback-failed"
            result.reason += safe(f": unexpected error: {type(e).__name__}: {e}")
        result.finished_at = utcnow()
        self.state.save_patch(run_id, host.name, result.status, result.started_at,
                              result.to_dict())
        return result

    def _health_after_rollback(self, result: HostPatchResult, t: Transport,
                               host: HostConfig) -> None:
        after = self._health(t, host)
        result.health_after = [str(c) for c in after]
        if not all(c.ok for c in after):
            result.unhealthy_after_rollback = True
            result.reason += "; healthchecks still fail after rollback"

    def _installed(self, t: Transport) -> dict[str, str]:
        """{binary package: version} of the installed packages."""
        out = t.run(["dpkg-query", "-W", f"-f={DPKG_FORMAT}"]).check().stdout
        try:
            return {p.name: p.version for p in parse_dpkg_query(out)}
        except InventoryError as e:
            raise TransportError(str(e)) from e

    def _verify(self, t: Transport, targets: dict[str, str], install_args: list[str],
                before: dict[str, str]) -> None:
        """The targets have their versions, and nothing else changed but what the helper
        was given. The helper checks its own simulation right before installing, but
        apt runs again after it, without a lock in between: package lists or another
        apt run may have changed meanwhile. A change outside the plan is a failed
        install, which rolls back."""
        now = self._installed(t)

        def version(packages: dict[str, str], name: str) -> str | None:
            return packages.get(name, packages.get(apt.base_name(name)))

        wrong = [f"{b} is {version(now, b) or 'missing'}, expected {v}"
                 for b, v in targets.items() if version(now, b) != v]
        if wrong:
            raise TransportError("versions after install differ: " + "; ".join(wrong))
        allowed = {apt.base_name(name): v
                   for name, _, v in (a.partition("=") for a in install_args)}
        unexpected = []
        for name in sorted(before.keys() | now.keys()):
            old, new = before.get(name), now.get(name)
            if old == new:
                continue
            if new is None:
                unexpected.append(f"{name} {old} removed")
            elif allowed.get(apt.base_name(name)) != new:
                unexpected.append(f"{name} {old or '(new)'} -> {new}")
        if unexpected:
            shown = "; ".join(unexpected[:10])
            more = f" and {len(unexpected) - 10} more" if len(unexpected) > 10 else ""
            raise TransportError(f"install changed packages outside the plan: {shown}{more}")

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
                    # the helper lists the services again after needrestart restarted them
                    pending = apt.parse_pending_restarts(r.stdout)
                    result.restarted = [s for s in services if s not in pending]
                    if pending:
                        result.notes.append(
                            "services still need a restart (deferred by needrestart, or "
                            "the restart failed): " + ", ".join(pending))
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
        except Exception:  # noqa: BLE001 - host unreachable or odd output: any marker will do
            marker = ""
        try:
            provider.rollback(ref)
            self.state.set_snapshot_state(ref.provider, ref.target, ref.name, "rolled-back")
            if not self._wait_back(t, marker):
                raise TransportError("host not reachable after rollback")
            self._health_after_rollback(result, t, host)
            result.status = "rolled-back"
        except (TransportError, SnapshotError) as e:
            result.status = "rollback-failed"
            result.reason += f"; rollback failed: {e}"
        except Exception as e:  # noqa: BLE001 - must end in a stored status and an alert
            log.exception("rollback crashed", extra={"host": host.name})
            result.status = "rollback-failed"
            result.reason += safe(f"; rollback failed: unexpected error: "
                                  f"{type(e).__name__}: {e}")
