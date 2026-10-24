from dataclasses import dataclass, field

import pytest

from aptwarden import config
from aptwarden.definitions import parse as parse_definition
from aptwarden.models import Finding, FindingStatus, HostInventory, Package, Severity
from aptwarden.patch.runner import PatchRunner
from aptwarden.snapshot import NoSnapshots, SnapshotError, SnapshotProvider, SnapshotRef
from aptwarden.state import State
from aptwarden.transport import CommandResult, Transport
from tests.unit.test_definitions import defn

HELPER = "/usr/local/lib/aptwarden/aptwarden-helper"


@dataclass
class Host:
    """A scripted Debian host."""

    installed: dict[str, str]
    candidates: dict[str, str]
    sources: dict[str, str]  # binary base name -> source package
    source_versions: dict[str, str] = field(default_factory=dict)  # candidate -> source version
    healthy: bool = True
    healthy_after_install: bool = True
    helper_ok: bool = True
    install_fails: bool = False
    extra_sim: str = ""
    needrestart: str | None = "NEEDRESTART-SVC: ssh.service\n"
    reboot_required: bool = False
    boots: int = 0
    calls: list[list[str]] = field(default_factory=list)


class ScriptedTransport(Transport):
    def __init__(self, host: Host):
        super().__init__("web01")
        self.h = host

    def close(self):
        pass

    def run(self, argv, timeout=None):
        h = self.h
        h.calls.append(argv)

        def ok(out="", rc=0, err=""):
            return CommandResult(argv, rc, out, err)

        if argv[:3] == ["sudo", "-n", HELPER]:
            cmd, args = argv[3], argv[4:]
            if not h.helper_ok:
                return ok(rc=1, err="sudo: a password is required")
            if cmd == "version":
                return ok("aptwarden-helper 1\n")
            if cmd == "update":
                return ok()
            if cmd == "simulate":
                lines = []
                for a in args:
                    name, ver = a.split("=", 1)
                    base = name.split(":")[0]
                    lines.append(f"Inst {base} [{h.installed[name]}] ({ver} Debian-Security:13 "
                                 f"[amd64])")
                return ok("\n".join(lines) + "\n" + h.extra_sim)
            if cmd == "install":
                if h.install_fails:
                    return ok(rc=100, err="E: Sub-process /usr/bin/dpkg returned an error code")
                for a in args:
                    name, ver = a.split("=", 1)
                    h.installed[name] = ver
                if not h.healthy_after_install:
                    h.healthy = False
                return ok()
            if cmd == "needrestart":
                return ok(rc=3) if h.needrestart is None else ok(h.needrestart)
            if cmd == "reboot":
                h.boots += 1
                h.reboot_required = False
                return ok()
        if argv[:2] == ["apt-cache", "policy"]:
            return ok("".join(f"{p}:\n  Installed: {h.installed.get(p)}\n"
                              f"  Candidate: {h.candidates.get(p, '(none)')}\n"
                              for p in argv[2:]))
        if argv[:2] == ["apt-cache", "show"]:
            out = []
            for spec in argv[3:]:
                name, ver = spec.split("=", 1)
                src_ver = h.source_versions.get(ver, ver)
                out.append(f"Package: {name}\nVersion: {ver}\n"
                           f"Source: {h.sources[name]} ({src_ver})\n")
            return ok("\n".join(out))
        if argv[0] == "dpkg-query":
            return ok("".join(f"{p}\t{h.installed[p]}\n" for p in argv[3:]))
        if argv[:2] == ["test", "-e"]:
            return ok(rc=0 if h.reboot_required else 1)
        if argv[0] == "cat" and argv[1] == "/proc/sys/kernel/random/boot_id":
            fields = " ".join(["0"] * 19)
            return ok(f"boot-{h.boots}\n1 (systemd) S {fields} {1000 + h.boots}\n")
        if argv[:2] == ["systemctl", "is-active"]:
            return ok("active\n") if h.healthy else ok("failed\n", rc=3)
        return ok(rc=127, err=f"unexpected command {argv}")


class FakeProvider(SnapshotProvider):
    name = "fake"

    def __init__(self, host: Host, problems=()):
        self.h = host
        self.problems = list(problems)
        self.snaps: dict[str, dict] = {}
        self.rolled_back: list[str] = []
        self.fail_rollback = False

    def check(self):
        return self.problems

    def create(self, name, description):
        self.snaps[name] = dict(self.h.installed)
        return SnapshotRef("fake", "node/lxc/100", name)

    def rollback(self, ref):
        if self.fail_rollback:
            raise SnapshotError("rollback task failed")
        self.h.installed = dict(self.snaps[ref.name])
        self.h.healthy = True
        self.h.boots += 1  # the container restarts
        self.rolled_back.append(ref.name)

    def delete(self, ref):
        self.snaps.pop(ref.name)

    def list(self):
        return list(self.snaps)


def host_config(policy=None, healthchecks=None, **host):
    data = {"hosts": [{"name": "web01", "policy": {"modes": ["patch"], **(policy or {})},
                       "healthchecks": [{"systemd": "ssh.service"}] if healthchecks is None
                       else healthchecks,
                       "health": {"grace": 0, "retries": 2, "interval": 0}, **host}]}
    return config.from_dict(data).hosts[0]


def openssl_host(**kw) -> Host:
    return Host(
        installed={"openssl": "3.5.1-1", "libssl3t64:amd64": "3.5.1-1"},
        candidates={"openssl": "3.5.7-1", "libssl3t64:amd64": "3.5.7-1"},
        sources={"openssl": "openssl", "libssl3t64": "openssl"},
        **kw,
    )


def inventory(h: Host) -> HostInventory:
    pkgs = [Package(n, v, "amd64", h.sources[n.split(":")[0]], v, "ii ")
            for n, v in h.installed.items()]
    return HostInventory("web01", "debian", "13", "trixie", "13.1", "amd64", pkgs)


def finding(vid="CVE-2026-1", fixed="3.5.4-1", severity=Severity.CRITICAL, **kw) -> Finding:
    return Finding(vid, "openssl", "3.5.1-1", FindingStatus.FIXABLE, fixed_version=fixed,
                   binaries=["libssl3t64:amd64", "openssl"], severity=severity, **kw)


@pytest.fixture
def state(tmp_path):
    s = State(tmp_path / "state.db")
    yield s
    s.close()


_RUN = iter(range(1, 10_000))


def run(state, h, cfg=None, findings=None, provider=None, dry_run=False, definitions=(),
        run_id=None):
    cfg = cfg or host_config()
    run_id = run_id or f"20261022T020000Z-{next(_RUN):04x}"
    provider = provider if provider is not None else FakeProvider(h)
    runner = PatchRunner(state, list(definitions), sleep=lambda s: None)
    return runner.run(cfg, inventory(h), findings if findings is not None else [finding()],
                      run_id, ScriptedTransport(h), provider, dry_run), provider


def helper_calls(h, cmd):
    return [c for c in h.calls if c[:4] == ["sudo", "-n", HELPER, cmd]]


def test_dry_run_changes_nothing(state):
    h = openssl_host()
    result, provider = run(state, h, dry_run=True)
    assert result.status == "dry-run", result.reason
    assert result.items[0]["targets"] == {"libssl3t64:amd64": "3.5.7-1", "openssl": "3.5.7-1"}
    assert not helper_calls(h, "install") and not provider.snaps
    assert h.installed["openssl"] == "3.5.1-1"
    assert state.patches("web01") == []  # dry runs are not recorded


def test_successful_patch(state):
    h = openssl_host()
    result, provider = run(state, h, run_id="20261022T020000Z-abcd")
    assert result.status == "patched", result.reason
    assert h.installed == {"openssl": "3.5.7-1", "libssl3t64:amd64": "3.5.7-1"}
    assert result.snapshot["name"] == "aptw_20261022T020000Z_abcd"
    assert list(provider.snaps) == ["aptw_20261022T020000Z_abcd"]
    assert result.restarted == ["ssh.service"]
    assert result.health_after == ["systemd ssh.service: ok"]
    assert state.snapshots("web01")[0]["name"] == "aptw_20261022T020000Z_abcd"
    assert state.patches("web01")[0]["status"] == "patched"
    # the snapshot is taken after the simulation, before the install
    order = [c[3] for c in h.calls if c[:3] == ["sudo", "-n", HELPER]]
    assert order.index("simulate") < order.index("install")


def test_failed_healthcheck_rolls_back(state):
    h = openssl_host(healthy_after_install=False)
    result, provider = run(state, h, run_id="20261022T020000Z-abcd")
    assert result.status == "rolled-back"
    assert "healthchecks failed" in result.reason
    assert h.installed["openssl"] == "3.5.1-1"
    assert provider.rolled_back == ["aptw_20261022T020000Z_abcd"]
    assert result.health_after == ["systemd ssh.service: ok"]
    assert state.snapshots("web01", state=None)[0]["state"] == "rolled-back"
    assert result.alert


def test_manual_rollback_policy(state):
    h = openssl_host(healthy_after_install=False)
    result, provider = run(state, h, cfg=host_config({"rollback": "manual"}))
    assert result.status == "needs-manual-rollback"
    assert "aptwarden rollback --host web01" in result.reason
    assert provider.rolled_back == [] and h.installed["openssl"] == "3.5.7-1"


def test_rollback_failure(state):
    h = openssl_host(healthy_after_install=False)
    provider = FakeProvider(h)
    provider.fail_rollback = True
    result, _ = run(state, h, provider=provider)
    assert result.status == "rollback-failed" and "rollback task failed" in result.reason


def test_install_failure_rolls_back(state):
    h = openssl_host(install_fails=True)
    result, provider = run(state, h)
    assert result.status == "rolled-back"
    assert "apt-get install failed" in result.reason


def test_simulation_problems_abort_before_snapshot(state):
    h = openssl_host(extra_sim="Remv libimportant [1.0-1]\nInst libnew1 (2.0 Debian:13 [amd64])\n")
    result, provider = run(state, h)
    assert result.status == "aborted"
    assert "would remove libimportant" in result.reason
    assert "would newly install libnew1 2.0" in result.reason
    assert not provider.snaps and not helper_calls(h, "install")


def test_extra_dependency_upgrade_policy(state):
    extra = "Inst libc6 [2.41-12] (2.41-12+deb13u4 Debian-Security:13 [amd64])\n"
    result, _ = run(state, openssl_host(extra_sim=extra))
    assert result.status == "aborted" and "would also upgrade libc6" in result.reason
    result, _ = run(state, openssl_host(extra_sim=extra),
                    cfg=host_config({"allow_extra_upgrades": True}))
    assert result.status == "patched"
    assert "dependency upgrade libc6 -> 2.41-12+deb13u4" in result.notes


def test_unhealthy_before_patch_aborts(state):
    h = openssl_host(healthy=False)
    result, provider = run(state, h)
    assert result.status == "aborted" and "fail before patching" in result.reason
    assert not provider.snaps


def test_healthchecks_are_mandatory(state):
    h = openssl_host()
    result, _ = run(state, h, cfg=host_config(healthchecks=[]))
    assert result.status == "aborted" and "no healthchecks" in result.reason
    result, _ = run(state, openssl_host(), cfg=host_config(healthchecks=[]), dry_run=True)
    assert result.status == "dry-run"
    assert "no healthchecks configured: a real run would abort" in result.notes


def test_snapshots_are_mandatory_unless_allowed(state):
    result, _ = run(state, openssl_host(), provider=NoSnapshots())
    assert result.status == "aborted" and "allow_without_snapshot" in result.reason
    h = openssl_host()
    result, _ = run(state, h, provider=NoSnapshots(),
                    cfg=host_config({"allow_without_snapshot": True}))
    assert result.status == "patched" and result.snapshot is None
    # without a snapshot a failed healthcheck can only be reported
    h = openssl_host(healthy_after_install=False)
    result, _ = run(state, h, provider=NoSnapshots(),
                    cfg=host_config({"allow_without_snapshot": True}))
    assert result.status == "failed" and "no snapshot to roll back to" in result.reason


def test_snapshot_not_supported_aborts(state):
    h = openssl_host()
    result, _ = run(state, h, provider=FakeProvider(h, ["mp0 on dir storage"]))
    assert result.status == "aborted" and "mp0 on dir storage" in result.reason


def test_helper_missing_aborts(state):
    result, _ = run(state, openssl_host(helper_ok=False))
    assert result.status == "aborted" and "no sudo rule for the helper" in result.reason


def test_candidate_must_reach_fixed_version(state):
    h = openssl_host()
    h.candidates = {"openssl": "3.5.2-1", "libssl3t64:amd64": "3.5.2-1"}
    result, _ = run(state, h)
    assert result.status == "nothing-to-do"
    assert "does not reach the fixed version 3.5.4-1" in result.reason


def test_blocked_candidate_is_skipped(state):
    h = openssl_host()
    block, errors, _ = parse_definition(defn(
        id="AW-2026-0009", package="openssl", action="block",
        affected=[{"release": "any", "ranges": [{"introduced": "3.5.7-1",
                                                  "fixed": "3.5.8-1"}]}]), "AW-2026-0009.yaml")
    assert not errors
    result, _ = run(state, h, definitions=[block])
    assert result.status == "nothing-to-do" and "blocked by AW-2026-0009" in result.reason


def test_policy_selection(state):
    h = openssl_host()
    result, _ = run(state, h, findings=[finding(severity=Severity.MEDIUM)])
    assert result.status == "nothing-to-do"
    result, _ = run(state, h, findings=[finding(severity=Severity.LOW, kev=True)])
    assert result.status == "patched"  # KEV overrides the severity filter
    h = openssl_host()
    result, _ = run(state, h, findings=[finding(definition="AW-1", action="report")])
    assert result.status == "nothing-to-do"  # a definition restricted it to reporting


def test_epoch_and_source_version_resolution(state):
    h = Host(installed={"bsdutils": "1:2.41-5"}, candidates={"bsdutils": "1:2.41.5-0+deb13u1"},
             sources={"bsdutils": "util-linux"},
             source_versions={"1:2.41.5-0+deb13u1": "2.41.5-0+deb13u1"})
    f = Finding("CVE-2026-2", "util-linux", "2.41-5", FindingStatus.FIXABLE,
                fixed_version="2.41.5-0+deb13u1", binaries=["bsdutils"],
                severity=Severity.HIGH)
    inv = HostInventory("web01", "debian", "13", "trixie", "13.1", "amd64",
                        [Package("bsdutils", "1:2.41-5", "amd64", "util-linux", "2.41-5", "ii ")])
    result = PatchRunner(state, [], sleep=lambda s: None).run(
        host_config(), inv, [f], "r1", ScriptedTransport(h), FakeProvider(h))
    assert result.status == "patched", result.reason
    assert result.items[0]["target_source_version"] == "2.41.5-0+deb13u1"


def test_reboot_if_required(state):
    h = openssl_host(reboot_required=True)
    result, _ = run(state, h, cfg=host_config({"reboot": "if-required"}))
    assert result.status == "patched" and result.rebooted and h.boots == 1
    h = openssl_host(reboot_required=True)
    result, _ = run(state, h)
    assert not result.rebooted and "reboot required, not allowed by policy" in result.notes


def test_needrestart_missing_and_list_mode(state):
    result, _ = run(state, openssl_host(needrestart=None))
    assert "needrestart not installed: services were not restarted" in result.notes
    result, _ = run(state, openssl_host(), cfg=host_config({"restart": "list"}))
    assert result.restarted == [] and "services need a restart: ssh.service" in result.notes
    h = openssl_host()
    run(state, h, cfg=host_config({"restart": "off"}))
    assert not helper_calls(h, "needrestart")


def test_repeated_results_are_flagged(state):
    h = openssl_host(healthy=False)
    first, _ = run(state, h)
    second, _ = run(state, h)
    assert not first.repeated and second.repeated


def test_manual_rollback(state):
    h = openssl_host()
    result, provider = run(state, h)
    ref = SnapshotRef(**result.snapshot)
    out = PatchRunner(state, [], sleep=lambda s: None).manual_rollback(
        host_config(), ScriptedTransport(h), provider, ref, "r2")
    assert out.status == "rolled-back" and h.installed["openssl"] == "3.5.1-1"
    assert state.snapshots("web01", state=None)[0]["state"] == "rolled-back"


# real messages captured from a Debian 13 host
@pytest.mark.parametrize("stdout, stderr, expected", [
    ("aptwarden-helper 1\n", "", None),
    ("", "env: ‘sudo’: No such file or directory", "sudo is not installed"),
    ("", "sudo: a password is required", "no sudo rule for the helper"),
    ("", f"sudo: {HELPER}: command not found", "the helper is not installed at"),
    ("aptwarden-helper 0\n", "", "outdated helper (aptwarden-helper 0"),
    ("", "ssh_exchange_identification: boom", "helper not usable via sudo (ssh_"),
])
def test_explain_helper_failure(stdout, stderr, expected):
    from aptwarden.patch.runner import explain_helper_failure

    r = CommandResult(["sudo"], 0 if stdout else 1, stdout, stderr)
    msg = explain_helper_failure(r, HELPER)
    if expected is None:
        assert msg is None
    else:
        assert expected in msg and "see README" in msg


def test_no_newer_candidate_explains_versions(state):
    h = openssl_host()
    h.candidates = dict(h.installed)  # apt has nothing newer
    result, _ = run(state, h)
    assert result.status == "nothing-to-do"
    reason = result.skipped_items[0]["skipped"]
    assert "installed 3.5.1-1, fix needs 3.5.4-1" in reason
    assert "candidate 3.5.1-1" in reason and "security missing" in reason


def test_explain_helper_failure_keeps_original_message():
    from aptwarden.patch.runner import explain_helper_failure

    r = CommandResult(["sudo"], 1, "", "env: ‘sudo’: No such file or directory")
    msg = explain_helper_failure(r, HELPER)
    assert msg.startswith("sudo is not installed on the host (host said: env: ‘sudo’: No such")


def test_nothing_to_do_explains_policy(state):
    h = openssl_host()
    findings = [finding("CVE-1", severity=Severity.MEDIUM), finding("CVE-2", severity=Severity.LOW),
                finding("CVE-3", severity=Severity.CRITICAL, definition="AW-1", action="report")]
    result, _ = run(state, h, findings=findings)
    assert result.status == "nothing-to-do"
    assert result.reason == ("3 fixable, none allowed by policy (auto-patch: critical, high + KEV):"
                             " 1 low, 1 medium, 1 restricted to report by a definition")
    result, _ = run(state, h, findings=[])
    assert result.reason == "no fixable vulnerabilities"


def test_severity_override_patches_medium_and_notes_it(state):
    h = openssl_host()
    from dataclasses import replace
    base = host_config()
    # set by `aptwarden patch --min-severity`, never accepted in the config file
    cfg = replace(base, policy={**base.policy, "severity_override": True,
                                "auto_patch_severities": ["critical", "high", "medium"]})
    result, _ = run(state, h, cfg=cfg, findings=[finding(severity=Severity.MEDIUM)])
    assert result.status == "patched", result.reason
    assert "manual severity override: auto-patch critical, high, medium" in result.notes
    assert state.patches("web01")[0]["notes"][0].startswith("manual severity override")
