from datetime import datetime

import pytest

from aptwarden.definitions import Definition
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.patch import apt, window
from aptwarden.patch.planner import parse_show, preview

SIM = """NOTE: This is only a simulation!
Reading package lists...
Inst openssl-provider-legacy [3.5.1-1+deb13u1] (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])
Inst libssl3t64 [3.5.1-1+deb13u1] (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])
Inst openssl [3.5.1-1+deb13u1] (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])
Conf openssl (3.5.7-1~deb13u3 Debian-Security:13/stable-security [amd64])
"""


def test_parse_simulation_real_output():
    sim = apt.parse_simulation(SIM)
    assert sim.upgrades["libssl3t64"] == ("3.5.1-1+deb13u1", "3.5.7-1~deb13u3")
    assert set(sim.upgrades) == {"openssl", "libssl3t64", "openssl-provider-legacy"}
    assert sim.new == {} and sim.removals == [] and sim.errors == []


def test_parse_simulation_new_removed_errors():
    sim = apt.parse_simulation("Inst libnew1 (1.0-1 Debian:13/stable [amd64])\n"
                               "Remv oldpkg [2.0-1]\n"
                               "E: Unable to correct problems, you have held broken packages.\n")
    assert sim.new == {"libnew1": "1.0-1"}
    assert sim.removals == ["oldpkg"]
    assert "held broken packages" in sim.errors[0]


# apt 3.0.3 with --no-remove, captured on Debian 13
NO_REMOVE = """Reading package lists...
Building dependency tree...
Reading state information...
The following packages will be REMOVED:
  systemd-timesyncd libfoo1:i386*
The following NEW packages will be installed:
  chrony
0 upgraded, 1 newly installed, 2 to remove and 0 not upgraded.
E: Packages need to be removed but remove is disabled.
"""


def test_parse_simulation_no_remove():
    sim = apt.parse_simulation(NO_REMOVE + "Remv systemd-timesyncd [257.13-1~deb13u1]\n")
    assert sim.removals == ["systemd-timesyncd", "libfoo1"]
    assert sim.errors == ["Packages need to be removed but remove is disabled."]
    assert sim.new == {} and sim.upgrades == {}  # the summary block is not parsed


def test_allowed_extras():
    sim = apt.parse_simulation(SIM + "Inst libnew1 (1.0-1 Debian:13/stable [amd64])\n")
    assert apt.allowed_extras(sim, {"openssl": "3.5.7-1~deb13u3"}) == [
        "libnew1=1.0-1", "libssl3t64=3.5.7-1~deb13u3", "openssl-provider-legacy=3.5.7-1~deb13u3"]
    planned = {name: new for name, (_, new) in sim.upgrades.items()}
    assert apt.allowed_extras(apt.parse_simulation(SIM), planned) == []


def test_check_simulation():
    sim = apt.parse_simulation(SIM)
    planned = {"openssl": "3.5.7-1~deb13u3", "libssl3t64": "3.5.7-1~deb13u3",
               "openssl-provider-legacy": "3.5.7-1~deb13u3"}
    assert apt.check_simulation(sim, planned) == []
    problems = apt.check_simulation(sim, {"openssl": "3.5.7-1~deb13u3",
                                          "libssl3t64": "3.5.7-1~deb13u2",
                                          "zlib1g": "1:1.3-2"})
    assert "libssl3t64 would become 3.5.7-1~deb13u3, planned 3.5.7-1~deb13u2" in problems
    assert "zlib1g would not be upgraded" in problems
    assert any("would also upgrade openssl-provider-legacy" in p for p in problems)
    assert not any("openssl-provider-legacy" in p for p in apt.check_simulation(
        sim, {"openssl": "3.5.7-1~deb13u3", "libssl3t64": "3.5.7-1~deb13u3"},
        allow_extra_upgrades=True))
    bad = apt.parse_simulation("Inst x (1 a [amd64])\nRemv y [1]\nE: broken\n")
    problems = apt.check_simulation(bad, {})
    assert problems == ["apt error: broken", "would remove y", "would newly install x 1"]
    assert apt.check_simulation(bad, {}, allow_new_packages=("x",))[-1] == "would remove y"


# --- the root helper ----------------------------------------------------------------

def run_helper(tmp_path, *args, sim="", sim_rc=0):
    """Run the real helper with a fake apt-get; returns (result, apt-get calls)."""
    import subprocess
    from importlib import resources

    text = resources.files("aptwarden").joinpath("helper/aptwarden-helper").read_text()
    guard = '[ "$(id -u)" != 0 ]'  # the test hook is off for root, also when testing as root
    assert guard in text
    helper = tmp_path / "aptwarden-helper"
    helper.write_text(text.replace(guard, "true"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (tmp_path / "sim.txt").write_text(sim)
    log = tmp_path / "apt-get.log"
    log.write_text("")
    fake = bin_dir / "apt-get"
    fake.write_text(f'#!/bin/sh\necho "$*" >> {log}\n'
                    f'case " $* " in *" -s "*) cat {tmp_path / "sim.txt"}; exit {sim_rc} ;; esac\n')
    fake.chmod(0o755)
    r = subprocess.run(["sh", str(helper), *args], capture_output=True, text=True,
                       env={"APTWARDEN_HELPER_TESTBIN": str(bin_dir)})
    return r, log.read_text().splitlines()


PLAN = ["openssl=3.5.7-1~deb13u3", "libssl3t64:amd64=3.5.7-1~deb13u3",
        "openssl-provider-legacy=3.5.7-1~deb13u3"]


def test_helper_installs_the_simulated_transaction(tmp_path):
    r, calls = run_helper(tmp_path, "install", *PLAN, sim=SIM)
    assert r.returncode == 0, r.stderr
    assert len(calls) == 2 and " -s install -- " in calls[0]
    assert calls[1].endswith("install -- " + " ".join(PLAN)) and " -s " not in calls[1]
    assert all("--only-upgrade --no-remove" in c for c in calls)


def fake_needrestart(tmp_path, still_listed):
    """A needrestart that lists ssh and dbus, restarts only without -b (as the real one
    does) and then lists ``still_listed``. Returns its call log."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log, done = tmp_path / "needrestart.log", tmp_path / "restarted"
    fake = bin_dir / "needrestart"
    fake.write_text(f"""#!/bin/sh
echo "$*" >> {log}
case " $* " in
    *" -b "*)
        echo "NEEDRESTART-VER: 3.11"
        echo "NEEDRESTART-KSTA: 1"
        if [ -e {done} ]; then
            for s in {still_listed}; do echo "NEEDRESTART-SVC: $s"; done
        else
            echo "NEEDRESTART-SVC: ssh.service"
            echo "NEEDRESTART-SVC: dbus.service"
        fi ;;
    *" -r a "*) echo "Restarting services..."; : > {done} ;;
esac
""")
    fake.chmod(0o755)
    log.write_text("")
    return log


def test_helper_needrestart_restart_really_restarts(tmp_path):
    # "needrestart -r a -b" restarts nothing: batch mode only lists
    log = fake_needrestart(tmp_path, "dbus.service")
    r, _ = run_helper(tmp_path, "needrestart", "restart")
    assert r.returncode == 0, r.stderr
    calls = log.read_text().splitlines()
    assert calls == ["-r l -b", "-r a -l", "-r l -b -l"]
    assert "-b" not in calls[1].split()
    services, reboot = apt.parse_needrestart(r.stdout)
    assert services == ["ssh.service", "dbus.service"] and not reboot
    assert apt.parse_pending_restarts(r.stdout) == ["dbus.service"]
    assert "Restarting services..." in r.stderr and "Restarting" not in r.stdout


def test_helper_needrestart_list_and_nothing_to_restart(tmp_path):
    log = fake_needrestart(tmp_path, "")
    r, _ = run_helper(tmp_path, "needrestart", "list")
    assert r.returncode == 0 and log.read_text().splitlines() == ["-r l -b"]
    assert apt.parse_needrestart(r.stdout)[0] == ["ssh.service", "dbus.service"]
    (tmp_path / "restarted").write_text("")  # nothing is listed any more
    r, _ = run_helper(tmp_path, "needrestart", "restart")
    assert r.returncode == 0, r.stderr
    assert log.read_text().splitlines()[1:] == ["-r l -b"]  # no restart pass needed
    assert apt.parse_needrestart(r.stdout)[0] == []


def test_helper_version(tmp_path):
    from aptwarden.patch.runner import HELPER_VERSION

    r, _ = run_helper(tmp_path, "version")
    assert r.stdout == f"aptwarden-helper {HELPER_VERSION}\n"


@pytest.mark.parametrize("args, sim, sim_rc, error", [
    # an upgrade nobody asked for (the lists changed since the central simulation)
    (PLAN[:2], SIM, 0, "would install openssl-provider-legacy 3.5.7-1~deb13u3, which was not"),
    # a new dependency
    (PLAN, SIM + "Inst libnew1 (1.0-1 Debian:13/stable [amd64])\n", 0,
     "would install libnew1 1.0-1"),
    # another version than requested
    (PLAN, SIM.replace("Inst openssl [3.5.1-1+deb13u1] (3.5.7-1~deb13u3",
                       "Inst openssl [3.5.1-1+deb13u1] (3.5.7-1~deb13u4"), 0,
     "would install openssl 3.5.7-1~deb13u4"),
    (PLAN, SIM + "Remv systemd-timesyncd [257.13-1~deb13u1]\n", 0,
     "would remove systemd-timesyncd [257.13-1~deb13u1]"),
    (PLAN, NO_REMOVE, 100, "simulation failed"),
], ids=["extra-upgrade", "new-dependency", "other-version", "removal", "no-remove-error"])
def test_helper_refuses_other_transactions(tmp_path, args, sim, sim_rc, error):
    r, calls = run_helper(tmp_path, "install", *args, sim=sim, sim_rc=sim_rc)
    assert r.returncode == 2 and error in r.stderr and "nothing installed" in r.stderr
    assert len(calls) == 1 and " -s " in calls[0]  # only the simulation ran
    if sim_rc:
        assert "E: Packages need to be removed but remove is disabled." in r.stderr


def test_helper_accepts_named_extras(tmp_path):
    sim = SIM + "Inst libnew1 (1.0-1 Debian:13/stable [amd64])\n"
    r, calls = run_helper(tmp_path, "install", *PLAN, "libnew1=1.0-1", sim=sim)
    assert r.returncode == 0, r.stderr
    assert len(calls) == 2


def test_helper_simulate_cannot_remove(tmp_path):
    r, calls = run_helper(tmp_path, "simulate", *PLAN, sim=SIM)
    assert r.returncode == 0 and r.stdout == SIM
    assert calls == [f"-q -y --only-upgrade --no-remove --no-install-recommends "
                     f"-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
                     f"-o DPkg::Lock::Timeout=300 -s install -- {' '.join(PLAN)}"]


def test_parse_policy_with_arch_and_none():
    text = """openssl:
  Installed: 3.5.1-1+deb13u1
  Candidate: 3.5.7-1~deb13u3
  Version table:
     3.5.7-1~deb13u3 500
libssl3t64:amd64:
  Installed: 3.5.1-1+deb13u1
  Candidate: 3.5.7-1~deb13u3
gone:
  Installed: 1.0
  Candidate: (none)
"""
    assert apt.parse_policy(text) == {"openssl": "3.5.7-1~deb13u3",
                                      "libssl3t64:amd64": "3.5.7-1~deb13u3", "gone": None}


def test_parse_needrestart():
    out = ("NEEDRESTART-VER: 3.8\nNEEDRESTART-KCUR: 6.8.12-4-pve\nNEEDRESTART-KSTA: 0\n"
           "NEEDRESTART-SVC: ssh.service\nNEEDRESTART-SVC: cron.service\n")
    assert apt.parse_needrestart(out) == (["ssh.service", "cron.service"], False)
    assert apt.parse_needrestart("NEEDRESTART-KSTA: 3\n") == ([], True)
    assert apt.parse_pending_restarts(out) == []
    assert apt.parse_pending_restarts(
        out + "APTWARDEN-PENDING: dbus.service\nAPTWARDEN-PENDING: \n") == ["dbus.service"]


def test_parse_show_source_versions():
    text = """Package: bsdutils
Version: 1:2.41.5-0+deb13u1
Source: util-linux (2.41.5-0+deb13u1)
Architecture: amd64

Package: openssl
Version: 3.5.7-1~deb13u3
Architecture: amd64

Package: libssl3t64
Version: 3.5.7-1~deb13u3
Source: openssl
"""
    assert parse_show(text) == {
        ("bsdutils", "1:2.41.5-0+deb13u1"): ("util-linux", "2.41.5-0+deb13u1"),
        ("openssl", "3.5.7-1~deb13u3"): ("openssl", "3.5.7-1~deb13u3"),
        ("libssl3t64", "3.5.7-1~deb13u3"): ("openssl", "3.5.7-1~deb13u3"),
    }


# 2026-10-19 is a Monday
@pytest.mark.parametrize("spec, when, inside", [
    ("Mon..Fri 02:00-04:00", "2026-10-19 02:30", True),
    ("Mon..Fri 02:00-04:00", "2026-10-19 04:00", False),
    ("Mon..Fri 02:00-04:00", "2026-10-24 02:30", False),  # Saturday
    ("Sat,Sun 22:00-02:00", "2026-10-24 23:00", True),
    ("Sat,Sun 22:00-02:00", "2026-10-26 01:00", True),  # Monday 01:00 belongs to Sunday
    ("Sat,Sun 22:00-02:00", "2026-10-24 01:00", False),  # Saturday 01:00 belongs to Friday
    ("daily 00:00-24:00", "2026-10-21 13:37", True),
    ("Fri..Mon 03:00-04:00", "2026-10-26 03:15", True),  # wrapping day range
    ("Fri..Mon 03:00-04:00", "2026-10-21 03:15", False),
])
def test_windows(spec, when, inside):
    assert window.parse(spec).contains(datetime.fromisoformat(when)) is inside


@pytest.mark.parametrize("bad", ["Mon 2-4", "Funday 02:00-04:00", "Mon 25:00-26:00",
                                 "Mon 02:00-24:30", "02:00-04:00"])
def test_invalid_windows(bad):
    with pytest.raises(ValueError):
        window.parse(bad)


def test_in_any():
    now = datetime.fromisoformat("2026-10-19 03:00")
    assert window.in_any([], now) and window.in_any(None, now)
    assert window.in_any(["Sun 01:00-02:00", "Mon 02:00-04:00"], now)
    assert not window.in_any(["Sun 01:00-02:00"], now)


def test_window_in_config(make_config):
    from aptwarden.config import ConfigError
    with pytest.raises(ConfigError, match="maintenance window"):
        make_config(hosts=[{"name": "a", "policy": {"window": ["Mon 2-4"]}}])


# --- time zones ------------------------------------------------------------------

from datetime import UTC  # noqa: E402

ZH = "Europe/Zurich"


def utc(text):
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


@pytest.mark.parametrize("instant, inside", [
    ("2026-07-01 00:30", True),    # 02:30 CEST (UTC+2)
    ("2026-07-01 02:30", False),   # 04:30 CEST; the same instant as UTC wall time would be inside
    ("2026-01-15 01:30", True),    # 02:30 CET (UTC+1)
    ("2026-01-15 00:30", False),   # 01:30 CET
])
def test_window_in_time_zone(instant, inside):
    assert window.in_any(["daily 02:00-03:00"], utc(instant), ZH) is inside


def test_window_without_time_zone_uses_wall_time_as_given():
    assert window.in_any(["daily 02:00-03:00"], datetime(2026, 7, 1, 2, 30))
    assert window.in_any(["daily 02:00-03:00"], utc("2026-07-01 02:30"), None) is \
        window.parse("daily 02:00-03:00").contains(utc("2026-07-01 02:30").astimezone())


def test_window_spring_forward_skips_the_missing_hour():
    # 2026-03-29: clocks jump from 02:00 CET to 03:00 CEST, 02:00-03:00 does not exist
    instants = [utc(f"2026-03-29 {h:02d}:{m:02d}") for h in (0, 1) for m in (0, 15, 30, 45)]
    assert not any(window.in_any(["daily 02:00-03:00"], t, ZH) for t in instants)
    # a window around the jump is open only for its real part
    assert window.in_any(["daily 01:30-03:30"], utc("2026-03-29 00:45"), ZH)  # 01:45 CET
    assert window.in_any(["daily 01:30-03:30"], utc("2026-03-29 01:15"), ZH)  # 03:15 CEST


def test_window_fall_back_is_open_twice():
    # 2026-10-25: 02:00-03:00 happens twice, first CEST (00:xx UTC), then CET (01:xx UTC)
    assert window.in_any(["daily 02:00-03:00"], utc("2026-10-25 00:30"), ZH)
    assert window.in_any(["daily 02:00-03:00"], utc("2026-10-25 01:30"), ZH)
    assert not window.in_any(["daily 02:00-03:00"], utc("2026-10-25 02:30"), ZH)  # 03:30 CET


def test_window_past_midnight_in_time_zone():
    # Sun 23:00 - Mon 01:00 local; Monday 2026-11-02 00:30 CET = Sunday 23:30 UTC
    assert window.in_any(["Sun 23:00-01:00"], utc("2026-11-01 23:30"), ZH)
    assert not window.in_any(["Sun 23:00-01:00"], utc("2026-11-02 00:30"), ZH)  # 01:30 CET


def test_next_open():
    # Monday 2026-11-02 10:00 CET; next Mon..Fri 03:00 window is Tuesday 03:00 CET
    start, now_open = window.next_open(["Mon..Fri 03:00-04:00"], utc("2026-11-02 09:00"), ZH)
    assert not now_open and start.isoformat() == "2026-11-03T03:00:00+01:00"
    start, now_open = window.next_open(["daily 02:00-03:00"], utc("2026-07-01 00:30"), ZH)
    assert now_open
    assert window.next_open([], utc("2026-07-01 00:30"), ZH) is None
    # Friday evening: the next weekday window is Monday
    start, _ = window.next_open(["Mon..Fri 03:00-04:00"], utc("2026-11-06 20:00"), ZH)
    assert start.strftime("%a %H:%M %Z") == "Mon 03:00 CET"
    # a start inside the skipped spring hour moves to the real instant
    start, _ = window.next_open(["Sun 02:30-03:30"], utc("2026-03-28 12:00"), ZH)
    assert start.isoformat() == "2026-03-29T03:30:00+02:00"


def test_next_start():
    # Monday 2026-11-02 10:00 CET: Tuesday 03:00 CET
    start = window.next_start(["Mon..Fri 03:00-04:00"], utc("2026-11-02 09:00"), ZH)
    assert start.isoformat() == "2026-11-03T03:00:00+01:00"
    # inside a window, the next start is the following one, not now
    start = window.next_start(["daily 02:00-03:00"], utc("2026-07-01 00:30"), ZH)
    assert start.isoformat() == "2026-07-02T02:00:00+02:00"
    # summer time now, winter time at the start (2026-10-25 changes back)
    start = window.next_start(["Sun 03:00-04:00"], utc("2026-10-24 12:00"), ZH)
    assert start.strftime("%Y-%m-%d %H:%M %Z") == "2026-10-25 03:00 CET"
    # the earliest of several windows
    start = window.next_start(["Sat 03:00-05:00", "Tue,Thu 22:00-23:00"],
                              utc("2026-11-02 09:00"), ZH)
    assert start.isoformat() == "2026-11-03T22:00:00+01:00"
    assert window.next_start([], utc("2026-07-01 00:30"), ZH) is None


def test_time_zone_in_config(make_config):
    from aptwarden.config import ConfigError

    cfg = make_config(policy={"timezone": ZH}, hosts=[{"name": "a"},
                                                     {"name": "b", "policy": {"timezone": "UTC"}}])
    assert [h.policy["timezone"] for h in cfg.hosts] == [ZH, "UTC"]
    with pytest.raises(ConfigError, match="unknown time zone"):
        make_config(hosts=[{"name": "a", "policy": {"timezone": "Europe/Zuerich"}}])


def test_runner_uses_host_time_zone(make_config):
    from aptwarden.runner import Runner

    cfg = make_config(hosts=[{"name": "a", "policy": {"modes": ["patch"], "timezone": ZH,
                                                       "window": ["daily 02:00-03:00"]}}])
    r = Runner(cfg)
    eligible, _ = r._eligible(cfg.hosts, False, False, utc("2026-07-01 00:30"))  # 02:30 CEST
    assert [h.name for h in eligible] == ["a"]
    _, skipped = r._eligible(cfg.hosts, False, False, utc("2026-07-01 02:30"))   # 04:30 CEST
    assert skipped == [("a", "outside the maintenance window")]
    r.close()


BLOCK_CURL = {"id": "AW-2026-0009", "summary": "broken curl update", "severity": "high",
              "package": "curl", "action": "block",
              "affected": [{"release": "trixie", "ranges": [{"introduced": "8.1-2",
                                                             "fixed": "8.1-3"}]}]}


def fixable(vid, source, severity, fixed="2", **kw):
    return Finding(vid, source, "1", FindingStatus.FIXABLE, fixed_version=fixed,
                   binaries=[source], severity=severity, **kw)


def test_preview_filters_like_the_planner():
    findings = [
        fixable("CVE-1", "openssl", Severity.CRITICAL),
        fixable("CVE-2", "openssl", Severity.HIGH),
        fixable("CVE-3", "tar", Severity.MEDIUM),                    # below the policy
        fixable("CVE-4", "sudo", Severity.LOW, kev=True),            # KEV: always
        fixable("CVE-5", "bash", Severity.CRITICAL, action="report"),  # restricted
        fixable("CVE-6", "curl", Severity.HIGH, fixed="8.1-2"),      # fix blocked
        Finding("CVE-7", "vim", "1", FindingStatus.NO_FIX, severity=Severity.CRITICAL),
    ]
    policy = {"auto_patch_severities": ["critical", "high"], "auto_patch_kev": True}
    items = preview(findings, policy, [Definition.from_dict(BLOCK_CURL)], "trixie")
    assert [(i.source_package, i.skipped) for i in items] == [
        ("openssl", None), ("curl", "fixed version 8.1-2 is blocked by AW-2026-0009"),
        ("sudo", None)]
    assert items[0].vulns == ["CVE-1", "CVE-2"]
    # the block applies to its release only
    items = preview(findings, policy, [Definition.from_dict(BLOCK_CURL)], "bookworm")
    assert not any(i.skipped for i in items)
