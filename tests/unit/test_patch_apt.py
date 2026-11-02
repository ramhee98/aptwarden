from datetime import datetime

import pytest

from aptwarden.patch import apt, window
from aptwarden.patch.planner import parse_show

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
