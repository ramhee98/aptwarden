import dataclasses

from aptwarden import config, pins
from aptwarden.definitions import Definition
from aptwarden.inventory import collect
from aptwarden.patch.runner import HELPER_VERSION
from tests.conftest import FakeTransport, debian_host_commands

# xz-utils 5.8.1-1 is installed (see dpkg-query-trixie.txt)
BLOCK_XZ = {"id": "AW-2026-0001", "summary": "backdoored xz", "severity": "critical",
            "package": "xz-utils", "action": "block",
            "affected": [{"release": "trixie", "ranges": [{"introduced": "5.8.1-2",
                                                           "fixed": "5.8.1-4"}]}]}

SHOW = """\
Package: xz-utils
Version: 5.8.1-1
Architecture: amd64

Package: xz-utils
Version: 5.8.1-2
Architecture: amd64

Package: liblzma5
Source: xz-utils (5.8.1-3)
Version: 5.8.1-3+b1
Architecture: amd64

Package: liblzma5
Source: xz-utils
Version: 5.8.1-4
Architecture: amd64

Package: liblzma5
Source: xz-utils
Version: 5.8.1-1
Architecture: amd64
"""

PIN_CAT = ("cat", pins.PIN_FILE)
SHOW_CMD = ("apt-cache", "show", "--", "liblzma5", "xz-utils")
VERSION_CMD = ("sudo", "-n", "/usr/local/lib/aptwarden/aptwarden-helper", "version")
PIN_CMD = ("sudo", "-n", "/usr/local/lib/aptwarden/aptwarden-helper", "pin")
WANTED = ["liblzma5=5.8.1-3+b1", "xz-utils=5.8.1-2"]


def host(enforce="pin"):
    cfg = config.from_dict({"hosts": [{"name": "web01", "policy": {"enforce_block": enforce}}]})
    return cfg.hosts[0]


def transport(pin_file=None, helper=f"aptwarden-helper {HELPER_VERSION}\n", pin_rc=0):
    cmds = debian_host_commands()
    cmds[PIN_CAT] = (0, pin_file, "") if pin_file is not None else (
        1, "", f"cat: {pins.PIN_FILE}: No such file or directory")
    cmds[SHOW_CMD] = (0, SHOW, "")
    cmds[VERSION_CMD] = (0, helper, "")
    for args in ([], WANTED):
        cmds[PIN_CMD + tuple(args)] = (pin_rc, "", "aptwarden-helper: boom" if pin_rc else "")
    return FakeTransport("web01", cmds)


def pin_file(*pairs):
    return "".join(f"Explanation: aptwarden\nPackage: {p}\nPin: version {v}\n"
                   f"Pin-Priority: -1\n\n" for p, v in pairs)


def sudo_calls(t):
    return [c[3:] for c in t.calls if c[0] == "sudo"]


def run(t, h=None, definitions=None):
    inv = collect(t)
    t.calls.clear()
    defs = [Definition.from_dict(BLOCK_XZ)] if definitions is None else definitions
    return pins.enforce(t, h or host(), inv, defs)


def test_wanted_pins_blocked_source_versions_except_the_installed():
    inv = collect(transport())
    blocks = pins.blocking([Definition.from_dict(BLOCK_XZ)])
    # 5.8.1-3+b1 is a binNMU of source 5.8.1-3; 5.8.1-4 is fixed; 5.8.1-1 is installed
    assert pins.wanted(inv, blocks, SHOW) == {("xz-utils", "5.8.1-2"): "AW-2026-0001",
                                              ("liblzma5", "5.8.1-3+b1"): "AW-2026-0001"}
    other_release = dataclasses.replace(inv, codename="bookworm")
    assert pins.wanted(other_release, blocks, SHOW) == {}


def test_blocking_ignores_expired_and_other_actions():
    expired = Definition.from_dict({**BLOCK_XZ, "expires": "2020-01-01"})
    report = Definition.from_dict({**BLOCK_XZ, "action": "report"})
    assert pins.blocking([expired, report]) == {}


def test_parse_pin_file():
    assert pins.parse_pin_file(pin_file(("xz-utils", "5.8.1-2"), ("liblzma5", "5.8.1-3+b1"))) \
        == {("xz-utils", "5.8.1-2"), ("liblzma5", "5.8.1-3+b1")}
    assert pins.parse_pin_file("") == set()


def test_enforce_writes_pins_once():
    t = transport()
    result = run(t)
    assert result.changed and not result.error
    assert sudo_calls(t) == [["version"], ["pin", *WANTED]]
    assert result.notes() == ["blocked versions pinned away: liblzma5 5.8.1-3+b1, "
                              "xz-utils 5.8.1-2 (AW-2026-0001)"]
    # the next scan finds them in place and needs no sudo
    t = transport(pin_file(("xz-utils", "5.8.1-2"), ("liblzma5", "5.8.1-3+b1")))
    result = run(t)
    assert not result.changed and sudo_calls(t) == []
    assert result.notes()  # still reported while they are active


def test_enforce_without_blocks_needs_no_helper():
    t = transport(helper="")
    result = run(t, definitions=[])
    assert result.notes() == [] and sudo_calls(t) == []
    assert not any(c[0] == "apt-cache" for c in t.calls)


def test_enforce_removes_pins_no_longer_wanted():
    # the definition expired, or the host went back to enforce_block: alert
    for h, defs in ((host(), []), (host("alert"), None)):
        t = transport(pin_file(("xz-utils", "5.8.1-2")))
        result = run(t, h, defs)
        assert result.changed and sudo_calls(t) == [["version"], ["pin"]]
        assert result.notes() == []


def test_enforce_reports_helper_problems():
    result = run(transport(helper="aptwarden-helper 3\n"))
    assert not result.changed
    [note] = result.notes()
    assert note.startswith(
        "enforce_block: pin failed, blocked versions are NOT pinned away: outdated helper "
        f"(aptwarden-helper 3, expected version {HELPER_VERSION})")

    result = run(transport(pin_rc=2))
    assert result.error == "helper pin exited 2: aptwarden-helper: boom"


def test_reports_enforce_pins_and_dry_runs_do_not(make_config, monkeypatch):
    import json

    from aptwarden.runner import Runner
    from aptwarden.sources import debian_tracker
    from tests.conftest import FakeFactory, FakeHttp, Response, fixture_json

    monkeypatch.setattr(debian_tracker, "MIN_SOURCE_PACKAGES", 1)
    cfg = make_config(hosts=[{"name": "web01", "policy": {
                          "enforce_block": "pin", "modes": ["dry-run"]}}],
                      sources={"osv": {"enabled": False}},
                      enrich={"cvss": {"enabled": False}, "kev": {"enabled": False}})
    tracker = json.dumps(fixture_json("tracker-trixie-subset.json.gz")).encode()
    http = FakeHttp({("GET", "https://security-tracker.debian.org/tracker/data/json"):
                     Response(200, tracker)})
    t = transport()
    monkeypatch.setattr(Runner, "definitions", lambda self: [Definition.from_dict(BLOCK_XZ)])
    runner = Runner(cfg, http=http, transports=FakeFactory({"web01": t}))
    try:
        run = runner.patch(cfg.hosts, dry_run=True, notify=False)
        assert run.hosts and sudo_calls(t) == []  # a dry run changes nothing

        [web] = runner.report(cfg.hosts, notify=False).hosts
        assert sudo_calls(t) == [["version"], ["pin", *WANTED]]
        assert ("blocked versions pinned away: liblzma5 5.8.1-3+b1, xz-utils 5.8.1-2 "
                "(AW-2026-0001)") in web.warnings
    finally:
        runner.close()
