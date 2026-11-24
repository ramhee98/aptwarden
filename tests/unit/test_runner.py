import json

import pytest

from aptwarden import cli
from aptwarden.models import FindingStatus
from aptwarden.runner import Runner
from aptwarden.sources import debian_tracker
from aptwarden.sources.osv import OsvSource
from aptwarden.transport import TransportError
from tests.conftest import (
    FakeFactory,
    FakeHttp,
    FakeTransport,
    Response,
    debian_host_commands,
    fixture_json,
    json_response,
    ubuntu_host_commands,
)

TRACKER = "https://security-tracker.debian.org/tracker/data/json"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV = "https://api.osv.dev"


class Unreachable(FakeTransport):
    def run(self, argv, timeout=None):
        raise TransportError("ssh 192.0.2.20: Connection timed out")


@pytest.fixture
def setup(make_config, monkeypatch):
    monkeypatch.setattr(debian_tracker, "MIN_SOURCE_PACKAGES", 1)
    cfg = make_config(
        hosts=[{"name": "web01", "address": "192.0.2.10"},
               {"name": "db01", "address": "192.0.2.20"}],
        sources={"osv": {"enabled": False}},
        enrich={"cvss": {"enabled": False}},
    )
    tracker = json.dumps(fixture_json("tracker-trixie-subset.json.gz")).encode()
    http = FakeHttp({
        ("GET", TRACKER): Response(200, tracker),
        ("GET", KEV): json_response({"vulnerabilities": [
            {"cveID": "CVE-2026-24061", "dateAdded": "2026-01-27"}]}),
    })
    factory = FakeFactory({"web01": FakeTransport("web01", debian_host_commands()),
                           "db01": Unreachable("db01", {})})
    return cfg, http, factory


def test_report_end_to_end(setup):
    cfg, http, factory = setup
    runner = Runner(cfg, http=http, transports=factory)
    run = runner.report(cfg.hosts)
    assert run.status == "partial"  # db01 unreachable
    web, db = run.hosts
    assert not db.ok and "timed out" in db.error
    fixable = [f for f in web.findings if f.status == FindingStatus.FIXABLE]
    assert len({f.source_package for f in fixable}) == 28
    kev = [f for f in fixable if f.kev]
    assert {f.vuln_id for f in kev} == {"CVE-2026-24061"}
    assert all(f.first_seen for f in web.findings)
    assert factory.transports["web01"].closed

    # persisted and readable without scanning
    latest = runner.state.latest("web01")
    assert latest.run_id == run.run_id
    assert len(latest.findings) == len(web.findings)
    assert runner.state.run_info(run.run_id)["status"] == "partial"
    runner.close()


def test_report_flags_fixes_from_missing_sources(setup, capsys):
    from aptwarden import report
    from aptwarden.models import Severity

    cfg, http, factory = setup
    factory.transports["web01"] = FakeTransport(
        "web01", debian_host_commands(apt_suites=("trixie", "trixie-updates")))
    runner = Runner(cfg, http=http, transports=factory)
    [web] = runner.report(cfg.select_hosts(["web01"])).hosts
    fixable = [f for f in web.findings if f.status == FindingStatus.FIXABLE]
    missing = [f for f in fixable if f.missing_source]
    # still counted as fixable, but flagged: the fixes are only in trixie-security
    assert len({f.source_package for f in fixable}) == 28
    assert missing and {f.missing_source for f in missing} == {"trixie-security"}
    packages = len({f.source_package for f in missing})
    assert (f"apt sources lack trixie-security: {len(missing)} fixable vulnerabilities in "
            f"{packages} packages cannot be installed until it is added") in web.warnings
    # stored, so the status page and later reports see it
    stored = runner.state.latest("web01")
    assert sum(1 for f in stored.findings if f.missing_source) == len(missing)
    text = report.render_text([web], [], min_severity=Severity.UNKNOWN)
    assert "(needs trixie-security)" in text
    runner.close()


def test_report_with_security_source_flags_nothing(setup):
    cfg, http, factory = setup
    runner = Runner(cfg, http=http, transports=factory)
    [web] = runner.report(cfg.select_hosts(["web01"])).hosts
    assert not any(f.missing_source for f in web.findings)
    assert not any("apt sources lack" in w for w in web.warnings)
    runner.close()


def test_report_without_any_data_fails(setup):
    cfg, http, factory = setup
    http.routes[("GET", TRACKER)] = Response(500)
    runner = Runner(cfg, http=http, transports=factory)
    run = runner.report(cfg.select_hosts(["web01"]))
    assert run.status == "failed"
    assert not run.data_available
    runner.close()


def test_report_fails_hosts_no_source_covers(setup):
    # Without data a host would show 0 findings and look clean.
    cfg, http, factory = setup
    factory.transports["db01"] = FakeTransport("db01", ubuntu_host_commands())
    runner = Runner(cfg, http=http, transports=factory)
    run = runner.report(cfg.hosts)
    web, db = run.hosts
    assert web.ok and web.findings
    assert not db.ok
    assert db.error == "no vulnerability source covers Ubuntu 24.04 LTS (noble)"
    assert run.status == "partial"
    runner.close()


def test_report_fails_ubuntu_hosts_when_osv_fails(setup, make_config):
    # OSV is the only source for Ubuntu: a failed query must not leave them looking clean
    _, http, factory = setup
    cfg = make_config(hosts=[{"name": "web01", "address": "192.0.2.10"},
                             {"name": "db01", "address": "192.0.2.20"}],
                      sources={"osv": {"enabled": True, "url": OSV}},
                      enrich={"cvss": {"enabled": False}})
    http.routes[("POST", f"{OSV}/v1/querybatch")] = Response(503)
    factory.transports["db01"] = FakeTransport("db01", ubuntu_host_commands())
    runner = Runner(cfg, http=http, transports=factory)
    run = runner.report(cfg.hosts)
    web, db = run.hosts
    assert web.ok and web.findings  # the Debian tracker still covers it
    assert not db.ok
    assert db.error.startswith("no vulnerability data for Ubuntu 24.04 LTS (noble): osv: "
                               "query failed")
    assert run.status == "partial"
    runner.close()


def test_report_keeps_ubuntu_pro_markers(setup, make_config):
    # the Debian tracker's missing-source check must not touch Ubuntu hosts
    _, http, factory = setup
    cfg = make_config(hosts=[{"name": "web01", "address": "192.0.2.10"},
                             {"name": "db01", "address": "192.0.2.20"}],
                      sources={"osv": {"enabled": True, "url": OSV}},
                      enrich={"cvss": {"enabled": False}})
    pro = "Ubuntu:Pro:24.04:LTS"
    record = {"id": "UBUNTU-CVE-2026-50", "modified": "2026-01-01T00:00:00Z",
              "affected": [{"package": {"name": "openssl", "ecosystem": pro,
                                        "purl": "pkg:deb/ubuntu/openssl?distro=esm-apps%2Fnoble"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [
                                {"introduced": "0"}, {"fixed": "3.5.1-1+deb13u1+esm1"}]}]}]}

    def route(headers, data):
        return json_response({"results": [
            {"vulns": [{"id": record["id"], "modified": record["modified"]}]}
            if q["package"] == {"ecosystem": pro, "name": "openssl"} else {}
            for q in json.loads(data)["queries"]]})

    http.routes[("POST", f"{OSV}/v1/querybatch")] = route
    http.routes[("GET", f"{OSV}/v1/vulns/UBUNTU-CVE-2026-50")] = json_response(record)
    factory.transports["db01"] = FakeTransport("db01", ubuntu_host_commands())
    runner = Runner(cfg, http=http, transports=factory)
    _, db = runner.report(cfg.hosts).hosts
    [f] = [f for f in db.findings if f.vuln_id == "CVE-2026-50"]
    assert f.missing_source == "noble-apps-security (Ubuntu Pro)"
    assert any(w.startswith("apt sources lack noble-apps-security (Ubuntu Pro): 1 fixable")
               for w in db.warnings)
    runner.close()


def test_osv_covers_ubuntu_only_online(setup):
    # OSV covers hosts with an ecosystem, but not in offline runs
    cfg, http, factory = setup
    runner = Runner(cfg, http=http, transports=factory)
    osv = OsvSource({"url": OSV}, runner.cache, http)
    runner.sources.append(osv)
    debian = runner.collect([cfg.hosts[0]])["web01"]
    assert runner.covering_sources(debian) == ["osv"]  # tracker cache still empty
    runner.offline = True
    assert runner.covering_sources(debian) == []
    runner.close()


def test_osv_and_tracker_findings_are_merged(setup, make_config):
    cfg, http, factory = setup
    cfg = make_config(hosts=[{"name": "web01"}], enrich={"cvss": {"enabled": False}})
    rec = fixture_json("osv-DEBIAN-CVE-2025-11187.json")
    http.routes[("POST", f"{OSV}/v1/querybatch")] = lambda h, d: json_response({"results": [
        {"vulns": [{"id": rec["id"], "modified": "m"}]}
        if q["package"]["name"] == "openssl" else {}
        for q in json.loads(d)["queries"]]})
    http.routes[("GET", f"{OSV}/v1/vulns/{rec['id']}")] = json_response(rec)
    runner = Runner(cfg, http=http, transports=factory)
    run = runner.report(cfg.hosts)
    [f] = [f for f in run.hosts[0].findings if f.vuln_id == "CVE-2025-11187"]
    assert f.origins == ["debian_tracker", "osv"]
    assert "DEBIAN-CVE-2025-11187" in f.aliases
    runner.close()


def test_cli_report_status_and_exit_codes(setup, tmp_path, monkeypatch, capsys):
    cfg, http, factory = setup
    config_file = tmp_path / "config.yaml"
    config_file.write_text(json.dumps(cfg.raw))  # JSON is valid YAML
    monkeypatch.setattr("aptwarden.runner.HttpClient", lambda: http)
    monkeypatch.setattr("aptwarden.runner.TransportFactory", lambda: factory)

    assert cli.main(["-c", str(config_file), "-q", "report", "--host", "web01"]) == 0
    out = capsys.readouterr().out
    assert "fixable now:" in out and "inetutils" in out and "KEV" in out

    assert cli.main(["-c", str(config_file), "-q", "report"]) == 1  # db01 unreachable
    capsys.readouterr()

    assert cli.main(["-c", str(config_file), "status", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    web = next(h for h in doc["hosts"] if h["name"] == "web01")
    assert web["ok"] and web["counts"]["fixable"] > 0

    assert cli.main(["-c", str(config_file), "hosts", "check"]) == 1
    out = capsys.readouterr().out
    assert "web01" in out and "FAIL" in out
    assert "apt sources" not in out  # web01 has trixie-security

    factory.transports["web01"] = FakeTransport(
        "web01", debian_host_commands(apt_suites=("trixie",)))
    assert cli.main(["-c", str(config_file), "hosts", "check", "--host", "web01"]) == 0
    assert "apt sources lack trixie-security" in capsys.readouterr().out

    assert cli.main(["-c", str(tmp_path / "missing.yaml"), "status"]) == 2
    assert cli.main(["version"]) == 0


def test_cli_reports_unwritable_directories_cleanly(tmp_path, capsys):
    blocker = tmp_path / "file"
    blocker.write_text("")
    config_file = tmp_path / "config.yaml"
    config_file.write_text(f"cache_dir: {blocker}/cache\nhosts: [{{name: web01}}]\n")
    assert cli.main(["-c", str(config_file), "-q", "hosts", "check"]) == 1
    assert "aptwarden:" in capsys.readouterr().err


def test_changes_and_alerts_across_runs(setup):
    from aptwarden.notify import Message, Notifier

    class Collect(Notifier):
        name = "collect"

        def __init__(self):
            self.sent: list[Message] = []

        def send(self, msg):
            self.sent.append(msg)

    cfg, http, factory = setup
    notifier = Collect()
    hosts = cfg.select_hosts(["web01"])

    runner = Runner(cfg, http=http, transports=factory, notifiers=[notifier])
    run1 = runner.report(hosts)
    assert run1.changes["web01"].first_scan
    [msg] = notifier.sent  # alert and summary in one mail
    assert msg.kind == "alert" and "aptwarden summary" in msg.body
    assert "CVE-2026-24061" in msg.body  # KEV

    # openssl upgraded past every fix: its findings are resolved, nothing new
    from tests.conftest import fixture_text
    dpkg = fixture_text("dpkg-query-trixie.txt").replace("3.5.1-1+deb13u1", "9.9.9-1")
    factory.transports["web01"] = FakeTransport("web01", debian_host_commands(dpkg))
    notifier.sent.clear()
    run2 = runner.report(hosts)
    ch = run2.changes["web01"]
    assert not ch.first_scan and ch.new == []
    assert {f.source_package for f in ch.resolved} == {"openssl"}
    assert [m.kind for m in notifier.sent] == ["summary"]  # already alerted
    assert "Resolved since the last scan" in notifier.sent[0].body
    runner.close()


def test_failed_notification_makes_run_partial(setup):
    from aptwarden.notify import Notifier, NotifyError

    class Broken(Notifier):
        name = "broken"

        def send(self, msg):
            raise NotifyError("relay down")

    cfg, http, factory = setup
    runner = Runner(cfg, http=http, transports=factory, notifiers=[Broken()])
    run = runner.report(cfg.select_hosts(["web01"]))
    assert run.status == "partial"
    assert any("relay down" in n for n in run.notes)
    runner.close()


def test_cli_defs_validate_needs_no_config(tmp_path, capsys, monkeypatch):
    from tests.unit.test_definitions import VALID

    monkeypatch.setenv("APTWARDEN_CONFIG", str(tmp_path / "does-not-exist.yaml"))
    (tmp_path / "defs").mkdir()
    (tmp_path / "defs" / "AW-2026-0001.yaml").write_text(VALID)
    assert cli.main(["defs", "validate", str(tmp_path / "defs")]) == 0
    assert "1 valid definitions, 0 errors" in capsys.readouterr().out
    (tmp_path / "defs" / "AW-2026-0002.yaml").write_text(VALID)  # id/file name mismatch
    assert cli.main(["defs", "validate", str(tmp_path / "defs")]) == 1


def test_report_writes_status_page(setup):
    cfg, http, factory = setup
    runner = Runner(cfg, http=http, transports=factory)
    runner.report(cfg.select_hosts(["web01"]), notify=False)
    runner.close()
    page = (cfg.state_dir / "www" / "index.html").read_text()
    assert "CVE-2026-24061" in page and "web01" in page


def test_hosts_check_accept_new_only_for_unknown_hosts(setup, tmp_path, monkeypatch, capsys):
    cfg, http, factory = setup
    config_file = tmp_path / "config.yaml"
    config_file.write_text(json.dumps(cfg.raw))
    monkeypatch.setattr("aptwarden.runner.TransportFactory", lambda: factory)
    known = {"192.0.2.10": [], "192.0.2.20": ["SHA256:old (ED25519)"]}
    seen = {}
    monkeypatch.setattr("aptwarden.transport.known_host_keys",
                        lambda addr, port, f: known[addr])

    real_collect = Runner.collect

    def collect(self, hosts):
        seen.update({h.name: h.ssh.strict_host_key_checking for h in hosts})
        known["192.0.2.10"] = ["SHA256:new (ED25519)"]  # ssh recorded it
        return real_collect(self, hosts)

    monkeypatch.setattr(Runner, "collect", collect)
    cli.main(["-c", str(config_file), "-q", "hosts", "check", "--accept-new"])
    out = capsys.readouterr().out
    assert seen == {"web01": "accept-new", "db01": "yes"}  # known host stays strict
    assert "web01: new host key recorded: SHA256:new (ED25519)" in out
    assert "db01" not in out.split("new host key")[0].splitlines()[-1]


def test_hosts_check_ubuntu(setup, tmp_path, monkeypatch, capsys):
    cfg, http, factory = setup
    factory.transports["db01"] = FakeTransport("db01", ubuntu_host_commands())
    config_file = tmp_path / "config.yaml"
    config_file.write_text(json.dumps(cfg.raw))
    monkeypatch.setattr("aptwarden.runner.TransportFactory", lambda: factory)
    cli.main(["-c", str(config_file), "-q", "hosts", "check"])
    rows = {line.split()[0]: line for line in capsys.readouterr().out.splitlines()}
    assert "Ubuntu 24.04 LTS (noble)" in rows["db01"]
    assert "no vulnerability source covers this release" in rows["db01"]
    # no Debian tracker notes, and noble-security is found in the sources entries
    assert "tracker" not in rows["db01"] and "lack" not in rows["db01"]
    assert "Debian 13.1 (trixie)" in rows["web01"]


def test_ownership_guard(tmp_path, monkeypatch, capsys):
    from aptwarden.cli import ownership_problem

    owners = {tmp_path / "state": 999, tmp_path / "cache": 0}
    owner_of = owners.__getitem__
    msg = ownership_problem([tmp_path / "state", tmp_path / "cache"], 0, owner_of)
    assert "not root" in msg and "runuser -u" in msg
    # as the service user, or with root-owned directories: fine
    assert ownership_problem([tmp_path / "state"], 999, owner_of) is None
    assert ownership_problem([tmp_path / "cache"], 0, owner_of) is None
    # directories that do not exist yet are fine too
    assert ownership_problem([tmp_path / "missing"], 0) is None

    # wired into the CLI for commands that write state, not for read-only ones
    config_file = tmp_path / "config.yaml"
    config_file.write_text(f"state_dir: {tmp_path}/s\ncache_dir: {tmp_path}/c\n"
                           "hosts: [{name: web01}]\n")
    monkeypatch.setattr("aptwarden.cli.ownership_problem", lambda dirs, euid: "owned by aptwarden")
    assert cli.main(["-c", str(config_file), "status"]) == 2
    assert "owned by aptwarden" in capsys.readouterr().err
    assert cli.main(["-c", str(config_file), "config", "check"]) == 0


def test_hosts_check_names_the_time_zone(make_config, monkeypatch):
    class Down:
        def run(self, *a, **kw):
            raise TransportError("ssh: timed out")

        def close(self):
            pass

    class Factory:
        def create(self, host):
            return Down()

        def cleanup(self):
            pass

    monkeypatch.setattr("aptwarden.transport.TransportFactory", Factory)
    policy = {"modes": ["patch"], "window": ["Sat 02:00-03:00"],
              "allow_without_snapshot": True}
    cfg = make_config(hosts=[{"name": "web01", "policy": policy},
                             {"name": "ny01", "policy": {**policy,
                                                          "timezone": "America/New_York"}}])
    server, ny = (cli._patch_readiness(h, cfg) for h in cfg.hosts)
    # tests/conftest.py sets TZ=Asia/Kolkata
    assert any(n.endswith("(server local time, Asia/Kolkata)") for n in server), server
    assert any(n.endswith("(America/New_York)") for n in ny), ny


def test_hosts_check_names_a_wrong_guest(make_config, monkeypatch):
    from tests.unit.test_patch_runner import FakeProvider, ScriptedTransport, openssl_host

    h = openssl_host(macs=("bc:24:11:00:00:99",))
    monkeypatch.setattr(Runner, "provider", lambda self, host: FakeProvider(h))
    cfg = make_config(hosts=[{"name": "web01", "policy": {"modes": ["patch"]}}])
    assert cli._snapshot_readiness(cfg.hosts[0], cfg, ScriptedTransport(h)) == (
        "snapshot NOT ready: node/lxc/100 (web01) is not this host: none of its MAC "
        "addresses (bc:24:11:00:00:01) is on web01; check snapshot.vmid")
    h.macs = ("bc:24:11:00:00:01",)
    assert cli._snapshot_readiness(cfg.hosts[0], cfg, ScriptedTransport(h)) == "snapshot ok"


@pytest.mark.parametrize("modes, enforce, version, expected", [
    (["patch"], "alert", "4", "helper 4 ok"),
    # patching needs 3: ready, and the note says what the helper cannot do yet
    (["patch"], "alert", "3", "helper 3 ok (pin needs 4)"),
    (["dry-run"], "alert", "3", "helper 3 ok (pin needs 4)"),
    (["patch"], "pin", "3", "helper NOT ready: outdated helper (aptwarden-helper 3; "
                            "enforce_block: pin needs version 4 or newer): update it to version"),
    (["report"], "pin", "3", "helper NOT ready: outdated helper (aptwarden-helper 3; "
                             "enforce_block: pin needs version 4 or newer)"),
    (["patch"], "alert", "2", "helper NOT ready: outdated helper (aptwarden-helper 2; "
                              "patching needs version 3 or newer)"),
    (["patch"], "pin", "7", "helper 7 ok"),
])
def test_hosts_check_helper_note(make_config, modes, enforce, version, expected):
    cfg = make_config(hosts=[{"name": "web01",
                              "policy": {"modes": modes, "enforce_block": enforce}}])
    h = cfg.hosts[0]
    t = FakeTransport("web01", {("sudo", "-n", h.ssh.helper, "version"):
                                (0, f"aptwarden-helper {version}\n", "")})
    note = cli._helper_note(t, h)
    assert note.startswith(expected), note
    assert "see README" not in note
