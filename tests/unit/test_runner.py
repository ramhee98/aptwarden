import json

import pytest

from aptwarden import cli
from aptwarden.models import FindingStatus
from aptwarden.runner import Runner
from aptwarden.sources import debian_tracker
from aptwarden.transport import TransportError
from tests.conftest import (
    FakeFactory,
    FakeHttp,
    FakeTransport,
    Response,
    debian_host_commands,
    fixture_json,
    json_response,
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


def test_report_without_any_data_fails(setup):
    cfg, http, factory = setup
    http.routes[("GET", TRACKER)] = Response(500)
    runner = Runner(cfg, http=http, transports=factory)
    run = runner.report(cfg.select_hosts(["web01"]))
    assert run.status == "failed"
    assert not run.data_available
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
    kinds = [m.kind for m in notifier.sent]
    assert kinds == ["alert", "summary"]
    assert "CVE-2026-24061" in notifier.sent[0].body  # KEV

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
