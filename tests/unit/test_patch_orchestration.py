import json
import shutil
import ssl
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aptwarden.notify import Message, Notifier, noteworthy_patches
from aptwarden.patch.runner import HostPatchResult, PatchRunner
from aptwarden.runner import Runner, RunReport, _PatchLock
from aptwarden.snapshot import SnapshotError, SnapshotRef, snapshot_name
from aptwarden.snapshot.proxmox import ProxmoxClient, ProxmoxSnapshots
from aptwarden.sources import SourceStatus
from aptwarden.state import HostRecord
from tests.unit.test_patch_runner import (
    FakeProvider,
    ScriptedTransport,
    finding,
    inventory,
    openssl_host,
)


def cfg_with(make_config, **policy):
    return make_config(hosts=[
        {"name": "web01", "policy": {"modes": ["patch"], **policy},
         "healthchecks": [{"systemd": "ssh.service"}],
         "health": {"grace": 0, "retries": 1, "interval": 0}},
        {"name": "db01", "policy": {"modes": ["report"]}},
        {"name": "dev01", "policy": {"modes": ["dry-run"]}},
    ], sources={"debian_tracker": {"enabled": False}, "osv": {"enabled": False}},
        enrich={"cvss": {"enabled": False}, "kev": {"enabled": False}})


def test_eligibility(make_config):
    cfg = cfg_with(make_config, window=["Mon..Fri 02:00-04:00"])
    runner = Runner(cfg)
    monday_3am = datetime(2026, 10, 19, 3, 0)
    eligible, skipped = runner._eligible(cfg.hosts, False, False, monday_3am)
    assert [h.name for h in eligible] == ["web01"]
    assert dict(skipped) == {"db01": "patching not enabled for this host (policy.modes)",
                             "dev01": "patching not enabled for this host (policy.modes)"}
    _, skipped = runner._eligible(cfg.hosts, False, False, datetime(2026, 10, 19, 12, 0))
    assert dict(skipped)["web01"] == "outside the maintenance window"
    eligible, _ = runner._eligible(cfg.hosts, False, True, datetime(2026, 10, 19, 12, 0))
    assert [h.name for h in eligible] == ["web01"]  # --ignore-window
    eligible, skipped = runner._eligible(cfg.hosts, True, False, datetime(2026, 10, 19, 12, 0))
    assert [h.name for h in eligible] == ["web01", "dev01"]  # dry runs ignore the window
    runner.close()


def test_patch_run_end_to_end(make_config, monkeypatch):
    cfg = cfg_with(make_config)
    h = openssl_host()
    provider = FakeProvider(h)
    sent = []

    class Collect(Notifier):
        name = "collect"

        def send(self, msg: Message):
            sent.append(msg)

    class Factory:
        def create(self, host):
            return ScriptedTransport(h)

        def cleanup(self):
            pass

    runner = Runner(cfg, transports=Factory(), providers=lambda host: provider,
                    notifiers=[Collect()],
                    patch_runner=PatchRunner(None, [], sleep=lambda s: None))
    runner._patch_runner.state = runner.state

    def fake_report(run, hosts, force):
        run.sources = [SourceStatus("debian_tracker")]
        for host in hosts:
            run.hosts.append(HostRecord(run.run_id, host.name, "192.0.2.10", True, None, {},
                                        [], "now", [finding()]))
            run.inventories[host.name] = inventory(h)
        run.status = "ok"

    monkeypatch.setattr(runner, "_report", fake_report)
    run = runner.patch(cfg.hosts, ignore_window=True)
    by_host = {p.host: p for p in run.patches}
    assert by_host["web01"].status == "patched"
    assert by_host["db01"].status == "skipped"
    assert run.status == "ok"
    # the scan part alerts the new critical finding once, then the patch summary
    assert [m.kind for m in sent] == ["alert", "summary"]
    assert "critical/KEV/blocked" in sent[0].subject
    assert "web01: patched" in sent[1].body and "openssl 3.5.1-1 -> 3.5.7-1" in sent[1].body

    # second run: nothing left, nothing to report
    sent.clear()
    h.candidates = dict(h.installed)
    run = runner.patch(cfg.hosts, ignore_window=True)
    assert {p.host: p.status for p in run.patches}["web01"] == "nothing-to-do"
    assert sent == []

    # a failed patch is an alert and marks the run partial
    h.installed = {"openssl": "3.5.1-1", "libssl3t64:amd64": "3.5.1-1"}
    h.candidates = {"openssl": "3.5.7-1", "libssl3t64:amd64": "3.5.7-1"}
    h.healthy_after_install = False
    sent.clear()
    run = runner.patch(cfg.hosts, ignore_window=True)
    assert {p.host: p.status for p in run.patches}["web01"] == "rolled-back"
    assert run.status == "partial"
    assert [m.kind for m in sent] == ["alert", "summary"]
    assert "patching: web01 rolled-back" in sent[0].subject
    assert "CVE-2026-1" not in sent[0].subject  # the finding itself was alerted before
    runner.close()


def test_noteworthy_patches_suppress_repeated_aborts():
    run = RunReport("r", "patch", "now")
    run.patches = [HostPatchResult("a", "r", status="aborted", repeated=True),
                   HostPatchResult("b", "r", status="aborted", repeated=False),
                   HostPatchResult("c", "r", status="nothing-to-do"),
                   HostPatchResult("d", "r", status="patched")]
    assert [p.host for p in noteworthy_patches(run)] == ["b", "d"]


def test_patch_lock(tmp_path):
    lock = _PatchLock(tmp_path / "patch.lock")
    with pytest.raises(RuntimeError, match="another patch run"):
        _PatchLock(tmp_path / "patch.lock")
    lock.release()
    _PatchLock(tmp_path / "patch.lock").release()


def test_snapshot_cleanup(make_config):
    cfg = cfg_with(make_config)
    h = openssl_host()
    provider = FakeProvider(h)
    runner = Runner(cfg, providers=lambda host: provider)
    st = runner.state
    for name in ("aptw_old", "aptw_new", "aptw_gone", "aptw_rolled"):
        st.add_snapshot("fake", "node/lxc/100", name, "web01", "r")
    st.set_snapshot_state("fake", "node/lxc/100", "aptw_rolled", "rolled-back")
    provider.snaps = {"aptw_old": {}, "aptw_new": {}, "aptw_rolled": {}}
    st.db.execute("UPDATE snapshots SET created_at = ? WHERE name IN ('aptw_old', 'aptw_rolled')",
                  ((datetime.now(UTC) - timedelta(days=8)).isoformat(),))
    st.db.commit()
    web = cfg.select_hosts(["web01"])

    assert sorted(runner.cleanup_snapshots(web, dry_run=True)) == [
        "web01: would delete snapshot aptw_old", "web01: would delete snapshot aptw_rolled"]
    assert "aptw_old" in provider.snaps
    assert sorted(runner.cleanup_snapshots(web)) == [
        "web01: deleted snapshot aptw_old", "web01: deleted snapshot aptw_rolled"]
    states = {s["name"]: s["state"] for s in st.snapshots("web01", state=None)}
    assert states == {"aptw_old": "deleted", "aptw_new": "active", "aptw_gone": "gone",
                      "aptw_rolled": "deleted"}

    # a snapshot needed for a manual rollback survives its age
    st.add_snapshot("fake", "node/lxc/100", "aptw_keep", "web01", "r2")
    provider.snaps["aptw_keep"] = {}
    st.db.execute("UPDATE snapshots SET created_at = '2020-01-01T00:00:00+00:00' "
                  "WHERE name = 'aptw_keep'")
    st.save_patch("r2", "web01", "needs-manual-rollback", "2026-10-22T00:00:00+00:00", {
        "status": "needs-manual-rollback",
        "snapshot": {"provider": "fake", "target": "node/lxc/100", "name": "aptw_keep"}})
    assert runner.cleanup_snapshots(web) == []
    runner.close()


def test_snapshot_name():
    assert snapshot_name("20261022T161054Z-9d0d") == "aptw_20261022T161054Z_9d0d"
    assert len(snapshot_name("x" * 100)) == 40


# --- Proxmox --------------------------------------------------------------------

class FakeApi:
    def __init__(self):
        self.calls = []
        self.feature = 1

    def request(self, method, path, params=None):
        self.calls.append((method, path, params))
        if path.endswith("/feature"):
            return {"hasFeature": self.feature}
        if path.endswith("/snapshot") and method == "GET":
            return [{"name": "current"}, {"name": "aptw_x"}, {"name": "manual"}]
        return "UPID:R720:1:2:3:vzsnapshot:139:aptwarden@pam!t:"

    def wait_task(self, node, upid, timeout=None):
        self.calls.append(("WAIT", upid, None))


def test_proxmox_provider_calls():
    api = FakeApi()
    p = ProxmoxSnapshots(api, "R720", "lxc", 139)
    assert p.check() == []
    api.feature = 0
    assert "snapshots not supported" in p.check()[0]
    ref = p.create("aptw_1", "test")
    assert ref == SnapshotRef("proxmox", "R720/lxc/139", "aptw_1")
    assert api.calls[2] == ("POST", "/nodes/R720/lxc/139/snapshot",
                            {"snapname": "aptw_1", "description": "test"})
    p.rollback(ref)
    assert ("POST", "/nodes/R720/lxc/139/snapshot/aptw_1/rollback", {"start": 1}) in api.calls
    p.delete(ref)
    assert ("DELETE", "/nodes/R720/lxc/139/snapshot/aptw_1", None) in api.calls
    assert p.list() == ["aptw_x", "manual"]
    # never touches foreign snapshots or other guests
    with pytest.raises(SnapshotError):
        p.delete(SnapshotRef("proxmox", "R720/lxc/139", "manual"))
    with pytest.raises(SnapshotError):
        p.rollback(SnapshotRef("proxmox", "R720/lxc/138", "aptw_1"))
    q = ProxmoxSnapshots(FakeApi(), "R720", "qemu", 200, vmstate=True)
    q.create("aptw_2", "vm")
    assert q.client.calls[0][2]["vmstate"] == 1


@pytest.fixture
def tls_server(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=pve", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    fp = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint",
                         "-sha256"], check=True, capture_output=True, text=True
                        ).stdout.strip().split("=", 1)[1]
    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["auth"] = self.headers.get("Authorization")
            body = json.dumps({"data": {"version": "9.2.11"}}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{server.server_address[1]}", fp, seen
    server.shutdown()


def test_proxmox_client_pins_certificate(tls_server, tmp_path):
    url, fp, seen = tls_server
    (tmp_path / "token").write_text("00000000-1111-2222-3333-444444444444\n")
    settings = {"url": url, "token_id": "aptwarden@pam!t", "token_file": "token",
                "tls_fingerprint": fp}
    client = ProxmoxClient(settings, tmp_path)
    assert client.request("GET", "/version") == {"version": "9.2.11"}
    assert seen["auth"] == "PVEAPIToken=aptwarden@pam!t=00000000-1111-2222-3333-444444444444"
    wrong = ProxmoxClient({**settings, "tls_fingerprint": "AA:" * 31 + "AA"}, tmp_path)
    with pytest.raises(SnapshotError, match="fingerprint mismatch"):
        wrong.request("GET", "/version")
    unpinned = ProxmoxClient({**settings, "tls_fingerprint": None}, tmp_path)
    with pytest.raises(SnapshotError, match="CERTIFICATE_VERIFY_FAILED"):
        unpinned.request("GET", "/version")  # self-signed, no CA, no pin: refused


def test_cli_severity_override_maps_and_leaves_config_alone(make_config, tmp_path, monkeypatch):
    import json

    from aptwarden import cli

    cfg = cfg_with(make_config)
    config_file = tmp_path / "config.yaml"
    config_file.write_text(json.dumps(cfg.raw))
    seen = []

    def fake_patch(self, hosts, **kw):
        seen.append(kw["severities"])
        return RunReport("r", "patch", "now", status="ok")

    monkeypatch.setattr(Runner, "patch", fake_patch)
    base = ["-c", str(config_file), "-q", "patch", "--host", "web01"]
    assert cli.main(base) == 0
    assert cli.main(base + ["--min-severity", "medium"]) == 0
    assert cli.main(base + ["--all-severities"]) == 0
    assert seen == [None, ["critical", "high", "medium"],
                    ["critical", "high", "medium", "low", "unknown"]]
    with pytest.raises(SystemExit):
        cli.main(base + ["--all-severities", "--min-severity", "low"])


def test_runner_override_is_per_run(make_config, monkeypatch):
    cfg = cfg_with(make_config)
    h = openssl_host()
    seen = []

    class Factory:
        def create(self, host):
            return ScriptedTransport(h)

        def cleanup(self):
            pass

    class Capture(PatchRunner):
        def run(self, host, *a, **kw):
            seen.append(dict(host.policy))
            return HostPatchResult(host.name, "r", status="nothing-to-do")

    runner = Runner(cfg, transports=Factory(), providers=lambda host: FakeProvider(h),
                    patch_runner=Capture(None, []))

    def fake_report(run, hosts, force):
        run.sources = [SourceStatus("debian_tracker")]
        for host in hosts:
            run.hosts.append(HostRecord(run.run_id, host.name, "x", True, None, {}, [], "now", []))
            run.inventories[host.name] = inventory(h)
        run.status = "ok"

    monkeypatch.setattr(runner, "_report", fake_report)
    run = runner.patch(cfg.select_hosts(["web01"]), ignore_window=True, notify=False,
                       severities=["critical", "high", "medium", "low", "unknown"])
    assert seen[0]["auto_patch_severities"][-1] == "unknown" and seen[0]["severity_override"]
    assert "manual severity override for this run" in run.notes[0]
    # the configuration itself is untouched
    assert cfg.select_hosts(["web01"])[0].policy["auto_patch_severities"] == ["critical", "high"]
    assert "severity_override" not in cfg.select_hosts(["web01"])[0].policy
    runner.close()
