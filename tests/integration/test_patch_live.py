"""Live patch tests against disposable Proxmox guests. NEVER point these at
production: every host must be listed in APTWARDEN_IT_VMIDS, and its guest's
hostname in Proxmox must equal the host name in the configuration.

Run where the configuration and the Proxmox token are readable, e.g. on a test
central host as the aptwarden user:

    APTWARDEN_IT_CONFIG=/etc/aptwarden/config.yaml APTWARDEN_IT_VMIDS=139,140 \\
        python3 -m pytest -m integration -o addopts= tests/integration/test_patch_live.py

The rollback test injects the failure itself: an HTTP healthcheck served by the
test turns unhealthy right after the real package installation and healthy
again once the real rollback ran. The host ends up rolled back, i.e. unchanged.
"""

import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aptwarden import config, inventory
from aptwarden.runner import Runner
from aptwarden.snapshot import SnapshotRef
from aptwarden.transport import Transport, TransportFactory

pytestmark = pytest.mark.integration

CONFIG = os.environ.get("APTWARDEN_IT_CONFIG")
VMIDS = {int(v) for v in os.environ.get("APTWARDEN_IT_VMIDS", "").split(",") if v.strip()}
if not CONFIG or not VMIDS:
    pytest.skip("APTWARDEN_IT_CONFIG and APTWARDEN_IT_VMIDS not set", allow_module_level=True)


@pytest.fixture
def cfg(tmp_path):
    base = config.load(CONFIG)
    raw = dict(base.raw)
    raw.update(state_dir=str(tmp_path / "state"), cache_dir=str(tmp_path / "cache"))
    raw["notify"] = {**raw["notify"], "email": {"enabled": False}}
    raw["enrich"] = {**raw["enrich"], "cvss": {**raw["enrich"]["cvss"],
                                               "nvd": {"enabled": False}}}
    raw["hosts"] = [h for h in raw["hosts"]
                    if (h.get("snapshot") or {}).get("vmid") in VMIDS]
    for h in raw["hosts"]:
        h["policy"] = {**h.get("policy", {}), "modes": ["report", "dry-run", "patch"]}
    if not raw["hosts"]:
        pytest.skip("no configured host matches APTWARDEN_IT_VMIDS")
    return config.from_dict(raw, base.path)


@pytest.fixture
def guarded(cfg):
    """Refuse to run unless Proxmox confirms each guest is the configured host."""
    runner = Runner(cfg)
    try:
        for h in cfg.hosts:
            guest = runner.provider(h).guest_config()
            assert guest.get("hostname") == h.name, (
                f"guard: VMID {h.snapshot['vmid']} is {guest.get('hostname')!r}, "
                f"not {h.name!r}")
    finally:
        runner.close()
    return cfg


def test_snapshot_roundtrip(guarded):
    runner = Runner(guarded)
    try:
        h = guarded.hosts[0]
        provider = runner.provider(h)
        assert provider.check() == []
        name = f"aptw_ittest_{secrets.token_hex(3)}"
        ref = provider.create(name, "aptwarden integration test")
        assert name in provider.list()
        provider.delete(ref)
        assert name not in provider.list()
    finally:
        runner.close()


def test_dry_run_changes_nothing(guarded):
    runner = Runner(guarded)
    try:
        run = runner.patch(guarded.hosts, dry_run=True, notify=False)
        for p in run.patches:
            assert p.status in ("dry-run", "nothing-to-do"), (p.host, p.status, p.reason)
            assert p.snapshot is None
        assert runner.state.snapshots(state=None) == []
    finally:
        runner.close()


class Health:
    healthy = True


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if Health.healthy else 503)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def health_url():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Health.healthy = True
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


class BreakingTransport(Transport):
    """Turns the injected healthcheck unhealthy after the real install."""

    def __init__(self, inner: Transport):
        super().__init__(inner.host)
        self.inner = inner

    def run(self, argv, timeout=None):
        result = self.inner.run(argv, timeout)
        if argv[:2] == ["sudo", "-n"] and len(argv) > 3 and argv[3] == "install":
            Health.healthy = False
        return result

    def close(self):
        self.inner.close()


class BreakingFactory:
    def __init__(self):
        self.inner = TransportFactory()

    def create(self, host):
        return BreakingTransport(self.inner.create(host))

    def cleanup(self):
        self.inner.cleanup()


class HealingRunner(Runner):
    def provider(self, host):
        provider = super().provider(host)
        rollback = provider.rollback

        def heal_after_rollback(ref: SnapshotRef):
            rollback(ref)
            Health.healthy = True

        provider.rollback = heal_after_rollback
        return provider


def installed_versions(host) -> dict[str, str]:
    factory = TransportFactory()
    try:
        with factory.create(host) as t:
            return {p.name: p.version for p in inventory.collect(t).packages}
    finally:
        factory.cleanup()


def test_failed_healthcheck_rolls_back(guarded, health_url):
    probe = Runner(guarded)
    try:
        dry = probe.patch(guarded.hosts, dry_run=True, notify=False)
    finally:
        probe.close()
    candidates = [p.host for p in dry.patches if p.status == "dry-run"]
    if not candidates:
        pytest.skip("no test host has anything to patch")
    [host] = guarded.select_hosts(candidates[:1])
    host.healthchecks = [{"http": health_url}]
    host.health = {"grace": 0, "retries": 2, "interval": "2s"}
    before = installed_versions(host)

    factory = BreakingFactory()
    runner = HealingRunner(guarded, transports=factory)
    try:
        run = runner.patch([host], ignore_window=True, notify=False)
        [result] = run.patches
        assert result.status == "rolled-back", (result.status, result.reason)
        assert "healthchecks failed" in result.reason
        assert result.health_after == [f"http {health_url}: ok (HTTP 200)"]
        assert installed_versions(host) == before
        [snap] = runner.state.snapshots(host.name, state=None)
        assert snap["state"] == "rolled-back"

        # the rolled-back snapshot is cleaned up once it is old enough
        runner.cfg.raw["snapshots"]["keep"] = 0
        assert runner.cleanup_snapshots([host]) == [f"{host.name}: deleted snapshot "
                                                    f"{snap['name']}"]
        assert snap["name"] not in runner.provider(host).list()
    finally:
        # never leave test snapshots behind, even when an assertion failed
        provider = Runner.provider(runner, host)
        for snap in runner.state.snapshots(host.name, state=("active", "rolled-back")):
            if snap["name"] in provider.list():
                provider.delete(SnapshotRef(snap["provider"], snap["target"], snap["name"]))
        factory.cleanup()
        runner.close()
