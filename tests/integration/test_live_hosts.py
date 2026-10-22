"""Tests against real, disposable Debian hosts. Never point these at production.

    APTWARDEN_IT_HOSTS="aptwarden@192.0.2.21,aptwarden@192.0.2.22" \\
        pytest -m integration tests/integration

APTWARDEN_IT_NETWORK=1 additionally runs a full report with live feeds.
"""

import os

import pytest

from aptwarden import config, debversion, inventory
from aptwarden.runner import Runner
from aptwarden.transport import SshTransport, TransportError, TransportFactory

pytestmark = pytest.mark.integration

HOSTS = [h for h in os.environ.get("APTWARDEN_IT_HOSTS", "").split(",") if h]
if not HOSTS:
    pytest.skip("APTWARDEN_IT_HOSTS not set", allow_module_level=True)


def host_config(target: str, **ssh) -> config.HostConfig:
    user, _, address = target.rpartition("@")
    data = {"hosts": [{"name": address.replace(".", "-"), "address": address,
                       "ssh": {"user": user or "aptwarden",
                               "strict_host_key_checking": "accept-new", **ssh}}]}
    return config.from_dict(data).hosts[0]


@pytest.fixture(scope="module")
def factory():
    f = TransportFactory()
    yield f
    f.cleanup()


@pytest.mark.parametrize("target", HOSTS)
def test_inventory_over_ssh(target, factory):
    with factory.create(host_config(target)) as transport:
        inv = inventory.collect(transport)
    assert inv.os_id == "debian"
    assert inv.codename in {"bookworm", "trixie", "forky"}
    assert len(inv.packages) > 100
    for p in inv.packages:
        debversion.parse(p.version)
        debversion.parse(p.source_version)
    assert inv.facts["kernel"]


@pytest.mark.parametrize("target", HOSTS[:1])
def test_unprivileged_user(target, factory):
    with factory.create(host_config(target)) as transport:
        uid = transport.run(["id", "-u"]).check().stdout.strip()
    assert uid != "0", "run integration tests with the unprivileged aptwarden user"


@pytest.mark.parametrize("target", HOSTS[:1])
def test_wrong_port_is_a_transport_error(target):
    t = SshTransport("x", host_config(target).address,
                     host_config(target, port=1, connect_timeout=3).ssh, "/tmp")
    with pytest.raises(TransportError):
        t.run(["true"])


@pytest.mark.skipif(not os.environ.get("APTWARDEN_IT_NETWORK"), reason="APTWARDEN_IT_NETWORK")
def test_full_report(tmp_path):
    hosts = [host_config(t) for t in HOSTS]
    cfg = config.from_dict({
        "state_dir": str(tmp_path / "state"),
        "cache_dir": str(tmp_path / "cache"),
        "enrich": {"cvss": {"nvd": {"enabled": False}}},
        "hosts": [{"name": h.name, "address": h.address,
                   "ssh": {"user": h.ssh.user, "strict_host_key_checking": "accept-new"}}
                  for h in hosts],
    })
    runner = Runner(cfg)
    try:
        run = runner.report(cfg.hosts)
    finally:
        runner.close()
    assert run.status == "ok", [s.to_dict() for s in run.sources]
    assert all(h.ok for h in run.hosts)
