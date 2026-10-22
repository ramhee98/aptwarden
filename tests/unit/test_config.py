import pytest

from aptwarden import config
from aptwarden.config import ConfigError, parse_duration, read_secret


def test_defaults_and_host_inheritance(make_config, tmp_path):
    cfg = make_config(ssh={"user": "scanner", "identity_file": "keys/id"},
                      hosts=[{"name": "web01", "address": "192.0.2.10"},
                             {"name": "db01", "ssh": {"port": 2222, "user": "other"}},
                             {"name": "self", "transport": "local"}])
    web, db, local = cfg.hosts
    assert (web.address, web.ssh.user, web.ssh.port) == ("192.0.2.10", "scanner", 22)
    assert web.ssh.identity_file == str(tmp_path / "keys/id")  # relative to config file
    assert (db.address, db.ssh.user, db.ssh.port) == ("db01", "other", 2222)
    assert local.transport == "local"
    assert cfg.sources["debian_tracker"]["enabled"] is True
    assert cfg.report["min_severity"] == "high"


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"hosts": [{"name": "a", "adress": "typo"}]}, "adress"),
        ({"hosts": [{"name": "bad name"}]}, "does not match"),
        ({"report": {"min_severity": "urgent"}}, "min_severity"),
        ({"sources": {"debian_tracker": {"refresh_interval": "1 hour"}}}, "refresh_interval"),
        ({"hosts": [{"name": "a"}, {"name": "a"}]}, "duplicate"),
        ({"unknown_key": 1}, "unknown_key"),
    ],
)
def test_invalid_configs(make_config, overrides, message):
    with pytest.raises(ConfigError, match=message):
        make_config(**overrides)


def test_select_hosts(make_config):
    cfg = make_config(hosts=[{"name": "a"}, {"name": "b"}])
    assert [h.name for h in cfg.select_hosts(None)] == ["a", "b"]
    assert [h.name for h in cfg.select_hosts(["b"])] == ["b"]
    with pytest.raises(ConfigError, match="unknown host"):
        cfg.select_hosts(["c"])


@pytest.mark.parametrize("value, seconds", [(90, 90), ("90s", 90), ("30m", 1800),
                                            ("1h", 3600), ("3d", 259200)])
def test_parse_duration(value, seconds):
    assert parse_duration(value) == seconds


def test_parse_duration_invalid():
    with pytest.raises(ConfigError):
        parse_duration("1w")


def test_load_yaml_file(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("state_dir: state\nhosts:\n  - name: web01\n")
    cfg = config.load(p)
    assert cfg.state_dir == tmp_path / "state"
    assert cfg.hosts[0].name == "web01"


def test_load_errors(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        config.load(tmp_path / "missing.yaml")
    p = tmp_path / "broken.yaml"
    p.write_text("hosts: [\n")
    with pytest.raises(ConfigError, match="cannot parse"):
        config.load(p)


def test_read_secret_prefers_credentials_directory(tmp_path, monkeypatch):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "nvd").write_text("from-systemd\n")
    (tmp_path / "nvd").write_text("from-config-dir\n")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(creds))
    assert read_secret("nvd", tmp_path) == "from-systemd"
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    assert read_secret("nvd", tmp_path) == "from-config-dir"
    with pytest.raises(ConfigError):
        read_secret("missing", tmp_path)
