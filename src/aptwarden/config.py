"""Configuration loading: YAML, defaults, JSON schema validation, typed access."""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import jsonschema
import yaml

from aptwarden.patch import window

DEFAULT_PATH = "/etc/aptwarden/config.yaml"

DEFAULTS: dict = {
    "state_dir": "/var/lib/aptwarden",
    "cache_dir": "/var/cache/aptwarden",
    "max_parallel": 4,
    "keep_runs": 100,
    "log": {"level": "info", "format": "auto"},
    "ssh": {
        "user": "aptwarden",
        "port": 22,
        "identity_file": None,
        "known_hosts_file": None,
        "strict_host_key_checking": "yes",
        "connect_timeout": 10,
        "command_timeout": 300,
        "options": {},
        "helper": "/usr/local/lib/aptwarden/aptwarden-helper",
    },
    "policy": {
        "modes": ["report"],
        "auto_patch_severities": ["critical", "high"],
        "auto_patch_kev": True,
        "window": [],
        "restart": "auto",
        "reboot": "never",
        "rollback": "auto",
        "allow_without_snapshot": False,
        "allow_extra_upgrades": False,
        "allow_new_packages": [],
    },
    "health": {"grace": "10s", "retries": 6, "interval": "5s"},
    "snapshots": {"keep": "7d", "vmstate": False},
    "status_page": {"enabled": True, "path": None, "mode": "0640"},
    "sources": {
        "debian_tracker": {
            "enabled": True,
            "url": "https://security-tracker.debian.org/tracker/data/json",
            "refresh_interval": "1h",
            "max_age": "3d",
        },
        "osv": {"enabled": True, "url": "https://api.osv.dev", "workers": 8},
        "custom": {
            "enabled": False,
            "url": "https://github.com/ramhee98/aptwarden-definitions.git",
            "ref": "signed-tags",
            "branch": "main",
            "tag_pattern": r"^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$",
            "allowed_signers_file": "/etc/aptwarden/allowed_signers",
            "path": "definitions",
            "refresh_interval": "1h",
        },
    },
    "enrich": {
        "cvss": {
            "enabled": True,
            "osv_url": "https://api.osv.dev",
            "workers": 8,
            "cache_ttl": "30d",
            "negative_ttl": "7d",
            "nvd": {
                "enabled": True,
                "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "api_key_file": None,
                "budget": "1m",
            },
        },
        "kev": {
            "enabled": True,
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "refresh_interval": "24h",
        },
    },
    "report": {"min_severity": "high", "show": "fixable"},
    "notify": {
        "summary": "always",
        "subject_prefix": "[aptwarden]",
        "alert": {
            "min_severity": "critical",
            "kev": True,
            "host_errors": True,
            "remind_after": "7d",
        },
        "email": {
            "enabled": False,
            "port": 25,
            "security": "starttls",
            "tls_verify": True,
            "tls_server_name": None,
            "username": None,
            "password_file": None,
            "timeout": 30,
        },
    },
    "hosts": [],
}

_DURATION_RE = re.compile(r"^([0-9]+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class ConfigError(Exception):
    pass


def parse_duration(value: int | str) -> int:
    """Return seconds for 90, "90s", "30m", "1h" or "3d"."""
    if isinstance(value, int):
        return value
    m = _DURATION_RE.match(value)
    if not m:
        raise ConfigError(f"invalid duration {value!r}")
    return int(m.group(1)) * _UNITS[m.group(2)]


def read_secret(path: str, base: Path | None = None) -> str:
    """Read a secret from a file. Relative paths are looked up in systemd's
    $CREDENTIALS_DIRECTORY first (LoadCredential=), then relative to ``base``."""
    p = Path(path)
    if not p.is_absolute():
        cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if cred_dir and (Path(cred_dir) / p).exists():
            p = Path(cred_dir) / p
        elif base is not None:
            p = base / p
    try:
        return p.read_text().strip()
    except OSError as e:
        raise ConfigError(f"cannot read secret {path}: {e.strerror}") from e


@dataclass
class SshSettings:
    user: str
    port: int
    identity_file: str | None
    known_hosts_file: str | None
    strict_host_key_checking: str
    connect_timeout: int
    command_timeout: int
    options: dict = field(default_factory=dict)
    helper: str = "/usr/local/lib/aptwarden/aptwarden-helper"


@dataclass
class HostConfig:
    name: str
    address: str
    transport: str
    ssh: SshSettings
    tags: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)  # merged with the global policy
    health: dict = field(default_factory=dict)
    healthchecks: list[dict] = field(default_factory=list)
    snapshot: dict = field(default_factory=lambda: {"provider": "none"})


@dataclass
class Config:
    path: Path | None
    raw: dict
    hosts: list[HostConfig]

    @property
    def base_dir(self) -> Path:
        return self.path.parent if self.path else Path.cwd()

    @property
    def state_dir(self) -> Path:
        return Path(self.raw["state_dir"])

    @property
    def cache_dir(self) -> Path:
        return Path(self.raw["cache_dir"])

    @property
    def max_parallel(self) -> int:
        return self.raw["max_parallel"]

    @property
    def keep_runs(self) -> int:
        return self.raw["keep_runs"]

    @property
    def log(self) -> dict:
        return self.raw["log"]

    @property
    def sources(self) -> dict:
        return self.raw["sources"]

    @property
    def enrich(self) -> dict:
        return self.raw["enrich"]

    @property
    def report(self) -> dict:
        return self.raw["report"]

    @property
    def notify(self) -> dict:
        return self.raw["notify"]

    @property
    def proxmox(self) -> dict | None:
        return self.raw.get("proxmox")

    @property
    def snapshots(self) -> dict:
        return self.raw["snapshots"]

    def select_hosts(self, names: list[str] | None) -> list[HostConfig]:
        if not names:
            return list(self.hosts)
        by_name = {h.name: h for h in self.hosts}
        unknown = [n for n in names if n not in by_name]
        if unknown:
            raise ConfigError(f"unknown host(s): {', '.join(unknown)}")
        return [by_name[n] for n in names]


def _schema() -> dict:
    text = resources.files("aptwarden").joinpath("schemas/config.schema.json").read_text()
    return json.loads(text)


def deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def _resolve(path: str | None, base: Path) -> str | None:
    if path is None:
        return None
    p = Path(path).expanduser()
    return str(p if p.is_absolute() else base / p)


def from_dict(data: dict, path: Path | None = None) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("configuration must be a mapping")
    merged = deep_merge(DEFAULTS, data)
    validator = jsonschema.Draft202012Validator(_schema())
    errors = sorted(validator.iter_errors(merged), key=lambda e: list(e.absolute_path))
    if errors:
        lines = [f"  {'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
                 for e in errors]
        raise ConfigError("invalid configuration:\n" + "\n".join(lines))

    base = path.parent if path else Path.cwd()
    for section in ("state_dir", "cache_dir"):
        merged[section] = _resolve(merged[section], base)
    merged["status_page"]["path"] = _resolve(merged["status_page"]["path"], base)
    # Validate every duration early so typos fail at load time, not mid-run.
    for section in (merged["sources"], merged["enrich"], merged["notify"], merged["health"],
                    merged["snapshots"]):
        _check_durations(section)

    hosts: list[HostConfig] = []
    seen: set[str] = set()
    for h in merged["hosts"]:
        if h["name"] in seen:
            raise ConfigError(f"duplicate host name {h['name']!r}")
        seen.add(h["name"])
        ssh = deep_merge(merged["ssh"], h.get("ssh", {}))
        ssh["identity_file"] = _resolve(ssh["identity_file"], base)
        ssh["known_hosts_file"] = _resolve(ssh["known_hosts_file"], base)
        policy = deep_merge(merged["policy"], h.get("policy", {}))
        for w in policy["window"]:
            try:
                window.parse(w)
            except ValueError as e:
                raise ConfigError(f"host {h['name']}: {e}") from None
        snapshot = h.get("snapshot", {"provider": "none"})
        if snapshot["provider"] == "proxmox" and "proxmox" not in merged:
            raise ConfigError(f"host {h['name']}: snapshot provider proxmox needs a proxmox "
                              f"section")
        hosts.append(
            HostConfig(
                name=h["name"],
                address=h.get("address", h["name"]),
                transport=h.get("transport", "ssh"),
                ssh=SshSettings(**ssh),
                tags=h.get("tags", []),
                policy=policy,
                health=deep_merge(merged["health"], h.get("health", {})),
                healthchecks=h.get("healthchecks", []),
                snapshot=snapshot,
            )
        )
    return Config(path=path, raw=merged, hosts=hosts)


def _check_durations(section: dict) -> None:
    for key, value in section.items():
        if isinstance(value, dict):
            _check_durations(value)
        elif key in ("refresh_interval", "max_age", "cache_ttl", "negative_ttl", "budget",
                     "remind_after", "grace", "interval", "keep"):
            parse_duration(value)


def load(path: str | os.PathLike | None = None) -> Config:
    p = Path(path or os.environ.get("APTWARDEN_CONFIG") or DEFAULT_PATH)
    try:
        data = yaml.safe_load(p.read_text())
    except OSError as e:
        raise ConfigError(f"cannot read {p}: {e.strerror}") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"cannot parse {p}: {e}") from e
    return from_dict(data or {}, p.resolve())
