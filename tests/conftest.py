from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from aptwarden import config
from aptwarden.cache import Cache
from aptwarden.http import HttpError, Response
from aptwarden.transport import CommandResult, Transport

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


def fixture_json(name: str):
    path = FIXTURES / name
    if name.endswith(".gz"):
        return json.loads(gzip.decompress(path.read_bytes()))
    return json.loads(path.read_text())


class FakeHttp:
    """Maps (method, url) to a Response, a callable(request) -> Response, or
    an exception. Records every request."""

    def __init__(self, routes: dict | None = None):
        self.routes = dict(routes or {})
        self.calls: list[tuple[str, str, dict, bytes | None]] = []

    def request(self, method, url, *, headers=None, data=None, retries=None):
        self.calls.append((method, url, headers or {}, data))
        route = self.routes.get((method, url))
        if route is None:  # keys ending in "*" match by prefix
            route = next((r for (m, u), r in self.routes.items()
                          if m == method and u.endswith("*") and url.startswith(u[:-1])), None)
        if route is None:
            raise AssertionError(f"unexpected request {method} {url}")
        if isinstance(route, Exception):
            raise route
        if callable(route):
            return route(headers or {}, data)
        return route

    def get(self, url, headers=None, **kw):
        return self.request("GET", url, headers=headers, **kw)

    def post_json(self, url, payload, **kw):
        return self.request("POST", url, data=json.dumps(payload).encode(), **kw)

    def urls(self, method: str | None = None) -> list[str]:
        return [c[1] for c in self.calls if method is None or c[0] == method]


def json_response(obj, status: int = 200, headers: dict | None = None) -> Response:
    return Response(status, json.dumps(obj).encode(), headers or {})


class FakeTransport(Transport):
    def __init__(self, host: str, commands: dict[tuple[str, ...], tuple[int, str, str]]):
        super().__init__(host)
        self.commands = commands
        self.calls: list[list[str]] = []
        self.closed = False

    def run(self, argv, timeout=None):
        self.calls.append(argv)
        key = tuple(argv) if tuple(argv) in self.commands else (argv[0], "*")
        if key not in self.commands:
            return CommandResult(argv, 127, "", f"{argv[0]}: not found")
        rc, out, err = self.commands[key]
        return CommandResult(argv, rc, out, err)

    def close(self):
        self.closed = True


def debian_host_commands(dpkg_output: str | None = None,
                         os_release: str | None = None) -> dict:
    from aptwarden.inventory import DPKG_FORMAT

    return {
        ("cat", "/etc/os-release"): (0, os_release or fixture_text("os-release-trixie.txt"), ""),
        ("dpkg-query", "-W", f"-f={DPKG_FORMAT}"):
            (0, dpkg_output or fixture_text("dpkg-query-trixie.txt"), ""),
        ("dpkg", "--print-architecture"): (0, "amd64\n", ""),
        ("cat", "/etc/debian_version"): (0, "13.1\n", ""),
        ("sh", "*"): (0, "kernel=6.8.12-pve\nvirt=lxc\nreboot_required=no\n"
                         "unattended_upgrade_periodic=0\n", ""),
    }


class FakeFactory:
    def __init__(self, transports: dict[str, Transport | Exception]):
        self.transports = transports

    def create(self, host):
        t = self.transports[host.name]
        if isinstance(t, Exception):
            raise t
        return t

    def cleanup(self):
        pass


@pytest.fixture
def cache(tmp_path):
    c = Cache(tmp_path / "cache.db")
    yield c
    c.close()


@pytest.fixture
def make_config(tmp_path):
    def make(**overrides) -> config.Config:
        data = {
            "state_dir": str(tmp_path / "state"),
            "cache_dir": str(tmp_path / "cache"),
            "hosts": [{"name": "web01", "address": "192.0.2.10"}],
        }
        data.update(overrides)
        return config.from_dict(data, tmp_path / "config.yaml")

    return make


__all__ = ["FakeHttp", "FakeTransport", "FakeFactory", "HttpError", "Response", "fixture_json",
           "fixture_text", "json_response", "debian_host_commands"]
