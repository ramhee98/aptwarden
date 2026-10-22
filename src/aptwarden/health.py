"""Healthchecks: systemd units (on the host via SSH), HTTP and TCP (from the
central host, i.e. the way clients see the service)."""

from __future__ import annotations

import logging
import socket
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from aptwarden.transport import Transport, TransportError

log = logging.getLogger(__name__)


@dataclass
class CheckResult:
    check: str
    ok: bool
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.check}: {'ok' if self.ok else 'FAILED'}" + (
            f" ({self.detail})" if self.detail else "")


def describe(check: dict) -> str:
    for kind in ("systemd", "http", "tcp"):
        if kind in check:
            return f"{kind} {check[kind]}"
    return str(check)


def run_check(check: dict, transport: Transport) -> CheckResult:
    name = describe(check)
    timeout = check.get("timeout", 10)
    try:
        if "systemd" in check:
            r = transport.run(["systemctl", "is-active", check["systemd"]], timeout=timeout)
            state = r.stdout.strip() or r.stderr.strip()
            return CheckResult(name, r.returncode == 0, "" if r.returncode == 0 else state)
        if "http" in check:
            return _http(name, check, timeout)
        if "tcp" in check:
            host, _, port = check["tcp"].rpartition(":")
            with socket.create_connection((host.strip("[]"), int(port)), timeout=timeout):
                return CheckResult(name, True)
    except TransportError as e:
        return CheckResult(name, False, str(e))
    except OSError as e:
        return CheckResult(name, False, str(e))
    return CheckResult(name, False, "unknown check type")


def _http(name: str, check: dict, timeout: float) -> CheckResult:
    ctx = ssl.create_default_context()
    if not check.get("verify_tls", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(check["http"], headers={"User-Agent": "aptwarden-healthcheck"})
    expect = check.get("expect_status", 200)
    expected = set(expect) if isinstance(expect, list) else {expect}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            status, body = r.status, r.read(1_000_000)
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(1_000_000) or b""
    if status not in expected:
        return CheckResult(name, False, f"HTTP {status}, expected {sorted(expected)}")
    if check.get("contains") and check["contains"].encode() not in body:
        return CheckResult(name, False, f"response lacks {check['contains']!r}")
    return CheckResult(name, True, f"HTTP {status}")


def run_all(checks: list[dict], transport: Transport) -> list[CheckResult]:
    return [run_check(c, transport) for c in checks]


def wait_healthy(checks: list[dict], transport: Transport, *, grace: float, retries: int,
                 interval: float, sleep: Callable[[float], None] = time.sleep
                 ) -> list[CheckResult]:
    """Wait ``grace`` seconds, then retry until every check passes or the
    retries are used up. Returns the last results."""
    sleep(grace)
    results = run_all(checks, transport)
    for _ in range(retries):
        if all(r.ok for r in results):
            break
        sleep(interval)
        results = run_all(checks, transport)
    for r in results:
        (log.info if r.ok else log.warning)("healthcheck", extra={"host": transport.host,
                                                                 "result": str(r)})
    return results
