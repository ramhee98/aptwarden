"""Healthchecks: systemd units (on the host via SSH), HTTP and TCP.

HTTP and TCP checks run from the central host, i.e. the way clients see the
service. With ``on_host: true`` they run on the target instead, as the
unprivileged SSH user (never through the root helper): then the central host
needs nothing but SSH to the target. An on-host HTTP check connects to
127.0.0.1 but keeps the URL's host name (curl --resolve), so virtual hosts, SNI
and certificate checks behave as from outside.

``connect_to`` sends an HTTP check's connection to another address (e.g. the
internal reverse proxy when the name resolves to a public IP). SNI, the Host
header and the certificate check still use the URL's host name, and only the
original host is redirected: a redirect to another host resolves normally.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
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


MAX_BODY = 1_000_000


_CONNECT_TO = re.compile(r"^(?:\[(?P<v6>[0-9A-Fa-f:.]+)\]|(?P<host>[^:\[\]]+))(?::(?P<port>\d+))?$")


def parse_connect_to(value: str, default_port: int) -> tuple[str, int]:
    """"ip", "ip:port", "host", "[v6]" or "[v6]:port" -> (address, port)."""
    m = _CONNECT_TO.match(value.strip())
    if not m:
        raise ValueError(f"invalid connect_to {value!r} (ip, ip:port or [ipv6]:port)")
    port = int(m.group("port")) if m.group("port") else default_port
    if not 0 < port < 65536:
        raise ValueError(f"invalid port in connect_to {value!r}")
    return (m.group("v6") or m.group("host")), port


def _url_port(parts: urllib.parse.SplitResult) -> int:
    return parts.port or (443 if parts.scheme == "https" else 80)


def describe(check: dict) -> str:
    for kind in ("systemd", "http", "tcp"):
        if kind in check:
            where = []
            if check.get("on_host"):
                where.append("on host")
            if check.get("connect_to"):
                where.append(f"via {check['connect_to']}")
            return f"{kind} {check[kind]}" + (f" ({', '.join(where)})" if where else "")
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
            if check.get("on_host"):
                return _http_on_host(name, check, timeout, transport)
            return _http(name, check, timeout)
        if "tcp" in check:
            host, _, port = check["tcp"].rpartition(":")
            if check.get("on_host"):
                return _tcp_on_host(name, host.strip("[]"), port, timeout, transport)
            with socket.create_connection((host.strip("[]"), int(port)), timeout=timeout):
                return CheckResult(name, True)
    except TransportError as e:
        return CheckResult(name, False, str(e))
    except OSError as e:
        return CheckResult(name, False, str(e))
    return CheckResult(name, False, "unknown check type")


def _pinned(cls, address: tuple[str, int]):
    """A connection class that opens its socket to ``address`` while keeping
    the request's host name for SNI, Host header and certificate checks."""

    class Pinned(cls):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # http.client opens the socket through this attribute in connect()
            self._create_connection = lambda _addr, *a, **kw: socket.create_connection(
                address, *a, **kw)

    return Pinned


class _ConnectToHandler(urllib.request.HTTPHandler, urllib.request.HTTPSHandler):
    """Redirects connections to the original host (and port) only; any other
    host, e.g. after a redirect, is resolved normally."""

    def __init__(self, original: str, address: tuple[str, int], context: ssl.SSLContext):
        urllib.request.HTTPHandler.__init__(self)
        urllib.request.HTTPSHandler.__init__(self, context=context)
        self.original = original.lower()
        self.address = address

    def _cls(self, req, cls):
        return _pinned(cls, self.address) if req.host.lower() == self.original else cls

    def http_open(self, req):
        return self.do_open(self._cls(req, http.client.HTTPConnection), req)

    def https_open(self, req):
        return self.do_open(self._cls(req, http.client.HTTPSConnection), req,
                            context=self._context)


def _http(name: str, check: dict, timeout: float) -> CheckResult:
    ctx = ssl.create_default_context()
    if not check.get("verify_tls", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(check["http"], headers={"User-Agent": "aptwarden-healthcheck"})
    if check.get("connect_to"):
        parts = urllib.parse.urlsplit(check["http"])
        address = parse_connect_to(check["connect_to"], _url_port(parts))
        opener = urllib.request.build_opener(_ConnectToHandler(req.host, address, ctx))
        open_ = opener.open
    else:
        def open_(r, timeout):
            return urllib.request.urlopen(r, timeout=timeout, context=ctx)
    try:
        with open_(req, timeout=timeout) as r:
            status, body = r.status, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(MAX_BODY) or b""
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return CheckResult(name, False, reason.verify_message)
        return CheckResult(name, False, str(reason))
    return _judge(name, check, status, body)


def _expected(check: dict) -> set[int]:
    expect = check.get("expect_status", 200)
    return set(expect) if isinstance(expect, list) else {expect}


def _judge(name: str, check: dict, status: int, body: bytes) -> CheckResult:
    expected = _expected(check)
    if status not in expected:
        return CheckResult(name, False, f"HTTP {status}, expected {sorted(expected)}")
    if check.get("contains") and check["contains"].encode() not in body:
        return CheckResult(name, False, f"response lacks {check['contains']!r}")
    return CheckResult(name, True, f"HTTP {status}")


def _tcp_on_host(name: str, host: str, port: str, timeout: float,
                 transport: Transport) -> CheckResult:
    # host and port are passed as arguments, never pasted into the script
    r = transport.run(["timeout", str(int(timeout)), "bash", "-c",
                       'exec 3<>"/dev/tcp/$1/$2"', "aptwarden", host, port], timeout=timeout + 5)
    if r.returncode == 0:
        return CheckResult(name, True)
    if r.returncode == 124:
        return CheckResult(name, False, "timed out")
    return CheckResult(name, False, (r.stderr.strip().splitlines() or ["failed"])[-1])


# curl exit codes worth a readable message
_CURL_ERRORS = {6: "could not resolve host", 7: "connection refused", 28: "timed out",
                35: "TLS handshake failed", 51: "certificate does not match the host name",
                60: "certificate not trusted", 63: "response too large"}


def curl_argv(check: dict, timeout: float) -> list[str]:
    url = check["http"]
    parts = urllib.parse.urlsplit(url)
    argv = ["curl", "--silent", "--show-error", "--location", "--max-redirs", "5",
            "--max-time", str(int(timeout)), "--max-filesize", str(MAX_BODY),
            "--user-agent", "aptwarden-healthcheck", "--write-out", "\n%{http_code}"]
    host = parts.hostname or ""
    port = _url_port(parts)
    if check.get("connect_to"):
        # --connect-to (unlike --resolve) may also change the port; SNI and Host
        # stay the URL's
        address, target_port = parse_connect_to(check["connect_to"], port)
        target = f"[{address}]" if ":" in address else address
        argv += ["--connect-to", f"{host}:{port}:{target}:{target_port}"]
    else:
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if host and not is_ip and host != "localhost":
            argv += ["--resolve", f"{host}:{port}:127.0.0.1"]
    if not check.get("verify_tls", True):
        argv.append("--insecure")
    argv += ["--output", "-" if check.get("contains") else "/dev/null", "--", url]
    return argv


def _http_on_host(name: str, check: dict, timeout: float, transport: Transport) -> CheckResult:
    r = transport.run(curl_argv(check, timeout), timeout=timeout + 10)
    if r.returncode == 127:
        return CheckResult(name, False, "curl is not installed on the host")
    if r.returncode != 0:
        detail = _CURL_ERRORS.get(r.returncode) or r.stderr.strip() or f"curl exit {r.returncode}"
        return CheckResult(name, False, detail)
    body, _, code = r.stdout.rpartition("\n")
    try:
        status = int(code.strip())
    except ValueError:
        return CheckResult(name, False, "unexpected curl output")
    return _judge(name, check, status, body.encode())


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
