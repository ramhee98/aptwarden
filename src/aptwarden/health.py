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

Trust: checks come from the configuration, which only root and the aptwarden
user can change, so their targets are trusted like the rest of it. What is not
trusted is the checked service: a compromised web server could redirect the
central host to internal services. Hence ``redirects`` (default ``same-host``:
only redirects to the URL's own host are followed; ``any``; ``none``) and the
optional ``allowed_networks``: checks from the central host then connect only
to addresses in these networks. A name is resolved once, the address checked,
and the connection opened to exactly that address (no DNS rebinding between
check and connect), for every redirect too; proxies from the environment are
not used then.
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
            address = (host.strip("[]"), int(port))
            if networks := _networks(check):
                address = allowed_address(address[0], address[1], networks)
            with socket.create_connection(address, timeout=timeout):
                return CheckResult(name, True)
    except TransportError as e:
        return CheckResult(name, False, str(e))
    except OSError as e:
        return CheckResult(name, False, str(e))
    return CheckResult(name, False, "unknown check type")


MAX_REDIRECTS = 5


class TargetRefused(OSError):
    """A check would connect outside health.allowed_networks."""


def _networks(check: dict) -> list | None:
    nets = check.get("allowed_networks")
    return [ipaddress.ip_network(n, strict=False) for n in nets] if nets else None


def _ip(text: str):
    ip = ipaddress.ip_address(text.split("%", 1)[0])  # drop an IPv6 zone id
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped else ip


def allowed_address(host: str, port: int, networks: list) -> tuple[str, int]:
    """Resolve ``host`` once and return the first address inside ``networks``;
    the caller connects to exactly that address. TargetRefused otherwise."""
    try:
        infos = socket.getaddrinfo(host.strip("[]"), port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise TargetRefused(f"cannot resolve {host}: {e.strerror}") from None
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    for address in addresses:
        if any(_ip(address) in n for n in networks):
            return address, port
    raise TargetRefused(f"{host} ({', '.join(addresses)}) is outside health.allowed_networks")


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


class _GuardedHandler(urllib.request.HTTPHandler, urllib.request.HTTPSHandler):
    """Chooses the address of every connection, redirects included: connect_to
    for the original host (and port) only, an address checked against the
    allowed networks if there are any, else normal resolution."""

    def __init__(self, original: str, connect_to: tuple[str, int] | None,
                 networks: list | None, context: ssl.SSLContext):
        urllib.request.HTTPHandler.__init__(self)
        urllib.request.HTTPSHandler.__init__(self, context=context)
        self.original = original.lower()
        self.connect_to = connect_to
        self.networks = networks

    def _cls(self, req, cls):
        if self.connect_to and req.host.lower() == self.original:
            address = self.connect_to
            if self.networks and not any(_ip(address[0]) in n for n in self.networks):
                raise TargetRefused(f"connect_to {address[0]} is outside "
                                    f"health.allowed_networks")
        elif self.networks:
            parts = urllib.parse.urlsplit(req.full_url)
            address = allowed_address(parts.hostname or "", _url_port(parts), self.networks)
        else:
            return cls
        return _pinned(cls, address)

    def http_open(self, req):
        return self.do_open(self._cls(req, http.client.HTTPConnection), req)

    def https_open(self, req):
        return self.do_open(self._cls(req, http.client.HTTPSConnection), req,
                            context=self._context)


class _RedirectPolicy(urllib.request.HTTPRedirectHandler):
    """Follows redirects as health.redirects allows, at most MAX_REDIRECTS, and
    only to http(s). A refused redirect is not followed: its 3xx response is
    judged instead, and ``refused`` remembers where it pointed."""

    max_redirections = MAX_REDIRECTS

    def __init__(self, policy: str, original_host: str):
        self.policy = policy
        self.original_host = original_host.lower()
        self.refused: str | None = None

    def http_error_302(self, req, fp, code, msg, headers):
        # urllib refuses other schemes itself, before redirect_request; record them
        location = headers.get("location") or headers.get("uri")
        if location:
            newurl = urllib.parse.urljoin(req.full_url, location)
            if urllib.parse.urlsplit(newurl).scheme not in ("http", "https"):
                self.refused = newurl
                return None
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme not in ("http", "https") or self.policy == "none"
                or (self.policy == "same-host"
                    and (target.hostname or "").lower() != self.original_host)):
            self.refused = newurl
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _refused_detail(result: CheckResult, policy: str, target: str | None) -> CheckResult:
    if result.ok or not target:
        return result
    return CheckResult(result.check, False,
                       f"{result.detail}; redirect to {target} not followed (redirects: {policy})")


def _http(name: str, check: dict, timeout: float) -> CheckResult:
    ctx = ssl.create_default_context()
    if not check.get("verify_tls", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(check["http"], headers={"User-Agent": "aptwarden-healthcheck"})
    parts = urllib.parse.urlsplit(check["http"])
    connect_to = (parse_connect_to(check["connect_to"], _url_port(parts))
                  if check.get("connect_to") else None)
    networks = _networks(check)
    policy = check.get("redirects", "same-host")
    redirects = _RedirectPolicy(policy, parts.hostname or "")
    handlers = [_GuardedHandler(req.host, connect_to, networks, ctx), redirects]
    if networks:
        handlers.append(urllib.request.ProxyHandler({}))  # a proxy would bypass the check
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as r:
            status, body = r.status, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read(MAX_BODY) or b""
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return CheckResult(name, False, reason.verify_message)
        return CheckResult(name, False, str(reason))
    return _refused_detail(_judge(name, check, status, body), policy, redirects.refused)


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
    # redirects "any": curl follows them (http and https only); otherwise
    # _http_on_host follows the allowed ones itself, using %{redirect_url}
    follow = (["--location", "--max-redirs", str(MAX_REDIRECTS), "--proto-redir", "=http,https"]
              if check.get("redirects", "same-host") == "any" else [])
    argv = ["curl", "--silent", "--show-error", *follow,
            "--max-time", str(int(timeout)), "--max-filesize", str(MAX_BODY),
            "--user-agent", "aptwarden-healthcheck",
            "--write-out", "\n%{http_code} %{redirect_url}"]
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
    policy = check.get("redirects", "same-host")
    original = (urllib.parse.urlsplit(check["http"]).hostname or "").lower()
    current = check
    for hop in range(MAX_REDIRECTS + 1):
        r = transport.run(curl_argv(current, timeout), timeout=timeout + 10)
        if r.returncode == 127:
            return CheckResult(name, False, "curl is not installed on the host")
        if r.returncode != 0:
            detail = (_CURL_ERRORS.get(r.returncode) or r.stderr.strip()
                      or f"curl exit {r.returncode}")
            return CheckResult(name, False, detail)
        body, _, last = r.stdout.rpartition("\n")
        code, _, location = last.strip().partition(" ")
        try:
            status = int(code)
        except ValueError:
            return CheckResult(name, False, "unexpected curl output")
        if not (location and 300 <= status < 400):
            return _judge(name, check, status, body.encode())
        target = urllib.parse.urlsplit(location)
        allowed = target.scheme in ("http", "https") and (
            policy == "any"
            or (policy == "same-host" and (target.hostname or "").lower() == original))
        if not allowed:
            return _refused_detail(_judge(name, check, status, body.encode()), policy, location)
        if hop == MAX_REDIRECTS:
            break
        current = {**current, "http": location}
    return CheckResult(name, False, f"more than {MAX_REDIRECTS} redirects")


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
