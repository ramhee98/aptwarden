import pytest

from aptwarden.health import curl_argv, run_check
from aptwarden.transport import CommandResult, Transport


class Scripted(Transport):
    def __init__(self, rc=0, stdout="", stderr=""):
        super().__init__("web01")
        self.rc, self.stdout, self.stderr = rc, stdout, stderr
        self.calls = []

    def run(self, argv, timeout=None):
        self.calls.append(argv)
        return CommandResult(argv, self.rc, self.stdout, self.stderr)


def test_curl_argv_keeps_host_name_for_vhost_and_tls():
    argv = curl_argv({"http": "https://blog.example.org/wp-login.php"}, 10)
    assert argv[argv.index("--resolve") + 1] == "blog.example.org:443:127.0.0.1"
    assert argv[-2:] == ["--", "https://blog.example.org/wp-login.php"]
    assert argv[argv.index("--output") + 1] == "/dev/null"  # no body needed
    assert "--insecure" not in argv
    argv = curl_argv({"http": "http://app.example.org:8080/", "contains": "ok",
                      "verify_tls": False}, 5)
    assert "app.example.org:8080:127.0.0.1" in argv
    assert argv[argv.index("--output") + 1] == "-" and "--insecure" in argv
    # IPs and localhost are used as they are
    assert "--resolve" not in curl_argv({"http": "https://127.0.0.1/admin/"}, 5)
    assert "--resolve" not in curl_argv({"http": "http://localhost/"}, 5)


@pytest.mark.parametrize("rc, stdout, stderr, ok, detail", [
    (0, "<html>ok</html>\n200", "", True, "HTTP 200"),
    (0, "\n302", "", False, "HTTP 302, expected [200]"),
    (0, "<html>Error establishing a database connection\n200", "", False, "lacks"),
    (127, "", "env: 'curl': No such file or directory", False, "curl is not installed"),
    (7, "", "curl: (7) Failed to connect", False, "connection refused"),
    (60, "", "curl: (60) SSL certificate problem", False, "certificate not trusted"),
])
def test_http_on_host(rc, stdout, stderr, ok, detail):
    t = Scripted(rc, stdout, stderr)
    r = run_check({"http": "https://blog.example.org/", "on_host": True,
                   "contains": "</html>"}, t)
    assert r.ok is ok and detail in r.detail
    assert t.calls[0][0] == "curl"  # runs as the SSH user, not through sudo or the helper
    assert r.check.endswith("(on host)")


def test_tcp_on_host_passes_host_and_port_as_arguments():
    t = Scripted(0)
    assert run_check({"tcp": "127.0.0.1:53", "on_host": True}, t).ok
    argv = t.calls[0]
    assert argv[:4] == ["timeout", "10", "bash", "-c"]
    assert argv[-2:] == ["127.0.0.1", "53"] and "$1" in argv[4]
    assert run_check({"tcp": "127.0.0.1:53", "on_host": True}, Scripted(124)).detail == "timed out"
    refused = run_check({"tcp": "127.0.0.1:53", "on_host": True},
                        Scripted(1, "", "bash: connect: Connection refused\nbash: line 1: ..."))
    assert not refused.ok


def test_on_host_is_valid_in_config(make_config):
    cfg = make_config(hosts=[{"name": "dns01", "healthchecks": [
        {"tcp": "127.0.0.1:53", "on_host": True},
        {"http": "https://127.0.0.1/admin/", "on_host": True, "verify_tls": False}]}])
    assert cfg.hosts[0].healthchecks[0]["on_host"] is True


# --- connect_to -----------------------------------------------------------------

import shutil  # noqa: E402
import socket  # noqa: E402
import ssl  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402

from aptwarden import health  # noqa: E402
from aptwarden.health import describe, parse_connect_to  # noqa: E402


@pytest.mark.parametrize("value, port, expected", [
    ("192.0.2.20", 443, ("192.0.2.20", 443)),
    ("192.0.2.20:8443", 443, ("192.0.2.20", 8443)),
    ("[2001:db8::20]:8443", 443, ("2001:db8::20", 8443)),
    ("[2001:db8::20]", 80, ("2001:db8::20", 80)),
    ("proxy.lan", 443, ("proxy.lan", 443)),
])
def test_parse_connect_to(value, port, expected):
    assert parse_connect_to(value, port) == expected


@pytest.mark.parametrize("bad", ["", "2001:db8::1", "a:b:c", "1.2.3.4:0", "1.2.3.4:99999",
                                 "[::1"])
def test_parse_connect_to_rejects(bad):
    with pytest.raises(ValueError):
        parse_connect_to(bad, 443)


def test_describe_shows_connect_to():
    assert describe({"http": "https://a.example/", "connect_to": "192.0.2.20"}) == \
        "http https://a.example/ (via 192.0.2.20)"
    assert describe({"http": "https://a.example/", "on_host": True, "connect_to": "10.0.0.2"}) \
        == "http https://a.example/ (on host, via 10.0.0.2)"


def test_curl_argv_connect_to():
    argv = curl_argv({"http": "https://blog.example.org/", "connect_to": "192.0.2.20"}, 5)
    assert argv[argv.index("--connect-to") + 1] == "blog.example.org:443:192.0.2.20:443"
    assert "--resolve" not in argv
    argv = curl_argv({"http": "http://blog.example.org:8080/",
                      "connect_to": "[2001:db8::20]:80"}, 5)
    assert argv[argv.index("--connect-to") + 1] == "blog.example.org:8080:[2001:db8::20]:80"


@pytest.fixture
def tls_backend(tmp_path, monkeypatch):
    """A TLS server for test.example on 127.0.0.1 and a plain one for redirects."""
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=test.example",
                    "-addext", "subjectAltName=DNS:test.example", "-days", "1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    seen = {"sni": [], "host": []}
    plain = HTTPServer(("127.0.0.1", 0), type("Plain", (BaseHTTPRequestHandler,), {
        "do_GET": lambda self: (self.send_response(200), self.end_headers(),
                                self.wfile.write(b"plain ok")),
        "log_message": lambda self, *a: None}))

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen["host"].append(self.headers.get("Host"))
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{plain.server_address[1]}/")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html>tls ok</html>")

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.sni_callback = lambda sock, name, c: seen["sni"].append(name)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    for s in (server, plain):
        threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
    # trust the test certificate
    real = ssl.create_default_context
    monkeypatch.setattr(health.ssl, "create_default_context",
                        lambda *a, **kw: real(cafile=str(cert)))
    yield server.server_address[1], seen
    server.shutdown()
    plain.shutdown()


def test_connect_to_keeps_sni_host_and_certificate_name(tls_backend):
    port, seen = tls_backend
    r = run_check({"http": "https://test.example/", "connect_to": f"127.0.0.1:{port}",
                   "contains": "tls ok"}, None)
    assert r.ok, r.detail
    assert seen["sni"] == ["test.example"] and seen["host"] == ["test.example"]


def test_connect_to_still_verifies_the_url_host_name(tls_backend):
    port, _ = tls_backend
    r = run_check({"http": "https://other.example/", "connect_to": f"127.0.0.1:{port}"}, None)
    assert not r.ok and "match" in r.detail.lower()


def test_connect_to_applies_only_to_the_original_host(tls_backend):
    port, _ = tls_backend
    # the redirect goes to localhost:<plain>; if it were pinned too, it would hit the TLS port
    r = run_check({"http": "https://test.example/redirect", "connect_to": f"127.0.0.1:{port}",
                   "contains": "plain ok", "redirects": "any"}, None)
    assert r.ok, r.detail


def test_connect_to_defaults_from_health(make_config):
    from aptwarden.config import ConfigError

    cfg = make_config(health={"connect_to": "192.0.2.20"}, hosts=[{"name": "web01",
        "health": {}, "healthchecks": [
            {"http": "https://a.example/"},
            {"http": "https://b.example/", "connect_to": "192.0.2.99"},
            {"http": "https://c.example/", "on_host": True},
            {"tcp": "192.0.2.10:443"}]}])
    checks = cfg.hosts[0].healthchecks
    assert checks[0]["connect_to"] == "192.0.2.20"          # default applied
    assert checks[1]["connect_to"] == "192.0.2.99"          # the check wins
    assert "connect_to" not in checks[2]                    # not for on-host checks
    assert "connect_to" not in checks[3]                    # http only
    host_level = make_config(hosts=[{"name": "web01", "health": {"connect_to": "10.0.0.1"},
                                     "healthchecks": [{"http": "https://a.example/"}]}])
    assert host_level.hosts[0].healthchecks[0]["connect_to"] == "10.0.0.1"
    with pytest.raises(ConfigError, match="invalid connect_to"):
        make_config(hosts=[{"name": "web01", "healthchecks": [
            {"http": "https://a.example/", "connect_to": "a:b:c"}]}])


# --- redirects and allowed networks (SEC-05) ---------------------------------

@pytest.fixture
def web():
    """Plain HTTP server on 127.0.0.1; ``routes[path] = (status, location)``."""
    routes: dict[str, tuple[int, str | None]] = {}
    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, location = routes.get(self.path, (200, None))
            self.send_response(status)
            if location:
                self.send_header("Location", location.format(port=server.server_port))
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                     daemon=True).start()
    yield server.server_port, routes, hits
    server.shutdown()
    server.server_close()


def test_redirects_same_host_by_default(web):
    port, routes, hits = web
    routes["/same"] = (302, "http://127.0.0.1:{port}/ok")
    routes["/cross"] = (302, "http://localhost:{port}/ok")
    assert run_check({"http": f"http://127.0.0.1:{port}/same"}, None).ok
    r = run_check({"http": f"http://127.0.0.1:{port}/cross"}, None)
    assert not r.ok
    assert r.detail == (f"HTTP 302, expected [200]; redirect to http://localhost:{port}/ok "
                        f"not followed (redirects: same-host)")
    assert hits == ["/same", "/ok", "/cross"]  # the refused target was never requested
    # a refused redirect is judged as the 3xx it is
    assert run_check({"http": f"http://127.0.0.1:{port}/cross", "expect_status": 302}, None).ok


def test_redirect_policies_any_and_none(web):
    port, routes, _ = web
    routes["/cross"] = (302, "http://localhost:{port}/ok")
    routes["/same"] = (302, "http://127.0.0.1:{port}/ok")
    assert run_check({"http": f"http://127.0.0.1:{port}/cross", "redirects": "any"}, None).ok
    r = run_check({"http": f"http://127.0.0.1:{port}/same", "redirects": "none"}, None)
    assert not r.ok and "not followed (redirects: none)" in r.detail


def test_redirects_never_leave_http(web):
    port, routes, hits = web
    routes["/file"] = (302, "file:///etc/passwd")
    r = run_check({"http": f"http://127.0.0.1:{port}/file", "redirects": "any"}, None)
    assert not r.ok and "redirect to file:///etc/passwd not followed" in r.detail


def test_redirect_loop_is_bounded(web):
    port, routes, hits = web
    routes["/loop"] = (302, "http://127.0.0.1:{port}/loop")
    assert not run_check({"http": f"http://127.0.0.1:{port}/loop"}, None).ok
    assert len(hits) <= 6


def test_allowed_networks_refuse_other_targets(web):
    port, routes, hits = web
    lan = {"allowed_networks": ["192.0.2.0/24"]}
    r = run_check({"http": f"http://localhost:{port}/", **lan}, None)
    assert not r.ok and "is outside health.allowed_networks" in r.detail and hits == []
    r = run_check({"tcp": f"localhost:{port}", **lan}, None)
    assert not r.ok and "is outside health.allowed_networks" in r.detail
    loop = {"allowed_networks": ["127.0.0.0/8"]}
    assert run_check({"http": f"http://localhost:{port}/", **loop}, None).ok
    assert run_check({"tcp": f"localhost:{port}", **loop}, None).ok


def test_allowed_networks_apply_to_every_redirect(web):
    port, routes, hits = web
    routes["/away"] = (302, "http://192.0.2.1/")  # e.g. into the management network
    r = run_check({"http": f"http://127.0.0.1:{port}/away", "redirects": "any",
                   "allowed_networks": ["127.0.0.0/8"]}, None)
    assert not r.ok and "192.0.2.1" in r.detail and "outside health.allowed_networks" in r.detail


def test_allowed_networks_pin_the_checked_address(web, monkeypatch):
    """DNS rebinding: the name resolves to an allowed address once, then to a
    forbidden one. The connection must go to the address that was checked."""
    port, routes, hits = web
    real = socket.getaddrinfo
    answers = iter(["127.0.0.1"] + ["192.0.2.1"] * 10)

    def rebinding(host, *a, **kw):
        if host == "rebind.test":
            return real(next(answers), *a, **kw)
        return real(host, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    r = run_check({"http": f"http://rebind.test:{port}/", "contains": "ok",
                   "allowed_networks": ["127.0.0.0/8"]}, None)
    assert r.ok, r.detail
    assert hits == ["/"]


def test_allowed_networks_ignore_environment_proxies(web, monkeypatch):
    port, _, _ = web
    monkeypatch.setenv("http_proxy", "http://192.0.2.1:3128")
    monkeypatch.setenv("no_proxy", "")
    assert run_check({"http": f"http://127.0.0.1:{port}/",
                      "allowed_networks": ["127.0.0.0/8"]}, None).ok


def test_allowed_networks_in_config(make_config):
    from aptwarden.config import ConfigError

    cfg = make_config(health={"allowed_networks": ["192.0.2.0/24", "2001:db8::/32"]},
                      hosts=[{"name": "web01", "healthchecks": [
                          {"http": "https://blog.example.org/", "connect_to": "192.0.2.11"},
                          {"tcp": "192.0.2.10:22"},
                          {"http": "https://127.0.0.1/admin/", "on_host": True},
                          {"systemd": "ssh.service"}]}])
    checks = cfg.hosts[0].healthchecks
    assert checks[0]["allowed_networks"] == ["192.0.2.0/24", "2001:db8::/32"]
    assert checks[0]["redirects"] == "same-host"
    assert checks[1]["allowed_networks"] and "allowed_networks" not in checks[2]  # on host
    for bad, match in [({"http": "https://x.example/", "connect_to": "10.0.0.1"}, "connect_to"),
                       ({"http": "http://169.254.169.254/latest/"}, "http check"),
                       ({"tcp": "127.0.0.1:8006"}, "tcp check")]:
        with pytest.raises(ConfigError, match=f"{match} .* is outside health.allowed_networks"):
            make_config(health={"allowed_networks": ["192.0.2.0/24"]},
                        hosts=[{"name": "web01", "healthchecks": [bad]}])
    with pytest.raises(ConfigError, match="health.allowed_networks"):
        make_config(health={"allowed_networks": ["not-a-network"]})


class Sequence(Transport):
    """Answers each call with the next (rc, stdout) pair."""

    def __init__(self, *answers):
        super().__init__("web01")
        self.answers = list(answers)
        self.calls = []

    def run(self, argv, timeout=None):
        self.calls.append(argv)
        rc, out = self.answers.pop(0)
        return CommandResult(argv, rc, out, "")


def test_on_host_redirects():
    base = {"http": "http://blog.example.org/", "on_host": True}
    assert "--location" not in curl_argv(base, 5)
    follows = curl_argv({**base, "redirects": "any"}, 5)
    assert "--location" in follows and follows[follows.index("--proto-redir") + 1] == "=http,https"
    # same host: followed by aptwarden, with --resolve for the new port
    t = Sequence((0, "\n301 https://blog.example.org/"), (0, "ok\n200 "))
    assert run_check(base, t).ok
    assert "blog.example.org:443:127.0.0.1" in t.calls[1] and t.calls[1][-1] == \
        "https://blog.example.org/"
    # another host: not followed
    t = Sequence((0, "\n302 https://sso.example.org/login"))
    r = run_check(base, t)
    assert not r.ok and "redirect to https://sso.example.org/login not followed" in r.detail
    assert len(t.calls) == 1
    # none, and a loop
    assert not run_check({**base, "redirects": "none"},
                         Sequence((0, "\n302 http://blog.example.org/x"))).ok
    t = Sequence(*[(0, "\n302 http://blog.example.org/again")] * 10)
    r = run_check(base, t)
    assert r.detail == "more than 5 redirects" and len(t.calls) == 6
