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
        threading.Thread(target=s.serve_forever, daemon=True).start()
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
                   "contains": "plain ok"}, None)
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
