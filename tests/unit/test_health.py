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
