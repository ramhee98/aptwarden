import shlex

import pytest

from aptwarden.config import SshSettings
from aptwarden.transport import LocalTransport, SshTransport, TransportError


def settings(**kw):
    base = dict(user="aptwarden", port=2222, identity_file="/etc/aptwarden/id",
                known_hosts_file="/var/lib/aptwarden/known_hosts",
                strict_host_key_checking="yes", connect_timeout=5, command_timeout=60,
                options={"ProxyJump": "bastion"})
    base.update(kw)
    return SshSettings(**base)


def test_ssh_argv():
    t = SshTransport("web01", "192.0.2.10", settings(), "/run/aptw")
    argv = t.base_argv()
    assert argv[0] == "ssh"
    opts = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "-o")
    assert opts["BatchMode"] == "yes"
    assert opts["StrictHostKeyChecking"] == "yes"
    assert opts["IdentityFile"] == "/etc/aptwarden/id"
    assert opts["IdentitiesOnly"] == "yes"
    assert opts["UserKnownHostsFile"] == "/var/lib/aptwarden/known_hosts"
    assert opts["ControlPath"] == "/run/aptw/%C"
    assert opts["ProxyJump"] == "bastion"
    assert argv[-5:] == ["-p", "2222", "-l", "aptwarden", "192.0.2.10"]
    assert t.base_argv("-O", "exit")[-7:-5] == ["-O", "exit"]


def test_ssh_remote_command_is_quoted(monkeypatch):
    captured = {}

    class P:
        returncode, stdout, stderr = 0, "ok", ""

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return P()

    monkeypatch.setattr("subprocess.run", fake_run)
    t = SshTransport("web01", "192.0.2.10", settings(), "/run/aptw")
    t.run(["dpkg-query", "-W", "-f=${Package}\\t$(id)\\n"])
    remote = captured["cmd"][-1]
    assert captured["cmd"][-2] == "--"
    # the remote shell must see exactly the original argv
    assert shlex.split(remote) == ["env", "LC_ALL=C.UTF-8", "dpkg-query", "-W",
                                   "-f=${Package}\\t$(id)\\n"]


def test_ssh_connection_failure_raises(monkeypatch):
    class P:
        returncode, stdout, stderr = 255, "", "ssh: connect to host 192.0.2.10: No route"

    monkeypatch.setattr("subprocess.run", lambda cmd, **kw: P())
    t = SshTransport("web01", "192.0.2.10", settings(), "/run/aptw")
    with pytest.raises(TransportError, match="No route"):
        t.run(["true"])


def test_local_transport():
    t = LocalTransport("self")
    r = t.run(["sh", "-c", "echo $LC_ALL; exit 3"])
    assert r.returncode == 3 and r.stdout.strip() == "C.UTF-8"
    with pytest.raises(TransportError):
        r.check()
    # like over SSH, a missing command is a failed command, not a transport error
    assert t.run(["/nonexistent/binary"]).returncode == 127


@pytest.mark.skipif(not __import__("shutil").which("ssh-keygen"), reason="needs ssh-keygen")
def test_known_host_keys(tmp_path):
    import subprocess

    from aptwarden.transport import known_host_keys

    key = tmp_path / "hostkey"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    pub = (tmp_path / "hostkey.pub").read_text().split()
    kh = tmp_path / "known_hosts"
    kh.write_text(f"192.0.2.10 {pub[0]} {pub[1]}\n[192.0.2.11]:2222 {pub[0]} {pub[1]}\n")
    subprocess.run(["ssh-keygen", "-H", "-f", str(kh)], check=True, capture_output=True)  # hash
    fp = subprocess.run(["ssh-keygen", "-lf", str(tmp_path / "hostkey.pub")], check=True,
                        capture_output=True, text=True).stdout.split()[1]
    assert known_host_keys("192.0.2.10", 22, str(kh)) == [f"{fp} (ED25519)"]
    assert known_host_keys("192.0.2.11", 2222, str(kh)) == [f"{fp} (ED25519)"]
    assert known_host_keys("192.0.2.11", 22, str(kh)) == []
    assert known_host_keys("192.0.2.99", 22, str(kh)) == []
