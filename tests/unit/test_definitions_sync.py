"""Sync against real git repositories with real SSH signatures."""

import os
import shutil
import subprocess

import pytest

from aptwarden.definitions import sync as sync_mod
from aptwarden.definitions.sync import GitSync, SyncError, tag_sort_key
from tests.unit.test_definitions import VALID, defn

pytestmark = pytest.mark.skipif(not (shutil.which("git") and shutil.which("ssh-keygen")),
                                reason="needs git and ssh-keygen")

EMAIL = "maintainer@example.org"


class Upstream:
    def __init__(self, path, tmp):
        self.path = path
        self.keys = {}
        for name in ("good", "evil"):
            key = tmp / f"{name}_key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                           check=True)
            self.keys[name] = key
        path.mkdir()
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        return subprocess.run(["git", "-C", str(self.path), "-c", f"user.email={EMAIL}",
                               "-c", "user.name=Maintainer", "-c", "gpg.format=ssh", *args],
                              check=True, capture_output=True, text=True, env=env)

    def commit(self, files: dict[str, str], message="update"):
        for name, text in files.items():
            p = self.path / "definitions" / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def tag(self, name, key="good", signed=True, force=False):
        args = ["tag", "-m", name] + (["-f"] if force else [])
        if signed:
            args = ["-c", f"user.signingkey={self.keys[key]}.pub"] + args + ["-s"]
        self.git(*args, name)


@pytest.fixture
def env(tmp_path):
    up = Upstream(tmp_path / "upstream", tmp_path)
    signers = tmp_path / "allowed_signers"
    signers.write_text(f"{EMAIL} {(up.keys['good'].parent / 'good_key.pub').read_text()}")
    settings = {"url": str(up.path), "ref": "signed-tags", "branch": "main",
                "tag_pattern": r"^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]+)?$",
                "path": "definitions"}
    sync = GitSync(settings, tmp_path / "mirror.git", signers)
    return up, sync


def test_tag_sort_key():
    tags = ["v2026.10.9", "v2026.10.22", "v2026.10.22.2", "v2025.12.31"]
    assert sorted(tags, key=tag_sort_key, reverse=True)[0] == "v2026.10.22.2"


def test_accepts_newest_signed_tag(env):
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    r = sync.sync(None, set())
    assert r.changed and r.ref == "v2026.10.21" and r.commit == c1
    assert [d.id for d in r.definitions] == ["AW-2026-0001"]
    assert r.problems == []
    # unchanged on the next sync
    assert not sync.sync(c1, set()).changed


def test_untagged_main_is_ignored(env):
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    up.commit({"2026/AW-2026-0001.yaml": defn(severity="low")})
    r = sync.sync(c1, set())
    assert not r.changed


def test_unsigned_and_foreign_signed_tags_are_rejected(env):
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    up.commit({"2026/AW-2026-0001.yaml": defn(severity="low")})
    up.tag("v2026.10.22", signed=False)
    up.tag("v2026.10.22.1", key="evil")
    r = sync.sync(None, set())
    # falls back to the older, validly signed tag
    assert r.changed and r.ref == "v2026.10.21" and r.commit == c1
    assert sorted(r.rejected) == ["v2026.10.22", "v2026.10.22.1"]
    assert all("no valid signature" in p for p in r.problems)
    # rejected tags are not reported again
    r2 = sync.sync(c1, set(r.rejected))
    assert not r2.changed and r2.problems == []


def test_rollback_is_rejected(env):
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID}, "first")
    up.tag("v2026.10.21")
    c2 = up.commit({"2026/AW-2026-0001.yaml": defn(severity="low")}, "second")
    up.tag("v2026.10.22")
    assert sync.sync(c1, set()).commit == c2
    # attacker rewrites history and signs... with a stolen key? No: even a valid
    # signature on a commit that drops accepted history must not be accepted.
    up.git("reset", "-q", "--hard", c1)
    up.commit({"2026/AW-2026-0001.yaml": defn(summary="rewritten history entry")}, "fork")
    up.tag("v2026.10.23")
    r = sync.sync(c2, set())
    assert not r.changed
    assert "does not descend" in r.problems[0]


def test_invalid_content_in_signed_tag_is_rejected(env):
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    up.commit({"2026/AW-2026-0001.yaml": defn(severity="urgent")})
    up.tag("v2026.10.22")
    r = sync.sync(c1, set())
    assert not r.changed
    assert r.rejected == ["v2026.10.22"]
    assert "invalid definitions" in r.problems[0]


def test_moved_tag_is_ignored(env):
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    assert sync.sync(None, set()).commit == c1
    up.commit({"2026/AW-2026-0001.yaml": defn(severity="low")})
    up.tag("v2026.10.21", force=True)
    r = sync.sync(c1, set())
    assert not r.changed
    assert "v2026.10.21 was changed upstream" in r.warnings[0]


def test_branch_mode(env):
    up, sync = env
    up.commit({"2026/AW-2026-0001.yaml": VALID})
    sync.settings = {**sync.settings, "ref": "branch"}
    r = sync.sync(None, set())
    assert r.changed and r.ref == "main"
    assert "without signature verification" in r.warnings[0]


def test_missing_allowed_signers(env, tmp_path):
    up, sync = env
    up.commit({"2026/AW-2026-0001.yaml": VALID})
    sync.allowed_signers = tmp_path / "nope"
    with pytest.raises(SyncError, match="allowed signers"):
        sync.sync(None, set())


def test_unreachable_upstream(env, tmp_path):
    _, sync = env
    sync.settings = {**sync.settings, "url": str(tmp_path / "missing")}
    with pytest.raises(SyncError, match="fetch"):
        sync.sync(None, set())


# --- archive limits (SEC-02) -------------------------------------------------

def add_raw(up, name, data: bytes | None = None, symlink_to: str | None = None):
    p = up.path / "definitions" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    if symlink_to:
        p.symlink_to(symlink_to)
    else:
        p.write_bytes(data)


def rejected_after_valid(up, sync, change):
    """A valid signed tag, then a newer signed tag made by ``change``: the newer
    one must be rejected with a problem, the valid state kept."""
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    change()
    up.git("add", "-A")
    up.git("commit", "-q", "-m", "bad")
    up.tag("v2026.10.22")
    r = sync.sync(c1, set())
    assert not r.changed and r.rejected == ["v2026.10.22"]
    assert len(r.problems) == 1 and "definitions archive rejected" in r.problems[0]
    return r.problems[0]


def test_too_many_entries(env, monkeypatch):
    up, sync = env
    monkeypatch.setattr(sync_mod, "MAX_ENTRIES", 5)
    problem = rejected_after_valid(up, sync, lambda: [
        add_raw(up, f"2026/x{i}.txt", b"x") for i in range(10)])
    assert "more than 5 entries" in problem


def test_oversized_definition_file(env, monkeypatch):
    up, sync = env
    monkeypatch.setattr(sync_mod, "MAX_FILE", 1024)
    problem = rejected_after_valid(up, sync, lambda: add_raw(
        up, "2026/AW-2026-0002.yaml", b"# " + b"x" * 2000 + b"\n"))
    assert "AW-2026-0002.yaml: 2003 bytes, more than 1 KiB" in problem


def test_definition_files_too_large_together(env, monkeypatch):
    up, sync = env
    monkeypatch.setattr(sync_mod, "MAX_TOTAL", 4096)
    problem = rejected_after_valid(up, sync, lambda: [
        add_raw(up, f"2026/AW-2026-{i:04d}.yaml", b"#" * 1000 + b"\n") for i in range(2, 8)])
    assert "larger than 4 KiB together" in problem


def test_oversized_archive(env, monkeypatch):
    up, sync = env
    monkeypatch.setattr(sync_mod, "MAX_ARCHIVE", 64 * 1024)
    # not a definition file, but still part of the archive stream
    problem = rejected_after_valid(up, sync, lambda: add_raw(
        up, "blob.bin", os.urandom(200 * 1024)))
    assert "archive larger than 64 KiB" in problem


def test_symlink_is_rejected(env):
    up, sync = env
    problem = rejected_after_valid(up, sync, lambda: add_raw(
        up, "2026/AW-2026-0002.yaml", symlink_to="/etc/passwd"))
    assert "AW-2026-0002.yaml: unexpected entry type" in problem


def test_non_utf8_definition_is_rejected(env):
    up, sync = env
    problem = rejected_after_valid(up, sync, lambda: add_raw(
        up, "2026/AW-2026-0002.yaml", b"id: \xff\xfe\n"))
    assert "not UTF-8" in problem


def test_readme_is_skipped_unread(env):
    up, sync = env
    up.commit({"2026/AW-2026-0001.yaml": VALID, "README.md": "# not a definition\n"})
    up.tag("v2026.10.21")
    r = sync.sync(None, set())
    assert r.changed and [d.id for d in r.definitions] == ["AW-2026-0001"]


@pytest.fixture
def gpg_home(monkeypatch):
    """An OpenPGP key for EMAIL in the keyring of the user aptwarden runs as, trusted
    ultimately: what git would check an OpenPGP tag against."""
    import tempfile

    if not shutil.which("gpg"):
        pytest.skip("needs gpg")
    home = tempfile.mkdtemp(prefix="aptw-gpg-")  # short: gpg-agent's socket lives there
    gnupg = os.path.join(home, ".gnupg")
    os.mkdir(gnupg, 0o700)
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("GNUPGHOME", gnupg)
    subprocess.run(["gpg", "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase",
                    "", "--quick-gen-key", f"Maintainer <{EMAIL}>", "ed25519", "sign", "never"],
                   check=True, capture_output=True)
    yield gnupg
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], check=False, capture_output=True)
    shutil.rmtree(home, ignore_errors=True)


def test_openpgp_signed_tags_are_rejected(env, gpg_home):
    # git picks the format from the signature, not from gpg.format=ssh, so an OpenPGP tag
    # would be checked against the user's keyring instead of allowed_signers
    up, sync = env
    c1 = up.commit({"2026/AW-2026-0001.yaml": VALID})
    up.tag("v2026.10.21")
    up.commit({"2026/AW-2026-0001.yaml": defn(severity="low")})
    up.git("-c", "gpg.format=openpgp", "-c", f"user.signingkey={EMAIL}", "tag", "-s",
           "-m", "v2026.10.22", "v2026.10.22")
    # an SSH signature header in the message must not make it look like an SSH tag
    up.git("-c", "gpg.format=openpgp", "-c", f"user.signingkey={EMAIL}", "tag", "-s",
           "-m", "v2026.10.22.1\n\n-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----",
           "v2026.10.22.1")
    assert "BEGIN PGP SIGNATURE" in up.git("cat-file", "tag", "v2026.10.22").stdout
    r = sync.sync(None, set())
    assert r.changed and r.ref == "v2026.10.21" and r.commit == c1
    assert sorted(r.rejected) == ["v2026.10.22", "v2026.10.22.1"]
    assert all("no valid signature" in p for p in r.problems)
