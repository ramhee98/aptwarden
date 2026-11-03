"""Fetch definitions from Git and decide which state to trust.

Mode ``signed-tags`` (default): take the newest tag matching ``tag_pattern``
that

1. carries a valid SSH signature by a key in the local allowed_signers file,
2. descends from the last accepted commit (no rollback to older content),
3. passes schema and semantic validation.

Newer tags failing a check are rejected (and reported once); older valid tags
are still considered. Files are read straight from the verified commit, there
is no working tree that could drift.

Mode ``branch`` follows a branch tip without any verification, for forks and
testing only.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tarfile
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

from aptwarden.definitions import Definition, load_files

log = logging.getLogger(__name__)


class SyncError(Exception):
    pass


class ArchiveRejected(SyncError):
    """The definitions archive of a commit breaks a limit or holds unexpected
    entries; the tag is rejected like invalid content."""


# Limits for the archive of one commit, enforced while streaming it, before
# anything is read in full. The real repository holds a few files of 1-2 kB.
MAX_ARCHIVE = 32 * 2**20  # bytes of tar stream from git archive
MAX_ENTRIES = 5000  # tar entries (files and directories)
MAX_FILE = 256 * 1024  # one definition file
MAX_TOTAL = 16 * 2**20  # all definition files together


def _size(n: int) -> str:
    for unit, factor in (("MiB", 2**20), ("KiB", 1024)):
        if n >= factor:
            return f"{n / factor:g} {unit}"
    return f"{n} bytes"


class _Limited:
    """A read-only stream that fails once more than ``limit`` bytes were read."""

    def __init__(self, fp, limit: int):
        self.fp = fp
        self.limit = limit
        self.count = 0

    def read(self, n: int = -1) -> bytes:
        data = self.fp.read(n if n is not None and n >= 0 else self.limit + 1 - self.count)
        self.count += len(data)
        if self.count > self.limit:
            raise ArchiveRejected(f"archive larger than {_size(self.limit)}")
        return data


@dataclass
class SyncResult:
    changed: bool
    ref: str | None = None  # tag or branch name
    commit: str | None = None
    definitions: list[Definition] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # alert-worthy
    warnings: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)  # tags rejected in this sync


def tag_sort_key(tag: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", tag))


_SSH_SIGNATURE = "-----BEGIN SSH SIGNATURE-----"
# the signature formats git knows (gpg-interface.c)
_SIGNATURE_HEADERS = (_SSH_SIGNATURE, "-----BEGIN PGP SIGNATURE-----",
                      "-----BEGIN PGP MESSAGE-----", "-----BEGIN SIGNED MESSAGE-----")


class GitSync:
    def __init__(self, settings: dict, repo_dir: Path, allowed_signers: Path | None):
        self.settings = settings
        self.repo_dir = repo_dir
        self.allowed_signers = allowed_signers

    def _command(self, *args: str) -> tuple[list[str], dict[str, str]]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "LC_ALL": "C",
            # Only our own settings count, never ~/.gitconfig or /etc/gitconfig.
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        # gpg.format only applies to signing; git verifies with the format of the signature
        # itself. Disable the OpenPGP and X.509 programs, so such a signature can never be
        # checked against the user's keyring instead of allowed_signers.
        cmd = ["git", "-C", str(self.repo_dir), "-c", "gpg.format=ssh",
               "-c", "gpg.openpgp.program=false", "-c", "gpg.x509.program=false"]
        if self.allowed_signers:
            cmd += ["-c", f"gpg.ssh.allowedSignersFile={self.allowed_signers}"]
        return cmd + list(args), env

    def _git(self, *args: str, check: bool = True, binary: bool = False,
             timeout: int = 120) -> subprocess.CompletedProcess:
        cmd, env = self._command(*args)
        try:
            p = subprocess.run(cmd, capture_output=True, text=not binary,
                               env=env, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SyncError(f"git {args[0]}: {e}") from e
        if check and p.returncode != 0:
            err = p.stderr if isinstance(p.stderr, str) else p.stderr.decode(errors="replace")
            raise SyncError(f"git {args[0]} failed: {err.strip()}")
        return p

    def fetch(self) -> list[str]:
        """Clone or update the bare mirror. Returns warnings (e.g. moved tags)."""
        url = self.settings["url"]
        if not (self.repo_dir / "HEAD").exists():
            self.repo_dir.mkdir(parents=True, exist_ok=True)
            self._git("init", "--quiet", "--bare")
        # Branches may be rewritten, tags never: a moved tag is refused.
        # No --quiet: the "would clobber" rejection of a moved tag is only printed without it.
        p = self._git("fetch", "--prune", "--no-auto-gc", url,
                      "+refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*",
                      check=False, timeout=300)
        warnings = []
        if p.returncode != 0:
            clobbered = re.findall(r"\[rejected\]\s+(\S+)\s+->\s+\S+\s+\(would clobber", p.stderr)
            if not clobbered:
                raise SyncError(f"git fetch {url} failed: {p.stderr.strip()}")
            warnings += [f"tag {t} was changed upstream and is ignored (tags are immutable, "
                         f"publish a new tag)" for t in clobbered]
        return warnings

    def _commit_of(self, ref: str) -> str:
        p = self._git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
        return p.stdout.strip() if p.returncode == 0 else ""

    def _tags(self) -> list[str]:
        pattern = re.compile(self.settings["tag_pattern"])
        tags = [t for t in self._git("tag", "--list").stdout.split() if pattern.match(t)]
        return sorted(tags, key=tag_sort_key, reverse=True)

    def verify_tag(self, tag: str) -> tuple[bool, str]:
        # git uses the last line that starts a signature of any format, so that one must be
        # an SSH signature (a message may contain more such lines).
        obj = self._git("cat-file", "tag", tag, check=False).stdout
        headers = [line for line in obj.splitlines() if line.startswith(_SIGNATURE_HEADERS)]
        if headers and not headers[-1].startswith(_SSH_SIGNATURE):
            return False, "not an SSH signature"
        if not headers:
            return False, "unsigned"
        p = self._git("verify-tag", tag, check=False)
        detail = " ".join(p.stderr.split())
        return p.returncode == 0, detail

    def _is_ancestor(self, ancestor: str, commit: str) -> bool:
        return self._git("merge-base", "--is-ancestor", ancestor, commit,
                         check=False).returncode == 0

    def read_files(self, commit: str, timeout: int = 120) -> dict[str, str]:
        """The definition files of ``commit`` as {path below settings.path: text}.
        The archive is streamed from git with the limits above; breaking one
        raises ArchiveRejected."""
        path = self.settings["path"].strip("/")
        cmd, env = self._command("archive", "--format=tar", commit, "--", path)
        files: dict[str, str] = {}
        unreadable: tarfile.TarError | None = None
        try:
            with tempfile.TemporaryFile() as err, subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=err, env=env) as proc:
                timer = threading.Timer(timeout, proc.kill)
                timer.start()
                try:
                    files = _untar(proc.stdout, path)
                except tarfile.TarError as e:  # empty or broken stream; see stderr
                    unreadable = e
                except BaseException:
                    proc.kill()
                    raise
                finally:
                    timer.cancel()
                    proc.stdout.close()
                returncode = proc.wait()
                err.seek(0)
                stderr = err.read(64 * 1024).decode(errors="replace").strip()
        except OSError as e:
            raise SyncError(f"git archive: {e}") from e
        if returncode != 0:
            if "did not match any files" in stderr:
                return {}
            raise SyncError(f"git archive failed: {stderr or f'exit {returncode}'}")
        if unreadable is not None:
            raise ArchiveRejected(f"unreadable archive: {unreadable}")
        return files

    def _load(self, commit: str, ref: str, result: SyncResult) -> bool:
        try:
            files = self.read_files(commit)
        except ArchiveRejected as e:
            result.problems.append(f"{ref}: definitions archive rejected, ignored: {e}")
            return False
        loaded = load_files(files)
        result.warnings += [f"{ref}: {w}" for w in loaded.warnings]
        if not loaded.ok:
            result.problems += [f"{ref}: invalid definitions, ignored: {e}" for e in loaded.errors]
            return False
        result.definitions = loaded.definitions
        return True

    def sync(self, accepted_commit: str | None, rejected: set[str]) -> SyncResult:
        warnings = self.fetch()
        if self.settings["ref"] == "branch":
            result = self._sync_branch(accepted_commit)
        else:
            result = self._sync_tags(accepted_commit, rejected)
        result.warnings = warnings + result.warnings
        return result

    def _sync_branch(self, accepted_commit: str | None) -> SyncResult:
        branch = self.settings["branch"]
        commit = self._commit_of(f"refs/heads/{branch}")
        if not commit:
            raise SyncError(f"branch {branch} not found")
        result = SyncResult(changed=commit != accepted_commit, ref=branch, commit=commit)
        result.warnings.append("following a branch without signature verification")
        if result.changed and not self._load(commit, branch, result):
            result.changed = False
        return result

    def _sync_tags(self, accepted_commit: str | None, rejected: set[str]) -> SyncResult:
        if not self.allowed_signers or not self.allowed_signers.is_file():
            raise SyncError(f"allowed signers file {self.allowed_signers} not found")
        result = SyncResult(changed=False)
        for tag in self._tags():
            commit = self._commit_of(tag)
            if accepted_commit and commit == accepted_commit:
                break  # everything newer was rejected, the accepted state stays
            if tag in rejected:
                continue
            ok, detail = self.verify_tag(tag)
            if not ok:
                result.problems.append(f"tag {tag} rejected: no valid signature by an allowed "
                                       f"signer ({detail or 'unsigned'})")
                result.rejected.append(tag)
                continue
            if accepted_commit and not self._is_ancestor(accepted_commit, commit):
                result.problems.append(f"tag {tag} rejected: does not descend from the accepted "
                                       f"commit {accepted_commit[:12]} (history rewritten or "
                                       f"rollback attempt)")
                result.rejected.append(tag)
                continue
            if not self._load(commit, tag, result):
                result.rejected.append(tag)
                continue
            result.changed, result.ref, result.commit = True, tag, commit
            log.info("definitions tag accepted", extra={"tag": tag, "commit": commit,
                                                        "definitions": len(result.definitions)})
            break
        return result


def _untar(stream, path: str) -> dict[str, str]:
    """Read definition files from a tar stream, checking every limit on the
    member header before its data is read."""
    files: dict[str, str] = {}
    total = 0
    with tarfile.open(fileobj=_Limited(stream, MAX_ARCHIVE), mode="r|") as tar:
        for n, member in enumerate(tar, 1):
            if n > MAX_ENTRIES:
                raise ArchiveRejected(f"more than {MAX_ENTRIES} entries")
            if member.isdir():
                continue
            if not member.isfile():
                raise ArchiveRejected(f"{member.name}: unexpected entry type (symlink, device "
                                      f"or link); only regular files and directories")
            if not member.name.endswith((".yaml", ".yml")):
                continue  # e.g. a README; skipped without reading it
            if member.size > MAX_FILE:
                raise ArchiveRejected(f"{member.name}: {member.size} bytes, more than "
                                      f"{_size(MAX_FILE)}")
            total += member.size
            if total > MAX_TOTAL:
                raise ArchiveRejected(f"definition files larger than {_size(MAX_TOTAL)} "
                                      f"together")
            data = tar.extractfile(member).read(MAX_FILE + 1)  # type: ignore[union-attr]
            try:
                files[member.name.removeprefix(path + "/")] = data.decode("utf-8")
            except UnicodeDecodeError:
                raise ArchiveRejected(f"{member.name}: not UTF-8") from None
    return files
