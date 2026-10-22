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

import io
import logging
import os
import re
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from aptwarden.definitions import Definition, load_files

log = logging.getLogger(__name__)


class SyncError(Exception):
    pass


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


class GitSync:
    def __init__(self, settings: dict, repo_dir: Path, allowed_signers: Path | None):
        self.settings = settings
        self.repo_dir = repo_dir
        self.allowed_signers = allowed_signers

    def _git(self, *args: str, check: bool = True, binary: bool = False,
             timeout: int = 120) -> subprocess.CompletedProcess:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "LC_ALL": "C",
            # Only our own settings count, never ~/.gitconfig or /etc/gitconfig.
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        cmd = ["git", "-C", str(self.repo_dir), "-c", "gpg.format=ssh"]
        if self.allowed_signers:
            cmd += ["-c", f"gpg.ssh.allowedSignersFile={self.allowed_signers}"]
        try:
            p = subprocess.run(cmd + list(args), capture_output=True, text=not binary,
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
        p = self._git("verify-tag", tag, check=False)
        detail = " ".join(p.stderr.split())
        return p.returncode == 0, detail

    def _is_ancestor(self, ancestor: str, commit: str) -> bool:
        return self._git("merge-base", "--is-ancestor", ancestor, commit,
                         check=False).returncode == 0

    def read_files(self, commit: str) -> dict[str, str]:
        path = self.settings["path"].strip("/")
        p = self._git("archive", "--format=tar", commit, "--", path, check=False, binary=True)
        if p.returncode != 0:
            if b"did not match any files" in p.stderr:
                return {}
            raise SyncError(f"git archive failed: {p.stderr.decode(errors='replace').strip()}")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(p.stdout)) as tar:
            for member in tar.getmembers():
                if member.isfile() and member.name.endswith((".yaml", ".yml")):
                    data = tar.extractfile(member).read()  # type: ignore[union-attr]
                    files[member.name.removeprefix(path + "/")] = data.decode("utf-8")
        return files

    def _load(self, commit: str, ref: str, result: SyncResult) -> bool:
        loaded = load_files(self.read_files(commit))
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
