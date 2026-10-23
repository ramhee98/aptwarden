"""Command execution on target hosts."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass

from aptwarden.config import HostConfig, SshSettings

# Commands run with a fixed locale so their output is parseable.
_ENV_PREFIX = ["env", "LC_ALL=C.UTF-8"]


class TransportError(Exception):
    """The host could not be reached or the command could not be started."""


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def check(self) -> CommandResult:
        if not self.ok:
            msg = self.stderr.strip() or self.stdout.strip() or "no output"
            raise TransportError(f"{shlex.join(self.argv)} exited {self.returncode}: {msg}")
        return self


class Transport(ABC):
    def __init__(self, host: str):
        self.host = host

    @abstractmethod
    def run(self, argv: list[str], timeout: float | None = None) -> CommandResult: ...

    def close(self) -> None:  # noqa: B027 - optional hook
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class LocalTransport(Transport):
    def __init__(self, host: str, timeout: float = 300):
        super().__init__(host)
        self.timeout = timeout

    def run(self, argv: list[str], timeout: float | None = None) -> CommandResult:
        try:
            p = subprocess.run(
                _ENV_PREFIX + argv,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise TransportError(f"{shlex.join(argv)}: {e}") from e
        return CommandResult(argv, p.returncode, p.stdout, p.stderr)


class SshTransport(Transport):
    """Runs commands through the OpenSSH client with connection multiplexing,
    so ssh_config, known_hosts, ProxyJump etc. work as usual."""

    def __init__(self, host: str, address: str, settings: SshSettings, control_dir: str):
        super().__init__(host)
        self.address = address
        self.settings = settings
        self.control_path = os.path.join(control_dir, "%C")

    def base_argv(self, *extra: str) -> list[str]:
        """ssh argv up to and including the destination; ``extra`` goes before it."""
        s = self.settings
        opts = {
            "BatchMode": "yes",
            "ConnectTimeout": str(s.connect_timeout),
            "ControlMaster": "auto",
            "ControlPath": self.control_path,
            "ControlPersist": "60",
            "StrictHostKeyChecking": s.strict_host_key_checking,
            "ServerAliveInterval": "15",
            "ServerAliveCountMax": "4",
        }
        if s.known_hosts_file:
            opts["UserKnownHostsFile"] = s.known_hosts_file
        if s.identity_file:
            opts["IdentityFile"] = s.identity_file
            opts["IdentitiesOnly"] = "yes"
        opts.update({k: str(v) for k, v in s.options.items()})
        argv = ["ssh"]
        for k, v in opts.items():
            argv += ["-o", f"{k}={v}"]
        return argv + list(extra) + ["-p", str(s.port), "-l", s.user, self.address]

    def run(self, argv: list[str], timeout: float | None = None) -> CommandResult:
        # ssh joins its arguments into one string for the remote shell, so the
        # command must be quoted as a whole.
        cmd = self.base_argv() + ["--", shlex.join(_ENV_PREFIX + argv)]
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.settings.command_timeout,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise TransportError(f"ssh {self.address}: {e}") from e
        if p.returncode == 255:
            raise TransportError(f"ssh {self.address}: {p.stderr.strip() or 'connection failed'}")
        return CommandResult(argv, p.returncode, p.stdout, p.stderr)

    def close(self) -> None:
        subprocess.run(
            self.base_argv("-O", "exit"),
            capture_output=True,
            timeout=10,
            check=False,
        )


def known_host_keys(address: str, port: int, known_hosts_file: str | None) -> list[str]:
    """Fingerprints recorded for a host in known_hosts (hashed entries included),
    e.g. ["SHA256:abc... (ED25519)"]. Empty if the host is unknown."""
    name = address if port == 22 else f"[{address}]:{port}"
    cmd = ["ssh-keygen", "-l", "-F", name]
    if known_hosts_file:
        cmd += ["-f", known_hosts_file]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []
    keys = []
    for line in p.stdout.splitlines():  # "<host> <TYPE> <fingerprint>"
        parts = line.split()
        if line.startswith("#") or len(parts) < 3:
            continue
        keys.append(f"{parts[2]} ({parts[1]})")
    return keys


class TransportFactory:
    """Creates transports and owns the directory for SSH control sockets."""

    def __init__(self):
        base = os.environ.get("RUNTIME_DIRECTORY") or None
        # Socket paths are limited to ~104 bytes, so keep the directory short.
        self._tmp = tempfile.TemporaryDirectory(prefix="aptw-", dir=base)

    def create(self, host: HostConfig) -> Transport:
        if host.transport == "local":
            return LocalTransport(host.name, timeout=host.ssh.command_timeout)
        return SshTransport(host.name, host.address, host.ssh, self._tmp.name)

    def cleanup(self) -> None:
        self._tmp.cleanup()
