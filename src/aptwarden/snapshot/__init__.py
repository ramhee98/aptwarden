"""Snapshot providers: a safety net before patching.

``proxmox`` snapshots LXC containers and QEMU VMs through the Proxmox API.
``none`` is for hosts without snapshots, patching them needs an explicit
``allow_without_snapshot``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

# Only snapshots with this prefix that aptwarden recorded itself are ever
# rolled back to or deleted.
PREFIX = "aptw_"


class SnapshotError(Exception):
    pass


@dataclass(frozen=True)
class SnapshotRef:
    provider: str
    target: str  # provider specific, e.g. "R720-Server/lxc/139"
    name: str


@dataclass(frozen=True)
class GuestIdentity:
    """What the provider knows about the guest it snapshots, to make sure that it is
    the host aptwarden patches over SSH."""

    target: str
    name: str
    macs: frozenset[str]  # lower case, from the guest's network devices


def _short(hostname: str) -> str:
    return hostname.strip().split(".")[0].lower()


def identity_problem(guest: GuestIdentity, hostname: str, macs: set[str]) -> str | None:
    """None if the guest is the host with this hostname and these MAC addresses.

    A MAC address of the guest's configuration must be on the host. Only a guest
    without any falls back to its name, which must be the host's short hostname."""
    label = f"{guest.target} ({guest.name or 'no name'})"
    if guest.macs:
        if guest.macs & macs:
            return None
        return (f"{label} is not this host: none of its MAC addresses "
                f"({', '.join(sorted(guest.macs))}) is on {hostname or 'the host'}; "
                "check snapshot.vmid")
    if guest.name and _short(guest.name) == _short(hostname):
        return None
    return (f"{label} is not this host: it has no MAC address in its configuration and "
            f"its name is not the host's ({hostname or 'unknown'}); check snapshot.vmid")


def snapshot_name(run_id: str) -> str:
    # Proxmox: starts with a letter, [A-Za-z0-9_-], at most 40 characters.
    return (PREFIX + run_id.replace("-", "_"))[:40]


class SnapshotProvider(ABC):
    name = ""

    @abstractmethod
    def check(self) -> list[str]:
        """Problems that prevent snapshots (empty list = ready)."""

    def identity(self) -> GuestIdentity | None:
        """The guest the snapshots are of, None if the provider cannot tell."""
        return None

    @abstractmethod
    def create(self, name: str, description: str) -> SnapshotRef: ...

    @abstractmethod
    def rollback(self, ref: SnapshotRef) -> None:
        """Roll back and make sure the guest is running again."""

    @abstractmethod
    def delete(self, ref: SnapshotRef) -> None: ...

    @abstractmethod
    def list(self) -> list[str]:
        """Names of existing snapshots."""


class NoSnapshots(SnapshotProvider):
    name = "none"

    def check(self) -> list[str]:
        return []

    def create(self, name: str, description: str) -> SnapshotRef:
        raise SnapshotError("no snapshot provider configured")

    def rollback(self, ref: SnapshotRef) -> None:
        raise SnapshotError("no snapshot provider configured")

    def delete(self, ref: SnapshotRef) -> None:
        raise SnapshotError("no snapshot provider configured")

    def list(self) -> list[str]:
        return []
