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


def snapshot_name(run_id: str) -> str:
    # Proxmox: starts with a letter, [A-Za-z0-9_-], at most 40 characters.
    return (PREFIX + run_id.replace("-", "_"))[:40]


class SnapshotProvider(ABC):
    name = ""

    @abstractmethod
    def check(self) -> list[str]:
        """Problems that prevent snapshots (empty list = ready)."""

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
