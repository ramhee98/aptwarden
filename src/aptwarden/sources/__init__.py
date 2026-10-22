"""Vulnerability source plugins.

A source refreshes its data into the cache and turns host inventories into
findings. Adding a source means subclassing ``Source`` and registering it in
``REGISTRY``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from aptwarden.cache import Cache
from aptwarden.http import HttpClient
from aptwarden.models import Finding, HostInventory


@dataclass
class SourceStatus:
    name: str
    ok: bool = True
    updated_at: float | None = None  # when the data last changed upstream / was loaded
    checked_at: float | None = None
    message: str = ""
    warnings: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)  # raise an immediate alert

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ok": self.ok,
            "updated_at": self.updated_at,
            "checked_at": self.checked_at,
            "message": self.message,
            "warnings": self.warnings,
            "alerts": self.alerts,
        }


class Source(ABC):
    name: str = ""
    # Lower wins when several sources report the same vulnerability.
    priority: int = 100

    def __init__(self, settings: dict, cache: Cache, http: HttpClient, offline: bool = False,
                 **context):
        self.settings = settings
        self.cache = cache
        self.http = http
        self.offline = offline
        self.context = context  # e.g. state, base_dir; for sources that need them

    @abstractmethod
    def refresh(self, force: bool = False) -> SourceStatus:
        """Update cached data if needed. Must not raise for network errors;
        report them in the returned status instead."""

    @abstractmethod
    def match(self, inventories: list[HostInventory]) -> dict[str, list[Finding]]:
        """Return findings per host name. Takes all hosts at once so sources
        can batch remote queries."""


# Sources that provide general vulnerability data. If none of them works, a run
# has no data, whatever custom definitions say.
CORE_SOURCES = frozenset({"debian_tracker", "osv"})


def build_sources(cfg_sources: dict, cache: Cache, http: HttpClient, offline: bool,
                  **context) -> list[Source]:
    from aptwarden.sources.custom import CustomSource
    from aptwarden.sources.debian_tracker import DebianTrackerSource
    from aptwarden.sources.osv import OsvSource

    registry: dict[str, type[Source]] = {
        CustomSource.name: CustomSource,
        DebianTrackerSource.name: DebianTrackerSource,
        OsvSource.name: OsvSource,
    }
    sources = [
        registry[name](settings, cache, http, offline, **context)
        for name, settings in cfg_sources.items()
        if settings.get("enabled", True)
    ]
    return sorted(sources, key=lambda s: s.priority)
