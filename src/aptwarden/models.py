"""Core data types shared by inventory, sources, enrichment and reporting."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import IntEnum, StrEnum


class Severity(IntEnum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.UNKNOWN


class FindingStatus(StrEnum):
    FIXABLE = "fixable"  # fixed version is available in a repository of the release
    FIX_PENDING = "fix-pending"  # fixed in Debian, not yet published (e.g. next point release)
    NO_FIX = "no-fix"  # vulnerable, no fix in this release
    UNDETERMINED = "undetermined"  # Debian has not determined whether the release is affected


@dataclass(frozen=True)
class Package:
    name: str  # binary package, with ":arch" qualifier for multi-arch: same packages
    version: str
    arch: str
    source: str
    source_version: str
    status: str  # dpkg db:Status-Abbrev, e.g. "ii "


@dataclass
class HostInventory:
    host: str
    os_id: str
    os_version_id: str
    codename: str
    debian_version: str
    arch: str
    packages: list[Package]
    facts: dict[str, str] = field(default_factory=dict)
    collected_at: str = ""

    def source_packages(self) -> dict[tuple[str, str], list[str]]:
        """Map (source package, source version) to the installed binaries built from it."""
        result: dict[tuple[str, str], list[str]] = defaultdict(list)
        for p in self.packages:
            result[(p.source, p.source_version)].append(p.name)
        return dict(result)

    def summary(self) -> dict:
        return {
            "os_id": self.os_id,
            "os_version_id": self.os_version_id,
            "codename": self.codename,
            "debian_version": self.debian_version,
            "arch": self.arch,
            "package_count": len(self.packages),
            "facts": self.facts,
            "collected_at": self.collected_at,
        }


@dataclass
class Finding:
    vuln_id: str  # CVE-..., TEMP-... (Debian), later AW-... (custom definitions)
    source_package: str
    installed_version: str  # source version, see docs/architecture.md
    status: FindingStatus
    fixed_version: str | None = None
    binaries: list[str] = field(default_factory=list)
    origins: list[str] = field(default_factory=list)  # source plugins that reported it
    aliases: list[str] = field(default_factory=list)
    urgency: str | None = None  # Debian tracker urgency
    nodsa: bool = False
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    severity_reason: str = ""
    cvss_score: float | None = None
    cvss_vector: str | None = None
    kev: bool = False
    first_seen: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source_package, self.installed_version, self.vuln_id)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = str(self.status)
        d["severity"] = str(self.severity)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        d = dict(d)
        d["status"] = FindingStatus(d["status"])
        d["severity"] = Severity.parse(d["severity"])
        return cls(**d)
