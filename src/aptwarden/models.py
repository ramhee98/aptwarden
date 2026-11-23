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
    # Only produced by custom definitions to overrule other sources; never stored.
    NOT_AFFECTED = "not-affected"


DISTROS = {"debian": "Debian", "ubuntu": "Ubuntu"}


def release_label(summary: dict) -> str:
    """``Debian 13.1 (trixie)`` or ``Ubuntu 24.04.3 LTS (noble)`` from a host
    summary. Summaries stored before 0.10 have neither distro nor os_version."""
    distro = summary.get("distro") or "debian"
    version = summary.get("os_version") or summary.get("debian_version") or "?"
    return (f"{DISTROS.get(distro, distro)} {version} "
            f"({summary.get('codename') or '?'})")


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
    notes: list[str] = field(default_factory=list)  # from this scan's actions, not stored
    distro: str = "debian"  # one of DISTROS; Debian derivatives count as debian
    os_version: str = ""  # for display: "13.1" (Debian), "24.04.3 LTS" (Ubuntu)

    def source_packages(self) -> dict[tuple[str, str], list[str]]:
        """Map (source package, source version) to the installed binaries built from it."""
        result: dict[tuple[str, str], list[str]] = defaultdict(list)
        for p in self.packages:
            result[(p.source, p.source_version)].append(p.name)
        return dict(result)

    def apt_suites(self) -> set[str] | None:
        """Suites of the host's package sources (``trixie``, ``trixie-security``,
        ``noble-security``, ...), or None if they could not be read."""
        value = self.facts.get("apt_suites")
        return None if value is None else set(value.split())

    def release_label(self) -> str:
        return release_label(self.summary())

    def summary(self) -> dict:
        return {
            "distro": self.distro,
            "os_id": self.os_id,
            "os_version_id": self.os_version_id,
            "os_version": self.os_version,
            "codename": self.codename,
            # content of /etc/debian_version; on Ubuntu the Debian base, e.g. "trixie/sid"
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
    definition: str | None = None  # id of the custom definition that decided this finding
    action: str | None = None  # the definition's action: report | auto-patch | block
    # fixable, but the fixed version is only in these repositories (e.g. "trixie-security"),
    # and the host's apt sources lack them
    missing_source: str | None = None

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
