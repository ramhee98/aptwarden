"""Decide what to patch on a host.

1. select findings: fixable, allowed by the host policy (severity or KEV), not
   restricted by a custom definition (action "report")
2. group them by installed source package; every installed binary of that
   source is upgraded together, so the set stays consistent
3. take the host's apt candidates and resolve their *source* versions (binary
   and source versions can differ by epoch or binNMU); a candidate must reach
   the fixed version and must not be blocked by a definition
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aptwarden import debversion
from aptwarden.definitions import Definition
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.patch.apt import base_name


@dataclass
class PlanItem:
    source_package: str
    installed_version: str
    fixed_version: str  # highest fixed version among the selected findings
    severity: Severity
    vulns: list[str]
    binaries: list[str]  # installed names, e.g. libssl3t64:amd64
    targets: dict[str, str] = field(default_factory=dict)  # binary -> candidate version
    target_source_version: str | None = None
    skipped: str | None = None

    def to_dict(self) -> dict:
        return {"source_package": self.source_package, "installed": self.installed_version,
                "fixed": self.fixed_version, "severity": str(self.severity),
                "vulns": self.vulns, "binaries": self.binaries, "targets": self.targets,
                "target_source_version": self.target_source_version, "skipped": self.skipped}


def select(findings: list[Finding], policy: dict) -> list[Finding]:
    allowed = {Severity.parse(s) for s in policy["auto_patch_severities"]}
    return [
        f for f in findings
        if f.status == FindingStatus.FIXABLE and f.fixed_version
        and f.action != "report"  # a definition restricted this vulnerability to reporting
        and (f.severity in allowed or (policy["auto_patch_kev"] and f.kev))
    ]


def group(findings: list[Finding]) -> list[PlanItem]:
    items: dict[tuple[str, str], PlanItem] = {}
    for f in findings:
        key = (f.source_package, f.installed_version)
        item = items.get(key)
        if item is None:
            item = items[key] = PlanItem(f.source_package, f.installed_version,
                                         f.fixed_version, f.severity, [], [])
        item.vulns.append(f.vuln_id)
        item.binaries = sorted(set(item.binaries) | set(f.binaries))
        item.severity = max(item.severity, f.severity)
        if debversion.compare(f.fixed_version, item.fixed_version) > 0:
            item.fixed_version = f.fixed_version
    return sorted(items.values(), key=lambda i: (-i.severity, i.source_package))


def parse_show(text: str) -> dict[tuple[str, str], tuple[str, str]]:
    """``apt-cache show pkg=ver...`` -> {(package, version): (source, source_version)}."""
    result = {}
    for stanza in re.split(r"\n\s*\n", text):
        fields = {}
        for line in stanza.splitlines():
            key, sep, value = line.partition(":")
            if sep and not line[0].isspace():
                fields[key] = value.strip()
        if "Package" not in fields or "Version" not in fields:
            continue
        source, source_version = fields["Package"], fields["Version"]
        if "Source" in fields:
            m = re.match(r"^(\S+)(?:\s+\((\S+)\))?$", fields["Source"])
            if m:
                source = m.group(1)
                source_version = m.group(2) or fields["Version"]
        result[(fields["Package"], fields["Version"])] = (source, source_version)
    return result


def blocked_by(definitions: list[Definition], source: str, release: str,
               version: str) -> Definition | None:
    for d in definitions:
        if d.action != "block" or d.package != source or d.expired():
            continue
        verdict = d.evaluate(release, version)
        if verdict and verdict[0]:
            return d
    return None


def resolve(item: PlanItem, candidates: dict[str, str | None],
            installed: dict[str, str], sources: dict[tuple[str, str], tuple[str, str]],
            definitions: list[Definition], release: str) -> None:
    """Fill targets or mark the item as skipped. ``candidates`` and
    ``installed`` are keyed by the installed binary name."""
    targets = {}
    for binary in item.binaries:
        cand = candidates.get(binary) or candidates.get(base_name(binary))
        if cand and cand != installed.get(binary):
            targets[binary] = cand
    if not targets:
        item.skipped = "no newer candidate version in the host's apt sources"
        return
    source_versions = set()
    for binary, cand in targets.items():
        src = sources.get((base_name(binary), cand))
        if src is None or src[0] != item.source_package:
            item.skipped = (f"candidate {binary} {cand} does not belong to source "
                            f"{item.source_package}")
            return
        source_versions.add(src[1])
    if len(source_versions) != 1:
        item.skipped = f"candidates come from different source versions: {sorted(source_versions)}"
        return
    target = source_versions.pop()
    item.target_source_version = target
    if debversion.compare(target, item.fixed_version) < 0:
        item.skipped = (f"candidate {target} does not reach the fixed version "
                        f"{item.fixed_version} (security repository missing?)")
        return
    block = blocked_by(definitions, item.source_package, release, target)
    if block:
        item.skipped = f"candidate {target} is blocked by {block.id}"
        return
    item.targets = targets
