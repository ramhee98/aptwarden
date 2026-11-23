"""Merge findings reported by several sources for the same host."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from aptwarden import debversion
from aptwarden.models import Finding, FindingStatus


def merge(per_source: list[tuple[int, list[Finding]]]) -> list[Finding]:
    """Merge ``[(priority, findings), ...]`` into one finding per
    (source package, installed version, vulnerability).

    The source with the lowest priority value decides status and versions;
    the others contribute origins, aliases and fields the winner lacks.
    """
    merged: dict[tuple[str, str, str], Finding] = {}
    for _priority, findings in sorted(per_source, key=lambda item: item[0]):
        for f in findings:
            current = merged.get(f.key)
            if current is None:
                merged[f.key] = replace(f, origins=list(f.origins), aliases=list(f.aliases),
                                        binaries=list(f.binaries))
                continue
            current.origins += [o for o in f.origins if o not in current.origins]
            current.aliases = sorted(set(current.aliases) | set(f.aliases))
            current.binaries = sorted(set(current.binaries) | set(f.binaries))
            if not current.description:
                current.description = f.description
            if not current.urgency:
                current.urgency = f.urgency
    # A custom definition saying "not affected" overrules every other source.
    kept = (f for f in merged.values() if f.status != FindingStatus.NOT_AFFECTED)
    return sorted(kept, key=lambda f: f.key)


def mark_missing_sources(findings: list[Finding], suites: set[str] | None,
                         repositories: Callable[[str], dict[str, str]]) -> None:
    """Set ``missing_source`` on fixable findings whose fixed version is only in
    repositories the host's apt sources lack (typically ``<codename>-security``).

    The status stays ``fixable``: the fix exists, the host has to add the source.
    ``repositories(source_package)`` gives the newest version per repository of the
    host's release. Unknown suites or repositories leave the findings alone.
    """
    if not suites:
        return
    cache: dict[str, dict[str, str]] = {}
    for f in findings:
        f.missing_source = None
        if f.status != FindingStatus.FIXABLE or not f.fixed_version:
            continue
        if f.source_package not in cache:
            cache[f.source_package] = repositories(f.source_package)
        try:
            having = [repo for repo, version in cache[f.source_package].items()
                      if debversion.compare(version, f.fixed_version) >= 0]
        except ValueError:
            continue
        if having and not any(repo in suites for repo in having):
            f.missing_source = ", ".join(sorted(having))
