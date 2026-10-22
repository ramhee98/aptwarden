"""Merge findings reported by several sources for the same host."""

from __future__ import annotations

from dataclasses import replace

from aptwarden.models import Finding


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
    return sorted(merged.values(), key=lambda f: f.key)
