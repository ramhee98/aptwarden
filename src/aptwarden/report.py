"""Text and JSON rendering of run results."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from aptwarden import debversion
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.sources import SourceStatus
from aptwarden.state import HostRecord

_SEVERITIES = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.UNKNOWN]


@dataclass
class PackageGroup:
    """All findings of one installed source package version."""

    source_package: str
    installed_version: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return max(f.severity for f in self.findings)

    @property
    def kev(self) -> bool:
        return any(f.kev for f in self.findings)

    @property
    def target_version(self) -> str | None:
        """Lowest version that fixes every finding in the group."""
        return debversion.max_version(f.fixed_version for f in self.findings if f.fixed_version)

    @property
    def top(self) -> Finding:
        return max(self.findings, key=_finding_rank)


def is_visible(group: PackageGroup, min_severity: Severity) -> bool:
    """Only hide what is known to be below the threshold: KEV and entirely
    unscored packages are always shown ("unknown" means "look at it")."""
    return group.kev or group.severity >= min_severity or group.severity == Severity.UNKNOWN


def _finding_rank(f: Finding):
    return (f.severity, f.kev, f.cvss_score or 0.0, f.vuln_id)


def group_findings(findings: list[Finding]) -> list[PackageGroup]:
    groups: dict[tuple[str, str], PackageGroup] = {}
    for f in findings:
        key = (f.source_package, f.installed_version)
        groups.setdefault(key, PackageGroup(*key)).findings.append(f)
    for g in groups.values():
        g.findings.sort(key=_finding_rank, reverse=True)
    return sorted(
        groups.values(),
        key=lambda g: (-g.severity, not g.kev, -(g.top.cvss_score or 0.0), g.source_package),
    )


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "never"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M UTC")


def format_table(rows: list[list[str]], indent: str = "  ") -> list[str]:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    out = []
    for r in rows:
        cells = [c.ljust(w) for c, w in zip(r, widths, strict=True)]
        out.append((indent + "  ".join(cells)).rstrip())
    return out


def _top_label(f: Finding) -> str:
    parts = [f.vuln_id]
    if f.cvss_score is not None:
        parts.append(f"{f.cvss_score:.1f}")
    if f.kev:
        parts.append("KEV")
    return " ".join(parts)


def truncate(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"


def render_host(rec: HostRecord, min_severity: Severity, show_all: bool,
                show_cves: bool) -> list[str]:
    s = rec.summary
    if not rec.ok:
        return [f"{rec.host}  {rec.address or ''}", f"  ERROR: {rec.error}", ""]
    header = (f"{rec.host}  {rec.address or ''}  Debian {s.get('debian_version', '?')} "
              f"({s.get('codename', '?')})  {s.get('package_count', 0)} packages  "
              f"scanned {rec.scanned_at}")
    lines = [header]
    lines += [f"  ! {w}" for w in rec.warnings]

    by_status: dict[FindingStatus, list[Finding]] = {st: [] for st in FindingStatus}
    for f in rec.findings:
        by_status[f.status].append(f)
    fixable = by_status[FindingStatus.FIXABLE]
    fix_groups = group_findings(fixable)
    counts = Counter(f.severity for f in fixable)
    sev_summary = " · ".join(f"{sev} {counts[sev]}" for sev in _SEVERITIES if counts[sev])
    kev_count = sum(1 for f in fixable if f.kev)
    lines.append(
        f"  fixable now: {len(fixable)} vulnerabilities in {len(fix_groups)} packages"
        + (f"  [{sev_summary}]" if sev_summary else "")
        + (f"  KEV {kev_count}" if kev_count else "")
    )
    lines.append(
        f"  not fixable: fix pending {len(by_status[FindingStatus.FIX_PENDING])} · "
        f"no fix {len(by_status[FindingStatus.NO_FIX])} · "
        f"undetermined {len(by_status[FindingStatus.UNDETERMINED])}"
    )

    shown = [g for g in fix_groups if is_visible(g, min_severity)]
    if shown:
        lines.append("")
        lines += _group_table(shown, "FIXED", show_cves)
    hidden = len(fix_groups) - len(shown)
    if hidden:
        lines.append(f"  … {hidden} more fixable packages below {min_severity} "
                     f"(--min-severity low to show)")

    if show_all:
        other = [f for st, fs in by_status.items() if st != FindingStatus.FIXABLE for f in fs]
        groups = [g for g in group_findings(other) if is_visible(g, min_severity)]
        if groups:
            lines += ["", "  not fixable yet:"]
            lines += _group_table(groups, "STATUS", show_cves, status_column=True)
    lines.append("")
    return lines


def _group_table(groups: list[PackageGroup], last_header: str, show_cves: bool,
                 status_column: bool = False) -> list[str]:
    rows = [["SEVERITY", "PACKAGE", "INSTALLED", last_header, "VULNS", "TOP"]]
    for g in groups:
        if status_column:
            statuses = Counter(str(f.status) for f in g.findings)
            last = ",".join(sorted(statuses))
        else:
            last = g.target_version or "?"
        rows.append([str(g.severity), g.source_package, g.installed_version, last,
                     str(len(g.findings)), _top_label(g.top)])
    table = format_table(rows)
    if not show_cves:
        return table
    out = table[:1]
    for g, line in zip(groups, table[1:], strict=True):
        out.append(line)
        for f in g.findings:
            score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
            flag = " KEV" if f.kev else "    "
            out.append(f"      {f.vuln_id:<18} {str(f.severity):<8} {score:>4}{flag}  "
                       f"{truncate(f.description, 90)}")
    return out


def render_text(hosts: list[HostRecord], sources: list[SourceStatus], *,
                min_severity: Severity, show_all: bool = False, show_cves: bool = False,
                title: str = "", notes: list[str] | None = None) -> str:
    lines = []
    if title:
        lines += [title, ""]
    for s in sources:
        state = "ok" if s.ok else "UNAVAILABLE"
        detail = f"checked {_fmt_ts(s.checked_at)}" if s.checked_at else ""
        if s.message:
            detail = (detail + "; " if detail else "") + s.message
        lines.append(f"source {s.name}: {state}" + (f" ({detail})" if detail else ""))
        lines += [f"  ! {w}" for w in s.warnings]
    if sources and not any(s.ok for s in sources if s.name != "kev"):
        lines.append("!! NO VULNERABILITY DATA AVAILABLE: results below are NOT a clean bill "
                     "of health")
    lines += [f"note: {n}" for n in notes or []]
    lines.append("")
    for rec in hosts:
        lines += render_host(rec, min_severity, show_all, show_cves)
    return "\n".join(lines).rstrip() + "\n"


def host_to_dict(rec: HostRecord) -> dict:
    counts = Counter(str(f.status) for f in rec.findings)
    return {
        "name": rec.host,
        "address": rec.address,
        "ok": rec.ok,
        "error": rec.error,
        "run_id": rec.run_id,
        "scanned_at": rec.scanned_at,
        "warnings": rec.warnings,
        "summary": rec.summary,
        "counts": dict(counts),
        "findings": [f.to_dict() for f in rec.findings],
    }


def render_json(hosts: list[HostRecord], sources: list[SourceStatus], **meta) -> str:
    doc = {**meta, "sources": [s.to_dict() for s in sources],
           "hosts": [host_to_dict(h) for h in hosts]}
    return json.dumps(doc, indent=2) + "\n"
