"""Severity normalisation and KEV flagging for findings."""

from __future__ import annotations

from aptwarden.enrich.cvss import CvssLookup, CvssResult
from aptwarden.enrich.kev import Kev
from aptwarden.models import Finding, FindingStatus, Severity

_URGENCY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unimportant": Severity.LOW,
}


def normalize_urgency(urgency: str | None) -> str:
    # The tracker marks derived urgencies with trailing asterisks ("low**").
    return (urgency or "").strip().rstrip("*").strip().lower()


def assess(finding: Finding, cvss: CvssResult | None) -> None:
    """Set severity and reason on a finding. Order (docs/architecture.md):
    Debian "unimportant" > CVSS > Debian urgency > unknown."""
    urgency = normalize_urgency(finding.urgency)
    if cvss is not None:
        finding.cvss_score = cvss.score
        finding.cvss_vector = cvss.vector
    if urgency == "unimportant":
        finding.severity = Severity.LOW
        finding.severity_reason = "debian: unimportant"
    elif cvss is not None and cvss.score:
        finding.severity = Severity.from_cvss(cvss.score)
        finding.severity_reason = f"cvss {cvss.version or '?'} {cvss.score} ({cvss.origin})"
    elif urgency in _URGENCY:
        finding.severity = _URGENCY[urgency]
        finding.severity_reason = f"debian urgency: {urgency}"
    else:
        finding.severity = Severity.UNKNOWN
        finding.severity_reason = "no score available"


def cve_ids(finding: Finding) -> list[str]:
    ids = [finding.vuln_id] + finding.aliases
    return [i for i in dict.fromkeys(ids) if i.startswith("CVE-")]


def enrich(findings_by_host: dict[str, list[Finding]], cvss: CvssLookup | None,
           kev: Kev | None) -> None:
    all_findings = [f for fs in findings_by_host.values() for f in fs]
    scores: dict[str, CvssResult] = {}
    if cvss is not None:
        # Fixable findings first: they drive actions, so they get NVD's budget.
        # "unimportant" decides the severity on its own, no score needed.
        ordered = sorted(all_findings, key=lambda f: f.status != FindingStatus.FIXABLE)
        wanted = [c for f in ordered if normalize_urgency(f.urgency) != "unimportant"
                  for c in cve_ids(f)[:1]]
        scores = cvss.lookup(wanted)
    for f in all_findings:
        ids = cve_ids(f)
        assess(f, scores.get(ids[0]) if ids else None)
        if kev is not None:
            f.kev = any(kev.contains(i) for i in ids)
