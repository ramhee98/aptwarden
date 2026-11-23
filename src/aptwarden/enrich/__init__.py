"""Severity normalisation and KEV flagging for findings."""

from __future__ import annotations

from aptwarden.enrich.cvss import CvssLookup, CvssResult, is_cve
from aptwarden.enrich.kev import Kev
from aptwarden.models import Finding, FindingStatus, Severity

# Debian's urgencies and Ubuntu's priorities (critical, negligible)
_URGENCY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
# The distribution knows the issue does not matter for its build: decides on its own,
# before CVSS. Debian says "unimportant", Ubuntu "negligible".
_NEGLIGIBLE = frozenset({"unimportant", "negligible"})
_URGENCY_NAME = {"debian": "debian urgency", "ubuntu": "ubuntu priority"}


def normalize_urgency(urgency: str | None) -> str:
    # The tracker marks derived urgencies with trailing asterisks ("low**").
    return (urgency or "").strip().rstrip("*").strip().lower()


def assess(finding: Finding, cvss: CvssResult | None, distro: str = "debian") -> None:
    """Set severity and reason on a finding. Order (docs/architecture.md):
    custom definition > Debian "unimportant" / Ubuntu "negligible" > CVSS >
    Debian urgency / Ubuntu priority > unknown."""
    urgency = normalize_urgency(finding.urgency)
    if cvss is not None:
        finding.cvss_score = cvss.score
        finding.cvss_vector = cvss.vector
    if finding.definition:
        return  # a custom definition set the severity and has the last word
    if urgency in _NEGLIGIBLE:
        finding.severity = Severity.LOW
        finding.severity_reason = f"{distro}: {urgency}"
    elif cvss is not None and cvss.score:
        finding.severity = Severity.from_cvss(cvss.score)
        finding.severity_reason = f"cvss {cvss.version or '?'} {cvss.score} ({cvss.origin})"
    elif urgency in _URGENCY:
        finding.severity = _URGENCY[urgency]
        finding.severity_reason = f"{_URGENCY_NAME.get(distro, 'urgency')}: {urgency}"
    else:
        finding.severity = Severity.UNKNOWN
        finding.severity_reason = "no score available"


def cve_ids(finding: Finding) -> list[str]:
    ids = [finding.vuln_id] + finding.aliases
    return [i for i in dict.fromkeys(ids) if is_cve(i)]


def enrich(findings_by_host: dict[str, list[Finding]], cvss: CvssLookup | None,
           kev: Kev | None, distros: dict[str, str] | None = None) -> None:
    """``distros`` maps hosts to their distribution (default debian), which
    names the urgency in the severity reason."""
    all_findings = [f for fs in findings_by_host.values() for f in fs]
    distro_of = {id(f): (distros or {}).get(host, "debian")
                 for host, fs in findings_by_host.items() for f in fs}
    scores: dict[str, CvssResult] = {}
    if cvss is not None:
        # Fixable findings first: they drive actions, so they get NVD's budget.
        # "unimportant" / "negligible" decide the severity on their own, no score needed.
        ordered = sorted(all_findings, key=lambda f: f.status != FindingStatus.FIXABLE)
        wanted = [c for f in ordered if normalize_urgency(f.urgency) not in _NEGLIGIBLE
                  for c in cve_ids(f)[:1]]
        scores = cvss.lookup(wanted)
    for f in all_findings:
        ids = cve_ids(f)
        assess(f, scores.get(ids[0]) if ids else None, distro_of[id(f)])
        if kev is not None:
            f.kev = any(kev.contains(i) for i in ids)
