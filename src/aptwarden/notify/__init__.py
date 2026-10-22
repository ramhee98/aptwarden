"""Notifications: a summary per run and immediate alerts.

Alerts fire for new findings at or above ``notify.alert.min_severity`` or
listed in CISA KEV, for hosts that start failing, and when no vulnerability
data is available at all. Each (host, source package, vulnerability) is
alerted once, then again after ``remind_after``. A failed delivery is retried
on the next run.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from aptwarden import report
from aptwarden.config import Config, parse_duration
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.state import HostRecord, State

if TYPE_CHECKING:
    from aptwarden.runner import RunReport

log = logging.getLogger(__name__)

TRACKER_URL = "https://security-tracker.debian.org/tracker/"
MAX_LISTED = 50  # findings listed per section before truncating


class NotifyError(Exception):
    pass


@dataclass
class Message:
    kind: str  # "summary" | "alert" | "test"
    subject: str
    body: str


class Notifier(ABC):
    name: str = ""

    @abstractmethod
    def send(self, msg: Message) -> None:
        """Deliver the message or raise NotifyError."""


@dataclass
class HostChanges:
    """Differences to the host's previous successful scan."""

    first_scan: bool = False
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    newly_failed: bool = False
    recovered: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.new or self.resolved or self.newly_failed or self.recovered)


def build_notifiers(cfg: Config) -> list[Notifier]:
    from aptwarden.notify.email import EmailNotifier

    notifiers: list[Notifier] = []
    if cfg.notify["email"].get("enabled"):
        notifiers.append(EmailNotifier(cfg.notify["email"], cfg.base_dir))
    return notifiers


def alert_candidates(findings: list[Finding], alert_cfg: dict) -> list[Finding]:
    min_severity = Severity.parse(alert_cfg["min_severity"])
    return [
        f for f in findings
        if f.status != FindingStatus.UNDETERMINED
        and (f.severity >= min_severity or (alert_cfg.get("kev", True) and f.kev)
             or f.action == "block")  # a known-bad version is installed
    ]


def _fix_text(f: Finding) -> str:
    if f.status == FindingStatus.FIXABLE:
        return f"fixed in {f.fixed_version}"
    if f.status == FindingStatus.FIX_PENDING:
        return f"fix pending ({f.fixed_version}, not published yet)"
    return "no fix available yet"


def _finding_lines(f: Finding, detail: bool) -> list[str]:
    score = f" {f.cvss_score:.1f}" if f.cvss_score is not None else ""
    kev = "  KEV" if f.kev else ""
    definition = f"  [{f.definition} {f.action}]" if f.definition else ""
    lines = [f"  {f.vuln_id}  {f.severity}{score}{kev}{definition}  {f.source_package} "
             f"{f.installed_version}: {_fix_text(f)}"]
    if detail:
        if f.description:
            lines.append(f"      {report.truncate(f.description, 200)}")
        lines.append(f"      {TRACKER_URL}{f.vuln_id}")
    return lines


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity, not f.kev, -(f.cvss_score or 0),
                                           f.source_package, f.vuln_id))


def compose_alert(prefix: str, run: RunReport, alerts: dict[str, list[Finding]],
                  failed: list[HostRecord]) -> Message | None:
    no_data = not run.data_available
    source_alerts = [(s.name, a) for s in run.sources for a in s.alerts]
    if not (alerts or failed or no_data or source_alerts):
        return None
    parts = []
    lines = [f"aptwarden alert · run {run.run_id} · {run.started_at}", ""]
    if source_alerts:
        parts.append("source problems")
        lines.append("Problems with vulnerability sources:")
        lines += [f"  {name}: {a}" for name, a in source_alerts]
        lines.append("")
    if no_data:
        parts.append("no vulnerability data")
        lines += ["NO VULNERABILITY DATA: every source failed, hosts could not be checked."]
        lines += [f"  source {s.name}: {s.message or 'unavailable'}"
                  for s in run.sources if not s.ok]
        lines.append("")
    if failed:
        parts.append(f"{len(failed)} host(s) unreachable")
        lines.append("Hosts that could not be scanned:")
        lines += [f"  {h.host} ({h.address}): {h.error}" for h in failed]
        lines.append("")
    if alerts:
        total = sum(len(v) for v in alerts.values())
        parts.append(f"{total} critical/KEV/blocked vulnerabilities on "
                     f"{', '.join(sorted(alerts))}")
        lines += ["Critical, known-exploited or blocked vulnerabilities (new, or reminder):", ""]
        for host in sorted(alerts):
            rec = next(h for h in run.hosts if h.host == host)
            lines.append(f"{host} ({rec.address})")
            findings = _sorted(alerts[host])
            for f in findings[:MAX_LISTED]:
                lines += _finding_lines(f, detail=True)
            if len(findings) > MAX_LISTED:
                lines.append(f"  … and {len(findings) - MAX_LISTED} more "
                             f"(aptwarden status --host {host} --cves)")
            lines.append("")
    return Message("alert", f"{prefix} ALERT: {'; '.join(parts)}", "\n".join(lines))


def compose_summary(prefix: str, run: RunReport, cfg: Config) -> Message:
    min_severity = Severity.parse(cfg.report["min_severity"])
    rows = [["HOST", "FIXABLE", "CRITICAL", "HIGH", "KEV", "NEW", "RESOLVED"]]
    totals: Counter = Counter()
    errors = []
    for h in run.hosts:
        if not h.ok:
            errors.append(h)
            rows.append([h.host, "ERROR", "-", "-", "-", "-", "-"])
            continue
        ch = run.changes.get(h.host, HostChanges())
        fixable = [f for f in h.findings if f.status == FindingStatus.FIXABLE]
        c = Counter(f.severity for f in fixable)
        kev = sum(1 for f in fixable if f.kev)
        totals.update(fixable=len(fixable), critical=c[Severity.CRITICAL], kev=kev,
                      new=len(ch.new))
        rows.append([h.host, str(len(fixable)), str(c[Severity.CRITICAL]),
                     str(c[Severity.HIGH]), str(kev),
                     "first scan" if ch.first_scan else str(len(ch.new)), str(len(ch.resolved))])

    problem = "PROBLEM: " if run.status != "ok" else ""
    subject = (f"{prefix} {problem}{len(run.hosts)} hosts · {totals['fixable']} fixable "
               f"({totals['critical']} critical, {totals['kev']} KEV) · {totals['new']} new")
    lines = [f"aptwarden summary · run {run.run_id} · status {run.status}", ""]
    lines += report.format_table(rows, indent="")
    for h in errors:
        lines.append(f"  {h.host}: {h.error}")
    lines += [f"note: {n}" for n in run.notes]

    new_lines, resolved_lines = [], []
    for h in run.hosts:
        ch = run.changes.get(h.host)
        if not ch:
            continue
        relevant = [f for f in ch.new if f.status == FindingStatus.FIXABLE
                    or f.severity >= min_severity or f.kev]
        for f in _sorted(relevant)[:MAX_LISTED]:
            new_lines += [f"  {h.host}" + line[1:] for line in _finding_lines(f, detail=False)]
        if len(relevant) > MAX_LISTED:
            new_lines.append(f"  {h.host}: … and {len(relevant) - MAX_LISTED} more")
        if ch.resolved:
            pkgs = sorted({f.source_package for f in ch.resolved})
            resolved_lines.append(f"  {h.host}: {len(ch.resolved)} vulnerabilities in "
                                  f"{', '.join(pkgs[:10])}" + (" …" if len(pkgs) > 10 else ""))
        if ch.recovered:
            resolved_lines.append(f"  {h.host}: reachable again")
    if new_lines:
        lines += ["", "New since the last scan (fixable or above threshold):"] + new_lines
    if resolved_lines:
        lines += ["", "Resolved since the last scan:"] + resolved_lines

    lines += ["", "-" * 72, ""]
    lines.append(report.render_text(run.hosts, run.sources, min_severity=min_severity,
                                    show_all=cfg.report["show"] == "all"))
    return Message("summary", subject, "\n".join(lines))


class Dispatcher:
    def __init__(self, cfg: Config, state: State, notifiers: list[Notifier] | None = None):
        self.cfg = cfg
        self.state = state
        self.notifiers = build_notifiers(cfg) if notifiers is None else notifiers

    def send(self, msg: Message) -> list[str]:
        """Send through every notifier; returns error messages."""
        errors = []
        for n in self.notifiers:
            try:
                n.send(msg)
                log.info("notification sent", extra={"notifier": n.name, "kind": msg.kind})
            except NotifyError as e:
                errors.append(f"{n.name}: {e}")
                log.error("notification failed", extra={"notifier": n.name, "kind": msg.kind,
                                                        "error": str(e)})
        return errors

    def dispatch(self, run: RunReport) -> list[str]:
        if not self.notifiers:
            return []
        ncfg = self.cfg.notify
        alert_cfg = ncfg["alert"]
        prefix = ncfg["subject_prefix"]
        remind = parse_duration(alert_cfg["remind_after"])

        alerts: dict[str, list[Finding]] = {}
        for h in run.hosts:
            if h.ok:
                due = self.state.alert_due(h.host, alert_candidates(h.findings, alert_cfg),
                                           remind)
                if due:
                    alerts[h.host] = due
        failed = [h for h in run.hosts if not h.ok and alert_cfg["host_errors"]
                  and run.changes.get(h.host, HostChanges(newly_failed=True)).newly_failed]

        errors: list[str] = []
        alert = compose_alert(prefix, run, alerts, failed)
        if alert is not None:
            alert_errors = self.send(alert)
            errors += alert_errors
            if not alert_errors:
                for host, findings in alerts.items():
                    self.state.mark_alerted(host, findings)

        policy = ncfg["summary"]
        changed = any(c.changed for c in run.changes.values())
        if policy == "always" or (policy == "changes" and (changed or alert is not None
                                                           or run.status != "ok")):
            errors += self.send(compose_summary(prefix, run, self.cfg))
        return errors
