"""Static, read-only HTML status page.

Rendered from state.db after every report and patch run, so it always shows
the latest state of every configured host. No JavaScript, no server-side code:
serve the file with any web server (e.g. an existing reverse proxy with
authentication). Everything from external sources is HTML-escaped and the
page forbids scripts through its Content-Security-Policy.
"""

from __future__ import annotations

import contextlib
import html
import json
import logging
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aptwarden import __version__
from aptwarden.config import Config, HostConfig
from aptwarden.definitions import Definition
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.patch import planner, window
from aptwarden.patch.runner import policy_skip_reason
from aptwarden.report import group_findings, truncate
from aptwarden.sources.custom import stored_definitions
from aptwarden.state import HostRecord, State

log = logging.getLogger(__name__)

TRACKER_URL = "https://security-tracker.debian.org/tracker/"
MAX_OTHER = 30  # not-fixable findings listed per host (above the report threshold)
# No scripts, no external resources, no forms.
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
       "form-action 'none'")

_CSS = """
:root{--bg:#fafafa;--fg:#1d1d1f;--muted:#6b6b70;--card:#fff;--line:#e3e3e6;
--crit:#b3261e;--high:#c25e00;--med:#8a6d00;--low:#3d6b35;--unk:#5f6368;--ok:#2e7d32;
--bad:#b3261e;--warn:#a15c00;--link:#0b57d0}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#e8e8ea;--muted:#9a9aa0;
--card:#1e1e21;--line:#333338;--crit:#ff6b62;--high:#ff9f43;--med:#e8c547;--low:#8fd18a;
--unk:#a0a4a8;--ok:#7bd88f;--bad:#ff6b62;--warn:#f0b35a;--link:#8ab4f8}}
*{box-sizing:border-box}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);
font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:24px 0 8px}
.muted{color:var(--muted)}a{color:var(--link)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.tile b{display:block;font-size:22px}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line)}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-weight:600;color:var(--muted);white-space:nowrap}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.sev{font-weight:600;white-space:nowrap}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}
.low{color:var(--low)}.unknown{color:var(--unk)}
.badge{display:inline-block;padding:0 6px;border-radius:4px;border:1px solid currentColor;
font-size:12px;white-space:nowrap}
.good{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;
margin:8px 0;padding:8px 12px}
summary{cursor:pointer;font-weight:600}
code{font-size:12px}
ul{margin:4px 0;padding-left:20px}
.trend svg{display:block;max-width:100%;height:auto;overflow:visible}
.trend .axis{stroke:var(--line);stroke-width:1}
.trend polyline{fill:none;stroke-width:1.5;stroke-linejoin:round}
.trend .total{stroke:var(--muted)}.trend .crit{stroke:var(--crit)}.trend .hi{stroke:var(--high)}
.trend circle{fill:var(--muted)}.trend circle.hit{fill:transparent;stroke:none}
.attention{background:var(--card);border:1px solid var(--bad);border-radius:8px;padding:8px 12px}
.attention li{margin:2px 0}
"""

_PATCH_CLASS = {"patched": "good", "dry-run": "muted", "nothing-to-do": "muted",
                "skipped": "muted", "aborted": "warn"}
# A latest patch run in one of these needs a human; rolled-back fixed itself.
ATTENTION_PATCH = ("needs-manual-rollback", "rollback-failed", "failed")
REPEATED_ABORTS = 2  # consecutive aborted patch runs before they need attention
PATCH_HISTORY = 5  # patch runs shown per host
HEALTH_LOOKBACK = 50  # patch runs searched for the latest healthcheck results
# health.CheckResult as stored: "systemd nginx.service: ok (active)"; the
# shortest check name, so a detail containing ": FAILED" stays in the detail
_CHECK = re.compile(r"^(?P<check>.*?): (?P<state>ok|FAILED)(?: \((?P<detail>.*)\))?$", re.S)


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _sev(sev: Severity) -> str:
    return f'<span class="sev {sev}">{sev}</span>'


def _vuln_link(vuln_id: str) -> str:
    """Link to the vulnerability's row in the "Vulnerabilities" section."""
    return f'<a href="#v-{_e(vuln_id)}">{_e(vuln_id)}</a>'


def _tracker_link(vuln_id: str) -> str:
    return f'<a href="{_e(TRACKER_URL + vuln_id)}" rel="noreferrer">{_e(vuln_id)}</a>'


def _local(when: datetime, tz: str | None) -> str:
    """``when`` as wall-clock time in ``tz`` (server local time without one),
    with the zone's abbreviation: 2026-11-02 07:00 CET."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return window.local_now(tz, when).strftime("%Y-%m-%d %H:%M %Z")


def _when(value: str | None, tz: str | None) -> str:
    """A stored ISO timestamp in ``tz``; unescaped."""
    if not value:
        return "never"
    try:
        return _local(datetime.fromisoformat(value), tz)
    except ValueError:
        return value


def _ts(value: str | None, tz: str | None) -> str:
    return _e(_when(value, tz))


def _zone_label(tz: str | None) -> str:
    return tz or f"server local time, {window.server_zone()}"


def page_timezone(cfg: Config) -> str | None:
    """The global policy.timezone; None (server local time) without a valid one."""
    tz = cfg.raw["policy"].get("timezone")
    try:
        window.zone(tz)
    except ValueError:
        return None
    return tz


def _patch_badge(status: str | None) -> str:
    if not status:
        return '<span class="muted">-</span>'
    cls = _PATCH_CLASS.get(status, "bad")
    return f'<span class="badge {cls}">{_e(status)}</span>'


def _risk_order(f: Finding) -> tuple:
    return -f.severity, not f.kev, -(f.cvss_score or 0), f.vuln_id


def _finding_rows(findings: list[Finding], fixed_column: bool) -> str:
    """Without descriptions: those are in the "Vulnerabilities" section, once per page."""
    rows = []
    for f in sorted(findings, key=_risk_order):
        score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
        flags = " ".join(filter(None, [
            '<span class="badge bad">KEV</span>' if f.kev else "",
            f'<span class="badge warn">{_e(f.definition)} {_e(f.action)}</span>'
            if f.definition else "",
        ]))
        last = _e(f.fixed_version or "-") if fixed_column else _e(f.status)
        rows.append(f"<tr><td>{_vuln_link(f.vuln_id)}</td><td>{_sev(f.severity)}</td>"
                    f'<td class="num">{score}</td><td>{last}</td><td>{flags}</td></tr>')
    return "".join(rows)


def _listed(rec: HostRecord, min_severity: Severity
            ) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """(fixable, not fixable, the not fixable ones listed) of a host's findings."""
    fixable = [f for f in rec.findings if f.status == FindingStatus.FIXABLE]
    others = [f for f in rec.findings if f.status != FindingStatus.FIXABLE]
    notable = [f for f in others if f.severity >= min_severity or f.kev][:MAX_OTHER]
    return fixable, others, notable


def _vulnerabilities(records: list[tuple[HostRecord, str | None]],
                     min_severity: Severity) -> str:
    """Every vulnerability listed in a host's details, once, with its description and
    hosts. The host tables link here instead of repeating the descriptions."""
    found: dict[str, list[tuple[str, Finding]]] = {}
    for rec, _ in records:
        fixable, _, notable = _listed(rec, min_severity)
        for f in fixable + notable:
            found.setdefault(f.vuln_id, []).append((rec.host, f))
    if not found:
        return ""
    rows = []
    for vuln_id, items in found.items():
        # the hosts' data can differ (e.g. a score only from one source): take the worst
        findings = [f for _, f in items]
        severity = max(f.severity for f in findings)
        cvss = max((f.cvss_score for f in findings if f.cvss_score is not None), default=None)
        kev = any(f.kev for f in findings)
        description = next((f.description for f in findings if f.description), "")
        hosts = ", ".join(map(_host_link, dict.fromkeys(host for host, _ in items)))
        score = f"{cvss:.1f}" if cvss is not None else "-"
        badge = '<span class="badge bad">KEV</span>' if kev else ""
        rows.append(((-severity, not kev, -(cvss or 0), vuln_id),  # as _risk_order
                     f'<tr id="v-{_e(vuln_id)}"><td>{_tracker_link(vuln_id)}</td>'
                     f'<td>{_sev(severity)}</td><td class="num">{score}</td><td>{badge}</td>'
                     f"<td>{_e(truncate(description, 160))}</td><td>{hosts}</td></tr>"))
    rows.sort(key=lambda r: r[0])
    return (f"<h2>Vulnerabilities</h2>"
            f'<p class="muted">{len(rows)} vulnerabilities listed in the host details, each '
            "once. IDs link to the Debian security tracker.</p>"
            '<div class="wrap"><table>'
            + _head("ID", "Severity", "CVSS", "", "Description", "Hosts")
            + "".join(row for _, row in rows) + "</table></div>")


def _modes_badges(host: HostConfig | None) -> str:
    if host is None:
        return '<span class="muted">not configured</span>'
    modes = host.policy["modes"]
    if "patch" in modes:
        return '<span class="badge good">patch</span>'
    if "dry-run" in modes:
        return '<span class="badge muted">dry-run</span>'
    return '<span class="muted">report only</span>'


def _policy_line(host: HostConfig | None) -> str:
    if host is None:
        return '<p class="muted">no longer in the configuration</p>'
    p = host.policy
    snap = host.snapshot
    snapshot = (f"proxmox {snap.get('type', '')} {snap.get('vmid', '')}"
                if snap["provider"] == "proxmox" else "none")
    items = [
        f"modes {', '.join(p['modes']) or '-'}",
        f"window {window.describe(p['window'], _zone_label(p.get('timezone')))}",
        f"auto-patch {', '.join(p['auto_patch_severities'])}"
        + (" + KEV" if p["auto_patch_kev"] else ""),
        f"rollback {p['rollback']}", f"restart {p['restart']}", f"reboot {p['reboot']}",
        f"snapshot {snapshot}", f"{len(host.healthchecks)} healthchecks",
    ]
    if "patch" not in p["modes"] and "dry-run" not in p["modes"]:
        items = items[:1]  # the rest only matters for patching
    return f'<p class="muted">policy: {_e(" · ".join(items))}</p>'


@dataclass
class NextPatch:
    """Preview of a patch host's next run, from the last scan only: no SSH,
    no apt simulation."""
    when: str  # start of the next window, in the host's time zone
    items: list[planner.PlanItem]
    summary: str  # e.g. "openssl, inetutils (2 critical, 1 high)"


def _next_patch(rec: HostRecord, host: HostConfig | None, definitions: list[Definition],
                now: datetime) -> NextPatch | None:
    if host is None or "patch" not in host.policy["modes"]:
        return None
    p = host.policy
    tz = p.get("timezone")
    if not p["window"]:
        when = "any time"
    elif window.in_any(p["window"], now, tz):
        when = "open now"
    else:
        when = _local(window.next_start(p["window"], now, tz), tz)
    items = planner.preview(rec.findings, p, definitions, rec.summary.get("codename", ""))
    active = {i.source_package for i in items if not i.skipped}
    if not items:
        summary = f"nothing ({policy_skip_reason(rec.findings, p)})"
    elif not active:
        summary = "nothing, every selected package is held back by a definition"
    else:
        counts = Counter(f.severity for f in planner.select(rec.findings, p)
                         if f.source_package in active)
        names = [i.source_package for i in items if not i.skipped]
        summary = (", ".join(names) + " ("
                   + ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items(), reverse=True))
                   + ")")
    return NextPatch(when, items, summary)


def _next_patch_section(nxt: NextPatch, scanned_at: str | None, tz: str | None) -> str:
    parts = [f'<h3>Next patch run <span class="muted">· preview based on the last scan '
             f'({_ts(scanned_at, tz)})</span></h3>',
             f"<p>window: {_e(nxt.when)}<br>would patch: {_e(nxt.summary)}</p>"]
    if nxt.items:
        parts.append('<div class="wrap"><table>'
                     + _head("Severity", "Package", "Installed", "Fixed in", "Vulns", ""))
        for i in nxt.items:
            held = (f'<span class="badge warn">held back</span> {_e(i.skipped)}'
                    if i.skipped else "")
            parts.append(f"<tr><td>{_sev(i.severity)}</td><td>{_e(i.source_package)}</td>"
                         f"<td><code>{_e(i.installed_version)}</code></td>"
                         f"<td><code>{_e(i.fixed_version)}</code></td>"
                         f'<td class="num">{len(i.vulns)}</td><td>{held}</td></tr>')
        parts.append("</table></div>")
    parts.append('<p class="muted">The patch run itself checks the apt candidates, so it can '
                 "still hold back a package (mirror behind, blocked candidate).</p>")
    return "".join(parts)


def _next_cell(nxt: NextPatch | None) -> str:
    if nxt is None:
        return '<span class="muted">-</span>'
    return f'{_e(nxt.when)}<br><span class="muted">would patch: {_e(nxt.summary)}</span>'


TREND_W, TREND_H, TREND_PAD = 300, 56, 4


def _trend(points: list[tuple[str, int, int, int]], tz: str | None) -> str:
    """Inline SVG of fixable findings per stored scan: total, critical, high.
    No script; colours come from the page's CSS variables; <title> carries the
    values (whole chart and per scan)."""
    if not points:
        return ""
    times = [datetime.fromisoformat(p[0]).timestamp() for p in points]
    t0, t1 = times[0], times[-1]
    top = max(max(p[1] for p in points), 1)
    inner_w, inner_h = TREND_W - 2 * TREND_PAD, TREND_H - 2 * TREND_PAD

    def num(v: float) -> str:
        """One decimal, whole numbers without one: keeps the page small."""
        text = f"{v:.1f}"
        return text.removesuffix(".0")

    def xy(i: int, value: int) -> tuple[str, str]:
        x = TREND_PAD + (inner_w * (times[i] - t0) / (t1 - t0) if t1 > t0 else inner_w / 2)
        y = TREND_PAD + inner_h * (1 - value / top)
        return num(x), num(y)

    def line(col: int, cls: str) -> str:
        """A step line: a value holds until the next scan. An unchanged value would repeat
        the point it ends on, so repeats are left out; the shape stays the same."""
        if len(points) == 1:
            return ""
        coords = [xy(0, points[0][col])]
        for i in range(1, len(points)):
            coords += [(xy(i, 0)[0], xy(i - 1, points[i - 1][col])[1]),
                       xy(i, points[i][col])]
        kept = [c for n, c in enumerate(coords) if n == 0 or c != coords[n - 1]]
        return f'<polyline class="{cls}" points="{" ".join(",".join(c) for c in kept)}"/>'

    first, last = _when(points[0][0], tz), _when(points[-1][0], tz)
    latest = points[-1]
    span = f"{first} – {last}" if len(points) > 1 else first
    summary = (f"Fixable vulnerabilities, {len(points)} scan{'s' if len(points) > 1 else ''}, "
               f"{span}: now {latest[1]} ({latest[2]} critical, {latest[3]} high), "
               f"highest {max(p[1] for p in points)}")
    marks = []
    for i, (when, total, crit, high) in enumerate(points):
        x, y = xy(i, total)
        label = f"{_when(when, tz)}: {total} fixable, {crit} critical, {high} high"
        dot = '<circle r="2" cx="{x}" cy="{y}"/>' if i == len(points) - 1 else ""
        marks.append(dot.format(x=x, y=y)
                     + f'<circle class="hit" r="5" cx="{x}" cy="{y}"><title>{_e(label)}'
                       "</title></circle>")
    base = TREND_H - TREND_PAD
    svg = (f'<svg viewBox="0 0 {TREND_W} {TREND_H}" width="{TREND_W}" height="{TREND_H}" '
           f'role="img" aria-label="{_e(summary)}"><title>{_e(summary)}</title>'
           f'<line class="axis" x1="{TREND_PAD}" y1="{base}" x2="{TREND_W - TREND_PAD}" '
           f'y2="{base}"/>'
           + line(1, "total") + line(3, "hi") + line(2, "crit") + "".join(marks) + "</svg>")
    return (f'<div class="trend"><h3>Fixable over time</h3>{svg}'
            f'<p class="muted">{len(points)} stored scan{"s" if len(points) > 1 else ""}, '
            f"{_e(span)} · max {top} · <span class=\"sev\">total</span> · "
            '<span class="sev critical">critical</span> · <span class="sev high">high</span>'
            " · history limited by keep_runs</p></div>")


def last_health(patches: list[dict]) -> tuple[dict, str] | None:
    """(patch run, "health_after" or "health_before") of the newest run that ran
    healthchecks; health_after wins."""
    for p in patches:
        for key in ("health_after", "health_before"):
            if p.get(key):
                return p, key
    return None


def _health_section(found: tuple[dict, str], tz: str | None) -> str:
    p, key = found
    if key == "health_before":
        when = "before patching"
    elif p.get("status") == "rolled-back":
        when = "after the rollback"
    else:
        when = "after patching"
    parts = [f'<h3>Healthchecks <span class="muted">· {when}, '
             f"{_ts(p.get('started_at'), tz)}, run <code>{_e(p.get('run_id', '?'))}</code>"
             f"</span> {_patch_badge(p.get('status'))}</h3><ul>"]
    for line in p[key]:
        m = _CHECK.match(str(line))
        if m is None:
            parts.append(f'<li><span class="muted">?</span> {_e(line)}</li>')
            continue
        mark = ('<span class="good">✓</span>' if m["state"] == "ok"
                else '<span class="bad">✗</span>')
        detail = f' <span class="muted">{_e(m["detail"])}</span>' if m["detail"] else ""
        parts.append(f"<li>{mark} <code>{_e(m['check'])}</code>{detail}</li>")
    parts.append("</ul>")
    return "".join(parts)


def _host_section(rec: HostRecord, latest_error: str | None, patches: list[dict],
                  snapshots: list[dict], min_severity: Severity,
                  host: HostConfig | None = None, tz: str | None = None,
                  next_patch: NextPatch | None = None,
                  health: tuple[dict, str] | None = None,
                  trend: list[tuple[str, int, int, int]] | None = None) -> str:
    s = rec.summary
    fixable, others, notable = _listed(rec, min_severity)
    parts = [f'<details id="{_e(rec.host)}"><summary>{_e(rec.host)} '
             f'<span class="muted">· {_e(rec.address or "")} · Debian '
             f'{_e(s.get("debian_version", "?"))} ({_e(s.get("codename", "?"))}) · '
             f'{len(fixable)} fixable</span></summary>']
    if latest_error:
        parts.append(f'<p class="bad">{_e(latest_error)}</p>')
    parts += [f'<p class="warn">⚠ {_e(w)}</p>' for w in rec.warnings]
    parts.append(f'<p class="muted">scanned {_ts(rec.scanned_at, tz)} · '
                 f'{_e(s.get("package_count", 0))} packages</p>')
    parts.append(_policy_line(host))
    parts.append(_trend(trend or [], tz))
    if next_patch:
        parts.append(_next_patch_section(next_patch, rec.scanned_at, tz))

    if fixable:
        parts.append('<h3>Fixable now</h3><div class="wrap"><table>'
                     + _head("Severity", "Package", "Installed", "Fixed in", "Vulns", "Top"))
        for g in group_findings(fixable):
            kev = ' <span class="badge bad">KEV</span>' if g.kev else ""
            parts.append(f"<tr><td>{_sev(g.severity)}</td><td>{_e(g.source_package)}</td>"
                         f"<td><code>{_e(g.installed_version)}</code></td>"
                         f"<td><code>{_e(g.target_version or '?')}</code></td>"
                         f'<td class="num">{len(g.findings)}</td>'
                         f"<td>{_vuln_link(g.top.vuln_id)}{kev}</td></tr>")
        parts.append("</table></div>")
        parts.append('<details><summary>All fixable vulnerabilities</summary><div class="wrap">'
                     "<table>" + _head("ID", "Severity", "CVSS", "Fixed in", "")
                     + _finding_rows(fixable, fixed_column=True) + "</table></div></details>")

    counts = Counter(f.status for f in others)
    parts.append(f'<p class="muted">not fixable: fix pending '
                 f'{counts[FindingStatus.FIX_PENDING]} · no fix {counts[FindingStatus.NO_FIX]} · '
                 f'undetermined {counts[FindingStatus.UNDETERMINED]}</p>')
    if notable:
        parts.append(f"<details><summary>Not fixable yet, {_e(min_severity)} and above "
                     f"({len(notable)})</summary><div class=\"wrap\"><table>"
                     + _head("ID", "Severity", "CVSS", "Status", "")
                     + _finding_rows(notable, fixed_column=False) + "</table></div></details>")

    if health:
        parts.append(_health_section(health, tz))
    if patches:
        parts.append('<h3>Patch history</h3><div class="wrap"><table>'
                     + _head("Started", "Status", "Packages", "Snapshot", "Reason"))
        for p in patches:
            pkgs = ", ".join(i["source_package"] for i in p.get("items", []))
            snap = (p.get("snapshot") or {}).get("name", "-")
            parts.append(f"<tr><td>{_ts(p.get('started_at'), tz)}</td>"
                         f"<td>{_patch_badge(p.get('status'))}</td><td>{_e(pkgs or '-')}</td>"
                         f"<td><code>{_e(snap)}</code></td>"
                         f"<td>{_e(truncate(p.get('reason', ''), 160))}</td></tr>")
        parts.append("</table></div>")
    if snapshots:
        parts.append("<h3>Snapshots kept by aptwarden</h3><ul>" + "".join(
            f"<li><code>{_e(x['name'])}</code> on {_e(x['target'])}, "
            f"{_ts(x['created_at'], tz)} ({_e(x['state'])})</li>" for x in snapshots) + "</ul>")
    parts.append("</details>")
    return "".join(parts)


def _head(*columns: str) -> str:
    """A table's header row; scope tells screen readers the cells are column headers."""
    return "<tr>" + "".join(f'<th scope="col">{_e(c)}</th>' for c in columns) + "</tr>"


def _host_link(name: str) -> str:
    return f'<a href="#{_e(name)}">{_e(name)}</a>'


def _aborted_streak(history: list[dict]) -> int:
    n = 0
    for p in history:
        if p.get("status") != "aborted":
            break
        n += 1
    return n


def _attention_items(records: list[tuple[HostRecord, str | None]],
                     history: dict[str, list[dict]],
                     tz: str | None) -> list[tuple[tuple[str, ...], str]]:
    """(hosts, html) for everything that needs a human, worst first. A known exploited
    vulnerability is one entry for all its hosts; the others are one entry per host."""
    failed, scans, aborts = [], [], []
    kev: dict[tuple[str, str], list[tuple[str, Finding]]] = {}
    for rec, error in records:
        latest = (history[rec.host] or [{}])[0]
        link = _host_link(rec.host)
        if latest.get("status") in ATTENTION_PATCH:
            failed.append(((rec.host,), f"{link}: last patch run "
                           f"{_patch_badge(latest['status'])} "
                           f"{_ts(latest.get('started_at'), tz)}"
                           f" · {_e(truncate(latest.get('reason', ''), 160))}"))
        if error:
            scans.append(((rec.host,), f'{link}: <span class="bad">{_e(error)}</span>'))
        for f in rec.findings:
            if f.kev and f.status == FindingStatus.FIXABLE:
                kev.setdefault((f.vuln_id, f.source_package), []).append((rec.host, f))
        streak = _aborted_streak(history[rec.host])
        if streak >= REPEATED_ABORTS:
            more = "+" if streak == len(history[rec.host]) == PATCH_HISTORY else ""
            aborts.append(((rec.host,), f"{link}: {_patch_badge('aborted')} "
                           f"{streak}{more} patch runs in a row · "
                           f"{_e(truncate(latest.get('reason', ''), 160))}"))
    return failed + scans + _kev_items(kev) + aborts


def _kev_items(kev: dict[tuple[str, str], list[tuple[str, Finding]]]
               ) -> list[tuple[tuple[str, ...], str]]:
    """One entry per vulnerability and package, with all affected hosts. The fixed version
    is given once, or per host where the hosts differ (e.g. other Debian releases)."""
    def fixed(f: Finding) -> str:
        return f"<code>{_e(f.fixed_version or '?')}</code>"

    items = []
    for (vuln_id, package), found in kev.items():
        by_host: dict[str, Finding] = {}
        for host, f in found:
            by_host.setdefault(host, f)
        severity = max(f.severity for f in by_host.values())
        if len({f.fixed_version for f in by_host.values()}) == 1:
            where = (f", fixed in {fixed(found[0][1])} — "
                     + ", ".join(map(_host_link, by_host)))
        else:
            where = " — " + ", ".join(f"{_host_link(host)} (fixed in {fixed(f)})"
                                      for host, f in by_host.items())
        items.append(((-severity, vuln_id, package), (tuple(by_host), (
            f'<span class="badge bad">KEV</span> {_vuln_link(vuln_id)} {_sev(severity)} in '
            f"{_e(package)}{where}"))))
    return [item for _, item in sorted(items)]


def _attention(items: list[tuple[tuple[str, ...], str]]) -> str:
    if not items:
        return '<p class="good">Nothing needs attention</p>'
    return ('<div class="attention"><ul>' + "".join(f"<li>{html}</li>" for _, html in items)
            + "</ul></div>")


def _counts(rec: HostRecord) -> dict[str, int]:
    fixable = [f for f in rec.findings if f.status == FindingStatus.FIXABLE]
    sev = Counter(f.severity for f in fixable)
    return {"fixable": len(fixable), "critical": sev[Severity.CRITICAL],
            "high": sev[Severity.HIGH], "kev": sum(1 for f in fixable if f.kev)}


@dataclass
class Status:
    """Everything the page and status.json are built from."""
    now: datetime
    tz: str | None
    records: list[tuple[HostRecord, str | None]]  # last good scan, error of the latest
    scanned_at: dict[str, str]  # time of the latest scan attempt
    missing: list[str]  # configured, never scanned
    last_run: str | None
    history: dict[str, list[dict]]
    upcoming: dict[str, NextPatch | None]
    attention: list[tuple[tuple[str, ...], str]]  # (hosts, html)
    health: dict[str, tuple[dict, str] | None]  # latest healthcheck results per host


def collect(cfg: Config, state: State, now: datetime | None = None) -> Status:
    now = now or datetime.now(UTC)
    tz = page_timezone(cfg)
    records: list[tuple[HostRecord, str | None]] = []
    scanned_at: dict[str, str] = {}
    missing: list[str] = []
    last_run = None
    for h in cfg.hosts:
        latest = state.latest(h.name)
        if latest is None:
            missing.append(h.name)
            continue
        good = latest if latest.ok else state.latest(h.name, ok_only=True)
        error = None if latest.ok else (f"latest scan {_when(latest.scanned_at, tz)} failed: "
                                         f"{latest.error}")
        if last_run is None or latest.run_id > last_run:
            last_run = latest.run_id
        records.append((good or latest, error))
        scanned_at[h.name] = latest.scanned_at

    by_name = {h.name: h for h in cfg.hosts}
    history = {rec.host: state.patches(rec.host, PATCH_HISTORY) for rec, _ in records}
    custom = cfg.raw["sources"].get("custom", {}).get("enabled", False)
    definitions = stored_definitions(state) if custom else []
    upcoming = {rec.host: _next_patch(rec, by_name.get(rec.host), definitions, now)
                for rec, _ in records}
    health = {rec.host: last_health(history[rec.host])
              or last_health(state.patches(rec.host, HEALTH_LOOKBACK)) for rec, _ in records}
    return Status(now, tz, records, scanned_at, missing, last_run, history, upcoming,
                  _attention_items(records, history, tz), health)


def _utc(value: str | datetime | None) -> str | None:
    """ISO 8601 in UTC with a Z, as monitoring tools parse it."""
    if value is None:
        return None
    when = datetime.fromisoformat(value) if isinstance(value, str) else value
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_json(st: Status) -> dict:
    """Numbers and states only: no package names, vulnerability texts or addresses."""
    # per host and problem: a KEV entry counts once for each of its hosts
    attention = Counter(host for hosts, _ in st.attention for host in hosts)
    hosts = []
    for rec, error in st.records:
        patch = (st.history[rec.host] or [{}])[0]
        hosts.append({"name": rec.host, "scan_ok": error is None,
                      "scanned_at": _utc(st.scanned_at[rec.host]),
                      "last_patch": patch.get("status"),
                      "last_patch_at": _utc(patch.get("started_at")),
                      **_counts(rec), "needs_attention": attention[rec.host]})
    hosts += [{"name": name, "scan_ok": None, "scanned_at": None, "last_patch": None,
               "last_patch_at": None, "fixable": 0, "critical": 0, "high": 0, "kev": 0,
               "needs_attention": 0} for name in st.missing]
    total = Counter()
    for h in hosts[:len(st.records)]:
        total.update({k: h[k] for k in ("fixable", "critical", "high", "kev")})
    return {"generated_at": _utc(st.now), "last_run": st.last_run,
            "hosts": len(st.records), "hosts_failing": sum(1 for _, e in st.records if e),
            "fixable": total["fixable"], "critical": total["critical"], "high": total["high"],
            "kev": total["kev"], "needs_attention": attention.total(),
            "not_scanned": len(st.missing), "aptwarden": __version__, "hosts_detail": hosts}


def render(cfg: Config, state: State, now: datetime | None = None,
           st: Status | None = None) -> str:
    st = st or collect(cfg, state, now)
    now, tz, records, history, upcoming = st.now, st.tz, st.records, st.history, st.upcoming
    missing, last_run = st.missing, st.last_run
    min_severity = Severity.parse(cfg.report["min_severity"])
    by_name = {h.name: h for h in cfg.hosts}
    total = Counter()
    rows = []
    for rec, error in records:
        c = _counts(rec)
        patch = (history[rec.host] or [{}])[0]
        total.update(hosts=1, errors=1 if error else 0, **c)
        status = ('<span class="badge bad">scan failed</span>' if error
                  else '<span class="badge good">ok</span>')
        failing = bool(error) or patch.get("status") in ATTENTION_PATCH
        risk = (not failing, -c["kev"], -c["critical"], -c["high"], rec.host)
        rows.append((risk, f'<tr><td>{_host_link(rec.host)}</td>'
                    f"<td>{_modes_badges(by_name.get(rec.host))}</td><td>{status}</td>"
                    f'<td class="num">{c["fixable"]}</td>'
                    f'<td class="num critical">{c["critical"] or ""}</td>'
                    f'<td class="num high">{c["high"] or ""}</td>'
                    f'<td class="num">{c["kev"] or ""}</td>'
                    f"<td>{_ts(rec.scanned_at, tz)}</td>"
                    f"<td>{_patch_badge(patch.get('status'))} "
                    f"<span class=\"muted\">{_ts(patch.get('started_at'), tz) if patch else ''}"
                    f"</span></td><td>{_next_cell(upcoming[rec.host])}</td></tr>"))
    rows.sort()

    sources_html = ""
    info = state.run_info(last_run) if last_run else None
    sources = (info or {}).get("data", {}).get("sources", [])
    if sources:
        items = []
        for src in sources:
            cls = "good" if src.get("ok") else "bad"
            checked = (_local(datetime.fromtimestamp(src["checked_at"], UTC), tz)
                       if src.get("checked_at") else "never")
            detail = f" · {_e(src['message'])}" if src.get("message") else ""
            warn = "".join(f'<br><span class="warn">⚠ {_e(w)}</span>'
                           for w in src.get("warnings", []) + src.get("alerts", []))
            items.append(f'<li><span class="badge {cls}">{_e(src["name"])}</span> checked '
                         f"{_e(checked)}{detail}{warn}</li>")
        sources_html = "<h2>Data sources</h2><ul>" + "".join(items) + "</ul>"

    tiles = "".join(f'<div class="tile"><b class="{cls}">{value}</b>{_e(label)}</div>'
                    for value, label, cls in [
                        (total["hosts"], "hosts", ""),
                        (total["fixable"], "fixable vulnerabilities", ""),
                        (total["critical"], "critical", "critical" if total["critical"] else ""),
                        (total["high"], "high", "high" if total["high"] else ""),
                        (total["kev"], "known exploited", "bad" if total["kev"] else ""),
                        (total["errors"], "hosts failing", "bad" if total["errors"] else "good"),
                    ])
    hosts_html = "".join(
        _host_section(rec, error, history[rec.host],
                      state.snapshots(rec.host, ("active", "rolled-back")), min_severity,
                      by_name.get(rec.host), tz, upcoming[rec.host], st.health[rec.host],
                      state.fixable_history(rec.host))
        for rec, error in records)
    missing_html = (f'<p class="muted">not scanned yet: {_e(", ".join(missing))}</p>'
                    if missing else "")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<title>aptwarden status</title>
<style>{_CSS}</style>
</head>
<body><main>
<h1>aptwarden status</h1>
<p class="muted">generated {_e(_local(now, tz))} · times in {_e(_zone_label(tz))} ·
aptwarden {_e(__version__)}
{f"· latest run {_e(last_run)}" if last_run else ""}</p>
<div class="tiles">{tiles}</div>
<h2>Needs attention</h2>
{_attention(st.attention)}
<h2>Hosts</h2>
<div class="wrap"><table>
{_head("Host", "Modes", "Scan", "Fixable", "Critical", "High", "KEV", "Scanned",
       "Last patch", "Next patch (preview)")}
{"".join(row for _, row in rows)}
</table></div>
<p class="muted">Hosts with errors first, then by known exploited, critical and high
fixable vulnerabilities. Next patch: the next window in the host's time zone and what it
would patch, a preview based on the last scan. Modes and policy:
configuration at the time this page was generated ({_e(_local(now, tz))}). Configuration
changes appear after the next report or patch run.</p>
{missing_html}
{sources_html}
<h2>Host details</h2>
{hosts_html}
{_vulnerabilities(records, min_severity)}
</main></body>
</html>
"""


def output_path(cfg: Config) -> Path:
    path = cfg.raw["status_page"].get("path")
    return Path(path) if path else cfg.state_dir / "www" / "index.html"


def _write_atomic(path: Path, text: str, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}-", suffix=path.suffix, dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def write(cfg: Config, state: State) -> Path | None:
    """Write the page and status.json next to it, each atomically. Never fails
    a run: errors are only logged. status.json is written first, so whatever
    watches the page (the publish path unit) finds both up to date."""
    if not cfg.raw["status_page"]["enabled"]:
        return None
    path = output_path(cfg)
    mode = int(cfg.raw["status_page"]["mode"], 8)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        st = collect(cfg, state)
        _write_atomic(path.parent / "status.json",
                      json.dumps(status_json(st), indent=2) + "\n", mode)
        _write_atomic(path, render(cfg, state, st=st), mode)
    except OSError as e:
        log.error("status page not written", extra={"path": str(path), "error": str(e)})
        return None
    log.info("status page written", extra={"path": str(path)})
    return path
