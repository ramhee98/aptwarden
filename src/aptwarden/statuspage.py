"""Static, read-only HTML status page.

Rendered from state.db after every report and patch run, so it always shows
the latest state of every configured host. No JavaScript, no server-side code:
serve the file with any web server (e.g. an existing reverse proxy with
authentication). Everything from external sources is HTML-escaped and the
page forbids scripts through its Content-Security-Policy.
"""

from __future__ import annotations

import html
import logging
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from aptwarden import __version__
from aptwarden.config import Config, HostConfig
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.report import group_findings, truncate
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
"""

_PATCH_CLASS = {"patched": "good", "dry-run": "muted", "nothing-to-do": "muted",
                "skipped": "muted", "aborted": "warn"}


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _sev(sev: Severity) -> str:
    return f'<span class="sev {sev}">{sev}</span>'


def _vuln_link(vuln_id: str) -> str:
    return f'<a href="{_e(TRACKER_URL + vuln_id)}" rel="noreferrer">{_e(vuln_id)}</a>'


def _ts(value: str | None) -> str:
    return _e(value.replace("T", " ").replace("+00:00", " UTC")) if value else "never"


def _patch_badge(status: str | None) -> str:
    if not status:
        return '<span class="muted">-</span>'
    cls = _PATCH_CLASS.get(status, "bad")
    return f'<span class="badge {cls}">{_e(status)}</span>'


def _finding_rows(findings: list[Finding], fixed_column: bool) -> str:
    rows = []
    for f in sorted(findings, key=lambda f: (-f.severity, not f.kev, -(f.cvss_score or 0),
                                              f.vuln_id)):
        score = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "-"
        flags = " ".join(filter(None, [
            '<span class="badge bad">KEV</span>' if f.kev else "",
            f'<span class="badge warn">{_e(f.definition)} {_e(f.action)}</span>'
            if f.definition else "",
        ]))
        last = _e(f.fixed_version or "-") if fixed_column else _e(f.status)
        rows.append(f"<tr><td>{_vuln_link(f.vuln_id)}</td><td>{_sev(f.severity)}</td>"
                    f'<td class="num">{score}</td><td>{last}</td><td>{flags}</td>'
                    f"<td>{_e(truncate(f.description, 160))}</td></tr>")
    return "".join(rows)


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
        f"window {', '.join(p['window']) or 'any time'}",
        f"auto-patch {', '.join(p['auto_patch_severities'])}"
        + (" + KEV" if p["auto_patch_kev"] else ""),
        f"rollback {p['rollback']}", f"restart {p['restart']}", f"reboot {p['reboot']}",
        f"snapshot {snapshot}", f"{len(host.healthchecks)} healthchecks",
    ]
    if "patch" not in p["modes"] and "dry-run" not in p["modes"]:
        items = items[:1]  # the rest only matters for patching
    return f'<p class="muted">policy: {_e(" · ".join(items))}</p>'


def _host_section(rec: HostRecord, latest_error: str | None, patches: list[dict],
                  snapshots: list[dict], min_severity: Severity,
                  host: HostConfig | None = None) -> str:
    s = rec.summary
    fixable = [f for f in rec.findings if f.status == FindingStatus.FIXABLE]
    others = [f for f in rec.findings if f.status != FindingStatus.FIXABLE]
    parts = [f'<details id="{_e(rec.host)}"><summary>{_e(rec.host)} '
             f'<span class="muted">· {_e(rec.address or "")} · Debian '
             f'{_e(s.get("debian_version", "?"))} ({_e(s.get("codename", "?"))}) · '
             f'{len(fixable)} fixable</span></summary>']
    if latest_error:
        parts.append(f'<p class="bad">{_e(latest_error)}</p>')
    parts += [f'<p class="warn">⚠ {_e(w)}</p>' for w in rec.warnings]
    parts.append(f'<p class="muted">scanned {_ts(rec.scanned_at)} · '
                 f'{_e(s.get("package_count", 0))} packages</p>')
    parts.append(_policy_line(host))

    if fixable:
        parts.append('<h3>Fixable now</h3><div class="wrap"><table><tr><th>Severity</th>'
                     '<th>Package</th><th>Installed</th><th>Fixed in</th><th>Vulns</th>'
                     '<th>Top</th></tr>')
        for g in group_findings(fixable):
            kev = ' <span class="badge bad">KEV</span>' if g.kev else ""
            parts.append(f"<tr><td>{_sev(g.severity)}</td><td>{_e(g.source_package)}</td>"
                         f"<td><code>{_e(g.installed_version)}</code></td>"
                         f"<td><code>{_e(g.target_version or '?')}</code></td>"
                         f'<td class="num">{len(g.findings)}</td>'
                         f"<td>{_vuln_link(g.top.vuln_id)}{kev}</td></tr>")
        parts.append("</table></div>")
        parts.append('<details><summary>All fixable vulnerabilities</summary><div class="wrap">'
                     "<table><tr><th>ID</th><th>Severity</th><th>CVSS</th><th>Fixed in</th>"
                     "<th></th><th>Description</th></tr>"
                     + _finding_rows(fixable, fixed_column=True) + "</table></div></details>")

    counts = Counter(f.status for f in others)
    parts.append(f'<p class="muted">not fixable: fix pending '
                 f'{counts[FindingStatus.FIX_PENDING]} · no fix {counts[FindingStatus.NO_FIX]} · '
                 f'undetermined {counts[FindingStatus.UNDETERMINED]}</p>')
    notable = [f for f in others if f.severity >= min_severity or f.kev][:MAX_OTHER]
    if notable:
        parts.append(f"<details><summary>Not fixable yet, {_e(min_severity)} and above "
                     f"({len(notable)})</summary><div class=\"wrap\"><table><tr><th>ID</th>"
                     "<th>Severity</th><th>CVSS</th><th>Status</th><th></th>"
                     "<th>Description</th></tr>"
                     + _finding_rows(notable, fixed_column=False) + "</table></div></details>")

    if patches:
        parts.append('<h3>Patch history</h3><div class="wrap"><table><tr><th>Started</th>'
                     "<th>Status</th><th>Packages</th><th>Snapshot</th><th>Reason</th></tr>")
        for p in patches:
            pkgs = ", ".join(i["source_package"] for i in p.get("items", []))
            snap = (p.get("snapshot") or {}).get("name", "-")
            parts.append(f"<tr><td>{_ts(p.get('started_at'))}</td>"
                         f"<td>{_patch_badge(p.get('status'))}</td><td>{_e(pkgs or '-')}</td>"
                         f"<td><code>{_e(snap)}</code></td>"
                         f"<td>{_e(truncate(p.get('reason', ''), 160))}</td></tr>")
        parts.append("</table></div>")
    if snapshots:
        parts.append("<h3>Snapshots kept by aptwarden</h3><ul>" + "".join(
            f"<li><code>{_e(x['name'])}</code> on {_e(x['target'])}, "
            f"{_ts(x['created_at'])} ({_e(x['state'])})</li>" for x in snapshots) + "</ul>")
    parts.append("</details>")
    return "".join(parts)


def render(cfg: Config, state: State, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    min_severity = Severity.parse(cfg.report["min_severity"])
    records: list[tuple[HostRecord, str | None]] = []
    missing: list[str] = []
    last_run = None
    for h in cfg.hosts:
        latest = state.latest(h.name)
        if latest is None:
            missing.append(h.name)
            continue
        good = latest if latest.ok else state.latest(h.name, ok_only=True)
        error = None if latest.ok else f"latest scan {latest.scanned_at} failed: {latest.error}"
        if last_run is None or latest.run_id > last_run:
            last_run = latest.run_id
        records.append((good or latest, error))

    by_name = {h.name: h for h in cfg.hosts}
    total = Counter()
    rows = []
    for rec, error in records:
        fixable = [f for f in rec.findings if f.status == FindingStatus.FIXABLE]
        sev = Counter(f.severity for f in fixable)
        kev = sum(1 for f in fixable if f.kev)
        patch = (state.patches(rec.host, 1) or [{}])[0]
        total.update(hosts=1, fixable=len(fixable), critical=sev[Severity.CRITICAL],
                     high=sev[Severity.HIGH], kev=kev, errors=1 if error else 0)
        status = ('<span class="badge bad">scan failed</span>' if error
                  else '<span class="badge good">ok</span>')
        rows.append(f'<tr><td><a href="#{_e(rec.host)}">{_e(rec.host)}</a></td>'
                    f"<td>{_modes_badges(by_name.get(rec.host))}</td><td>{status}</td>"
                    f'<td class="num">{len(fixable)}</td>'
                    f'<td class="num critical">{sev[Severity.CRITICAL] or ""}</td>'
                    f'<td class="num high">{sev[Severity.HIGH] or ""}</td>'
                    f'<td class="num">{kev or ""}</td>'
                    f"<td>{_ts(rec.scanned_at)}</td>"
                    f"<td>{_patch_badge(patch.get('status'))} "
                    f"<span class=\"muted\">{_ts(patch.get('started_at')) if patch else ''}"
                    "</span></td></tr>")

    sources_html = ""
    info = state.run_info(last_run) if last_run else None
    sources = (info or {}).get("data", {}).get("sources", [])
    if sources:
        items = []
        for src in sources:
            cls = "good" if src.get("ok") else "bad"
            checked = (datetime.fromtimestamp(src["checked_at"], UTC).strftime("%Y-%m-%d %H:%M UTC")
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
        _host_section(rec, error, state.patches(rec.host, 5),
                      state.snapshots(rec.host, ("active", "rolled-back")), min_severity,
                      by_name.get(rec.host))
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
<p class="muted">generated {_e(now.strftime("%Y-%m-%d %H:%M UTC"))} · aptwarden {_e(__version__)}
{f"· latest run {_e(last_run)}" if last_run else ""}</p>
<div class="tiles">{tiles}</div>
<h2>Hosts</h2>
<div class="wrap"><table>
<tr><th>Host</th><th>Modes</th><th>Scan</th><th>Fixable</th><th>Critical</th><th>High</th><th>KEV</th>
<th>Scanned</th><th>Last patch</th></tr>
{"".join(rows)}
</table></div>
<p class="muted">Modes and policy: configuration at the time this page was generated
({_e(now.strftime("%Y-%m-%d %H:%M UTC"))}). Configuration changes appear after the next
report or patch run.</p>
{missing_html}
{sources_html}
<h2>Host details</h2>
{hosts_html}
</main></body>
</html>
"""


def output_path(cfg: Config) -> Path:
    path = cfg.raw["status_page"].get("path")
    return Path(path) if path else cfg.state_dir / "www" / "index.html"


def write(cfg: Config, state: State) -> Path | None:
    """Write the page atomically. Never fails a run: errors are only logged."""
    if not cfg.raw["status_page"]["enabled"]:
        return None
    path = output_path(cfg)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".index-", suffix=".html", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(render(cfg, state))
        os.chmod(tmp, int(cfg.raw["status_page"]["mode"], 8))
        os.replace(tmp, path)
    except OSError as e:
        log.error("status page not written", extra={"path": str(path), "error": str(e)})
        return None
    log.info("status page written", extra={"path": str(path)})
    return path
