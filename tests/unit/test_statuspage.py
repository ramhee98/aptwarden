import json
import os
import re
import stat
from datetime import UTC, datetime

import pytest

from aptwarden import statuspage
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.patch import window
from aptwarden.state import HostRecord, State


@pytest.fixture(autouse=True)
def utc_server(server_tz):
    """The page's times here are in the server's zone: UTC unless a test sets another."""
    server_tz("UTC")


EVIL = '<script>alert(1)</script><img src=x onerror=alert(2)> "quoted" & more'


def seed(state: State):
    state.start_run("r1", "report")
    findings = [
        Finding("CVE-2026-24061", "inetutils", "2:2.6-3", FindingStatus.FIXABLE,
                fixed_version="2:2.6-3+deb13u3", severity=Severity.CRITICAL, cvss_score=9.8,
                kev=True, description=EVIL, definition="AW-2026-0002", action="auto-patch"),
        Finding("CVE-2026-2", "openssl", "3.5.1-1", FindingStatus.FIXABLE,
                fixed_version="3.5.7-1", severity=Severity.HIGH),
        Finding("CVE-2026-3", "tar", "1.35-1", FindingStatus.NO_FIX, severity=Severity.HIGH),
    ]
    state.save_host("r1", HostRecord("r1", "web01", "192.0.2.10", True, None,
                                     {"debian_version": "13.1", "codename": "trixie",
                                      "package_count": 249}, ["reboot required"],
                                     "2026-10-23T06:00:00+00:00", findings))
    state.save_host("r1", HostRecord("r1", "db01", "192.0.2.20", False, "ssh: timed out", {}, [],
                                     "2026-10-23T06:00:00+00:00"))
    state.finish_run("r1", "partial", {"sources": [
        {"name": "debian_tracker", "ok": True, "checked_at": 1761200000.0, "message": "",
         "warnings": [], "alerts": []},
        {"name": "custom", "ok": True, "checked_at": 1761200000.0,
         "message": "v2026.10.22 (0279728af8ec), 2 definitions", "warnings": [],
         "alerts": ["tag v2026.10.23 rejected: unsigned"]}]})
    state.save_patch("p1", "web01", "rolled-back", "2026-10-23T02:00:00+00:00", {
        "status": "rolled-back", "started_at": "2026-10-23T02:00:00+00:00",
        "reason": "healthchecks failed", "items": [{"source_package": "openssl"}],
        "snapshot": {"provider": "proxmox", "target": "pve/lxc/139", "name": "aptw_p1"}})
    state.add_snapshot("proxmox", "pve/lxc/139", "aptw_p1", "web01", "p1")


def test_render(make_config, tmp_path):
    cfg = make_config(hosts=[
        {"name": "web01", "snapshot": {"provider": "proxmox", "vmid": 139, "type": "lxc"},
         "policy": {"modes": ["report", "dry-run", "patch"], "window": ["Mon..Fri 03:00-04:00"],
                    "timezone": "Europe/Zurich", "rollback": "manual"},
         "healthchecks": [{"systemd": "nginx.service"}]},
        {"name": "db01"}, {"name": "new01"}],
        proxmox={"url": "https://192.0.2.9:8006", "node": "pve", "token_id": "a@pve!t",
                 "token_file": "t"})
    state = State(cfg.state_dir / "state.db")
    seed(state)
    page = statuspage.render(cfg, state)
    state.close()

    # untrusted text is escaped, scripts are impossible
    assert "<script" not in page and "<img" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "default-src 'none'" in page
    # content
    assert '<a href="#web01">web01</a>' in page
    assert 'class="badge bad">scan failed' in page
    assert "ssh: timed out" in page
    assert "not scanned yet: new01" in page
    assert "2:2.6-3+deb13u3" in page and "AW-2026-0002 auto-patch" in page
    assert ">KEV<" in page
    assert "rolled-back" in page and "aptw_p1" in page
    assert "tag v2026.10.23 rejected: unsigned" in page
    assert "reboot required" in page
    assert "https://security-tracker.debian.org/tracker/CVE-2026-24061" in page
    assert "CVE-2026-3" in page  # not fixable, above the threshold
    # modes and policy, with where they come from
    assert '<td><span class="badge good">patch</span></td>' in page
    assert '<td><span class="muted">report only</span></td>' in page
    assert ("policy: modes report, dry-run, patch · window Mon..Fri 03:00-04:00 (Europe/Zurich) · "
            "auto-patch "
            "critical, high + KEV · rollback manual · restart auto · reboot never · snapshot "
            "proxmox lxc 139 · 1 healthchecks") in page
    assert "policy: modes report</p>" in page
    assert "configuration at the time this page was generated" in page


def test_write_atomic_with_mode(make_config):
    cfg = make_config()
    state = State(cfg.state_dir / "state.db")
    seed(state)
    path = statuspage.write(cfg, state)
    state.close()
    assert path == cfg.state_dir / "www" / "index.html"
    assert path.read_text().startswith("<!doctype html>")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert sorted(p.name for p in path.parent.iterdir()) == ["index.html", "status.json"]
    assert stat.S_IMODE(os.stat(path.parent / "status.json").st_mode) == 0o640


def test_disabled_and_custom_path(make_config, tmp_path):
    cfg = make_config(status_page={"enabled": False})
    state = State(cfg.state_dir / "state.db")
    assert statuspage.write(cfg, state) is None
    assert not (cfg.state_dir / "www").exists()
    cfg = make_config(status_page={"path": "web/status.html", "mode": "644"})
    assert statuspage.write(cfg, state) == tmp_path / "web" / "status.html"
    assert stat.S_IMODE(os.stat(tmp_path / "web" / "status.html").st_mode) == 0o644
    state.close()


def test_write_errors_do_not_raise(make_config, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    cfg = make_config(status_page={"path": str(blocker / "index.html")})
    state = State(cfg.state_dir / "state.db")
    assert statuspage.write(cfg, state) is None
    state.close()


def save_scan(state: State, host: str, findings=(), ok=True):
    state.save_host("r1", HostRecord("r1", host, "192.0.2.30", ok, None if ok else "boom", {},
                                     [], "2026-10-23T06:00:00+00:00", list(findings)))


def save_patch(state: State, run_id: str, host: str, status: str, started: str, reason=""):
    state.save_patch(run_id, host, status, started,
                     {"status": status, "started_at": started, "reason": reason, "items": []})


def test_needs_attention_and_risk_order(make_config):
    names = ["web01", "db01", "mail01", "app01", "once01", "crit01", "high01", "aaa01"]
    cfg = make_config(hosts=[{"name": n} for n in names])
    state = State(cfg.state_dir / "state.db")
    seed(state)  # web01: KEV fixable, rolled back; db01: scan failed
    save_scan(state, "mail01")
    save_patch(state, "p2", "mail01", "needs-manual-rollback", "2026-10-23T02:10:00+00:00",
               "healthchecks failed, rollback: manual")
    save_scan(state, "app01")
    for i, started in enumerate(["2026-10-21T02:00:00+00:00", "2026-10-22T02:00:00+00:00"]):
        save_patch(state, f"a{i}", "app01", "aborted", started, "simulation: held packages")
    save_scan(state, "once01")
    save_patch(state, "o1", "once01", "patched", "2026-10-21T02:00:00+00:00")
    save_patch(state, "o2", "once01", "aborted", "2026-10-22T02:00:00+00:00", "ssh: timed out")
    save_scan(state, "crit01", [Finding("CVE-2026-9", "curl", "8.1-1", FindingStatus.FIXABLE,
                                        fixed_version="8.1-2", severity=Severity.CRITICAL)])
    save_scan(state, "high01", [Finding("CVE-2026-8", "curl", "8.1-1", FindingStatus.FIXABLE,
                                        fixed_version="8.1-2", severity=Severity.HIGH)])
    save_scan(state, "aaa01")
    page = statuspage.render(cfg, state)
    state.close()

    attention = page.split("<h2>Needs attention</h2>")[1].split("<h2>Hosts</h2>")[0]
    entries = re.findall(r'<li>(?:<a href="#([\w.-]+)">|<span class="badge bad">(KEV))',
                         attention)
    assert ["".join(e) for e in entries] == ["mail01", "db01", "KEV", "app01"]
    assert "needs-manual-rollback" in attention and "rollback: manual" in attention
    assert "latest scan 2026-10-23 06:00 UTC failed: ssh: timed out" in attention
    assert "CVE-2026-24061" in attention and "2:2.6-3+deb13u3" in attention
    assert '2:2.6-3+deb13u3</code> — <a href="#web01">web01</a></li>' in attention
    assert "CVE-2026-2<" not in attention  # fixable, but not known exploited
    assert "2 patch runs in a row · simulation: held packages" in attention
    assert "rolled-back" not in attention  # fixed itself
    assert "once01" not in attention  # a single abort is not yet a pattern

    table = page.split("<h2>Hosts</h2>")[1].split("<h2>")[0]
    assert re.findall(r'<tr><td><a href="#([\w.-]+)">', table) == [
        "db01", "mail01", "web01", "crit01", "high01", "aaa01", "app01", "once01"]


def kev(vuln_id, package, fixed, severity=Severity.CRITICAL):
    return Finding(vuln_id, package, "1", FindingStatus.FIXABLE, fixed_version=fixed,
                   severity=severity, kev=True)


def test_needs_attention_groups_kev_by_vulnerability(make_config):
    names = ["web01", "web02", "old01", "mail01", "clean01"]
    cfg = make_config(hosts=[{"name": n} for n in names])
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    save_scan(state, "web01", [kev("CVE-2026-10", "brotli", "1.1.0-2+deb13u1"),
                               kev("CVE-2026-11", "curl", "8.14-2", Severity.HIGH)])
    save_scan(state, "web02", [kev("CVE-2026-10", "brotli", "1.1.0-2+deb13u1")])
    save_scan(state, "old01", [kev("CVE-2026-11", "curl", "7.88-10+deb12u9", Severity.HIGH)])
    save_scan(state, "mail01", [kev("CVE-2026-10", "brotli", "1.1.0-2+deb13u1")])
    save_patch(state, "p1", "mail01", "failed", "2026-10-23T02:00:00+00:00", "apt failed")
    save_scan(state, "clean01")
    st = statuspage.collect(cfg, state, datetime(2026, 11, 2, 6, 30, tzinfo=UTC))
    page = statuspage.render(cfg, state, st=st)
    data = statuspage.status_json(st)
    state.close()

    attention = page.split("<h2>Needs attention</h2>")[1].split("<h2>Hosts</h2>")[0]
    items = re.findall(r"<li>(.*?)</li>", attention)
    assert len(items) == 3  # mail01 failed; one entry per vulnerability
    assert items[0].startswith('<a href="#mail01">mail01</a>: last patch run')
    # the same fixed version everywhere: given once, then the hosts
    assert "CVE-2026-10" in items[1] and "critical" in items[1]
    assert items[1].endswith(
        " in brotli, fixed in <code>1.1.0-2+deb13u1</code> — "
        '<a href="#web01">web01</a>, <a href="#web02">web02</a>, '
        '<a href="#mail01">mail01</a>')
    # different fixed versions (e.g. Debian 12 and 13): one per host
    assert "CVE-2026-11" in items[2] and "high" in items[2]
    assert items[2].endswith(
        ' in curl — <a href="#web01">web01</a> (fixed in <code>8.14-2</code>), '
        '<a href="#old01">old01</a> (fixed in <code>7.88-10+deb12u9</code>)')

    # status.json still counts per host and problem, as before the grouping
    assert data["needs_attention"] == 6
    by_name = {h["name"]: h["needs_attention"] for h in data["hosts_detail"]}
    assert by_name == {"web01": 2, "web02": 1, "old01": 1, "mail01": 2, "clean01": 0}


def test_nothing_needs_attention(make_config):
    cfg = make_config(hosts=[{"name": "web01"}])
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    save_scan(state, "web01")
    save_patch(state, "p1", "web01", "rolled-back", "2026-10-23T02:00:00+00:00")
    page = statuspage.render(cfg, state)
    state.close()
    assert '<h2>Needs attention</h2>\n<p class="good">Nothing needs attention</p>' in page


def time_cfg(make_config, **policy):
    return make_config(policy=policy, hosts=[
        {"name": "web01", "policy": {"modes": ["patch"], "window": ["Mon..Fri 03:00-04:00"]},
         "healthchecks": [{"systemd": "nginx.service"}]},
        {"name": "db01", "policy": {"modes": ["patch"], "window": ["Sun 04:00-05:00"],
                                    "timezone": "America/New_York"},
         "healthchecks": [{"systemd": "postgresql.service"}]}])


def render_times(cfg):
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    for host in ("web01", "db01"):  # scanned in summer time
        state.save_host("r1", HostRecord("r1", host, "192.0.2.30", True, None, {}, [],
                                         "2026-10-23T06:00:00+00:00", []))
    state.finish_run("r1", "ok", {"sources": [{"name": "debian_tracker", "ok": True,
                                                 "checked_at": 1793595600.0}]})  # 2026-11-02 05:00 UTC
    state.save_patch("p1", "web01", "patched", "2026-11-02T06:00:00+00:00",  # winter time
                     {"status": "patched", "started_at": "2026-11-02T06:00:00+00:00",
                      "items": []})
    page = statuspage.render(cfg, state, now=datetime(2026, 11, 2, 6, 30, tzinfo=UTC))
    state.close()
    return page


def test_times_in_the_global_policy_timezone(make_config):
    page = render_times(time_cfg(make_config, timezone="Europe/Zurich"))
    assert "generated 2026-11-02 07:30 CET · times in Europe/Zurich" in page
    assert "scanned 2026-10-23 08:00 CEST" in page  # summer time
    assert "2026-11-02 07:00 CET" in page  # patch, winter time
    assert "checked 2026-11-02 06:00 CET" in page
    assert "UTC" not in page
    # windows in each host's own zone
    assert "window Mon..Fri 03:00-04:00 (Europe/Zurich)" in page
    assert "window Sun 04:00-05:00 (America/New_York)" in page


def test_times_in_server_local_time(make_config, server_tz):
    server_tz("America/New_York")
    page = render_times(time_cfg(make_config))
    assert "generated 2026-11-02 01:30 EST · times in server local time, America/New_York" in page
    assert "scanned 2026-10-23 02:00 EDT" in page
    assert "2026-11-02 01:00 EST" in page
    assert "window Mon..Fri 03:00-04:00 (server local time, America/New_York)" in page
    assert "window Sun 04:00-05:00 (America/New_York)" in page


def test_server_zone(monkeypatch):
    monkeypatch.setenv("TZ", ":Europe/Zurich")
    assert window.server_zone() == "Europe/Zurich"


def preview_cfg(make_config, **web01_policy):
    return make_config(
        policy={"timezone": "Europe/Zurich"},
        sources={"custom": {"enabled": True}},
        hosts=[
            {"name": "web01", "policy": {"modes": ["report", "patch"],
                                         "window": ["Mon..Fri 03:00-04:00"], **web01_policy},
             "healthchecks": [{"systemd": "nginx.service"}]},
            {"name": "ny01", "policy": {"modes": ["patch"], "window": ["Sun 02:00-03:00"],
                                        "timezone": "America/New_York"},
             "healthchecks": [{"systemd": "nginx.service"}]},
            {"name": "any01", "policy": {"modes": ["patch"]},
             "healthchecks": [{"systemd": "nginx.service"}]},
            {"name": "rep01"}])


def render_preview(cfg, now):
    from tests.unit.test_patch_apt import BLOCK_CURL, fixable

    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    state.set(**{"definitions.data": [BLOCK_CURL]})
    web = [fixable("CVE-2026-1", "openssl", Severity.CRITICAL),
           fixable("CVE-2026-2", "openssl", Severity.CRITICAL),
           fixable("CVE-2026-3", "inetutils", Severity.HIGH),
           fixable("CVE-2026-4", "tar", Severity.MEDIUM),
           fixable("CVE-2026-5", "curl", Severity.HIGH, fixed="8.1-2")]
    for host, findings in [("web01", web), ("ny01", web[3:4]), ("any01", web[:1]),
                           ("rep01", web)]:
        state.save_host("r1", HostRecord("r1", host, "192.0.2.30", True, None,
                                         {"codename": "trixie"}, [],
                                         "2026-11-02T05:00:00+00:00", findings))
    page = statuspage.render(cfg, state, now=now)
    state.close()
    return page


def test_next_window_and_preview(make_config):
    # Monday 2026-11-02 10:00 CET
    page = render_preview(preview_cfg(make_config), datetime(2026, 11, 2, 9, 0, tzinfo=UTC))
    table = page.split("<h2>Hosts</h2>")[1].split("<h2>")[0]
    assert '<th scope="col">Next patch (preview)</th>' in table
    assert ("2026-11-03 03:00 CET<br><span class=\"muted\">would patch: openssl, inetutils "
            "(2 critical, 1 high)</span>") in table
    # in the host's own time zone; nothing allowed by its policy
    assert ("2026-11-08 02:00 EST<br><span class=\"muted\">would patch: nothing (1 fixable, "
            "none allowed by policy (auto-patch: critical, high + KEV): 1 medium)") in table
    assert "any time<br>" in table
    rep_row = next(r for r in table.split("<tr>") if 'href="#rep01"' in r)
    assert rep_row.endswith('<td><span class="muted">-</span></td></tr>')

    web = page.split('<details id="web01">')[1].split('<details id="ny01">')[0]
    assert "Next patch run <span class=\"muted\">· preview based on the last scan " \
           "(2026-11-02 06:00 CET)" in web
    assert "window: 2026-11-03 03:00 CET<br>would patch: openssl, inetutils" in web
    assert "held back</span> fixed version 8.1-2 is blocked by AW-2026-0009" in web
    assert "Next patch run" not in page.split('<details id="rep01">')[1]


def test_preview_window_open_and_severity_policy(make_config):
    # Tuesday 2026-11-03 03:30 CET, inside the window; summer and winter as elsewhere
    cfg = preview_cfg(make_config, auto_patch_severities=["critical"], auto_patch_kev=False)
    page = render_preview(cfg, datetime(2026, 11, 3, 2, 30, tzinfo=UTC))
    assert "open now<br><span class=\"muted\">would patch: openssl (2 critical)</span>" in page


def test_preview_in_summer_time(make_config):
    # Friday 2026-07-03 12:00 CEST: next window Monday 03:00 CEST
    page = render_preview(preview_cfg(make_config), datetime(2026, 7, 3, 10, 0, tzinfo=UTC))
    assert "2026-07-06 03:00 CEST<br>" in page


def test_status_json(make_config):
    names = ["web01", "db01", "mail01", "app01", "new01"]
    cfg = make_config(hosts=[{"name": n} for n in names])
    state = State(cfg.state_dir / "state.db")
    seed(state)  # web01: KEV critical + high fixable, rolled back; db01: scan failed
    save_scan(state, "mail01")
    save_patch(state, "p2", "mail01", "needs-manual-rollback", "2026-10-23T02:10:00+00:00",
               "healthchecks failed")
    save_scan(state, "app01")
    for i in range(2):
        save_patch(state, f"a{i}", "app01", "aborted", f"2026-10-2{i}T02:00:00+00:00", "x")
    path = statuspage.write(cfg, state)
    st = statuspage.collect(cfg, state, datetime(2026, 11, 2, 6, 30, tzinfo=UTC))
    data = statuspage.status_json(st)
    state.close()

    text = (path.parent / "status.json").read_text()
    assert json.loads(text)["hosts_detail"] == json.loads(json.dumps(data))["hosts_detail"]
    # numbers and states only
    for secret in ("openssl", "inetutils", "CVE-", "192.0.2", "script", "timed out",
                   "healthchecks failed", "trixie"):
        assert secret not in text
    assert data["generated_at"] == "2026-11-02T06:30:00Z"
    assert {k: v for k, v in data.items() if k not in ("hosts_detail", "aptwarden",
                                                         "generated_at")} == {
        "last_run": "r1", "hosts": 4, "hosts_failing": 1, "fixable": 2, "critical": 1,
        "high": 1, "kev": 1, "needs_attention": 4, "not_scanned": 1}
    by_name = {h["name"]: h for h in data["hosts_detail"]}
    assert by_name["web01"] == {
        "name": "web01", "scan_ok": True, "scanned_at": "2026-10-23T06:00:00Z",
        "last_patch": "rolled-back", "last_patch_at": "2026-10-23T02:00:00Z", "fixable": 2,
        "critical": 1, "high": 1, "kev": 1, "needs_attention": 1}
    assert by_name["db01"]["scan_ok"] is False
    assert by_name["mail01"]["last_patch"] == "needs-manual-rollback"
    assert by_name["mail01"]["needs_attention"] == 1
    assert by_name["app01"]["needs_attention"] == 1  # repeated aborts
    assert by_name["new01"]["scan_ok"] is None and by_name["new01"]["scanned_at"] is None


def test_status_json_all_clear(make_config):
    cfg = make_config(hosts=[{"name": "web01"}])
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    save_scan(state, "web01")
    data = statuspage.status_json(statuspage.collect(cfg, state))
    state.close()
    assert data["needs_attention"] == 0 and data["hosts_failing"] == 0
    assert data["hosts_detail"][0]["scan_ok"] is True


def test_trend_without_repeated_points():
    # unchanged values on most scans: each would repeat the point its step ends on
    values = [(5, 1, 2), (5, 1, 2), (5, 1, 2), (7, 2, 2), (7, 2, 2), (1, 0, 1), (1, 0, 1),
              (13, 3, 4), (13, 3, 4), (0, 0, 0)]
    points = [(f"2026-10-{day:02d}T06:00:00+00:00", *v) for day, v in enumerate(values, 1)]
    svg = statuspage._trend(points, "UTC")

    lines = dict(re.findall(r'<polyline class="(\w+)" points="([^"]+)"', svg))
    assert set(lines) == {"total", "crit", "hi"}
    for col, cls in ((0, "total"), (1, "crit"), (2, "hi")):
        coords = [tuple(map(float, c.split(","))) for c in lines[cls].split()]
        assert all(coords[i] != coords[i - 1] for i in range(1, len(coords))), cls
        for c in lines[cls].split():
            assert re.fullmatch(r"\d+(\.\d)?,\d+(\.\d)?", c) and ".0," not in c + ","
        # the same step shape: every scan's value is reached at its x, and held until the next
        xs = sorted({x for x, _ in coords})
        assert len(xs) == len(values)
        top = 13
        for i, x in enumerate(xs):
            y = round(4 + 48 * (1 - values[i][col] / top), 1)
            assert (x, y) in coords
            if i:
                y_before = round(4 + 48 * (1 - values[i - 1][col] / top), 1)
                assert (x, y_before) in coords
        # a horizontal run over unchanged scans keeps its end points only
        assert len(coords) == 2 * len(values) - 1 - sum(
            values[i][col] == values[i - 1][col] for i in range(1, len(values)))

    # the values for screen readers and tooltips are unchanged
    summary = ("Fixable vulnerabilities, 10 scans, 2026-10-01 06:00 UTC – 2026-10-10 06:00 UTC: "
               "now 0 (0 critical, 0 high), highest 13")
    assert f'aria-label="{summary}"><title>{summary}</title>' in svg
    assert re.findall(r"<circle[^>]*><title>([^<]+)</title>", svg) == [
        f"{when[:10]} 06:00 UTC: {t} fixable, {c} critical, {h} high"
        for when, t, c, h in points]


def test_table_headers_have_scope(make_config):
    cfg = make_config(hosts=[{"name": "web01"}, {"name": "db01"}])
    state = State(cfg.state_dir / "state.db")
    seed(state)
    page = statuspage.render(cfg, state)
    state.close()
    headers = re.findall(r"<th[ >]", page)
    assert len(headers) > 10
    assert len(headers) == page.count('<th scope="col">')


def save_health(state, run_id, host, status, started, **health):
    state.save_patch(run_id, host, status, started,
                     {"run_id": run_id, "status": status, "started_at": started,
                      "reason": "", "items": [], **health})


def host_details(page, host):
    return page.split(f'<details id="{host}">')[1].split("</details>\n")[0]


def test_latest_healthcheck_results(make_config):
    cfg = make_config(hosts=[{"name": "web01"}, {"name": "db01"}, {"name": "new01"}])
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    for host in ("web01", "db01", "new01"):
        save_scan(state, host)
    # web01: an older run with results after patching, then one with only "before"
    # results, then a run without healthchecks (nothing to do)
    save_health(state, "p1", "web01", "patched", "2026-10-20T02:00:00+00:00",
                health_before=["systemd nginx.service: ok (active)"],
                health_after=["systemd nginx.service: ok (active)"])
    save_health(state, "p2", "web01", "aborted", "2026-10-21T02:00:00+00:00",
                health_before=["systemd nginx.service: ok (active)",
                               "http https://web01.example.org/: FAILED (HTTP 502: "
                               f"{EVIL})",
                               "tcp 192.0.2.10:443: ok"])
    save_health(state, "p3", "web01", "nothing-to-do", "2026-10-22T02:00:00+00:00")
    # db01: rolled back, health_after wins over health_before
    save_health(state, "p4", "db01", "rolled-back", "2026-10-22T02:00:00+00:00",
                health_before=["systemd postgresql.service: FAILED (inactive)"],
                health_after=["systemd postgresql.service: ok (active)", "garbage line"])
    page = statuspage.render(cfg, state)
    state.close()

    web = host_details(page, "web01")
    assert ('<h3>Healthchecks <span class="muted">· before patching, 2026-10-21 02:00 UTC, '
            'run <code>p2</code></span> <span class="badge warn">aborted</span></h3>') in web
    assert ('<li><span class="good">✓</span> <code>systemd nginx.service</code> '
            '<span class="muted">active</span></li>') in web
    # the check name keeps its colon; the detail is escaped
    assert ('<li><span class="bad">✗</span> <code>http https://web01.example.org/</code> '
            '<span class="muted">HTTP 502: &lt;script&gt;') in web
    assert "<script" not in page
    assert '<li><span class="good">✓</span> <code>tcp 192.0.2.10:443</code></li>' in web

    db = host_details(page, "db01")
    assert "· after the rollback, 2026-10-22 02:00 UTC, run <code>p4</code>" in db
    assert "postgresql.service</code> <span class=\"muted\">active</span>" in db
    assert "inactive" not in db
    assert '<li><span class="muted">?</span> garbage line</li>' in db

    assert "<h3>Healthchecks" not in host_details(page, "new01")


def test_healthcheck_results_beyond_the_patch_history(make_config):
    cfg = make_config(hosts=[{"name": "web01"}])
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    save_scan(state, "web01")
    save_health(state, "p0", "web01", "patched", "2026-10-01T02:00:00+00:00",
                health_after=["systemd ssh.service: ok (active)"])
    for day in range(10, 20):  # more runs without checks than the history shows
        save_health(state, f"n{day}", "web01", "nothing-to-do", f"2026-10-{day}T02:00:00+00:00")
    page = statuspage.render(cfg, state)
    state.close()
    assert "· after patching, 2026-10-01 02:00 UTC, run <code>p0</code>" in page


def test_fixable_history(make_config):
    cfg = make_config(hosts=[{"name": "web01"}, {"name": "db01"}, {"name": "new01"}])
    state = State(cfg.state_dir / "state.db")
    crit = Finding("CVE-1", "openssl", "1", FindingStatus.FIXABLE, fixed_version="2",
                   severity=Severity.CRITICAL)
    high = Finding("CVE-2", "curl", "1", FindingStatus.FIXABLE, fixed_version="2",
                   severity=Severity.HIGH)
    low = Finding("CVE-3", "tar", "1", FindingStatus.FIXABLE, fixed_version="2",
                  severity=Severity.LOW)
    nofix = Finding("CVE-4", "vim", "1", FindingStatus.NO_FIX, severity=Severity.CRITICAL)
    scans = [("r1", "2026-07-20T06:00:00+00:00", True, [crit, high, low, nofix]),
             ("r2", "2026-10-21T06:00:00+00:00", False, []),  # failed scans are left out
             ("r3", "2026-10-22T06:00:00+00:00", True, [high, low]),
             ("r4", "2026-11-02T06:00:00+00:00", True, [])]
    for run_id, when, ok, findings in scans:
        state.start_run(run_id, "report")
        state.save_host(run_id, HostRecord(run_id, "web01", "192.0.2.10", ok,
                                           None if ok else "boom", {}, [], when, findings))
    state.save_host("r4", HostRecord("r4", "db01", "192.0.2.20", True, None, {}, [],
                                     "2026-11-02T06:00:00+00:00", [high]))
    assert state.fixable_history("web01") == [
        ("2026-07-20T06:00:00+00:00", 3, 1, 1), ("2026-10-22T06:00:00+00:00", 2, 0, 1),
        ("2026-11-02T06:00:00+00:00", 0, 0, 0)]
    page = statuspage.render(cfg, state, now=datetime(2026, 11, 2, 7, 0, tzinfo=UTC))
    state.close()

    web = host_details(page, "web01")
    svg = web.split("<svg")[1].split("</svg>")[0]
    # the values in <title>, for the chart and each scan
    assert ("<title>Fixable vulnerabilities, 3 scans, 2026-07-20 06:00 UTC – 2026-11-02 "
            "06:00 UTC: now 0 (0 critical, 0 high), highest 3</title>") in svg
    assert "<title>2026-10-22 06:00 UTC: 2 fixable, 0 critical, 1 high</title>" in svg
    assert svg.count('<circle class="hit"') == 3
    assert {'class="total"', 'class="crit"', 'class="hi"'} <= set(
        re.findall(r'class="\w+"', svg))
    # the period is stated, colours only through CSS variables
    assert "3 stored scans, 2026-07-20 06:00 UTC – 2026-11-02 06:00 UTC" in web
    assert "#" not in svg and "style=" not in svg and "<script" not in svg
    assert ".trend .crit{stroke:var(--crit)}" in page

    # step line: the value holds until the next scan (y = 4 at 3 of 3, 52 at 0); one decimal,
    # whole numbers without
    total = re.search(r'<polyline class="total" points="([^"]+)"', svg)[1].split()
    assert total == ["4,4", "265.4,4", "265.4,20", "296,20", "296,52"]
    assert '<circle r="2" cx="296" cy="52"/>' in svg

    db = host_details(page, "db01")
    assert "1 stored scan, 2026-11-02 06:00 UTC" in db and "<polyline" not in db
    assert '<details id="new01">' not in page  # never scanned: no section, no chart
