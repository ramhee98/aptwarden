import os
import re
import stat

from aptwarden import statuspage
from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.state import HostRecord, State

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
    assert [p.name for p in path.parent.iterdir()] == ["index.html"]  # no temp files left


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
    entries = re.findall(r'<li><a href="#([\w.-]+)">', attention)
    assert entries == ["mail01", "db01", "web01", "app01"]
    assert "needs-manual-rollback" in attention and "rollback: manual" in attention
    assert "latest scan 2026-10-23T06:00:00+00:00 failed: ssh: timed out" in attention
    assert "CVE-2026-24061" in attention and "2:2.6-3+deb13u3" in attention
    assert "CVE-2026-2<" not in attention  # fixable, but not known exploited
    assert "2 patch runs in a row · simulation: held packages" in attention
    assert "rolled-back" not in attention  # fixed itself
    assert "once01" not in attention  # a single abort is not yet a pattern

    table = page.split("<h2>Hosts</h2>")[1].split("<h2>")[0]
    assert re.findall(r'<tr><td><a href="#([\w.-]+)">', table) == [
        "db01", "mail01", "web01", "crit01", "high01", "aaa01", "app01", "once01"]


def test_nothing_needs_attention(make_config):
    cfg = make_config(hosts=[{"name": "web01"}])
    state = State(cfg.state_dir / "state.db")
    state.start_run("r1", "report")
    save_scan(state, "web01")
    save_patch(state, "p1", "web01", "rolled-back", "2026-10-23T02:00:00+00:00")
    page = statuspage.render(cfg, state)
    state.close()
    assert '<h2>Needs attention</h2>\n<p class="good">Nothing needs attention</p>' in page
