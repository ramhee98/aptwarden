import os
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
    cfg = make_config(hosts=[{"name": "web01"}, {"name": "db01"}, {"name": "new01"}])
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
