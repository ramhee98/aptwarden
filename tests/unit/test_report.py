import json

from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.report import group_findings, render_json, render_text
from aptwarden.sources import SourceStatus
from aptwarden.state import HostRecord


def f(vid, pkg="openssl", sev=Severity.HIGH, status=FindingStatus.FIXABLE, fixed="3.5.4-1",
      score=None, kev=False, installed="3.5.1-1"):
    return Finding(vid, pkg, installed, status, fixed_version=fixed, severity=sev,
                   cvss_score=score, kev=kev, description=f"description of {vid}")


def host(findings, ok=True, warnings=()):
    return HostRecord("r1", "web01", "192.0.2.10", ok, None if ok else "ssh: unreachable",
                      {"debian_version": "13.1", "codename": "trixie", "package_count": 249},
                      list(warnings), "2026-10-22T10:00:00+00:00", findings)


FINDINGS = [
    f("CVE-1", sev=Severity.CRITICAL, score=9.8, fixed="3.5.4-1~deb13u2"),
    f("CVE-2", sev=Severity.MEDIUM, fixed="3.5.7-1~deb13u3"),
    f("CVE-3", pkg="inetutils", sev=Severity.CRITICAL, score=9.8, kev=True, fixed="2:2.6-3+deb13u3",
      installed="2:2.6-3"),
    f("CVE-4", pkg="zlib", sev=Severity.LOW, fixed="1:1.3-2", installed="1:1.3-1"),
    f("CVE-5", pkg="tar", sev=Severity.HIGH, status=FindingStatus.NO_FIX, fixed=None),
    f("CVE-6", pkg="tar", sev=Severity.LOW, status=FindingStatus.FIX_PENDING, fixed="1.35-2"),
    f("CVE-7", pkg="curl", sev=Severity.UNKNOWN, fixed="8.14.1-2"),
    f("CVE-8", pkg="sudo", sev=Severity.LOW, kev=True, fixed="1.9.16-2"),
]
SOURCES = [SourceStatus("debian_tracker", checked_at=1761130000.0), SourceStatus("kev")]


def test_group_findings_order_and_target_version():
    groups = group_findings([x for x in FINDINGS if x.status == FindingStatus.FIXABLE])
    assert [g.source_package for g in groups] == ["inetutils", "openssl", "sudo", "zlib",
                                                  "curl"]  # KEV first within a severity
    ssl = groups[1]
    assert ssl.target_version == "3.5.7-1~deb13u3"  # fixes every finding of the package
    assert ssl.severity == Severity.CRITICAL
    assert ssl.top.vuln_id == "CVE-1"


def test_render_text_default():
    out = render_text([host(FINDINGS)], SOURCES, min_severity=Severity.HIGH, title="t")
    assert "fixable now: 6 vulnerabilities in 5 packages" in out
    assert "critical 2 · medium 1 · low 2 · unknown 1" in out
    assert "KEV 2" in out
    assert "fix pending 1 · no fix 1 · undetermined 0" in out
    lines = out.splitlines()
    table = [ln for ln in lines if ln.startswith("  critical") or ln.startswith("  low")]
    assert "inetutils" in table[0] and "CVE-3 9.8 KEV" in table[0]
    assert "openssl" in table[1] and "3.5.7-1~deb13u3" in table[1]
    # KEV and unscored packages stay visible, only known-low zlib is hidden
    assert "  low       sudo" in out
    assert "  unknown   curl" in out
    assert "zlib" not in out
    assert "1 more fixable packages below high" in out
    assert "not fixable yet" not in out


def test_render_text_all_and_cves():
    out = render_text([host(FINDINGS)], SOURCES, min_severity=Severity.LOW, show_all=True,
                      show_cves=True)
    assert "not fixable yet:" in out
    assert "fix-pending,no-fix" in out
    assert "description of CVE-2" in out
    assert "below" not in out


def test_render_text_errors_and_warnings():
    out = render_text([host([], ok=False), host([], warnings=["reboot required"])],
                      [SourceStatus("debian_tracker", ok=False, message="refresh failed: x")],
                      min_severity=Severity.HIGH)
    assert "ERROR: ssh: unreachable" in out
    assert "! reboot required" in out
    assert "source debian_tracker: UNAVAILABLE" in out
    assert "NO VULNERABILITY DATA AVAILABLE" in out


def test_render_json_is_complete():
    doc = json.loads(render_json([host(FINDINGS)], SOURCES, run_id="r1", status="ok"))
    assert doc["run_id"] == "r1"
    [h] = doc["hosts"]
    assert len(h["findings"]) == len(FINDINGS)
    assert h["counts"] == {"fixable": 6, "no-fix": 1, "fix-pending": 1}
    assert h["findings"][0]["severity"] == "critical"
    assert doc["sources"][0]["name"] == "debian_tracker"


def test_cve_listing_keeps_columns_aligned():
    out = render_text([host(FINDINGS)], SOURCES, min_severity=Severity.LOW, show_cves=True)
    lines = out.splitlines()
    header = next(ln for ln in lines if ln.lstrip().startswith("SEVERITY"))
    col = header.index("FIXED")
    rows = [ln for ln in lines if ln.startswith("  critical") or ln.startswith("  low")]
    assert rows and all(ln[col - 2:col] == "  " and ln[col] != " " for ln in rows)
