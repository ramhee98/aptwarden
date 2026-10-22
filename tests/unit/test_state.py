from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.state import HostRecord, State


def record(run_id, ok=True, findings=(), scanned_at="2026-10-22T10:00:00+00:00"):
    return HostRecord(run_id, "web01", "192.0.2.10", ok, None if ok else "unreachable",
                      {"codename": "trixie"}, [], scanned_at, list(findings))


def finding(vid="CVE-1"):
    return Finding(vid, "openssl", "1.0-1", FindingStatus.FIXABLE, fixed_version="1.0-2",
                   severity=Severity.HIGH, kev=True, binaries=["libssl3t64"])


def test_save_and_load_latest(tmp_path):
    st = State(tmp_path / "state.db")
    st.start_run("r1", "report")
    st.save_host("r1", record("r1", findings=[finding()]))
    st.finish_run("r1", "ok", {"sources": []})
    st.start_run("r2", "report")
    st.save_host("r2", record("r2", ok=False, scanned_at="2026-10-22T11:00:00+00:00"))
    st.finish_run("r2", "partial", {})

    latest = st.latest("web01")
    assert latest.run_id == "r2" and not latest.ok
    good = st.latest("web01", ok_only=True)
    assert good.run_id == "r1"
    [f] = good.findings
    assert (f.vuln_id, f.status, f.severity, f.kev) == (
        "CVE-1", FindingStatus.FIXABLE, Severity.HIGH, True)
    assert st.run_info("r1")["status"] == "ok"
    assert st.latest("other") is None


def test_mark_seen_keeps_first_seen(tmp_path):
    st = State(tmp_path / "state.db")
    a = [finding()]
    st.mark_seen("web01", a, now="2026-10-01T00:00:00+00:00")
    b = [finding()]
    st.mark_seen("web01", b, now="2026-10-22T00:00:00+00:00")
    assert b[0].first_seen == "2026-10-01T00:00:00+00:00"


def test_prune_cascades(tmp_path):
    st = State(tmp_path / "state.db")
    for i in range(5):
        rid = f"r{i}"
        st.start_run(rid, "report")
        st.save_host(rid, record(rid, findings=[finding()],
                                 scanned_at=f"2026-10-22T1{i}:00:00+00:00"))
    assert st.prune(2) == 3
    assert st.db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
    assert st.latest("web01").run_id == "r4"


def test_reopen_keeps_data(tmp_path):
    st = State(tmp_path / "state.db")
    st.start_run("r1", "report")
    st.close()
    assert State(tmp_path / "state.db").run_info("r1")["command"] == "report"
