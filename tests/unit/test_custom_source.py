import pytest

from aptwarden.definitions import parse
from aptwarden.definitions.sync import SyncError, SyncResult
from aptwarden.enrich import enrich
from aptwarden.matcher import merge
from aptwarden.models import FindingStatus, HostInventory, Package, Severity
from aptwarden.notify import alert_candidates
from aptwarden.sources.custom import CustomSource
from aptwarden.sources.debian_tracker import DebianTrackerSource
from aptwarden.state import State
from tests.conftest import FakeHttp
from tests.unit.test_definitions import VALID, defn

SETTINGS = {"enabled": True, "url": "https://example.org/defs.git", "ref": "signed-tags",
            "branch": "main", "tag_pattern": r"^v.*$", "allowed_signers_file": "signers",
            "path": "definitions", "refresh_interval": "1h"}

INETUTILS = defn(id="AW-2026-0002", aliases=["CVE-2026-24061"], package="inetutils",
                 summary="inetutils telnetd: auth bypass", action="auto-patch",
                 affected=[{"release": "trixie", "ranges": [
                     {"introduced": "0", "fixed": "2:2.6-3+deb13u1"}]}])
# A definition overruling the tracker: our version is not affected.
OVERRULE = defn(id="AW-2026-0003", aliases=["CVE-2026-0001"], package="openssl",
                summary="openssl: false positive", severity="low", action="report",
                affected=[{"release": "trixie", "ranges": [
                    {"introduced": "3.6.0", "fixed": "3.6.1-1"}]}])


def definition(text, name):
    d, errors, _ = parse(text, name)
    assert not errors, errors
    return d


def inventory(**versions):
    pkgs = [Package(name, v, "amd64", src, v, "ii ") for name, (src, v) in versions.items()]
    return HostInventory("web01", "debian", "13", "trixie", "13.1", "amd64", pkgs)


@pytest.fixture
def setup(cache, tmp_path):
    state = State(tmp_path / "state.db")
    src = CustomSource(SETTINGS, cache, FakeHttp(), state=state, base_dir=tmp_path)
    defs = [definition(VALID, "AW-2026-0001.yaml"),
            definition(INETUTILS, "AW-2026-0002.yaml"),
            definition(OVERRULE, "AW-2026-0003.yaml")]
    state.set(**{"definitions.data": [d.to_dict() for d in defs],
                 "definitions.ref": "v2026.10.22", "definitions.commit": "abc123"})
    tracker = DebianTrackerSource({"url": "x", "refresh_interval": "1h", "max_age": "3d"},
                                  cache, FakeHttp())
    tracker.load({
        "inetutils": {"CVE-2026-24061": {"releases": {"trixie": {
            "status": "resolved", "fixed_version": "2:2.6-3+deb13u1", "urgency": "low",
            "repositories": {"trixie-security": "2:2.6-3+deb13u3"}}}}},
        "openssl": {"CVE-2026-0001": {"releases": {"trixie": {
            "status": "resolved", "fixed_version": "3.5.4-1", "urgency": "high",
            "repositories": {"trixie": "3.5.4-1"}}}}},
    })
    yield src, tracker, state
    state.close()


def test_block_and_precedence(setup):
    src, tracker, _ = setup
    inv = inventory(**{"liblzma5:amd64": ("xz-utils", "5.6.1-1"),
                       "inetutils-telnet": ("inetutils", "2:2.6-3"),
                       "openssl": ("openssl", "3.5.1-1")})
    custom = src.match([inv])["web01"]
    tracked = tracker.match([inv])["web01"]
    merged = {f.vuln_id: f for f in merge([(50, tracked), (0, custom)])}

    xz = merged["CVE-2024-3094"]
    assert (xz.action, xz.definition, xz.severity) == ("block", "AW-2026-0001", Severity.CRITICAL)
    assert xz.status == FindingStatus.FIXABLE and xz.fixed_version == "5.6.1+really5.4.5-1"

    tel = merged["CVE-2026-24061"]
    assert tel.origins == ["custom", "debian_tracker"]
    assert tel.action == "auto-patch" and tel.severity == Severity.CRITICAL
    assert tel.status == FindingStatus.FIXABLE  # tracker repos have the fix

    # the tracker says vulnerable, the definition says not affected: dropped
    assert "CVE-2026-0001" not in merged


def test_definition_severity_beats_cvss(setup):
    src, _, _ = setup
    [f] = src.match([inventory(inetutils=("inetutils", "2:2.6-3"))])["web01"]

    class Lookup:
        pending = 0

        def lookup(self, ids):
            from aptwarden.enrich.cvss import CvssResult
            return {i: CvssResult(5.0, "3.1", "v", "osv") for i in ids}

    enrich({"web01": [f]}, Lookup(), None)
    assert f.severity == Severity.CRITICAL and f.cvss_score == 5.0
    assert f.severity_reason == "definition AW-2026-0002"


def test_blocked_versions_always_alert(setup):
    src, _, _ = setup
    [f] = src.match([inventory(xz=("xz-utils", "5.6.0-0.2"))])["web01"]
    f.severity = Severity.LOW
    assert alert_candidates([f], {"min_severity": "critical", "kev": True}) == [f]


def test_fix_pending_when_repos_lag(setup):
    src, tracker, _ = setup
    tracker.load({"inetutils": {"CVE-2026-24061": {"releases": {"trixie": {
        "status": "resolved", "fixed_version": "2:2.6-3+deb13u1",
        "repositories": {"trixie": "2:2.6-3"}}}}}})
    [f] = src.match([inventory(inetutils=("inetutils", "2:2.6-3"))])["web01"]
    assert f.status == FindingStatus.FIX_PENDING


def test_expired_and_other_release_are_ignored(setup):
    src, _, state = setup
    d = definition(defn(expires="2020-01-01"), "AW-2026-0001.yaml")
    state.set(**{"definitions.data": [d.to_dict()]})
    assert src.match([inventory(xz=("xz-utils", "5.6.1-1"))])["web01"] == []


def test_refresh_activates_and_remembers_rejections(setup, monkeypatch):
    src, _, state = setup
    calls = []

    def fake_sync(accepted, rejected):
        calls.append((accepted, set(rejected)))
        return SyncResult(changed=True, ref="v2026.10.23", commit="def456",
                          definitions=[definition(VALID, "AW-2026-0001.yaml")],
                          problems=["tag v2026.10.24 rejected: unsigned"],
                          rejected=["v2026.10.24"])

    monkeypatch.setattr(src.git, "sync", fake_sync)
    status = src.refresh()
    assert calls == [("abc123", set())]
    assert status.alerts == ["tag v2026.10.24 rejected: unsigned"]
    assert "v2026.10.23" in status.message and "1 definitions" in status.message
    assert state.get("definitions.rejected") == ["v2026.10.24"]

    src.refresh()  # within refresh_interval: no sync
    assert len(calls) == 1
    src.refresh(force=True)
    assert calls[-1] == ("def456", {"v2026.10.24"})


def test_sync_failure_keeps_definitions(setup, monkeypatch):
    src, _, _ = setup

    def boom(accepted, rejected):
        raise SyncError("git fetch failed: could not resolve host")

    monkeypatch.setattr(src.git, "sync", boom)
    status = src.refresh(force=True)
    assert status.ok and "keeping the active definitions" in status.warnings[0]
    assert len(src.definitions()) == 3


def test_relative_allowed_signers_resolve_against_config_dir(setup, tmp_path):
    src, _, _ = setup
    assert src.git.allowed_signers == tmp_path / "signers"
