import json
import time

import pytest

from aptwarden.http import HttpError, Response
from aptwarden.inventory import parse_dpkg_query
from aptwarden.models import FindingStatus, HostInventory, Package
from aptwarden.sources import debian_tracker
from aptwarden.sources.debian_tracker import DebianTrackerSource, _classify
from tests.conftest import FakeHttp, fixture_json, fixture_text

URL = "https://security-tracker.debian.org/tracker/data/json"
SETTINGS = {"enabled": True, "url": URL, "refresh_interval": "1h", "max_age": "3d"}


def rel(status, fixed=None, repos=None, urgency="not yet assigned", **extra):
    r = {"status": status, "repositories": repos or {}, "urgency": urgency, **extra}
    if fixed is not None:
        r["fixed_version"] = fixed
    return r


MINI = {
    "openssl": {
        "CVE-2026-0001": {"description": "fixable via security",
                          "releases": {"trixie": rel("resolved", "3.5.4-1~deb13u2", {
                              "trixie": "3.5.1-1", "trixie-security": "3.5.4-1~deb13u2"})}},
        "CVE-2026-0002": {"description": "fix only in next point release",
                          "releases": {"trixie": rel("resolved", "3.5.5-1~deb13u1",
                                                     {"trixie": "3.5.1-1"},
                                                     next_point_update=True)}},
        "CVE-2026-0003": {"description": "already fixed in installed version",
                          "releases": {"trixie": rel("resolved", "3.5.0-1",
                                                     {"trixie": "3.5.1-1"})}},
        "CVE-2026-0004": {"description": "never affected",
                          "releases": {"trixie": rel("resolved", "0", {"trixie": "3.5.1-1"})}},
        "CVE-2026-0005": {"description": "open, no fix",
                          "releases": {"trixie": rel("open", None, {"trixie": "3.5.1-1"},
                                                     urgency="unimportant")}},
        "CVE-2026-0006": {"releases": {"trixie": rel("undetermined", None,
                                                     {"trixie": "3.5.1-1"})}},
        "CVE-2026-0007": {"description": "other release only",
                          "releases": {"bookworm": rel("resolved", "3.0.17-1~deb12u3", {
                              "bookworm": "3.0.17-1~deb12u2"})}},
        "TEMP-1234567-ABCDEF": {"releases": {"trixie": rel(
            "resolved", "3.5.4-1~deb13u2", {"trixie-security": "3.5.4-1~deb13u2"},
            nodsa="Minor issue", nodsa_reason="")}},
    },
    "zlib": {
        "CVE-2026-0100": {"releases": {"trixie": rel("resolved", "1:1.3.dfsg+really1.3.1-2",
                                                     {"trixie": "1:1.3.dfsg+really1.3.1-1"})}},
    },
}


def inventory(packages, codename="trixie"):
    return HostInventory("web01", "debian", "13", codename, "13.1", "amd64", packages)


def pkg(name, version, source=None, source_version=None):
    return Package(name, version, "amd64", source or name, source_version or version, "ii ")


@pytest.fixture
def source(cache):
    s = DebianTrackerSource(SETTINGS, cache, FakeHttp())
    s.load(MINI)
    return s


def test_match_statuses(source):
    inv = inventory([pkg("libssl3t64", "3.5.1-1", "openssl"), pkg("openssl", "3.5.1-1")])
    findings = {f.vuln_id: f for f in source.match([inv])["web01"]}
    assert findings["CVE-2026-0001"].status == FindingStatus.FIXABLE
    assert findings["CVE-2026-0001"].fixed_version == "3.5.4-1~deb13u2"
    assert findings["CVE-2026-0001"].binaries == ["libssl3t64", "openssl"]
    assert findings["CVE-2026-0001"].description == "fixable via security"
    assert findings["CVE-2026-0002"].status == FindingStatus.FIX_PENDING
    assert findings["CVE-2026-0005"].status == FindingStatus.NO_FIX
    assert findings["CVE-2026-0005"].fixed_version is None
    assert findings["CVE-2026-0005"].urgency == "unimportant"
    assert findings["CVE-2026-0006"].status == FindingStatus.UNDETERMINED
    assert findings["TEMP-1234567-ABCDEF"].nodsa is True
    for not_affected in ("CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0007"):
        assert not_affected not in findings


def test_match_uses_source_version_not_binary_version(source):
    # binary has an epoch the source lacks; comparing it would hide the finding
    inv = inventory([pkg("libssl3t64", "1:3.5.1-1", "openssl", "3.5.1-1")])
    ids = {f.vuln_id for f in source.match([inv])["web01"]}
    assert "CVE-2026-0001" in ids


def test_match_with_epochs(source):
    inv = inventory([pkg("zlib1g", "1:1.3.dfsg+really1.3.1-1", "zlib")])
    [f] = source.match([inv])["web01"]
    assert f.status == FindingStatus.FIX_PENDING  # fix not in any repository yet


def test_fully_patched_host_has_no_fixable(source):
    inv = inventory([pkg("openssl", "3.5.5-1~deb13u1")])
    findings = source.match([inv])["web01"]
    assert all(f.status != FindingStatus.FIXABLE for f in findings)
    assert {f.vuln_id for f in findings} == {"CVE-2026-0005", "CVE-2026-0006"}


def test_unknown_release_warns(source):
    inv = inventory([pkg("openssl", "3.5.1-1")], codename="duke")
    assert source.match([inv]) == {"web01": []}
    assert "duke" in source.host_warnings["web01"][0]


def test_classify_rejects_bad_version():
    with pytest.raises(ValueError):
        _classify("1.0", "resolved", "1:", {})


def test_realistic_subset_against_real_inventory(cache):
    s = DebianTrackerSource(SETTINGS, cache, FakeHttp())
    s.load(fixture_json("tracker-trixie-subset.json.gz"))
    packages = parse_dpkg_query(fixture_text("dpkg-query-trixie.txt"))
    findings = s.match([inventory(packages)])["web01"]
    fixable = [f for f in findings if f.status == FindingStatus.FIXABLE]
    by_pkg = {f.source_package for f in fixable}
    # Debian 13.1 container vs tracker state of 2026-10-22, cross-checked
    # against `apt list --upgradable` on the same host.
    assert len(by_pkg) == 28
    assert {"openssl", "glibc", "openssh", "inetutils", "util-linux"} <= by_pkg
    ssl = [f for f in fixable if f.source_package == "openssl"]
    assert all(f.installed_version == "3.5.1-1+deb13u1" for f in ssl)
    assert "libssl3t64:amd64" in ssl[0].binaries


def test_refresh_downloads_and_uses_conditional_get(cache, monkeypatch):
    monkeypatch.setattr(debian_tracker, "MIN_SOURCE_PACKAGES", 1)
    lm = "Thu, 22 Oct 2026 12:32:07 GMT"
    http = FakeHttp({("GET", URL): Response(200, json.dumps(MINI).encode(),
                                            {"last-modified": lm})})
    s = DebianTrackerSource(SETTINGS, cache, http)
    status = s.refresh()
    assert status.ok and status.updated_at
    assert s.releases() == {"trixie", "bookworm"}

    # within refresh_interval: no request
    s.refresh()
    assert len(http.calls) == 1

    # forced: no If-Modified-Since; due: with If-Modified-Since, 304 keeps data
    cache.set_time("debian_tracker.checked_at", time.time() - 7200)
    http.routes[("GET", URL)] = Response(304)
    status = s.refresh()
    assert http.calls[-1][2]["If-Modified-Since"] == lm
    assert status.ok and s.has_data()


def test_refresh_failure_keeps_old_data(cache, monkeypatch):
    monkeypatch.setattr(debian_tracker, "MIN_SOURCE_PACKAGES", 1)
    s = DebianTrackerSource(SETTINGS, cache, FakeHttp({("GET", URL): Response(
        200, json.dumps(MINI).encode())}))
    s.refresh()
    s.http.routes[("GET", URL)] = HttpError(URL, "timed out")
    status = s.refresh(force=True)
    assert status.ok  # stale but usable
    assert "refresh failed" in status.message
    assert s.has_data()


def test_refresh_rejects_truncated_feed(cache):
    s = DebianTrackerSource(SETTINGS, cache, FakeHttp({("GET", URL): Response(
        200, json.dumps(MINI).encode())}))
    status = s.refresh()
    assert not status.ok
    assert "truncated" in status.message
    assert not s.has_data()


def test_stale_data_warns(source, cache):
    cache.set_time("debian_tracker.checked_at", time.time() - 4 * 86400)
    source.offline = True
    status = source.refresh()
    assert status.ok
    assert any("not verified" in w for w in status.warnings)


def test_offline_without_data_is_not_ok(cache):
    s = DebianTrackerSource(SETTINGS, cache, FakeHttp(), offline=True)
    assert not s.refresh().ok
