import json

import pytest

from aptwarden.http import HttpError, Response
from aptwarden.models import FindingStatus, HostInventory, Package
from aptwarden.sources.osv import (
    OsvSource,
    ecosystem,
    evaluate_ranges,
    normalize_id,
    pro_ecosystem,
)
from tests.conftest import FakeHttp, fixture_json, json_response

URL = "https://api.osv.dev"
SETTINGS = {"enabled": True, "url": URL, "workers": 2}
ECO = "Debian:13"


def inventory(host="web01", version="3.5.1-1"):
    return HostInventory(host, "debian", "13", "trixie", "13.1", "amd64", [
        Package("openssl", version, "amd64", "openssl", version, "ii "),
        Package("libssl3t64:amd64", version, "amd64", "openssl", version, "ii "),
    ])


def record(vid, events, modified="2026-01-01T00:00:00Z", **extra):
    return {"id": vid, "modified": modified, "upstream": [vid.removeprefix("DEBIAN-")],
            "affected": [{"package": {"name": "openssl", "ecosystem": ECO},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}],
                          "ecosystem_specific": {"urgency": "low"}}], **extra}


def batch_route(results):
    def route(headers, data):
        queries = json.loads(data)["queries"]
        return json_response({"results": [results.get(q["version"], {}) for q in queries]})
    return route


def test_normalize_id():
    assert normalize_id("DEBIAN-CVE-2025-11187") == "CVE-2025-11187"
    assert normalize_id("UBUNTU-CVE-2026-109518") == "CVE-2026-109518"
    assert normalize_id("CVE-2025-1") == "CVE-2025-1"


def ubuntu_inventory(version_id="24.04", codename="noble", host="u1", apt="2.8.3"):
    return HostInventory(host, "ubuntu", version_id, codename, "trixie/sid", "amd64", [
        Package("apt", apt, "amd64", "apt", apt, "ii "),
        Package("libapt-pkg6.0t64:amd64", apt, "amd64", "apt", apt, "ii "),
    ], distro="ubuntu", os_version=f"{version_id} LTS")


@pytest.mark.parametrize("os_id, distro, version_id, expected", [
    ("debian", "debian", "13", "Debian:13"),
    ("raspbian", "debian", "12", None),       # derivatives have no OSV ecosystem
    ("ubuntu", "ubuntu", "24.04", "Ubuntu:24.04:LTS"),
    ("ubuntu", "ubuntu", "26.04", "Ubuntu:26.04:LTS"),
    ("ubuntu", "ubuntu", "25.10", "Ubuntu:25.10"),
    ("ubuntu", "ubuntu", "25.04", "Ubuntu:25.04"),  # odd year: interim, not LTS
    ("ubuntu", "ubuntu", "", None),
    ("ubuntu", "ubuntu", "24.04.1", None),
])
def test_ecosystem(os_id, distro, version_id, expected):
    inv = HostInventory("h", os_id, version_id, "x", "", "amd64", [], distro=distro)
    assert ecosystem(inv) == expected


def test_evaluate_ranges_real_ubuntu_record():
    rec = fixture_json("osv-UBUNTU-CVE-2026-109518.json")
    lts = "Ubuntu:24.04:LTS"
    assert evaluate_ranges(rec, lts, "apt", "2.7.14build2") == (True, "2.8.4ubuntu0.1")
    assert evaluate_ranges(rec, lts, "apt", "2.8.4ubuntu0.1") == (False, None)
    assert evaluate_ranges(rec, "Ubuntu:26.04:LTS", "apt", "3.2.0") == (True, "3.2.1ubuntu0.1")
    # Ubuntu Pro has its own ecosystem; a noble host does not get its fixes
    assert evaluate_ranges(rec, "Ubuntu:Pro:20.04:LTS", "apt", "2.0.10") == (True, "2.0.12+esm1")


def test_match_ubuntu(cache):
    real = fixture_json("osv-UBUNTU-CVE-2026-109518.json")
    open_ = {**real, "id": "UBUNTU-CVE-2026-2", "upstream": ["CVE-2026-2"],
             "severity": [{"type": "Ubuntu", "score": "negligible"}],
             "affected": [{"package": {"name": "apt", "ecosystem": "Ubuntu:24.04:LTS"},
                           "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    # the USN of the CVE above: already covered
    usn = {**real, "id": "USN-8996-1", "summary": "APT vulnerability", "related": [],
           "upstream": ["UBUNTU-CVE-2026-109518"]}
    # a fix without a CVE: only the USN reports it
    no_cve = {**real, "id": "USN-9100-1", "summary": "APT vulnerability", "upstream": [],
              "related": [], "severity": [], "details": "It was discovered that APT ..."}
    regression = {**no_cve, "id": "USN-9100-2", "summary": "APT regression"}
    withdrawn = {**real, "id": "UBUNTU-CVE-2026-3", "withdrawn": "2026-11-01T00:00:00Z"}
    lsn = {**real, "id": "LSN-0120-1"}
    recs = (real, open_, usn, no_cve, regression, withdrawn, lsn)
    ids = [{"id": r["id"], "modified": r["modified"]} for r in recs]
    seen = []

    def route(headers, data):
        queries = json.loads(data)["queries"]
        seen.extend(q["package"]["ecosystem"] for q in queries)
        return json_response({"results": [{"vulns": ids} for _ in queries]})

    http = FakeHttp({("POST", f"{URL}/v1/querybatch"): route,
                     **{("GET", f"{URL}/v1/vulns/{r['id']}"): json_response(r) for r in recs}})
    src = OsvSource(SETTINGS, cache, http)
    assert src.covers(ubuntu_inventory())
    findings = {f.vuln_id: f for f in src.match([ubuntu_inventory()])["u1"]}
    assert seen == ["Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"]  # no Pro entries here
    assert set(findings) == {"CVE-2026-109518", "CVE-2026-2", "USN-9100-1"}
    fixed = findings["CVE-2026-109518"]
    assert (fixed.status, fixed.fixed_version) == (FindingStatus.FIXABLE, "2.8.4ubuntu0.1")
    assert fixed.urgency == "high"  # Ubuntu priority
    assert fixed.binaries == ["apt", "libapt-pkg6.0t64:amd64"]
    assert "UBUNTU-CVE-2026-109518" in fixed.aliases
    assert fixed.description.startswith("On Debian, Ubuntu")
    assert findings["CVE-2026-2"].status == FindingStatus.NO_FIX
    assert findings["CVE-2026-2"].urgency == "negligible"
    notice = findings["USN-9100-1"]
    assert (notice.status, notice.fixed_version) == (FindingStatus.FIXABLE, "2.8.4ubuntu0.1")
    assert notice.aliases == ["USN-9100-1"] and notice.urgency is None
    assert notice.description == "It was discovered that APT ..."


def test_evaluate_ranges_real_record():
    rec = fixture_json("osv-DEBIAN-CVE-2025-11187.json")
    assert evaluate_ranges(rec, ECO, "openssl", "3.5.1-1") == (True, "3.5.4-1~deb13u2")
    assert evaluate_ranges(rec, ECO, "openssl", "3.5.4-1~deb13u2") == (False, None)
    # other ecosystem or package: no entry, not affected
    assert evaluate_ranges(rec, ECO, "gnutls28", "1.0") == (False, None)
    assert evaluate_ranges(rec, "Debian:12:extra", "openssl", "3.5.1-1") == (False, None)


def test_evaluate_ranges_variants():
    rec = record("X", [{"introduced": "1.0-1"}, {"fixed": "1.2-1"},
                       {"introduced": "2.0-1"}, {"last_affected": "2.1-1"},
                       {"introduced": "3.0-1"}])
    assert evaluate_ranges(rec, ECO, "openssl", "0.9-1") == (False, None)
    assert evaluate_ranges(rec, ECO, "openssl", "1.1-1") == (True, "1.2-1")
    assert evaluate_ranges(rec, ECO, "openssl", "1.5-1") == (False, None)
    assert evaluate_ranges(rec, ECO, "openssl", "2.1-1") == (True, None)
    assert evaluate_ranges(rec, ECO, "openssl", "3.5-1") == (True, None)
    no_ranges = {"affected": [{"package": {"name": "openssl", "ecosystem": ECO},
                               "versions": ["3.5.1-1"]}]}
    assert evaluate_ranges(no_ranges, ECO, "openssl", "3.5.1-1") == (True, None)


def test_match_batches_hydrates_and_caches(cache):
    fixed = record("DEBIAN-CVE-2026-1", [{"introduced": "0"}, {"fixed": "3.5.4-1~deb13u2"}])
    open_ = record("DEBIAN-CVE-2026-2", [{"introduced": "0"}])
    dsa = record("DSA-6000-1", [{"introduced": "0"}, {"fixed": "3.5.4-1~deb13u2"}])
    ids = [{"id": r["id"], "modified": r["modified"]} for r in (fixed, open_, dsa)]
    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): batch_route({"3.5.1-1": {"vulns": ids}}),
        ("GET", f"{URL}/v1/vulns/DEBIAN-CVE-2026-1"): json_response(fixed),
        ("GET", f"{URL}/v1/vulns/DEBIAN-CVE-2026-2"): json_response(open_),
        ("GET", f"{URL}/v1/vulns/DSA-6000-1"): json_response(dsa),
    })
    src = OsvSource(SETTINGS, cache, http)
    src.refresh()
    result = src.match([inventory("a"), inventory("b")])
    # one query for both hosts (same package version)
    assert len(http.urls("POST")) == 1
    findings = {f.vuln_id: f for f in result["a"]}
    assert set(findings) == {"CVE-2026-1", "CVE-2026-2"}  # DSA skipped
    assert findings["CVE-2026-1"].status == FindingStatus.FIXABLE
    assert findings["CVE-2026-1"].fixed_version == "3.5.4-1~deb13u2"
    assert findings["CVE-2026-1"].binaries == ["libssl3t64:amd64", "openssl"]
    assert findings["CVE-2026-1"].urgency == "low"
    assert findings["CVE-2026-2"].status == FindingStatus.NO_FIX
    assert {f.vuln_id for f in result["b"]} == set(findings)

    # second run: records come from the cache
    gets = len(http.urls("GET"))
    src.match([inventory("a")])
    assert len(http.urls("GET")) == gets


def test_record_ids_are_quoted_in_urls(cache):
    # ids come from OSV's answer; they must not be able to change the request path
    ids = [{"id": "DSA-1/../../v1/x?y", "modified": "2026-01-01T00:00:00Z"}]
    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): batch_route({"3.5.1-1": {"vulns": ids}}),
        ("GET", f"{URL}/v1/vulns/DSA-1%2F..%2F..%2Fv1%2Fx%3Fy"): Response(404),
    })
    src = OsvSource(SETTINGS, cache, http)
    src.refresh()
    src.match([inventory()])
    assert http.urls("GET") == [f"{URL}/v1/vulns/DSA-1%2F..%2F..%2Fv1%2Fx%3Fy"]


def test_match_refetches_modified_records(cache):
    rec = record("DEBIAN-CVE-2026-1", [{"introduced": "0"}, {"fixed": "3.5.4-1"}])
    state = {"modified": "2026-01-01T00:00:00Z"}
    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): lambda h, d: json_response({"results": [{"vulns": [
            {"id": rec["id"], "modified": state["modified"]}]}]}),
        ("GET", f"{URL}/v1/vulns/DEBIAN-CVE-2026-1"): json_response(rec),
    })
    src = OsvSource(SETTINGS, cache, http)
    src.match([inventory()])
    state["modified"] = "2026-02-01T00:00:00Z"
    src.match([inventory()])
    assert len(http.urls("GET")) == 2


def test_pagination(cache):
    r1 = record("DEBIAN-CVE-2026-1", [{"introduced": "0"}])
    r2 = record("DEBIAN-CVE-2026-2", [{"introduced": "0"}])

    def route(headers, data):
        q = json.loads(data)["queries"]
        if len(q) == 1 and q[0].get("page_token") == "p2":
            return json_response({"results": [{"vulns": [{"id": r2["id"], "modified": "m"}]}]})
        return json_response({"results": [{"vulns": [{"id": r1["id"], "modified": "m"}],
                                           "next_page_token": "p2"}]})

    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): route,
        ("GET", f"{URL}/v1/vulns/{r1['id']}"): json_response(r1),
        ("GET", f"{URL}/v1/vulns/{r2['id']}"): json_response(r2),
    })
    result = OsvSource(SETTINGS, cache, http).match([inventory()])
    assert {f.vuln_id for f in result["web01"]} == {"CVE-2026-1", "CVE-2026-2"}


@pytest.mark.parametrize("answer", [
    {"results": []},  # fewer results than queries: the rest would look clean
    {"results": [{}, {}]},
    {"results": {"vulns": []}},
    {"results": ["x"]},
    {},
    [],
])
def test_incomplete_batch_answer_fails_the_source(cache, answer):
    http = FakeHttp({("POST", f"{URL}/v1/querybatch"): json_response(answer)})
    src = OsvSource(SETTINGS, cache, http)
    status = src.refresh()
    assert src.match([inventory()]) == {}
    assert not status.ok and "querybatch" in status.message


def test_incomplete_page_fails_the_source(cache):
    def route(headers, data):
        if json.loads(data)["queries"][0].get("page_token"):
            return json_response({"results": []})
        return json_response({"results": [{"vulns": [], "next_page_token": "p2"}]})

    http = FakeHttp({("POST", f"{URL}/v1/querybatch"): route})
    src = OsvSource(SETTINGS, cache, http)
    status = src.refresh()
    assert src.match([inventory()]) == {}
    assert not status.ok and "0 results for 1 queries" in status.message


def test_unavailable_record_warns(cache):
    """A record OSV lists but does not serve is not silently dropped: an older cached
    copy is used, else the host gets a warning."""
    known = record("DEBIAN-CVE-2026-1", [{"introduced": "0"}, {"fixed": "3.5.4-1"}])
    gone = record("DEBIAN-CVE-2026-2", [{"introduced": "0"}])
    dsa = {"id": "DSA-6000-1", "modified": "m"}
    state = {"modified": known["modified"]}
    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): lambda h, d: batch_route({"3.5.1-1": {"vulns": [
            {"id": known["id"], "modified": state["modified"]},
            {"id": gone["id"], "modified": gone["modified"]}, dsa]}})(h, d),
        ("GET", f"{URL}/v1/vulns/{known['id']}"): json_response(known),
        ("GET", f"{URL}/v1/vulns/{gone['id']}"): Response(404),
        ("GET", f"{URL}/v1/vulns/DSA-6000-1"): Response(404),
    })
    src = OsvSource(SETTINGS, cache, http)
    status = src.refresh()
    result = src.match([inventory("a"), inventory("b", version="3.5.4-1")])
    assert status.ok and [f.vuln_id for f in result["a"]] == ["CVE-2026-1"]
    warning = ("OSV did not return 1 vulnerability records it listed for this host "
               "(HTTP 404), their findings may be missing: DEBIAN-CVE-2026-2")
    assert src.host_warnings == {"a": [warning]}  # b has other versions, not queried
    # the known record is modified upstream and then not served: the cached copy is used
    state["modified"] = "2026-03-01T00:00:00Z"
    http.routes[("GET", f"{URL}/v1/vulns/{known['id']}")] = Response(404)
    result = src.match([inventory("a")])
    assert [f.vuln_id for f in result["a"]] == ["CVE-2026-1"]
    assert src.host_warnings == {"a": [warning]}


def test_query_failure_marks_status(cache):
    http = FakeHttp({("POST", f"{URL}/v1/querybatch"): Response(503)})
    src = OsvSource(SETTINGS, cache, http)
    status = src.refresh()
    assert src.match([inventory()]) == {}
    assert not status.ok and "503" in status.message

    http.routes[("POST", f"{URL}/v1/querybatch")] = HttpError(URL, "timed out")
    status = src.refresh()
    assert src.match([inventory()]) == {}
    assert not status.ok


def test_offline_skips(cache):
    src = OsvSource(SETTINGS, cache, FakeHttp(), offline=True)
    assert "offline" in src.refresh().message
    assert src.match([inventory()]) == {}


def test_non_debian_host_warns(cache):
    inv = inventory()
    inv.os_version_id = ""
    src = OsvSource(SETTINGS, cache, FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): batch_route({})}))
    assert src.match([inv]) == {"web01": []}
    assert src.host_warnings["web01"]


def pro_record(vid, package, eco, events, kind="apps", codename="noble"):
    return {"id": vid, "modified": "2026-01-01T00:00:00Z", "upstream": [vid.removeprefix("UBUNTU-")],
            "related": [], "details": f"{vid} details",
            "affected": [{"package": {"name": package, "ecosystem": eco,
                                      "purl": f"pkg:deb/ubuntu/{package}?arch=source&distro="
                                              f"esm-{kind}%2F{codename}"},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


def pro_setup(cache, suites):
    std, pro = "Ubuntu:24.04:LTS", "Ubuntu:Pro:24.04:LTS"
    recs = {
        # universe package only Pro tracks: fixed there
        "UBUNTU-CVE-2026-10": pro_record("UBUNTU-CVE-2026-10", "7zip", pro,
                                         [{"introduced": "0"}, {"fixed": "23.01+dfsg-11ubuntu0.1~esm1"}]),
        # ... and open there
        "UBUNTU-CVE-2026-11": pro_record("UBUNTU-CVE-2026-11", "7zip", pro, [{"introduced": "0"}]),
    }
    # open in the release, fixed in Pro (esm-infra): one record with both entries
    both = pro_record("UBUNTU-CVE-2026-12", "zlib", std, [{"introduced": "0"}])
    both["affected"].append(pro_record("x", "zlib", pro, [{"introduced": "0"}, {"fixed": "1:1.3-1ubuntu0.1~esm1"}],
                                       kind="infra")["affected"][0])
    recs[both["id"]] = both
    # fixed in the release already: Pro adds nothing
    done = pro_record("UBUNTU-CVE-2026-13", "zlib", std, [{"introduced": "0"}, {"fixed": "1:1.3-1ubuntu0.2"}])
    done["affected"].append(pro_record("x", "zlib", pro, [{"introduced": "0"}, {"fixed": "1:1.3-1ubuntu0.1~esm2"}])["affected"][0])
    recs[done["id"]] = done
    ids = [{"id": v, "modified": r["modified"]} for v, r in recs.items()]

    def route(headers, data):
        return json_response({"results": [{"vulns": ids} for _ in json.loads(data)["queries"]]})

    http = FakeHttp({("POST", f"{URL}/v1/querybatch"): route,
                     **{("GET", f"{URL}/v1/vulns/{v}"): json_response(r) for v, r in recs.items()}})
    inv = HostInventory("u1", "ubuntu", "24.04", "noble", "trixie/sid", "amd64", [
        Package("7zip", "23.01+dfsg-11", "amd64", "7zip", "23.01+dfsg-11", "ii "),
        Package("zlib1g:amd64", "1:1.3-1", "amd64", "zlib", "1:1.3-1", "ii "),
    ], facts={"apt_suites": " ".join(suites)}, distro="ubuntu")
    return OsvSource(SETTINGS, cache, http), inv


def test_match_ubuntu_pro(cache):
    src, inv = pro_setup(cache, ["noble", "noble-security", "noble-updates"])
    found = {f.vuln_id: f for f in src.match([inv])["u1"]}
    assert {k: (str(f.status), f.fixed_version, f.missing_source) for k, f in found.items()} == {
        "CVE-2026-10": ("fixable", "23.01+dfsg-11ubuntu0.1~esm1",
                        "noble-apps-security (Ubuntu Pro)"),
        "CVE-2026-11": ("no-fix", None, None),
        "CVE-2026-12": ("fixable", "1:1.3-1ubuntu0.1~esm1", "noble-infra-security (Ubuntu Pro)"),
        "CVE-2026-13": ("fixable", "1:1.3-1ubuntu0.2", None),
    }
    assert found["CVE-2026-12"].binaries == ["zlib1g:amd64"]


def test_match_ubuntu_pro_attached(cache):
    src, inv = pro_setup(cache, ["noble", "noble-security", "noble-apps-security",
                                 "noble-infra-updates"])
    found = {f.vuln_id: f for f in src.match([inv])["u1"]}
    assert not any(f.missing_source for f in found.values())
    assert found["CVE-2026-12"].fixed_version == "1:1.3-1ubuntu0.1~esm1"


def test_no_pro_for_interim_releases():
    inv = HostInventory("h", "ubuntu", "25.10", "questing", "", "amd64", [], distro="ubuntu")
    assert (ecosystem(inv), pro_ecosystem(inv)) == ("Ubuntu:25.10", None)
    inv.os_version_id = "24.04"
    assert pro_ecosystem(inv) == "Ubuntu:Pro:24.04:LTS"
