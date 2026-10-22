import json

from aptwarden.http import HttpError, Response
from aptwarden.models import FindingStatus, HostInventory, Package
from aptwarden.sources.osv import OsvSource, evaluate_ranges, normalize_id
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
    assert normalize_id("CVE-2025-1") == "CVE-2025-1"


def test_evaluate_ranges_real_record():
    rec = fixture_json("osv-DEBIAN-CVE-2025-11187.json")
    assert evaluate_ranges(rec, ECO, "openssl", "3.5.1-1") == (True, "3.5.4-1~deb13u2")
    assert evaluate_ranges(rec, ECO, "openssl", "3.5.4-1~deb13u2") == (False, None)
    # other ecosystem or package: not covered by a range
    assert evaluate_ranges(rec, ECO, "gnutls28", "1.0")[1] is None


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


def test_match_refetches_modified_records(cache):
    rec = record("DEBIAN-CVE-2026-1", [{"introduced": "0"}, {"fixed": "3.5.4-1"}])
    state = {"modified": "2026-01-01T00:00:00Z"}
    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): lambda h, d: json_response({"results": [{"vulns": [
            {"id": rec["id"], "modified": state["modified"]}]}, {}]}),
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
                                           "next_page_token": "p2"}, {}]})

    http = FakeHttp({
        ("POST", f"{URL}/v1/querybatch"): route,
        ("GET", f"{URL}/v1/vulns/{r1['id']}"): json_response(r1),
        ("GET", f"{URL}/v1/vulns/{r2['id']}"): json_response(r2),
    })
    result = OsvSource(SETTINGS, cache, http).match([inventory()])
    assert {f.vuln_id for f in result["web01"]} == {"CVE-2026-1", "CVE-2026-2"}


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
