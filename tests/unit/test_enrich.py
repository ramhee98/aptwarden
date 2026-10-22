import time

import pytest

from aptwarden.enrich import assess, enrich
from aptwarden.enrich.cvss import CvssLookup, CvssResult
from aptwarden.enrich.kev import Kev
from aptwarden.http import Response
from aptwarden.models import Finding, FindingStatus, Severity
from tests.conftest import FakeHttp, fixture_json, json_response

OSV = "https://api.osv.dev"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://example.org/kev.json"


def finding(vid="CVE-2026-1", status=FindingStatus.FIXABLE, urgency=None, aliases=()):
    return Finding(vid, "openssl", "3.5.1-1", status, urgency=urgency, aliases=list(aliases))


@pytest.mark.parametrize(
    "urgency, cvss, severity, reason",
    [
        ("unimportant", CvssResult(9.8, "3.1", "v", "osv"), Severity.LOW, "unimportant"),
        ("not yet assigned", CvssResult(9.8, "3.1", "v", "osv"), Severity.CRITICAL, "cvss"),
        ("low", CvssResult(7.0, "3.1", "v", "nvd"), Severity.HIGH, "cvss"),
        ("medium**", None, Severity.MEDIUM, "urgency"),
        ("high", CvssResult(None, None, None, "osv"), Severity.HIGH, "urgency"),
        ("not yet assigned", None, Severity.UNKNOWN, "no score"),
        (None, CvssResult(0.0, "3.1", "v", "osv"), Severity.UNKNOWN, "no score"),
    ],
)
def test_assess_order(urgency, cvss, severity, reason):
    f = finding(urgency=urgency)
    assess(f, cvss)
    assert f.severity == severity
    assert reason in f.severity_reason


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def lookup(cache, http, **nvd):
    settings = {"osv_url": OSV, "workers": 2, "cache_ttl": "30d", "negative_ttl": "7d",
                "nvd": {"enabled": True, "url": NVD, "api_key_file": None, "budget": "1m",
                        **nvd}}
    lk = CvssLookup(settings, cache, http)
    clock = FakeClock()
    lk.clock, lk.sleep = clock, clock.sleep
    return lk, clock


def v3(score_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
    return {"severity": [{"type": "CVSS_V3", "score": score_vector}]}


V4 = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/"
                                                 "VA:H/SC:N/SI:N/SA:N"}]}


def test_lookup_flow_osv_then_nvd_then_cache(cache):
    http = FakeHttp({
        ("GET", f"{OSV}/v1/vulns/CVE-1"): json_response(v3()),
        ("GET", f"{OSV}/v1/vulns/CVE-2"): json_response(V4),
        ("GET", f"{OSV}/v1/vulns/CVE-3"): Response(404),
        ("GET", f"{OSV}/v1/vulns/CVE-4"): json_response({"severity": []}),
        ("GET", f"{NVD}?cveId=CVE-2"): json_response(fixture_json("nvd-CVE-2025-11187.json")),
        ("GET", f"{NVD}?cveId=CVE-3"): Response(404),
    })
    lk, _ = lookup(cache, http)
    res = lk.lookup(["CVE-1", "CVE-2", "CVE-3", "CVE-4", "TEMP-123"])
    assert res["CVE-1"].score == 9.8 and res["CVE-1"].origin == "osv"
    assert res["CVE-2"].score == 6.1 and res["CVE-2"].origin == "nvd"
    assert "CVE-3" not in res and "CVE-4" not in res  # no score anywhere
    assert f"{NVD}?cveId=CVE-4" not in http.urls()  # OSV mirrors NVD: no point asking
    assert lk.pending == 0

    calls = len(http.calls)
    assert lk.lookup(["CVE-1", "CVE-2", "CVE-3", "CVE-4"]).keys() == {"CVE-1", "CVE-2"}
    assert len(http.calls) == calls  # everything cached


def test_nvd_budget_and_rate_limit(cache):
    routes = {}
    for i in range(20):
        routes[("GET", f"{OSV}/v1/vulns/CVE-{i}")] = json_response(V4)
        routes[("GET", f"{NVD}?cveId=CVE-{i}")] = json_response(
            {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV40": [
                {"type": "Primary", "cvssData": {"baseScore": 8.0, "version": "4.0"}}]}}}]})
    http = FakeHttp(routes)
    lk, clock = lookup(cache, http, budget="30s")
    ids = [f"CVE-{i}" for i in range(20)]
    res = lk.lookup(ids)
    nvd_calls = [u for u in http.urls() if u.startswith(NVD)]
    # 6.5 s spacing without API key: requests at 0, 6.5, ..., 26 -> 5 within 30 s
    assert len(nvd_calls) == 5
    assert nvd_calls[0].endswith("CVE-0")  # priority order is kept
    assert len(res) == 5
    assert lk.pending == 15

    # next run: OSV is not asked again, NVD continues with the rest
    osv_calls = len([u for u in http.urls() if u.startswith(OSV)])
    clock.now += 100
    lk.lookup(ids)
    assert len([u for u in http.urls() if u.startswith(OSV)]) == osv_calls
    assert lk.pending == 10


def test_nvd_rate_limited_response_stops(cache):
    http = FakeHttp({
        ("GET", f"{OSV}/v1/vulns/CVE-1"): Response(404),
        ("GET", f"{OSV}/v1/vulns/CVE-2"): Response(404),
        ("GET", f"{NVD}?cveId=CVE-1"): Response(403),
    })
    lk, _ = lookup(cache, http)
    assert lk.lookup(["CVE-1", "CVE-2"]) == {}
    assert lk.pending == 2
    assert f"{NVD}?cveId=CVE-2" not in http.urls()


def test_nvd_api_key_header(cache, tmp_path):
    keyfile = tmp_path / "nvd.key"
    keyfile.write_text("secret-key\n")
    http = FakeHttp({
        ("GET", f"{OSV}/v1/vulns/CVE-1"): Response(404),
        ("GET", f"{NVD}?cveId=CVE-1"): json_response(fixture_json("nvd-CVE-2025-11187.json")),
    })
    lk, _ = lookup(cache, http, api_key_file=str(keyfile))
    lk.lookup(["CVE-1"])
    assert http.calls[-1][2]["apiKey"] == "secret-key"


def test_nvd_disabled_does_not_count_pending(cache):
    http = FakeHttp({("GET", f"{OSV}/v1/vulns/CVE-1"): json_response(V4)})
    lk, _ = lookup(cache, http, enabled=False)
    assert lk.lookup(["CVE-1"]) == {}
    assert lk.pending == 0


def test_negative_cache_expires(cache):
    http = FakeHttp({("GET", f"{OSV}/v1/vulns/CVE-1"): json_response({"severity": []})})
    lk, _ = lookup(cache, http)
    lk.lookup(["CVE-1"])
    cache.db.execute("UPDATE cvss SET fetched_at = ?", (time.time() - 8 * 86400,))
    http.routes[("GET", f"{OSV}/v1/vulns/CVE-1")] = json_response(v3())
    assert lk.lookup(["CVE-1"])["CVE-1"].score == 9.8


def test_offline_uses_stale_cache_only(cache):
    http = FakeHttp({("GET", f"{OSV}/v1/vulns/CVE-1"): json_response(v3())})
    lk, _ = lookup(cache, http)
    lk.lookup(["CVE-1"])
    cache.db.execute("UPDATE cvss SET fetched_at = 0")
    lk.offline = True
    calls = len(http.calls)
    res = lk.lookup(["CVE-1", "CVE-2"])
    assert res["CVE-1"].score == 9.8
    assert len(http.calls) == calls
    assert lk.pending == 1


def kev_doc(*cves):
    return {"count": len(cves), "vulnerabilities": [
        {"cveID": c, "dateAdded": "2026-01-01", "knownRansomwareCampaignUse": "Unknown"}
        for c in cves]}


def test_kev_refresh_and_contains(cache):
    http = FakeHttp({("GET", KEV_URL): json_response(kev_doc("CVE-2026-24061"),
                                                     headers={"etag": '"abc"'})})
    kev = Kev({"url": KEV_URL, "refresh_interval": "24h"}, cache, http)
    assert kev.refresh().ok
    assert kev.contains("CVE-2026-24061") and not kev.contains("CVE-1")
    cache.set_time("kev.checked_at", time.time() - 2 * 86400)
    http.routes[("GET", KEV_URL)] = Response(304)
    assert kev.refresh().ok
    assert http.calls[-1][2]["If-None-Match"] == '"abc"'
    assert kev.contains("CVE-2026-24061")


def test_kev_rejects_empty_catalog(cache):
    http = FakeHttp({("GET", KEV_URL): json_response(kev_doc())})
    status = Kev({"url": KEV_URL, "refresh_interval": "24h"}, cache, http).refresh()
    assert not status.ok and "empty" in status.message


def test_enrich_sets_severity_and_kev(cache):
    http = FakeHttp({
        ("GET", f"{OSV}/v1/vulns/CVE-2026-1"): json_response(v3()),
        ("GET", f"{OSV}/v1/vulns/CVE-2026-2"): json_response({"severity": []}),
        ("GET", KEV_URL): json_response(kev_doc("CVE-2026-2")),
    })
    lk, _ = lookup(cache, http)
    kev = Kev({"url": KEV_URL, "refresh_interval": "24h"}, cache, http)
    kev.refresh()
    findings = {"web01": [
        finding("CVE-2026-1"),
        finding("TEMP-9", aliases=["CVE-2026-2"], urgency="medium"),
        finding("CVE-2026-3", status=FindingStatus.NO_FIX, urgency="unimportant"),
    ]}
    enrich(findings, lk, kev)
    a, b, c = findings["web01"]
    assert (a.severity, a.cvss_score, a.kev) == (Severity.CRITICAL, 9.8, False)
    assert (b.severity, b.kev) == (Severity.MEDIUM, True)
    assert c.severity == Severity.LOW
    assert f"{OSV}/v1/vulns/CVE-2026-3" not in http.urls()  # unimportant: no lookup
