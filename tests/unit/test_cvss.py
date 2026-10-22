import pytest

from aptwarden.enrich.cvss import cvss3_base_score, parse_nvd, parse_osv_severity
from tests.conftest import fixture_json


@pytest.mark.parametrize(
    "vector, score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:H", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L", 1.6),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        # temporal metrics after the base metrics are ignored
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", 9.8),
    ],
)
def test_cvss3_base_score(vector, score):
    assert cvss3_base_score(vector) == score


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "garbage",
    ],
)
def test_cvss3_rejects_invalid(vector):
    with pytest.raises(ValueError):
        cvss3_base_score(vector)


def test_parse_osv_severity_from_real_record():
    result = parse_osv_severity(fixture_json("osv-CVE-2025-11187.json"))
    assert result.score == 6.1
    assert result.version == "3.1"
    assert result.origin == "osv"


def test_parse_osv_severity_v4_only_needs_nvd():
    record = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                                                         "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}
    assert parse_osv_severity(record) is None


def test_parse_nvd_real_response():
    result = parse_nvd(fixture_json("nvd-CVE-2025-11187.json"))
    assert result.score == 6.1
    assert result.version == "3.1"
    assert result.origin == "nvd"


def test_parse_nvd_prefers_primary_and_v31():
    data = {"vulnerabilities": [{"cve": {"metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0, "version": "2.0"}}],
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 9.8, "version": "3.1"}},
            {"type": "Primary", "cvssData": {"baseScore": 7.5, "version": "3.1"}},
        ],
    }}}]}
    assert parse_nvd(data).score == 7.5


def test_parse_nvd_without_metrics():
    assert parse_nvd({"vulnerabilities": [{"cve": {"metrics": {}}}]}).score is None
    assert parse_nvd({"vulnerabilities": []}).score is None
