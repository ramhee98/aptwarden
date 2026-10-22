from aptwarden.matcher import merge
from aptwarden.models import Finding, FindingStatus


def f(vid, origin, status=FindingStatus.FIXABLE, fixed="2.0-1", **kw):
    return Finding(vid, "openssl", "1.0-1", status, fixed_version=fixed, origins=[origin], **kw)


def test_higher_priority_source_wins():
    tracker = f("CVE-1", "debian_tracker", FindingStatus.FIX_PENDING, "2.0-1", urgency=None)
    osv = f("CVE-1", "osv", FindingStatus.FIXABLE, "2.0-1", urgency="low",
            aliases=["DEBIAN-CVE-1"], description="from osv", binaries=["libssl"])
    [m] = merge([(50, [osv]), (10, [tracker])])
    assert m.status == FindingStatus.FIX_PENDING  # tracker knows about repositories
    assert m.origins == ["debian_tracker", "osv"]
    assert m.aliases == ["DEBIAN-CVE-1"]
    assert m.urgency == "low"  # filled from the lower priority source
    assert m.description == "from osv"
    assert m.binaries == ["libssl"]


def test_distinct_vulns_are_kept_and_inputs_untouched():
    a, b = f("CVE-1", "debian_tracker"), f("CVE-2", "osv")
    merged = merge([(10, [a]), (50, [b])])
    assert [m.vuln_id for m in merged] == ["CVE-1", "CVE-2"]
    merged[0].origins.append("x")
    assert a.origins == ["debian_tracker"]
