from aptwarden.matcher import mark_missing_sources, merge
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


REPOS = {"openssl": {"trixie": "1.0-1", "trixie-security": "2.0-1"},
         "tar": {"trixie": "2.0-1", "trixie-security": "2.0-1"}}


def test_mark_missing_sources():
    only_security = f("CVE-1", "debian_tracker")
    in_main = Finding("CVE-2", "tar", "1.0-1", FindingStatus.FIXABLE, fixed_version="2.0-1")
    pending = f("CVE-3", "debian_tracker", FindingStatus.FIX_PENDING, "3.0-1")
    no_repos = Finding("CVE-4", "vim", "1.0-1", FindingStatus.FIXABLE, fixed_version="2.0-1")
    findings = [only_security, in_main, pending, no_repos]
    mark_missing_sources(findings, {"trixie", "trixie-updates"}, lambda s: REPOS.get(s, {}))
    assert only_security.missing_source == "trixie-security"
    assert in_main.missing_source is None  # the point release brought it to trixie too
    assert pending.missing_source is None
    assert no_repos.missing_source is None  # unknown to the tracker: not judged

    mark_missing_sources(findings, {"trixie", "trixie-security"}, lambda s: REPOS.get(s, {}))
    assert only_security.missing_source is None  # cleared once the source is there


def test_mark_missing_sources_with_unknown_suites():
    finding = f("CVE-1", "debian_tracker")
    mark_missing_sources([finding], None, lambda s: REPOS[s])
    assert finding.missing_source is None


def test_merge_keeps_where_the_fix_is():
    # a definition wins, but only OSV knows the fix is in Ubuntu Pro
    pro = "noble-apps-security (Ubuntu Pro)"
    custom = Finding("CVE-1", "catdoc", "1:0.95-5", FindingStatus.FIXABLE,
                     fixed_version="1:0.95-5ubuntu0.1~esm1", origins=["custom"])
    osv = Finding("CVE-1", "catdoc", "1:0.95-5", FindingStatus.FIXABLE,
                  fixed_version="1:0.95-5ubuntu0.1~esm1", origins=["osv"], missing_source=pro)
    [f] = merge([(0, [custom]), (50, [osv])])
    assert f.origins == ["custom", "osv"] and f.missing_source == pro
    # another fixed version: the marker does not describe the winner's fix
    other = Finding("CVE-1", "catdoc", "1:0.95-5", FindingStatus.FIXABLE,
                    fixed_version="1:0.95-6", origins=["custom"])
    [f] = merge([(0, [other]), (50, [osv])])
    assert f.missing_source is None
