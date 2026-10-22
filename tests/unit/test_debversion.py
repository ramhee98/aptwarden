import pytest

from aptwarden import debversion
from aptwarden.debversion import Version, compare, in_range, max_version, parse
from tests.conftest import FIXTURES


def load_cases():
    cases = []
    for line in (FIXTURES / "debversion_cases.tsv").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        a, b, result = line.split("\t")
        cases.append((a, b, int(result)))
    return cases


CASES = load_cases()


def test_case_table_is_substantial():
    assert len(CASES) > 4000


def test_matches_dpkg_for_all_generated_cases():
    mismatches = [(a, b, r, compare(a, b)) for a, b, r in CASES if compare(a, b) != r]
    assert mismatches == []


def test_comparison_is_antisymmetric():
    for a, b, r in CASES[:500]:
        assert compare(b, a) == -r


@pytest.mark.parametrize(
    "a, op, b",
    [
        ("1.0", "==", "1.0-0"),
        ("1.0", "==", "0:1.0"),
        ("1.0", "==", "1.00"),
        ("1.0~rc1", "<", "1.0"),
        ("1.0~~", "<", "1.0~"),
        ("1.0~", "<", "1.0"),
        ("1.0", "<", "1.0+b1"),
        ("1.0", "<", "1.0a"),
        ("1.0a", "<", "1.0+"),
        ("1:0.9", ">", "2.0"),
        ("1.0-1~bpo12+1", "<", "1.0-1"),
        ("1.0-1+deb12u2", "<", "1.0-1+deb12u10"),
        ("3.0.15-1~deb12u1", "<", "3.0.15-1"),
        ("5.6.1+really5.4.5-1", ">", "5.6.1"),
        ("2.41-5", "<", "1:2.41-5"),
        ("10", ">", "9"),
        ("1.0-beta-1", "<", "1.0-beta-2"),
    ],
)
def test_known_orderings(a, op, b):
    result = compare(a, b)
    assert {"<": result < 0, "==": result == 0, ">": result > 0}[op]


@pytest.mark.parametrize(
    "version, expected",
    [
        ("1.0", Version(0, "1.0", "")),
        ("1:2.41-5", Version(1, "2.41", "5")),
        ("1.0-beta-1", Version(0, "1.0-beta", "1")),
        ("2:4.21.4+dfsg-1", Version(2, "4.21.4+dfsg", "1")),
        ("  1.0-1 ", Version(0, "1.0", "1")),
    ],
)
def test_parse(version, expected):
    assert parse(version) == expected


def test_version_str_roundtrip():
    for v in ("1:2.41-5", "1.0", "1.0-beta-1"):
        assert str(parse(v)) == v


@pytest.mark.parametrize(
    "bad", ["", "   ", "1.0 1", ":1.0", "a:1.0", "1:", "1.0-", "-1"],
)
def test_parse_rejects_hard_errors(bad):
    with pytest.raises(ValueError):
        parse(bad)


def test_sort_key_and_max_version():
    versions = ["1.0-1", "1.0~rc1-1", "1:0.1-1", "1.0-1+deb12u1", "0.9-3"]
    assert sorted(versions, key=debversion.sort_key) == [
        "0.9-3", "1.0~rc1-1", "1.0-1", "1.0-1+deb12u1", "1:0.1-1",
    ]
    assert max_version(versions) == "1:0.1-1"
    assert max_version([]) is None


@pytest.mark.parametrize(
    "version, introduced, fixed, last_affected, expected",
    [
        ("1.0-1", "0", "1.0-2", None, True),
        ("1.0-2", "0", "1.0-2", None, False),
        ("0.9-1", "1.0-1", "1.0-2", None, False),
        ("1.5-1", "1.0-1", None, "1.5-1", True),
        ("1.5-2", "1.0-1", None, "1.5-1", False),
        ("2.0-1", "1.0-1", None, None, True),
        ("2.0-1", None, None, None, True),
    ],
)
def test_in_range(version, introduced, fixed, last_affected, expected):
    assert in_range(version, introduced, fixed, last_affected) is expected
