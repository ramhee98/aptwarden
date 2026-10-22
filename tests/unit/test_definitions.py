import textwrap
from datetime import date

import pytest

from aptwarden.definitions import load_dir, load_files, parse

VALID = """
schema_version: 1
id: AW-2026-0001
aliases: [CVE-2024-3094]
summary: "xz-utils: backdoor in 5.6.0 and 5.6.1"
severity: critical
package: xz-utils
affected:
  - release: any
    ranges:
      - introduced: "5.6.0"
        fixed: "5.6.1+really5.4.5-1"
action: block
published: 2026-10-22
"""


def defn(**changes) -> str:
    import yaml
    d = yaml.safe_load(VALID)
    d.update(changes)
    return yaml.safe_dump(d)


def test_valid_definition():
    d, errors, warnings = parse(VALID, "2026/AW-2026-0001.yaml")
    assert errors == [] and warnings == []
    assert d.published == "2026-10-22"
    assert d.vuln_ids() == ["CVE-2024-3094"]


@pytest.mark.parametrize("version, affected", [
    ("5.6.0-0.1", True), ("5.6.0-0.2", True), ("5.6.1-1", True),
    ("5.6.1+really5.4.5-1", False), ("5.4.1-1+deb12u1", False), ("5.8.1-1+deb13u2", False),
])
def test_evaluate_block_range(version, affected):
    d, _, _ = parse(VALID, "AW-2026-0001.yaml")
    assert d.evaluate("trixie", version)[0] is affected


def test_release_specific_ranges_and_any_fallback():
    text = defn(affected=[
        {"release": "trixie", "ranges": [{"introduced": "0", "fixed": "2.0-1"}]},
        {"release": "any", "ranges": [{"introduced": "0", "last_affected": "1.5-1"}]},
    ], action="auto-patch")
    d, errors, _ = parse(text, "AW-2026-0001.yaml")
    assert errors == []
    assert d.evaluate("trixie", "1.9-1") == (True, "2.0-1")
    assert d.evaluate("bookworm", "1.5-1") == (True, None)
    assert d.evaluate("bookworm", "1.6-1") == (False, None)
    only_trixie, _, _ = parse(defn(affected=[{"release": "trixie", "ranges": [
        {"introduced": "0", "fixed": "2.0-1"}]}]), "AW-2026-0001.yaml")
    assert only_trixie.evaluate("bookworm", "1.0") is None  # no opinion


@pytest.mark.parametrize("text, message", [
    (defn(id="CVE-2024-3094"), "does not match"),
    (defn(severity="urgent"), "severity"),
    (defn(package="Xz Utils"), "package"),
    (defn(action="auto-patch", affected=[{"release": "any", "ranges": [
        {"introduced": "5.6.0"}]}]), "auto-patch needs"),
    (defn(affected=[{"release": "any", "ranges": [
        {"introduced": "2.0", "fixed": "1.0"}]}]), "not below"),
    (defn(affected=[{"release": "any", "ranges": [
        {"introduced": "0", "fixed": "1.0", "last_affected": "0.9"}]}]), "should not be valid"),
    (defn(affected=[{"release": "any", "ranges": [{"introduced": "1:"}]}]), "after colon"),
    (defn(published="yesterday"), "is not a 'date'"),
    (defn(references=["http://insecure.example"]), "does not match"),
    (defn(run="rm -rf /"), "Additional properties"),
    ("{not: [valid", "invalid YAML"),
])
def test_invalid_definitions(text, message):
    d, errors, _ = parse(text, "AW-2026-0001.yaml")
    assert d is None
    assert any(message in e for e in errors), errors


def test_file_name_must_match_id():
    _, errors, _ = parse(VALID, "2026/AW-2026-0009.yaml")
    assert "file name must be AW-2026-0001.yaml" in errors[0]


def test_unknown_release_is_a_warning():
    text = defn(affected=[{"release": "bulseye", "ranges": [{"introduced": "0",
                                                              "fixed": "1.0"}]}])
    d, errors, warnings = parse(text, "AW-2026-0001.yaml")
    assert d is not None and errors == []
    assert "bulseye" in warnings[0]


def test_duplicates_and_all_or_nothing():
    result = load_files({"a/AW-2026-0001.yaml": VALID, "b/AW-2026-0001.yaml": VALID})
    assert not result.ok and "duplicate id" in result.errors[0]


def test_expiry():
    d, _, _ = parse(defn(expires="2026-01-01"), "AW-2026-0001.yaml")
    assert d.expired(date(2026, 1, 2)) and not d.expired(date(2026, 1, 1))


def test_roundtrip_dict():
    d, _, _ = parse(VALID, "AW-2026-0001.yaml")
    from aptwarden.definitions import Definition
    assert Definition.from_dict(d.to_dict()) == d


def test_load_dir(tmp_path):
    (tmp_path / "2026").mkdir()
    (tmp_path / "2026" / "AW-2026-0001.yaml").write_text(textwrap.dedent(VALID))
    (tmp_path / "notes.txt").write_text("ignored")
    result = load_dir(tmp_path)
    assert result.ok and [d.id for d in result.definitions] == ["AW-2026-0001"]
