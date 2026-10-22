"""Custom vulnerability definitions (YAML, one definition per file).

Schema: ``schemas/definition-v1.schema.json``. On top of the schema, the loader
checks that versions parse with Debian semantics, ranges are ordered, ids are
unique and match the file name, and that ``auto-patch`` has a fixed version
to patch to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from functools import cache
from importlib import resources
from pathlib import Path

import jsonschema
import yaml

from aptwarden import debversion

KNOWN_RELEASES = frozenset({"buster", "bullseye", "bookworm", "trixie", "forky", "duke", "sid"})


@dataclass(frozen=True)
class Range:
    introduced: str
    fixed: str | None = None
    last_affected: str | None = None


@dataclass
class Definition:
    id: str
    summary: str
    severity: str
    package: str
    action: str
    affected: dict[str, list[Range]]  # release (or "any") -> ranges
    aliases: list[str] = field(default_factory=list)
    details: str = ""
    references: list[str] = field(default_factory=list)
    published: str | None = None
    expires: str | None = None
    path: str = ""

    def ranges_for(self, release: str) -> list[Range] | None:
        """Ranges for a release; None means the definition has no opinion."""
        if release in self.affected:
            return self.affected[release]
        return self.affected.get("any")

    def expired(self, today: date | None = None) -> bool:
        return bool(self.expires) and date.fromisoformat(self.expires) < (today or date.today())

    def evaluate(self, release: str, version: str) -> tuple[bool, str | None] | None:
        """(affected, fixed version) for an installed source version, or None
        if the definition does not cover the release."""
        ranges = self.ranges_for(release)
        if ranges is None:
            return None
        for r in ranges:
            if debversion.in_range(version, r.introduced, r.fixed, r.last_affected):
                return True, r.fixed
        return False, None

    def vuln_ids(self) -> list[str]:
        """Ids findings are reported under: the aliases, so the definition
        merges with (and overrides) other sources, else its own id."""
        return list(self.aliases) or [self.id]

    def to_dict(self) -> dict:
        return {
            "schema_version": 1, "id": self.id, "summary": self.summary,
            "severity": self.severity, "package": self.package, "action": self.action,
            "aliases": self.aliases, "details": self.details, "references": self.references,
            "published": self.published, "expires": self.expires, "path": self.path,
            "affected": [
                {"release": rel, "ranges": [
                    {k: v for k, v in vars(r).items() if v is not None} for r in ranges]}
                for rel, ranges in self.affected.items()
            ],
        }

    @classmethod
    def from_dict(cls, d: dict, path: str = "") -> Definition:
        affected: dict[str, list[Range]] = {}
        for entry in d["affected"]:
            affected.setdefault(entry["release"], []).extend(Range(**r) for r in entry["ranges"])
        return cls(
            id=d["id"], summary=d["summary"], severity=d["severity"], package=d["package"],
            action=d["action"], affected=affected, aliases=list(d.get("aliases", [])),
            details=d.get("details", ""), references=list(d.get("references", [])),
            published=_date_str(d.get("published")), expires=_date_str(d.get("expires")),
            path=d.get("path", path),
        )


def _date_str(value) -> str | None:
    # YAML turns unquoted 2026-10-22 into a date object.
    return value.isoformat() if isinstance(value, date) else value


@dataclass
class LoadResult:
    definitions: list[Definition] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@cache
def _validator() -> jsonschema.Draft202012Validator:
    text = resources.files("aptwarden").joinpath("schemas/definition-v1.schema.json").read_text()
    return jsonschema.Draft202012Validator(
        json.loads(text), format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)


def _semantic_errors(d: dict) -> list[str]:
    errors = []
    has_fix = False
    for entry in d["affected"]:
        for r in entry["ranges"]:
            versions = {k: r[k] for k in ("introduced", "fixed", "last_affected") if k in r}
            for key, v in versions.items():
                if key == "introduced" and v == "0":
                    continue
                try:
                    debversion.parse(v)
                except ValueError as e:
                    errors.append(f"{entry['release']}: {key} {v!r}: {e}")
            end = r.get("fixed") or r.get("last_affected")
            has_fix = has_fix or "fixed" in r
            if end and r["introduced"] != "0":
                try:
                    if debversion.compare(r["introduced"], end) >= 0:
                        errors.append(f"{entry['release']}: introduced {r['introduced']} is not "
                                      f"below {end}")
                except ValueError:
                    pass  # already reported
    if d["action"] == "auto-patch" and not has_fix:
        errors.append("action auto-patch needs at least one range with a fixed version")
    releases = [e["release"] for e in d["affected"]]
    if len(releases) != len(set(releases)):
        errors.append("a release is listed more than once in affected")
    return errors


def parse(text: str, name: str) -> tuple[Definition | None, list[str], list[str]]:
    """Parse and validate one definition file. Returns (definition, errors, warnings)."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return None, [f"{name}: invalid YAML: {e}"], []
    if isinstance(data, dict):
        for key in ("published", "expires"):
            data[key] = _date_str(data.get(key)) if key in data else None
        data = {k: v for k, v in data.items() if v is not None}
    errors = [
        f"{name}: {'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in sorted(_validator().iter_errors(data), key=lambda e: list(e.absolute_path))
    ]
    if errors:
        return None, errors, []
    errors = [f"{name}: {e}" for e in _semantic_errors(data)]
    stem = Path(name).name.removesuffix(".yaml").removesuffix(".yml")
    if stem != data["id"]:
        errors.append(f"{name}: file name must be {data['id']}.yaml")
    warnings = [f"{name}: unknown release {e['release']!r}" for e in data["affected"]
                if e["release"] != "any" and e["release"] not in KNOWN_RELEASES]
    if errors:
        return None, errors, warnings
    return Definition.from_dict(data, name), [], warnings


def load_files(files: dict[str, str]) -> LoadResult:
    """Validate a set of definition files ``{path: text}``. All or nothing:
    callers must not activate a result with errors."""
    result = LoadResult()
    seen: dict[str, str] = {}
    for name in sorted(files):
        definition, errors, warnings = parse(files[name], name)
        result.errors += errors
        result.warnings += warnings
        if definition is None:
            continue
        if definition.id in seen:
            result.errors.append(f"{name}: duplicate id {definition.id} (also in "
                                 f"{seen[definition.id]})")
            continue
        seen[definition.id] = name
        result.definitions.append(definition)
    return result


def load_dir(path: Path) -> LoadResult:
    files = {
        str(p.relative_to(path)): p.read_text()
        for p in sorted(path.rglob("*")) if p.suffix in (".yaml", ".yml") and p.is_file()
    }
    return load_files(files)
