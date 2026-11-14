"""Checks on the shipped systemd units."""

from __future__ import annotations

from pathlib import Path

UNITS = Path(__file__).resolve().parents[2] / "contrib" / "systemd"


def _setting(unit: Path, key: str) -> list[str]:
    return [line.split("=", 1)[1].strip() for line in unit.read_text().splitlines()
            if line.startswith(f"{key}=")]


def test_runtime_directories_are_not_shared():
    # systemd removes a unit's RuntimeDirectory when that unit stops, even if another
    # running unit names the same directory: a patch run that ended during the report
    # deleted the report's SSH control socket directory.
    owners: dict[str, str] = {}
    for unit in sorted(UNITS.glob("*.service")):
        for d in _setting(unit, "RuntimeDirectory"):
            for name in d.split():
                assert name not in owners, f"{unit.name} and {owners[name]} share {name}"
                owners[name] = unit.name
    assert {"aptwarden-report.service", "aptwarden-patch.service"} <= set(owners.values())
