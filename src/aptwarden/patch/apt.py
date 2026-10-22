"""Parsing apt output and checking a simulation against the plan."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_INST = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) ")
_REMV = re.compile(r"^Remv (\S+)(?: \[(\S+)\])?")


def base_name(package: str) -> str:
    """libssl3t64:amd64 -> libssl3t64 (apt -s prints names without arch)."""
    return package.split(":", 1)[0]


def parse_policy(text: str) -> dict[str, str | None]:
    """``apt-cache policy pkg...`` -> {package: candidate or None}."""
    result: dict[str, str | None] = {}
    current = None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.endswith(":"):
            current = line[:-1]
            result[current] = None
        elif current and line.strip().startswith("Candidate:"):
            value = line.split(":", 1)[1].strip()
            result[current] = None if value == "(none)" else value
    return result


@dataclass
class Simulation:
    upgrades: dict[str, tuple[str, str]] = field(default_factory=dict)  # name -> (old, new)
    new: dict[str, str] = field(default_factory=dict)  # newly installed name -> version
    removals: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_simulation(text: str) -> Simulation:
    sim = Simulation()
    for line in text.splitlines():
        if m := _INST.match(line):
            name, old, new = base_name(m.group(1)), m.group(2), m.group(3)
            if old:
                sim.upgrades[name] = (old, new)
            else:
                sim.new[name] = new
        elif m := _REMV.match(line):
            sim.removals.append(base_name(m.group(1)))
        elif line.startswith("E: "):
            sim.errors.append(line[3:].strip())
    return sim


def check_simulation(sim: Simulation, planned: dict[str, str], *,
                     allow_extra_upgrades: bool = False,
                     allow_new_packages: tuple[str, ...] = ()) -> list[str]:
    """Problems that must stop the patch. ``planned`` maps base package names
    to the exact target version."""
    problems = [f"apt error: {e}" for e in sim.errors]
    problems += [f"would remove {name}" for name in sim.removals]
    for name, version in planned.items():
        if name not in sim.upgrades:
            problems.append(f"{name} would not be upgraded")
        elif sim.upgrades[name][1] != version:
            problems.append(f"{name} would become {sim.upgrades[name][1]}, planned {version}")
    for name, version in sim.new.items():
        if name not in allow_new_packages:
            problems.append(f"would newly install {name} {version}")
    if not allow_extra_upgrades:
        for name, (old, new) in sim.upgrades.items():
            if name not in planned:
                problems.append(f"would also upgrade {name} {old} -> {new} (not in the plan)")
    return problems


def parse_needrestart(text: str) -> tuple[list[str], bool]:
    """``needrestart -b`` -> (services needing or getting a restart, reboot needed)."""
    services, reboot = [], False
    for line in text.splitlines():
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "NEEDRESTART-SVC" and value:
            services.append(value)
        elif key == "NEEDRESTART-KSTA" and value in ("2", "3"):
            reboot = True  # 2: ABI compatible upgrade pending, 3: version upgrade pending
    return services, reboot
