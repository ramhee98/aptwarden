"""``policy.enforce_block: pin``: keep versions that ``block`` definitions mark as
known-bad from being installed on the host at all, also by a manual ``apt upgrade``
or unattended-upgrades.

Definitions name source versions in ranges, apt preferences pin binary versions. So
the scan asks the host's apt (``apt-cache show``, no root) for every available
version of the installed binaries of a blocked source package and pins exactly those
built from a blocked source version to priority -1. The installed version is never
pinned: that is the alert's job, and apt would only try to move away from it.

The pins are one file, ``/etc/apt/preferences.d/aptwarden-block``, written by the
helper (``pin pkg=version ...``; no arguments removes the file). The scan reads the
file itself and calls the helper only when the pins change, so a host without blocked
versions never needs sudo for this.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from aptwarden.config import HostConfig
from aptwarden.definitions import Definition
from aptwarden.log import safe
from aptwarden.models import HostInventory
from aptwarden.patch.apt import base_name
from aptwarden.patch.planner import parse_show
from aptwarden.patch.runner import explain_helper_failure
from aptwarden.transport import Transport, TransportError

log = logging.getLogger(__name__)

PIN_FILE = "/etc/apt/preferences.d/aptwarden-block"
MAX_PINS = 500  # the helper's limit for arguments

# What the helper accepts (see check_packages there).
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*")
_VERSION = re.compile(r"[0-9][A-Za-z0-9+.:~-]*")


@dataclass
class PinResult:
    pins: dict[tuple[str, str], str] = field(default_factory=dict)  # (pkg, ver) -> def id
    changed: bool = False
    error: str | None = None

    def notes(self) -> list[str]:
        if self.error:
            return [f"enforce_block: pin failed, blocked versions are NOT pinned away: "
                    f"{self.error}"]
        if not self.pins:
            return []
        by_def: dict[str, list[str]] = {}
        for (pkg, ver), def_id in sorted(self.pins.items()):
            by_def.setdefault(def_id, []).append(f"{pkg} {ver}")
        return ["blocked versions pinned away: " + "; ".join(
            f"{', '.join(items)} ({def_id})" for def_id, items in sorted(by_def.items()))]


def parse_pin_file(text: str) -> set[tuple[str, str]]:
    """(package, version) pairs of a pin file written by the helper."""
    pins = set()
    package = None
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            package = None
            continue
        value = value.strip()
        if key == "Package":
            package = value
        elif key == "Pin" and package and value.startswith("version "):
            pins.add((package, value.removeprefix("version ").strip()))
    return pins


def blocking(definitions: list[Definition]) -> dict[str, list[Definition]]:
    """Active block definitions by source package."""
    result: dict[str, list[Definition]] = {}
    for d in definitions:
        if d.action == "block" and not d.expired():
            result.setdefault(d.package, []).append(d)
    return result


def wanted(inv: HostInventory, blocks: dict[str, list[Definition]],
           show: str) -> dict[tuple[str, str], str]:
    """Pins for the versions in ``apt-cache show`` output that are built from a blocked
    source version, except the installed ones."""
    installed = {(base_name(p.name), p.version) for p in inv.packages}
    pins = {}
    for (pkg, ver), (source, source_version) in parse_show(show).items():
        if (pkg, ver) in installed or not (_PACKAGE.fullmatch(pkg) and _VERSION.fullmatch(ver)):
            continue
        for d in blocks.get(source, []):
            try:
                verdict = d.evaluate(inv.codename, source_version, distro=inv.distro)
            except ValueError:
                continue
            if verdict and verdict[0]:
                pins[(pkg, ver)] = d.id
                break
    return pins


def enforce(t: Transport, host: HostConfig, inv: HostInventory,
            definitions: list[Definition]) -> PinResult:
    """Bring the host's pin file in line with the definitions. With
    ``enforce_block: alert`` the wanted pins are none, which removes a file left from
    an earlier ``pin``."""
    result = PinResult()
    try:
        current_file = t.run(["cat", PIN_FILE], timeout=30)
        current = parse_pin_file(current_file.stdout) if current_file.ok else set()
        if host.policy.get("enforce_block", "alert") == "pin":
            blocks = blocking(definitions)
            binaries = sorted({base_name(p.name) for p in inv.packages if p.source in blocks})
            if binaries:
                show = t.run(["apt-cache", "show", "--", *binaries], timeout=120)
                result.pins = wanted(inv, blocks, show.stdout)
        if len(result.pins) > MAX_PINS:
            result.error = f"{len(result.pins)} versions to pin, at most {MAX_PINS} supported"
            return result
        if set(result.pins) == current and (current_file.ok or not result.pins):
            return result
        r = t.run(["sudo", "-n", host.ssh.helper, "version"], timeout=30)
        if problem := explain_helper_failure(r, host.ssh.helper, "pin"):
            result.error = problem
            return result
        r = t.run(["sudo", "-n", host.ssh.helper, "pin",
                   *(f"{p}={v}" for p, v in sorted(result.pins))], timeout=60)
        if not r.ok:
            result.error = safe(f"helper pin exited {r.returncode}: "
                                + ((r.stderr or r.stdout).strip()[-300:] or "no output"))
            return result
        result.changed = True
        log.info("pins updated", extra={"host": host.name, "pins": len(result.pins)})
    except TransportError as e:
        result.error = str(e)
    return result
