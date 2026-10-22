"""Package inventory of a Debian host. Needs no privileges."""

from __future__ import annotations

import logging
import shlex
from datetime import UTC, datetime

from aptwarden.models import HostInventory, Package
from aptwarden.transport import Transport, TransportError

log = logging.getLogger(__name__)

DPKG_FORMAT = (
    "${binary:Package}\\t${Version}\\t${source:Package}\\t${source:Version}"
    "\\t${db:Status-Abbrev}\\t${Architecture}\\n"
)

# Second character of db:Status-Abbrev. Everything except "not installed" (n)
# and "config files only" (c) means code from the package is on disk.
_INSTALLED_STATES = frozenset("iUFWtH")

# Read-only facts, printed as key=value lines. A constant script, no input is
# interpolated.
FACTS_SCRIPT = r"""
echo "kernel=$(uname -r)"
echo "virt=$(systemd-detect-virt 2>/dev/null || echo unknown)"
if [ -e /run/reboot-required ]; then echo "reboot_required=yes"; else echo "reboot_required=no"; fi
uu=$(apt-config shell V APT::Periodic::Unattended-Upgrade 2>/dev/null)
eval "$uu"
echo "unattended_upgrade_periodic=${V:-0}"
"""


class InventoryError(Exception):
    pass


def parse_dpkg_query(text: str) -> list[Package]:
    packages = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            raise InventoryError(f"unexpected dpkg-query output on line {lineno}: {line!r}")
        name, version, source, source_version, status, arch = parts
        if len(status) < 2 or status[1] not in _INSTALLED_STATES:
            continue
        packages.append(
            Package(
                name=name,
                version=version,
                arch=arch,
                source=source or name.split(":", 1)[0],
                source_version=source_version or version,
                status=status,
            )
        )
    return packages


def parse_os_release(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        try:
            parts = shlex.split(value)
        except ValueError:
            parts = [value]
        result[key] = parts[0] if parts else ""
    return result


def parse_facts(text: str) -> dict[str, str]:
    facts = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            facts[key.strip()] = value.strip()
    return facts


def collect(transport: Transport) -> HostInventory:
    try:
        osr = transport.run(["cat", "/etc/os-release"])
        if not osr.ok:
            osr = transport.run(["cat", "/usr/lib/os-release"]).check()
        os_release = parse_os_release(osr.stdout)
        if os_release.get("ID") != "debian" and "debian" not in os_release.get("ID_LIKE", ""):
            raise InventoryError(f"not a Debian based system (ID={os_release.get('ID')!r})")

        dpkg = transport.run(["dpkg-query", "-W", f"-f={DPKG_FORMAT}"]).check()
        packages = parse_dpkg_query(dpkg.stdout)
        arch = transport.run(["dpkg", "--print-architecture"]).check().stdout.strip()
        debian_version = transport.run(["cat", "/etc/debian_version"]).stdout.strip()
        facts_result = transport.run(["sh", "-c", FACTS_SCRIPT])
        facts = parse_facts(facts_result.stdout) if facts_result.ok else {}
    except TransportError as e:
        raise InventoryError(str(e)) from e

    names = {p.name.split(":", 1)[0] for p in packages}
    facts["needrestart_installed"] = "yes" if "needrestart" in names else "no"
    facts["unattended_upgrades_installed"] = "yes" if "unattended-upgrades" in names else "no"

    codename = os_release.get("VERSION_CODENAME", "")
    if not codename:
        raise InventoryError("VERSION_CODENAME missing in os-release")
    inv = HostInventory(
        host=transport.host,
        os_id=os_release.get("ID", ""),
        os_version_id=os_release.get("VERSION_ID", ""),
        codename=codename,
        debian_version=debian_version,
        arch=arch,
        packages=packages,
        facts=facts,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    log.info(
        "inventory collected",
        extra={"host": inv.host, "codename": codename, "packages": len(packages)},
    )
    return inv
