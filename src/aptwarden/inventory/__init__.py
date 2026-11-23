"""Package inventory of a Debian or Ubuntu host. Needs no privileges."""

from __future__ import annotations

import csv
import io
import logging
import re
import shlex
from datetime import UTC, date, datetime

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

# What dpkg itself accepts (it still allows the deprecated "_" in names, and lowercases
# them). Anything else (e.g. control characters) comes from a host that lies about its
# packages and would end up in terminals, logs and mails.
_NAME = re.compile(r"[a-z0-9][a-z0-9+._-]*(:[a-z0-9-]+)?")
_SOURCE = re.compile(r"([a-z0-9][a-z0-9+._-]*)?")
_VERSION = re.compile(r"[A-Za-z0-9.+~:-]+")
_ARCH = re.compile(r"[a-z0-9-]+")
_STATUS = re.compile(r"[a-zA-Z ]{2,3}")

# The host's configured package indexes, as apt itself sees them: one-line and deb822
# sources, disabled entries and options are already resolved. The codename comes from
# the downloaded Release file (so "stable-security" turns into "trixie-security"), the
# release from the sources entry, which is all there is before the first apt update.
APT_TARGETS_FORMAT = "$(TARGET_OF)|$(IDENTIFIER)|$(CODENAME)|$(RELEASE)"
_SUITE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+~_/-]*")

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


# Ubuntu's release dates, shipped on every Ubuntu host (distro-info-data).
DISTRO_INFO = "/usr/share/distro-info/ubuntu.csv"
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


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
        if not (_NAME.fullmatch(name) and _VERSION.fullmatch(version)
                and _SOURCE.fullmatch(source) and _STATUS.fullmatch(status)
                and (not source_version or _VERSION.fullmatch(source_version))
                and _ARCH.fullmatch(arch)):
            raise InventoryError(f"invalid package data from dpkg-query on line {lineno}: "
                                 f"{line!r}")
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


def parse_apt_suites(text: str, distro: str = "debian") -> list[str]:
    """Suites of the binary package indexes from ``apt-get indextargets``.

    Debian: the codename from the Release file, so an alias like ``stable-security``
    resolves to ``trixie-security``. Ubuntu's Release files carry the bare codename
    for every pocket (``Codename: noble`` in noble-security), so there the suite of
    the sources entry counts. Ubuntu has no aliases like ``stable``.
    """
    suites = set()
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) != 4 or parts[0] != "deb" or parts[1] != "Packages":
            continue
        name = parts[3] if distro == "ubuntu" else (parts[2] or parts[3])
        if _SUITE.fullmatch(name):  # skips flat repositories ("./") and garbage
            suites.add(name)
    return sorted(suites)


def parse_distro_info(text: str, codename: str) -> dict[str, str]:
    """End of standard support (``support_end``, the server date for LTS releases)
    and of Ubuntu Pro's ESM (``esm_end``) for a release, from distro-info's CSV.
    Older files lack newer releases: then nothing is known."""
    try:
        for row in csv.DictReader(io.StringIO(text)):
            row = {(k or "").lower(): (v or "") for k, v in row.items()}
            if row.get("series") != codename:
                continue
            facts = {}
            support_end = row.get("eol-server") or row.get("eol", "")
            if _DATE.fullmatch(support_end):
                facts["support_end"] = support_end
            if _DATE.fullmatch(row.get("eol-esm", "")):
                facts["esm_end"] = row["eol-esm"]
            return facts
    except csv.Error:
        pass
    return {}


def support_note(inv: HostInventory, today: date | None = None) -> str | None:
    """A warning once the host's release is past its standard support."""
    end, esm = inv.facts.get("support_end"), inv.facts.get("esm_end")
    today_s = (today or datetime.now(UTC).date()).isoformat()
    if not end or today_s <= end:
        return None
    if esm and today_s <= esm:
        return (f"{inv.release_label()} is out of standard support since {end}: security "
                f"fixes only through Ubuntu Pro (ESM until {esm})")
    return f"{inv.release_label()} is out of support since {esm or end}: no security fixes"


def detect_distro(os_release: dict[str, str]) -> str:
    """``debian`` or ``ubuntu``. Debian derivatives (``ID_LIKE=debian``) count as
    Debian, as before. Ubuntu derivatives (Mint, Pop!_OS, ...) are refused: their
    own repositories are not covered by Ubuntu's data, so they would look cleaner
    than they are."""
    os_id = os_release.get("ID", "")
    like = os_release.get("ID_LIKE", "").split()
    if os_id in ("debian", "ubuntu"):
        return os_id
    if "ubuntu" in like:
        raise InventoryError(f"unsupported distribution: {os_id!r} is based on Ubuntu, "
                             "only Ubuntu itself is supported")
    if "debian" in like:
        return "debian"
    raise InventoryError(f"not a Debian based system (ID={os_id!r})")


def os_version(distro: str, os_release: dict[str, str], debian_version: str) -> str:
    """The version to show: Debian's point release from /etc/debian_version
    ("13.1"), Ubuntu's from PRETTY_NAME ("24.04.3 LTS"; VERSION lacks the point
    release and, on 26.04, "LTS")."""
    if distro == "ubuntu":
        pretty, name = os_release.get("PRETTY_NAME", ""), os_release.get("NAME", "")
        if name and pretty.startswith(name + " "):
            return pretty[len(name) + 1:]
        return os_release.get("VERSION_ID", "")
    return debian_version or os_release.get("VERSION_ID", "")


def collect(transport: Transport) -> HostInventory:
    try:
        osr = transport.run(["cat", "/etc/os-release"])
        if not osr.ok:
            osr = transport.run(["cat", "/usr/lib/os-release"]).check()
        os_release = parse_os_release(osr.stdout)
        distro = detect_distro(os_release)

        dpkg = transport.run(["dpkg-query", "-W", f"-f={DPKG_FORMAT}"]).check()
        packages = parse_dpkg_query(dpkg.stdout)
        arch = transport.run(["dpkg", "--print-architecture"]).check().stdout.strip()
        debian_version = transport.run(["cat", "/etc/debian_version"]).stdout.strip()
        facts_result = transport.run(["sh", "-c", FACTS_SCRIPT])
        facts = parse_facts(facts_result.stdout) if facts_result.ok else {}
        targets = transport.run(["apt-get", "indextargets", f"--format={APT_TARGETS_FORMAT}"])
        suites = parse_apt_suites(targets.stdout, distro) if targets.ok else []
        # no suites at all means apt could not tell (e.g. too old): then nothing is checked
        if suites:
            facts["apt_suites"] = " ".join(suites)
        if distro == "ubuntu":
            info = transport.run(["cat", DISTRO_INFO])
            if info.ok:
                facts.update(parse_distro_info(info.stdout, os_release.get("VERSION_CODENAME", "")))
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
        distro=distro,
        os_version=os_version(distro, os_release, debian_version),
        arch=arch,
        packages=packages,
        facts=facts,
        collected_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    log.info(
        "inventory collected",
        extra={"host": inv.host, "distro": distro, "codename": codename,
               "packages": len(packages)},
    )
    return inv
