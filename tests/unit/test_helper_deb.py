"""The aptwarden-helper Debian package (tools/build-helper-deb). Installing and
removing it is tested in CI in a Debian 13 container (contrib/deb/test-helper-deb)."""

import os
import shutil
import subprocess
from importlib import resources
from pathlib import Path

import pytest

from aptwarden.patch.runner import HELPER_VERSION

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "tools" / "build-helper-deb"
POSTINST = ROOT / "contrib" / "deb" / "aptwarden-helper" / "postinst"

needs_dpkg = pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="needs dpkg-deb")


def build(out: Path) -> Path:
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}
    r = subprocess.run([str(BUILD), str(out)], capture_output=True, text=True, env=env,
                       check=True)
    return Path(r.stdout.strip())


@needs_dpkg
def test_package_version_is_the_helper_version_and_reproducible(tmp_path):
    deb = build(tmp_path / "a")
    assert deb.name == f"aptwarden-helper_{HELPER_VERSION}_all.deb"

    def field(name):
        return subprocess.run(["dpkg-deb", "-f", str(deb), name], capture_output=True,
                              text=True, check=True).stdout.strip()

    assert field("Version") == str(HELPER_VERSION)
    assert field("Architecture") == "all"
    assert "sudo" in field("Depends")
    assert build(tmp_path / "b").read_bytes() == deb.read_bytes()


@needs_dpkg
def test_package_contents(tmp_path):
    deb = build(tmp_path)
    listing = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True,
                             check=True).stdout
    files = {line.split()[-1]: line.split()[:2] for line in listing.splitlines()}
    assert files["./usr/lib/aptwarden/aptwarden-helper"] == ["-rwxr-xr-x", "root/root"]
    # postinst writes the sudoers rule after checking it with visudo; nothing in
    # /etc or /usr/local comes from the archive
    assert not [f for f in files if f.startswith(("./etc/", "./usr/local/"))]
    x = tmp_path / "x"
    subprocess.run(["dpkg-deb", "-x", str(deb), str(x)], check=True)
    packaged = (x / "usr/lib/aptwarden/aptwarden-helper").read_text()
    assert packaged == resources.files("aptwarden").joinpath(
        "helper/aptwarden-helper").read_text()


def test_postinst_sudoers_rule_matches_the_manual_one():
    """Same defaults as helper/sudoers, the user may run the helper and nothing else,
    and the rule is checked with visudo before it is installed."""
    manual = resources.files("aptwarden").joinpath("helper/sudoers").read_text()
    text = POSTINST.read_text()
    [defaults] = [line for line in manual.splitlines() if line.startswith("Defaults")]
    assert defaults in text
    assert "aptwarden ALL=(root) NOPASSWD: $cmds\n" in text
    assert 'cmds=$HELPER\n' in text and 'cmds="$cmds, $LEGACY"' in text
    assert text.index("visudo -cqf") < text.index('mv -f "$tmp" "$SUDOERS"')


def test_installer_refuses_when_the_package_is_installed(capsys):
    from aptwarden import cli

    assert cli.main(["helper", "show", "--install"]) == 0
    script = capsys.readouterr().out
    check = script.index("dpkg -s aptwarden-helper")
    assert check < script.index("install -d -m 755")
    assert "update it with apt instead" in script


# sha256 over everything that goes into the package, per package version. One version
# must always have the same content: an apt repository refuses a version it already has
# with other content, and hosts would not upgrade to it.
PACKAGE_INPUTS = {
    4: "fba8d5fc43bf37f8b2acf71f5f7162b0ad4df3ba66ccd4d24d4b534fedab93f5",
}


def package_fingerprint() -> str:
    import hashlib

    h = hashlib.sha256()
    for path in (resources.files("aptwarden").joinpath("helper/aptwarden-helper"),
                 *sorted((ROOT / "contrib" / "deb" / "aptwarden-helper").iterdir()),
                 ROOT / "LICENSE", BUILD):
        h.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()


def test_a_changed_package_has_a_new_version():
    fingerprint = package_fingerprint()
    assert PACKAGE_INPUTS.get(HELPER_VERSION) == fingerprint, (
        "the helper or the package changed: raise HELPER_VERSION (helper script and "
        f"patch/runner.py) and add {HELPER_VERSION + 1}: {fingerprint!r} here"
        if HELPER_VERSION in PACKAGE_INPUTS else
        f"add {HELPER_VERSION}: {fingerprint!r} to PACKAGE_INPUTS")
