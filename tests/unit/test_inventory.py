import pytest

from aptwarden.inventory import (
    APT_TARGETS_FORMAT,
    InventoryError,
    collect,
    parse_apt_suites,
    parse_dpkg_query,
    parse_facts,
    parse_os_release,
)
from aptwarden.transport import TransportError
from tests.conftest import FakeTransport, debian_host_commands, fixture_text


def test_parse_real_dpkg_output():
    packages = parse_dpkg_query(fixture_text("dpkg-query-trixie.txt"))
    # 250 lines, one of them "ic " (config files only) is skipped
    assert len(packages) == 249
    by_name = {p.name: p for p in packages}
    # binary version with epoch, source version without
    bsdutils = by_name["bsdutils"]
    assert (bsdutils.version, bsdutils.source, bsdutils.source_version) == (
        "1:2.41-5", "util-linux", "2.41-5")
    # binNMU: binary +b5, source without
    bash = by_name["bash"]
    assert (bash.version, bash.source_version) == ("5.2.37-2+b5", "5.2.37-2")
    # multi-arch qualifier kept on the binary name
    assert "bind9-libs:amd64" in by_name


@pytest.mark.parametrize("line", [
    "evil\x1b[2J\t1\tevil\t1\tii \tamd64",       # control characters in the name
    "openssl\t3.5\x1b]0;x\x07\topenssl\t3.5\tii \tamd64",  # ... in the version
    "openssl\t3.5\topen ssl\t3.5\tii \tamd64",      # in the source
    "openssl\t3.5\topenssl\t3.5\n1\tii \tamd64",   # a line break in a field
    "openssl\t3.5\topenssl\t3.5\tii \tamd\x9b64",   # C1 in the architecture
    "-oops\t1\t\t\tii \tamd64",
    "openssl\t\topenssl\t3.5\tii \tamd64",          # empty version
])
def test_parse_dpkg_rejects_invalid_package_data(line):
    with pytest.raises(InventoryError, match="invalid package data|unexpected dpkg-query") as e:
        parse_dpkg_query(line + "\n")
    assert "\x1b" not in str(e.value) and "\x9b" not in str(e.value)


def test_parse_dpkg_accepts_deprecated_underscore():
    # dpkg still accepts "_" in package names, e.g. in old third-party packages
    [pkg] = parse_dpkg_query("vendor_tool\t1.0-1\tvendor_tool\t\tii \tamd64\n")
    assert (pkg.name, pkg.source) == ("vendor_tool", "vendor_tool")


def test_parse_dpkg_status_filter():
    text = (
        "a\t1\ta\t1\tii \tamd64\n"
        "b\t1\tb\t1\trc \tamd64\n"
        "c\t1\tc\t1\thi \tamd64\n"
        "d\t1\td\t1\tiF \tamd64\n"
        "e\t1\te\t1\tpn \tamd64\n"
    )
    assert [p.name for p in parse_dpkg_query(text)] == ["a", "c", "d"]


def test_parse_dpkg_fills_missing_source():
    p = parse_dpkg_query("foo:amd64\t1.0-1\t\t\tii \tamd64\n")[0]
    assert (p.source, p.source_version) == ("foo", "1.0-1")


def test_parse_dpkg_rejects_garbage():
    with pytest.raises(InventoryError):
        parse_dpkg_query("not tab separated\n")


def test_parse_os_release():
    osr = parse_os_release(fixture_text("os-release-trixie.txt"))
    assert osr["ID"] == "debian"
    assert osr["VERSION_CODENAME"] == "trixie"
    assert osr["VERSION_ID"] == "13"
    assert osr["PRETTY_NAME"] == "Debian GNU/Linux 13 (trixie)"


def test_parse_facts():
    assert parse_facts("a=1\nnoise\nb = two words\n") == {"a": "1", "b": "two words"}


def test_collect():
    t = FakeTransport("web01", debian_host_commands())
    inv = collect(t)
    assert inv.host == "web01"
    assert (inv.os_id, inv.os_version_id, inv.codename) == ("debian", "13", "trixie")
    assert inv.debian_version == "13.1"
    assert len(inv.packages) == 249
    assert inv.facts["virt"] == "lxc"
    assert inv.facts["needrestart_installed"] == "no"
    sources = inv.source_packages()
    assert sorted(sources[("util-linux", "2.41-5")])[:2] == ["bsdextrautils", "bsdutils"]


def test_collect_rejects_non_debian():
    cmds = debian_host_commands(os_release='ID=fedora\nVERSION_ID="40"\n')
    with pytest.raises(InventoryError, match="not a Debian"):
        collect(FakeTransport("x", cmds))


def test_collect_accepts_debian_derivatives_but_needs_codename():
    cmds = debian_host_commands(os_release='ID=foo\nID_LIKE="debian"\nVERSION_ID=1\n')
    with pytest.raises(InventoryError, match="VERSION_CODENAME"):
        collect(FakeTransport("x", cmds))


def test_collect_wraps_transport_errors():
    class Broken(FakeTransport):
        def run(self, argv, timeout=None):
            raise TransportError("ssh 192.0.2.1: Connection refused")

    with pytest.raises(InventoryError, match="Connection refused"):
        collect(Broken("x", {}))


def test_parse_apt_suites():
    text = (
        # Release file read: the codename wins over the sources entry's "stable-security"
        "deb|Packages|trixie-security|stable-security\n"
        "deb|Translations|trixie-security|stable-security\n"
        # before the first apt update there is no codename, only the sources entry
        "deb|Packages||trixie\n"
        "deb|Packages|trixie-updates|trixie-updates\n"
        "deb-src|Sources|forky|forky\n"       # source packages are not installed from
        "deb|Packages||./\n"                  # flat repository
        "deb|Packages|bad\x1b[2J|bad\n"       # garbage from the host
        "noise\n"
    )
    assert parse_apt_suites(text) == ["trixie", "trixie-security", "trixie-updates"]


def test_collect_apt_suites():
    inv = collect(FakeTransport("web01", debian_host_commands(apt_suites=("trixie",))))
    assert inv.facts["apt_suites"] == "trixie"
    assert inv.apt_suites() == {"trixie"}


def test_collect_without_apt_suites():
    cmds = debian_host_commands()
    del cmds[("apt-get", "indextargets", f"--format={APT_TARGETS_FORMAT}")]
    inv = collect(FakeTransport("web01", cmds))  # e.g. apt too old for indextargets
    assert "apt_suites" not in inv.facts
    assert inv.apt_suites() is None
