import pytest

from aptwarden.inventory import (
    InventoryError,
    collect,
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
