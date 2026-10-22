"""Debian version parsing and comparison.

A pure Python port of dpkg's ``parseversion()`` and ``verrevcmp()`` from
``lib/dpkg/version.c``, so results match ``dpkg --compare-versions`` exactly:

* ``epoch:upstream-revision``; a missing epoch is 0, a missing revision is ""
  (which compares equal to "0", so ``1.0 == 1.0-0``)
* non-digit runs compare by a modified ASCII order where ``~`` sorts before
  everything, even the end of the string, and letters sort before non-letters
* digit runs compare numerically
"""

from __future__ import annotations

import functools
from typing import NamedTuple

_DIGITS = frozenset("0123456789")
_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class Version(NamedTuple):
    epoch: int
    upstream: str
    revision: str

    def __str__(self) -> str:
        s = f"{self.epoch}:{self.upstream}" if self.epoch else self.upstream
        return f"{s}-{self.revision}" if self.revision else s


def parse(version: str) -> Version:
    """Split a version string into epoch, upstream version and revision.

    Raises ValueError for the cases dpkg treats as hard errors. Like dpkg, it
    tolerates unusual characters (dpkg only warns about those).
    """
    v = version.strip()
    if not v:
        raise ValueError("version string is empty")
    if any(c.isspace() for c in v):
        raise ValueError(f"version string has embedded spaces: {version!r}")

    epoch = 0
    if ":" in v:
        epoch_str, v = v.split(":", 1)
        if not epoch_str:
            raise ValueError(f"epoch in version is empty: {version!r}")
        if not all(c in _DIGITS for c in epoch_str):
            raise ValueError(f"epoch in version is not a number: {version!r}")
        epoch = int(epoch_str)
        if epoch > 2**31 - 1:
            raise ValueError(f"epoch in version is too big: {version!r}")
        if not v:
            raise ValueError(f"nothing after colon in version number: {version!r}")

    upstream, sep, revision = v.rpartition("-")
    if not sep:
        upstream, revision = v, ""
    elif not revision:
        raise ValueError(f"revision number is empty: {version!r}")
    if not upstream:
        raise ValueError(f"version number is empty: {version!r}")
    return Version(epoch, upstream, revision)


def _order(c: str) -> int:
    if c in _DIGITS:
        return 0
    if c in _LETTERS:
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and a[i] not in _DIGITS) or (j < lb and b[j] not in _DIGITS):
            ac = _order(a[i]) if i < la else 0
            bc = _order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i] in _DIGITS and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i] in _DIGITS:
            return 1
        if j < lb and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


def compare(a: str | Version, b: str | Version) -> int:
    """Return -1, 0 or 1 like ``dpkg --compare-versions a lt|eq|gt b``."""
    va = a if isinstance(a, Version) else parse(a)
    vb = b if isinstance(b, Version) else parse(b)
    if va.epoch != vb.epoch:
        return _sign(va.epoch - vb.epoch)
    r = _verrevcmp(va.upstream, vb.upstream)
    if r:
        return _sign(r)
    return _sign(_verrevcmp(va.revision, vb.revision))


sort_key = functools.cmp_to_key(compare)


def max_version(versions):
    """Return the highest version of an iterable, or None if it is empty."""
    best = None
    for v in versions:
        if best is None or compare(v, best) > 0:
            best = v
    return best


def in_range(
    version: str,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """True if ``version`` lies in an OSV-style ECOSYSTEM range.

    ``introduced`` of None or "0" means "since the beginning". ``fixed`` is
    exclusive, ``last_affected`` inclusive.
    """
    if introduced not in (None, "0") and compare(version, introduced) < 0:
        return False
    if fixed is not None and compare(version, fixed) >= 0:
        return False
    return not (last_affected is not None and compare(version, last_affected) > 0)
