"""Maintenance windows like "Mon..Fri 02:00-04:00", "Sat,Sun 22:00-02:00" or
"daily 03:00-04:00". A window ending before it starts runs past midnight and
belongs to its start day.

Times are wall-clock times in ``policy.timezone`` (an IANA name such as
Europe/Zurich), or the central host's local time without one. Across daylight
saving changes, a window covering the skipped hour is shorter that night (or
empty), and one covering the repeated hour is open twice; patch runs are
idempotent, so the second pass finds nothing to do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_RE = re.compile(r"^\s*(\S+)\s+(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})\s*$")


@dataclass(frozen=True)
class Window:
    days: frozenset[int]  # 0 = Monday
    start: time
    end: time | None  # None = 24:00
    text: str

    def contains(self, now: datetime) -> bool:
        t = now.time()
        crosses = self.end is not None and self.end <= self.start
        if not crosses:
            return now.weekday() in self.days and t >= self.start and (
                self.end is None or t < self.end)
        if now.weekday() in self.days and t >= self.start:
            return True
        yesterday = (now - timedelta(days=1)).weekday()
        return yesterday in self.days and t < self.end  # type: ignore[operator]


def _days(spec: str) -> frozenset[int]:
    spec = spec.lower()
    if spec in ("daily", "*"):
        return frozenset(range(7))
    days: set[int] = set()
    for part in spec.split(","):
        if ".." in part:
            a, b = part.split("..", 1)
            ia, ib = _DAYS.index(a[:3]), _DAYS.index(b[:3])
            days.update(range(ia, ib + 1) if ia <= ib else [*range(ia, 7), *range(0, ib + 1)])
        else:
            days.add(_DAYS.index(part[:3]))
    return frozenset(days)


def parse(text: str) -> Window:
    m = _RE.match(text)
    if not m:
        raise ValueError(f"invalid maintenance window {text!r} (e.g. 'Mon..Fri 02:00-04:00')")
    try:
        days = _days(m.group(1))
    except ValueError:
        raise ValueError(f"invalid days in maintenance window {text!r}") from None
    sh, sm, eh, em = (int(m.group(i)) for i in range(2, 6))
    if sh > 23 or sm > 59 or eh > 24 or em > 59 or (eh == 24 and em):
        raise ValueError(f"invalid time in maintenance window {text!r}")
    end = None if eh == 24 else time(eh, em)
    return Window(days, time(sh, sm), end, text)


def zone(name: str | None) -> tzinfo | None:
    """ZoneInfo for an IANA name; None (server local time) without one."""
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"unknown time zone {name!r} (expected an IANA name such as "
                         f"Europe/Zurich)") from None


def local_now(tz: str | None = None, now: datetime | None = None) -> datetime:
    """``now`` as wall-clock time in ``tz``. An aware ``now`` is converted; a
    naive one is taken as already being in that zone (tests). Without ``tz``,
    the server's local time."""
    z = zone(tz)
    if now is None:
        now = datetime.now(UTC)
    if now.tzinfo is None:
        return now.replace(tzinfo=z) if z else now.astimezone()
    return now.astimezone(z) if z else now.astimezone()


def in_any(windows: list[str] | None, now: datetime | None = None,
           tz: str | None = None) -> bool:
    """True if ``now`` lies in one of the windows; no windows means always."""
    if not windows:
        return True
    local = local_now(tz, now)
    return any(parse(w).contains(local) for w in windows)


def next_open(windows: list[str] | None, now: datetime | None = None,
              tz: str | None = None) -> tuple[datetime, bool] | None:
    """(start, already_open) of the current or next window, in ``tz``.
    None without windows (always open)."""
    if not windows:
        return None
    local = local_now(tz, now)
    if in_any(windows, local):
        return local, True
    z = local.tzinfo
    best = None
    for w in map(parse, windows):
        for d in range(0, 8):
            day = (local + timedelta(days=d)).date()
            if day.weekday() not in w.days:
                continue
            start = datetime.combine(day, w.start, tzinfo=z)
            # normalise a start in the skipped DST hour to a real instant
            start = start.astimezone(UTC).astimezone(z)
            if start > local:  # the first start of this window after now
                if best is None or start < best:
                    best = start
                break
    return (best, False) if best else None


def describe(windows: list[str] | None, tz: str | None) -> str:
    where = tz or "server local time"
    return f"{', '.join(windows)} ({where})" if windows else "any time"
