"""Maintenance windows like "Mon..Fri 02:00-04:00", "Sat,Sun 22:00-02:00" or
"daily 03:00-04:00". A window ending before it starts runs past midnight and
belongs to its start day. Times are the central host's local time."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta

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


def in_any(windows: list[str] | None, now: datetime | None = None) -> bool:
    """True if ``now`` lies in one of the windows; no windows means always."""
    if not windows:
        return True
    now = now or datetime.now()
    return any(parse(w).contains(now) for w in windows)
