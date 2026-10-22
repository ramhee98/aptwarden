"""Structured logging: JSON lines for journald, readable text for terminals.

Extra fields go through the standard ``extra`` argument::

    log.info("host scanned", extra={"host": "web01", "packages": 412})

The current run id is attached to every record automatically.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime

run_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("run_id", default=None)

_STANDARD_ATTRS = frozenset(
    vars(logging.LogRecord("x", logging.INFO, "x", 0, "x", None, None)).keys()
) | {"message", "asctime", "run_id"}


def _fields(record: logging.LogRecord) -> dict:
    return {k: v for k, v in vars(record).items() if k not in _STANDARD_ATTRS}


class _RunIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = run_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if getattr(record, "run_id", None):
            entry["run_id"] = record.run_id
        entry.update(_fields(record))
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        extra = " ".join(f"{k}={v}" for k, v in _fields(record).items())
        line = f"{ts} {record.levelname:<7} {record.getMessage()}"
        if extra:
            line += f"  {extra}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def setup(level: str = "info", fmt: str = "auto", stream=None) -> None:
    """Configure the root logger. ``fmt`` is "json", "text" or "auto"
    (text on a terminal, JSON otherwise, e.g. under systemd)."""
    stream = stream or sys.stderr
    if fmt == "auto":
        fmt = "text" if stream.isatty() else "json"
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    handler.addFilter(_RunIdFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
