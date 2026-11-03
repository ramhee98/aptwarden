"""Minimal HTTP client on top of urllib with gzip, retries and an injectable interface.

Responses are read in blocks with a size limit, and gzip bodies are decompressed
incrementally with a separate limit on the decompressed size: a server cannot
make aptwarden buffer an unbounded body or inflate a decompression bomb.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field

from aptwarden import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"aptwarden/{__version__} (+https://github.com/ramhee98/aptwarden)"
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
# The largest feed, the Debian tracker JSON, is about 14 MiB gzip-compressed and
# 84 MiB decompressed (2026-11). The limit applies to the bytes received and,
# separately, to the decompressed body.
MAX_BODY = 256 * 2**20
CHUNK = 2**16


class HttpError(Exception):
    def __init__(self, url: str, message: str, status: int | None = None):
        super().__init__(f"{url}: {message}")
        self.url = url
        self.status = status


class ResponseTooLarge(HttpError):
    """The body exceeded the size limit; not retried."""


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)  # lower-case keys

    def json(self):
        return json.loads(self.body)


class HttpClient:
    def __init__(self, timeout: float = 60, retries: int = 2, backoff: float = 2.0,
                 max_body: int = MAX_BODY):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_body = max_body

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: bytes | None = None,
        retries: int | None = None,
    ) -> Response:
        """Send a request. Every HTTP status is returned as a Response; only
        network failures (after retries) raise HttpError."""
        attempts = (self.retries if retries is None else retries) + 1
        hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip", **(headers or {})}
        last_error = ""
        for attempt in range(attempts):
            if attempt:
                time.sleep(self.backoff * attempt)
            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    resp = self._response(url, r.status, r, r.headers)
            except urllib.error.HTTPError as e:
                with e:
                    resp = self._response(url, e.code, e, e.headers)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_error = str(getattr(e, "reason", e))
                log.debug("http request failed", extra={"url": url, "error": last_error})
                continue
            if resp.status in RETRY_STATUS and attempt + 1 < attempts:
                last_error = f"HTTP {resp.status}"
                continue
            return resp
        raise HttpError(url, last_error or "request failed")

    def _response(self, url: str, status: int, fp, headers) -> Response:
        hdrs = _lower(headers)
        return Response(status, read_body(fp, url, self.max_body,
                                          gzipped=hdrs.get("content-encoding") == "gzip",
                                          length=hdrs.get("content-length")), hdrs)

    def get(self, url: str, headers: dict[str, str] | None = None, **kw) -> Response:
        return self.request("GET", url, headers=headers, **kw)

    def post_json(self, url: str, payload, **kw) -> Response:
        return self.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload).encode(),
            **kw,
        )


def _lower(headers) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


def read_body(fp, url: str, limit: int, *, gzipped: bool = False,
              length: str | None = None) -> bytes:
    """Read ``fp`` in blocks; more than ``limit`` bytes received, or more than
    ``limit`` bytes after gzip decompression, raises ResponseTooLarge. Invalid
    gzip data raises HttpError."""
    size = f"{limit / 2**20:g} MiB" if limit >= 2**20 else f"{limit} bytes"
    too_large = f"response larger than {size}"
    if length and length.isdigit() and int(length) > limit:
        raise ResponseTooLarge(url, too_large + f" (Content-Length {length})")
    out = bytearray()
    received = 0
    inflate = zlib.decompressobj(wbits=31) if gzipped else None
    try:
        while chunk := fp.read(CHUNK):
            received += len(chunk)
            if received > limit:
                raise ResponseTooLarge(url, too_large)
            if inflate is None:
                out += chunk
                continue
            while chunk:
                # max_length caps the output of a single call: a bomb never
                # inflates more than the limit, the rest stays unconsumed
                out += inflate.decompress(chunk, limit + 1 - len(out))
                if len(out) > limit:
                    raise ResponseTooLarge(url, too_large + " after decompression")
                chunk = inflate.unconsumed_tail
                if inflate.eof:  # another gzip member may follow
                    chunk = inflate.unused_data + chunk
                    inflate = zlib.decompressobj(wbits=31)
        if inflate is not None:
            out += inflate.flush()
    except zlib.error as e:
        raise HttpError(url, f"invalid gzip body: {e}") from None
    if len(out) > limit:
        raise ResponseTooLarge(url, too_large + " after decompression")
    return bytes(out)
