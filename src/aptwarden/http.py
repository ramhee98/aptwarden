"""Minimal HTTP client on top of urllib with gzip, retries and an injectable interface."""

from __future__ import annotations

import gzip
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from aptwarden import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"aptwarden/{__version__} (+https://github.com/ramhee98/aptwarden)"
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})


class HttpError(Exception):
    def __init__(self, url: str, message: str, status: int | None = None):
        super().__init__(f"{url}: {message}")
        self.url = url
        self.status = status


@dataclass
class Response:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)  # lower-case keys

    def json(self):
        return json.loads(self.body)


class HttpClient:
    def __init__(self, timeout: float = 60, retries: int = 2, backoff: float = 2.0):
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff

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
                    resp = Response(r.status, r.read(), _lower(r.headers))
            except urllib.error.HTTPError as e:
                resp = Response(e.code, e.read() or b"", _lower(e.headers))
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_error = str(getattr(e, "reason", e))
                log.debug("http request failed", extra={"url": url, "error": last_error})
                continue
            if resp.headers.get("content-encoding") == "gzip" and resp.body:
                resp.body = gzip.decompress(resp.body)
            if resp.status in RETRY_STATUS and attempt + 1 < attempts:
                last_error = f"HTTP {resp.status}"
                continue
            return resp
        raise HttpError(url, last_error or "request failed")

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
