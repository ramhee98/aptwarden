import contextlib
import gzip
import io
import threading
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aptwarden.http import CHUNK, HttpClient, HttpError, ResponseTooLarge, read_body

LIMIT = 64 * 1024


@pytest.fixture
def server():
    """Local HTTP server; tests set ``routes[path] = (status, headers, body)``."""
    routes: dict[str, tuple[int, dict, bytes]] = {}
    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            status, headers, body = routes[self.path]
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            if "Content-Length" not in headers:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            # the client may stop reading early, as intended
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05},
                     daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", routes, hits
    httpd.shutdown()
    httpd.server_close()


def client():
    return HttpClient(timeout=5, retries=2, backoff=0, max_body=LIMIT)


def test_plain_and_gzip_bodies_within_the_limit(server):
    base, routes, _ = server
    routes["/plain"] = (200, {}, b"x" * LIMIT)
    routes["/gz"] = (200, {"Content-Encoding": "gzip"}, gzip.compress(b"y" * LIMIT))
    # two gzip members, as gzip.decompress accepts
    routes["/multi"] = (200, {"Content-Encoding": "gzip"},
                        gzip.compress(b"a" * 10) + gzip.compress(b"b" * 10))
    assert client().get(base + "/plain").body == b"x" * LIMIT
    assert client().get(base + "/gz").body == b"y" * LIMIT
    assert client().get(base + "/multi").body == b"a" * 10 + b"b" * 10


def test_oversized_body_is_rejected_without_retries(server):
    base, routes, hits = server
    routes["/big"] = (200, {}, b"x" * (LIMIT + 1))
    with pytest.raises(ResponseTooLarge, match="response larger than 65536 bytes"):
        client().get(base + "/big")
    assert hits == ["/big"]  # not retried


def test_body_without_content_length_is_cut_off(server):
    base, routes, _ = server
    # a lying or missing Content-Length must not matter: the limit counts bytes read
    routes["/lying"] = (200, {"Content-Length": "10"}, b"x" * 10)
    routes["/huge"] = (200, {"Content-Length": str(LIMIT * 1000)}, b"")
    assert client().get(base + "/lying").body == b"x" * 10
    with pytest.raises(ResponseTooLarge, match=r"Content-Length 65536000"):
        client().get(base + "/huge")


def test_gzip_bomb_stops_at_the_limit(server):
    base, routes, _ = server
    bomb = gzip.compress(b"\0" * (LIMIT * 200))  # ~13 MB inflated, a few kB on the wire
    assert len(bomb) < LIMIT
    routes["/bomb"] = (200, {"Content-Encoding": "gzip"}, bomb)
    with pytest.raises(ResponseTooLarge, match="after decompression"):
        client().get(base + "/bomb")


def test_error_status_bodies_are_limited_too(server):
    base, routes, _ = server
    routes["/404"] = (404, {}, b"not found")
    routes["/500big"] = (500, {}, b"x" * (LIMIT + 1))
    resp = client().get(base + "/404")
    assert resp.status == 404 and resp.body == b"not found"
    with pytest.raises(ResponseTooLarge):
        client().get(base + "/500big")


def test_invalid_gzip_is_an_http_error(server):
    base, routes, _ = server
    routes["/bad"] = (200, {"Content-Encoding": "gzip"}, b"definitely not gzip")
    with pytest.raises(HttpError, match="invalid gzip body"):
        client().get(base + "/bad")


class CountingReader(io.BytesIO):
    """Records how much a reader asked for, to show the body is never read whole."""

    def __init__(self, data):
        super().__init__(data)
        self.largest = 0

    def read(self, n=-1):
        self.largest = max(self.largest, n if n >= 0 else len(self.getvalue()))
        return super().read(n)


def test_read_body_reads_in_blocks_and_inflates_bounded():
    fp = CountingReader(b"z" * (3 * CHUNK))
    assert read_body(fp, "u", 4 * CHUNK) == b"z" * (3 * CHUNK)
    assert fp.largest == CHUNK  # blockwise, never the whole body at once
    # one compressed block that inflates far beyond the limit still stops at it
    deflated = zlib.compressobj(wbits=31)
    bomb = deflated.compress(b"\0" * (LIMIT * 50)) + deflated.flush()
    with pytest.raises(ResponseTooLarge, match="after decompression"):
        read_body(io.BytesIO(bomb), "u", LIMIT, gzipped=True)
