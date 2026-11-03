import io
import json
import logging
import sys

from aptwarden import cli
from aptwarden import log as aplog
from aptwarden.log import JsonFormatter, SafeStream, TextFormatter, safe


def record(msg, **extra):
    r = logging.LogRecord("aptwarden.test", logging.WARNING, __file__, 1, msg, None, None)
    r.__dict__.update(extra)
    return r


def test_safe_escapes_c0_and_c1_controls():
    assert safe("a\x1b[2Jb\x07\x00\x7f\x9b") == "a\\x1b[2Jb\\x07\\x00\\x7f\\x9b"
    assert safe("one\ntwo\rthree") == "one\\ntwo\\rthree"
    assert safe("one\ntwo\r", keep_newlines=True) == "one\ntwo\\r"
    # ordinary text, tabs and non-ASCII letters stay as they are
    assert safe("tab\there äöü € 1:2.41-5") == "tab\there äöü € 1:2.41-5"
    assert safe(42) == "42"


def test_text_formatter_escapes_host_data():
    line = TextFormatter().format(record("host said: \x1b]0;pwned\x07\nFAKE line",
                                         host="web\x1b[31m01"))
    assert "\x1b" not in line and "\n" not in line
    assert "host said: \\x1b]0;pwned\\x07\\nFAKE line" in line
    assert "host=web\\x1b[31m01" in line


def test_json_formatter_already_escapes():
    entry = json.loads(JsonFormatter().format(record("a\x1bb\nc")))
    assert entry["msg"] == "a\x1bb\nc"  # json.dumps escapes, decoding restores it


def test_safe_stream():
    buf = io.StringIO()
    s = SafeStream(buf)
    s.write("ok\n\x1b[2J\n")
    assert buf.getvalue() == "ok\n\\x1b[2J\n"
    assert s.isatty() is False  # everything else is passed through


def test_cli_output_is_escaped(monkeypatch, capsys):
    monkeypatch.setattr(cli, "__version__", "1.0\x1b[2J")
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out == "aptwarden 1.0\\x1b[2J\n"
    assert not isinstance(sys.stdout, aplog.SafeStream)  # restored
