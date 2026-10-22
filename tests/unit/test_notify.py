import smtplib
import sqlite3

import pytest

from aptwarden.models import Finding, FindingStatus, Severity
from aptwarden.notify import (
    Dispatcher,
    HostChanges,
    Message,
    Notifier,
    NotifyError,
    alert_candidates,
    compose_alert,
    compose_summary,
)
from aptwarden.notify import email as email_mod
from aptwarden.notify.email import EmailNotifier
from aptwarden.runner import RunReport
from aptwarden.sources import SourceStatus
from aptwarden.state import HostRecord, State

EMAIL = {"enabled": True, "host": "192.0.2.25", "port": 25, "security": "starttls",
         "tls_verify": True, "tls_server_name": "mx.example.org", "username": None,
         "password_file": None, "from": "aptwarden@example.org", "to": ["admin@example.org"],
         "timeout": 5}


class FakeSMTP:
    instances: list = []
    starttls_offered = True
    refuse: dict = {}
    fail_connect: Exception | None = None

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.calls = []
        self.sent = []
        self.server_name = None
        FakeSMTP.instances.append(self)

    def connect(self, host, port):
        if FakeSMTP.fail_connect:
            raise FakeSMTP.fail_connect
        self.calls.append(("connect", host, port))

    def ehlo(self):
        self.calls.append(("ehlo",))

    def has_extn(self, name):
        return self.starttls_offered and name == "starttls"

    def starttls(self, context):
        self.calls.append(("starttls", self.server_name))

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg):
        if FakeSMTP.refuse:
            raise smtplib.SMTPRecipientsRefused(FakeSMTP.refuse)
        self.sent.append(msg)
        return {}

    def quit(self):
        self.calls.append(("quit",))

    def close(self):
        pass


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instances = []
    FakeSMTP.starttls_offered = True
    FakeSMTP.refuse = {}
    FakeSMTP.fail_connect = None
    monkeypatch.setattr(email_mod, "_SMTP", FakeSMTP)
    monkeypatch.setattr(email_mod, "_SMTP_SSL", FakeSMTP)
    return FakeSMTP


def test_email_send_with_starttls(smtp):
    EmailNotifier(EMAIL).send(Message("alert", "subj", "body äöü"))
    [conn] = smtp.instances
    assert conn.calls == [("connect", "192.0.2.25", 25), ("ehlo",),
                          ("starttls", "mx.example.org"), ("ehlo",), ("quit",)]
    [msg] = conn.sent
    assert msg["Subject"] == "subj"
    assert msg["To"] == "admin@example.org"
    assert msg["Auto-Submitted"] == "auto-generated"
    assert msg["Message-ID"].endswith("@example.org>")
    assert "body äöü" in msg.get_content()


def test_email_requires_starttls_when_configured(smtp):
    smtp.starttls_offered = False
    with pytest.raises(NotifyError, match="does not offer STARTTLS"):
        EmailNotifier(EMAIL).send(Message("test", "s", "b"))
    EmailNotifier({**EMAIL, "security": "none"}).send(Message("test", "s", "b"))
    assert smtp.instances[-1].sent


def test_email_login_with_password_file(smtp, tmp_path):
    (tmp_path / "smtp-pw").write_text("s3cret\n")
    cfg = {**EMAIL, "username": "aptw", "password_file": "smtp-pw"}
    EmailNotifier(cfg, tmp_path).send(Message("test", "s", "b"))
    assert ("login", "aptw", "s3cret") in smtp.instances[0].calls


def test_email_greylisting_is_reported_as_temporary(smtp):
    smtp.refuse = {"admin@example.org": (450, b"4.7.1 Service is unavailable (try later)")}
    with pytest.raises(NotifyError, match=r"450 4\.7\.1 .*temporary"):
        EmailNotifier(EMAIL).send(Message("test", "s", "b"))


def test_email_connection_error(smtp):
    smtp.fail_connect = ConnectionRefusedError(111, "Connection refused")
    with pytest.raises(NotifyError, match="Connection refused"):
        EmailNotifier(EMAIL).send(Message("test", "s", "b"))


def test_starttls_verifies_against_server_name(monkeypatch):
    seen = {}
    monkeypatch.setattr(smtplib.SMTP, "starttls",
                        lambda self, *a, **kw: seen.setdefault("host", self._host))
    conn = email_mod._SMTP()
    conn._host = "192.0.2.25"
    conn.server_name = "mx.example.org"
    conn.starttls()
    assert seen["host"] == "mx.example.org"


# --- dispatcher ----------------------------------------------------------------

class FakeNotifier(Notifier):
    name = "fake"

    def __init__(self):
        self.sent: list[Message] = []
        self.fail = False

    def send(self, msg):
        if self.fail:
            raise NotifyError("relay down")
        self.sent.append(msg)


def f(vid, sev=Severity.HIGH, kev=False, status=FindingStatus.FIXABLE, pkg="openssl"):
    return Finding(vid, pkg, "3.5.1-1", status, fixed_version="3.5.4-1", severity=sev, kev=kev,
                   description=f"about {vid}")


def run_with(hosts, changes=None, sources=None, status="ok"):
    run = RunReport("r1", "report", "2026-10-22T10:00:00+00:00", status=status)
    run.sources = sources or [SourceStatus("debian_tracker")]
    run.hosts = hosts
    run.changes = changes or {h.host: HostChanges() for h in hosts}
    return run


def ok_host(name, findings):
    return HostRecord("r1", name, "192.0.2.10", True, None, {"codename": "trixie"}, [],
                      "2026-10-22T10:00:00+00:00", findings)


def failed_host(name):
    return HostRecord("r1", name, "192.0.2.20", False, "ssh: timed out", {}, [],
                      "2026-10-22T10:00:00+00:00")


@pytest.fixture
def dispatcher(make_config, tmp_path):
    cfg = make_config(notify={"summary": "changes", "alert": {"remind_after": "1d"}})
    state = State(tmp_path / "state.db")
    notifier = FakeNotifier()
    yield Dispatcher(cfg, state, [notifier]), notifier, state
    state.close()


def test_alert_candidates():
    cfg = {"min_severity": "critical", "kev": True}
    fs = [f("A", Severity.CRITICAL), f("B", Severity.LOW, kev=True), f("C", Severity.HIGH),
          f("D", Severity.CRITICAL, status=FindingStatus.UNDETERMINED),
          f("E", Severity.CRITICAL, status=FindingStatus.NO_FIX)]
    assert [x.vuln_id for x in alert_candidates(fs, cfg)] == ["A", "B", "E"]
    assert [x.vuln_id for x in alert_candidates(fs, {**cfg, "kev": False})] == ["A", "E"]


def test_alert_once_then_reminder(dispatcher):
    d, notifier, state = dispatcher
    host = ok_host("web01", [f("CVE-1", Severity.CRITICAL), f("CVE-2", Severity.HIGH)])
    assert d.dispatch(run_with([host])) == []
    [alert] = [m for m in notifier.sent if m.kind == "alert"]
    assert "1 critical/KEV vulnerabilities on web01" in alert.subject
    assert "CVE-1" in alert.body and "CVE-2" not in alert.body
    assert "security-tracker.debian.org/tracker/CVE-1" in alert.body

    notifier.sent.clear()
    d.dispatch(run_with([host]))
    assert notifier.sent == []  # no alert again, no changes -> no summary

    # after remind_after
    state.db.execute("UPDATE seen SET alerted_at = '2026-01-01T00:00:00+00:00'")
    d.dispatch(run_with([host]))
    assert [m.kind for m in notifier.sent] == ["alert", "summary"]


def test_failed_delivery_is_retried(dispatcher):
    d, notifier, _ = dispatcher
    host = ok_host("web01", [f("CVE-1", Severity.CRITICAL)])
    notifier.fail = True
    errors = d.dispatch(run_with([host]))
    assert errors and "relay down" in errors[0]
    notifier.fail = False
    d.dispatch(run_with([host]))
    assert any(m.kind == "alert" for m in notifier.sent)


def test_host_failure_alerts_on_transition_only(dispatcher):
    d, notifier, _ = dispatcher
    host = failed_host("db01")
    d.dispatch(run_with([host], {"db01": HostChanges(newly_failed=True)}, status="partial"))
    alert = next(m for m in notifier.sent if m.kind == "alert")
    assert "1 host(s) unreachable" in alert.subject and "ssh: timed out" in alert.body
    notifier.sent.clear()
    d.dispatch(run_with([host], {"db01": HostChanges(newly_failed=False)}, status="partial"))
    assert [m.kind for m in notifier.sent] == ["summary"]  # status not ok -> summary


def test_no_data_alerts(dispatcher):
    d, notifier, _ = dispatcher
    run = run_with([ok_host("web01", [])],
                   sources=[SourceStatus("debian_tracker", ok=False, message="HTTP 500")],
                   status="failed")
    d.dispatch(run)
    alert = next(m for m in notifier.sent if m.kind == "alert")
    assert "no vulnerability data" in alert.subject and "HTTP 500" in alert.body


def test_summary_policies(make_config, tmp_path):
    host = ok_host("web01", [f("CVE-1", Severity.HIGH)])
    for policy, expected in (("always", ["summary"]), ("changes", []), ("never", [])):
        state = State(tmp_path / f"{policy}.db")
        notifier = FakeNotifier()
        Dispatcher(make_config(notify={"summary": policy}), state, [notifier]).dispatch(
            run_with([host]))
        assert [m.kind for m in notifier.sent] == expected, policy
        state.close()


def test_no_notifiers_is_a_noop(make_config, tmp_path):
    state = State(tmp_path / "s.db")
    assert Dispatcher(make_config(), state).dispatch(run_with([])) == []
    state.close()


def test_compose_summary(make_config):
    web = ok_host("web01", [f("CVE-1", Severity.CRITICAL, kev=True), f("CVE-2", Severity.LOW),
                            f("CVE-3", Severity.HIGH, status=FindingStatus.NO_FIX)])
    changes = {"web01": HostChanges(new=[web.findings[0], web.findings[1]],
                                    resolved=[f("CVE-9", pkg="glibc")]),
               "db01": HostChanges(newly_failed=True)}
    msg = compose_summary("[aptw]", run_with([web, failed_host("db01")], changes,
                                             status="partial"), make_config())
    assert msg.subject == "[aptw] PROBLEM: 2 hosts · 2 fixable (1 critical, 1 KEV) · 2 new"
    assert "db01: ssh: timed out" in msg.body
    assert "New since the last scan" in msg.body
    # fixable findings are listed even below the report threshold
    assert "web01 CVE-1" in msg.body and "web01 CVE-2" in msg.body
    assert "web01: 1 vulnerabilities in glibc" in msg.body
    assert "fixable now: 2 vulnerabilities" in msg.body  # full report appended


def test_compose_alert_none_when_nothing_to_say():
    assert compose_alert("[a]", run_with([ok_host("web01", [])]), {}, []) is None


def test_state_migration_from_v1(tmp_path):
    path = tmp_path / "state.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE seen (host TEXT NOT NULL, source_package TEXT NOT NULL, "
               "vuln_id TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, "
               "PRIMARY KEY (host, source_package, vuln_id))")
    db.execute("INSERT INTO seen VALUES ('web01', 'openssl', 'CVE-1', 'a', 'b')")
    db.execute("PRAGMA user_version=1")
    db.commit()
    db.close()
    state = State(path)
    assert state.db.execute("PRAGMA user_version").fetchone()[0] == 2
    assert state.alert_due("web01", [f("CVE-1")], 0) != []
    state.mark_alerted("web01", [f("CVE-1")])
    assert state.alert_due("web01", [f("CVE-1")], 0) == []
