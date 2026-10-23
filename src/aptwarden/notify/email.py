"""E-mail notifications over SMTP (STARTTLS, implicit TLS or plain)."""

from __future__ import annotations

import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from aptwarden.config import ConfigError, read_secret
from aptwarden.notify import Message, Notifier, NotifyError


class _SMTP(smtplib.SMTP):
    """STARTTLS verifies the certificate against ``server_name`` if set (for a
    relay addressed by IP), else against the connect address. smtplib only
    records the host when it is passed to the constructor, so connect() does
    it here; otherwise the TLS handshake would get an empty server name."""

    server_name: str | None = None

    def connect(self, host="localhost", port=0, source_address=None):
        self._host = host
        return super().connect(host, port, source_address)

    def starttls(self, *args, **kwargs):
        if self.server_name:
            self._host = self.server_name
        return super().starttls(*args, **kwargs)


class _SMTP_SSL(smtplib.SMTP_SSL):  # noqa: N801 - mirrors smtplib's name
    server_name: str | None = None

    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((host, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self.server_name or host)


class EmailNotifier(Notifier):
    name = "email"

    def __init__(self, settings: dict, base_dir: Path | None = None):
        self.settings = settings
        self.base_dir = base_dir

    def build(self, msg: Message) -> EmailMessage:
        s = self.settings
        em = EmailMessage()
        em["Subject"] = msg.subject
        em["From"] = s["from"]
        em["To"] = ", ".join(s["to"])
        em["Date"] = formatdate(localtime=True)
        em["Message-ID"] = make_msgid(domain=s["from"].rpartition("@")[2] or None)
        # RFC 3834: keeps vacation responders and ticket systems from replying.
        em["Auto-Submitted"] = "auto-generated"
        em["X-Aptwarden-Kind"] = msg.kind
        em.set_content(msg.body)
        return em

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.settings.get("tls_verify", True):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def send(self, msg: Message) -> None:
        s = self.settings
        security = s.get("security", "starttls")
        server_name = s.get("tls_server_name")
        timeout = s.get("timeout", 30)
        try:
            if security == "ssl":
                smtp = _SMTP_SSL(context=self._context(), timeout=timeout)
            else:
                smtp = _SMTP(timeout=timeout)
            smtp.server_name = server_name
            smtp.connect(s["host"], s["port"])
            try:
                smtp.ehlo()
                if security == "starttls":
                    if not smtp.has_extn("starttls"):
                        raise NotifyError(f"{s['host']} does not offer STARTTLS")
                    smtp.starttls(context=self._context())
                    smtp.ehlo()
                if s.get("username"):
                    password = read_secret(s["password_file"], self.base_dir) \
                        if s.get("password_file") else ""
                    smtp.login(s["username"], password)
                refused = smtp.send_message(self.build(msg))
            finally:
                try:
                    smtp.quit()
                except (smtplib.SMTPException, OSError):
                    smtp.close()
        except NotifyError:
            raise
        except ConfigError as e:
            raise NotifyError(str(e)) from e
        except ssl.SSLCertVerificationError as e:
            hint = "" if s.get("tls_server_name") else (
                " (if the relay is addressed by IP, set notify.email.tls_server_name to the "
                "name in its certificate)")
            raise NotifyError(f"smtp {s['host']}:{s['port']}: {e.verify_message}{hint}") from e
        except smtplib.SMTPRecipientsRefused as e:
            raise NotifyError(_refused_text(e.recipients)) from e
        except smtplib.SMTPResponseException as e:
            raise NotifyError(f"smtp {s['host']}:{s['port']}: {e.smtp_code} "
                              f"{_decode(e.smtp_error)}") from e
        except (smtplib.SMTPException, OSError, ValueError) as e:
            raise NotifyError(f"smtp {s['host']}:{s['port']}: {e}") from e
        if refused:
            raise NotifyError(_refused_text(refused))


def _decode(value) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value)


def _refused_text(recipients: dict) -> str:
    parts = []
    for rcpt, (code, text) in recipients.items():
        kind = "temporary, retried next run" if 400 <= code < 500 else "permanent"
        parts.append(f"{rcpt}: {code} {_decode(text)} ({kind})")
    return "recipient refused: " + "; ".join(parts)
