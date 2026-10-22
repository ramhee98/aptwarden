"""Proxmox VE API client (token auth) and snapshot provider.

The token needs VM.Audit, VM.Snapshot, VM.Snapshot.Rollback and VM.PowerMgmt
on the guests (e.g. through a pool), nothing else. The API certificate is
either verified against a CA file or system CAs, or pinned by its SHA-256
fingerprint (the usual case for the self-signed default certificate).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import ssl
import time
import urllib.parse
from pathlib import Path

from aptwarden.config import read_secret
from aptwarden.snapshot import PREFIX, SnapshotError, SnapshotProvider, SnapshotRef

log = logging.getLogger(__name__)


def normalize_fingerprint(fp: str) -> str:
    return fp.replace(":", "").strip().lower()


class ProxmoxClient:
    def __init__(self, settings: dict, base_dir: Path | None = None):
        self.settings = settings
        url = urllib.parse.urlsplit(settings["url"])
        if url.scheme != "https":
            raise SnapshotError("proxmox.url must be https")
        self.host, self.port = url.hostname, url.port or 8006
        self.timeout = settings.get("timeout", 30)
        self.token = f"{settings['token_id']}={read_secret(settings['token_file'], base_dir)}"
        self.fingerprint = normalize_fingerprint(settings.get("tls_fingerprint") or "")
        if self.fingerprint:
            self.context = ssl.create_default_context()
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE  # replaced by the pin check below
        else:
            self.context = ssl.create_default_context(cafile=settings.get("ca_file") or None)

    def _connect(self) -> http.client.HTTPSConnection:
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.context,
                                           timeout=self.timeout)
        try:
            conn.connect()
        except (OSError, ssl.SSLError) as e:
            raise SnapshotError(f"proxmox {self.host}:{self.port}: {e}") from e
        if self.fingerprint:
            der = conn.sock.getpeercert(binary_form=True)
            if hashlib.sha256(der).hexdigest() != self.fingerprint:
                conn.close()
                raise SnapshotError(f"proxmox {self.host}: certificate fingerprint mismatch")
        return conn

    def request(self, method: str, path: str, params: dict | None = None):
        conn = self._connect()
        headers = {"Authorization": f"PVEAPIToken={self.token}"}
        body = None
        if params and method in ("POST", "PUT"):
            body = urllib.parse.urlencode(params)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif params:
            path += "?" + urllib.parse.urlencode(params)
        try:
            conn.request(method, "/api2/json" + path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
        except (OSError, http.client.HTTPException) as e:
            raise SnapshotError(f"proxmox {method} {path}: {e}") from e
        finally:
            conn.close()
        if resp.status != 200:
            raise SnapshotError(f"proxmox {method} {path}: HTTP {resp.status} {resp.reason}")
        return json.loads(raw or b"{}").get("data")

    def wait_task(self, node: str, upid: str, timeout: float | None = None) -> None:
        deadline = time.monotonic() + (timeout or self.settings.get("task_timeout", 600))
        path = f"/nodes/{node}/tasks/{urllib.parse.quote(upid, safe='')}/status"
        while True:
            status = self.request("GET", path)
            if status.get("status") == "stopped":
                if status.get("exitstatus") != "OK":
                    raise SnapshotError(f"proxmox task {upid} failed: {status.get('exitstatus')}")
                return
            if time.monotonic() > deadline:
                raise SnapshotError(f"proxmox task {upid} did not finish in time")
            time.sleep(1)


class ProxmoxSnapshots(SnapshotProvider):
    name = "proxmox"

    def __init__(self, client: ProxmoxClient, node: str, guest_type: str, vmid: int,
                 vmstate: bool = False):
        if guest_type not in ("lxc", "qemu"):
            raise SnapshotError(f"invalid guest type {guest_type!r}")
        self.client = client
        self.node = node
        self.type = guest_type
        self.vmid = vmid
        self.vmstate = vmstate and guest_type == "qemu"
        self.base = f"/nodes/{node}/{guest_type}/{vmid}"

    @property
    def target(self) -> str:
        return f"{self.node}/{self.type}/{self.vmid}"

    def guest_config(self) -> dict:
        return self.client.request("GET", self.base + "/config") or {}

    def check(self) -> list[str]:
        try:
            feature = self.client.request("GET", self.base + "/feature",
                                          {"feature": "snapshot"}) or {}
        except SnapshotError as e:
            return [str(e)]
        if not feature.get("hasFeature"):
            return [f"{self.target}: snapshots not supported (storage of a disk or mount point "
                    f"has no snapshot support)"]
        return []

    def create(self, name: str, description: str) -> SnapshotRef:
        params = {"snapname": name, "description": description}
        if self.type == "qemu":
            params["vmstate"] = int(self.vmstate)
        upid = self.client.request("POST", self.base + "/snapshot", params)
        self.client.wait_task(self.node, upid)
        log.info("snapshot created", extra={"target": self.target, "snapshot": name})
        return SnapshotRef(self.name, self.target, name)

    def rollback(self, ref: SnapshotRef) -> None:
        self._own(ref)
        upid = self.client.request("POST", f"{self.base}/snapshot/{ref.name}/rollback",
                                   {"start": 1})
        self.client.wait_task(self.node, upid)
        log.warning("snapshot rolled back", extra={"target": self.target, "snapshot": ref.name})

    def delete(self, ref: SnapshotRef) -> None:
        self._own(ref)
        upid = self.client.request("DELETE", f"{self.base}/snapshot/{ref.name}")
        self.client.wait_task(self.node, upid)
        log.info("snapshot deleted", extra={"target": self.target, "snapshot": ref.name})

    def list(self) -> list[str]:
        snaps = self.client.request("GET", self.base + "/snapshot") or []
        return [s["name"] for s in snaps if s.get("name") != "current"]

    def _own(self, ref: SnapshotRef) -> None:
        if ref.target != self.target or not ref.name.startswith(PREFIX):
            raise SnapshotError(f"refusing to touch snapshot {ref.name} on {ref.target}")
