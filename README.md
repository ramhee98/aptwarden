# aptwarden

CVE monitoring and, in a later phase, controlled patching for Debian hosts.

aptwarden runs on one central host and connects to your Debian servers over SSH. It
inventories their installed packages and matches them against the Debian Security
Tracker and OSV.dev. It scores the findings with CVSS and CISA KEV and reports what can
be fixed right now. No agent runs on the target hosts, and reporting needs no root
privileges there.

> **Status:** Phases 1 to 3 are done: inventory, vulnerability matching, report,
> status, e-mail notifications and custom definitions from a signed Git repository.
> Next comes patching behind a staged safety net (simulation, Proxmox snapshot,
> healthcheck, rollback). See [docs/architecture.md](docs/architecture.md).

## How it works

```
aptwarden report
  ├─ refresh feeds   Debian tracker JSON (conditional GET), CISA KEV → cache.db
  ├─ per host        ssh → dpkg-query, os-release → match → CVSS/KEV → state.db
  └─ output          text or JSON report
```

- **Matching uses source packages and source versions.** That is how Debian tracks
  security fixes. `bsdutils 1:2.41-5`, for example, is built from `util-linux 2.41-5`.
- **Version comparison** is a pure Python port of dpkg's algorithm. It is tested against
  4000+ cases generated with `dpkg --compare-versions`.
- **Each finding gets one status:**
  - `fixable`: the fix is in the release's repositories
  - `fix-pending`: fixed in Debian but not published yet, e.g. it waits for the next
    point release
  - `no-fix`: open in this release
  - `undetermined`: Debian has not decided yet
- **Severity:** Debian `unimportant` wins first, then the CVSS base score, then Debian's
  urgency. CVSS vectors come from OSV, and NVD is the rate-limited fallback.
- **CISA KEV:** CVEs in the KEV catalog are flagged and always shown.

## Requirements

- Central host: Debian 12 or 13 (a small LXC is enough, 1 GB RAM recommended) with
  Python 3.11+, OpenSSH client and outbound HTTPS to `security-tracker.debian.org`,
  `api.osv.dev`, `services.nvd.nist.gov` and `www.cisa.gov`.
- Target hosts: Debian (or Debian based with `VERSION_CODENAME`) reachable over SSH.

The runtime dependencies are PyYAML and jsonschema. Both come from Debian packages,
PyPI is not needed.

## Setup

### Central host

```sh
apt install python3 python3-venv python3-yaml python3-jsonschema openssh-client git

useradd --system --home-dir /var/lib/aptwarden --shell /usr/sbin/nologin aptwarden

python3 -m venv --system-site-packages /opt/aptwarden
/opt/aptwarden/bin/pip install --no-deps git+https://github.com/ramhee98/aptwarden
# or from a wheel built with `pip wheel --no-deps -w dist .`
ln -s /opt/aptwarden/bin/aptwarden /usr/local/bin/aptwarden

install -d -m 755 /etc/aptwarden
install -d -m 700 -o aptwarden -g aptwarden /etc/aptwarden/ssh /var/lib/aptwarden \
    /var/cache/aptwarden
runuser -u aptwarden -- ssh-keygen -t ed25519 -N '' -C "aptwarden@$(hostname)" \
    -f /etc/aptwarden/ssh/id_ed25519

cp contrib/config.example.yaml /etc/aptwarden/config.yaml   # then edit hosts
```

### Target hosts

Reporting only reads the dpkg database, so the SSH user needs no sudo rights. Restrict
the key to the central host's address:

```sh
useradd --system --create-home --shell /bin/sh aptwarden
install -d -m 700 -o aptwarden -g aptwarden ~aptwarden/.ssh
echo 'restrict,from="192.0.2.5" ssh-ed25519 AAAA... aptwarden@central' \
    > ~aptwarden/.ssh/authorized_keys
chown aptwarden: ~aptwarden/.ssh/authorized_keys
chmod 600 ~aptwarden/.ssh/authorized_keys
```

### Host keys

Before the first run, check the hosts' key fingerprints. There are two ways to fill
`known_hosts`:

- Pre-populate `/var/lib/aptwarden/known_hosts` (for example with `ssh-keyscan`, after
  checking the fingerprints).
- Run the first `hosts check` with `strict_host_key_checking: accept-new`, then switch
  back to `yes`.

```sh
runuser -u aptwarden -- aptwarden hosts check
```

### Timer

```sh
cp contrib/systemd/aptwarden-report.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now aptwarden-report.timer
journalctl -u aptwarden-report.service      # report plus JSON log lines
```

- **Exit code:** the service exits with 1 when a host or feed failed, so failures show
  up in `systemctl --failed`.
- **Sandboxing:** the unit's hardening options were tested in an unprivileged Proxmox LXC
  without nesting.

## Configuration

[contrib/config.example.yaml](contrib/config.example.yaml) lists every option with its
default. A minimal configuration:

```yaml
ssh:
  identity_file: /etc/aptwarden/ssh/id_ed25519
  known_hosts_file: /var/lib/aptwarden/known_hosts
hosts:
  - name: proxy01
    address: 192.0.2.10
  - name: mail01
    address: mail01.example.org
    ssh: {port: 2222}
```

- **Validation:** the configuration is checked against a JSON schema. Unknown keys and
  typos are errors.
- **Config path:** `-c` or `$APTWARDEN_CONFIG` overrides the default
  `/etc/aptwarden/config.yaml`.
- **Secrets** are always referenced as files (`*_file`), never inline. A relative path is
  first looked up in systemd's `$CREDENTIALS_DIRECTORY` (`LoadCredential=`).

### Custom definitions

Your own vulnerability definitions come from a Git repository, by default
[aptwarden-definitions](https://github.com/ramhee98/aptwarden-definitions). There
you'll find the format, the actions (`report`, `auto-patch`, `block`) and the release
process. aptwarden activates only signed release tags that descend from the last
accepted one:

```sh
# trust the maintainer key(s); format: <principal> <key>
echo "32970397+ramhee98@users.noreply.github.com ssh-ed25519 AAAA..." \
    > /etc/aptwarden/allowed_signers
```

```yaml
sources:
  custom:
    enabled: true
    url: https://github.com/ramhee98/aptwarden-definitions.git
    allowed_signers_file: /etc/aptwarden/allowed_signers
```

```sh
aptwarden defs sync          # fetch, verify and activate now (otherwise once per refresh_interval)
aptwarden defs list          # the active definitions
aptwarden defs validate DIR  # check a definitions directory, no config needed (CI)
```

- **Precedence:** a definition wins over the Debian tracker and OSV for the CVEs it
  lists, including "not affected".
- **`block`:** an installed blocked version always raises an alert.
- **Rejected releases:** a rejected tag (unsigned, foreign key, rollback, invalid
  content) raises one alert, and the previous release stays active.

### NVD API key

CVSS vectors come from OSV. For CVEs that OSV only has with a CVSS v4 vector, or not at
all, aptwarden falls back to NVD, which allows 5 requests per 30 seconds without a key.
Lookups that don't fit into the per-run budget continue on the next run. A free API key
(<https://nvd.nist.gov/developers/request-an-api-key>) raises the rate tenfold:

```yaml
enrich:
  cvss:
    nvd:
      api_key_file: nvd-api-key   # with LoadCredential=nvd-api-key:/etc/aptwarden/credentials/nvd-api-key
```

### Notifications

Each run sends a summary. The summary lists new and resolved vulnerabilities since the
last scan, followed by the full report. An immediate alert goes out for:

- new findings at or above `notify.alert.min_severity` (default `critical`)
- findings listed in CISA KEV, whatever their severity
- hosts that start failing
- runs without any vulnerability data

Each host and vulnerability is alerted once, with a reminder after `remind_after`. A
failed delivery is retried on the next run and marks the run as `partial`.

```yaml
notify:
  email:
    enabled: true
    host: 192.0.2.25
    port: 25
    security: starttls
    tls_server_name: mx.example.org   # the relay's certificate name when `host` is an IP
    from: aptwarden@example.org
    to: [admin@example.org]
```

```sh
aptwarden notify test                # send a test message
aptwarden report --no-notify         # interactive run without mails
```

If the relay greylists (Proxmox Mail Gateway does by default), whitelist the central
host's address. Otherwise every alert is delayed and the first attempt fails.

## Usage

```
aptwarden report                       inventory, match, store and print a report
aptwarden report --host web01 --cves   one host, every vulnerability per package
aptwarden report --all                 include vulnerabilities without an available fix
aptwarden report --format json         complete machine-readable result
aptwarden report --offline             no network for vulnerability data, cache only
aptwarden status                       latest stored results, no scanning
aptwarden hosts check                  connectivity and inventory test
aptwarden sources refresh [--force]    update the cached feeds
aptwarden config check [--dump]        validate (and print) the configuration
aptwarden notify test                  send a test notification
aptwarden defs sync | list | validate  custom definitions
```

Example (shortened):

```
web01  192.0.2.10  Debian 13.1 (trixie)  249 packages  scanned 2026-10-22T13:18:35+00:00
  fixable now: 258 vulnerabilities in 28 packages  [critical 10 · high 81 · medium 75 · low 22 · unknown 70]  KEV 1
  not fixable: fix pending 0 · no fix 236 · undetermined 1

  SEVERITY  PACKAGE     INSTALLED        FIXED                VULNS  TOP
  critical  inetutils   2:2.6-3          2:2.6-3+deb13u3      4      CVE-2026-24061 9.8 KEV
  critical  openssl     3.5.1-1+deb13u1  3.5.7-1~deb13u3      57     CVE-2026-63073 9.8
  high      openssh     1:10.0p1-7       1:10.0p1-7+deb13u3   8      CVE-2026-35385 7.5
  … 14 more fixable packages below high (--min-severity low to show)
```

- **FIXED** is the version that fixes every listed vulnerability of the package.
- **Hidden rows:** the text report hides fixable packages below `report.min_severity`.
  Packages with a KEV entry or without any score are always shown.
- **JSON** output (`--format json`) always contains everything.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | a host or a data source failed |
| 2 | configuration or usage error |

## Files

| Path | Content |
|---|---|
| `/etc/aptwarden/config.yaml` | configuration |
| `/var/lib/aptwarden/state.db` | run history, findings, first/last seen |
| `/var/cache/aptwarden/cache.db` | feed cache, about 100 MB, safe to delete |

## Known limitations

- **Matching is per source package, like debsecan.** When a vulnerability affects only
  one binary of a source package (e.g. `inetutils-telnetd`), every installed binary of
  that source is reported.
- **Fix availability comes from the Debian repositories,** not from the host's apt
  configuration. A host without `*-security` in its sources cannot install a fix marked
  `fixable`.
- **No CVSS v4 calculation yet:** v4-only CVEs need NVD for a score.
- **Docker images are not scanned yet** (planned as a Trivy plugin).

## Development

```sh
python3 -m venv --system-site-packages .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest                 # unit tests, offline, fixtures only
.venv/bin/ruff check src tests tools
```

- **Fixtures** in `tests/fixtures` are real data: `dpkg-query` output of a Debian 13.1
  container, a trimmed tracker snapshot, and OSV and NVD responses.
  `tools/gen_debversion_cases.py` regenerates the version comparison table with dpkg as
  the oracle.
- **Integration tests** run against disposable hosts only. Never point them at
  production:

```sh
APTWARDEN_IT_HOSTS="aptwarden@192.0.2.21,aptwarden@192.0.2.22" \
APTWARDEN_IT_NETWORK=1 \
    .venv/bin/pytest -m integration tests/integration
```

CI runs the unit tests on Python 3.11 to 3.13, and in `debian:12` and `debian:13`
containers with Debian's packages only.

## License

MIT, see [LICENSE](LICENSE).
