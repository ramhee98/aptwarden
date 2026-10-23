# aptwarden

CVE monitoring and controlled patching for Debian hosts.

aptwarden runs on one central host and connects to your Debian servers over SSH. It
inventories their installed packages and matches them against the Debian Security
Tracker, OSV.dev and your own signed definitions, scores the findings with CVSS and
CISA KEV, and reports what can be fixed right now. No agent runs on the target hosts,
and reporting needs no root privileges there.

Where you allow it, aptwarden also patches, behind a staged safety net:

1. simulation
2. Proxmox snapshot
3. upgrade of exactly the affected packages
4. service restarts
5. healthchecks
6. automatic rollback on failure

> **Status:** All four phases are done:
>
> - reporting
> - e-mail notifications
> - signed custom definitions
> - patching with Proxmox snapshots and rollback
>
> Docker image scanning and a status web page are planned. See
> [docs/architecture.md](docs/architecture.md).

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
apt install python3 python3-venv python3-yaml python3-jsonschema python3-setuptools \
    python3-wheel openssh-client git

useradd --system --home-dir /var/lib/aptwarden --shell /usr/sbin/nologin aptwarden

python3 -m venv --system-site-packages /opt/aptwarden
# --no-build-isolation: build with Debian's setuptools, so PyPI is never contacted
/opt/aptwarden/bin/pip install --no-deps --no-build-isolation git+https://github.com/ramhee98/aptwarden
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

Regular runs use `strict_host_key_checking: yes`: an unknown or changed host key stops
the connection. To record the key of a new host once, use `--accept-new`. It applies
only to hosts not yet in `known_hosts`, and a changed key is still refused:

```sh
runuser -u aptwarden -- aptwarden hosts check --accept-new --host mail01
# mail01: new host key recorded: SHA256:Fmls... (ED25519)
```

Compare the printed fingerprint with the host's own fingerprint
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host). Alternatively,
pre-populate `/var/lib/aptwarden/known_hosts` with `ssh-keyscan` after checking the
fingerprints.

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

### Running commands

Run aptwarden as the service user: `runuser -u aptwarden -- aptwarden report`. As
root, aptwarden refuses commands that write to state or cache directories owned by
another user. Otherwise it would create root-owned files (e.g. the status page) that
the service and the publish unit can no longer read. Read-only commands such as
`config check` and `helper show` also work as root.

### Updating

```sh
/opt/aptwarden/bin/pip install --no-deps --no-build-isolation --force-reinstall \
    git+https://github.com/ramhee98/aptwarden
aptwarden version && aptwarden config check
runuser -u aptwarden -- aptwarden hosts check
```

Notes on updating:

- **`--force-reinstall` is required** while the version number does not change between
  commits; without it pip keeps the installed copy.
- **State and cache upgrade themselves:** `state.db` and `cache.db` migrate on first
  use. The cache may be rebuilt, which costs one feed download.
- **The systemd units are not part of the package.** If `contrib/systemd/` changed,
  copy the units again and run `systemctl daemon-reload`:

  ```sh
  base=https://raw.githubusercontent.com/ramhee98/aptwarden/main/contrib/systemd
  for u in aptwarden-report.service aptwarden-report.timer aptwarden-patch.service \
           aptwarden-patch.timer aptwarden-status-publish.path aptwarden-status-publish.service; do
      [ -e /etc/systemd/system/$u ] && curl -fsSo /etc/systemd/system/$u $base/$u
  done
  systemctl daemon-reload
  ```

- **The helper on patch targets is not updated automatically.** `hosts check` reports
  `helper NOT ready: outdated helper` when it is outdated; refresh it with
  `aptwarden helper show --install`, see
  [Target hosts: helper and sudo](#target-hosts-helper-and-sudo).

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

## Patching

Patching is opt-in per host. aptwarden only patches a host when all of these hold:

- its `policy.modes` contains `patch`,
- the run is inside one of its maintenance windows,
- it has healthchecks,
- it has a snapshot provider (or an explicit `allow_without_snapshot: true`).

### Flow

| Step | What happens | On failure |
|---|---|---|
| plan | Select fixable findings allowed by the policy (`auto_patch_severities`, `auto_patch_kev`, not restricted by a definition), refresh the package lists and resolve the apt candidates. Every installed binary of an affected source package is upgraded together. A candidate must reach the fixed *source* version and must not be blocked by a definition. | `nothing-to-do` |
| preflight | Helper reachable via sudo, snapshot feature available, healthchecks configured **and passing** | `aborted` |
| simulate | `apt-get -s` with exactly the planned `package=version`s. Any removal, new package or upgrade outside the plan stops the run (`allow_new_packages`, `allow_extra_upgrades`). | `aborted` |
| snapshot | Proxmox snapshot `aptw_<run-id>`, without RAM state by default | `aborted` |
| apply | Install exactly the simulated versions (non-interactive, keep old config files) and verify them with dpkg | rollback |
| restart | needrestart `auto` / `list` / `off`; reboot `never` / `if-required` | rollback |
| healthcheck | systemd units on the host; HTTP and TCP from the central host, with grace period and retries | rollback, or alert only with `rollback: manual` |

The result is one of these statuses:

| Status | Meaning | Alert |
|---|---|---|
| `patched` | upgraded and healthy | no (patch summary mail) |
| `rolled-back` | failed, rolled back to the snapshot | **yes** |
| `needs-manual-rollback` | failed, `rollback: manual`; run `aptwarden rollback --host …` | **yes** |
| `failed` | failed without a snapshot to roll back to | **yes** |
| `rollback-failed` | the rollback itself failed | **yes** |
| `aborted` | stopped before any change | mail only if the reason is new |
| `nothing-to-do`, `skipped`, `dry-run` | nothing changed | no |

A rollback discards everything written after the snapshot, e.g. received mail or
database writes. The window is minutes, but for mail and database hosts consider
`rollback: manual`.

### Target hosts: helper and sudo

A sudoers rule on `apt-get` itself would be root for anyone who can pass options. Target
hosts therefore get a small root-owned helper. It has fixed subcommands, validates every
`package=version` and only upgrades installed packages. sudo allows this one script and
nothing else:

`aptwarden helper show --install` prints a self-contained script that installs everything
in one step. Run it as root on the target. The script:

- installs sudo if it is missing,
- writes helper and sudoers rule with the right owner and mode, and removes misnamed
  rule files (sudo silently ignores files with a dot in their name),
- validates the rule with `visudo` and checks the helper as user `aptwarden`.

It is idempotent, so you can run it again after an update to refresh the helper.

```sh
# via SSH as root
aptwarden helper show --install | ssh root@TARGET sh
# or for a Proxmox container without root SSH, through the node
aptwarden helper show --install | ssh root@PVE-NODE pct exec VMID -- sh
```

The user `aptwarden` with the central host's key must exist first (see
[Target hosts](#target-hosts)). Check from the central host afterwards:

```sh
runuser -u aptwarden -- aptwarden hosts check --host TARGET      # expect "helper ok"
```

Install `needrestart` on the target if services should be restarted after library
updates.

### Proxmox API token

Use a dedicated user and a pool containing only the guests aptwarden may snapshot. The
token can do nothing else, so a test token can never touch production guests:

```sh
pveum role add AptwardenPatch --privs "VM.Audit,VM.Snapshot,VM.Snapshot.Rollback,VM.PowerMgmt"
pveum pool add aptwarden-prod
pveum pool modify aptwarden-prod --vms 101,102
pveum user add aptwarden@pve --comment "aptwarden patch automation"   # @pve: no shell login
pveum user token add aptwarden@pve central --privsep 1
# privilege separation: the token gets the intersection, so grant both
pveum acl modify /pool/aptwarden-prod --users aptwarden@pve --roles AptwardenPatch
pveum acl modify /pool/aptwarden-prod --tokens 'aptwarden@pve!central' --roles AptwardenPatch
```

Store the secret (the `value` printed once) on the central host only:

```sh
install -d -m 750 -o root -g aptwarden /etc/aptwarden/credentials
( umask 077; nano /etc/aptwarden/credentials/proxmox-token )
chown aptwarden: /etc/aptwarden/credentials/proxmox-token
```

Get the API certificate fingerprint from *Node → System → Certificates*, or with
`openssl s_client -connect PVE:8006 </dev/null | openssl x509 -noout -fingerprint -sha256`.
Pin it after comparing it with the GUI.

### Configuration

```yaml
proxmox:
  url: https://192.0.2.9:8006
  node: pve1
  token_id: aptwarden@pve!central
  token_file: credentials/proxmox-token        # relative to /etc/aptwarden
  tls_fingerprint: "39:B8:6C:...:08:66"        # or ca_file for a CA-signed certificate

snapshots:
  keep: 7d                                     # aptwarden's own snapshots are deleted after this

policy:                                        # defaults for every host
  modes: [report]                              # add dry-run and/or patch per host
  auto_patch_severities: [critical, high]
  auto_patch_kev: true                         # KEV-listed: patch whatever the severity
  restart: auto                                # needrestart: auto | list | off
  reboot: never                                # never | if-required
  rollback: auto                               # auto | manual

hosts:
  - name: proxy01
    address: 192.0.2.10
    snapshot: {provider: proxmox, vmid: 101, type: lxc}   # type: lxc | qemu
    policy:
      modes: [report, dry-run, patch]
      window: ["Mon..Fri 02:00-04:00", "Sat 03:00-05:00"]  # local time of the central host
    healthchecks:
      - systemd: nginx.service
      - http: https://proxy01.example.org/healthz
        expect_status: 200
      - tcp: 192.0.2.10:443
  - name: mail01
    address: 192.0.2.25
    snapshot: {provider: proxmox, vmid: 102, type: lxc}
    policy: {modes: [report, patch], rollback: manual, window: ["Sun 04:00-05:00"]}
    healthchecks: [{systemd: postfix@-.service}, {tcp: "192.0.2.25:25"}]
```

### Commands

```sh
aptwarden patch --dry-run [--host H]   # plan + simulation, changes nothing (ignores windows)
aptwarden patch [--host H]             # the real thing, inside the maintenance windows
aptwarden patch --ignore-window        # ... outside them, deliberately
aptwarden patches [--host H]           # patch history
aptwarden rollback --host H            # roll back to the newest aptwarden snapshot (asks first)
aptwarden snapshots list               # snapshots aptwarden created
aptwarden snapshots cleanup [--dry-run]
aptwarden hosts check                  # also checks helper/sudo, snapshots, healthchecks
```

The patch timer runs hourly. Each host is only patched inside its window:

```sh
cp contrib/systemd/aptwarden-patch.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now aptwarden-patch.timer
```

Mails from patch runs:

- a patch summary when something was patched, or when a run aborted for a new reason
- an immediate alert for anything that needs a human

Quiet hours cause no mail.

## Status page

After every `report` and `patch` run, aptwarden writes a static, read-only HTML page:
`/var/lib/aptwarden/www/index.html` by default. It contains:

- totals and a table of all hosts (fixable, critical, high, KEV, last scan, last
  patch)
- per host: the fixable packages, every vulnerability (collapsible), the patch history
  and aptwarden's snapshots
- the state of the data sources and definitions, including rejected releases

The page is always rendered from the stored state of every configured host, so a patch
run of one host does not hide the others. It has no JavaScript and no forms. A
Content-Security-Policy forbids scripts and external resources, and all external text
(CVE descriptions etc.) is escaped. aptwarden itself runs no web server.

To publish the page, use your existing web server, LAN-only and with a password: the
page lists your hosts' open vulnerabilities. [contrib/publish/](contrib/publish/README.md)
contains a complete setup:

- **Push on change:** a systemd path unit on the central host pushes the page whenever
  it changes, over SSH with a dedicated key.
- **Restricted key:** on the web server, `rrsync -wo` limits the key to writing into
  one directory. The web server gets no access to the central host.
- **nginx location:** `satisfy all` with an IP allowlist, Basic Auth and the same CSP
  as the page.

```yaml
status_page:
  enabled: true          # default
  path: null             # default: <state_dir>/www/index.html
  mode: "0640"           # e.g. "0644" if another local user serves it
```

`aptwarden status --format html` prints the page to stdout.

## Usage

```
aptwarden report                       inventory, match, store and print a report
aptwarden report --host web01 --cves   one host, every vulnerability per package
aptwarden report --all                 include vulnerabilities without an available fix
aptwarden report --format json         complete machine-readable result
aptwarden report --offline             no network for vulnerability data, cache only
aptwarden status                       latest stored results, no scanning
aptwarden status --format html         the status page on stdout
aptwarden hosts check [--accept-new]   connectivity and inventory test
aptwarden sources refresh [--force]    update the cached feeds
aptwarden config check [--dump]        validate (and print) the configuration
aptwarden notify test                  send a test notification
aptwarden defs sync | list | validate  custom definitions
aptwarden patch [--dry-run]            patch (see Patching)
aptwarden rollback --host H            roll back to aptwarden's snapshot
aptwarden snapshots list | cleanup     aptwarden's snapshots
aptwarden patches                      patch history
aptwarden helper show [--install]      the root helper (or its installer) for targets
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
| `/var/lib/aptwarden/www/index.html` | static status page |
| `/var/cache/aptwarden/cache.db` | feed cache, about 100 MB, safe to delete |
| `/var/cache/aptwarden/definitions.git` | mirror of the definitions repository |
| `/etc/aptwarden/credentials/` | secrets (Proxmox token, NVD key, SMTP password) |

## Known limitations

- **Matching is per source package, like debsecan.** When a vulnerability affects only
  one binary of a source package (e.g. `inetutils-telnetd`), every installed binary of
  that source is reported.
- **Fix availability comes from the Debian repositories,** not from the host's apt
  configuration. A host without `*-security` in its sources cannot install a fix marked
  `fixable`.
- **No CVSS v4 calculation yet:** v4-only CVEs need NVD for a score.
- **Docker images are not scanned yet** (planned as a Trivy plugin).
- **PVE nodes are report-only by design:** Proxmox requires `apt full-upgrade`, and
  a node cannot snapshot itself.
- **`enforce_block: pin` is not implemented yet:** blocked versions are never installed
  by aptwarden, but manual `apt` runs are not prevented.

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
  production.
  - **Inventory over SSH:**

    ```sh
    APTWARDEN_IT_HOSTS="aptwarden@192.0.2.21,aptwarden@192.0.2.22" \
    APTWARDEN_IT_NETWORK=1 \
        .venv/bin/pytest -m integration tests/integration/test_live_hosts.py
    ```

  - **Live patching** against Proxmox test guests: snapshot roundtrip, dry run, a real
    patch with an injected healthcheck failure and the automatic rollback. Run it
    where the config and the token are readable, e.g. on a test central host as the
    aptwarden user. A guest is only used if its VMID is listed and Proxmox reports
    its hostname as the configured host name:

    ```sh
    APTWARDEN_IT_CONFIG=/etc/aptwarden/config.yaml APTWARDEN_IT_VMIDS=139,140 \
        python3 -m pytest -m integration -o addopts= tests/integration/test_patch_live.py
    ```

CI runs the unit tests on Python 3.11 to 3.13, and in `debian:12` and `debian:13`
containers with Debian's packages only.

## License

MIT, see [LICENSE](LICENSE).
