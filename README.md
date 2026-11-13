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

> **Status:** Done:
>
> - reporting
> - e-mail notifications
> - signed custom definitions
> - patching with Proxmox snapshots and rollback
> - a static status page
>
> Docker image scanning is planned. See [docs/architecture.md](docs/architecture.md).

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

- **Central host:** Debian 12 or 13 (a small LXC is enough, 1 GB RAM recommended) with
  Python 3.11+ and the OpenSSH client. It needs outbound HTTPS to
  `security-tracker.debian.org`, `api.osv.dev`, `services.nvd.nist.gov`, `www.cisa.gov`
  and `github.com` (custom definitions, installation, updates). It also needs SSH to
  every target and, for patching, the Proxmox API (port 8006).
- **Target hosts:** Debian (or Debian based with `VERSION_CODENAME`) reachable over SSH.
  HTTP and TCP healthchecks run from the central host unless `on_host` is set, see
  [Healthchecks](#healthchecks-from-the-central-host-or-on-the-host).

The runtime dependencies are PyYAML and jsonschema. Both come from Debian packages,
PyPI is not needed.

## Setup

### Central host

```sh
apt install python3 python3-venv python3-yaml python3-jsonschema python3-setuptools \
    python3-wheel openssh-client git

useradd --system --home-dir /var/lib/aptwarden --shell /usr/sbin/nologin aptwarden

python3 -m venv --system-site-packages /opt/aptwarden
# a release tag, not the latest commit of main (see "Installing a verified release")
# --no-build-isolation: build with Debian's setuptools, so PyPI is never contacted
/opt/aptwarden/bin/pip install --no-deps --no-build-isolation \
    git+https://github.com/ramhee98/aptwarden@v0.7.0
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

Reporting only reads the dpkg database, so the SSH user needs no sudo rights. Hosts
that should also be patched additionally get a small helper and a sudo rule, see
[Target hosts: helper and sudo](#target-hosts-helper-and-sudo). Restrict the key to the
central host's address:

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
/opt/aptwarden/bin/pip install --no-deps --no-build-isolation \
    git+https://github.com/ramhee98/aptwarden@v0.7.0
aptwarden version && aptwarden config check
runuser -u aptwarden -- aptwarden hosts check
```

Notes on updating:

- **Install release tags,** not `main`: a tag names one reviewed state, `main` is
  whatever was pushed last. Testing an unreleased commit needs `--force-reinstall` while
  the version number stays the same; without it pip keeps the installed copy.
- **Installing a verified release:** pip does not check signatures. When releases are
  tagged with `git tag -s` (see [Development](#development)), check the tag before
  installing from the checked-out tree:

  ```sh
  git clone --quiet https://github.com/ramhee98/aptwarden /root/aptwarden-src
  git -C /root/aptwarden-src -c gpg.format=ssh \
      -c gpg.ssh.allowedSignersFile=/etc/aptwarden/release_signers \
      -c gpg.openpgp.program=false -c gpg.x509.program=false verify-tag v0.7.0
  git -C /root/aptwarden-src checkout --quiet v0.7.0
  /opt/aptwarden/bin/pip install --no-deps --no-build-isolation /root/aptwarden-src
  ```

  `release_signers` lists the release key in `allowed_signers` format, like the
  definitions signers file. git verifies a tag in the format of its signature, whatever
  `gpg.format` says, so the two `program=false` options make sure an OpenPGP or X.509
  signed tag fails instead of being checked against root's own keyring.
- **`aptwarden version`** shows the installed version; the status page and
  `status.json` show it too.
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

```sh
( umask 077; nano /etc/aptwarden/credentials/nvd-api-key )      # paste the key
chown aptwarden: /etc/aptwarden/credentials/nvd-api-key
```

```yaml
enrich:
  cvss:
    nvd:
      api_key_file: credentials/nvd-api-key    # relative to /etc/aptwarden
```

This works for timer runs and for manual `runuser` runs alike. With systemd's
`LoadCredential=` instead, the file may stay root-owned, but then it is only readable
inside the service, not for manual runs. The log line `cvss lookup` shows progress:
`nvd_waiting` drops by about 80 per run with a key, about 9 without.

### Notifications

Each run sends a summary. The summary lists new and resolved vulnerabilities since the
last scan, followed by the full report. An immediate alert goes out for:

- new findings at or above `notify.alert.min_severity` (default `critical`)
- findings listed in CISA KEV, whatever their severity
- hosts that start failing
- runs without any vulnerability data

Each host and vulnerability is alerted once, with a reminder after `remind_after`. A
failed delivery is retried on the next run and marks the run as `partial`.

Patch results go into the next summary by default, so hosts patched in different
windows overnight cause one mail in the morning, not one per window (see
`notify.patch_summary` under [Patching](#patching)).

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

Patching is opt-in per host. Every configured host is always included in reports;
`policy.modes` only decides whether `dry-run` and `patch` are allowed (`patch` implies
`dry-run`). aptwarden only patches a host when all of these hold:

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
| apply | Install exactly the simulated versions (non-interactive, keep old config files) and verify them with dpkg. The helper simulates again right before and refuses to install anything it was not given as `package=version`, or to remove anything. Extras allowed by the policy are passed explicitly. | rollback |
| restart | needrestart `auto` / `list` / `off`; reboot `never` / `if-required` | rollback |
| healthcheck | systemd units on the host; HTTP and TCP from the central host or, with `on_host`, on the host itself; with grace period and retries | rollback, or alert only with `rollback: manual` |

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
hosts therefore get a small root-owned helper. It has fixed subcommands and validates every
`package=version`. Before it installs, it simulates the transaction itself and refuses it
if apt would install anything not named with exactly that version, or remove anything.
sudo allows this one script and nothing else:

`aptwarden helper show --install` prints a self-contained script that installs everything
in one step. Run it as root on the target. The script:

- installs sudo if it is missing (and needrestart with `--with-needrestart`),
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

With `policy.restart: auto` (the default), install `needrestart` too, so that services
using an updated library are restarted. Without it, a patched host keeps running the
old code until the next restart. `--with-needrestart` makes the installer take care of
it:

```sh
aptwarden helper show --install --with-needrestart | ssh root@TARGET sh
aptwarden helper show --install --with-needrestart | ssh root@PVE-NODE pct exec VMID -- sh
```

If installing a package fails, for example because of stale package lists, the
installer runs `apt-get update` once and retries. This applies to sudo and needrestart.

needrestart needs no configuration. During a patch, aptwarden suppresses its apt hook
and runs it explicitly according to `policy.restart`. For your own `apt` runs it keeps
asking interactively as usual. `hosts check` shows `needrestart installed` once it is
there.

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

`token_id` in the configuration must match exactly, including the realm:
`aptwarden@pve!central` and `aptwarden@pam!central` are different tokens, and a
mismatch shows up as HTTP 401. Store the secret (the `value` printed once) on the
central host only:

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
      window: ["Mon..Fri 02:00-04:00", "Sat 03:00-05:00"]
      timezone: Europe/Zurich                              # default: the central host's local time
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
aptwarden patch --host H --min-severity medium   # this run only: also patch medium (or low)
aptwarden patch --host H --all-severities        # this run only: every fixable finding
aptwarden patches [--host H]           # patch history
aptwarden rollback --host H            # roll back to the newest aptwarden snapshot (asks first)
aptwarden snapshots list               # snapshots aptwarden created
aptwarden snapshots cleanup [--dry-run]
aptwarden hosts check                  # also checks helper/sudo, snapshots, healthchecks
```

`--min-severity` and `--all-severities` override `policy.auto_patch_severities` for one
manual run, e.g. to clean up a host completely. Everything else still applies: `modes`
must contain `patch`, and the window (unless `--ignore-window`), snapshot, simulation,
healthchecks, rollback policy and restrictions by definitions are unchanged. The run
and its patch history are marked with the override; the timer never uses these options.

`nothing-to-do` names the reason. For example, `25 fixable, none allowed by policy
(auto-patch: critical, high + KEV): 19 medium, 5 low, 1 unknown` means the fixable
findings are below the policy's threshold.

### Healthchecks from the central host or on the host

`http` and `tcp` checks run from the central host by default, so they see the service
the way clients do. With `on_host: true` they run on the target itself, over the
existing SSH connection, as the unprivileged `aptwarden` user and not through the root
helper. Then the central host needs nothing but SSH to the target, and no firewall
openings for the checked ports.

```yaml
healthchecks:
  - http: https://blog.example.org/
    on_host: true          # curl on the host, connected to 127.0.0.1
    contains: "</html>"
  - tcp: 127.0.0.1:53
    on_host: true
```

- **Host name, virtual host and TLS are kept.** An on-host HTTP check connects to
  `127.0.0.1` but keeps the URL's host name (`curl --resolve`), so virtual hosts, SNI and
  certificate checks behave as from outside.
- **curl is needed on the target** for HTTP checks; `hosts check` reports when it is
  missing. TCP checks only need bash.
- **The service sees `127.0.0.1` as the client.** IP allowlists, rate limits or fail2ban
  may answer differently than for real clients (e.g. 403 instead of 401). Adjust
  `expect_status` accordingly.
- **Weaker for network problems:** an on-host check does not notice a firewall or routing
  problem between clients and the host. For the question "did the update break the
  service?" it covers the same ground.

### Checking a site through an internal address (`connect_to`)

When a site's name resolves to a public IP the central host cannot reach (NAT, split
DNS), point the check at the internal address, typically the reverse proxy:

```yaml
healthchecks:
  - http: https://blog.example.org/healthz
    connect_to: 192.0.2.11          # also ip:port or [ipv6]:port
```

- **What changes:** only where the TCP connection goes. SNI, the `Host` header and the
  certificate check still use the name from the URL.
- **Only the original host is redirected.** A redirect to another host is resolved
  normally.
- **Default for several checks:** set `health.connect_to` globally or per host. A
  `connect_to` on the check wins.
- **With `on_host: true`:** `connect_to` replaces `127.0.0.1` (via
  `curl --connect-to`), but only when it is set on the check itself. The default from
  `health` never applies to on-host checks.
- **Shown in check names**, e.g. `http https://blog.example.org/healthz (via 192.0.2.11)`.

### Redirects and allowed networks

Checks come from the configuration, so their targets are trusted like the rest of it.
The checked service is not: a compromised web server could redirect the central host's
check to internal services (the Proxmox API, services on the central host itself).

```yaml
health:
  redirects: same-host          # default; any | none, also per check
  allowed_networks: [192.0.2.0/24, 2001:db8:10::/48]   # default []: no restriction
```

- **`redirects`:**
  - `same-host` follows only redirects to the URL's own host, e.g. `http://` to
    `https://`.
  - `any` follows every redirect.
  - `none` follows none.

  Only `http` and `https` are followed, at most 5 times. A redirect that is not followed
  is judged as the 3xx response it is: with `expect_status: 302` the check passes,
  otherwise it fails with `redirect to … not followed`. On-host checks follow the same
  rules.
- **`allowed_networks`:** checks from the central host connect only to addresses in
  these networks.
  - **Applies to:** HTTP and TCP checks, `connect_to` and every redirect.
  - **DNS rebinding:** a name is resolved once, the address checked, and the connection
    opened to exactly that address, so a second DNS answer cannot change the target.
  - **Proxies:** proxies from the environment are not used while the list is set.
  - **At config load:** addresses written as IPs (in the URL, `tcp` or `connect_to`)
    are checked already then. Host names are checked when the check runs.
  - **On-host checks are not restricted**; they run on the target itself.

### Timer and maintenance windows

Windows are wall-clock times in `policy.timezone`, an IANA name such as `Europe/Zurich`
(globally or per host). Without it they use the central host's local time, which in an
LXC is often UTC, so set it explicitly. Daylight saving time is handled:

- **Skipped hour (spring):** a window covering the hour that does not exist is shorter
  that night, or empty if it lies entirely inside that hour.
- **Repeated hour (autumn):** a window covering the hour that happens twice is open
  twice. The second pass finds nothing left to do.

`hosts check` shows the next window of every patch host in its time zone, and the status
page shows the windows with their time zone. Without `timezone`, both name the server's
zone: `(server local time, Europe/Zurich)`, from `$TZ` or `/etc/localtime`.

The patch timer runs hourly. Each host is only patched inside its window:

```sh
cp contrib/systemd/aptwarden-patch.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now aptwarden-patch.timer
```

Mails from patch runs:

- an immediate alert for anything that needs a human (rolled back, failed, ...)
- what was patched, or a run that aborted for a new reason: by default
  (`notify.patch_summary: digest`) collected into the next report summary, under
  **Patch runs since the last summary**, with the count in its subject. With
  `patch_summary: immediate` each patch run that did something sends its own mail
  instead, which means one mail per maintenance window.

Quiet hours cause no mail.

### Dependencies between hosts (`depends_on`)

A patch run processes its hosts one after another, in the order of the configuration.
`depends_on` names hosts that must be patched first:

```yaml
hosts:
  - name: wordpress01
    depends_on: [proxy01, pihole01]
```

- **Order:** dependencies in the same run are patched before the hosts that depend on
  them. Hosts without dependencies keep the configured order.
- **Failed dependency:** when a dependency ends the run `rolled-back`,
  `needs-manual-rollback`, `failed`, `rollback-failed` or `aborted`, its dependents are
  skipped with the reason `dependency proxy01 rolled-back`. They are not touched and
  cause no alert of their own; the dependency's alert covers it. This carries on to
  hosts depending on a skipped one.
- **Patch history:** a skipped dependent is stored with status `skipped` and its reason,
  so `aptwarden patches` and the status page show that it was left out on purpose. A
  skip does not replace the host's last patch run: the status page, `last_patch` in
  `status.json`, the snapshot cleanup and the check for repeated aborts all use the
  last run that actually ran. Hosts skipped for their window or modes are not stored.
- **Dependency not in the run:** outside its window, without `patch` in its modes or not
  selected with `--host`, it does not hold anything back; the host is patched as usual.
- **Dry run:** `aptwarden patch --dry-run` shows the patch order and which hosts would be
  skipped if a dependency fails.

Unknown host names, a host depending on itself, and cycles are configuration errors.

A dependent host starts only after its dependency has passed its own healthchecks. For
dependencies that may reboot (`reboot: if-required`; DNS such as Pi-hole, the reverse
proxy), separate windows are still the recommended setup: give them their own window,
apart from the hosts behind them. A reboot then interrupts the services behind them on
its own, and problems that show only hours later turn up before the hosts behind them
are patched. An unimportant host patched a day earlier works the same way as a canary
for bad package updates.

## Status page

After every `report` and `patch` run, aptwarden writes a static, read-only HTML page:
`/var/lib/aptwarden/www/index.html` by default. It contains:

- totals, then a **Needs attention** block right below them (see below)
- a table of all hosts (modes, fixable, critical, high, KEV, last scan, last patch run
  that ran; a skip because a dependency failed does not count),
  sorted by risk: hosts with errors first (failed scan, or a last patch run listed
  below), then by the number of fixable known exploited, critical and high
  vulnerabilities, then by name
- per host its policy, as configured when the page was generated, with its maintenance
  windows in the host's own time zone
- for hosts with `patch` in `policy.modes`, in the table and in the host's details: the
  start of the next maintenance window and what it would patch (see below)
- per host: the fixable packages, every vulnerability (collapsible: ID, severity, CVSS,
  fixed version or status), the patch history and aptwarden's snapshots. The details
  of each host are collapsed; a link to a host (from the hosts table, Needs attention
  or Vulnerabilities) opens them, in Chrome 97, Firefox 148 (ESR 153) and Safari 26.2
  or later. Older browsers do not open them; click the host's line in Host details.
- per host: a small chart of the fixable vulnerabilities over the stored scans (total,
  critical and high), with the period it covers; hovering a point shows its values (see
  below)
- per host: the latest healthcheck results, ✓ or ✗ with the detail for each check. They
  come from the newest patch run that ran checks: the results after patching (or after
  the rollback), else those before patching, with the run and its time. Dry runs are not
  stored, so they do not appear here
- the state of the data sources and definitions, including rejected releases
- at the end, **Vulnerabilities**: every vulnerability listed in a host's details, once
  (see below)

**Needs attention** lists, worst first, everything that needs a human. Each host links
to its details:

- hosts whose last patch run ended `needs-manual-rollback`, `rollback-failed` or `failed`
  (`rolled-back` is not listed: the host is back on its snapshot. An `aptwarden
  rollback` also ends as `rolled-back` and clears the entry)
- hosts whose last scan failed
- fixable known exploited (KEV) vulnerabilities, one entry per vulnerability and
  package with all hosts that have it, e.g. "KEV CVE-2026-10 critical in brotli, fixed
  in 1.1.0-2+deb13u1 — web01, web02". If the hosts need different fixed versions (for
  example on different Debian releases), the version is given per host.
- hosts whose last patch runs were `aborted` at least twice in a row, with the reason.
  An abort with the same reason as the previous run sends no further mail, so the page
  keeps them visible.

When none of this applies, the block says "Nothing needs attention".

**Vulnerabilities** has one row per vulnerability with its ID, severity, CVSS score, KEV
badge, description and the hosts that have it. The ID links to the Debian security
tracker. The host tables and the Needs attention block show no descriptions: their
vulnerability IDs link to this row instead, so a description shared by many hosts is
on the page only once. Where the hosts' data differ, the row shows the highest severity
and score. The section is not collapsible, so these links always land on the row.
Up to 6 hosts are named; with more, the cell reads `all 40 hosts`, `all 40 hosts except
web07` (up to 3 named) or a collapsed list such as `12 hosts`.

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
  one directory (any file in it, not only the two). The web server gets no access to
  the central host.
- **nginx location:** `satisfy all` with an IP allowlist, Basic Auth and the same CSP
  as the page.

```yaml
status_page:
  enabled: true          # default
  path: null             # default: <state_dir>/www/index.html
  mode: "0640"           # e.g. "0644" if another local user serves it
```

**Next patch run** shows the start of the next window in the host's time zone (`open now`
inside a window, `any time` without windows) and a preview such as `would patch: openssl,
inetutils (2 critical, 1 high)`: the source packages and the number of vulnerabilities per
severity. The preview applies the planner's selection to the fixable findings of the last
scan: `auto_patch_severities`, `auto_patch_kev`, definitions restricting a vulnerability
to `report`, and `block` definitions covering the fixed version (listed as held back). It
reads only `state.db`, with no SSH connection and no apt simulation, so the patch run can
still hold back a package once it sees the apt candidates (mirror behind, blocked
candidate). Changes after the last scan appear with the next report run. In the hosts
table, a preview of more than 3 packages names the first 3 and counts the rest, e.g.
`openssl, curl, tar +9 more (4 critical, 11 high)`; hovering shows the full list, and the
host's details list every package.

**Fixable over time** is an inline SVG, so it needs no script and no external resource;
its colours follow the light or dark theme. Failed scans are left out. The chart shows
what `state.db` still holds: `keep_runs` (default 100) counts *every* run, including the
hourly patch runs, so with the patch timer 100 runs are about four days. For a longer
history, raise it, e.g. `keep_runs: 2000` for about 80 days; `state.db` then grows by
the findings of every stored scan.

Times on the page (scans, patch runs, snapshots, data sources, when it was generated)
are shown in the global `policy.timezone` with the zone's abbreviation, e.g.
`2026-11-02 07:00 CET` in winter and `2026-10-23 08:00 CEST` in summer. Without it, they
use the central host's local time zone; the page header names the zone used.

`aptwarden status --format html` prints the page to stdout.

### status.json for monitoring

Next to `index.html`, aptwarden writes `status.json`, also atomically and with the same
`mode`. It contains only numbers and states: host names, but no package names,
vulnerability texts or addresses.

```json
{"generated_at": "2026-11-02T06:00:12Z", "last_run": "20261102T060001Z-3f9a",
 "hosts": 7, "hosts_failing": 0, "fixable": 12, "critical": 0, "high": 3, "kev": 0,
 "needs_attention": 0, "not_scanned": 0, "aptwarden": "0.7.0",
 "hosts_detail": [{"name": "web01", "scan_ok": true, "scanned_at": "2026-11-02T06:00:05Z",
                   "last_patch": "patched", "last_patch_at": "2026-10-30T02:00:41Z",
                   "fixable": 2, "critical": 0, "high": 1, "kev": 0,
                   "needs_attention": 0}]}
```

- Times are UTC in ISO 8601.
- `hosts` counts scanned hosts, `not_scanned` the configured hosts never scanned.
- `needs_attention` counts the problems in the **Needs attention** block per host: a
  KEV entry listing three hosts counts three, the same as before KEV entries were
  grouped, so existing monitoring rules keep working. Per host, it is the number of
  problems that host has.
- `scan_ok` is `false` when the latest scan failed and `null` before the first one.

The publish unit pushes it together with the page.

**Uptime Kuma**, with a monitor of type *HTTP(s) - Json Query* on
`https://proxy.example.org/aptwarden/status.json`:

- Under *Authentication*, choose *HTTP Basic Auth* with the nginx credentials. The
  Uptime Kuma host must be in the location's `allow` list.
- **Freshness:** set the *Json Query* to
  `($millis() - $toMillis(generated_at)) < 2 * 3600 * 1000` and the *Expected Value* to
  `true`. With the hourly patch timer the file is at most about an hour old. With only
  the daily report timer, allow 26 hours (`26 * 3600 * 1000`). A stale file means the
  timers or the publish push stopped.
- **Nothing to do:** a second monitor with the *Json Query* `needs_attention = 0` and the
  *Expected Value* `true`.

Uptime Kuma 2.x shows the query as *Json Query Expression* with a *Condition*: keep `==`
and `true`. Both expressions are [JSONata](https://jsonata.org/).

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
aptwarden helper show [--install [--with-needrestart]]   the helper or its installer
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
| 2 | configuration or usage error, or run as root on directories owned by the service user |

## Files

| Path | Content |
|---|---|
| `/etc/aptwarden/config.yaml` | configuration |
| `/var/lib/aptwarden/state.db` | run history, findings, first/last seen |
| `/var/lib/aptwarden/www/index.html` | static status page |
| `/var/cache/aptwarden/cache.db` | feed cache, about 100 MB, safe to delete |
| `/var/cache/aptwarden/definitions.git` | mirror of the definitions repository |
| `/etc/aptwarden/credentials/` | secrets (Proxmox token, NVD key, SMTP password) |
| `/etc/aptwarden/ssh/` | SSH keys: `id_ed25519` (targets), `publish_ed25519` (status page) |
| `/etc/aptwarden/allowed_signers` | keys trusted for signed definition releases |
| `/etc/aptwarden/publish.env` | `PUBLISH_TARGET` for the status page push |
| `/var/lib/aptwarden/known_hosts` | SSH host keys of the targets |

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
- **`depends_on` only orders hosts within one patch run,** it does not link runs or
  windows, see [Dependencies between hosts](#dependencies-between-hosts-depends_on).

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
    APTWARDEN_IT_CONFIG=/etc/aptwarden/config.yaml APTWARDEN_IT_VMIDS=9001,9002 \
        python3 -m pytest -m integration -o addopts= tests/integration/test_patch_live.py
    ```

CI runs the unit tests on Python 3.11 to 3.13, and in `debian:12` and `debian:13`
containers with Debian's packages only.

**Releases:** the version lives only in `src/aptwarden/__init__.py` (`pyproject.toml`
reads it from there). Raise the minor version for new features or changes to the
configuration or `status.json`, the patch version for fixes, then tag the commit,
signed so that installations can verify it:

```sh
git -c gpg.format=ssh -c user.signingkey=~/.ssh/release_ed25519.pub tag -s -m v0.7.0 v0.7.0
git push origin v0.7.0
```

CI also runs [bandit](https://bandit.readthedocs.io/) and CodeQL on `src`,
[pip-audit](https://pypi.org/project/pip-audit/) on the dependencies (on every push and
weekly), ShellCheck on the root helper, zizmor on the workflow and gitleaks on the
history; see [SECURITY.md](SECURITY.md#security-checks-in-ci). For release tags it
attaches a CycloneDX SBOM (`sbom` artifact). Dependabot keeps the pinned action SHAs
and the hash-pinned CI tools current, proposing a new version only once it is a week
old (security updates right away).

## Security

[SECURITY.md](SECURITY.md) covers how to report a vulnerability, the threat model, the
minimum privileges for SSH and Proxmox, the residual risks of snapshots and rollbacks,
and the safe defaults with the settings that weaken them.

## License

MIT, see [LICENSE](LICENSE).
