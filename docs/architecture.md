# aptwarden architecture

aptwarden runs on one central host. It reaches Debian hosts over SSH, inventories their
installed packages, matches them against vulnerability data and reports the results. A
later phase adds patching behind a staged safety net: simulation, snapshot, update,
healthcheck and rollback.

## Design principles

- **Core works on any Debian host over SSH.** Proxmox is an optional snapshot provider,
  not a requirement.
- **Agentless.** The only thing deployed to target hosts (from phase 4 on) is a small
  root-owned helper script. sudo grants access to that script and nothing else.
- **Few dependencies.** The runtime dependencies are PyYAML and jsonschema. Both are
  available as Debian packages (`python3-yaml`, `python3-jsonschema`). The standard
  library covers everything else: `urllib` (HTTP), `sqlite3` (state and cache), `smtplib`
  (mail) and `subprocess` + OpenSSH (transport). OpenSSH is used instead of paramiko, so
  `ssh_config`, `known_hosts`, ProxyJump and ControlMaster all behave as usual.
- **Debian version semantics are implemented in pure Python** (`aptwarden.debversion`). It
  is tested against a case table generated with `dpkg --compare-versions`, so CI does not
  need dpkg.
- **Matching uses source packages.** The Debian Security Tracker keys everything by source
  package and source version. Binary versions can differ from the source version through
  binNMUs (`+b1`) or a binary-only epoch, e.g. `bsdutils 1:2.41-5` is built from
  `util-linux 2.41-5`. aptwarden therefore compares `${source:Version}`, never the binary
  version.

## Components

| Module | Responsibility |
|---|---|
| `transport` | `ssh` (OpenSSH with connection multiplexing) and `local` |
| `inventory` | `dpkg-query` (binary + source package, versions, status), os-release, architecture, facts such as unattended-upgrades and needrestart |
| `sources` | Vulnerability source plugins: `debian_tracker`, `osv`, later `custom` (GitHub definitions) and `trivy` (Docker images) |
| `enrich` | Severity normalisation: CVSS (OSV CVE records, NVD fallback) and CISA KEV |
| `matcher` | Merges findings from all sources per (host, source package, vulnerability); precedence custom > debian_tracker > osv |
| `state` | SQLite: runs, per-host results, findings, first-seen tracking |
| `report` | Text and JSON output |
| `cli` | `report`, `status`, `hosts check`, `sources refresh`, `config check` |
| later: `policy`, `patch`, `snapshot`, `health`, `notify`, `definitions` | see phases 2 to 4 |

## Data flow

```
systemd timer ─► aptwarden report
  ├─ sources refresh:  Debian tracker JSON (conditional GET), KEV → cache.db
  ├─ per host (parallel):
  │     inventory ─► sources.match ─► matcher ─► enrich (CVSS, KEV) ─► findings
  ├─ state.db: run, host results, findings, first/last seen
  └─ output: text/JSON report (phase 2: notifications)
```

## Vulnerability sources

### Debian Security Tracker (primary)

`https://security-tracker.debian.org/tracker/data/json` is about 85 MB raw and 14 MB with
gzip. It sends `Last-Modified`, so aptwarden makes a conditional request and parses the
data only when it changed. Parsing takes under a second at about 450 MB peak RSS. The
data is reduced to per-release rows and stored in `cache.db`.

For each installed source package and the host's release:

| Tracker state | aptwarden status |
|---|---|
| `resolved`, `fixed_version` = `0` | not affected |
| `resolved`, installed >= fixed | not affected |
| `resolved`, installed < fixed, fixed version present in a release repository | `fixable` |
| `resolved`, installed < fixed, fix not yet in any repository (e.g. next point release) | `fix-pending` |
| `open` | `no-fix` |
| `undetermined` | `undetermined` |

### OSV.dev (secondary)

OSV's Debian records (`DEBIAN-CVE-*`) are generated from the Debian tracker. For dpkg
packages they mainly add redundancy if the tracker is unavailable. aptwarden queries
`/v1/querybatch` with source package and source version, then hydrates every
vulnerability once. Hydrated records are cached by `(id, modified)`. OSV becomes more
important for Docker images and language ecosystems later.

### Severity

The Debian tracker only carries an `urgency`, and most entries are "not yet assigned".
aptwarden computes a normalised severity:

1. a custom definition's severity (phase 3)
2. Debian urgency `unimportant` → `low` (Debian knows when an issue does not apply to its
   build)
3. CVSS base score → critical (>= 9.0), high (>= 7.0), medium (>= 4.0), low (> 0)
4. Debian urgency `high`/`medium`/`low`
5. `unknown`

CVSS comes from OSV's `CVE-*` records. They carry the CVSS vector, are fast and have no
tight rate limit. aptwarden computes the CVSS 3.x base score from the vector itself. NVD
(API 2.0) is the fallback for CVEs without a v3 vector, for example v4-only. NVD is
rate-limited (5 requests per 30 s without an API key), so lookups run within a time
budget per run. Missing scores are filled in on later runs. Results, including negative
results, are cached.

A CVE listed in CISA KEV (known exploited) is flagged and will raise an immediate alert
in phase 2.

### Noise control

A typical Debian host has hundreds of open CVEs without a fix (no-dsa, postponed,
unimportant). The report separates **fixable now** from everything else. The default
summary shows fixable findings at or above a configurable severity. `--all` shows
everything.

## Patching (phase 4)

```
plan → preflight → simulate → snapshot → apply → restart → healthcheck ─┬─ ok   → done
                                                                        └─ fail → rollback (auto|manual) + alert
```

1. **plan:** Find every installed binary built from a vulnerable source package. Upgrade
   it only if the candidate version is >= the fixed version.
2. **preflight:** Run healthchecks *before* patching and abort if they already fail, so
   that a pre-existing problem cannot trigger a rollback. Also check that the dpkg lock is
   free, the snapshot feature is available and there is enough disk space.
3. **simulate:** Run `apt-get -s install --only-upgrade pkg=ver ...`. Abort on any
   removal, any new package outside the plan (allowlist configurable), any target-version
   mismatch, or any version in a blocked range.
4. **snapshot:** Create `aptw-<run-id>` without RAM state by default, and wait for the
   Proxmox task to finish.
5. **apply:** Install exactly the simulated packages and versions, non-interactive, with
   `--force-confold`.
6. **restart:** needrestart is configurable per host (`auto`, `list` or `off`; default
   `auto`). Reboot is `never` or `if-required`, inside the maintenance window. After a
   reboot, wait for SSH.
7. **healthcheck:** systemd units, HTTP and TCP checks, with a grace period and retries.
8. **rollback:** `auto` or `manual`. In manual mode aptwarden alerts and you run
   `aptwarden rollback <run-id>`.
9. **cleanup:** Delete only snapshots with the `aptw-` prefix that are recorded in
   `state.db` and older than the configured age.

- **Without a snapshot provider** (plain Debian servers, PVE nodes): auto-patching
  requires an explicit `allow_without_snapshot: true`. A failed healthcheck then only
  raises an alert, because apt downgrades are not a reliable rollback.
- **Without configured healthchecks**, aptwarden refuses to auto-patch.

### Target host privileges

A sudoers rule on `apt-get` itself amounts to root. `apt-get install *` allows
`-o APT::Update::Pre-Invoke::=/bin/sh`. Target hosts therefore get
`/usr/local/lib/aptwarden/aptwarden-helper`, a POSIX shell script owned by root:

- It has fixed subcommands: `update`, `simulate`, `install`, `needrestart`, `reboot` and
  `pin`.
- It validates package names and versions with a regex and only allows `--only-upgrade`.
- sudo grants the `aptwarden` user this one script.
- Inventory needs no privileges at all.

## Custom definitions (phase 3)

The definitions live in a separate public repository with YAML files. The format follows
OSV range semantics:

```yaml
schema_version: 1
id: AW-2026-0001
aliases: [CVE-2026-12345]
summary: "openssl: remote code execution in ..."
severity: critical            # critical | high | medium | low
package: openssl              # Debian source package
affected:
  - release: bookworm
    ranges: [{introduced: "0", fixed: "3.0.17-1~deb12u3"}]
action: auto-patch            # report | auto-patch | block
references: [https://example.org/advisory]
```

Trust model for a public repository:

- **Definitions can only tighten local policy, never loosen it.** `auto-patch` takes effect
  only if the host policy already allows auto-patching for that severity.
- **Every new commit must be signed.** aptwarden checks every commit since the last
  verified head with `git verify-commit` against a locally configured `allowed_signers`
  file, never one from the repository. Signature or schema failures keep the last good
  state active and raise an alert.
- **Definitions are data only.** They never contain package sources, commands or scripts.
- **`block`** marks the affected versions as known-bad (think xz 5.6.x). aptwarden
  - never installs them,
  - reports them as critical when they are installed,
  - can optionally write an apt preferences file per host (`enforce_block: pin`) with
    Pin-Priority -1.
- **The JSON schema ships with aptwarden.** The definitions repository validates pull
  requests with `aptwarden defs validate`.

## Storage

| Path | Content | Safe to delete |
|---|---|---|
| `/var/lib/aptwarden/state.db` | runs, host results, findings, first/last seen | no (history) |
| `/var/cache/aptwarden/cache.db` | tracker data, OSV records, CVSS, KEV | yes (re-downloaded) |

## Security of the central host

The central host holds SSH access to every target and, later, a Proxmox API token. It
runs as a dedicated `aptwarden` user under systemd hardening (`ProtectSystem=strict`,
`NoNewPrivileges`, `StateDirectory`, `CacheDirectory`). Secrets are read from files or
from systemd credentials (`*_file` keys) and never stored inline. On the target hosts,
`authorized_keys` should restrict the key with `from="<central host IP>"`.

## Risks

- **Rollback discards data written after the snapshot,** such as received mail and
  database writes. The window is minutes. For mail hosts (PMG, mailcow) `rollback: manual`
  is recommended.
- **Simulation only checks package resolution.** Pre- and post-patch healthchecks plus
  needrestart cover the gap. The quality of the healthchecks determines the safety.
- **LXC snapshots** fail when a mount point lives on storage without snapshot support,
  and bind mounts can prevent them depending on the configuration. `hosts check` verifies
  the snapshot feature through the Proxmox API.
- **PVE nodes** require `apt full-upgrade`, and selectively upgrading Proxmox packages is
  risky. Nodes default to report-only. An explicit full-upgrade mode may follow.
- **unattended-upgrades running in parallel** is allowed. aptwarden waits for the dpkg lock
  and flags the host as patched outside the safety net.

## Alternatives considered

- **Vuls:** mature agentless SSH scanning. It needs Go and several database services, has
  no custom definitions in this form, and no snapshot-backed patch flow.
- **debsecan on every host:** decentralised, no policy, no custom definitions.
- **Ansible for execution:** a large dependency for a handful of commands.
- **paramiko:** an extra dependency that ignores `ssh_config` and ProxyJump.
- **pydantic:** an extra dependency. JSON Schema also gives users of the definitions
  repository editor completion.

## Phases

1. Inventory, Debian tracker + OSV matching, CVSS/KEV enrichment, report and status (text
   and JSON), state database, JSON logs, systemd timer.
2. Notifications (email, ntfy, Slack-compatible, generic webhook), alert de-duplication.
3. Definitions repository: schema, sync, signature verification, precedence, block logic.
4. Patching: helper, simulation parser, Proxmox snapshot provider, healthchecks,
   needrestart/reboot, rollback, cleanup, maintenance windows, integration tests.
5. Later: Trivy plugin for Docker images, small status web page.
