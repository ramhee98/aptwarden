# aptwarden architecture

aptwarden runs on one central host. It reaches Debian and Ubuntu hosts over SSH,
inventories their installed packages, matches them against vulnerability data and
reports the results. A later phase adds patching behind a staged safety net:
simulation, snapshot, update, healthcheck and rollback.

## Design principles

- **Core works on any Debian or Ubuntu host over SSH.** Proxmox is an optional snapshot
  provider, not a requirement.
- **Agentless.** The only thing deployed to target hosts (for patching) is a small
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
| `sources` | Vulnerability source plugins: `custom` (own definitions from Git), `debian_tracker`, `osv`, later `trivy` (Docker images) |
| `enrich` | Severity normalisation: CVSS (OSV CVE records, NVD fallback) and CISA KEV |
| `matcher` | Merges findings from all sources per (host, source package, vulnerability); precedence custom > debian_tracker > osv; drops `not-affected` |
| `state` | SQLite: runs, per-host results, findings, first-seen tracking |
| `report` | Text and JSON output |
| `statuspage` | Static read-only HTML page from state.db, written after every run |
| `cli` | `report`, `status`, `patch`, `rollback`, `snapshots`, `patches`, `defs`, `notify test`, `hosts check`, `helper show`, ... |
| `notify` | Run summary and de-duplicated immediate alerts; e-mail notifier, webhooks pluggable |
| `definitions` | Custom definitions: schema, validation, signed-tag Git sync |
| `patch` | Planner, apt simulation checks, maintenance windows, the patch pipeline |
| `snapshot` | Snapshot providers: `proxmox` (LXC and QEMU via API token), `none` |
| `health` | Healthchecks: systemd (on the host), HTTP and TCP (from the central host) |
| `helper/` | The root helper and sudoers rule for target hosts |

## Data flow

```
systemd timer ─► aptwarden report
  ├─ sources refresh:  Debian tracker JSON (conditional GET), KEV → cache.db
  ├─ per host (parallel):
  │     inventory ─► sources.match ─► matcher ─► enrich (CVSS, KEV) ─► findings
  ├─ state.db: run, host results, findings, first/last seen
  ├─ output: text/JSON report, notifications
  └─ patch runs: per eligible host the patch pipeline (see Patching)
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

A `fixable` finding whose fixed version is only in repositories missing from the host's
apt sources (read with `apt-get indextargets`, compared by suite name) keeps its status
and gets `missing_source`, e.g. `trixie-security`. The host gets a warning, and patch
previews hold the package back.

### OSV.dev (secondary)

OSV's Debian records (`DEBIAN-CVE-*`) are generated from the Debian tracker. For dpkg
packages they mainly add redundancy if the tracker is unavailable. aptwarden queries
`/v1/querybatch` with source package and source version, then hydrates every
vulnerability once. Hydrated records are cached by `(id, modified)`. OSV becomes more
important for Docker images and language ecosystems later.

For Ubuntu hosts OSV is the only source so far. Canonical publishes `UBUNTU-CVE-*`
records in the ecosystems `Ubuntu:<version>:LTS` (April releases of even years) and
`Ubuntu:<version>`, one entry per release and source package. A fixed event means the
fix is released to the release's `-security`/`-updates` pockets, so the finding is
`fixable`; an entry without one is `no-fix`. For LTS releases aptwarden also queries
the Ubuntu Pro ecosystem (`Ubuntu:Pro:24.04:LTS`). It covers other packages than the
release's ecosystem: universe packages in esm-apps, and after the end of standard
support the release's own fixes in esm-infra. Pro findings are added where the
release's data has none, or replace an open finding with a Pro fix; a Pro fix keeps
`fixable` and gets `missing_source` `<codename>-apps-security (Ubuntu Pro)` (the
pocket comes from the entry's purl) unless the host's suites include it. Since OSV is
the only source for Ubuntu, a failed OSV query fails Ubuntu hosts instead of leaving
them with 0 findings. Canonical's bulk files were measured and not used: the OSV
archive is 12.6 GB uncompressed (152 s to parse daily, same data as the API), the VEX
archive 29.9 GB. Security notices (`USN-*`)
bundle the CVEs of every release they cover and are skipped, except where no CVE
record of the package covers any of their CVEs: some fixes have no CVE at all (e.g.
USN-8945-1, xz-utils). Regression notices (summary `<package> regression`) are always
skipped.

### Severity

The Debian tracker only carries an `urgency`, and most entries are "not yet assigned".
aptwarden computes a normalised severity:

1. a custom definition's severity
2. Debian urgency `unimportant` or Ubuntu priority `negligible` → `low` (the
   distribution knows when an issue does not apply to its build)
3. CVSS base score → critical (>= 9.0), high (>= 7.0), medium (>= 4.0), low (> 0)
4. Debian urgency `high`/`medium`/`low`, Ubuntu priority `critical` to `low`
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

## Patching

```
plan → preflight → simulate → snapshot → apply → restart → healthcheck ─┬─ ok   → patched
                                                                        └─ fail → rollback (auto) / alert (manual)
```

1. **plan:** Select fixable findings allowed by the host policy (severity, KEV, not
   restricted by a definition's `report` action). Group them by installed source
   package; every installed binary of that source is upgraded together. Refresh the
   package lists (helper `update`), read the candidates (`apt-cache policy`) and
   resolve each candidate's **source** version (`apt-cache show`), because binary
   versions differ by epoch or binNMU (`bsdutils 1:2.41.5-0+deb13u1` comes from
   `util-linux 2.41.5-0+deb13u1`, `libcap2 1:2.75-10+deb13u1+b3` from
   `1:2.75-10+deb13u1`). The candidate must reach the fixed version and must not be
   blocked by a definition.
2. **preflight:** The helper must answer via `sudo -n`. Healthchecks must be
   configured and pass *before* patching, so a pre-existing problem cannot trigger a
   rollback. The Proxmox snapshot feature must be available (a mount point on storage
   without snapshots fails here), and the guest must be the host: one of the MAC
   addresses of its `netN` devices must be on the host (`/sys/class/net/*/address`), or,
   for a guest without network devices, its name must be the host's short hostname.
   Otherwise a wrong `snapshot.vmid` would snapshot one guest, patch another and roll
   back the first one on a failure.
3. **simulate:** `apt-get -s install --only-upgrade pkg=ver ...` with exactly the plan.
   aptwarden aborts on any removal, any newly installed package (allowlist
   `allow_new_packages`), any upgrade outside the plan (`allow_extra_upgrades`), any
   apt error, and any target version mismatch.
4. **snapshot:** `aptw_<run-id>` (letters, digits and `_`; at most 40 characters),
   without RAM state unless `snapshots.vmstate`. The snapshot is recorded in
   `state.db`. Only recorded `aptw_` snapshots are ever rolled back to or deleted.
5. **apply:** helper `install` with the same arguments, plus the extra upgrades and new
   packages the policy allowed, each as `pkg=ver` from the simulation. The helper
   simulates again and refuses the transaction if it differs (see
   [Target host privileges](#target-host-privileges)). A refusal (exit status 2)
   ends the run as `aborted` without a rollback, since nothing changed; the unused
   snapshot is removed by the normal cleanup. A dpkg version check follows.
6. **restart:** needrestart `auto` (helper `needrestart restart`), `list` or `off`.
   needrestart's batch mode (`-b`) only lists services and never restarts them, so the
   helper lists (`-r l -b`), restarts without batch mode (`-r a -l`) and lists again.
   What is still listed is printed as `APTWARDEN-PENDING: <unit>`; only the other
   services count as restarted, the pending ones become a note of the result.
   With `reboot: if-required`, the host reboots when `/run/reboot-required` exists or
   needrestart reports a pending kernel. aptwarden waits until the boot marker changes.
   The marker is the kernel boot id plus the start time of PID 1, so it also works for
   LXC, which shares the host kernel.
7. **healthcheck:** after `health.grace`, retried `health.retries` times. A check never
   raises: whatever goes wrong while checking (e.g. a service that answers garbage or
   dies mid-response) is a failed check.
8. **rollback:** Proxmox rollback with `start=1`. For a running LXC this takes about
   3 s, because Proxmox stops and restarts the container itself. aptwarden then waits
   for the host and runs the healthchecks again. With `rollback: manual` it only
   alerts; `aptwarden rollback --host H` does it later.
9. **cleanup:** at the end of a patch run, or with `aptwarden snapshots cleanup`,
   recorded snapshots (active or rolled back) older than `snapshots.keep` are deleted.
   A snapshot still needed for a rollback (`needs-manual-rollback`, `failed`,
   `rollback-failed`) is kept.

**Unexpected errors:** an error the pipeline does not know (a bug, an answer nobody
expected) is handled like any other failure of the stage it happened in: before the
snapshot the run is `aborted`, afterwards it is rolled back or ends as `failed` /
`needs-manual-rollback`, and a rollback that crashes is `rollback-failed`. The result is
stored and alerted either way, and the patch run goes on with the next host. If even
that fails (e.g. the result cannot be stored), the host is reported as `failed` with
"the state of the host is unknown".

**Statuses:** `patched`, `rolled-back`, `needs-manual-rollback`, `failed`,
`rollback-failed`, `aborted` (nothing changed), `nothing-to-do`, `skipped`,
`dry-run`. Every status from `rolled-back` through `rollback-failed` raises an
immediate alert and marks the run `partial`. `aborted` marks the run `partial` too (exit
status 1), since the host was not patched, but raises no alert. Patch runs come from an
hourly timer, so they only send mail when something happened or an abort has a new
reason.

**Without a snapshot provider** (plain Debian servers), patching needs
`allow_without_snapshot: true`. A failed healthcheck then ends as `failed` with an
alert, because apt downgrades are not a reliable rollback.

A patch lock (`flock` on `state_dir/patch.lock`) keeps the timer and a manual run from
overlapping. `aptwarden rollback` and `aptwarden snapshots cleanup` (except with
`--dry-run`) take the same lock and fail while a patch run holds it, so they never roll
back or delete a snapshot a running patch depends on.

### Target host privileges

A sudoers rule on `apt-get` itself amounts to root (`-o APT::Update::Pre-Invoke::=/bin/sh`).
Target hosts therefore get `/usr/local/lib/aptwarden/aptwarden-helper`
(`aptwarden helper show`), a POSIX shell script owned by root. The `aptwarden-helper`
Debian package installs it as `/usr/lib/aptwarden/aptwarden-helper` and links the old
path to it, so `ssh.helper` stays the same in mixed fleets. Its properties:

- **Fixed subcommands:** `version`, `update`, `simulate`, `install`, `needrestart
  list|restart`, `pin` and `reboot`.
- **Strict argument checks:** arguments must be `package=version` with a restricted
  character set. Package names start alphanumeric, so options are impossible, and
  `--` separates them for apt.
- **Only the named transaction:** it always runs `--only-upgrade --no-remove
  --no-install-recommends` and keeps existing config files. `--only-upgrade` alone still
  installs new dependencies, and the central simulation can be outdated by the time
  `install` runs (package lists may change in between). So `install` simulates again
  and aborts, before changing anything, if apt would install a package that is not
  among its `package=version` arguments, a different version, or remove anything. What
  remains is the short gap between this simulation and the install, not the whole
  snapshot step.
- **Fixed environment:** `PATH`, `DEBIAN_FRONTEND=noninteractive`, and
  `NEEDRESTART_SUSPEND` (needrestart runs explicitly with the host's mode).

sudo allows exactly this script (`aptwarden helper show --sudoers`). Inventory needs no
privileges.

**Versions:** each feature needs a minimum helper version (`HELPER_FEATURES` in
`patch/runner.py`: patching 3, `pin` 4); newer helpers are accepted. A new helper
version therefore does not stop patching on hosts that have not updated yet, only the
feature that needs it. The central host has no way to replace the helper: updates come
through the host's own apt sources (the package) or whoever runs the installer.

### Proxmox token

The token belongs to a dedicated user and has privilege separation. The role
`VM.Audit, VM.Snapshot, VM.Snapshot.Rollback, VM.PowerMgmt` is granted to both the user
and the token on a pool that contains only the guests aptwarden may touch, so other
guests and the node are inaccessible. This is verified against PVE 9.2. The API
certificate is pinned by its SHA-256 fingerprint or verified against a CA.

## Custom definitions

Definitions live in a separate public repository
([aptwarden-definitions](https://github.com/ramhee98/aptwarden-definitions)): one
YAML file per definition, validated against `schemas/definition-v1.schema.json`
plus semantic checks (versions parse, ranges ordered, unique ids matching file
names, `auto-patch` has a fixed version).

```yaml
schema_version: 1
id: AW-2026-0002
aliases: [CVE-2026-24061]
summary: "inetutils telnetd: remote authentication bypass"
severity: critical
package: inetutils            # source package
affected:
  - release: trixie           # codename, or "any" (every Debian release)
    ranges: [{introduced: "0", fixed: "2:2.6-3+deb13u1"}]
action: auto-patch            # report | auto-patch | block
```

**Releases.** Debian and Ubuntu never share a codename, so a release names the
distribution too. `any` means every Debian release: Ubuntu's versions differ per
release (`1.2-3ubuntu0.24.04.1`), and existing definitions must not apply Debian
version ranges to Ubuntu hosts. A definition for Ubuntu names each release. This
needs no new field, which older aptwarden versions would reject (all or nothing);
they only warn about an unknown release.

**Precedence.** The `custom` source has the highest priority. For every
vulnerability a definition lists, the definition decides status, fixed version
and severity. If the installed version is outside its ranges, the definition
emits `not-affected` and the matcher drops other sources' findings for that
vulnerability (false-positive overrides).

**Trust model (public repository).**

- **Signed release tags, not branches.** Anyone may commit to `main`.
  aptwarden only activates the newest tag `vYYYY.MM.DD[.N]` that
  1. carries a valid SSH signature by a key in the local `allowed_signers` file
     (never taken from the repository). git verifies in the format of the signature,
     not of `gpg.format`, so tags with an OpenPGP or X.509 signature are refused
     before `verify-tag`, and the programs for those formats are set to `false`,
  2. descends from the last accepted commit (no rollback, no rewritten history),
  3. validates completely (all or nothing).

  Newer tags failing a check are rejected once with an alert, older valid tags
  are still considered, and the accepted state stays active otherwise. Tags are
  immutable: a moved tag is refused at fetch.
- **The signature covers the whole tree.** The maintainer signs after reviewing
  the diff since the last release, so pull requests can be merged in the web UI
  without weakening the model.
- **Files are read from the verified commit** (`git archive`), not from a
  working tree. Git runs with system and global config disabled.
- **The accepted definitions are stored in `state.db`,** so wiping the cache or a
  broken upstream cannot remove or roll them back.
- **Definitions only tighten local policy.** `auto-patch` takes effect only if the
  host policy already allows auto-patching for that severity.
- **Definitions are data only:** no package sources, commands or scripts.

**`block`** marks versions as known-bad (think xz 5.6.x):

- installed blocked versions always raise an alert, whatever their severity,
- the patch pipeline never installs them,
- with `policy.enforce_block: pin`, each report run pins the available blocked
  versions of installed packages to priority -1 in
  `/etc/apt/preferences.d/aptwarden-block`, written by the helper, so manual `apt` runs
  and unattended-upgrades skip them too.

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
  the snapshot feature through the Proxmox API, and that the guest is the host.
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
3. Definitions repository: schema, signed-tag sync, rollback protection, precedence,
   block alerts.
4. Patching: helper, simulation checks, Proxmox snapshots, healthchecks,
   needrestart/reboot, automatic rollback, cleanup, maintenance windows, live
   integration tests.
5. Static status page (done). Later: Trivy plugin for Docker images.
