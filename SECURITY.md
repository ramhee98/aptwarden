# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a
vulnerability** on <https://github.com/ramhee98/aptwarden>. Do not open a public issue.
Include the version (`aptwarden version`), what an attacker needs (network position,
access to which host or file) and, if possible, a way to reproduce it.

You get an answer within a week. Fixes are released as a new version. The advisory
names the first fixed version, and credits you if you like.

Only the latest release is supported.

## Threat model

aptwarden runs on one central host. From there it reads package lists of Debian hosts
over SSH and, for hosts that allow it, installs security updates with a Proxmox snapshot
as a safety net.

| Component | Trusted for | If it is compromised |
|---|---|---|
| **Central host** (aptwarden user, `/etc/aptwarden`) | everything below: SSH key, Proxmox token, SMTP credentials, configuration | An attacker can upgrade, restart, reboot or roll back every patch host, and snapshot and roll back every guest in the Proxmox pool. Protect it like a configuration management server. |
| **Configuration** | targets of healthchecks, URLs of data sources, hosts, policies | Writable only by root. It is trusted like code, see [Configuration](#configuration). |
| **Target hosts** | their own package list and service state | A host can lie about its packages, so its report is wrong. It cannot run code on the central host: output is parsed, never executed. A hostile web service on it is handled by the healthcheck redirect rules. |
| **Root helper** on target hosts | the only thing sudo allows | Fixed subcommands. Arguments are validated as `package=version`, and only installed packages are upgraded. Package maintainer scripts still run as root, so the trust in the host's apt sources stays as it is. |
| **Proxmox API** | snapshots and rollbacks of the pool's guests | The certificate fingerprint is pinned. The token is limited to one pool and four privileges, see [Minimum privileges](#minimum-privileges). |
| **Data sources** (Debian tracker, OSV, NVD, CISA KEV) | vulnerability data | Bad data causes wrong reports and wrong patch selection, but cannot run code. Responses are limited in size (256 MiB received and 256 MiB decompressed, read in blocks), and only `http(s)` URLs are used. Only fixed versions from the host's own apt sources are ever installed. |
| **Definitions repository** | overriding source data (`not-affected`, `block`, `auto-patch`) | Only tags signed by a key in `allowed_signers` are accepted, never older than the accepted commit. The archive is read with limits: 32 MiB, 5000 entries, 256 KiB per file, 16 MiB in total. No symlinks, no YAML aliases. A stolen signing key can hide vulnerabilities or block fixes, so keep it offline. |
| **Status page web server** | serving two files | It receives `index.html` and `status.json` through `rrsync -wo` and has no access to the central host. The page lists open vulnerabilities, so serve it LAN-only with a password. |

**Out of scope:** an attacker who is already root on the central host, a malicious
Debian mirror (apt's signature checks apply) and denial of service by the configured
data sources beyond the size limits.

## Minimum privileges

**SSH user on target hosts:**
- `aptwarden`, a normal user.
- Its key is restricted with `restrict,from="CENTRAL_IP"` in `authorized_keys`.
- Report-only hosts need no sudo at all.
- Patch hosts allow exactly one command in sudoers:
  `aptwarden ALL=(root) NOPASSWD: /usr/local/lib/aptwarden/aptwarden-helper`.
- `aptwarden helper show --sudoers` prints the rule, and `--install` sets everything
  up. See the README, "Target hosts: helper and sudo".

**Host keys:**
- `strict_host_key_checking: yes`, with aptwarden's own `known_hosts` file.
- New hosts are added once with `hosts check --accept-new`.
- `ssh.options` cannot weaken this. Only an allowlist of options is accepted: ProxyJump,
  algorithms, keepalives and similar. Host key checking, identities and multiplexing
  cannot be overridden, and neither can options that run commands, such as
  `ProxyCommand`.

**Proxmox token:**
- A dedicated user `aptwarden@pve`, with no shell login.
- A token with privilege separation.
- A role with `VM.Audit, VM.Snapshot, VM.Snapshot.Rollback, VM.PowerMgmt`. The last one
  is needed to start a container after a rollback.
- Granted on one pool that contains only the guests aptwarden may patch.
- A test token in its own pool can never touch production guests.

**Files on the central host:**
- `/etc/aptwarden/credentials/*` mode 0600, owned by aptwarden. The directory is 0750,
  root:aptwarden.
- The SSH key lives in `/etc/aptwarden/ssh/`, mode 0700.
- aptwarden refuses to run as root where that would leave root-owned state behind.

**Status page publishing:** a separate SSH key, limited on the web server to
`rrsync -wo` into one directory.

## Snapshots and rollbacks: residual risks

- **A rollback loses data.** Everything written on the guest since the snapshot is gone:
  mail, database rows, uploads, logs.
  - Use `rollback: manual` for hosts where that matters (mail servers, shops,
    anything with user content). aptwarden then alerts and leaves the decision to you
    (`aptwarden rollback --host …`).
- **Snapshots without RAM state** (`snapshots.vmstate: false`, the default): after a
  rollback the guest boots from the disk state. Services restart, and connections and
  in-flight work are lost.
- **Snapshots cost storage** until `snapshots.keep` (default 7 days) removes them.
  - **Full storage:** a snapshot can fail on full storage, and the patch run then
    aborts before changing anything.
  - **External snapshots:** aptwarden deletes only snapshots it created itself (`aptw_…`
    names recorded in `state.db`).
- **Snapshots contain secrets.** They hold everything that was on the guest at that
  time. Whoever can read the Proxmox storage can read them.
- **A rollback is not a security fix.** It restores the vulnerable versions. The next
  run tries again, and the finding stays open and reported.
- **Healthchecks decide.** A check that passes although the service is broken keeps a
  bad update; one that fails although the service works causes a needless rollback.
  Check what users see (HTTP with `contains`), not only that a unit runs.
- **Without a snapshot provider** patching is refused unless
  `allow_without_snapshot: true`. With it, a failed update has no automatic way back.

## Configuration

The configuration decides which hosts are contacted, which URLs are fetched and which
addresses healthchecks connect to. Keep it root-owned and not writable by the aptwarden
user:

```sh
chown root:aptwarden /etc/aptwarden/config.yaml && chmod 640 /etc/aptwarden/config.yaml
```

Safe defaults and the settings that weaken them:

| Setting | Default | Weakens it |
|---|---|---|
| `ssh.strict_host_key_checking` | `yes` | `accept-new` (trust on first use) |
| `ssh.options` | `{}` | only allowlisted options are accepted |
| `policy.modes` | `[report]` | `patch` per host |
| `policy.auto_patch_severities` | `[critical, high]` | more severities |
| `policy.allow_without_snapshot` | `false` | `true`: patching without a way back |
| `policy.allow_extra_upgrades`, `allow_new_packages` | `false` | `true`: upgrades outside the plan |
| `policy.rollback` | `auto` | `manual` keeps a failed state and alerts instead |
| `policy.reboot` | `never` | `if-required` |
| `health.redirects` | `same-host` | `any` |
| `health.allowed_networks` | `[]` (no restriction) | set it to restrict checks from the central host |
| `sources.custom.ref` | `signed-tags` | `branch`: no signature check (forks and testing only) |
| `proxmox` TLS | certificate checked against the system CAs, `ca_file` or the pinned `tls_fingerprint` | cannot be turned off |
| `notify.email.security`, `tls_verify` | `starttls`, `true` | `none`, `false` |
| `status_page.mode` | `0640` | `0644` |

## Security checks in CI

The CI workflow runs three kinds of checks:
- **Unit tests,** including the security regression tests: size limits for HTTP and
  definitions archives, YAML aliases, protected ssh options, ssh quoting, healthcheck
  redirects and allowed networks.
- **[bandit](https://bandit.readthedocs.io/)** on the code.
- **[pip-audit](https://pypi.org/project/pip-audit/)** on the dependencies, on every
  push and weekly.

Release tags get a CycloneDX SBOM. Actions are pinned to commit SHAs, and Dependabot
keeps them current.
