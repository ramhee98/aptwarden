# Changelog

Release notes for aptwarden. Versions before 0.4.0 are described in their release
commits.

## Unreleased

### Fixes

- **A wrong `snapshot.vmid` no longer snapshots and rolls back another guest.** The
  preflight (and `hosts check`) compares the Proxmox guest with the host aptwarden
  reaches over SSH: one of the MAC addresses of the guest's network devices must be on
  the host, and a guest without any must have the host's short hostname as its name.
  Otherwise the run is `aborted` before anything changes. Before, a mixed-up VMID was
  only checked for snapshot support, so a failed patch rolled back the wrong guest.
- **An aborted patch makes the run exit with 1** (status `partial`), so a host that is
  never patched, e.g. because its healthchecks fail before patching or its simulation
  is refused, shows up in `systemctl --failed`. It still raises no alert and sends a
  mail only when the reason is new. Before, such a run exited with 0.

## 0.10.0 (2026-11-23)

### Upgrade notes

- **No helper or configuration change is needed.** Ubuntu hosts are added like Debian
  hosts (see the README, "Ubuntu hosts"); keep the `osv` source enabled, it is their
  only source. Helper 4 works on Ubuntu 24.04 and 26.04 (sudo-rs) as it is.
- **A host that no source covers now fails** instead of showing 0 findings with a
  warning. A Debian host is affected only if its release is missing from the tracker
  and OSV is disabled, or in `--offline` runs with an empty tracker cache.
- **Definitions:** `release: any` keeps covering every Debian release. Definitions for
  Ubuntu name their releases, and older central hosts accept them (they warn about an
  unknown release).

### Ubuntu

- **Ubuntu hosts are scanned through OSV.** The `osv` source queries Canonical's
  records in the ecosystems `Ubuntu:24.04:LTS`, `Ubuntu:25.10` etc. (LTS: April
  releases of even years). `UBUNTU-CVE-*` ids are reported as `CVE-*`. A fix in a
  record is published, so the finding is `fixable`; without a fix it is `no-fix`.
  Tested on Ubuntu 24.04 and 26.04: every fixable finding had an apt candidate that
  reaches the fix.
- **Ubuntu Pro.** OSV's Pro ecosystem (`Ubuntu:Pro:24.04:LTS`) is queried as well. It
  is not an addition to the release's data but covers other packages: universe
  packages in esm-apps (223 on 24.04, e.g. 7zip, catdoc), which the release's data
  does not cover, and on releases past standard support the release's fixes
  (esm-infra). A Pro fix
  stays `fixable` and is marked `needs noble-apps-security (Ubuntu Pro)` (report,
  status page, host warning, held back by patch previews) unless the host's apt
  sources include that pocket, the same way as a missing `trixie-security` on Debian.
- **Security notices without a CVE.** Some Ubuntu fixes exist only as a USN (e.g.
  xz-utils USN-8945-1, sudo-rs USN-8708-1, ca-certificates updates). A USN is reported
  as `USN-…` where no CVE record of the package covers one of its CVEs; regression
  notices are skipped.
- **Severity:** Ubuntu's priority `negligible` counts like Debian's `unimportant`
  (`low`, before CVSS); `low` to `critical` are used after CVSS like Debian's urgency.
  The reason says `ubuntu priority: medium`.
- **End of support.** The inventory reads the host's
  `/usr/share/distro-info/ubuntu.csv`. Past standard support, the host gets a warning
  (also in `hosts check`): `Ubuntu 20.04 LTS (focal) is out of standard support since
  2025-05-29: security fixes only through Ubuntu Pro (ESM until 2030-04-23)`, and
  after that, or for interim releases, `out of support … no security fixes`.
- **OSV failures fail Ubuntu hosts.** OSV is their only source, so when its query
  fails they fail with `no vulnerability data for Ubuntu 24.04 LTS (noble): osv: …`
  instead of showing 0 findings.
- **Links:** on Ubuntu hosts, CVEs link to `ubuntu.com/security/CVE-…` in alert mails
  and on the status page (where every host listing the CVE runs Ubuntu), USNs to
  `ubuntu.com/security/notices/`.
- **Custom definitions on Ubuntu:** name the release (`release: noble`). `release:
  any` keeps meaning every Debian release and no longer applies to Ubuntu hosts, whose
  versions differ per release. No new field: older aptwarden versions accept such
  definitions and only warn about an unknown release. Ubuntu codenames are known, so
  `defs validate` does not warn about them. Blocks and pins follow the same rule.
- **A Pro marker survives a definition:** when a definition decides a finding and
  names the same fixed version as OSV, the finding keeps OSV's `needs …-security
  (Ubuntu Pro)`.
- **Patching Ubuntu hosts works unchanged:** tested on 24.04 (87 packages) and 26.04
  (57 packages, sudo-rs as `sudo`) in Proxmox LXCs with snapshot, needrestart, ssh,
  systemd and HTTP healthchecks, and a rollback on both. The helper needs no change.
- **A fix only in a repository the host lacks** (e.g. Ubuntu Pro) is skipped by patch
  runs with that reason, `fixed version … is only in noble-apps-security (Ubuntu Pro),
  which the host's apt sources lack`, instead of guessing at mirrors and point
  releases.
- **OSV skips withdrawn records**, and a record without any entry for the queried
  ecosystem and package no longer counts as affecting it (OSV matches ecosystems
  loosely).

### Hosts and inventory

- **A host no source has data for fails instead of looking clean.** Before, such a
  host (an Ubuntu host, or a Debian release the tracker lacks while OSV is disabled)
  got only a warning and 0 findings. Now it fails with
  `no vulnerability source covers Ubuntu 24.04 LTS (noble)`, and `hosts check` notes
  `no vulnerability source covers this release`. OSV does not count in `--offline` runs.
- **Distribution detection.** The inventory records `distro` (`debian` or `ubuntu`)
  and `os_version`. Debian derivatives (`ID_LIKE=debian`) count as Debian as before;
  Ubuntu derivatives such as Linux Mint are refused, because Ubuntu's data does not
  cover their own repositories.
- **Release shown per distribution:** `Debian 13.1 (trixie)`, `Ubuntu 24.04 LTS
  (noble)` in the report, the status page and `hosts check`. On Ubuntu,
  `/etc/debian_version` names the Debian base (`trixie/sid`); it stays in the JSON
  summary as `debian_version`.
- **apt sources on Ubuntu:** Ubuntu's Release files name the bare codename for every
  pocket, so the suites come from the sources entries there (`noble-security`).

### Helper package

- **Releases on GitHub.** For every release tag, once all checks passed, CI creates a
  GitHub release with the helper package, the SBOM and `SHA256SUMS`, so they stay
  downloadable without a login (workflow artifacts expire). The maintainer adds
  `SHA256SUMS.sig`, an SSH signature by the release key, verified with
  `ssh-keygen -Y verify` and the `release_signers` file.
- **README: apt repository setup in full,** including a pin that allows only
  `aptwarden-helper` from that repository. aptwarden runs no public repository on
  purpose; SECURITY.md explains why.

## 0.9.1 (2026-11-23)

### Upgrade notes

- **Patch hosts no longer need the newest helper.** Only hosts with `enforce_block: pin`
  need helper version 4; patching works with helper 3 again. This corrects the 0.9.0
  upgrade note: hosts that patch but do not pin need no reinstall.

### Helper package

- **The helper as a Debian package, for fleets.** `aptwarden-helper_<version>_all.deb`
  (version = helper version) installs the helper as `/usr/lib/aptwarden/aptwarden-helper`,
  writes `/etc/sudoers.d/aptwarden` after checking it with `visudo -c`, and creates the
  user `aptwarden` if it is missing (the SSH key is still yours to add). It links
  `/usr/local/lib/aptwarden/aptwarden-helper` to the packaged helper, replacing one the
  installer script left there, so the default `ssh.helper` works for hosts with and
  without the package. Install and update it through your own signed apt repository or
  configuration management; the README shows `apt install ./…deb`, reprepro and
  Ansible. CI builds it reproducibly, installs, upgrades and removes it in a Debian 13
  container, and attaches it to release tags (`aptwarden-helper-deb` artifact).
  `tools/build-helper-deb` builds it locally.
- **The installer script refuses to run where the package is installed,** since it
  would overwrite the package's link and sudoers rule.
- SECURITY.md: new section "Distributing the helper". The central host still has no
  way to install or replace the helper.

### Patching

- **A minimum helper version per feature instead of the exact version.** Patching needs
  helper 3 or newer, `enforce_block: pin` needs 4 or newer, and helpers newer than this
  aptwarden knows are accepted. Raising the helper version for a new feature therefore
  no longer stops patching on every host until it is reinstalled. A helper that is too
  old for a feature is refused with the feature and the version it needs, e.g.
  `outdated helper (aptwarden-helper 3; enforce_block: pin needs version 4 or newer)`.
- **`hosts check` shows what the helper can do,** e.g. `helper 3 ok (pin needs 4)`, and
  `helper NOT ready` only when the host uses a feature the helper is too old for.

## 0.9.0 (2026-11-23)

### Upgrade notes

- **Reinstall the helper on every patch host** and on hosts that use
  `enforce_block: pin` (`aptwarden helper show --install`, see the README, "Target
  hosts: helper and sudo"). The helper is now version 4; until it is updated, patch runs
  abort on that host with `outdated helper` and change nothing.

### Definitions

- **`policy.enforce_block: pin` keeps blocked versions off the host.** Each report run
  pins the available versions that a `block` definition marks as known-bad to priority
  -1 in `/etc/apt/preferences.d/aptwarden-block`, so a manual `apt upgrade` or
  unattended-upgrades cannot install them either. The helper's new `pin` command
  writes the file; the scan calls it only when the pins change and removes them when
  the definition ends or the host goes back to `alert` (the default). The host shows
  `blocked versions pinned away: …` while pins are active, and a warning if they could
  not be written. `hosts check` checks the helper on hosts that only pin.

### Reporting

- **Fixes a host cannot install are flagged.** A scan now reads the host's package
  sources (`apt-get indextargets`, no root needed). A fixable vulnerability whose fix is
  only in a repository the host lacks, usually `trixie-security`, stays `fixable` but is
  marked `needs trixie-security`, and the host gets a warning such as `apt sources lack
  trixie-security: 12 fixable vulnerabilities in 4 packages cannot be installed until it
  is added`. The warning appears in the report, the summary mail and on the status page,
  which lists it under Needs attention. The JSON output has `missing_source` per finding.
- **`hosts check` notes `apt sources lack <codename>-security`** for hosts without a
  security source, and `apt sources unknown` where apt cannot list them.
- Patch previews on the status page hold back packages whose fix is in a missing
  source.

### Status page

- **The patch history shows versions.** Each patched source package is listed with its
  version before and after the run, e.g. `openssl 3.5.1-1 → 3.5.4-1`, instead of only
  its name. Runs already in the history show them too.

### CLI

- **`aptwarden patches` lists versions.** Below each run, its source packages are
  listed with their old and new version.

### Patching

- **Dependency upgrade notes name the old version as well**, e.g.
  `dependency upgrade libc6 2.41-12 -> 2.41-12+deb13u4`.

## 0.8.1 (2026-11-19)

### Upgrade notes

- **Copy the systemd units again** (`aptwarden-report.service`,
  `aptwarden-patch.service`) and run `systemctl daemon-reload`, see the README,
  "Upgrading".

### Notifications

- **A night with patch windows sends one mail.** With `patch_summary: digest` the patch
  results already went into the 06:00 report, but the scan before each patch run still
  sent its own vulnerability alert: new critical/KEV findings, and reminders, which come
  back `remind_after` after the run that last sent them, so at the time of whichever
  window that was. Hosts patched at 02:00 and 04:00 caused an alert at each. Now these
  alerts wait for the next report. Patch problems, hosts that cannot be reached and
  source problems still alert immediately. `patch_summary: immediate` keeps the old
  behaviour.
- **The report sends its alert and summary as one mail.** The alert is on top, the
  summary below it, and the subject starts with `ALERT:` followed by the summary's
  counts. `X-Aptwarden-Kind` is `alert`, so a mail filter on it still catches it.

### Fixes

- **The report no longer fails when a patch run ends at the same time.** Both units
  used `RuntimeDirectory=aptwarden`, and systemd removes that directory when either
  unit stops, even while the other still runs. When the hourly patch run finished
  during the 06:00 report, the report lost the directory holding its SSH control
  sockets, exited with `[Errno 2] No such file or directory: '/run/aptwarden/aptw-…'`
  and sent no summary. Each unit now has its own runtime directory
  (`/run/aptwarden-report`, `/run/aptwarden-patch`).

## 0.8.0 (2026-11-13)

### Upgrade notes

- **Reinstall the helper on every patch host** (`aptwarden helper show --install`, see
  the README, "Target hosts: helper and sudo"). The helper is now version 3; until it is
  updated, patch runs abort on that host with `outdated helper` and change nothing.

### Patching

- **`restart: auto` restarts services again.** The helper ran `needrestart -r a -b`, and
  needrestart's batch mode only lists services: nothing was ever restarted, while the
  patch result said `restarted: …`. Patched hosts kept running the old library code
  until someone restarted the services. The helper now restarts without batch mode and
  asks needrestart again afterwards. `restarted` lists only what really was restarted;
  services needrestart left alone (e.g. dbus) or that still need a restart are in a note
  of the result. Hosts patched by earlier versions may still run old code: check them
  with `needrestart` or reboot them.
- **An unexpected error no longer skips the rollback.** The patch pipeline only handled
  its own error types. Anything else, e.g. an HTTP healthcheck against a service that
  died mid-response after the update (`http.client.IncompleteRead`), ended the whole
  patch run with a traceback: the host stayed patched without a rollback, nothing was
  stored, no alert was sent and the remaining hosts were not patched. Now a healthcheck
  that cannot be carried out is a failed check, and any error in the pipeline is handled
  like a failure of its stage: aborted before the snapshot, rolled back (or `failed` /
  `needs-manual-rollback`) after it, `rollback-failed` if the rollback itself crashes.
  The run continues with the next host.
- The Proxmox client reports a response that is not the expected JSON, or a missing task
  id, as a snapshot error instead of crashing.

## 0.7.0 (2026-11-13)

### Notifications

- **Patch results go into the morning report by default** (`notify.patch_summary:
  digest`). The hourly patch timer sent a mail after every run that patched something,
  so hosts with maintenance windows spread over the night caused one mail per window.
  Now the next report summary lists the patch runs since the previous summary under
  **Patch runs since the last summary** and counts them in its subject
  (`· 3 patched`). With `summary: changes` a summary goes out when there is a patch run
  to report, even if no vulnerability changed.
- Patch problems (rolled back, failed, manual rollback needed) still send an immediate
  alert. `patch_summary: immediate` restores the previous behaviour.
- A patch run still in progress when the report runs is listed in the following summary,
  and a summary that could not be delivered keeps its patch runs for the next one.

## 0.6.0 (2026-11-06)

### Patching

- **Hosts skipped because a dependency failed are in the patch history** with status
  `skipped` and the reason, e.g. `dependency proxy01 failed`. Before, they were only in
  the run's report and mail, so `aptwarden patches` and the status page could not tell
  a deliberate skip from a host the run never reached. Dry runs and hosts skipped for
  their window or modes are still not stored.
- A stored skip does not count as the host's last patch run. The snapshot cleanup still
  keeps a snapshot needed for a manual rollback when a later run skipped the host
  (without this, the skip would have released it), and an abort after a skip is still
  recognised as repeated, so it sends no new mail.

### Status page

- Needs attention, the hosts table and `last_patch` / `last_patch_at` in `status.json`
  use the last run that actually ran: a failed host that is then skipped stays listed.
  Skips neither count towards nor interrupt a streak of aborted runs. The host's patch
  history shows the skip.
- **Vulnerabilities** names up to 6 hosts per vulnerability. With more it shows
  `all 40 hosts`, `all 40 hosts except web07` (up to 3 named) or a collapsed list.
  Before, a vulnerability on 40 hosts listed 40 links in its row.
- **would patch** in the hosts table names at most 3 packages and counts the rest
  (`openssl, curl, tar +9 more (4 critical, 11 high)`); the full list is in the tooltip
  and in the host's details.
- Measured with 40 similar hosts sharing 30 vulnerabilities in 12 packages: the page is
  6% smaller (508 to 478 kB, gzip 8.3 to 8.1 kB). With 4 hosts it grows by 0.3 kB (two
  CSS rules).

### CLI

- `hosts check` names the server's time zone for hosts without `timezone`:
  `next window Sat 2026-11-07 02:00 CET (server local time, Europe/Zurich)`. Before, it
  said only `server local time`, which hid a central host in an unexpected zone.

### Upgrade notes

- No manual steps: configuration, helper (version 2), systemd units, the database and
  the format of `status.json` are unchanged. The page is rewritten by the next report.
- `last_patch` in `status.json` behaves as before: the stored skips are left out, so it
  still shows the host's last run that ran.
- Hosts skipped for a failed dependency before this version are not in the history;
  only skips from now on are stored.

## 0.5.0 (2026-11-05)

### Status page

- **Needs attention** shows a fixable known exploited (KEV) vulnerability once, with all
  hosts that have it, instead of one entry per host. The fixed version is given once, or
  per host where they differ. `needs_attention` in `status.json` still counts per host
  and problem, so monitoring rules are unaffected.
- The trend chart is smaller: a step line no longer repeats a point when a value is
  unchanged, and coordinates have one decimal at most. It looks the same.
- Table headers carry `scope="col"` for screen readers.
- Links to a host open its collapsed details instead of only scrolling to them. Tested
  with Chrome 156, Firefox 157, Firefox ESR 153 and WebKit 27.2.
- Vulnerability descriptions are on the page only once, in a new **Vulnerabilities**
  section at the end with severity, CVSS, KEV, description and affected hosts. Host
  tables link their IDs there; that row links to the Debian tracker. With 40 similar
  hosts the page is 36% smaller (75% with gzip). With 4 hosts that share fewer
  vulnerabilities it is 9% larger uncompressed but 21% smaller with gzip.

### Upgrade notes

- No manual steps: configuration, helper (version 2), systemd units and the format of
  `status.json` are unchanged. The page is rewritten by the next report.

## 0.4.0 (2026-11-03)

### Security

- **The root helper installs only the simulated transaction (helper version 2).**
  `install` now simulates the transaction itself right before installing and refuses
  it if apt would install a package that was not named as `package=version`, another
  version, or remove anything. `--no-remove` is set for `simulate` and `install`.
  Before, the check ran only on the central host: if the package lists changed between
  that simulation and the install, a different transaction ran unchecked, and
  `--only-upgrade` still installed new dependencies. With `allow_extra_upgrades` or
  `allow_new_packages`, the central host now passes the allowed extras explicitly.
  A refusal ends the patch run as `aborted` (nothing changed, no rollback).
- **Host addresses can no longer start with `-` or contain whitespace.** The config
  loader refuses them, and the SSH transport refuses them again before running `ssh`.
  An address like `-oProxyCommand=…` used to reach ssh's argument list as an option.
  It was not exploitable with OpenSSH 9.6 or later, which rejects such a host name,
  so this adds a layer of defence in depth.
- **Definition tags must carry an SSH signature.** git verifies a tag in the format of
  its signature and ignores `gpg.format=ssh` for that, so an OpenPGP-signed tag was
  checked against the keyring of the user aptwarden runs as instead of
  `allowed_signers`. Tags whose signature is not SSH are now rejected before
  `verify-tag`, and git runs with `gpg.openpgp.program=false` and
  `gpg.x509.program=false`. The README's command for verifying a release tag sets the
  same options.

### Hardening

- Package names, versions and architectures reported by a target host must match what
  dpkg accepts, otherwise the host's inventory fails. Control characters in CLI output,
  text logs and error messages with remote output are escaped, so a host cannot
  rewrite the terminal or fake log lines.
- Only well-formed CVE ids (`CVE-YYYY-NNNN…`) are looked up at OSV and NVD, and every
  id that goes into a request URL is URL-encoded.
- `aptwarden rollback` and `aptwarden snapshots cleanup` take the patch lock and fail
  while a patch run is active. `rollback` asks its question before taking the lock, so
  an unanswered prompt does not block patch runs, and stops if the snapshots changed in
  the meantime.
- `notify.email` with a `username` and `security: none` is refused at config load and
  before login, so the SMTP password is never sent without TLS.
- The systemd units add `SystemCallFilter=@system-service`, `ProtectProc=invisible`,
  `ProcSubset=pid`, `PrivateIPC`, `RemoveIPC` and `MemoryDenyWriteExecute`.
- The nginx example repeats the HSTS header in its `location` (a local `add_header`
  hides the server block's), and the publishing guide uses bcrypt (`htpasswd -B`) and
  checks the web server's host key fingerprint before recording it.
- CI: checkouts keep no credentials, the security tools are pinned with hashes, and
  ShellCheck, CodeQL, zizmor and gitleaks run in addition to bandit and pip-audit.

### Upgrade notes

- **Reinstall the helper on every patch host:** `aptwarden helper show --install | ssh
  root@TARGET sh`. Until then, patch runs on that host abort with `outdated helper
  (aptwarden-helper 1, expected version 2)`. Report-only hosts are not affected.
- **Copy the systemd units again** from `contrib/systemd/` and run
  `systemctl daemon-reload`.
- A configuration with `notify.email.username` and `security: none` no longer loads.
  Use `starttls` or `ssl`, or drop the login.
