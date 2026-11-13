# Changelog

Release notes for aptwarden. Versions before 0.4.0 are described in their release
commits.

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
