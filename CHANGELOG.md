# Changelog

Release notes for aptwarden. Versions before 0.4.0 are described in their release
commits.

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
