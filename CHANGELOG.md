# Changelog

Release notes for aptwarden. Versions before 0.4.0 are described in their release
commits.

## Unreleased

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
  schema refuses them, and the SSH transport refuses them again before running `ssh`.
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

### Upgrade notes

- **Reinstall the helper on every patch host:** `aptwarden helper show --install | ssh
  root@TARGET sh`. Until then, patch runs on that host abort with `outdated helper
  (aptwarden-helper 1, expected version 2)`. Report-only hosts are not affected.
