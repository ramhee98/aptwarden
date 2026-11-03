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

### Upgrade notes

- **Reinstall the helper on every patch host:** `aptwarden helper show --install | ssh
  root@TARGET sh`. Until then, patch runs on that host abort with `outdated helper
  (aptwarden-helper 1, expected version 2)`. Report-only hosts are not affected.
