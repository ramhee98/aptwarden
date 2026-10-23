"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys

from aptwarden import __version__, config, report
from aptwarden import log as aplog
from aptwarden.models import HostInventory, Severity
from aptwarden.sources import SourceStatus

EXIT_OK, EXIT_PROBLEM, EXIT_USAGE = 0, 1, 2


def _add_output_args(p: argparse.ArgumentParser, formats=("text", "json")) -> None:
    p.add_argument("--host", action="append", metavar="NAME",
                   help="limit to this host (repeatable)")
    p.add_argument("--format", choices=list(formats), default="text",
                   help="html: render the status page to stdout" if "html" in formats else None)
    p.add_argument("--min-severity", choices=[str(s) for s in Severity],
                   help="hide packages below this severity (text output)")
    p.add_argument("--all", action="store_true",
                   help="also list vulnerabilities without an available fix")
    p.add_argument("--cves", action="store_true", help="list every vulnerability per package")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aptwarden", description="CVE monitoring and controlled patching for Debian hosts")
    parser.add_argument("-c", "--config", help=f"config file (default: $APTWARDEN_CONFIG or "
                                               f"{config.DEFAULT_PATH})")
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("report", help="inventory hosts, match vulnerabilities, report")
    _add_output_args(p)
    p.add_argument("--offline", action="store_true",
                   help="no network access for vulnerability data, use the cache only")
    p.add_argument("--force-refresh", action="store_true",
                   help="download feeds even if the cache is fresh")
    p.add_argument("--no-notify", action="store_true",
                   help="do not send notifications for this run")

    p = sub.add_parser("status", help="show the latest stored results (no scanning)")
    _add_output_args(p, formats=("text", "json", "html"))

    p = sub.add_parser("hosts", help="host management")
    hsub = p.add_subparsers(dest="hosts_command", metavar="SUBCOMMAND", required=True)
    hc = hsub.add_parser("check", help="test connectivity and inventory collection")
    hc.add_argument("--host", action="append", metavar="NAME")
    hc.add_argument("--accept-new", action="store_true",
                    help="record the SSH host key of hosts not yet in known_hosts (trust on "
                         "first use; changed keys are still refused) and print it for checking")

    p = sub.add_parser("sources", help="vulnerability data sources")
    ssub = p.add_subparsers(dest="sources_command", metavar="SUBCOMMAND", required=True)
    sr = ssub.add_parser("refresh", help="update cached feeds")
    sr.add_argument("--force", action="store_true", help="ignore refresh intervals")

    p = sub.add_parser("config", help="configuration")
    csub = p.add_subparsers(dest="config_command", metavar="SUBCOMMAND", required=True)
    cc = csub.add_parser("check", help="validate the configuration")
    cc.add_argument("--dump", action="store_true", help="print the effective configuration")

    p = sub.add_parser("patch", help="patch hosts (snapshot, update, healthcheck, rollback)")
    p.add_argument("--host", action="append", metavar="NAME")
    p.add_argument("--dry-run", action="store_true",
                   help="plan and simulate only, change nothing")
    p.add_argument("--ignore-window", action="store_true",
                   help="patch outside the maintenance window")
    p.add_argument("--no-notify", action="store_true")
    p.add_argument("--format", choices=["text", "json"], default="text")

    p = sub.add_parser("rollback", help="roll a host back to an aptwarden snapshot")
    p.add_argument("--host", required=True, metavar="NAME")
    p.add_argument("--snapshot", help="snapshot name (default: the newest one of this host)")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    p = sub.add_parser("snapshots", help="aptwarden's snapshots")
    snsub = p.add_subparsers(dest="snapshots_command", metavar="SUBCOMMAND", required=True)
    sl = snsub.add_parser("list", help="snapshots recorded by aptwarden")
    sl.add_argument("--host", action="append", metavar="NAME")
    sc = snsub.add_parser("cleanup", help="delete snapshots older than snapshots.keep")
    sc.add_argument("--host", action="append", metavar="NAME")
    sc.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("patches", help="patch history")
    p.add_argument("--host", metavar="NAME")
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("helper", help="the root helper for target hosts")
    hsub2 = p.add_subparsers(dest="helper_command", metavar="SUBCOMMAND", required=True)
    hs = hsub2.add_parser("show", help="print the helper script (or the sudoers rule)")
    hs.add_argument("--sudoers", action="store_true")

    p = sub.add_parser("defs", help="custom vulnerability definitions")
    dsub = p.add_subparsers(dest="defs_command", metavar="SUBCOMMAND", required=True)
    dv = dsub.add_parser("validate", help="validate a definitions directory (no config needed)")
    dv.add_argument("path", help="directory with definition files, e.g. definitions/")
    dsync = dsub.add_parser("sync", help="fetch, verify and activate definitions now")
    dsync.add_argument("--force", action="store_true", help="ignore refresh_interval")
    dsub.add_parser("list", help="show the active definitions")

    p = sub.add_parser("notify", help="notifications")
    nsub = p.add_subparsers(dest="notify_command", metavar="SUBCOMMAND", required=True)
    nsub.add_parser("test", help="send a test message through every configured notifier")

    sub.add_parser("version", help="print the version")
    return parser


def _min_severity(args, cfg: config.Config) -> Severity:
    return Severity.parse(args.min_severity or cfg.report["min_severity"])


def _show_all(args, cfg: config.Config) -> bool:
    return args.all or cfg.report["show"] == "all"


def cmd_report(args, cfg: config.Config) -> int:
    from aptwarden.runner import Runner

    hosts = cfg.select_hosts(args.host)
    runner = Runner(cfg, offline=args.offline)
    try:
        run = runner.report(hosts, force_refresh=args.force_refresh,
                            notify=not args.no_notify)
    finally:
        runner.close()
    if args.format == "json":
        out = report.render_json(run.hosts, run.sources, run_id=run.run_id, status=run.status,
                                 started_at=run.started_at, finished_at=run.finished_at,
                                 notes=run.notes)
    else:
        out = report.render_text(
            run.hosts, run.sources, min_severity=_min_severity(args, cfg),
            show_all=_show_all(args, cfg), show_cves=args.cves, notes=run.notes,
            title=f"aptwarden report · run {run.run_id} · status {run.status}")
    sys.stdout.write(out)
    return EXIT_OK if run.status == "ok" else EXIT_PROBLEM


def cmd_status(args, cfg: config.Config) -> int:
    from aptwarden.state import State

    state = State(cfg.state_dir / "state.db")
    if args.format == "html":
        from aptwarden import statuspage

        try:
            sys.stdout.write(statuspage.render(cfg, state))
        finally:
            state.close()
        return EXIT_OK
    records = []
    last_run = None
    try:
        for h in cfg.select_hosts(args.host):
            latest = state.latest(h.name)
            if latest is None:
                continue
            rec = latest if latest.ok else (state.latest(h.name, ok_only=True) or latest)
            if rec is not latest:
                rec.warnings = [f"latest scan ({latest.scanned_at}) failed: {latest.error}; "
                                f"showing results from {rec.scanned_at}"] + rec.warnings
            records.append(rec)
            if last_run is None or rec.run_id > last_run:
                last_run = rec.run_id
        info = state.run_info(last_run) if last_run else None
    finally:
        state.close()
    if not records:
        print("no results stored yet, run 'aptwarden report' first", file=sys.stderr)
        return EXIT_PROBLEM
    sources = [SourceStatus(**s) for s in (info or {}).get("data", {}).get("sources", [])]
    if args.format == "json":
        sys.stdout.write(report.render_json(records, sources, run_id=last_run))
    else:
        sys.stdout.write(report.render_text(
            records, sources, min_severity=_min_severity(args, cfg),
            show_all=_show_all(args, cfg), show_cves=args.cves,
            title=f"aptwarden status · latest run {last_run}"))
    return EXIT_OK


def _patch_readiness(h: config.HostConfig, runner_cfg: config.Config) -> list[str]:
    """Problems that would stop patching this host."""
    from aptwarden.patch.runner import explain_helper_failure
    from aptwarden.runner import Runner
    from aptwarden.snapshot import SnapshotError
    from aptwarden.transport import TransportError, TransportFactory

    notes = []
    factory = TransportFactory()
    try:
        t = factory.create(h)
        try:
            r = t.run(["sudo", "-n", h.ssh.helper, "version"], timeout=30)
            problem = explain_helper_failure(r, h.ssh.helper)
            if problem:
                notes.append("helper NOT ready: " + problem.rsplit("; see README", 1)[0])
            else:
                notes.append("helper ok")
        except TransportError as e:
            notes.append(f"helper check failed: {e}")
        finally:
            t.close()
    finally:
        factory.cleanup()
    if not h.healthchecks:
        notes.append("no healthchecks (patching would abort)")
    if h.snapshot["provider"] == "none":
        notes.append("no snapshots" + ("" if h.policy["allow_without_snapshot"]
                                       else " (patching would abort)"))
    else:
        runner = Runner(runner_cfg, offline=True)
        try:
            problems = runner.provider(h).check()
            notes.append("snapshot ok" if not problems else "snapshot NOT ready: " + problems[0])
        except SnapshotError as e:
            notes.append(f"snapshot NOT ready: {e}")
        finally:
            runner.close()
    return notes


def cmd_hosts_check(args, cfg: config.Config) -> int:
    from aptwarden.runner import Runner

    hosts = cfg.select_hosts(args.host)
    unknown: set[str] = set()
    if args.accept_new:
        from dataclasses import replace

        from aptwarden.transport import known_host_keys

        for h in hosts:
            if h.transport == "ssh" and not known_host_keys(h.address, h.ssh.port,
                                                            h.ssh.known_hosts_file):
                unknown.add(h.name)
                # only for this check; regular runs keep the configured strict mode
                h.ssh = replace(h.ssh, strict_host_key_checking="accept-new")
    runner = Runner(cfg, offline=True)
    try:
        tracker = next((s for s in runner.sources if s.name == "debian_tracker"), None)
        releases = tracker.releases() if tracker else set()
        results = runner.collect(hosts)
    finally:
        runner.close()
    rows = [["HOST", "ADDRESS", "RESULT", "RELEASE", "PACKAGES", "NOTES"]]
    failed = 0
    for h in hosts:
        r = results[h.name]
        if not isinstance(r, HostInventory):
            failed += 1
            rows.append([h.name, h.address, "FAIL", "-", "-", str(r)])
            continue
        notes = []
        if releases and r.codename not in releases:
            notes.append("release not in tracker cache")
        if not releases:
            notes.append("tracker cache empty, run 'aptwarden sources refresh'")
        for key in ("needrestart_installed", "reboot_required"):
            if r.facts.get(key) == "yes":
                notes.append(key.replace("_", " "))
        if r.facts.get("unattended_upgrade_periodic", "0") not in ("", "0"):
            notes.append("unattended-upgrades active")
        if "patch" in h.policy["modes"] or "dry-run" in h.policy["modes"]:
            notes += _patch_readiness(h, runner_cfg=cfg)
        rows.append([h.name, h.address, "ok", f"{r.debian_version} ({r.codename})",
                     str(len(r.packages)), ", ".join(notes)])
    print("\n".join(report.format_table(rows, indent="")))
    if args.accept_new:
        from aptwarden.transport import known_host_keys

        for h in hosts:
            if h.name not in unknown:
                continue
            keys = known_host_keys(h.address, h.ssh.port, h.ssh.known_hosts_file)
            if keys:
                print(f"{h.name}: new host key recorded: {', '.join(keys)}")
            else:
                print(f"{h.name}: no host key recorded (host not reachable?)")
        if unknown:
            print("Compare with the host's own fingerprint: "
                  "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
        else:
            print("all selected hosts were already in known_hosts, nothing recorded")
    return EXIT_PROBLEM if failed else EXIT_OK


def cmd_sources_refresh(args, cfg: config.Config) -> int:
    from aptwarden.runner import Runner

    runner = Runner(cfg)
    try:
        statuses = runner.refresh(force=args.force)
    finally:
        runner.close()
    sys.stdout.write(report.render_text([], statuses, min_severity=Severity.UNKNOWN))
    return EXIT_OK if all(s.ok for s in statuses) else EXIT_PROBLEM


def cmd_notify_test(args, cfg: config.Config) -> int:
    import socket

    from aptwarden.notify import Dispatcher, Message
    from aptwarden.state import State

    state = State(cfg.state_dir / "state.db")
    try:
        dispatcher = Dispatcher(cfg, state)
        if not dispatcher.notifiers:
            print("no notifier enabled (see notify.email in the configuration)",
                  file=sys.stderr)
            return EXIT_USAGE
        msg = Message("test", f"{cfg.notify['subject_prefix']} test message",
                      f"Test message from aptwarden {__version__} on {socket.getfqdn()}.\n"
                      "If you can read this, notifications work.\n")
        errors = dispatcher.send(msg)
    finally:
        state.close()
    for e in errors:
        print(f"aptwarden: {e}", file=sys.stderr)
    if not errors:
        print(f"sent via {', '.join(n.name for n in dispatcher.notifiers)}")
    return EXIT_PROBLEM if errors else EXIT_OK


def cmd_defs_validate(args) -> int:
    from pathlib import Path

    from aptwarden.definitions import load_dir

    path = Path(args.path)
    if not path.is_dir():
        print(f"aptwarden: {path} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    result = load_dir(path)
    for w in result.warnings:
        print(f"warning: {w}")
    for e in result.errors:
        print(f"error: {e}")
    print(f"{len(result.definitions)} valid definitions, {len(result.errors)} errors")
    return EXIT_OK if result.ok else EXIT_PROBLEM


def _custom_source(cfg: config.Config, offline: bool = False):
    from aptwarden.cache import Cache
    from aptwarden.http import HttpClient
    from aptwarden.sources.custom import CustomSource
    from aptwarden.state import State

    state = State(cfg.state_dir / "state.db")
    cache = Cache(cfg.cache_dir / "cache.db")
    source = CustomSource(cfg.sources["custom"], cache, HttpClient(), offline, state=state,
                          base_dir=cfg.base_dir)
    return source, (state, cache)


def cmd_defs_sync(args, cfg: config.Config) -> int:
    if not cfg.sources["custom"]["enabled"]:
        print("custom definitions are disabled (sources.custom.enabled)", file=sys.stderr)
        return EXIT_USAGE
    source, handles = _custom_source(cfg)
    try:
        status = source.refresh(force=args.force)
    finally:
        for h in handles:
            h.close()
    print(f"definitions: {status.message}")
    for w in status.warnings:
        print(f"warning: {w}")
    for a in status.alerts:
        print(f"PROBLEM: {a}")
    return EXIT_PROBLEM if status.alerts or any("sync failed" in w for w in status.warnings) \
        else EXIT_OK


def cmd_defs_list(args, cfg: config.Config) -> int:
    source, handles = _custom_source(cfg, offline=True)
    try:
        status = source.refresh()
        defs = source.definitions()
    finally:
        for h in handles:
            h.close()
    print(f"definitions: {status.message}")
    if defs:
        rows = [["ID", "PACKAGE", "SEVERITY", "ACTION", "RELEASES", "ALIASES", "SUMMARY"]]
        for d in sorted(defs, key=lambda d: d.id):
            rows.append([d.id + (" (expired)" if d.expired() else ""), d.package, d.severity,
                         d.action, ",".join(d.affected), ",".join(d.aliases) or "-",
                         report.truncate(d.summary, 50)])
        print("\n".join(report.format_table(rows, indent="")))
    return EXIT_OK


def _patch_text(run) -> str:
    from aptwarden.notify import _patch_lines

    lines = [f"aptwarden {run.command} · run {run.run_id} · status {run.status}", ""]
    for p in run.patches:
        lines += _patch_lines(p, packages=p.dry_run)
        lines += [f"  health now: {x}" for x in p.health_before] if p.dry_run else []
        lines.append("")
    lines += [f"note: {n}" for n in run.notes]
    return "\n".join(lines).rstrip() + "\n"


def cmd_patch(args, cfg: config.Config) -> int:
    from aptwarden.runner import Runner

    runner = Runner(cfg)
    try:
        run = runner.patch(cfg.select_hosts(args.host), dry_run=args.dry_run,
                           ignore_window=args.ignore_window,
                           notify=not args.no_notify and not args.dry_run)
    except RuntimeError as e:
        print(f"aptwarden: {e}", file=sys.stderr)
        return EXIT_PROBLEM
    finally:
        runner.close()
    if args.format == "json":
        print(json.dumps({"run_id": run.run_id, "status": run.status, "notes": run.notes,
                          "patches": [p.to_dict() for p in run.patches]}, indent=2))
    else:
        sys.stdout.write(_patch_text(run))
    return EXIT_OK if run.status == "ok" else EXIT_PROBLEM


def cmd_rollback(args, cfg: config.Config) -> int:
    from aptwarden.patch.runner import PatchRunner
    from aptwarden.runner import Runner, new_run_id
    from aptwarden.snapshot import SnapshotRef
    from aptwarden.transport import TransportFactory

    [host] = cfg.select_hosts([args.host])
    runner = Runner(cfg, offline=True)
    factory = TransportFactory()
    try:
        snaps = runner.state.snapshots(host.name, ("active", "rolled-back"))
        if args.snapshot:
            snaps = [s for s in snaps if s["name"] == args.snapshot]
        if not snaps:
            print(f"aptwarden: no active aptwarden snapshot for {host.name}"
                  + (f" named {args.snapshot}" if args.snapshot else ""), file=sys.stderr)
            return EXIT_PROBLEM
        snap = snaps[0]
        if not args.yes:
            answer = input(f"Roll {host.name} back to {snap['name']} ({snap['created_at']})? "
                           "Everything written since then is lost. [y/N] ")
            if answer.strip().lower() not in ("y", "yes"):
                return EXIT_USAGE
        ref = SnapshotRef(snap["provider"], snap["target"], snap["name"])
        transport = factory.create(host)
        try:
            result = PatchRunner(runner.state, []).manual_rollback(
                host, transport, runner.provider(host), ref, new_run_id())
        finally:
            transport.close()
    finally:
        factory.cleanup()
        runner.close()
    print(f"{host.name}: {result.status} ({result.reason})")
    for x in result.health_after:
        print(f"  health: {x}")
    return EXIT_OK if result.status == "rolled-back" else EXIT_PROBLEM


def cmd_snapshots_list(args, cfg: config.Config) -> int:
    from aptwarden.state import State

    state = State(cfg.state_dir / "state.db")
    try:
        rows = [["HOST", "SNAPSHOT", "TARGET", "CREATED", "STATE", "RUN"]]
        for h in cfg.select_hosts(args.host):
            for snap in state.snapshots(h.name, state=None):
                rows.append([h.name, snap["name"], snap["target"], snap["created_at"],
                             snap["state"], snap["run_id"]])
    finally:
        state.close()
    print("\n".join(report.format_table(rows, indent="")))
    return EXIT_OK


def cmd_snapshots_cleanup(args, cfg: config.Config) -> int:
    from aptwarden.runner import Runner

    runner = Runner(cfg, offline=True)
    try:
        notes = runner.cleanup_snapshots(cfg.select_hosts(args.host), dry_run=args.dry_run)
    finally:
        runner.close()
    print("\n".join(notes) if notes else "nothing to clean up")
    return EXIT_OK


def cmd_patches(args, cfg: config.Config) -> int:
    from aptwarden.state import State

    state = State(cfg.state_dir / "state.db")
    try:
        history = state.patches(args.host, args.limit)
    finally:
        state.close()
    rows = [["STARTED", "HOST", "STATUS", "PACKAGES", "SNAPSHOT", "REASON"]]
    for p in history:
        pkgs = [i["source_package"] for i in p["items"]]
        rows.append([p["started_at"], p["host"], p["status"],
                     f"{len(pkgs)}: {report.truncate(','.join(pkgs), 30)}" if pkgs else "-",
                     (p.get("snapshot") or {}).get("name", "-"),
                     report.truncate(p["reason"], 60)])
    print("\n".join(report.format_table(rows, indent="")))
    return EXIT_OK


def cmd_helper_show(args) -> int:
    from importlib import resources

    name = "helper/sudoers" if args.sudoers else "helper/aptwarden-helper"
    sys.stdout.write(resources.files("aptwarden").joinpath(name).read_text())
    return EXIT_OK


def cmd_config_check(args, cfg: config.Config) -> int:
    if args.dump:
        print(json.dumps(cfg.raw, indent=2))
    else:
        print(f"configuration ok: {cfg.path} ({len(cfg.hosts)} hosts)")
    return EXIT_OK


# Commands that never write to the state or cache directories.
_READ_ONLY = {"config", "version", "helper"}


def ownership_problem(dirs, euid: int, owner_of=lambda p: p.stat().st_uid) -> str | None:
    """Running as root on directories that belong to the service user would
    create root-owned files the service can no longer read (e.g. the status
    page). Returns an error message, or None if all is well."""
    if euid != 0:
        return None
    for d in dirs:
        try:
            uid = owner_of(d)
        except OSError:
            continue  # not created yet
        if uid != 0:
            try:
                import pwd

                user = pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError):
                user = str(uid)
            return (f"{d} belongs to {user!r}, not root: running as root would create files "
                    f"{user!r} cannot read. Run as that user instead: "
                    f"runuser -u {user} -- aptwarden ...")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    if args.command == "version":
        print(f"aptwarden {__version__}")
        return EXIT_OK
    if args.command == "defs" and args.defs_command == "validate":
        return cmd_defs_validate(args)
    if args.command == "helper":
        return cmd_helper_show(args)
    try:
        cfg = config.load(args.config)
    except config.ConfigError as e:
        print(f"aptwarden: {e}", file=sys.stderr)
        return EXIT_USAGE

    if args.command not in _READ_ONLY:
        problem = ownership_problem([cfg.state_dir, cfg.cache_dir], os.geteuid())
        if problem:
            print(f"aptwarden: {problem}", file=sys.stderr)
            return EXIT_USAGE

    level = "debug" if args.verbose else "warning" if args.quiet else cfg.log["level"]
    aplog.setup(level, cfg.log["format"])

    handlers = {
        "report": cmd_report,
        "status": cmd_status,
        ("hosts", "check"): cmd_hosts_check,
        ("sources", "refresh"): cmd_sources_refresh,
        ("config", "check"): cmd_config_check,
        ("notify", "test"): cmd_notify_test,
        "patch": cmd_patch,
        "rollback": cmd_rollback,
        "patches": cmd_patches,
        ("snapshots", "list"): cmd_snapshots_list,
        ("snapshots", "cleanup"): cmd_snapshots_cleanup,
        ("defs", "sync"): cmd_defs_sync,
        ("defs", "list"): cmd_defs_list,
    }
    sub = getattr(args, f"{args.command}_command", None)
    handler = handlers[(args.command, sub) if sub else args.command]
    try:
        return handler(args, cfg)
    except config.ConfigError as e:
        print(f"aptwarden: {e}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as e:  # e.g. state or cache directory not writable
        print(f"aptwarden: {e}", file=sys.stderr)
        return EXIT_PROBLEM
    except KeyboardInterrupt:
        return 130
