"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys

from aptwarden import __version__, config, report
from aptwarden import log as aplog
from aptwarden.models import HostInventory, Severity
from aptwarden.sources import SourceStatus

EXIT_OK, EXIT_PROBLEM, EXIT_USAGE = 0, 1, 2


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", action="append", metavar="NAME",
                   help="limit to this host (repeatable)")
    p.add_argument("--format", choices=["text", "json"], default="text")
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
    _add_output_args(p)

    p = sub.add_parser("hosts", help="host management")
    hsub = p.add_subparsers(dest="hosts_command", metavar="SUBCOMMAND", required=True)
    hc = hsub.add_parser("check", help="test connectivity and inventory collection")
    hc.add_argument("--host", action="append", metavar="NAME")

    p = sub.add_parser("sources", help="vulnerability data sources")
    ssub = p.add_subparsers(dest="sources_command", metavar="SUBCOMMAND", required=True)
    sr = ssub.add_parser("refresh", help="update cached feeds")
    sr.add_argument("--force", action="store_true", help="ignore refresh intervals")

    p = sub.add_parser("config", help="configuration")
    csub = p.add_subparsers(dest="config_command", metavar="SUBCOMMAND", required=True)
    cc = csub.add_parser("check", help="validate the configuration")
    cc.add_argument("--dump", action="store_true", help="print the effective configuration")

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


def cmd_hosts_check(args, cfg: config.Config) -> int:
    from aptwarden.runner import Runner

    hosts = cfg.select_hosts(args.host)
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
        rows.append([h.name, h.address, "ok", f"{r.debian_version} ({r.codename})",
                     str(len(r.packages)), ", ".join(notes)])
    print("\n".join(report.format_table(rows, indent="")))
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


def cmd_config_check(args, cfg: config.Config) -> int:
    if args.dump:
        print(json.dumps(cfg.raw, indent=2))
    else:
        print(f"configuration ok: {cfg.path} ({len(cfg.hosts)} hosts)")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    if args.command == "version":
        print(f"aptwarden {__version__}")
        return EXIT_OK
    try:
        cfg = config.load(args.config)
    except config.ConfigError as e:
        print(f"aptwarden: {e}", file=sys.stderr)
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
