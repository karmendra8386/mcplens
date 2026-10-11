"""mcplens command-line interface.

Commands:
  mcplens scan     --cmd "..." | --config cfg.json [--name X] | --url URL
                   [--probes] [--format text|json]
  mcplens baseline (same target flags) [--out mcplens-baseline.json]
  mcplens diff     (same target flags) [--baseline mcplens-baseline.json]

Exit codes: scan -> 1 if any critical finding, else 0.
            diff -> 1 if tool definitions drifted from the baseline.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .baseline import diff_snapshot, load_snapshot, make_snapshot, save_snapshot
from .models import ScanReport
from .report import render_diff, render_text
from .rules import analyze_tools
from .transport import Target, fetch_tools


def _add_target_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("target (pick one)")
    g.add_argument("--cmd", metavar="COMMAND",
                   help='stdio server command, e.g. --cmd "python server.py"')
    g.add_argument("--config", metavar="PATH",
                   help="client config JSON (mcpServers format)")
    g.add_argument("--name", metavar="SERVER",
                   help="server name inside --config (required if it holds several)")
    g.add_argument("--url", metavar="URL",
                   help="streamable HTTP MCP endpoint URL")


def _resolve_target(args: argparse.Namespace) -> Target:
    if getattr(args, "url", None):
        return Target.from_url(args.url)
    if getattr(args, "config", None):
        return Target.from_config(args.config, args.name)
    if getattr(args, "cmd", None):
        return Target.from_command(args.cmd)
    raise SystemExit("error: specify a target with --cmd, --config, or --url")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcplens",
        description="MCP server security scanner with runtime behavioral verification.",
    )
    parser.add_argument("--version", action="version", version=f"mcplens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="enumerate tools, run static rules, optionally probe behavior")
    _add_target_args(p_scan)
    p_scan.add_argument("--probes", action="store_true",
                        help="run dynamic canary probes in a sandbox (stdio targets only)")
    p_scan.add_argument("--format", choices=("text", "json"), default="text")

    p_base = sub.add_parser("baseline", help="save a hash snapshot of tool definitions")
    _add_target_args(p_base)
    p_base.add_argument("--out", default="mcplens-baseline.json",
                        help="snapshot file to write (default: mcplens-baseline.json)")

    p_diff = sub.add_parser("diff", help="compare current tool definitions against a baseline")
    _add_target_args(p_diff)
    p_diff.add_argument("--baseline", default="mcplens-baseline.json",
                        help="snapshot file to compare against (default: mcplens-baseline.json)")
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    target = _resolve_target(args)
    report = ScanReport(target_label=target.label, transport=target.kind)

    probe_findings = []
    if args.probes:
        if target.kind != "stdio":
            print("error: --probes requires a stdio target (--cmd or --config)", file=sys.stderr)
            return 2
        from .probes import run_probes
        run = run_probes(target)
        report.tools = run.tools
        report.probes = run.results
        report.probes_run = True
        probe_findings = run.findings
    else:
        report.tools = fetch_tools(target)

    static_findings = analyze_tools(report.tools,
                                    target_url=target.url if target.kind == "http" else "")
    report.findings = static_findings + probe_findings

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report))
    return 1 if any(f.severity == "critical" for f in report.findings) else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    target = _resolve_target(args)
    tools = fetch_tools(target)
    snapshot = make_snapshot(tools, label=target.label)
    save_snapshot(snapshot, args.out)
    print(f"Baseline saved to {args.out}")
    print(f"  target:    {target.label}")
    print(f"  tools:     {len(tools)}")
    print(f"  set hash:  {snapshot['set_sha256']}")
    for t in tools:
        print(f"    {t.name:<32} {snapshot['tools'][t.name]['sha256'][:16]}…")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    target = _resolve_target(args)
    try:
        snapshot = load_snapshot(args.baseline)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load baseline: {exc}", file=sys.stderr)
        return 2
    tools = fetch_tools(target)
    result = diff_snapshot(snapshot, tools)
    print(render_diff(result, target.label))
    return 1 if result.has_changes else 0


def _flatten(exc: BaseException) -> str:
    """One-line message for an exception, unwrapping exception groups."""
    if isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        return _flatten(exc.exceptions[0])
    return str(exc) or type(exc).__name__


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "baseline":
            return cmd_baseline(args)
        if args.command == "diff":
            return cmd_diff(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BaseExceptionGroup as group:  # transport/task-group failures
        print(f"error: {_flatten(group)}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
