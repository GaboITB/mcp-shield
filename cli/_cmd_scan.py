"""Scan command implementations."""

from __future__ import annotations

import argparse
import copy
import glob as _glob
import json
import sys
from pathlib import Path

from mcp_shield import __version__
from mcp_shield.core.paths import get_audit_dir
from mcp_shield.cli._layers import (
    run_bait_switch_layer,
    run_live_layer,
    run_sandbox_layer,
)
from mcp_shield.cli._parser import _RE_ANSI, sanitize_filename
from mcp_shield.cli._utils import (
    exit_code_from_result,
    find_mcp_command,
    find_mcp_command_from_repo,
)


def cmd_scan_all(args: argparse.Namespace) -> int:
    """Scan all MCP servers detected on this system."""
    from mcp_shield.core.config_finder import find_mcp_configs

    quiet = getattr(args, "quiet", False)
    no_open = getattr(args, "no_open", False)

    if not quiet:
        print(
            f"[*] MCP Shield v{__version__} -- scanning all detected MCPs", flush=True
        )

    servers = find_mcp_configs()
    if not servers:
        print(
            "[!] No MCP servers found. Configure MCPs in Claude Desktop, Cursor, etc."
        )
        return 0

    if not quiet:
        print(
            f"[+] Found {len(servers)} MCP server(s): {', '.join(s.name for s in servers)}"
        )
        print()

    results: list[tuple[str, str, int]] = []  # (name, grade, score)
    worst_exit = 0

    for server in servers:
        if not quiet:
            print(f"{'='*60}")
            print(f"[*] Scanning: {server.name}")
            print(f"    Command: {server.command} {' '.join(server.args[:2])}")
            print(f"{'='*60}")

        # Build a fake args namespace for each scan
        scan_args = copy.copy(args)
        scan_args.source = server.source_file  # Use config file path as source hint
        scan_args.name = server.name
        scan_args.all = False
        scan_args.no_open = True  # Don't open browser for each individual scan

        # Determine the source path -- find the package root (not dist/)
        # Walk up from the entry point until we find package.json or pyproject.toml
        source_path = None
        for a in server.args:
            p = Path(a)
            if p.exists():
                candidate = p.parent if p.is_file() else p
                # Walk up to find package root
                for parent in [candidate] + list(candidate.parents):
                    if (parent / "package.json").exists() or (
                        parent / "pyproject.toml"
                    ).exists():
                        source_path = parent
                        break
                if not source_path:
                    source_path = candidate
                break
        # Fallback: try to resolve from command itself (for binaries)
        if not source_path:
            cmd_path = Path(server.command)
            if cmd_path.exists() and cmd_path.is_file():
                source_path = cmd_path.parent

        if source_path and source_path.is_dir():
            scan_args.source = str(source_path)
        else:
            if not quiet:
                print(f"[~] Could not resolve source path for {server.name}, skipping")
                print()
            results.append((server.name, "?", 0, 0))
            continue

        try:
            exit_code = cmd_scan(scan_args)
            worst_exit = max(worst_exit, exit_code)
        except Exception as exc:
            if not quiet:
                print(f"[!] Scan failed for {server.name}: {exc}")
            results.append((server.name, "ERR", 0, 0))
            continue

        # Read the latest audit result for the summary
        audit_dir = get_audit_dir()
        latest = sorted(
            _glob.glob(
                str(audit_dir / f"audit_{sanitize_filename(server.name)}_*.json")
            )
        )
        if latest:
            try:
                data = json.loads(Path(latest[-1]).read_text(encoding="utf-8"))
                n_findings = len(data.get("findings", []))
                results.append(
                    (
                        server.name,
                        data.get("grade", "?"),
                        data.get("total_score", 0),
                        n_findings,
                    )
                )
            except Exception:
                results.append((server.name, "?", 0, 0))
        else:
            results.append((server.name, "?", 0, 0))

        if not quiet:
            print()

    # Print consolidated summary
    if not quiet:
        total_findings = sum(r[3] for r in results)
        print(f"\n{'='*60}")
        print(
            f"[*] SCAN ALL -- SUMMARY ({len(results)} servers, {total_findings} findings)"
        )
        print(f"{'='*60}")
        print(f"  {'Name':<25} {'Grade':<8} {'Score':<8} {'Findings':<8}")
        print(f"  {'-'*25} {'-'*8} {'-'*8} {'-'*8}")
        for name, grade, score, nf in results:
            print(f"  {name:<25} {grade:<8} {score:<8} {nf:<8}")
        print()

    if not quiet and not no_open:
        audit_dir = get_audit_dir()
        print(f"[+] All reports saved in: {audit_dir}")

    return worst_exit


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand."""
    from mcp_shield.core.engine import AuditEngine
    from mcp_shield.core.registry import create_default_registry
    from mcp_shield.formatters.json import to_json, to_json_file
    from mcp_shield.formatters.terminal import (
        format_findings,
        format_full_report,
        format_summary,
        format_verdict,
    )

    # Handle --all: scan every detected MCP
    if getattr(args, "all", False):
        return cmd_scan_all(args)

    if not args.source:
        print("[!] Please specify a source or use --all.", file=sys.stderr)
        return 1

    # Sanitize --name to prevent path traversal and OS errors
    if args.name:
        args.name = sanitize_filename(args.name)

    quiet = getattr(args, "quiet", False)

    # For non-text formats, redirect progress logs to stderr so stdout
    # contains only the formatted output (parseable JSON/SARIF/clean HTML/MD).
    _structured_fmt = args.format in ("json", "sarif", "html", "markdown")
    _log_stream = sys.stderr if _structured_fmt else None  # None = stdout

    registry = create_default_registry()
    engine = AuditEngine(registry, quiet=quiet, log_stream=_log_stream)

    is_full = getattr(args, "full", False)
    do_sandbox = getattr(args, "sandbox", False) or is_full

    if not quiet:
        mode = "FULL audit (layers 1+2+3)" if is_full else "scanning"
        print(
            f"[*] MCP Shield v{__version__} -- {mode} {args.source}",
            flush=True,
            file=_log_stream,
        )

    # -- Layer 1: Static scan ------------------------------------------------
    if not quiet and is_full:
        print(f"\n{'='*60}", file=_log_stream)
        print("[*] LAYER 1: Static source code analysis", file=_log_stream)
        print(f"{'='*60}", file=_log_stream)

    try:
        result = engine.run(
            source=args.source,
            name=args.name,
            npm_package=args.npm_package,
            keep=args.keep or is_full,
            no_ignore=getattr(args, "no_ignore", False),
        )
    except Exception as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        return 2

    # -- Resolve MCP command for live/bait-switch layers ---------------------
    live_command = getattr(args, "live_command", None)
    live_args = getattr(args, "live_args", None) or []
    mcp_env: dict[str, str] | None = None

    if not live_command and is_full:
        # Try to find command from installed configs
        mcp_config = find_mcp_command(result.name)
        if mcp_config:
            live_command, live_args, mcp_env = mcp_config
            if not quiet:
                print(
                    f"[+] Found MCP config: {live_command} "
                    f"{' '.join(live_args[:3])}{'...' if len(live_args) > 3 else ''}",
                    file=_log_stream,
                )
        else:
            # Try to infer command from the cloned/scanned repo
            repo_dir = engine._tmp_dir / result.name if engine._tmp_dir else None
            local_source = Path(args.source)
            if repo_dir and repo_dir.is_dir():
                search_path = repo_dir
            elif local_source.is_dir():
                search_path = local_source
            else:
                search_path = None
            if search_path:
                repo_config = find_mcp_command_from_repo(search_path)
                if repo_config:
                    live_command, live_args, mcp_env = repo_config
                    if not quiet:
                        print(
                            f"[+] Inferred MCP command from repo: {live_command} "
                            f"{' '.join(live_args[:3])}{'...' if len(live_args) > 3 else ''}",
                            file=_log_stream,
                        )

    # -- Layer 1b: Live protocol analysis ------------------------------------
    if live_command:
        run_live_layer(engine, result, live_command, live_args, mcp_env, quiet)

    # -- Layer 2: Sandbox ----------------------------------------------------
    if do_sandbox:
        run_sandbox_layer(
            args.source,
            result.name,
            result,
            getattr(args, "sandbox_network", "none"),
            quiet,
        )

    # -- Layer 3: Bait-and-switch --------------------------------------------
    if is_full and live_command:
        run_bait_switch_layer(live_command, live_args, result, quiet, env=mcp_env)
    elif is_full and not live_command and not quiet:
        print(
            "\n[~] Bait-and-switch skipped: no MCP command found. "
            "Use --live-command to specify, or install the MCP in a "
            "client config first.",
            file=_log_stream,
        )

    # -- Final report --------------------------------------------------------
    # Apply --suppress filter
    suppress_raw = getattr(args, "suppress", None)
    if suppress_raw:
        suppressed = {s.strip() for s in suppress_raw.split(",")}
        actual_rules = {f.rule_id for f in result.findings}
        unknown = suppressed - actual_rules
        if unknown and not quiet:
            print(
                f"[~] Unknown suppression rule(s) (no matching findings): "
                f"{', '.join(sorted(unknown))}",
                file=sys.stderr,
            )
        before = len(result.findings)
        result.findings = [f for f in result.findings if f.rule_id not in suppressed]
        after = len(result.findings)
        if not quiet and before != after:
            print(
                f"[~] Suppressed {before - after} finding(s): {', '.join(sorted(suppressed & actual_rules))}",
                file=_log_stream,
            )

    if is_full and not quiet:
        print(f"\n{'='*60}", file=_log_stream)
        print("[*] CONSOLIDATED REPORT", file=_log_stream)
        print(f"{'='*60}", file=_log_stream)

    # Format output
    if args.format == "json":
        output = to_json(result)
    elif args.format == "markdown":
        output = format_full_report(result)
    elif args.format == "html":
        from mcp_shield.formatters.html import format_html_report

        output = format_html_report(result)
    elif args.format == "sarif":
        from mcp_shield.formatters.sarif import format_sarif

        output = format_sarif(result)
    else:
        output = (
            format_summary(result)
            + "\n\n"
            + format_findings(result)
            + "\n"
            + format_verdict(result)
        )

    # Write or print -- strip ANSI codes when writing to file
    if args.output:
        if args.format == "json":
            to_json_file(result, args.output)
        else:
            clean_output = _RE_ANSI.sub("", output)
            args.output.write_text(clean_output, encoding="utf-8")
        if not quiet:
            print(f"[+] Report written to {args.output}", file=_log_stream)
    elif not quiet or args.format != "text":
        # Non-text formats are always emitted even in --quiet mode — they're
        # the primary output, not human noise. --quiet only suppresses the
        # text report and progress messages.
        print(output)

    # Always print summary in text mode if writing to file
    if args.output and args.format != "text" and not quiet:
        print(file=_log_stream)
        print(format_summary(result), file=_log_stream)

    # Auto-save JSON, Markdown, and HTML reports
    from datetime import datetime as _dt

    audit_dir = get_audit_dir()
    audit_dir.mkdir(parents=True, exist_ok=True)
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_filename(result.name or "unknown")
    json_path = audit_dir / f"audit_{safe_name}_{ts}.json"
    md_path = audit_dir / f"audit_{safe_name}_{ts}.md"
    html_path = audit_dir / f"audit_{safe_name}_{ts}.html"
    to_json_file(result, json_path)
    md_path.write_text(format_full_report(result), encoding="utf-8")

    # Always generate and auto-open HTML report
    from mcp_shield.formatters.html import format_html_report as _fmt_html

    html_content = _fmt_html(result)
    html_path.write_text(html_content, encoding="utf-8")

    if not quiet:
        print(f"[+] Auto-saved: {json_path}", file=_log_stream)
        print(f"[+] Auto-saved: {html_path}", file=_log_stream)

    # Auto-open HTML report in default browser (unless --no-open or --quiet)
    no_open = getattr(args, "no_open", False)
    if not quiet and not no_open:
        import webbrowser

        try:
            webbrowser.open(html_path.as_uri())
            print("[+] Report opened in browser", file=_log_stream)
        except Exception:
            print(
                f"[~] Could not open browser -- report at: {html_path}",
                file=_log_stream,
            )

    return exit_code_from_result(result, fail_on=getattr(args, "fail_on", None))
