"""CLI entry point for MCP Shield v2.

Usage:
    py -3 -m mcp_shield scan <source> [--name NAME] [--format text|json|markdown]
    py -3 -m mcp_shield live <mcp_name>
    py -3 -m mcp_shield approve <mcp_name> [--yes] [--audit-file FILE]
    py -3 -m mcp_shield report [--name NAME] [--format text|json]

Exit codes:
    0 = clean (no findings or info only)
    1 = warnings (medium/low findings)
    2 = critical/high findings found
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_shield import __version__


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="MCP Shield v2 — Security audit framework for MCP servers.",
    )
    parser.add_argument(
        "--version", action="version", version=f"mcp-shield {__version__}"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-essential output"
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    scan_p = sub.add_parser(
        "scan", help="Audit an MCP server from source (GitHub URL or npm package)"
    )
    scan_p.add_argument("source", help="GitHub URL or npm package name")
    scan_p.add_argument("--name", help="Override MCP server name")
    scan_p.add_argument("--npm-package", help="Treat source as npm package name")
    scan_p.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    scan_p.add_argument("--output", "-o", type=Path, help="Write report to file")
    scan_p.add_argument(
        "--keep",
        action="store_true",
        help="Keep temporary directory after audit for inspection",
    )
    scan_p.add_argument(
        "--sandbox",
        action="store_true",
        help="Run sandbox analysis after the scan",
    )

    # --- live ---
    live_p = sub.add_parser(
        "live", help="Fetch live tools and compare against last approval"
    )
    live_p.add_argument(
        "mcp_name", nargs="?", help="MCP server name (as in settings.json)"
    )
    live_p.add_argument(
        "--all",
        action="store_true",
        help="Check all approved MCPs against their current live state",
    )

    # --- approve ---
    approve_p = sub.add_parser(
        "approve", help="Run approval workflow for an MCP server"
    )
    approve_p.add_argument("mcp_name", help="MCP server name")
    approve_p.add_argument(
        "--yes", "-y", action="store_true", help="Auto-approve without prompt"
    )
    approve_p.add_argument(
        "--audit-file", type=Path, help="Load audit result from JSON file"
    )
    approve_p.add_argument("--settings", type=Path, help="Path to Claude settings.json")

    # --- report ---
    report_p = sub.add_parser(
        "report", help="Show last audit results from approval store"
    )
    report_p.add_argument("--name", help="Filter by MCP server name")
    report_p.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    return parser


def _exit_code_from_result(result: "AuditResult") -> int:
    """Determine exit code from audit result."""
    from mcp_shield.core.models import Severity

    for f in result.findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            return 2
    if result.findings:
        return 1
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan subcommand."""
    from mcp_shield.core.engine import AuditEngine
    from mcp_shield.core.registry import create_default_registry
    from mcp_shield.formatters.json import to_json, to_json_file
    from mcp_shield.formatters.terminal import (
        format_full_report,
        format_summary,
    )

    registry = create_default_registry()
    engine = AuditEngine(registry)

    if not args.quiet:
        print(f"[*] MCP Shield v{__version__} — scanning {args.source}")

    try:
        result = engine.run(
            source=args.source,
            name=args.name,
            npm_package=args.npm_package,
            keep=args.keep,
        )
    except Exception as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        return 2

    # Format output
    if args.format == "json":
        output = to_json(result)
    elif args.format == "markdown":
        output = format_full_report(result)
    else:
        output = format_summary(result)

    # Write or print
    if args.output:
        if args.format == "json":
            to_json_file(result, args.output)
        else:
            args.output.write_text(output, encoding="utf-8")
        if not args.quiet:
            print(f"[+] Report written to {args.output}")
    else:
        print(output)

    # Always print summary in text mode if writing to file
    if args.output and args.format != "text" and not args.quiet:
        print()
        print(format_summary(result))

    # Auto-save JSON and Markdown reports
    from datetime import datetime as _dt

    audit_dir = Path.home() / ".config" / "mcp-shield" / "audits"
    audit_dir.mkdir(parents=True, exist_ok=True)
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    safe_name = (result.name or "unknown").replace("/", "_").replace("@", "")
    json_path = audit_dir / f"audit_{safe_name}_{ts}.json"
    md_path = audit_dir / f"audit_{safe_name}_{ts}.md"
    to_json_file(result, json_path)
    md_path.write_text(format_full_report(result), encoding="utf-8")
    if not args.quiet:
        print(f"[+] Auto-saved: {json_path}")
        print(f"[+] Auto-saved: {md_path}")

    # Run sandbox if requested
    if args.sandbox:
        from mcp_shield.runtime.sandbox import run_sandbox

        if not args.quiet:
            print("[*] Running sandbox analysis...")
        try:
            sandbox_result = run_sandbox(
                source=args.source,
                name=result.name,
            )
            if not args.quiet:
                print(f"[+] Sandbox completed: {sandbox_result.status}")
        except Exception as exc:
            print(f"[!] Sandbox failed: {exc}", file=sys.stderr)

    return _exit_code_from_result(result)


def _cmd_live(args: argparse.Namespace) -> int:
    """Execute the live subcommand."""
    from mcp_shield.approval.store import ApprovalStore
    from mcp_shield.approval.workflow import check_approved

    store = ApprovalStore()

    # --all: check every approved MCP
    if args.all:
        return _cmd_live_all(store)

    if not args.mcp_name:
        print("[!] Please specify an MCP name or use --all.")
        return 1

    return _check_single_live(args.mcp_name, store)


def _cmd_live_all(store: "ApprovalStore") -> int:
    """Check all approved MCPs against their current live state."""
    from mcp_shield.approval.store import ApprovalStore

    entries = store.list_approved()
    if not entries:
        print("[!] No approved MCPs found. Run 'scan' and 'approve' first.")
        return 0

    settings = _load_mcp_settings()
    if settings is None:
        return 1

    mcp_servers = settings.get("mcpServers", {})
    total_alerts = 0
    checked = 0

    for entry in entries:
        name = entry["name"]
        mcp_config = mcp_servers.get(name)
        if not mcp_config:
            print(f"[~] '{name}' — not found in settings, skipping.")
            continue

        command = mcp_config.get("command", "")
        mcp_args = mcp_config.get("args", [])
        env = mcp_config.get("env")
        if not command:
            print(f"[~] '{name}' — no command defined, skipping.")
            continue

        from mcp_shield.approval.workflow import check_approved
        from mcp_shield.fetcher.live import fetch_live_tools

        print(f"[*] Checking '{name}'...")
        live_tools = fetch_live_tools(command, mcp_args, env)
        if live_tools is None:
            print(f"[!] '{name}' — could not connect.")
            total_alerts += 1
            continue

        checked += 1
        alerts = check_approved(store, live_tools, name)
        if alerts:
            print(f"[!] '{name}' — {len(alerts)} change(s):")
            for alert in alerts:
                print(f"    - {alert}")
            total_alerts += len(alerts)
        else:
            print(f"[+] '{name}' — OK")

    print()
    print(
        f"[*] Checked {checked}/{len(entries)} approved MCPs, {total_alerts} alert(s)."
    )
    return 2 if total_alerts > 0 else 0


def _load_mcp_settings() -> dict | None:
    """Load MCP settings from known Claude config paths."""
    settings_path = None
    for candidate in [
        Path.home() / ".claude.json",
        Path.home() / ".claude" / "settings.json",
        Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    ]:
        if candidate.exists():
            settings_path = candidate
            break

    if not settings_path:
        print("[!] Cannot locate Claude settings to determine MCP command.")
        return None

    try:
        return json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Cannot read settings: {exc}")
        return None


def _check_single_live(mcp_name: str, store: "ApprovalStore") -> int:
    """Check a single MCP against its approval record."""
    from mcp_shield.approval.workflow import check_approved
    from mcp_shield.fetcher.live import fetch_live_tools

    entry = store.get(mcp_name)
    if not entry:
        print(f"[!] '{mcp_name}' has no approval record. Run 'scan' first.")
        return 1

    settings = _load_mcp_settings()
    if settings is None:
        return 1

    mcp_config = settings.get("mcpServers", {}).get(mcp_name)
    if not mcp_config:
        print(f"[!] MCP '{mcp_name}' not found in settings.")
        return 1

    command = mcp_config.get("command", "")
    mcp_args = mcp_config.get("args", [])
    env = mcp_config.get("env")

    if not command:
        print(f"[!] No command defined for MCP '{mcp_name}'")
        return 1

    print(f"[*] Fetching live tools from '{mcp_name}'...")
    live_tools = fetch_live_tools(command, mcp_args, env)

    if live_tools is None:
        print("[!] Could not connect to MCP server.")
        return 2

    print(f"[*] Got {len(live_tools)} live tools.")

    alerts = check_approved(store, live_tools, mcp_name)

    if alerts:
        print()
        print(f"[!] {len(alerts)} change(s) detected since approval:")
        for alert in alerts:
            print(f"    - {alert}")
        return 2
    else:
        print("[+] No changes detected. Tools match approved state.")
        return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    """Execute the approve subcommand."""
    from mcp_shield.approval.store import ApprovalStore
    from mcp_shield.approval.workflow import approve_mcp
    from mcp_shield.core.models import AuditResult
    from mcp_shield.formatters.json import to_json

    store = ApprovalStore()

    # Load audit result
    if args.audit_file:
        if not args.audit_file.exists():
            print(f"[!] Audit file not found: {args.audit_file}")
            return 1
        try:
            data = json.loads(args.audit_file.read_text(encoding="utf-8"))
            result = _audit_result_from_dict(data)
        except Exception as exc:
            print(f"[!] Failed to load audit file: {exc}")
            return 1
    else:
        # Check if we have a cached result
        cache_dir = Path.home() / ".config" / "mcp-shield" / "cache"
        cache_file = cache_dir / f"{args.mcp_name}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                result = _audit_result_from_dict(data)
            except Exception:
                print(
                    f"[!] No valid audit result for '{args.mcp_name}'. Run 'scan' first."
                )
                return 1
        else:
            print(
                f"[!] No audit result for '{args.mcp_name}'. Run 'scan' first, or use --audit-file."
            )
            return 1

    settings_path = getattr(args, "settings", None)
    approved = approve_mcp(
        result=result,
        store=store,
        settings_path=settings_path,
        auto_yes=args.yes,
    )

    return 0 if approved else 1


def _cmd_report(args: argparse.Namespace) -> int:
    """Execute the report subcommand."""
    from mcp_shield.approval.store import ApprovalStore

    store = ApprovalStore()
    entries = store.list_approved()

    if args.name:
        entries = [e for e in entries if e["name"] == args.name]

    if not entries:
        msg = f"No approval records found"
        if args.name:
            msg += f" for '{args.name}'"
        print(msg + ".")
        return 0

    if args.format == "json":
        print(json.dumps(entries, indent=2, ensure_ascii=False))
    else:
        print(f"{'Name':<25} {'Grade':<8} {'Tools':<8} {'Approved':<22} Source")
        print("-" * 90)
        for e in entries:
            print(
                f"{e['name']:<25} {e['grade']:<8} {e['tool_count']:<8} "
                f"{e['approved_at'][:19]:<22} {e['source'][:40]}"
            )

    return 0


def _audit_result_from_dict(data: dict) -> "AuditResult":
    """Reconstruct an AuditResult from a JSON dict.

    This handles the reverse of JSON serialization, rebuilding
    dataclass instances from plain dicts.
    """
    from mcp_shield.core.models import (
        AuditResult,
        Finding,
        PromptInfo,
        ResourceInfo,
        Severity,
        Surface,
        ToolInfo,
    )

    findings = []
    for fd in data.get("findings", []):
        findings.append(
            Finding(
                rule_id=fd["rule_id"],
                severity=Severity(fd["severity"]),
                surface=Surface(fd["surface"]),
                title=fd["title"],
                evidence=fd["evidence"],
                location=fd["location"],
                detail=fd.get("detail", ""),
            )
        )

    tools_static = []
    for td in data.get("tools_static", []):
        tools_static.append(
            ToolInfo(
                name=td["name"],
                description=td.get("description", ""),
                input_schema=td.get("input_schema", {}),
                output_schema=td.get("output_schema", {}),
                annotations=td.get("annotations", {}),
                source=td.get("source", ""),
                file=td.get("file", ""),
                line=td.get("line", 0),
            )
        )

    tools_live = []
    for td in data.get("tools_live", []):
        tools_live.append(
            ToolInfo(
                name=td["name"],
                description=td.get("description", ""),
                input_schema=td.get("input_schema", {}),
                output_schema=td.get("output_schema", {}),
                annotations=td.get("annotations", {}),
                source=td.get("source", ""),
                file=td.get("file", ""),
                line=td.get("line", 0),
            )
        )

    resources = []
    for rd in data.get("resources", []):
        resources.append(
            ResourceInfo(
                uri=rd["uri"],
                name=rd.get("name", ""),
                description=rd.get("description", ""),
                mime_type=rd.get("mime_type", ""),
            )
        )

    prompts = []
    for pd in data.get("prompts", []):
        prompts.append(
            PromptInfo(
                name=pd["name"],
                description=pd.get("description", ""),
                arguments=pd.get("arguments", []),
            )
        )

    return AuditResult(
        name=data.get("name", "unknown"),
        source=data.get("source", ""),
        findings=findings,
        tools_static=tools_static,
        tools_live=tools_live,
        resources=resources,
        prompts=prompts,
        health=data.get("health", {}),
        deps=data.get("deps", {}),
        urls=data.get("urls", []),
        pinned_version=data.get("pinned_version", {}),
        deprecated_msg=data.get("deprecated_msg", ""),
        sdk_info=data.get("sdk_info", {}),
        sbom=data.get("sbom", {}),
        dep_audit=data.get("dep_audit", ""),
        transitive_audit=data.get("transitive_audit", ""),
        timestamp=data.get("timestamp", ""),
    )


def main(argv: list[str] | None = None) -> None:
    """Main entry point for the CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "scan": _cmd_scan,
        "live": _cmd_live,
        "approve": _cmd_approve,
        "report": _cmd_report,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(0)

    try:
        code = handler(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        code = 130
    except Exception as exc:
        print(f"[!] Fatal error: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        code = 2

    sys.exit(code)
