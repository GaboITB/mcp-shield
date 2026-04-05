"""CLI entry point for MCP Shield v3.

Usage:
    python3 -m mcp_shield scan <source> [--name NAME] [--format text|json|html]
    python3 -m mcp_shield live <mcp_name>
    python3 -m mcp_shield approve <mcp_name> [--yes] [--audit-file FILE]
    python3 -m mcp_shield report [--name NAME] [--format text|json]
    python3 -m mcp_shield detect
    python3 -m mcp_shield sandbox <source> --name NAME
    python3 -m mcp_shield bait-switch <command> [args...]

Exit codes:
    0 = clean (no findings or info only)
    1 = warnings (medium/low findings)
    2 = critical/high findings found
"""

from __future__ import annotations

import sys

from mcp_shield.cli._cmd_live import cmd_live
from mcp_shield.cli._cmd_other import (
    cmd_approve,
    cmd_bait_switch,
    cmd_detect,
    cmd_report,
    cmd_sandbox,
)
from mcp_shield.cli._cmd_scan import cmd_scan
from mcp_shield.cli._parser import build_parser


def main(argv: list[str] | None = None) -> None:
    """Main entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "scan": cmd_scan,
        "live": cmd_live,
        "approve": cmd_approve,
        "report": cmd_report,
        "detect": cmd_detect,
        "sandbox": cmd_sandbox,
        "bait-switch": cmd_bait_switch,
    }

    handler = dispatch.get(args.subcommand)
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
