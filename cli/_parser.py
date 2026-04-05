"""Argument parser construction for MCP Shield CLI."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from mcp_shield import __version__

_RE_SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._-]")
_RE_ANSI = re.compile(r"\033\[[0-9;]*m")


def sanitize_filename(name: str) -> str:
    """Sanitize a string for safe use as a filename component.

    Strips path separators, traversal sequences, and special characters.
    Returns only alphanumeric, dots, hyphens, and underscores.
    """
    # Remove path traversal and separators first
    name = name.replace("..", "").replace("/", "_").replace("\\", "_")
    # Replace any remaining unsafe characters
    name = _RE_SAFE_FILENAME.sub("_", name)
    # Collapse repeated underscores and strip leading/trailing
    name = re.sub(r"_+", "_", name).strip("_.")
    return name[:100] or "unknown"


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="MCP Shield v3 — Security audit framework for MCP servers.",
    )
    parser.add_argument(
        "--version", action="version", version=f"mcp-shield {__version__}"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-essential output"
    )

    sub = parser.add_subparsers(dest="subcommand", help="Available commands")

    # --- scan ---
    scan_p = sub.add_parser(
        "scan", help="Audit an MCP server from source (GitHub URL or npm package)"
    )
    scan_p.add_argument(
        "source",
        nargs="?",
        default=None,
        help="GitHub URL, npm package name, or local path (omit with --all)",
    )
    scan_p.add_argument("--name", help="Override MCP server name")
    scan_p.add_argument("--npm-package", help="Treat source as npm package name")
    scan_p.add_argument(
        "--format",
        choices=["text", "json", "markdown", "html", "sarif"],
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
    scan_p.add_argument(
        "--sandbox-network",
        choices=["none", "bridge"],
        default="none",
        help="Docker network mode for sandbox (default: none = fully isolated)",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with code 2 if any finding at this severity or higher is found",
    )
    scan_p.add_argument(
        "--full",
        action="store_true",
        help=(
            "Full audit: static scan + live fetch + sandbox (if Docker) "
            "+ bait-and-switch (if MCP command found in configs). "
            "Equivalent to layers 1+2+3 in the audit methodology."
        ),
    )
    scan_p.add_argument(
        "--live-command",
        help="MCP server command for live analysis (e.g., 'node')",
    )
    scan_p.add_argument(
        "--live-args",
        nargs="*",
        help="Arguments for the MCP server command",
    )
    scan_p.add_argument(
        "--no-open",
        action="store_true",
        help="Do not auto-open HTML report in browser (for CI/CD)",
    )
    scan_p.add_argument(
        "--suppress",
        type=str,
        default=None,
        help="Comma-separated rule IDs to suppress (e.g., tls_disabled,binary_shell_cmd)",
    )
    scan_p.add_argument(
        "--all",
        action="store_true",
        help="Scan all MCP servers detected on this system",
    )
    scan_p.add_argument(
        "--no-ignore",
        action="store_true",
        help="Ignore .mcpshieldignore files in scanned repos (prevents attacker-controlled exclusions)",
    )
    scan_p.add_argument(
        "--audit",
        action="store_true",
        help="Show all findings including low-confidence ones (default hides confidence < 0.5)",
    )
    scan_p.add_argument(
        "--strict",
        action="store_true",
        help="Strict mode for CI/CD: only show HIGH+ findings with confidence >= 0.7",
    )
    scan_p.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help="Minimum confidence threshold (0.0-1.0) to include a finding",
    )

    # --- sandbox (standalone) ---
    sandbox_p = sub.add_parser(
        "sandbox", help="Run a MCP server in an isolated Docker sandbox"
    )
    sandbox_p.add_argument("source", help="GitHub URL or package name")
    sandbox_p.add_argument("--name", required=True, help="MCP server name")
    sandbox_p.add_argument(
        "--type",
        choices=["npm", "pip", "git"],
        default="npm",
        help="Package type (default: npm)",
    )
    sandbox_p.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Observation duration in seconds (default: 60)",
    )
    sandbox_p.add_argument(
        "--network",
        choices=["none", "bridge"],
        default="none",
        help="Docker network mode (default: none = fully isolated)",
    )

    # --- bait-switch ---
    bait_p = sub.add_parser(
        "bait-switch",
        help="Probe MCP server for bait-and-switch behavior (multi-identity test)",
    )
    bait_p.add_argument("command", help="Server executable (e.g., node, npx)")
    bait_p.add_argument(
        "server_args", nargs="*", help="Arguments for the server process"
    )
    bait_p.add_argument(
        "--thorough",
        action="store_true",
        help="Test 6 identities instead of 3",
    )

    # --- detect ---
    sub.add_parser(
        "detect",
        help="Auto-detect MCP server configs on this system",
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
