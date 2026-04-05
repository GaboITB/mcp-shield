"""npm-specific checks for MCP Shield v3.

Ports check_npm_deprecated(), check_mcp_sdk_version(), and
check_rate_limiting() from mcp_audit.py v1.

Fixed from v1: check_rate_limiting searches file-by-file instead of
concatenating all source into a single string (O(n^2) memory).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterator

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IS_WINDOWS = sys.platform == "win32"

CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".rb",
        ".sh",
        ".bash",
    }
)

IGNORE_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "vendor",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "coverage",
        ".turbo",
        ".cache",
        ".parcel-cache",
    }
)

IGNORE_FILES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.sum",
        "Pipfile.lock",
        "poetry.lock",
    }
)

_TEST_FILE_RE = re.compile(
    r"(_test\.go|\.test\.\w+|\.spec\.\w+|_test\.py|test_\w+\.py)$"
)
_MAX_FILE_SIZE = 500_000

_RATE_LIMIT_RE = re.compile(
    r"rate.?limit|throttl|token.?bucket|sliding.?window|"
    r"MAX_REQUESTS|REQUEST_LIMIT|RATE_LIMIT|cooldown|"
    r"p-limit|bottleneck|express-rate-limit|limiter",
    re.IGNORECASE,
)

_QUERY_KEYWORDS: tuple[str, ...] = (
    "query",
    "sql",
    "promql",
    "logql",
    "execute",
    "eval",
    "search",
    "find",
    "lookup",
    "fetch",
    "request",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def npm_cmd(args: list[str]) -> list[str]:
    """Build an npm command list — uses ``npm.cmd`` on Windows."""
    if IS_WINDOWS:
        return ["npm.cmd"] + args
    return ["npm"] + args


def _iter_code_files(repo_path: Path) -> Iterator[Path]:
    """Yield source code files inside *repo_path*."""
    for f in repo_path.rglob("*"):
        if any(d in f.parts for d in IGNORE_DIRS):
            continue
        if f.name in IGNORE_FILES:
            continue
        if _TEST_FILE_RE.search(f.name):
            continue
        if f.suffix in CODE_EXTENSIONS and f.is_file():
            try:
                if f.stat().st_size < _MAX_FILE_SIZE:
                    yield f
            except OSError:
                pass


def _read_file(filepath: Path) -> str:
    try:
        return filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# check_npm_deprecated
# ---------------------------------------------------------------------------


def check_npm_deprecated(repo_path: Path) -> tuple[str | None, list[Finding]]:
    """Check whether the npm package in *repo_path* is marked deprecated.

    Returns the deprecation message (or None) and any findings.
    """
    findings: list[Finding] = []
    pkg_json = repo_path / "package.json"
    if not pkg_json.exists():
        return None, findings

    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
        pkg_name = data.get("name")
        if not pkg_name:
            return None, findings

        r = subprocess.run(
            npm_cmd(["view", pkg_name, "deprecated", "--json"]),
            capture_output=True,
            timeout=15,
        )
        output = r.stdout.decode("utf-8", errors="ignore").strip()

        # npm view returns a JSON error object if the package does not exist
        if output.startswith("{"):
            try:
                err_data = json.loads(output)
                if "error" in err_data:
                    msg = f"Package not found on npm ({err_data['error'].get('code', 'unknown')})"
                    findings.append(
                        Finding(
                            rule_id="npm_deprecated",
                            severity=Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title=f"npm package not found: {pkg_name}",
                            evidence=msg,
                            location="package.json:0",
                            detail="Package absent from npm registry — removed, renamed, or never published",
                        )
                    )
                    return msg, findings
            except json.JSONDecodeError:
                pass

        # Non-empty, non-null output means the package is deprecated
        if output and output not in ('""', "null", "", "undefined"):
            msg = output.strip('"')
            findings.append(
                Finding(
                    rule_id="npm_deprecated",
                    severity=Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title=f"npm package DEPRECATED: {pkg_name}",
                    evidence=msg[:150],
                    location="package.json:0",
                    detail="Package marked deprecated on npm — maintainer abandoned or replaced",
                )
            )
            return msg, findings

    except Exception:
        pass

    return None, findings


# ---------------------------------------------------------------------------
# check_mcp_sdk_version
# ---------------------------------------------------------------------------


def check_mcp_sdk_version(
    deps: dict,
) -> tuple[dict[str, str] | None, list[Finding]]:
    """Check whether the MCP SDK dependency is up to date.

    *deps* is a dict with keys ``type``, ``deps``, ``dev_deps`` (the
    serialised form of ``DepsResult``).

    Returns an info dict ``{name, current, latest}`` (or None) and findings.
    """
    findings: list[Finding] = []
    all_deps = {**deps.get("deps", {}), **deps.get("dev_deps", {})}
    dep_type = deps.get("type", "")

    # Determine which SDK names to look for
    js_sdk_names: set[str] = {"@modelcontextprotocol/sdk"}
    py_sdk_names: set[str] = {"fastmcp", "python-sdk"}

    if dep_type == "npm":
        js_sdk_names.add("mcp")
    elif dep_type == "pip":
        py_sdk_names.add("mcp")
    else:
        js_sdk_names.add("mcp")  # fallback to JS

    sdk_name: str | None = None
    sdk_version: str | None = None

    for name, version in all_deps.items():
        if name in js_sdk_names or name in py_sdk_names:
            sdk_name = name
            sdk_version = str(version).lstrip("^~>=<! ")
            break

    if not sdk_name:
        return None, findings

    # Query npm for the latest version
    try:
        r = subprocess.run(
            npm_cmd(["view", sdk_name, "version"]),
            capture_output=True,
            timeout=15,
        )
        if r.returncode == 0:
            latest = r.stdout.decode().strip()
            if sdk_version and latest and sdk_version != latest:
                try:
                    current_parts = [int(x) for x in sdk_version.split(".")[:2]]
                    latest_parts = [int(x) for x in latest.split(".")[:2]]
                    if current_parts < latest_parts:
                        findings.append(
                            Finding(
                                rule_id="sdk_outdated",
                                severity=Severity.LOW,
                                surface=Surface.SOURCE_CODE,
                                title=f"Outdated MCP SDK: {sdk_name}@{sdk_version} (latest: {latest})",
                                evidence=f"{sdk_version} -> {latest}",
                                location="package.json:0",
                                detail="MCP SDK is not up to date — may miss security fixes",
                            )
                        )
                except (ValueError, IndexError):
                    pass
            return {
                "name": sdk_name,
                "current": sdk_version or "",
                "latest": latest,
            }, findings
    except Exception:
        pass

    return None, findings


# ---------------------------------------------------------------------------
# check_rate_limiting
# ---------------------------------------------------------------------------


def check_rate_limiting(
    repo_path: Path,
    tools: list[dict],
) -> tuple[list[str], list[Finding]]:
    """Detect MCP tools that accept arbitrary queries without rate limiting.

    Fixed from v1: searches file-by-file instead of concatenating all code
    into a single giant string.

    Returns the list of query-capable tool names and any findings.
    """
    findings: list[Finding] = []

    # Identify tools whose names suggest they accept queries
    query_tools: list[str] = []
    for tool in tools:
        name_lower = tool.get("name", "").lower()
        if any(kw in name_lower for kw in _QUERY_KEYWORDS):
            query_tools.append(tool["name"])

    if not query_tools:
        return [], findings

    # Search file-by-file for rate-limiting indicators
    has_rate_limit = False
    for code_file in _iter_code_files(repo_path):
        content = _read_file(code_file)
        if not content:
            continue
        if _RATE_LIMIT_RE.search(content):
            has_rate_limit = True
            break  # one match is enough

    if not has_rate_limit:
        for tool_name in query_tools:
            findings.append(
                Finding(
                    rule_id="no_rate_limiting",
                    severity=Severity.LOW,
                    surface=Surface.SOURCE_CODE,
                    title=f"No rate limiting on query tool: {tool_name}",
                    evidence=tool_name,
                    location="N/A:0",
                    detail="Tool accepts arbitrary queries without rate limiting — potential DoS",
                )
            )

    return query_tools, findings
