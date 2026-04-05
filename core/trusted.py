"""Trusted publisher registry for MCP Shield v3.

Known-good GitHub organizations and npm scopes whose MCP servers
have been vetted by the community. Findings from trusted publishers
are not suppressed — they are flagged with reduced severity to avoid
false-positive-driven distrust.

This list is intentionally conservative. Only organizations that:
1. Publish official, widely-used MCP servers
2. Have a public security disclosure process
3. Are maintained by a known company or team

Users can extend this list via .mcpshieldtrust files.
"""

from __future__ import annotations

import re
from pathlib import Path

# Trusted GitHub organizations (lowercase)
TRUSTED_GITHUB_ORGS: frozenset[str] = frozenset(
    {
        "anthropics",
        "modelcontextprotocol",
        "microsoft",
        "cloudflare",
        "grafana",
        "github",
        "google",
        "aws",
        "azure",
        "vercel",
        "supabase",
        "stripe",
        "slack",
        "linear",
        "notion",
        "atlassian",
        "jetbrains",
        "docker",
        "hashicorp",
    }
)

# Trusted npm scopes (lowercase, with @)
TRUSTED_NPM_SCOPES: frozenset[str] = frozenset(
    {
        "@anthropic-ai",
        "@modelcontextprotocol",
        "@cloudflare",
        "@microsoft",
        "@google",
        "@aws-sdk",
        "@vercel",
        "@supabase",
        "@stripe",
    }
)


# Known binary/package names from trusted publishers
_KNOWN_BINARIES: dict[str, str] = {
    "github-mcp-server": "github",
    "mcp-grafana": "grafana",
    "mcp-server-cloudflare": "cloudflare",
    "playwright-mcp": "microsoft",
    "claude-code-mcp-server": "anthropics",
}


def is_trusted_source(source: str, name: str = "") -> tuple[bool, str]:
    """Check if a source URL or package name is from a trusted publisher.

    Args:
        source: GitHub URL, npm package name, or local path.
        name: MCP server name (from --name or auto-inferred).

    Returns (is_trusted, publisher_name).
    """
    source_lower = source.lower()

    # GitHub URL: https://github.com/<org>/...
    gh_match = re.match(r"https?://github\.com/([^/]+)/", source_lower)
    if gh_match:
        org = gh_match.group(1)
        if org in TRUSTED_GITHUB_ORGS:
            return True, org

    # npm scoped package: @scope/package
    if source_lower.startswith("@"):
        scope = source_lower.split("/")[0]
        if scope in TRUSTED_NPM_SCOPES:
            return True, scope

    # Local path — check if it contains a known org or npm scope
    normalized = source_lower.replace("\\", "/")
    for org in TRUSTED_GITHUB_ORGS:
        if f"/{org}/" in normalized:
            return True, org
    for scope in TRUSTED_NPM_SCOPES:
        if scope in source_lower:
            return True, scope

    # Check known binary/package names in source path or MCP name
    for bin_name, publisher in _KNOWN_BINARIES.items():
        if bin_name in normalized or bin_name == name.lower():
            return True, publisher

    # Check if any directory component matches a known binary name
    path_parts = normalized.rstrip("/").split("/")
    for part in path_parts:
        if part in _KNOWN_BINARIES:
            return True, _KNOWN_BINARIES[part]

    return False, ""


def load_user_trust(repo_path: Path | None = None) -> set[str]:
    """Load additional trusted patterns from .mcpshieldtrust files.

    Checks both the repo root and ~/.config/mcp-shield/.mcpshieldtrust.
    Each line is a GitHub org or npm scope to trust.
    """
    extra: set[str] = set()
    from mcp_shield.core.paths import get_data_dir

    paths = [get_data_dir() / ".mcpshieldtrust"]
    if repo_path:
        paths.append(repo_path / ".mcpshieldtrust")

    for p in paths:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        extra.add(line)
            except OSError:
                pass
    return extra
