"""Analyzers — deps, URLs, npm checks, supply chain, SBOM, version pinning."""

from mcp_shield.analyzers.deps import (
    DepsResult,
    analyze_dependencies,
    find_phantom_deps,
)
from mcp_shield.analyzers.npm_checks import (
    check_mcp_sdk_version,
    check_npm_deprecated,
    check_rate_limiting,
    npm_cmd,
)
from mcp_shield.analyzers.sbom import generate_sbom
from mcp_shield.analyzers.supply_chain import compare_published_vs_source
from mcp_shield.analyzers.urls import extract_urls
from mcp_shield.analyzers.version_pin import (
    audit_transitive_deps,
    resolve_pinned_version,
    run_dep_audit,
)

__all__ = [
    # deps
    "DepsResult",
    "analyze_dependencies",
    "find_phantom_deps",
    # urls
    "extract_urls",
    # npm_checks
    "check_npm_deprecated",
    "check_mcp_sdk_version",
    "check_rate_limiting",
    "npm_cmd",
    # supply chain / sbom / version pin
    "compare_published_vs_source",
    "generate_sbom",
    "resolve_pinned_version",
    "audit_transitive_deps",
    "run_dep_audit",
]
