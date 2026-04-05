"""SARIF 2.1.0 output formatter for MCP Shield.

Produces a SARIF (Static Analysis Results Interchange Format) v2.1.0
compliant JSON document from an AuditResult. Zero external dependencies
-- uses only stdlib json.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from mcp_shield import __version__
from mcp_shield.core.models import AuditResult, Finding, Severity

# SARIF schema URI
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# Severity -> SARIF level mapping
_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Optional mappings -- imported lazily with graceful fallback
_cwe_map: dict[str, str] | None = None
_remediation_map: dict[str, str] | None = None


def _get_cwe_map() -> dict[str, str]:
    """Load CWE mapping, returning empty dict on failure."""
    global _cwe_map
    if _cwe_map is None:
        try:
            from mcp_shield.core.cwe import CWE_MAP

            _cwe_map = CWE_MAP
        except Exception:
            _cwe_map = {}
    return _cwe_map


def _get_remediation_map() -> dict[str, str]:
    """Load remediation mapping, returning empty dict on failure."""
    global _remediation_map
    if _remediation_map is None:
        try:
            from mcp_shield.core.remediation import REMEDIATION_MAP

            _remediation_map = REMEDIATION_MAP
        except Exception:
            _remediation_map = {}
    return _remediation_map


def _parse_location(location: str) -> dict[str, Any] | None:
    """Parse a Finding location string into a SARIF physicalLocation.

    Supports formats:
        "path/to/file.py:42"  -> artifact + region with line number
        "path/to/file.py"     -> artifact only (no colon-digit suffix)
        "tool_name"           -> returns None (not a file location)
    """
    if not location:
        return None

    # Try to split "file:line" where line is a positive integer
    colon_idx = location.rfind(":")
    if colon_idx > 0:
        maybe_line = location[colon_idx + 1 :]
        if maybe_line.isdigit() and int(maybe_line) > 0:
            file_path = location[:colon_idx]
            line_num = int(maybe_line)
            return {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {"startLine": line_num},
                }
            }

    # Check if it looks like a file path (contains a dot or path separator)
    if "." in location or "/" in location or "\\" in location:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": location},
            }
        }

    # Likely a tool name or endpoint -- encode as logical location
    return {
        "logicalLocations": [{"name": location, "kind": "module"}],
    }


def _build_rule(rule_id: str, finding: Finding) -> dict[str, Any]:
    """Build a SARIF reportingDescriptor (rule) from a Finding."""
    cwe_map = _get_cwe_map()
    remediation_map = _get_remediation_map()

    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": finding.title},
        "defaultConfiguration": {
            "level": _LEVEL_MAP.get(finding.severity, "note"),
        },
        "properties": {
            "severity": finding.severity.value,
            "surface": finding.surface.value,
        },
    }

    # Add CWE taxonomy reference if available
    cwe_id = cwe_map.get(rule_id)
    if cwe_id:
        # e.g. "CWE-78" -> numeric part 78
        cwe_num = cwe_id.split("-", 1)[1] if "-" in cwe_id else cwe_id
        rule["properties"]["cwe"] = cwe_id
        rule["relationships"] = [
            {
                "target": {
                    "id": cwe_id,
                    "guid": "",
                    "toolComponent": {"name": "CWE", "index": 0},
                },
                "kinds": ["superset"],
            }
        ]

    # Add remediation as help text if available
    remediation = remediation_map.get(rule_id)
    if remediation:
        rule["help"] = {
            "text": remediation,
            "markdown": remediation,
        }

    return rule


def _build_result(finding: Finding, rule_index: int) -> dict[str, Any]:
    """Build a SARIF result object from a Finding."""
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL_MAP.get(finding.severity, "note"),
        "message": {
            "text": finding.evidence,
        },
    }

    # Add detail as markdown if present
    if finding.detail:
        result["message"]["markdown"] = finding.detail

    # Parse location
    loc = _parse_location(finding.location)
    if loc:
        result["locations"] = [loc]

    # Add fingerprint for deduplication
    result["fingerprints"] = {
        "mcp-shield/v1": f"{finding.rule_id}/{finding.location}/{finding.evidence[:64]}",
    }

    return result


def _build_cwe_taxonomy() -> dict[str, Any]:
    """Build CWE external taxonomy reference."""
    return {
        "name": "CWE",
        "organization": "MITRE",
        "shortDescription": {"text": "Common Weakness Enumeration"},
        "informationUri": "https://cwe.mitre.org/",
        "isComprehensive": False,
    }


def format_sarif(result: AuditResult) -> str:
    """Convert an AuditResult into a SARIF 2.1.0 JSON string.

    Args:
        result: The audit result containing findings to format.

    Returns:
        A JSON string conforming to the SARIF 2.1.0 schema.
    """
    # Build rules array (deduplicated by rule_id, preserving order)
    seen_rules: dict[str, int] = {}
    rules: list[dict[str, Any]] = []

    for finding in result.findings:
        if finding.rule_id not in seen_rules:
            seen_rules[finding.rule_id] = len(rules)
            rules.append(_build_rule(finding.rule_id, finding))

    # Build results array
    results: list[dict[str, Any]] = []
    for finding in result.findings:
        rule_index = seen_rules[finding.rule_id]
        results.append(_build_result(finding, rule_index))

    # Build the tool driver
    driver: dict[str, Any] = {
        "name": "mcp-shield",
        "version": __version__,
        "informationUri": "https://github.com/GaboITB/mcp-shield",
        "rules": rules,
    }

    # Include CWE taxonomy only if we have CWE mappings
    cwe_map = _get_cwe_map()
    has_cwe = any(cwe_map.get(r) for r in seen_rules)
    taxonomies = [_build_cwe_taxonomy()] if has_cwe else []

    # Build the run
    run: dict[str, Any] = {
        "tool": {
            "driver": driver,
        },
        "results": results,
    }

    if taxonomies:
        run["taxonomies"] = taxonomies

    # Add invocation metadata
    run["invocations"] = [
        {
            "executionSuccessful": True,
            "properties": {
                "source": result.source,
                "name": result.name,
                "grade": result.grade.value,
                "totalScore": result.total_score,
            },
        }
    ]

    if result.timestamp:
        run["invocations"][0]["startTimeUtc"] = result.timestamp

    # Assemble the SARIF envelope
    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }

    return json.dumps(sarif, indent=2, ensure_ascii=False)
