"""Schema injection detector for MCP tool input schemas.

Scans JSON Schema definitions for:
- Malicious default values (shell commands, URLs, file paths)
- Enum values with hidden payloads
- Overly permissive schemas on sensitive fields
- Fields requesting sensitive data (passwords, tokens, keys)
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Shell command indicators in default values
_RE_SHELL_CMD = re.compile(
    r"(?:"
    r"\$\(.*\)"  # $(command)
    r"|`[^`]+`"  # `command`
    r"|\b(?:sh|bash|cmd|powershell|pwsh)\s+-c\b"
    r"|\b(?:rm|del|curl|wget|nc|ncat|python|node|perl|ruby)\s+"
    r"|&&\s*\w"  # chained commands
    r"|\|\s*\w"  # piped commands
    r"|;\s*(?:rm|curl|wget|cat|echo)\b"
    r")",
    re.IGNORECASE,
)

# URL patterns in defaults
_RE_URL = re.compile(
    r"https?://(?!(?:localhost|127\.0\.0\.1|example\.com|schema\.org))"
    r"[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]{5,}",
    re.IGNORECASE,
)

# File path patterns in defaults (absolute paths)
_RE_FILE_PATH = re.compile(
    r"(?:"
    r"/(?:etc|tmp|var|home|root|proc|dev|sys)/\S+"  # Unix absolute
    r"|[A-Z]:\\(?:Windows|Users|Temp|Program)\\\S+"  # Windows absolute
    r"|~/.+/"  # Home directory
    r"|\.\./"  # Path traversal
    r")",
    re.IGNORECASE,
)

# Sensitive field name patterns
_RE_SENSITIVE_FIELD = re.compile(
    r"(?:^|_|-)"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"credential|auth[_-]?token|access[_-]?key|private[_-]?key|"
    r"session[_-]?id|cookie|bearer|jwt|ssh[_-]?key|"
    r"client[_-]?secret|master[_-]?key|encryption[_-]?key)"
    r"(?:$|_|-)",
    re.IGNORECASE,
)

# Base64-encoded content in defaults
_RE_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{30,}={0,2}")


def _check_default_value(value: Any, field_path: str, tool_name: str) -> list[Finding]:
    """Check a single default value for malicious content."""
    findings: list[Finding] = []
    if not isinstance(value, str) or len(value) < 3:
        return findings

    if _RE_SHELL_CMD.search(value):
        findings.append(
            Finding(
                rule_id="schema_injection",
                severity=Severity.CRITICAL,
                surface=Surface.MCP_METADATA,
                title="Shell command in schema default value",
                evidence=f"{field_path}: {value[:150]}",
                location=tool_name,
                detail=(
                    f"Default value for '{field_path}' contains shell command "
                    "patterns. This could execute arbitrary commands if the "
                    "default is used without user review."
                ),
            )
        )

    if _RE_URL.search(value):
        url_match = _RE_URL.search(value)
        findings.append(
            Finding(
                rule_id="schema_injection",
                severity=Severity.HIGH,
                surface=Surface.MCP_METADATA,
                title="External URL in schema default value",
                evidence=f"{field_path}: {url_match.group(0)[:150] if url_match else value[:150]}",
                location=tool_name,
                detail=(
                    f"Default value for '{field_path}' contains an external URL. "
                    "This could be used for data exfiltration or SSRF."
                ),
            )
        )

    if _RE_FILE_PATH.search(value):
        findings.append(
            Finding(
                rule_id="schema_injection",
                severity=Severity.HIGH,
                surface=Surface.MCP_METADATA,
                title="File path in schema default value",
                evidence=f"{field_path}: {value[:150]}",
                location=tool_name,
                detail=(
                    f"Default value for '{field_path}' contains a file system path. "
                    "This could target sensitive files or enable path traversal."
                ),
            )
        )

    if _RE_BASE64_BLOCK.search(value):
        findings.append(
            Finding(
                rule_id="schema_injection",
                severity=Severity.MEDIUM,
                surface=Surface.MCP_METADATA,
                title="Base64 payload in schema default value",
                evidence=f"{field_path}: {value[:100]}...",
                location=tool_name,
                detail=(
                    f"Default value for '{field_path}' contains a base64-encoded "
                    "block. This may hide malicious payloads."
                ),
            )
        )

    return findings


def _check_enum_values(
    enum_values: list[Any], field_path: str, tool_name: str
) -> list[Finding]:
    """Check enum values for hidden payloads."""
    findings: list[Finding] = []
    for val in enum_values:
        if not isinstance(val, str):
            continue
        # Enum values containing shell commands or URLs
        sub_findings = _check_default_value(val, f"{field_path}[enum]", tool_name)
        findings.extend(sub_findings)
        # Enum values with invisible chars or excessive length
        if len(val) > 200:
            findings.append(
                Finding(
                    rule_id="schema_injection",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title="Oversized enum value (potential hidden payload)",
                    evidence=f"{field_path}[enum]: {val[:100]}... ({len(val)} chars)",
                    location=tool_name,
                    detail=(
                        "Enum values should be short identifiers. An oversized "
                        "value may contain hidden instructions or payloads."
                    ),
                )
            )
    return findings


def _walk_schema(
    schema: dict[str, Any], tool_name: str, path: str = ""
) -> list[Finding]:
    """Recursively walk a JSON Schema and check for issues."""
    findings: list[Finding] = []
    if not isinstance(schema, dict):
        return findings

    properties = schema.get("properties", {})
    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_path = f"{path}.{field_name}" if path else field_name

        # Check default values
        if "default" in field_schema:
            findings.extend(
                _check_default_value(field_schema["default"], field_path, tool_name)
            )

        # Check enum values
        if "enum" in field_schema and isinstance(field_schema["enum"], list):
            findings.extend(
                _check_enum_values(field_schema["enum"], field_path, tool_name)
            )

        # Check for sensitive field names with permissive schemas
        if _RE_SENSITIVE_FIELD.search(field_name):
            findings.append(
                Finding(
                    rule_id="schema_injection",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title=f"Schema requests sensitive field: '{field_name}'",
                    evidence=f"{field_path}: type={field_schema.get('type', 'any')}",
                    location=tool_name,
                    detail=(
                        f"Field '{field_name}' appears to request sensitive data "
                        "(password, token, key, etc.). Verify this is necessary "
                        "and that the value is handled securely."
                    ),
                )
            )

        # Check for overly permissive string fields with no constraints
        field_type = field_schema.get("type")
        if field_type == "string" and _RE_SENSITIVE_FIELD.search(field_name):
            has_constraints = any(
                k in field_schema
                for k in (
                    "maxLength",
                    "minLength",
                    "pattern",
                    "enum",
                    "format",
                    "const",
                )
            )
            if not has_constraints:
                findings.append(
                    Finding(
                        rule_id="schema_injection",
                        severity=Severity.LOW,
                        surface=Surface.MCP_METADATA,
                        title=f"No constraints on sensitive field '{field_name}'",
                        evidence=f"{field_path}: string with no validation",
                        location=tool_name,
                        detail=(
                            f"Sensitive field '{field_name}' has type 'string' "
                            "with no maxLength, pattern, or format constraint. "
                            "This increases injection surface."
                        ),
                    )
                )

        # Recurse into nested objects
        if field_schema.get("type") == "object":
            findings.extend(_walk_schema(field_schema, tool_name, field_path))
        # Recurse into array items
        items = field_schema.get("items")
        if isinstance(items, dict):
            findings.extend(_walk_schema(items, tool_name, f"{field_path}[]"))

    return findings


class SchemaInjectionDetector:
    """Detect malicious patterns in MCP tool input schemas."""

    name: str = "schema_injection"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        return _walk_schema(schema, tool_name)
