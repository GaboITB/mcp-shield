"""Resource injection detector for MCP resource metadata.

Scans MCP resource URIs, names, and descriptions for patterns that
indicate prompt injection, data exfiltration via resource content,
or suspicious URI schemes.

MCP resources are server-controlled content injected into the LLM
context — a powerful vector for prompt injection since the content
is trusted by default.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, ResourceInfo, Severity, Surface

# Suspicious URI schemes that could indicate exfiltration or local access
_DANGEROUS_SCHEMES = re.compile(
    r"^(?:file|ftp|data|javascript|vbscript|blob|gopher):",
    re.IGNORECASE,
)

# Internal/private network URIs
_INTERNAL_URI = re.compile(
    r"(?:localhost|127\.0\.0\.\d|10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\])",
    re.IGNORECASE,
)

# Wildcard resource templates that match everything
_OVERLY_BROAD_URI = re.compile(
    r"^[a-z]+://\*",
    re.IGNORECASE,
)

# Suspicious MIME types that could carry executable content
_EXECUTABLE_MIME = re.compile(
    r"(?:application/(?:javascript|x-javascript|wasm|x-executable|"
    r"x-sharedlib|octet-stream|x-httpd-php|x-sh|x-csh|x-perl|"
    r"x-python|java-archive|zip|gzip|x-tar))",
    re.IGNORECASE,
)

# Import the prompt injection scanner for reuse on descriptions
from mcp_shield.detectors.meta.prompt_injection import _scan_text


class ResourceInjectionDetector:
    """Detect injection and exfiltration risks in MCP resource metadata."""

    name: str = "resource_injection"

    def scan_resource(self, resource: ResourceInfo) -> list[Finding]:
        """Scan a single MCP resource for security issues."""
        findings: list[Finding] = []
        location = f"resource:{resource.uri}"

        # 1. Prompt injection in resource description
        if resource.description:
            findings.extend(
                _scan_text(resource.description, location, "resource description")
            )

        # 2. Prompt injection in resource name
        if resource.name and len(resource.name) > 100:
            findings.extend(_scan_text(resource.name, location, "resource name"))

        # 3. Dangerous URI scheme
        if _DANGEROUS_SCHEMES.match(resource.uri):
            scheme = resource.uri.split(":")[0]
            findings.append(
                Finding(
                    rule_id="resource_dangerous_uri",
                    severity=Severity.HIGH,
                    surface=Surface.MCP_METADATA,
                    title=f"Dangerous URI scheme: {scheme}://",
                    evidence=resource.uri[:200],
                    location=location,
                    detail=(
                        f"Resource uses the '{scheme}' URI scheme which can "
                        f"access local files, execute code, or bypass security "
                        f"boundaries when loaded into the LLM context."
                    ),
                )
            )

        # 4. Internal network URI
        if _INTERNAL_URI.search(resource.uri):
            findings.append(
                Finding(
                    rule_id="resource_internal_uri",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title="Resource points to internal network",
                    evidence=resource.uri[:200],
                    location=location,
                    detail=(
                        "Resource URI points to a private/internal address. "
                        "This could be used for SSRF or to exfiltrate data "
                        "from internal services when the resource is read."
                    ),
                )
            )

        # 5. Overly broad wildcard URI
        if _OVERLY_BROAD_URI.match(resource.uri):
            findings.append(
                Finding(
                    rule_id="resource_broad_uri",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title="Overly broad wildcard resource URI",
                    evidence=resource.uri[:200],
                    location=location,
                    detail=(
                        "Resource URI uses a wildcard that matches any path. "
                        "This grants the server access to inject arbitrary "
                        "content into the LLM context."
                    ),
                )
            )

        # 6. Executable MIME type
        if resource.mime_type and _EXECUTABLE_MIME.search(resource.mime_type):
            findings.append(
                Finding(
                    rule_id="resource_executable_mime",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title=f"Executable MIME type: {resource.mime_type}",
                    evidence=f"URI: {resource.uri[:150]}, MIME: {resource.mime_type}",
                    location=location,
                    detail=(
                        "Resource declares an executable MIME type. "
                        "Executable content injected into the LLM context "
                        "could be used for code execution if processed "
                        "by downstream tools."
                    ),
                )
            )

        return findings

    def scan_resources(self, resources: list[ResourceInfo]) -> list[Finding]:
        """Scan all resources from a server."""
        findings: list[Finding] = []
        for resource in resources:
            findings.extend(self.scan_resource(resource))
        return findings
