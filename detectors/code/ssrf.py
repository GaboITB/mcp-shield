"""SSRF (Server-Side Request Forgery) detector for MCP Shield v2.

Detects HTTP requests with dynamic or environment-sourced URLs:
- Python: requests, urllib, httpx, aiohttp
- JS/TS: fetch, axios, got, undici, ky, superagent, http.get
- Severity HIGH for user-controlled URLs, MEDIUM for env-based URLs
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Python HTTP libraries
RE_PY_REQUESTS = re.compile(
    r"""\brequests\.(get|post|put|patch|delete|head|options|request)\s*\("""
)
RE_PY_URLLIB = re.compile(r"""\burllib\.request\.(urlopen|urlretrieve|Request)\s*\(""")
RE_PY_HTTPX = re.compile(
    r"""\bhttpx\.(get|post|put|patch|delete|head|options|request|AsyncClient|Client)\s*\("""
)
RE_PY_AIOHTTP = re.compile(
    r"""\b(?:aiohttp\.ClientSession|session)\s*\(\s*\)\.(?:get|post|put|patch|delete)\s*\("""
)
RE_PY_AIOHTTP_SIMPLE = re.compile(r"""\bsession\.(get|post|put|patch|delete)\s*\(""")
RE_PY_HTTP_CLIENT = re.compile(r"""\bhttp\.client\.HTTPSConnection\s*\(""")

# JS/TS HTTP libraries
RE_JS_FETCH = re.compile(r"""\bfetch\s*\(""")
RE_JS_AXIOS = re.compile(r"""\baxios\s*[.(]""")
RE_JS_AXIOS_METHOD = re.compile(
    r"""\baxios\.(get|post|put|patch|delete|head|options|request)\s*\("""
)
RE_JS_GOT = re.compile(r"""\bgot\s*[.(]""")
RE_JS_GOT_METHOD = re.compile(r"""\bgot\.(get|post|put|patch|delete|head)\s*\(""")
RE_JS_HTTP_GET = re.compile(r"""\bhttps?\.(?:get|request)\s*\(""")
RE_JS_UNDICI = re.compile(r"""\bundici\.(fetch|request)\s*\(""")
RE_JS_KY = re.compile(r"""\bky\.(get|post|put|patch|delete|head)\s*\(""")
RE_JS_SUPERAGENT = re.compile(
    r"""\bsuperagent\.(get|post|put|patch|delete|head)\s*\("""
)
RE_JS_REQUEST_LIB = re.compile(r"""\brequest\s*\(""")

# Dynamic URL indicators
RE_FSTRING = re.compile(r"""f["'][^"']*\{[^}]+\}""")
RE_FORMAT_CALL = re.compile(r"""\.format\s*\(""")
RE_TEMPLATE_LITERAL = re.compile(r"""`[^`]*\$\{[^}]+\}[^`]*`""")
RE_CONCAT = re.compile(r"""\+\s*\w+""")

# Environment / config sourced URLs
RE_PY_ENV = re.compile(r"""\bos\.(?:environ|getenv)\s*[\[(]""")
RE_PY_CONFIG = re.compile(r"""\b(?:config|settings|cfg|conf)\s*[\[.]""", re.IGNORECASE)
RE_JS_PROCESS_ENV = re.compile(r"""\bprocess\.env\.""")
RE_JS_CONFIG = re.compile(r"""\b(?:config|settings|cfg|conf)\s*[\[.]""", re.IGNORECASE)

# User input indicators
RE_PY_USER_INPUT = re.compile(
    r"""\b(?:request\.|args\.|params\.|body\.|query\.|data\[|form\[|input\()""",
    re.IGNORECASE,
)
RE_JS_USER_INPUT = re.compile(
    r"""\b(?:req\.(params|query|body|headers)|request\.(params|query|body))""",
)

# Exfiltration API / telemetry endpoint patterns
RE_EXFIL_CRUX = re.compile(r"""crux|CrUX|chrome-ux-report""", re.IGNORECASE)
RE_EXFIL_PAGESPEED = re.compile(r"""\bpagespeed\b""", re.IGNORECASE)
RE_EXFIL_BEACON = re.compile(r"""beacon.*\.(com|io|net)""", re.IGNORECASE)
RE_EXFIL_COLLECTOR = re.compile(r"""collector.*\.(com|io)""", re.IGNORECASE)
RE_EXFIL_EVENTS = re.compile(r"""events.*\.(com|io|net)""", re.IGNORECASE)
RE_EXFIL_INGEST = re.compile(r"""ingest\.(sentry|datadog|bugsnag)""", re.IGNORECASE)

# URL validation / allowlist (mitigation)
RE_URL_VALIDATION = re.compile(
    r"""\b(?:urlparse|URL|new\s+URL|allowlist|whitelist|allowed_hosts|"""
    r"""ALLOWED_HOSTS|validate_url|is_valid_url|url_validator)\b""",
    re.IGNORECASE,
)

# File extensions
PY_EXTENSIONS = {".py", ".pyw"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}


def _ext(path: str) -> str:
    dot = path.rfind(".")
    return path[dot:].lower() if dot != -1 else ""


def _classify_url_source(line: str, is_python: bool) -> str | None:
    """Classify the URL source: 'user', 'env', 'dynamic', or None (static)."""
    if is_python:
        if RE_PY_USER_INPUT.search(line):
            return "user"
        if RE_PY_ENV.search(line) or RE_PY_CONFIG.search(line):
            return "env"
    else:
        if RE_JS_USER_INPUT.search(line):
            return "user"
        if RE_JS_PROCESS_ENV.search(line) or RE_JS_CONFIG.search(line):
            return "env"

    # Generic dynamic indicators
    if RE_FSTRING.search(line) or RE_FORMAT_CALL.search(line):
        return "dynamic"
    if RE_TEMPLATE_LITERAL.search(line) or RE_CONCAT.search(line):
        return "dynamic"

    return None


def _has_url_validation(content: str) -> bool:
    """Check if the file contains URL validation patterns."""
    return bool(RE_URL_VALIDATION.search(content))


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class SsrfDetector:
    """Detect server-side request forgery vulnerabilities."""

    name: str = "ssrf"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        ext = _ext(path)
        findings: list[Finding] = []
        if ext in PY_EXTENSIONS:
            findings.extend(self._scan_python(path, content))
        elif ext in JS_EXTENSIONS:
            findings.extend(self._scan_js(path, content))

        # Exfiltration API detection applies to all code files
        if ext in PY_EXTENSIONS | JS_EXTENSIONS:
            findings.extend(self._scan_exfiltration_api(content))

        return findings

    def _make_finding(
        self,
        line_text: str,
        lineno: int,
        lib_name: str,
        url_source: str,
        has_validation: bool,
    ) -> Finding:
        """Build a Finding with appropriate severity based on URL source."""
        if url_source == "user":
            severity = Severity.HIGH
            title = f"SSRF risk: {lib_name} with user-controlled URL"
            detail = (
                "The URL passed to the HTTP client appears to come from user input. "
                "An attacker could redirect requests to internal services."
            )
        elif url_source == "env":
            severity = Severity.MEDIUM
            title = f"SSRF risk: {lib_name} with environment-sourced URL"
            detail = (
                "The URL comes from environment or config. If the env is compromised, "
                "requests could be redirected to internal services."
            )
        else:
            severity = Severity.MEDIUM
            title = f"SSRF risk: {lib_name} with dynamic URL"
            detail = (
                "The URL is constructed dynamically. Ensure it is validated against "
                "an allowlist before use."
            )

        if has_validation and severity == Severity.MEDIUM:
            severity = Severity.LOW

        rule_id = "ssrf_dynamic_url" if url_source == "user" else "ssrf_env_url"

        return Finding(
            rule_id=rule_id,
            severity=severity,
            surface=Surface.SOURCE_CODE,
            title=title,
            evidence=line_text.strip()[:200],
            location=f"line {lineno}",
            detail=detail,
        )

    # -- Python ------------------------------------------------------------

    def _scan_python(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        has_validation = _has_url_validation(content)
        lines = content.splitlines()

        py_patterns = [
            (RE_PY_REQUESTS, "requests"),
            (RE_PY_URLLIB, "urllib"),
            (RE_PY_HTTPX, "httpx"),
            (RE_PY_AIOHTTP, "aiohttp"),
            (RE_PY_AIOHTTP_SIMPLE, "aiohttp.session"),
            (RE_PY_HTTP_CLIENT, "http.client"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern, lib_name in py_patterns:
                if pattern.search(line):
                    url_source = _classify_url_source(line, is_python=True)
                    if url_source is not None:
                        findings.append(
                            self._make_finding(
                                stripped, i, lib_name, url_source, has_validation
                            )
                        )
                    break  # One finding per line max

        return findings

    # -- JavaScript / TypeScript -------------------------------------------

    def _scan_js(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        has_validation = _has_url_validation(content)
        lines = content.splitlines()

        js_patterns = [
            (RE_JS_FETCH, "fetch"),
            (RE_JS_AXIOS_METHOD, "axios"),
            (RE_JS_AXIOS, "axios"),
            (RE_JS_GOT_METHOD, "got"),
            (RE_JS_GOT, "got"),
            (RE_JS_HTTP_GET, "http/https"),
            (RE_JS_UNDICI, "undici"),
            (RE_JS_KY, "ky"),
            (RE_JS_SUPERAGENT, "superagent"),
            (RE_JS_REQUEST_LIB, "request"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            for pattern, lib_name in js_patterns:
                if pattern.search(line):
                    url_source = _classify_url_source(line, is_python=False)
                    if url_source is not None:
                        findings.append(
                            self._make_finding(
                                stripped, i, lib_name, url_source, has_validation
                            )
                        )
                    break  # One finding per line max

        return findings

    # -- Exfiltration API detection ----------------------------------------

    def _scan_exfiltration_api(self, content: str) -> list[Finding]:
        """Detect references to known data exfiltration / beacon endpoints."""
        findings: list[Finding] = []
        lines = content.splitlines()

        exfil_patterns = [
            (RE_EXFIL_CRUX, "CrUX / Chrome UX Report endpoint"),
            (RE_EXFIL_PAGESPEED, "PageSpeed API endpoint"),
            (RE_EXFIL_BEACON, "Beacon endpoint"),
            (RE_EXFIL_COLLECTOR, "Collector endpoint"),
            (RE_EXFIL_EVENTS, "Events tracking endpoint"),
            (RE_EXFIL_INGEST, "Telemetry ingest endpoint"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            for pattern, label in exfil_patterns:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id="exfiltration_api",
                            severity=Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title=f"Potential data exfiltration: {label}",
                            evidence=stripped[:200],
                            location=f"line {i}",
                            detail=(
                                "This code references an external data collection "
                                "endpoint. An MCP tool sending data to third-party "
                                "services could exfiltrate sensitive information."
                            ),
                        )
                    )
                    break  # One finding per line

        return findings
