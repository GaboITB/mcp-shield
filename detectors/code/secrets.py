"""Hardcoded secrets detector for MCP Shield v2.

Detects credentials and sensitive values embedded in source code:
- Hardcoded passwords, API keys, tokens, secret keys
- Connection strings with embedded passwords
- TLS verification disabled (rejectUnauthorized, verify=False)
- Filters placeholders (YOUR_KEY, REPLACE_ME, example, ${...})
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Assignment patterns: variable = "value"
# Captures: group(1)=var_name, group(2)=quote_char, group(3)=value
RE_PY_ASSIGNMENT = re.compile(
    r"""(?:^|;|\s)"""
    r"""(password|passwd|pwd|secret|api_key|apikey|api_secret|apisecret|"""
    r"""token|access_token|auth_token|bearer|secret_key|secretkey|"""
    r"""private_key|privatekey|client_secret|app_secret|signing_key|"""
    r"""encryption_key|master_key|db_password|database_password|"""
    r"""auth|credentials|connection_string)"""
    r"""\s*=\s*(['"])((?:(?!\2).)+)\2""",
    re.IGNORECASE | re.MULTILINE,
)

# JS/TS object property or const patterns
RE_JS_ASSIGNMENT = re.compile(
    r"""(?:const|let|var|this\.)?\s*"""
    r"""(?:['"]?)(password|passwd|pwd|secret|apiKey|api_key|apiSecret|"""
    r"""token|accessToken|access_token|authToken|auth_token|bearer|"""
    r"""secretKey|secret_key|privateKey|private_key|clientSecret|"""
    r"""client_secret|appSecret|signingKey|encryptionKey|masterKey|"""
    r"""dbPassword|databasePassword|auth|credentials|connectionString)"""
    r"""(?:['"]?)\s*[:=]\s*['"`]((?:(?!['"`]).)+)['"`]""",
    re.IGNORECASE,
)

# Known token/key patterns (high-entropy strings)
RE_AWS_KEY = re.compile(r"""(?:AKIA|ASIA)[A-Z0-9]{16}""")
RE_GITHUB_TOKEN = re.compile(r"""gh[pousr]_[A-Za-z0-9_]{36,}""")
RE_GENERIC_TOKEN = re.compile(
    r"""(?:bearer|token|key|secret|password)\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]""",
    re.IGNORECASE,
)
RE_JWT = re.compile(
    r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]+"""
)
RE_PRIVATE_KEY_PEM = re.compile(r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""")

# Connection strings with passwords
RE_CONN_STRING = re.compile(
    r"""(?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql)://[^:]+:([^@\s'"]+)@""",
    re.IGNORECASE,
)
RE_JDBC_PASSWORD = re.compile(
    r"""jdbc:[^;]+;.*password=([^;'"\s]+)""",
    re.IGNORECASE,
)

# TLS disabled patterns
RE_TLS_REJECT_UNAUTH = re.compile(r"""rejectUnauthorized\s*:\s*false""", re.IGNORECASE)
RE_PY_VERIFY_FALSE = re.compile(r"""verify\s*=\s*False""")
RE_NODE_TLS_ENV = re.compile(r"""NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?""")
RE_INSECURE_SKIP = re.compile(r"""InsecureSkipVerify\s*:\s*true""", re.IGNORECASE)
RE_SSL_NO_VERIFY = re.compile(r"""\bssl\._create_unverified_context\b""")

# SQL multi-statement / injection patterns
RE_SQL_ROLLBACK = re.compile(r"""\bROLLBACK\s*;""", re.IGNORECASE)
RE_SQL_DANGEROUS_CHAIN = re.compile(
    r""";\s*(?:DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE)\b""",
    re.IGNORECASE,
)
RE_SQL_MULTI_OPTION = re.compile(
    r"""multi.?statement|allowMultiQueries|multipleStatements""",
    re.IGNORECASE,
)
RE_SQL_QUERY_MULTI = re.compile(
    r"""\.query\s*\(\s*['"`].*;\s*['"`]""",
)

# Credential in arguments patterns
RE_CRED_CONN_URI = re.compile(
    r"""(?:postgres|postgresql|mysql|mongodb|redis|amqp)://\S+:\S+@""",
    re.IGNORECASE,
)
RE_CRED_PASSWORD_ARG = re.compile(r"""--password[= ]\S+""")
RE_CRED_CONN_STRING_PW = re.compile(r"""connection.?string.*password""", re.IGNORECASE)
RE_CRED_ARGS_SECRETS = re.compile(
    r"""args.*(://|password|token|secret|key=)""", re.IGNORECASE
)
RE_CRED_PLACEHOLDER = re.compile(
    r"""(?:YOUR[_\s]|REPLACE|CHANGE|\$\{)""", re.IGNORECASE
)

# Sensitive file access patterns
RE_SENSITIVE_FILE = re.compile(
    r"""['"](?:[^'"]*(?:\.env|id_rsa|\.ssh/|credentials\.json|\.aws/credentials|\.kube/config)[^'"]*)['"]""",
)

# Placeholder / example filters (false positive reduction)
RE_PLACEHOLDER = re.compile(
    r"""(?:YOUR[_\s]?\w+|"""
    r"""REPLACE[_\s]?ME|CHANGE[_\s]?ME|TODO|FIXME|XXX|"""
    r"""example|placeholder|dummy|test|fake|mock|sample|"""
    r"""<[^>]+>|\$\{[^}]+\}|%\([^)]+\)|None|null|undefined|"""
    r"""process\.env|os\.environ|os\.getenv|"""
    r"""\.{3,}|xxx+|yyy+|zzz+)""",
    re.IGNORECASE,
)

# Minimum length for secret values to reduce false positives
MIN_SECRET_LENGTH = 4

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    ".py",
    ".pyw",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".mts",
    ".cts",
    ".jsx",
    ".tsx",
    ".go",
    ".rb",
    ".java",
    ".cs",
    ".php",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".json",
    ".env",
    ".properties",
}


def _ext(path: str) -> str:
    dot = path.rfind(".")
    return path[dot:].lower() if dot != -1 else ""


def _is_placeholder(value: str) -> bool:
    """Check if a value looks like a placeholder or template variable."""
    if len(value) < MIN_SECRET_LENGTH:
        return True
    return bool(RE_PLACEHOLDER.search(value))


def _is_env_file(path: str) -> bool:
    """Check if the file is a .env or similar config file."""
    lower = path.lower()
    return ".env" in lower or lower.endswith(".properties")


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class SecretsDetector:
    """Detect hardcoded secrets and disabled TLS verification."""

    name: str = "secrets"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        ext = _ext(path)
        if ext not in SCANNABLE_EXTENSIONS:
            return []

        findings: list[Finding] = []
        findings.extend(self._scan_assignments(content))
        findings.extend(self._scan_known_patterns(content))
        findings.extend(self._scan_connection_strings(content))
        findings.extend(self._scan_tls_disabled(content))
        findings.extend(self._scan_sql_multistatement(content))
        findings.extend(self._scan_credential_in_args(content))
        findings.extend(self._scan_sensitive_file_access(content))

        # Attach file path to location
        for idx, f in enumerate(findings):
            if not f.location.startswith("line"):
                continue
            # Location already has line number, keep as-is
        return findings

    def _scan_assignments(self, content: str) -> list[Finding]:
        """Scan for password/key/token assignments with literal values."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            # Python-style assignments
            for match in RE_PY_ASSIGNMENT.finditer(line):
                var_name = match.group(1)
                value = match.group(3)
                if not _is_placeholder(value):
                    findings.append(
                        Finding(
                            rule_id="secrets_hardcoded",
                            severity=Severity.HIGH,
                            surface=Surface.SOURCE_CODE,
                            title=f"Hardcoded secret in '{var_name}'",
                            evidence=self._redact(stripped, value),
                            location=f"line {i}",
                            detail=(
                                f"The variable '{var_name}' contains a hardcoded secret. "
                                "Move it to an environment variable or secrets manager."
                            ),
                        )
                    )

            # JS-style assignments (not already caught above)
            for match in RE_JS_ASSIGNMENT.finditer(line):
                var_name = match.group(1)
                value = match.group(2)
                if not _is_placeholder(value):
                    # Avoid duplicates: check if this line was already flagged
                    already_flagged = any(f.location == f"line {i}" for f in findings)
                    if not already_flagged:
                        findings.append(
                            Finding(
                                rule_id="secrets_hardcoded",
                                severity=Severity.HIGH,
                                surface=Surface.SOURCE_CODE,
                                title=f"Hardcoded secret in '{var_name}'",
                                evidence=self._redact(stripped, value),
                                location=f"line {i}",
                                detail=(
                                    f"The property '{var_name}' contains a hardcoded secret. "
                                    "Move it to an environment variable or secrets manager."
                                ),
                            )
                        )

        return findings

    def _scan_known_patterns(self, content: str) -> list[Finding]:
        """Scan for known secret patterns (AWS keys, GitHub tokens, JWTs, PEM keys)."""
        findings: list[Finding] = []
        lines = content.splitlines()

        pattern_checks = [
            (RE_AWS_KEY, "AWS access key", Severity.CRITICAL),
            (RE_GITHUB_TOKEN, "GitHub token", Severity.CRITICAL),
            (RE_JWT, "JSON Web Token (JWT)", Severity.HIGH),
            (RE_PRIVATE_KEY_PEM, "Private key (PEM)", Severity.CRITICAL),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            for pattern, label, severity in pattern_checks:
                match = pattern.search(line)
                if match:
                    matched_text = match.group(0)
                    if not _is_placeholder(matched_text):
                        findings.append(
                            Finding(
                                rule_id="secrets_hardcoded",
                                severity=severity,
                                surface=Surface.SOURCE_CODE,
                                title=f"{label} detected",
                                evidence=self._redact(stripped, matched_text),
                                location=f"line {i}",
                                detail=(
                                    f"A {label} was found in source code. "
                                    "Rotate this credential immediately and use "
                                    "environment variables or a secrets manager."
                                ),
                            )
                        )

        return findings

    def _scan_connection_strings(self, content: str) -> list[Finding]:
        """Scan for connection strings with embedded passwords."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue

            for pattern, label in (
                (RE_CONN_STRING, "Connection string password"),
                (RE_JDBC_PASSWORD, "JDBC password"),
            ):
                match = pattern.search(line)
                if match:
                    password = match.group(1)
                    if not _is_placeholder(password):
                        findings.append(
                            Finding(
                                rule_id="secrets_hardcoded",
                                severity=Severity.HIGH,
                                surface=Surface.SOURCE_CODE,
                                title=f"{label} in connection string",
                                evidence=self._redact(stripped, password),
                                location=f"line {i}",
                                detail=(
                                    "A password is embedded in a connection string. "
                                    "Use environment variables or a secrets manager."
                                ),
                            )
                        )

        return findings

    def _scan_tls_disabled(self, content: str) -> list[Finding]:
        """Scan for TLS verification being disabled."""
        findings: list[Finding] = []
        lines = content.splitlines()

        tls_patterns = [
            (
                RE_TLS_REJECT_UNAUTH,
                "rejectUnauthorized: false",
                "Node.js TLS verification disabled",
            ),
            (
                RE_PY_VERIFY_FALSE,
                "verify=False",
                "Python TLS/SSL verification disabled",
            ),
            (
                RE_NODE_TLS_ENV,
                "NODE_TLS_REJECT_UNAUTHORIZED=0",
                "Node.js TLS globally disabled via env",
            ),
            (
                RE_INSECURE_SKIP,
                "InsecureSkipVerify: true",
                "Go TLS verification disabled",
            ),
            (
                RE_SSL_NO_VERIFY,
                "ssl._create_unverified_context",
                "Python SSL verification bypassed",
            ),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*")):
                continue

            for pattern, evidence_hint, title in tls_patterns:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id="tls_disabled",
                            severity=Severity.HIGH,
                            surface=Surface.SOURCE_CODE,
                            title=title,
                            evidence=stripped[:200],
                            location=f"line {i}",
                            detail=(
                                "Disabling TLS verification allows man-in-the-middle "
                                "attacks. Remove this in production code."
                            ),
                        )
                    )

        return findings

    def _scan_sql_multistatement(self, content: str) -> list[Finding]:
        """Detect SQL multi-statement injection patterns."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            matched = False
            if RE_SQL_ROLLBACK.search(line):
                matched = True
            elif RE_SQL_DANGEROUS_CHAIN.search(line):
                matched = True
            elif RE_SQL_MULTI_OPTION.search(line):
                matched = True
            elif RE_SQL_QUERY_MULTI.search(line):
                matched = True

            if matched:
                findings.append(
                    Finding(
                        rule_id="sql_multistatement",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title="SQL multi-statement pattern detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "Multi-statement SQL allows chaining destructive queries "
                            "(DROP, DELETE, TRUNCATE). An MCP tool enabling this can "
                            "be exploited for SQL injection attacks."
                        ),
                    )
                )

        return findings

    def _scan_credential_in_args(self, content: str) -> list[Finding]:
        """Detect credentials passed via command arguments or connection URIs."""
        findings: list[Finding] = []
        lines = content.splitlines()

        cred_patterns = [
            (RE_CRED_CONN_URI, "Connection URI with embedded credentials"),
            (RE_CRED_PASSWORD_ARG, "Password passed as command argument"),
            (RE_CRED_CONN_STRING_PW, "Connection string with password"),
            (RE_CRED_ARGS_SECRETS, "Secret value in arguments"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            for pattern, label in cred_patterns:
                if pattern.search(line):
                    # Filter placeholders
                    if RE_CRED_PLACEHOLDER.search(line):
                        continue
                    findings.append(
                        Finding(
                            rule_id="credential_in_args",
                            severity=Severity.HIGH,
                            surface=Surface.SOURCE_CODE,
                            title=label,
                            evidence=stripped[:200],
                            location=f"line {i}",
                            detail=(
                                "Credentials passed via arguments or URIs can leak "
                                "through process lists, logs, and shell history. "
                                "Use environment variables or a secrets manager."
                            ),
                        )
                    )
                    break  # One finding per line

        return findings

    def _scan_sensitive_file_access(self, content: str) -> list[Finding]:
        """Detect access to sensitive files (.env, SSH keys, credentials)."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Only match in code context (string literals), skip comments
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            if RE_SENSITIVE_FILE.search(line):
                findings.append(
                    Finding(
                        rule_id="sensitive_file_access",
                        severity=Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="Sensitive file path referenced in code",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "Code references a sensitive file (.env, SSH keys, "
                            "credentials). An MCP tool accessing these files "
                            "could exfiltrate secrets."
                        ),
                    )
                )

        return findings

    @staticmethod
    def _redact(line: str, secret: str) -> str:
        """Redact the secret value from evidence, showing only first/last chars."""
        if len(secret) <= 6:
            redacted = "***"
        else:
            redacted = secret[:2] + "***" + secret[-2:]
        return line.replace(secret, redacted)
