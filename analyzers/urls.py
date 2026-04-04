"""URL extraction and classification for MCP Shield v2.

Ports extract_urls(), _is_documentation_context(), and _is_in_docstring()
from mcp_audit.py v1.  Loads a whitelist from known_safe_urls.json and
classifies every hardcoded URL as safe / suspicious / local / doc / unknown.

Fixed from v1: docstring ranges are pre-computed once per file instead of
re-scanning all preceding lines for every URL match (O(n*m) -> O(n)).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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
_URL_RE = re.compile(r"""["']?(https?://[^\s"'`,\)}\]>]+)["']?""")
_MAX_FILE_SIZE = 500_000

# Default whitelist path (same directory as the v1 mcp_audit.py)
_DEFAULT_WHITELIST = (
    Path(__file__).resolve().parent.parent.parent / "known_safe_urls.json"
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class UrlEntry:
    """A single extracted URL with its classification."""

    url: str
    domain: str
    classification: str  # safe | suspicious | local | doc | unknown
    file: str
    line: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_whitelist(
    path: Path | None = None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Load safe and suspicious domain lists from JSON."""
    wl_path = path or _DEFAULT_WHITELIST
    safe: dict[str, str] = {}
    suspicious: dict[str, str] = {}
    if wl_path.exists():
        try:
            data = json.loads(wl_path.read_text(encoding="utf-8"))
            safe = data.get("domains", {})
            suspicious = data.get("suspicious_domains", {})
        except (json.JSONDecodeError, OSError):
            pass
    return safe, suspicious


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


def _read_file(filepath: Path) -> tuple[str, list[str]]:
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
        return content, content.split("\n")
    except Exception:
        return "", []


# ---------------------------------------------------------------------------
# Docstring / documentation context detection
# ---------------------------------------------------------------------------


def _compute_docstring_lines(lines: list[str]) -> set[int]:
    """Pre-compute the set of line indices that fall inside a Python
    docstring (triple-quoted block).  O(n) per file instead of O(n*m).

    A line is "inside a docstring" if an odd number of triple-quote
    delimiters have appeared on all preceding lines.
    """
    inside: set[int] = set()
    triple_count = 0
    for idx, line in enumerate(lines):
        # Count delimiters on *preceding* lines (exclusive of current)
        if triple_count % 2 == 1:
            inside.add(idx)
        triple_count += line.count('"""') + line.count("'''")
    return inside


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(("//", "#", "*", "/*", "<!--", "'''", '"""'))


def _is_documentation_context(
    line: str,
    line_idx: int,
    docstring_lines: set[int],
) -> bool:
    """Return True if the URL on *line* is in a documentation context
    (comment, docstring, JSDoc, description attribute, markdown link, or
    example placeholder).
    """
    # Simple comment
    if _is_comment(line):
        return True
    # Inside a Python docstring (pre-computed)
    if line_idx in docstring_lines:
        return True
    # Description / help / example attribute
    if re.search(
        r"(description|help|example|usage|doc|hint)\s*[:=]", line, re.IGNORECASE
    ):
        return True
    # JSDoc or block comment continuation
    stripped = line.strip()
    if stripped.startswith(("*", "///", "/**")):
        return True
    # Markdown link [text](url)
    if re.search(r"\[.+?\]\(https?://", line):
        return True
    # Example / placeholder context
    if re.search(r"(e\.g\.|example|placeholder|target|FUZZ|XSS)", line, re.IGNORECASE):
        return True
    return False


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------


def extract_urls(
    repo_path: Path,
    *,
    whitelist_path: Path | None = None,
) -> tuple[list[dict], list[Finding]]:
    """Extract and classify hardcoded URLs from source files.

    Returns a list of URL entry dicts (for AuditResult.urls) and a list of
    Findings for suspicious / unknown URLs.
    """
    safe_domains, suspicious_domains = _load_whitelist(whitelist_path)

    urls: list[dict] = []
    findings: list[Finding] = []

    for filepath in _iter_code_files(repo_path):
        _content, lines = _read_file(filepath)
        if not lines:
            continue

        rel = str(filepath.relative_to(repo_path))

        # Pre-compute docstring ranges once per file (fixes v1 O(n*m) bug)
        docstring_lines = _compute_docstring_lines(lines)

        for i, line in enumerate(lines):
            is_doc = _is_documentation_context(line, i, docstring_lines)

            for match in _URL_RE.finditer(line):
                url = match.group(1)
                domain = re.sub(r"https?://([^/:]+).*", r"\1", url)

                if domain in safe_domains:
                    classification = "safe"
                elif domain in suspicious_domains:
                    classification = "suspicious"
                    if not is_doc:
                        findings.append(
                            Finding(
                                rule_id="suspicious_external_url",
                                severity=Severity.CRITICAL,
                                surface=Surface.SOURCE_CODE,
                                title=f"Suspicious URL: {domain}",
                                evidence=line.strip()[:150],
                                location=f"{rel}:{i + 1}",
                                detail=suspicious_domains[domain],
                            )
                        )
                elif any(
                    domain.startswith(p)
                    for p in ("localhost", "127.", "0.0.", "192.168.", "10.", "172.")
                ):
                    classification = "local"
                elif is_doc:
                    classification = "doc"
                else:
                    classification = "unknown"
                    findings.append(
                        Finding(
                            rule_id="unknown_external_url",
                            severity=Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title=f"Unknown external URL: {domain}",
                            evidence=line.strip()[:150],
                            location=f"{rel}:{i + 1}",
                        )
                    )

                urls.append(
                    {
                        "url": url[:200],
                        "domain": domain,
                        "classification": classification,
                        "file": rel,
                        "line": i + 1,
                    }
                )

    return urls, findings
