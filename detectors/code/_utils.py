"""Shared utilities for source code detectors.

Extracted from individual detectors to eliminate duplication.
"""

from __future__ import annotations

import re


# File extension helper — used by all 6 code detectors
def file_ext(path: str) -> str:
    """Return lowercased file extension (e.g., '.py', '.js')."""
    dot = path.rfind(".")
    return path[dot:].lower() if dot != -1 else ""


# Language classification sets
JS_TS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
PYTHON_EXTENSIONS = {".py"}
GO_EXTENSIONS = {".go"}
SHELL_EXTENSIONS = {".sh", ".bash"}


def is_js_ts(path: str) -> bool:
    """Check if a file is JavaScript or TypeScript."""
    return file_ext(path) in JS_TS_EXTENSIONS


def is_python(path: str) -> bool:
    """Check if a file is Python."""
    return file_ext(path) in PYTHON_EXTENSIONS


def is_go(path: str) -> bool:
    """Check if a file is Go."""
    return file_ext(path) in GO_EXTENSIONS


# Common interpolation/dynamic patterns — shared across shell, eval, ssrf detectors
RE_FSTRING = re.compile(r"""f["'][^"']*\{[^}]+\}""")
RE_FORMAT_CALL = re.compile(r"""\.format\s*\(""")
RE_PERCENT_FORMAT = re.compile(r"""%\s*[(\w]""")
RE_CONCAT = re.compile(r"""\+\s*\w+""")
RE_TEMPLATE_LITERAL = re.compile(r"""`[^`]*\$\{[^}]+\}[^`]*`""")


def has_interpolation(line: str, *, include_percent: bool = True) -> bool:
    """Heuristic: does the line contain string interpolation or concatenation?

    Args:
        line: Source code line to check.
        include_percent: Include %-format detection (disable for URL checks
            where ``%`` is common in URL-encoding).
    """
    if RE_FSTRING.search(line) or RE_FORMAT_CALL.search(line):
        return True
    if include_percent and RE_PERCENT_FORMAT.search(line):
        return True
    return bool(RE_CONCAT.search(line) or RE_TEMPLATE_LITERAL.search(line))


# Comment stripping for single-line comment detection
RE_LINE_COMMENT = re.compile(r"""^\s*(?://|#|--)\s""")


def is_comment_line(line: str) -> bool:
    """Check if a line is a single-line comment."""
    return bool(RE_LINE_COMMENT.match(line))
