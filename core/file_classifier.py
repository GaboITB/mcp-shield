"""File role classification for context-aware severity adjustment.

Classifies source files into roles (handler, test, build, config, library)
so that findings in test files or build scripts can be downgraded.
"""

from __future__ import annotations

import re
from enum import Enum


class FileRole(Enum):
    MCP_HANDLER = "handler"
    LIBRARY = "library"
    BUILD = "build"
    TEST = "test"
    CONFIG = "config"
    UNKNOWN = "unknown"


# Patterns for MCP handler detection
_RE_MCP_HANDLER = re.compile(
    r"@(?:mcp|server|app)\.tool|"
    r"server\.(?:tool|setRequestHandler|request_handler)|"
    r"\.addTool\s*\(|"
    r"mcp\.NewTool|RegisterTool|"
    r"add_resource\s*\(|"
    r"McpServer\s*\(",
    re.IGNORECASE,
)

_TEST_PATTERNS = (
    "test_",
    "_test.",
    ".test.",
    ".spec.",
    "__test__",
    "/tests/",
    "/test/",
    "/spec/",
    "/__tests__/",
    "/fixtures/",
    "/mocks/",
    "/stubs/",
)

_BUILD_PATTERNS = (
    "makefile",
    "dockerfile",
    "jenkinsfile",
    ".github/",
    ".circleci/",
    ".gitlab-ci",
    "scripts/build",
    "scripts/deploy",
    "scripts/ci",
    "gulpfile",
    "gruntfile",
    "webpack.config",
    "rollup.config",
    "vite.config",
    "tsconfig",
    "babel.config",
    ".eslintrc",
    ".prettierrc",
)

_CONFIG_EXTENSIONS = (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg")


def classify_file(path: str, content: str = "") -> FileRole:
    """Classify a file's role in the project.

    Args:
        path: Relative file path (forward slashes).
        content: File content (only first 5KB is checked for handlers).
    """
    lower = path.lower().replace("\\", "/")

    # Test files
    if any(p in lower for p in _TEST_PATTERNS):
        return FileRole.TEST

    # Build/CI files
    if any(p in lower for p in _BUILD_PATTERNS):
        return FileRole.BUILD

    # Config files (but package.json is BUILD)
    if any(lower.endswith(ext) for ext in _CONFIG_EXTENSIONS):
        if "package.json" in lower:
            return FileRole.BUILD
        return FileRole.CONFIG

    # MCP handler detection (check first 5KB of content)
    if content and _RE_MCP_HANDLER.search(content[:5000]):
        return FileRole.MCP_HANDLER

    return FileRole.LIBRARY
