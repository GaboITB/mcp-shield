"""Centralized path resolution for MCP Shield data directories.

Uses platform-appropriate locations:
- Windows: %APPDATA%/mcp-shield  (e.g. C:/Users/x/AppData/Roaming/mcp-shield)
- macOS/Linux: ~/.config/mcp-shield
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def get_data_dir() -> Path:
    """Return the MCP Shield data directory for the current platform."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "mcp-shield"
    return Path.home() / ".config" / "mcp-shield"


def get_audit_dir() -> Path:
    """Return the audit reports directory."""
    return get_data_dir() / "audits"


def get_cache_dir() -> Path:
    """Return the cache directory."""
    return get_data_dir() / "cache"


def get_log_dir() -> Path:
    """Return the logs directory."""
    return get_data_dir() / "logs"
