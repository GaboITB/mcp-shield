"""JSON formatters for MCP Shield v2.

Serializes AuditResult to JSON, handling Enum and dataclass types.
"""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import Path
from typing import Any

from mcp_shield.core.models import AuditResult


def _serialize(obj: Any) -> Any:
    """Custom serializer for non-standard types."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _result_to_dict(result: AuditResult) -> dict[str, Any]:
    """Convert AuditResult to a plain dict with computed properties."""
    data = dataclasses.asdict(result)
    # Add computed properties
    data["total_score"] = result.total_score
    data["grade"] = result.grade.value
    data["critical_count"] = result.critical_count
    data["high_count"] = result.high_count
    data["deny_rules"] = result.deny_rules()
    return data


def to_json(result: AuditResult, indent: int = 2) -> str:
    """Serialize AuditResult to a JSON string.

    Args:
        result: The audit result to serialize.
        indent: JSON indentation level.

    Returns:
        JSON string representation.
    """
    data = _result_to_dict(result)
    return json.dumps(data, default=_serialize, indent=indent, ensure_ascii=False)


def to_json_file(result: AuditResult, path: Path, indent: int = 2) -> None:
    """Write AuditResult as JSON to a file.

    Args:
        result: The audit result to serialize.
        path: Destination file path.
        indent: JSON indentation level.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = to_json(result, indent=indent)
    path.write_text(content, encoding="utf-8")
