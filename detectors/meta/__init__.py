"""MCP metadata detectors — scan tool descriptions, schemas, and names."""

from mcp_shield.detectors.meta.description_heuristic import (
    DescriptionHeuristicDetector,
)
from mcp_shield.detectors.meta.markdown_injection import (
    MarkdownInjectionDetector,
)
from mcp_shield.detectors.meta.prompt_injection import (
    PromptInjectionDetector,
)
from mcp_shield.detectors.meta.schema_injection import (
    SchemaInjectionDetector,
)
from mcp_shield.detectors.meta.unicode_tricks import (
    HomoglyphDetector,
    UnicodeInvisibleDetector,
)

ALL_META_DETECTORS = [
    PromptInjectionDetector,
    UnicodeInvisibleDetector,
    HomoglyphDetector,
    SchemaInjectionDetector,
    MarkdownInjectionDetector,
    DescriptionHeuristicDetector,
]

__all__ = [
    "PromptInjectionDetector",
    "UnicodeInvisibleDetector",
    "HomoglyphDetector",
    "SchemaInjectionDetector",
    "MarkdownInjectionDetector",
    "DescriptionHeuristicDetector",
    "ALL_META_DETECTORS",
]
