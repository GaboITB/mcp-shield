"""Detector registry — auto-discovers and manages all detectors.

Detectors register themselves by type (source/meta/runtime).
The engine queries the registry to get all active detectors.
"""

from __future__ import annotations

from mcp_shield.core.protocols import (
    MetadataDetector,
    RuntimeDetector,
    SourceDetector,
)


class DetectorRegistry:
    """Central registry for all detector instances."""

    def __init__(self) -> None:
        self._source: list[SourceDetector] = []
        self._meta: list[MetadataDetector] = []
        self._runtime: list[RuntimeDetector] = []

    def register(
        self, detector: SourceDetector | MetadataDetector | RuntimeDetector
    ) -> None:
        """Register a detector by its protocol type."""
        if isinstance(detector, SourceDetector):
            self._source.append(detector)
        if isinstance(detector, MetadataDetector):
            self._meta.append(detector)
        if isinstance(detector, RuntimeDetector):
            self._runtime.append(detector)

    @property
    def source_detectors(self) -> list[SourceDetector]:
        return list(self._source)

    @property
    def meta_detectors(self) -> list[MetadataDetector]:
        return list(self._meta)

    @property
    def runtime_detectors(self) -> list[RuntimeDetector]:
        return list(self._runtime)

    @property
    def total_count(self) -> int:
        return len(self._source) + len(self._meta) + len(self._runtime)


def create_default_registry() -> DetectorRegistry:
    """Create a registry with all built-in detectors."""
    from mcp_shield.detectors.code.eval_exec import EvalExecDetector
    from mcp_shield.detectors.code.path_traversal import PathTraversalDetector
    from mcp_shield.detectors.code.secrets import SecretsDetector
    from mcp_shield.detectors.code.shell_injection import ShellInjectionDetector
    from mcp_shield.detectors.code.ssrf import SsrfDetector
    from mcp_shield.detectors.code.permissions import PermissionsDetector
    from mcp_shield.detectors.code.binary_analysis import BinaryAnalysisDetector
    from mcp_shield.detectors.meta.prompt_injection import PromptInjectionDetector
    from mcp_shield.detectors.meta.unicode_tricks import (
        UnicodeInvisibleDetector,
        HomoglyphDetector,
    )
    from mcp_shield.detectors.meta.schema_injection import SchemaInjectionDetector
    from mcp_shield.detectors.meta.markdown_injection import MarkdownInjectionDetector
    from mcp_shield.detectors.meta.description_heuristic import (
        DescriptionHeuristicDetector,
    )
    from mcp_shield.detectors.delta.tool_shadowing import ToolShadowingDetector
    from mcp_shield.detectors.delta.param_divergence import ParamDivergenceDetector
    from mcp_shield.detectors.delta.capability_drift import CapabilityDriftDetector
    from mcp_shield.detectors.meta.annotation_coherence import (
        AnnotationCoherenceDetector,
    )
    from mcp_shield.detectors.meta.resource_injection import ResourceInjectionDetector
    from mcp_shield.detectors.meta.prompt_template import PromptTemplateDetector
    from mcp_shield.detectors.meta.sampling_detector import SamplingDetector

    reg = DetectorRegistry()

    # Code detectors
    reg.register(ShellInjectionDetector())
    reg.register(EvalExecDetector())
    reg.register(SsrfDetector())
    reg.register(SecretsDetector())
    reg.register(PathTraversalDetector())
    reg.register(PermissionsDetector())
    reg.register(BinaryAnalysisDetector())

    # Meta detectors
    reg.register(PromptInjectionDetector())
    reg.register(UnicodeInvisibleDetector())
    reg.register(HomoglyphDetector())
    reg.register(SchemaInjectionDetector())
    reg.register(MarkdownInjectionDetector())
    reg.register(DescriptionHeuristicDetector())
    reg.register(AnnotationCoherenceDetector())

    # Runtime detectors
    reg.register(ToolShadowingDetector())
    reg.register(ParamDivergenceDetector())
    reg.register(CapabilityDriftDetector())

    # Protocol surface detectors (not in standard registry — called by engine directly)
    # ResourceInjectionDetector, PromptTemplateDetector, SamplingDetector

    return reg
