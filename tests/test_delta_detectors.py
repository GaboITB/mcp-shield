"""Tests for delta (runtime) detectors — tool shadowing, param divergence, capability drift."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.core.models import Severity, ToolInfo
from mcp_shield.core.registry import create_default_registry


class _BaseDeltaTest(unittest.TestCase):
    def setUp(self):
        reg = create_default_registry()
        self.det = {d.name: d for d in reg.runtime_detectors}


# ── ToolShadowing ────────────────────────────────────────────────
class TestToolShadowing(_BaseDeltaTest):
    def test_new_tool_injected(self):
        static = [ToolInfo(name="read", description="Read data", source="static")]
        live = [
            ToolInfo(name="read", description="Read data", source="live"),
            ToolInfo(name="injected", description="Bad", source="live"),
        ]
        f = self.det["tool_shadowing"].scan_delta(static, live)
        self.assertTrue(any("injected" in x.evidence for x in f))

    def test_tool_disappeared(self):
        static = [
            ToolInfo(name="read", description="Read", source="static"),
            ToolInfo(name="write", description="Write", source="static"),
        ]
        live = [ToolInfo(name="read", description="Read", source="live")]
        f = self.det["tool_shadowing"].scan_delta(static, live)
        self.assertTrue(any("write" in x.evidence for x in f))

    def test_builtin_collision(self):
        static = []
        live = [ToolInfo(name="read_file", description="Read", source="live")]
        f = self.det["tool_shadowing"].scan_delta(static, live)
        shadow = [x for x in f if x.rule_id == "tool_shadowing"]
        self.assertTrue(len(shadow) > 0)

    def test_identical_no_finding(self):
        tools = [ToolInfo(name="query", description="Query data", source="static")]
        f = self.det["tool_shadowing"].scan_delta(tools, tools)
        appeared = [x for x in f if x.rule_id == "tool_appeared_live"]
        self.assertEqual(len(appeared), 0)


# ── ParamDivergence ──────────────────────────────────────────────
class TestParamDivergence(_BaseDeltaTest):
    def test_description_changed(self):
        static = [ToolInfo(name="query", description="Run a query", source="static")]
        live = [
            ToolInfo(
                name="query", description="Totally different purpose now", source="live"
            )
        ]
        f = self.det["param_divergence"].scan_delta(static, live)
        self.assertTrue(len(f) > 0)

    def test_new_required_param(self):
        static = [
            ToolInfo(
                name="query",
                description="Query",
                input_schema={
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                    "required": ["q"],
                },
                source="static",
            )
        ]
        live = [
            ToolInfo(
                name="query",
                description="Query",
                input_schema={
                    "type": "object",
                    "properties": {
                        "q": {"type": "string"},
                        "secret": {"type": "string"},
                    },
                    "required": ["q", "secret"],
                },
                source="live",
            )
        ]
        f = self.det["param_divergence"].scan_delta(static, live)
        self.assertTrue(len(f) > 0)

    def test_type_changed(self):
        static = [
            ToolInfo(
                name="fetch",
                description="Fetch",
                input_schema={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                },
                source="static",
            )
        ]
        live = [
            ToolInfo(
                name="fetch",
                description="Fetch",
                input_schema={
                    "type": "object",
                    "properties": {"url": {"type": "object"}},
                },
                source="live",
            )
        ]
        f = self.det["param_divergence"].scan_delta(static, live)
        self.assertTrue(len(f) > 0)

    def test_identical_schema_no_finding(self):
        schema = {"type": "object", "properties": {"q": {"type": "string"}}}
        tools = [
            ToolInfo(
                name="search",
                description="Search",
                input_schema=schema,
                source="static",
            )
        ]
        f = self.det["param_divergence"].scan_delta(tools, tools)
        self.assertEqual(len(f), 0)

    def test_constraint_removed(self):
        static = [
            ToolInfo(
                name="set",
                description="Set value",
                input_schema={
                    "type": "object",
                    "properties": {"val": {"type": "string", "enum": ["a", "b"]}},
                },
                source="static",
            )
        ]
        live = [
            ToolInfo(
                name="set",
                description="Set value",
                input_schema={
                    "type": "object",
                    "properties": {"val": {"type": "string"}},
                },
                source="live",
            )
        ]
        f = self.det["param_divergence"].scan_delta(static, live)
        self.assertTrue(len(f) > 0)


# ── CapabilityDrift ──────────────────────────────────────────────
class TestCapabilityDrift(_BaseDeltaTest):
    def test_no_drift_identical(self):
        tools = [ToolInfo(name="read", description="Read data", source="live")]
        f = self.det["capability_drift"].scan_delta(tools, tools)
        self.assertEqual(len(f), 0)

    def test_new_tool_detected(self):
        old = [ToolInfo(name="read", description="Read", source="live")]
        new = [
            ToolInfo(name="read", description="Read", source="live"),
            ToolInfo(name="delete_all", description="Delete everything", source="live"),
        ]
        f = self.det["capability_drift"].scan_delta(old, new)
        self.assertTrue(len(f) > 0)

    def test_tool_removed(self):
        old = [
            ToolInfo(name="read", description="Read", source="live"),
            ToolInfo(name="write", description="Write", source="live"),
        ]
        new = [ToolInfo(name="read", description="Read", source="live")]
        f = self.det["capability_drift"].scan_delta(old, new)
        self.assertTrue(len(f) > 0)

    def test_description_drift(self):
        old = [
            ToolInfo(
                name="exec",
                description="Execute a safe query on the database",
                source="live",
            )
        ]
        new = [
            ToolInfo(
                name="exec",
                description="Run arbitrary shell commands on the host system",
                source="live",
            )
        ]
        f = self.det["capability_drift"].scan_delta(old, new)
        self.assertTrue(len(f) > 0)

    def test_annotation_readonly_to_destructive(self):
        old = [
            ToolInfo(
                name="op",
                description="Op",
                annotations={"readOnlyHint": True},
                source="live",
            )
        ]
        new = [
            ToolInfo(
                name="op",
                description="Op",
                annotations={"destructiveHint": True},
                source="live",
            )
        ]
        f = self.det["capability_drift"].scan_delta(old, new)
        self.assertTrue(
            any(x.severity in (Severity.CRITICAL, Severity.HIGH) for x in f)
        )


if __name__ == "__main__":
    unittest.main()
