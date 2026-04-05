"""Tests for scoring — AIVSS, verdict, grade, models."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.core.models import (
    AuditResult,
    Finding,
    Grade,
    Severity,
    Surface,
    ToolInfo,
)
from mcp_shield.scoring.aivss import compute_aivss
from mcp_shield.scoring.verdict import compute_grade, compute_verdict
from mcp_shield.formatters.json import to_json, to_json_file
from mcp_shield.approval.store import ApprovalStore


# ── Verdict ──────────────────────────────────────────────────────
class TestVerdict(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(compute_verdict(0), "SAFE")
        self.assertEqual(compute_verdict(5), "SAFE")

    def test_caution(self):
        self.assertEqual(compute_verdict(6), "CAUTION")
        self.assertEqual(compute_verdict(20), "CAUTION")

    def test_warning(self):
        self.assertEqual(compute_verdict(21), "WARNING")
        self.assertEqual(compute_verdict(50), "WARNING")

    def test_danger(self):
        self.assertEqual(compute_verdict(51), "DANGER")
        self.assertEqual(compute_verdict(999), "DANGER")


# ── Grade ────────────────────────────────────────────────────────
class TestGrade(unittest.TestCase):
    def test_a_plus(self):
        self.assertEqual(compute_grade(0), Grade.A_PLUS)

    def test_a(self):
        self.assertEqual(compute_grade(1), Grade.A)
        self.assertEqual(compute_grade(20), Grade.A)

    def test_b(self):
        self.assertEqual(compute_grade(21), Grade.B)
        self.assertEqual(compute_grade(60), Grade.B)

    def test_c(self):
        self.assertEqual(compute_grade(61), Grade.C)
        self.assertEqual(compute_grade(150), Grade.C)

    def test_d(self):
        self.assertEqual(compute_grade(151), Grade.D)
        self.assertEqual(compute_grade(300), Grade.D)

    def test_f(self):
        self.assertEqual(compute_grade(301), Grade.F)
        self.assertEqual(compute_grade(500), Grade.F)

    def test_model_grade_matches_verdict_grade(self):
        """AuditResult.grade and compute_grade should agree."""
        for score_val in (0, 5, 15, 45, 100):
            result = AuditResult(name="t", source="t")
            # Inject findings with known total weight
            if score_val > 0:
                result.findings = (
                    [
                        Finding(
                            rule_id="shell_injection",
                            severity=Severity.CRITICAL,
                            surface=Surface.SOURCE_CODE,
                            title="test",
                            evidence="test",
                            location="t:1",
                        )
                    ]
                    * (score_val // 50)
                    if score_val >= 50
                    else [
                        Finding(
                            rule_id="telemetry_phonehome",
                            severity=Severity.LOW,
                            surface=Surface.SOURCE_CODE,
                            title="test",
                            evidence="test",
                            location="t:1",
                        )
                    ]
                    * (score_val // 8)
                )


# ── AIVSS ────────────────────────────────────────────────────────
class TestAIVSS(unittest.TestCase):
    def _finding(self, rule_id, severity=Severity.HIGH):
        return Finding(
            rule_id=rule_id,
            severity=severity,
            surface=Surface.SOURCE_CODE,
            title="test",
            evidence="test",
            location="t:1",
        )

    def test_no_findings_zero_score(self):
        r = compute_aivss([])
        self.assertEqual(r.score, 0.0)
        self.assertEqual(r.severity, "None")
        self.assertEqual(r.exploitation, 0.0)
        self.assertEqual(r.impact, 0.0)
        self.assertEqual(r.trust, 0.0)

    def test_shell_injection_raises_exploitation_and_impact(self):
        r = compute_aivss([self._finding("shell_injection")])
        self.assertGreater(r.exploitation, 0.0)
        self.assertGreater(r.impact, 0.0)

    def test_prompt_injection_raises_exploitation_and_impact(self):
        r = compute_aivss([self._finding("prompt_injection")])
        self.assertGreater(r.exploitation, 0.0)
        self.assertGreater(r.impact, 0.0)

    def test_tls_disabled_raises_trust(self):
        r = compute_aivss([self._finding("tls_disabled")])
        self.assertGreater(r.trust, 0.0)
        self.assertEqual(r.exploitation, 0.0)

    def test_deprecated_raises_trust(self):
        r = compute_aivss([self._finding("npm_deprecated")])
        self.assertGreater(r.trust, 0.0)

    def test_many_findings_capped_at_10(self):
        findings = [
            self._finding("shell_injection"),
            self._finding("eval_exec_dynamic"),
            self._finding("postinstall_script"),
            self._finding("obfuscated_code"),
            self._finding("sql_multistatement"),
            self._finding("prompt_injection"),
            self._finding("unicode_invisible"),
            self._finding("homoglyph_spoofing"),
            self._finding("schema_injection"),
            self._finding("ssrf_dynamic_url"),
        ]
        r = compute_aivss(findings)
        self.assertLessEqual(r.exploitation, 10.0)
        self.assertLessEqual(r.impact, 10.0)
        self.assertLessEqual(r.trust, 10.0)
        self.assertLessEqual(r.score, 10.0)

    def test_severity_labels(self):
        # Low range
        r = compute_aivss([self._finding("tls_disabled")])
        self.assertIn(r.severity, ("None", "Low"))

        # Higher range with many critical findings
        findings = [
            self._finding("shell_injection"),
            self._finding("prompt_injection"),
            self._finding("tool_shadowing"),
            self._finding("obfuscated_code"),
            self._finding("telemetry_phonehome"),
            self._finding("npm_deprecated"),
        ]
        r = compute_aivss(findings)
        self.assertIn(r.severity, ("Medium", "High", "Critical"))


# ── Models ───────────────────────────────────────────────────────
class TestModels(unittest.TestCase):
    def test_severity_ordering(self):
        self.assertTrue(Severity.CRITICAL < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.MEDIUM)
        self.assertTrue(Severity.LOW < Severity.INFO)

    def test_finding_weight_known(self):
        f = Finding(
            rule_id="shell_injection",
            severity=Severity.CRITICAL,
            surface=Surface.SOURCE_CODE,
            title="t",
            evidence="t",
            location="t",
        )
        self.assertEqual(f.weight, 50)

    def test_finding_weight_unknown(self):
        f = Finding(
            rule_id="unknown_rule",
            severity=Severity.INFO,
            surface=Surface.SOURCE_CODE,
            title="t",
            evidence="t",
            location="t",
        )
        self.assertEqual(f.weight, 0)

    def test_tool_is_destructive_by_annotation(self):
        t = ToolInfo(name="safe_op", annotations={"destructiveHint": True})
        self.assertTrue(t.is_destructive)

    def test_tool_is_readonly_by_annotation(self):
        t = ToolInfo(name="delete_all", annotations={"readOnlyHint": True})
        self.assertFalse(t.is_destructive)

    def test_tool_is_destructive_by_name(self):
        for name in ("delete_repo", "remove_user", "drop_table", "kill_process"):
            t = ToolInfo(name=name)
            self.assertTrue(t.is_destructive, f"{name} should be destructive")

    def test_tool_is_safe_by_name(self):
        for name in ("list_files", "get_status", "search_repos", "read_data"):
            t = ToolInfo(name=name)
            self.assertFalse(t.is_destructive, f"{name} should not be destructive")

    def test_content_hash_stable(self):
        t = ToolInfo(name="read", description="Read data")
        h1 = t.content_hash()
        h2 = t.content_hash()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 32)

    def test_content_hash_changes_on_desc(self):
        t1 = ToolInfo(name="read", description="Read data")
        t2 = ToolInfo(name="read", description="Different")
        self.assertNotEqual(t1.content_hash(), t2.content_hash())

    def test_audit_result_empty(self):
        r = AuditResult(name="test", source="test")
        self.assertEqual(r.total_score, 0)
        self.assertEqual(r.grade, Grade.A_PLUS)
        self.assertEqual(r.critical_count, 0)
        self.assertEqual(r.high_count, 0)

    def test_audit_result_findings_by_severity(self):
        r = AuditResult(
            name="t",
            source="t",
            findings=[
                Finding("a", Severity.HIGH, Surface.SOURCE_CODE, "t", "t", "t"),
                Finding("b", Severity.LOW, Surface.SOURCE_CODE, "t", "t", "t"),
                Finding("c", Severity.HIGH, Surface.SOURCE_CODE, "t", "t", "t"),
            ],
        )
        by_sev = r.findings_by_severity()
        self.assertEqual(len(by_sev[Severity.HIGH]), 2)
        self.assertEqual(len(by_sev[Severity.LOW]), 1)

    def test_audit_result_deny_rules(self):
        r = AuditResult(
            name="test-mcp",
            source="test",
            tools_static=[
                ToolInfo(name="read_data", annotations={"readOnlyHint": True}),
                ToolInfo(name="delete_all", description="Delete everything"),
            ],
        )
        rules = r.deny_rules()
        self.assertIn("mcp__test_mcp__delete_all", rules)
        self.assertNotIn("mcp__test_mcp__read_data", rules)


# ── JSON Formatter ───────────────────────────────────────────────
class TestJSONFormatter(unittest.TestCase):
    def test_serialize_empty_result(self):
        r = AuditResult(name="test", source="test")
        output = to_json(r)
        data = json.loads(output)
        self.assertEqual(data["name"], "test")
        self.assertEqual(data["grade"], "A+")
        self.assertEqual(data["total_score"], 0)

    def test_serialize_with_findings(self):
        r = AuditResult(
            name="t",
            source="t",
            findings=[
                Finding(
                    "shell_injection",
                    Severity.CRITICAL,
                    Surface.SOURCE_CODE,
                    "t",
                    "t",
                    "t",
                ),
            ],
        )
        data = json.loads(to_json(r))
        self.assertEqual(data["total_score"], 50)
        self.assertEqual(data["critical_count"], 1)

    def test_to_json_file(self):
        r = AuditResult(name="t", source="t")
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "out.json"
            to_json_file(r, p)
            self.assertTrue(p.exists())
            data = json.loads(p.read_text())
            self.assertEqual(data["name"], "t")


# ── Approval Store ───────────────────────────────────────────────
class TestApprovalStore(unittest.TestCase):
    def test_approve_and_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            r = AuditResult(
                name="my-mcp",
                source="test",
                tools_static=[ToolInfo(name="read", description="Read")],
            )
            store.approve("my-mcp", r)
            approved = store.list_approved()
            self.assertEqual(len(approved), 1)
            self.assertEqual(approved[0]["name"], "my-mcp")

    def test_check_no_changes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            tools = [ToolInfo(name="read", description="Read")]
            r = AuditResult(name="mcp", source="t", tools_static=tools)
            store.approve("mcp", r)
            alerts = store.check("mcp", tools)
            self.assertEqual(len(alerts), 0)

    def test_check_new_tool(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            tools = [ToolInfo(name="read", description="Read")]
            r = AuditResult(name="mcp", source="t", tools_static=tools)
            store.approve("mcp", r)
            new_tools = tools + [ToolInfo(name="evil", description="Evil")]
            alerts = store.check("mcp", new_tools)
            self.assertTrue(any("NEW TOOL" in a for a in alerts))

    def test_check_modified_tool(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            tools = [ToolInfo(name="query", description="Run query")]
            r = AuditResult(name="mcp", source="t", tools_static=tools)
            store.approve("mcp", r)
            modified = [ToolInfo(name="query", description="Completely different now")]
            alerts = store.check("mcp", modified)
            self.assertTrue(any("MODIFIED TOOL" in a for a in alerts))

    def test_check_unapproved(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            alerts = store.check("unknown", [])
            self.assertTrue(any("never been approved" in a for a in alerts))

    def test_revoke(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            r = AuditResult(name="mcp", source="t")
            store.approve("mcp", r)
            self.assertTrue(store.revoke("mcp"))
            self.assertEqual(len(store.list_approved()), 0)

    def test_revoke_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ApprovalStore(Path(tmpdir) / "approvals.json")
            self.assertFalse(store.revoke("nope"))

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "approvals.json"
            store1 = ApprovalStore(path)
            r = AuditResult(name="mcp", source="t")
            store1.approve("mcp", r)

            store2 = ApprovalStore(path)
            self.assertEqual(len(store2.list_approved()), 1)


if __name__ == "__main__":
    unittest.main()
