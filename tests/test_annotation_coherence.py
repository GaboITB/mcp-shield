"""Tests for annotation coherence detector."""

import unittest

from mcp_shield.detectors.meta.annotation_coherence import AnnotationCoherenceDetector


class TestAnnotationCoherenceDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnnotationCoherenceDetector()

    # --- readOnlyHint=true but destructive ---

    def test_readonly_but_deletes(self):
        findings = self.detector.scan_tool(
            "delete_user",
            "Deletes a user from the database",
            {},
            {"readOnlyHint": True},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)
        self.assertTrue(any(f.severity.value == "high" for f in findings))

    def test_readonly_but_kills(self):
        findings = self.detector.scan_tool(
            "stop_process",
            "Kills the specified process",
            {},
            {"readOnlyHint": True},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)

    # --- readOnlyHint=true but writes ---

    def test_readonly_but_writes(self):
        findings = self.detector.scan_tool(
            "save_config",
            "Writes configuration to disk",
            {},
            {"readOnlyHint": True},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)

    def test_readonly_but_creates(self):
        findings = self.detector.scan_tool(
            "create_file",
            "Creates a new file in the workspace",
            {},
            {"readOnlyHint": True},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)

    # --- destructiveHint=false but destructive ---

    def test_not_destructive_but_drops(self):
        findings = self.detector.scan_tool(
            "drop_table",
            "Drops the specified database table",
            {},
            {"destructiveHint": False},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)
        self.assertTrue(any(f.severity.value == "high" for f in findings))

    def test_not_destructive_but_truncates(self):
        findings = self.detector.scan_tool(
            "truncate_log",
            "Truncates the log file",
            {},
            {"destructiveHint": False},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)

    # --- idempotentHint=true but destructive ---

    def test_idempotent_but_deletes(self):
        findings = self.detector.scan_tool(
            "purge_cache",
            "Purges the entire cache",
            {},
            {"idempotentHint": True},
        )
        rules = [f.rule_id for f in findings]
        self.assertIn("annotation_incoherent", rules)

    # --- Clean cases ---

    def test_readonly_with_get(self):
        findings = self.detector.scan_tool(
            "get_users",
            "Lists all users in the system",
            {},
            {"readOnlyHint": True},
        )
        self.assertEqual(len(findings), 0)

    def test_destructive_correctly_annotated(self):
        findings = self.detector.scan_tool(
            "delete_file",
            "Deletes the specified file",
            {},
            {"destructiveHint": True, "readOnlyHint": False},
        )
        self.assertEqual(len(findings), 0)

    def test_no_annotations(self):
        findings = self.detector.scan_tool(
            "delete_file",
            "Deletes the specified file",
            {},
            None,
        )
        self.assertEqual(len(findings), 0)

    def test_empty_annotations(self):
        findings = self.detector.scan_tool(
            "delete_file",
            "Deletes the specified file",
            {},
            {},
        )
        self.assertEqual(len(findings), 0)

    def test_readonly_true_with_read_tool(self):
        findings = self.detector.scan_tool(
            "read_file",
            "Reads the contents of a file",
            {},
            {"readOnlyHint": True},
        )
        self.assertEqual(len(findings), 0)

    def test_destructive_false_with_query(self):
        findings = self.detector.scan_tool(
            "query_database",
            "Runs a SELECT query against the database",
            {},
            {"destructiveHint": False},
        )
        self.assertEqual(len(findings), 0)

    # --- Multiple incoherences ---

    def test_multiple_incoherences(self):
        findings = self.detector.scan_tool(
            "destroy_everything",
            "Destroys and deletes all data permanently",
            {},
            {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
        )
        # Should have at least 3 findings
        self.assertGreaterEqual(len(findings), 3)


if __name__ == "__main__":
    unittest.main()
