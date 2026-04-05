"""Tests for sampling capability detector."""

import unittest

from mcp_shield.core.models import ServerCapabilities
from mcp_shield.detectors.meta.sampling_detector import SamplingDetector


class TestSamplingDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SamplingDetector()

    def test_sampling_declared_flagged(self):
        caps = ServerCapabilities(tools=True, sampling=True)
        findings = self.detector.scan_capabilities(caps, "test-server")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "sampling_declared")
        self.assertEqual(findings[0].severity.value, "high")

    def test_no_sampling_clean(self):
        caps = ServerCapabilities(tools=True, resources=True, prompts=True)
        findings = self.detector.scan_capabilities(caps, "test-server")
        self.assertEqual(len(findings), 0)

    def test_sampling_false_clean(self):
        caps = ServerCapabilities(sampling=False)
        findings = self.detector.scan_capabilities(caps, "test-server")
        self.assertEqual(len(findings), 0)

    def test_all_capabilities_flags_sampling(self):
        caps = ServerCapabilities(
            tools=True, resources=True, prompts=True, sampling=True, logging=True
        )
        findings = self.detector.scan_capabilities(caps, "full-server")
        rules = [f.rule_id for f in findings]
        self.assertIn("sampling_declared", rules)

    def test_location_includes_server_name(self):
        caps = ServerCapabilities(sampling=True)
        findings = self.detector.scan_capabilities(caps, "my-mcp")
        self.assertIn("my-mcp", findings[0].location)


if __name__ == "__main__":
    unittest.main()
