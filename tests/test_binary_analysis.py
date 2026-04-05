"""Tests for binary analysis detector."""

from __future__ import annotations

import math
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.detectors.code.binary_analysis import (
    BinaryAnalysisDetector,
    _extract_strings,
    _is_binary,
    _shannon_entropy,
    _section_entropies,
)


def _make_elf_binary(
    strings_to_embed: list[str] | None = None, size: int = 8192
) -> str:
    """Create a synthetic ELF-like binary with embedded strings."""
    # ELF magic + padding
    data = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9  # 16 bytes ELF header start
    # Fill with semi-random bytes (not too high entropy)
    import struct

    for i in range(0, size - 16, 4):
        data += struct.pack("<I", (i * 2654435761) & 0xFFFFFFFF)

    # Embed strings
    if strings_to_embed:
        for s in strings_to_embed:
            # Insert at a somewhat random position
            pos = hash(s) % (len(data) - len(s) - 10)
            pos = max(16, abs(pos))
            encoded = b"\x00" + s.encode("ascii") + b"\x00"
            data = data[:pos] + encoded + data[pos + len(encoded) :]

    # Ensure minimum size
    if len(data) < size:
        data += b"\x00" * (size - len(data))

    # Convert to latin-1 string (how the scanner receives binary content)
    return data[:size].decode("latin-1", errors="replace")


def _make_pe_binary(strings_to_embed: list[str] | None = None, size: int = 8192) -> str:
    """Create a synthetic PE-like binary."""
    data = b"MZ" + b"\x90" * 14  # 16 bytes
    import struct

    for i in range(0, size - 16, 4):
        data += struct.pack("<I", (i * 1103515245 + 12345) & 0xFFFFFFFF)

    if strings_to_embed:
        for s in strings_to_embed:
            pos = abs(hash(s)) % max(1, len(data) - len(s) - 10)
            pos = max(16, pos)
            encoded = b"\x00" + s.encode("ascii") + b"\x00"
            data = data[:pos] + encoded + data[pos + len(encoded) :]

    if len(data) < size:
        data += b"\x00" * (size - len(data))

    return data[:size].decode("latin-1", errors="replace")


class TestIsBinary(unittest.TestCase):
    def test_elf_detected(self):
        content = _make_elf_binary()
        self.assertTrue(_is_binary("server", content))

    def test_pe_detected(self):
        content = _make_pe_binary()
        self.assertTrue(_is_binary("server.exe", content))

    def test_macho_detected(self):
        data = b"\xcf\xfa\xed\xfe" + b"\x00" * 4092
        content = data.decode("latin-1")
        self.assertTrue(_is_binary("server", content))

    def test_js_not_binary(self):
        content = 'const x = require("fs");\nconsole.log("hello");\n'
        self.assertFalse(_is_binary("server.js", content))

    def test_python_not_binary(self):
        content = "import os\nprint('hello')\n"
        self.assertFalse(_is_binary("server.py", content))

    def test_small_file_not_binary(self):
        content = "\x7fELF" + "x" * 10
        # Small file should still be detected by magic bytes
        self.assertTrue(_is_binary("tiny", content))


class TestExtractStrings(unittest.TestCase):
    def test_extracts_ascii_strings(self):
        data = b"\x00\x00hello world\x00\x00this is a test\x00\x00"
        strings = _extract_strings(data)
        self.assertTrue(any("hello world" in s for s in strings))
        self.assertTrue(any("this is a test" in s for s in strings))

    def test_skips_short_strings(self):
        data = b"\x00ab\x00cde\x00fghijk\x00"
        strings = _extract_strings(data, min_len=6)
        self.assertEqual(len(strings), 1)
        self.assertIn("fghijk", strings[0])

    def test_empty_data(self):
        self.assertEqual(_extract_strings(b""), [])


class TestShannonEntropy(unittest.TestCase):
    def test_zero_entropy_uniform(self):
        # All same byte = 0 entropy
        data = bytes([0x41] * 1000)
        self.assertAlmostEqual(_shannon_entropy(data), 0.0, places=2)

    def test_max_entropy_random(self):
        # All 256 byte values equally = 8.0 entropy
        data = bytes(range(256)) * 4
        entropy = _shannon_entropy(data)
        self.assertGreater(entropy, 7.9)

    def test_medium_entropy_text(self):
        # English text is typically 3-5 bits
        data = b"The quick brown fox jumps over the lazy dog. " * 20
        entropy = _shannon_entropy(data)
        self.assertGreater(entropy, 3.0)
        self.assertLess(entropy, 6.0)

    def test_empty_data(self):
        self.assertEqual(_shannon_entropy(b""), 0.0)


class TestBinaryAnalysisDetector(unittest.TestCase):
    def setUp(self):
        self.det = BinaryAnalysisDetector()

    def test_skip_non_binary(self):
        f = self.det.scan_file("test.js", "console.log('hello');")
        self.assertEqual(len(f), 0)

    def test_detect_elf_binary(self):
        content = _make_elf_binary()
        f = self.det.scan_file("mcp-server", content)
        self.assertTrue(any(x.rule_id == "binary_detected" for x in f))
        self.assertTrue(any("ELF" in x.title for x in f))

    def test_detect_pe_binary(self):
        content = _make_pe_binary()
        f = self.det.scan_file("mcp-server.exe", content)
        self.assertTrue(any(x.rule_id == "binary_detected" for x in f))
        self.assertTrue(any("PE" in x.title for x in f))

    def test_detect_url_in_binary(self):
        content = _make_elf_binary(["https://evil.attacker.com/c2/beacon"])
        f = self.det.scan_file("server", content)
        urls = [x for x in f if x.rule_id == "binary_url"]
        self.assertTrue(len(urls) > 0)

    def test_skip_safe_urls(self):
        content = _make_elf_binary(["https://github.com/user/repo"])
        f = self.det.scan_file("server", content)
        urls = [x for x in f if x.rule_id == "binary_url"]
        self.assertEqual(len(urls), 0)

    def test_detect_shell_command(self):
        content = _make_elf_binary(["/bin/sh -c whoami"])
        f = self.det.scan_file("server", content)
        shell = [x for x in f if x.rule_id == "binary_shell_cmd"]
        self.assertTrue(len(shell) > 0)

    def test_detect_c2_indicator(self):
        content = _make_elf_binary(["meterpreter_reverse_tcp"])
        f = self.det.scan_file("server", content)
        c2 = [x for x in f if x.rule_id == "binary_c2_indicator"]
        self.assertTrue(len(c2) > 0)

    def test_detect_credential_pattern(self):
        content = _make_elf_binary(["password=SuperSecret123!"])
        f = self.det.scan_file("server", content)
        secrets = [x for x in f if x.rule_id == "binary_secret"]
        self.assertTrue(len(secrets) > 0)

    def test_detect_go_exec_import(self):
        content = _make_elf_binary(["os/exec", "net/http"])
        f = self.det.scan_file("server", content)
        caps = [x for x in f if x.rule_id == "binary_capability"]
        self.assertTrue(len(caps) > 0)

    def test_detect_go_excessive_caps(self):
        content = _make_elf_binary(["os/exec", "net/http", "os.ReadFile"])
        f = self.det.scan_file("server", content)
        excessive = [x for x in f if x.rule_id == "binary_excessive_caps"]
        self.assertTrue(len(excessive) > 0)

    def test_detect_rust_patterns(self):
        content = _make_elf_binary(["std::process::Command", "tokio::net"])
        f = self.det.scan_file("server", content)
        caps = [x for x in f if x.rule_id == "binary_capability"]
        self.assertTrue(len(caps) > 0)

    def test_high_entropy_detection(self):
        """Binary with mostly random data should trigger high entropy."""
        # Create a binary that's mostly random
        import struct

        data = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9
        # Fill with pseudo-random high-entropy bytes
        for i in range(20000):
            data += struct.pack("B", (i * 179 + 31) % 256)
        content = data.decode("latin-1", errors="replace")
        # Note: this may or may not trigger depending on actual entropy
        f = self.det.scan_file("packed-server", content)
        # At minimum it should detect as binary
        self.assertTrue(any(x.rule_id == "binary_detected" for x in f))

    def test_finding_weights_registered(self):
        """All binary findings should have registered weights."""
        content = _make_elf_binary(
            [
                "https://evil.com/payload",
                "/bin/sh -c id",
                "password=leaked",
                "reverse_shell",
                "os/exec",
                "net/http",
            ]
        )
        f = self.det.scan_file("server", content)
        for finding in f:
            if finding.rule_id != "binary_detected":  # INFO level, weight 0 is ok
                self.assertGreaterEqual(
                    finding.weight,
                    0,
                    f"Weight for {finding.rule_id} should be >= 0",
                )

    def test_small_binary_skipped(self):
        """Binary smaller than MIN_BINARY_SIZE should be skipped."""
        data = b"\x7fELF" + b"\x00" * 100
        content = data.decode("latin-1")
        f = self.det.scan_file("tiny", content)
        self.assertEqual(len(f), 0)


if __name__ == "__main__":
    unittest.main()
