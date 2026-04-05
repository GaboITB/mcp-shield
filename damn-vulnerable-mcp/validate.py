#!/usr/bin/env python3
"""Validate MCP Shield detections against damn-vulnerable-mcp test targets.

Scans each vulnerable MCP file and verifies that the expected findings
are detected. This serves as an integration test for the scanner.

Usage:
    python3 damn-vulnerable-mcp/validate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.core.registry import create_default_registry

# Expected detections per file: (filename, expected_rule_ids)
EXPECTED: list[tuple[str, list[str]]] = [
    (
        "01-shell-injection.js",
        ["shell_injection", "shell_hardcoded"],
    ),
    (
        "02-eval-exec.js",
        ["eval_exec_dynamic", "eval_exec_static"],
    ),
    (
        "03-ssrf.ts",
        ["ssrf_dynamic_url", "ssrf_env_url"],
    ),
    (
        "04-secrets.py",
        ["secrets_hardcoded", "tls_disabled", "credential_in_args"],
    ),
    (
        "05-path-traversal.js",
        ["path_traversal"],
    ),
    (
        "06-postinstall-supply-chain/package.json",
        ["postinstall_script"],
    ),
    (
        "06-postinstall-supply-chain/index.js",
        ["obfuscated_code", "base64_decode", "telemetry_phonehome"],
    ),
    (
        "07-prompt-injection.json",
        [],  # JSON metadata — scanned separately via meta detectors
    ),
    (
        "08-permissions-excessive.js",
        ["excessive_permissions", "obfuscated_code", "base64_decode"],
    ),
    (
        "09-deno-bun-runtime.ts",
        ["shell_injection", "shell_hardcoded"],
    ),
    (
        "10-kitchen-sink.py",
        [
            "shell_injection",
            "eval_exec_dynamic",
            "secrets_hardcoded",
            "sensitive_file_access",
        ],
    ),
]


def main() -> int:
    reg = create_default_registry()
    dvmcp_dir = Path(__file__).parent
    passed = 0
    failed = 0
    total_findings = 0

    print("=" * 70)
    print("damn-vulnerable-mcp — MCP Shield Validation Suite")
    print("=" * 70)
    print()

    for filename, expected_rules in EXPECTED:
        filepath = dvmcp_dir / filename
        if not filepath.exists():
            print(f"  SKIP  {filename} — file not found")
            continue

        content = filepath.read_text(encoding="utf-8", errors="replace")

        # Run all source detectors
        findings = []
        for detector in reg.source_detectors:
            findings.extend(detector.scan_file(str(filepath), content))

        found_rules = {f.rule_id for f in findings}
        total_findings += len(findings)

        if not expected_rules:
            # No source-level expectations (e.g., JSON metadata file)
            print(f"  INFO  {filename} — {len(findings)} findings (metadata target)")
            passed += 1
            continue

        missing = [r for r in expected_rules if r not in found_rules]

        if missing:
            print(f"  FAIL  {filename}")
            print(f"         Expected: {expected_rules}")
            print(f"         Found:    {sorted(found_rules)}")
            print(f"         Missing:  {missing}")
            failed += 1
        else:
            print(
                f"  PASS  {filename} — {len(findings)} findings, all expected rules detected"
            )
            passed += 1

    print()
    print("-" * 70)
    print(f"Results: {passed} passed, {failed} failed, {total_findings} total findings")
    print("-" * 70)

    if failed > 0:
        print("\nSome expected detections are missing!")
        return 1

    print("\nAll expected detections verified successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
