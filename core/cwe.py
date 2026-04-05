"""CWE mapping for MCP Shield rule IDs.

Maps each rule_id to its corresponding CWE (Common Weakness Enumeration)
identifier. Used by reporters to enrich findings with standardized
vulnerability classification.
"""

from __future__ import annotations

CWE_MAP: dict[str, str] = {
    # ── Source code detectors ──────────────────────────────────────────
    "shell_injection": "CWE-78",
    "shell_hardcoded": "CWE-78",
    "eval_exec_dynamic": "CWE-95",
    "eval_exec_static": "CWE-95",
    "ssrf_dynamic_url": "CWE-918",
    "ssrf_env_url": "CWE-918",
    "secrets_hardcoded": "CWE-798",
    "path_traversal": "CWE-22",
    "excessive_permissions": "CWE-250",
    "tls_disabled": "CWE-295",
    "postinstall_script": "CWE-506",
    "obfuscated_code": "CWE-506",
    "base64_decode": "CWE-506",
    "telemetry_phonehome": "CWE-200",
    "sensitive_file_access": "CWE-200",
    "force_push": "CWE-284",
    "sql_multistatement": "CWE-89",
    "credential_in_args": "CWE-798",
    "exfiltration_api": "CWE-200",
    # ── Meta detectors ─────────────────────────────────────────────────
    "prompt_injection": "CWE-77",
    "unicode_invisible": "CWE-116",
    "homoglyph_spoofing": "CWE-116",
    "schema_injection": "CWE-20",
    "markdown_injection": "CWE-79",
    "description_empty": "CWE-710",
    "description_oversized": "CWE-400",
    "description_imperative": "CWE-77",
    # ── Delta detectors ────────────────────────────────────────────────
    "tool_shadowing": "CWE-506",
    "param_divergence": "CWE-345",
    "capability_drift": "CWE-345",
    "tool_appeared_live": "CWE-506",
    "tool_disappeared_live": "CWE-345",
    # ── Binary analysis detectors ──────────────────────────────────────
    # "binary_detected" has no CWE — it is purely informational.
    "binary_url": "CWE-918",
    "binary_shell_cmd": "CWE-78",
    "binary_secret": "CWE-798",
    "binary_c2_indicator": "CWE-506",
    "binary_embedded_payload": "CWE-506",
    "binary_high_entropy": "CWE-506",
    "binary_encrypted_section": "CWE-506",
    "binary_capability": "CWE-250",
    "binary_excessive_caps": "CWE-250",
    "binary_oversized": "CWE-400",
    # ── Bait-and-switch detectors ──────────────────────────────────────
    "bait_switch": "CWE-345",
    "bait_switch_tool_hidden": "CWE-506",
    "bait_switch_desc_changed": "CWE-345",
    "bait_switch_schema_changed": "CWE-345",
    # ── Sandbox runtime detectors ──────────────────────────────────────
    "sandbox_sensitive_file": "CWE-200",
    "sandbox_external_connection": "CWE-918",
    "sandbox_dns_query": "CWE-918",
    "sandbox_suspicious_process": "CWE-78",
    # ── Dependency detectors ───────────────────────────────────────────
    "unpinned_dependency": "CWE-829",
    "phantom_dependency": "CWE-829",
    "native_module_dep": "CWE-829",
    "npm_deprecated": "CWE-1104",
    "sdk_outdated": "CWE-1104",
    "no_rate_limiting": "CWE-770",
    # ── Resource detectors ───────────────────────────────────────────
    "resource_dangerous_uri": "CWE-918",
    "resource_internal_uri": "CWE-918",
    "resource_broad_uri": "CWE-284",
    "resource_executable_mime": "CWE-434",
    # ── Prompt template detectors ─────────────────────────────────────
    "prompt_template_suspicious": "CWE-77",
    # ── Sampling detector ─────────────────────────────────────────────
    "sampling_declared": "CWE-77",
    # ── Annotation coherence ──────────────────────────────────────────
    "annotation_incoherent": "CWE-345",
    # ── Health detectors (informational, no CWE) ──────────────────────
    # "no_tests", "no_license", "no_ci" have no CWE mapping.
}
