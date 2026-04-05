"""Remediation guidance for MCP Shield rule IDs.

Provides short, actionable remediation advice for each rule_id.
Used by reporters to help users fix detected issues.
"""

from __future__ import annotations

REMEDIATION_MAP: dict[str, str] = {
    # ── Source code detectors ──────────────────────────────────────────
    "shell_injection": (
        "Use subprocess with a list of arguments instead of shell=True. "
        "Validate and sanitize all user inputs before passing to commands."
    ),
    "shell_hardcoded": (
        "Replace hardcoded shell commands with parameterized subprocess calls. "
        "Avoid shell=True when arguments are static."
    ),
    "eval_exec_dynamic": (
        "Replace eval/exec with safe alternatives such as ast.literal_eval or a sandboxed interpreter. "
        "Never pass user-controlled data to eval."
    ),
    "eval_exec_static": (
        "Refactor static eval/exec calls into direct function invocations or dictionary lookups."
    ),
    "ssrf_dynamic_url": (
        "Validate and allowlist target URLs before making requests. "
        "Block access to internal/private IP ranges."
    ),
    "ssrf_env_url": (
        "Validate URLs loaded from environment variables against an explicit allowlist. "
        "Reject private and loopback addresses."
    ),
    "secrets_hardcoded": (
        "Move secrets to environment variables or a secrets manager. "
        "Never commit credentials to source code."
    ),
    "path_traversal": (
        "Normalize file paths with os.path.realpath and verify they stay within the intended base directory. "
        "Reject inputs containing '..' sequences."
    ),
    "excessive_permissions": (
        "Apply the principle of least privilege: request only the permissions the tool actually needs. "
        "Document why each permission is required."
    ),
    "tls_disabled": (
        "Enable TLS certificate verification (verify=True). "
        "Use a trusted CA bundle and never disable SSL checks in production."
    ),
    "postinstall_script": (
        "Review postinstall scripts for malicious behavior before publishing. "
        "Consider using --ignore-scripts during npm install."
    ),
    "obfuscated_code": (
        "Remove code obfuscation and provide readable source. "
        "Obfuscated code in an MCP server is a strong indicator of malicious intent."
    ),
    "base64_decode": (
        "Audit base64-decoded payloads to ensure they are not hiding malicious code. "
        "Prefer plain-text configuration where possible."
    ),
    "telemetry_phonehome": (
        "Make telemetry opt-in with clear user consent. "
        "Document what data is collected and where it is sent."
    ),
    "sensitive_file_access": (
        "Restrict file access to only the paths required by the tool's function. "
        "Never read SSH keys, credentials, or browser data without explicit user consent."
    ),
    "force_push": (
        "Remove force-push capabilities from MCP tools. "
        "Use regular push with conflict resolution to prevent data loss."
    ),
    "sql_multistatement": (
        "Use parameterized queries and disallow multi-statement execution. "
        "Limit database permissions to the minimum required operations."
    ),
    "credential_in_args": (
        "Accept credentials via environment variables or a secure config file, not as tool arguments. "
        "Mask sensitive fields in logs and schemas."
    ),
    "exfiltration_api": (
        "Restrict outbound network calls to a documented allowlist of endpoints. "
        "Log all external API calls for audit purposes."
    ),
    # ── Meta detectors ─────────────────────────────────────────────────
    "prompt_injection": (
        "Remove imperative instructions from tool descriptions. "
        "Descriptions should only describe the tool's function, not command the LLM."
    ),
    "unicode_invisible": (
        "Remove invisible Unicode characters (zero-width spaces, directional overrides) from descriptions and schemas. "
        "These can hide prompt injections."
    ),
    "homoglyph_spoofing": (
        "Replace lookalike Unicode characters with their ASCII equivalents. "
        "Homoglyphs can trick users and LLMs into misidentifying tool names."
    ),
    "schema_injection": (
        "Sanitize JSON schema definitions to remove embedded instructions or executable content. "
        "Schema fields should only define data types and constraints."
    ),
    "markdown_injection": (
        "Strip or escape Markdown image tags and links in tool descriptions. "
        "These can be used for data exfiltration via rendered content."
    ),
    "description_empty": (
        "Add a clear description to every tool explaining what it does. "
        "Users and LLMs rely on descriptions to decide whether to approve tool use."
    ),
    "description_oversized": (
        "Keep tool descriptions concise (under 1024 characters). "
        "Oversized descriptions may contain hidden instructions or overwhelm the LLM context."
    ),
    "description_imperative": (
        "Rewrite descriptions to be declarative rather than imperative. "
        "Replace commands like 'Always use this tool first' with factual capability statements."
    ),
    # ── Delta detectors ────────────────────────────────────────────────
    "tool_shadowing": (
        "Rename tools that shadow built-in or well-known tool names. "
        "Tool shadowing can hijack LLM behavior by intercepting calls meant for trusted tools."
    ),
    "param_divergence": (
        "Align the live tool schema with the static/documented schema. "
        "Parameter differences between registration and runtime indicate potential rug-pull behavior."
    ),
    "capability_drift": (
        "Investigate why the server's capabilities changed between static analysis and runtime. "
        "Pin the server version and re-audit after any update."
    ),
    "tool_appeared_live": (
        "Audit newly appeared tools that were not present in the static manifest. "
        "Tools injected at runtime may perform undisclosed operations."
    ),
    "tool_disappeared_live": (
        "Investigate why a statically declared tool is missing at runtime. "
        "Disappearing tools may indicate conditional or environment-dependent behavior."
    ),
    # ── Binary analysis detectors ──────────────────────────────────────
    "binary_detected": (
        "Review why a binary file is included in the MCP server package. "
        "Prefer source-compiled or well-known signed binaries."
    ),
    "binary_url": (
        "Audit URLs embedded in binary files and verify they point to legitimate endpoints."
    ),
    "binary_shell_cmd": (
        "Review shell commands found in binary data for malicious intent. "
        "Ensure no hidden command execution paths exist."
    ),
    "binary_secret": (
        "Remove hardcoded secrets from binary files. "
        "Use runtime environment variables or a secrets manager."
    ),
    "binary_c2_indicator": (
        "Investigate potential command-and-control indicators immediately. "
        "This is a strong signal of malicious behavior; consider removing the server."
    ),
    "binary_embedded_payload": (
        "Extract and analyze the embedded payload to determine its purpose. "
        "Embedded executables or archives in binaries are suspicious."
    ),
    "binary_high_entropy": (
        "Inspect high-entropy binary sections for encrypted or packed malicious payloads. "
        "Legitimate binaries rarely contain large high-entropy regions."
    ),
    "binary_encrypted_section": (
        "Investigate encrypted sections in binaries for hidden functionality. "
        "Document the purpose of any encrypted data."
    ),
    "binary_capability": (
        "Review declared binary capabilities and ensure least-privilege principles are followed."
    ),
    "binary_excessive_caps": (
        "Reduce binary capabilities to the minimum required set. "
        "Excessive permissions increase the blast radius of a compromise."
    ),
    "binary_oversized": (
        "Investigate why the binary is unusually large. "
        "Oversized binaries may bundle unnecessary or malicious payloads."
    ),
    # ── Bait-and-switch detectors ──────────────────────────────────────
    "bait_switch": (
        "The server changed tool definitions between install and runtime (rug pull detected). "
        "Do not trust this server; audit all tool definitions manually."
    ),
    "bait_switch_tool_hidden": (
        "A tool present at install time was hidden at runtime. "
        "This indicates deliberate concealment; investigate the server's intent."
    ),
    "bait_switch_desc_changed": (
        "A tool description changed between install and runtime. "
        "Pin the server version and compare descriptions to detect injected instructions."
    ),
    "bait_switch_schema_changed": (
        "A tool's input schema changed between install and runtime. "
        "Schema changes can silently alter what data the tool collects."
    ),
    # ── Sandbox runtime detectors ──────────────────────────────────────
    "sandbox_sensitive_file": (
        "Block access to sensitive files (SSH keys, credentials, browser data) in the sandbox. "
        "Use filesystem allowlists to restrict readable paths."
    ),
    "sandbox_external_connection": (
        "Restrict outbound network connections from the sandbox to a documented allowlist. "
        "Unexpected external connections may indicate data exfiltration."
    ),
    "sandbox_dns_query": (
        "Limit DNS resolution in the sandbox to expected domains. "
        "Unexpected DNS queries can be used for data exfiltration or C2 communication."
    ),
    "sandbox_suspicious_process": (
        "Restrict process execution in the sandbox to a known set of safe commands. "
        "Unexpected process spawning may indicate exploitation."
    ),
    # ── Dependency detectors ───────────────────────────────────────────
    "unpinned_dependency": (
        "Pin all dependencies to exact versions (e.g., ==1.2.3 or 1.2.3). "
        "Unpinned dependencies can silently introduce malicious updates."
    ),
    "phantom_dependency": (
        "Add the missing dependency to the project's manifest (package.json, requirements.txt). "
        "Phantom dependencies can be hijacked via dependency confusion attacks."
    ),
    "native_module_dep": (
        "Audit native/C-extension modules for memory safety issues. "
        "Prefer pure-Python/JS alternatives when available."
    ),
    "npm_deprecated": (
        "Replace deprecated packages with their maintained successors. "
        "Deprecated packages no longer receive security patches."
    ),
    "sdk_outdated": (
        "Update the MCP SDK to the latest stable version. "
        "Older SDKs may lack critical security fixes and protocol improvements."
    ),
    "no_rate_limiting": (
        "Implement rate limiting on tool invocations to prevent abuse. "
        "Use token-bucket or sliding-window algorithms."
    ),
    # ── Resource detectors ───────────────────────────────────────────
    "resource_dangerous_uri": (
        "Avoid file://, data://, and javascript:// URI schemes in resources. "
        "Use https:// URIs pointing to trusted, validated endpoints."
    ),
    "resource_internal_uri": (
        "Do not expose internal network resources (localhost, 10.x, 192.168.x). "
        "If internal access is required, document it and restrict to specific paths."
    ),
    "resource_broad_uri": (
        "Replace wildcard resource URIs with specific paths. "
        "Broad wildcards allow the server to inject arbitrary content into the LLM context."
    ),
    "resource_executable_mime": (
        "Do not serve executable MIME types as MCP resources. "
        "Use text/plain or application/json for content injected into the LLM context."
    ),
    # ── Prompt template detectors ─────────────────────────────────────
    "prompt_template_suspicious": (
        "Review prompt arguments with long default values for hidden instructions. "
        "Default values should be short, obvious, and user-visible."
    ),
    # ── Sampling detector ─────────────────────────────────────────────
    "sampling_declared": (
        "The server requests sampling capability (LLM completion control). "
        "Only approve if you trust the server — it can make the LLM produce "
        "attacker-controlled output. Deny this capability if not strictly needed."
    ),
    # ── Annotation coherence ──────────────────────────────────────────
    "annotation_incoherent": (
        "Fix tool annotations to match actual behavior. "
        "A tool marked readOnlyHint=true that performs writes is misleading "
        "and can trick approval workflows into granting unsafe access."
    ),
    # ── Health detectors (informational) ──────────────────────────────
    "no_tests": (
        "Add a test suite to validate tool behavior and catch regressions. "
        "Even basic smoke tests significantly improve trust."
    ),
    "no_license": ("Add a LICENSE file to clarify usage terms and legal obligations."),
    "no_ci": (
        "Set up continuous integration to run tests and linters on every commit. "
        "CI provides a baseline of code quality assurance."
    ),
}
