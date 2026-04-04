"""AIVSS — AI Vulnerability Scoring System.

Inspired by CVSS v4.0, adapted for AI/MCP agent security.
Three dimensions scored 0-10, weighted into a final 0-10 score.

Ported from MCP Shield v1.1 compute_aivss() with additional v2 metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from mcp_shield.core.models import Finding


@dataclass(frozen=True, slots=True)
class AIVSSResult:
    """Result of an AIVSS scoring pass."""

    score: float  # 0.0 - 10.0
    severity: str  # None / Low / Medium / High / Critical
    exploitation: float  # 0.0 - 10.0
    impact: float  # 0.0 - 10.0
    trust: float  # 0.0 - 10.0


def _has(findings: Sequence[Finding], *rule_ids: str) -> bool:
    """Return True if any finding matches one of the given rule_ids."""
    target = set(rule_ids)
    return any(f.rule_id in target for f in findings)


def _count(findings: Sequence[Finding], rule_id: str) -> int:
    """Return count of findings matching rule_id."""
    return sum(1 for f in findings if f.rule_id == rule_id)


def compute_aivss(findings: Sequence[Finding]) -> AIVSSResult:
    """Compute an AIVSS score from a list of findings.

    Dimensions:
      - Exploitation (weight 0.40): ease of attack / prompt injection
      - Impact       (weight 0.35): potential damage
      - Trust        (weight 0.25): reliability of the MCP server

    Returns an AIVSSResult dataclass.
    """

    # --- Detect presence of specific rule categories ---

    # v1.0 metrics
    has_shell_exec = _has(
        findings,
        "shell_injection",
        "eval_exec_dynamic",
    )
    has_network_exfil = _has(
        findings,
        "telemetry_phonehome",
    )
    has_postinstall = _has(findings, "postinstall_script")
    has_obfuscation = _has(findings, "obfuscated_code")
    phantom_count = _count(findings, "phantom_dependency")
    tls_disabled = _has(findings, "tls_disabled")
    phonehome = _has(findings, "telemetry_phonehome")

    # v1.1 metrics
    has_force_push = _has(findings, "force_push")
    has_sql_injection = _has(findings, "sql_multistatement")
    has_exfil_api = _has(
        findings,
        "telemetry_phonehome",
        "ssrf_dynamic_url",
    )
    has_ssrf = _has(findings, "ssrf_dynamic_url", "ssrf_env_url")
    has_cred_args = _has(findings, "credential_in_args")
    is_deprecated = _has(findings, "npm_deprecated")
    no_rate_limit = _has(findings, "no_rate_limiting")

    # v2 metrics — meta / delta detectors
    has_prompt_injection = _has(findings, "prompt_injection")
    has_unicode_invisible = _has(findings, "unicode_invisible")
    has_homoglyph = _has(findings, "homoglyph_spoofing")
    has_schema_injection = _has(findings, "schema_injection")
    has_tool_shadowing = _has(findings, "tool_shadowing")
    has_capability_drift = _has(findings, "capability_drift")

    # ---- Exploitation (0-10): ease of attack by an attacker / prompt injection ----
    exploitation = 0.0
    if has_shell_exec:
        exploitation += 4.0
    if has_postinstall:
        exploitation += 2.0
    if has_obfuscation:
        exploitation += 3.0
    if has_sql_injection:
        exploitation += 3.0
    if has_ssrf:
        exploitation += 2.0
    # v2 additions
    if has_prompt_injection:
        exploitation += 4.0
    if has_unicode_invisible:
        exploitation += 2.0
    if has_homoglyph:
        exploitation += 2.0
    if has_schema_injection:
        exploitation += 2.5
    exploitation = min(exploitation, 10.0)

    # ---- Impact (0-10): potential damage ----
    impact = 0.0
    if has_network_exfil:
        impact += 4.0
    if has_shell_exec:
        impact += 3.0
    if phantom_count >= 2:
        impact += 2.0
    if has_force_push:
        impact += 2.5
    if has_exfil_api:
        impact += 2.0
    if has_cred_args:
        impact += 2.0
    # v2 additions
    if has_tool_shadowing:
        impact += 3.5
    if has_capability_drift:
        impact += 3.0
    if has_prompt_injection:
        impact += 2.0
    impact = min(impact, 10.0)

    # ---- Trust (0-10): reliability of the MCP server ----
    trust = 0.0
    if tls_disabled:
        trust += 2.0
    if phonehome:
        trust += 1.5
    if phantom_count >= 1:
        trust += 1.0
    if is_deprecated:
        trust += 2.5
    if no_rate_limit:
        trust += 1.0
    # v2 additions
    if has_unicode_invisible or has_homoglyph:
        trust += 2.0
    if has_schema_injection:
        trust += 1.5
    if has_capability_drift:
        trust += 2.0
    trust = min(trust, 10.0)

    # ---- Final weighted score ----
    aivss_score = round(exploitation * 0.40 + impact * 0.35 + trust * 0.25, 1)
    aivss_score = min(aivss_score, 10.0)

    # ---- Severity label ----
    if aivss_score == 0.0:
        severity = "None"
    elif aivss_score <= 3.9:
        severity = "Low"
    elif aivss_score <= 6.9:
        severity = "Medium"
    elif aivss_score <= 8.9:
        severity = "High"
    else:
        severity = "Critical"

    return AIVSSResult(
        score=aivss_score,
        severity=severity,
        exploitation=round(exploitation, 1),
        impact=round(impact, 1),
        trust=round(trust, 1),
    )
