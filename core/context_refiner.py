"""Context-aware post-processing of raw findings.

Applies refinement rules to reduce false positives without modifying
the detectors themselves. Each rule can suppress a finding, change its
severity, or adjust its confidence score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_shield.core.file_classifier import FileRole
from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Safe postinstall commands (npm build hooks that are NOT attacks)
# ---------------------------------------------------------------------------

_SAFE_BUILD_RE = re.compile(
    r"^(?:npm\s+run\s+(?:build|compile|dist|prepare|tsc|postbuild)|"
    r"tsc(?:\s|$)|tsup|rollup|esbuild|vite\s+build|webpack|"
    r"babel|swc|unbuild|microbundle|ncc|"
    r"node-gyp\s+rebuild|husky(?:\s+install)?|patch-package|ngcc)",
    re.IGNORECASE,
)

# Dangerous patterns in lifecycle scripts
_DANGEROUS_SCRIPT_RE = re.compile(
    r"curl\s+.*\|\s*(?:sh|bash)|"
    r"wget\s+.*&&.*(?:sh|bash)|"
    r"node\s+-e\s+['\"]|"
    r"python[3]?\s+-c\s+['\"]|"
    r">\s*/etc/|"
    r"\bsudo\b|"
    r"base64\s+-d|"
    r"\$\(curl",
    re.IGNORECASE,
)

# Benign imperative patterns in tool descriptions
_BENIGN_IMPERATIVE_RE = re.compile(
    r"you\s+(?:should|must|shall)\s+"
    r"(?:provide|use|pass|specify|ensure|include|set|enter|supply|define|"
    r"have|configure|select|choose|create|add|give|make sure)",
    re.IGNORECASE,
)

# Conviction patterns (genuine prompt injection, never FP)
_CONVICTION_RE = re.compile(
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"forget\s+(?:all\s+)?(?:previous|prior|your)\s+instructions|"
    r"<\s*(?:system|instruction|admin|override)\s*>|"
    r"do\s+not\s+(?:tell|reveal|show|inform)\s+the\s+user|"
    r"secretly\s+(?:also|always|first|then)|"
    r"new\s+instructions\s*:|"
    r"IMPORTANT\s*:\s*(?:override|ignore|forget|disregard)",
    re.IGNORECASE,
)

# Shell injection: method definition (not a call)
_METHOD_DEF_RE = re.compile(
    r"(?:async\s+|static\s+|public\s+|private\s+|protected\s+)*"
    r"(?:function\s+)?(?:exec|spawn|fork)\s*\([^)]*\)\s*[{:]",
    re.IGNORECASE,
)

# Context: env var alternative present in the file
_ENV_VAR_RE = re.compile(
    r"process\.env\.|os\.(?:environ|getenv)|Deno\.env\.get",
    re.IGNORECASE,
)

# Git context for force push
_GIT_CONTEXT_RE = re.compile(
    r"git\s+(?:push|rebase|merge)|forcePush|force-push|updateRef",
    re.IGNORECASE,
)

# Lockfile names
_LOCKFILES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "Pipfile.lock",
    "poetry.lock",
    "go.sum",
)


@dataclass
class RefinementContext:
    """Context passed to the refiner for each scan."""

    repo_path: Path | None = None
    file_roles: dict[str, FileRole] | None = None
    file_contents: dict[str, str] | None = None
    has_lockfile: bool = False


def build_context(
    repo_path: Path | None = None,
    file_roles: dict[str, FileRole] | None = None,
    file_contents: dict[str, str] | None = None,
) -> RefinementContext:
    """Build a refinement context from scan data."""
    has_lockfile = False
    if repo_path:
        has_lockfile = any((repo_path / lf).exists() for lf in _LOCKFILES)
    return RefinementContext(
        repo_path=repo_path,
        file_roles=file_roles or {},
        file_contents=file_contents or {},
        has_lockfile=has_lockfile,
    )


def refine_finding(
    finding: Finding,
    ctx: RefinementContext,
) -> Finding | None:
    """Refine a single finding. Returns None to suppress it entirely.

    This function applies context-aware rules to adjust severity and
    confidence without modifying the detectors themselves.
    """
    rule = finding.rule_id
    loc = finding.location
    evidence = finding.evidence

    # Determine file role
    file_path = loc.split(":")[0] if ":" in loc else loc
    file_roles = ctx.file_roles or {}
    role = file_roles.get(file_path, FileRole.UNKNOWN)

    # ----- postinstall_script ------------------------------------------------
    if rule == "postinstall_script":
        return _refine_postinstall(finding, evidence)

    # ----- shell_injection ---------------------------------------------------
    if rule == "shell_injection":
        # Suppress method definitions (async exec_command(target, cmd) {)
        if _METHOD_DEF_RE.search(evidence):
            return None
        # Downgrade in test files
        if role == FileRole.TEST:
            return _with(finding, severity=Severity.INFO, confidence=0.3)
        # Downgrade in build scripts
        if role == FileRole.BUILD:
            return _with(finding, severity=Severity.LOW, confidence=0.3)

    # ----- shell_hardcoded ---------------------------------------------------
    if rule == "shell_hardcoded":
        # allowShell: true is NOT Node.js shell: true
        if "allowshell" in evidence.lower():
            return None
        # Downgrade in test/build files
        if role in (FileRole.TEST, FileRole.BUILD):
            return _with(finding, severity=Severity.INFO, confidence=0.3)

    # ----- force_push --------------------------------------------------------
    if rule == "force_push":
        # Only flag if git context is present
        if not _GIT_CONTEXT_RE.search(evidence):
            return None

    # ----- tls_disabled ------------------------------------------------------
    if rule == "tls_disabled":
        if role == FileRole.TEST:
            return _with(
                finding,
                severity=Severity.INFO,
                confidence=0.3,
                detail="TLS disabled in test file",
            )
        if role == FileRole.CONFIG:
            return _with(finding, severity=Severity.MEDIUM, confidence=0.5)

    # ----- credential_in_args ------------------------------------------------
    if rule == "credential_in_args":
        # Check if env var alternative exists in the same file
        file_content = (ctx.file_contents or {}).get(file_path, "")
        if file_content and _ENV_VAR_RE.search(file_content):
            return _with(
                finding,
                severity=Severity.LOW,
                confidence=0.3,
                detail="Environment variable alternative detected in same file",
            )

    # ----- unpinned_dependency -----------------------------------------------
    if rule == "unpinned_dependency":
        if ctx.has_lockfile:
            return _with(
                finding,
                severity=Severity.INFO,
                confidence=0.2,
                detail="Lockfile present — versions pinned in practice",
            )

    # ----- phantom_dependency ------------------------------------------------
    if rule == "phantom_dependency":
        # Already LOW when bundled, make it INFO
        if finding.severity == Severity.LOW:
            return _with(finding, severity=Severity.INFO, confidence=0.2)

    # ----- prompt_injection --------------------------------------------------
    if rule == "prompt_injection":
        return _refine_prompt_injection(finding, evidence)

    # ----- description_imperative (covers 3 different checks) ----------------
    if rule == "description_imperative":
        # Cross-tool reference -> MEDIUM (not HIGH)
        if "cross-tool" in finding.title.lower() or "other tool" in evidence.lower():
            return _with(finding, severity=Severity.MEDIUM, confidence=0.5)

    # ----- Default: assign confidence based on detection method ---------------
    return _assign_default_confidence(finding, role)


def _refine_postinstall(finding: Finding, evidence: str) -> Finding:
    """Refine postinstall_script findings based on script content."""
    evidence_lower = evidence.lower()

    # Dangerous content in any hook -> stay CRITICAL
    if _DANGEROUS_SCRIPT_RE.search(evidence):
        return _with(finding, confidence=0.95)

    # prepare hook with safe build commands -> INFO
    if "prepare" in evidence_lower:
        script_part = (
            evidence.split(":", 1)[-1].strip() if ":" in evidence else evidence
        )
        cmds = re.split(r"\s*[&|;]+\s*", script_part)
        cmds = [c.strip() for c in cmds if c.strip()]
        if all(_SAFE_BUILD_RE.match(c) for c in cmds):
            return _with(
                finding,
                severity=Severity.INFO,
                confidence=0.95,
                detail="Standard build preparation script (safe)",
            )
        return _with(
            finding,
            severity=Severity.LOW,
            confidence=0.6,
            detail="Non-standard prepare script — review manually",
        )

    # postinstall/preinstall/install without dangerous content -> HIGH
    return _with(
        finding,
        severity=Severity.HIGH,
        confidence=0.7,
        detail="Lifecycle hook runs at install time — review script content",
    )


def _refine_prompt_injection(finding: Finding, evidence: str) -> Finding | None:
    """Refine prompt_injection findings with graduated severity."""
    # Conviction patterns stay CRITICAL
    if _CONVICTION_RE.search(evidence):
        return _with(finding, confidence=0.95)

    # Benign imperatives are suppressed entirely
    if _BENIGN_IMPERATIVE_RE.search(evidence):
        return None

    # "you are now/actually/will now" -> HIGH (role reassignment)
    if re.search(r"you\s+(?:are\s+now|are\s+actually|will\s+now)", evidence, re.I):
        return _with(finding, severity=Severity.HIGH, confidence=0.7)

    # "you must/should/shall" without dangerous verb -> MEDIUM
    if re.search(r"you\s+(?:must|should|shall)\b", evidence, re.I):
        return _with(finding, severity=Severity.MEDIUM, confidence=0.4)

    # system_prompt reference -> MEDIUM
    if re.search(r"system.?prompt", evidence, re.I):
        return _with(finding, severity=Severity.MEDIUM, confidence=0.5)

    # Default: downgrade from CRITICAL to HIGH
    if finding.severity == Severity.CRITICAL:
        return _with(finding, severity=Severity.HIGH, confidence=0.6)

    return _with(finding, confidence=0.6)


def refine_findings(
    findings: list[Finding],
    ctx: RefinementContext,
) -> list[Finding]:
    """Refine a list of findings, suppressing FPs and adjusting severity."""
    refined = []
    for f in findings:
        result = refine_finding(f, ctx)
        if result is not None:
            refined.append(result)
    return refined


def _with(
    finding: Finding,
    severity: Severity | None = None,
    confidence: float | None = None,
    detail: str | None = None,
) -> Finding:
    """Create a new Finding with adjusted fields (frozen dataclass)."""
    return Finding(
        rule_id=finding.rule_id,
        severity=severity if severity is not None else finding.severity,
        surface=finding.surface,
        title=finding.title,
        evidence=finding.evidence,
        location=finding.location,
        detail=detail if detail is not None else finding.detail,
        confidence=confidence if confidence is not None else finding.confidence,
    )


def _assign_default_confidence(finding: Finding, role: FileRole) -> Finding:
    """Assign default confidence based on file role and severity."""
    if role == FileRole.TEST:
        return _with(finding, confidence=0.3)
    if role == FileRole.BUILD:
        return _with(finding, confidence=0.4)
    conf = {
        Surface.SOURCE_CODE: 0.7,
        Surface.MCP_METADATA: 0.8,
        Surface.RUNTIME_DELTA: 0.9,
    }.get(finding.surface, 0.7)
    return _with(finding, confidence=conf)
