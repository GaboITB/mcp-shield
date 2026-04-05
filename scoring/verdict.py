"""Verdict and grade computation for MCP Shield v3.

Ported from MCP Shield v1.1 compute_verdict() with added grade mapping.
"""

from __future__ import annotations

from mcp_shield.core.models import Grade


def compute_verdict(total_score: int) -> str:
    """Map a total weighted score to a human-readable verdict.

    Thresholds (from v1.1):
        0-5   -> SAFE
        6-20  -> CAUTION
        21-50 -> WARNING
        51+   -> DANGER

    Args:
        total_score: Sum of finding weights (AuditResult.total_score).

    Returns:
        One of "SAFE", "CAUTION", "WARNING", "DANGER".
    """
    if total_score <= 5:
        return "SAFE"
    elif total_score <= 20:
        return "CAUTION"
    elif total_score <= 50:
        return "WARNING"
    else:
        return "DANGER"


def compute_grade(total_score: int) -> Grade:
    """Map a total weighted score to a letter grade.

    Consistent with AuditResult.grade property in models.py:
        0        -> A+
        1-20     -> A
        21-60    -> B
        61-150   -> C
        151-300  -> D
        301+     -> F

    Args:
        total_score: Sum of finding weights (AuditResult.total_score).

    Returns:
        A Grade enum member.
    """
    if total_score == 0:
        return Grade.A_PLUS
    if total_score <= 20:
        return Grade.A
    if total_score <= 60:
        return Grade.B
    if total_score <= 150:
        return Grade.C
    if total_score <= 300:
        return Grade.D
    return Grade.F
