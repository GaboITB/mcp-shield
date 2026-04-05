"""Capability Drift Detector — MCP Shield v3.

Compares two snapshots of live tools (e.g., from different times or
different clientInfo) to detect behavioral changes: new/removed tools,
annotation mutations, and significant description drift.
"""

from __future__ import annotations

from mcp_shield.core.models import Finding, Severity, Surface, ToolInfo


def _char_diff_ratio(a: str, b: str) -> float:
    """Return the fraction of characters that differ between *a* and *b*.

    Uses a simple symmetric difference based on character counts, not
    edit distance — fast and sufficient for a >20% threshold check.
    """
    if not a and not b:
        return 0.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    # Count positional mismatches plus length difference
    common_len = min(len(a), len(b))
    mismatches = sum(1 for i in range(common_len) if a[i] != b[i])
    mismatches += abs(len(a) - len(b))
    return mismatches / max_len


class CapabilityDriftDetector:
    """Detects drift between two live snapshots of an MCP server."""

    name: str = "capability_drift"

    def scan_delta(
        self,
        baseline: list[ToolInfo],
        current: list[ToolInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        base_map: dict[str, ToolInfo] = {t.name: t for t in baseline}
        curr_map: dict[str, ToolInfo] = {t.name: t for t in current}

        # --- New tools appeared ---
        appeared = set(curr_map) - set(base_map)
        for name in sorted(appeared):
            findings.append(
                Finding(
                    rule_id="capability_drift",
                    severity=Severity.HIGH,
                    surface=Surface.RUNTIME_DELTA,
                    title=f"New tool appeared between snapshots: {name}",
                    evidence=(
                        f"Tool '{name}' is present in the current snapshot "
                        f"but was absent from the baseline snapshot."
                    ),
                    location=name,
                    detail=(
                        "Tools appearing between snapshots may indicate "
                        "dynamic behavior based on timing or client identity."
                    ),
                )
            )

        # --- Tools disappeared ---
        disappeared = set(base_map) - set(curr_map)
        for name in sorted(disappeared):
            findings.append(
                Finding(
                    rule_id="capability_drift",
                    severity=Severity.MEDIUM,
                    surface=Surface.RUNTIME_DELTA,
                    title=f"Tool disappeared between snapshots: {name}",
                    evidence=(
                        f"Tool '{name}' was in the baseline snapshot but "
                        f"is absent from the current snapshot."
                    ),
                    location=name,
                    detail=(
                        "Disappearing tools may indicate the server adapts "
                        "its surface dynamically, possibly to evade audits."
                    ),
                )
            )

        # --- Compare common tools ---
        common = set(base_map) & set(curr_map)
        for name in sorted(common):
            base = base_map[name]
            curr = curr_map[name]

            # Quick hash check — skip if identical
            if base.content_hash() == curr.content_hash():
                continue

            # Annotation changes
            self._check_annotations(findings, name, base, curr)

            # Description drift (> 20% character difference)
            self._check_description_drift(findings, name, base, curr)

        return findings

    @staticmethod
    def _check_annotations(
        findings: list[Finding],
        tool_name: str,
        base: ToolInfo,
        curr: ToolInfo,
    ) -> None:
        """Flag dangerous annotation transitions."""
        base_ann = base.annotations
        curr_ann = curr.annotations

        if base_ann == curr_ann:
            return

        # Specific high-risk transition: readOnly -> destructive
        was_readonly = base_ann.get("readOnlyHint", False)
        now_destructive = curr_ann.get("destructiveHint", False)
        if was_readonly and now_destructive:
            findings.append(
                Finding(
                    rule_id="capability_drift",
                    severity=Severity.CRITICAL,
                    surface=Surface.RUNTIME_DELTA,
                    title=(f"Read-only tool became destructive: {tool_name}"),
                    evidence=(
                        f"Baseline: readOnlyHint=true, "
                        f"Current: destructiveHint=true"
                    ),
                    location=tool_name,
                    detail=(
                        "A tool that was marked read-only is now marked "
                        "destructive. This is a strong indicator of "
                        "capability escalation — the server may have "
                        "changed behavior after gaining trust."
                    ),
                )
            )
            return  # already flagged the worst case

        # General annotation change
        changed_keys: list[str] = []
        all_keys = set(base_ann) | set(curr_ann)
        for k in sorted(all_keys):
            if base_ann.get(k) != curr_ann.get(k):
                changed_keys.append(f"{k}: {base_ann.get(k)!r} -> {curr_ann.get(k)!r}")

        if changed_keys:
            findings.append(
                Finding(
                    rule_id="capability_drift",
                    severity=Severity.HIGH,
                    surface=Surface.RUNTIME_DELTA,
                    title=(f"Annotations changed between snapshots: " f"{tool_name}"),
                    evidence="; ".join(changed_keys),
                    location=tool_name,
                    detail=(
                        "Annotation changes between snapshots alter how "
                        "the LLM perceives tool safety (read-only, "
                        "destructive, idempotent flags)."
                    ),
                )
            )

    @staticmethod
    def _check_description_drift(
        findings: list[Finding],
        tool_name: str,
        base: ToolInfo,
        curr: ToolInfo,
    ) -> None:
        """Flag significant description changes (> 20% different)."""
        if base.description == curr.description:
            return
        # Skip if baseline is empty — static extractor likely missed it
        if not base.description.strip():
            return

        ratio = _char_diff_ratio(base.description, curr.description)
        if ratio <= 0.20:
            return

        pct = int(ratio * 100)
        findings.append(
            Finding(
                rule_id="capability_drift",
                severity=Severity.HIGH,
                surface=Surface.RUNTIME_DELTA,
                title=(
                    f"Description significantly changed: "
                    f"{tool_name} ({pct}% different)"
                ),
                evidence=(
                    f"Baseline: {_truncate(base.description, 100)}\n"
                    f"Current:  {_truncate(curr.description, 100)}"
                ),
                location=tool_name,
                detail=(
                    "Large description changes between snapshots can "
                    "alter LLM behavior — the tool may have been "
                    "re-purposed or its prompt injection payload "
                    "modified."
                ),
            )
        )


def _truncate(text: str, max_len: int) -> str:
    """Truncate text for evidence display."""
    text = text.replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
