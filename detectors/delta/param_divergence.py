"""Parameter Divergence Detector — MCP Shield v2.

Compares input_schema between static-analysis and live versions of
the same tool. Flags new required params, changed types, removed
constraints, and description changes (potential rug pull).
"""

from __future__ import annotations

from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface, ToolInfo


def _get_required(schema: dict[str, Any]) -> set[str]:
    """Extract the set of required parameter names from a JSON Schema."""
    return set(schema.get("required", []))


def _get_properties(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract property definitions from a JSON Schema."""
    return dict(schema.get("properties", {}))


def _type_of(prop: dict[str, Any]) -> str:
    """Return a stable string representation of a property type."""
    t = prop.get("type", "")
    if isinstance(t, list):
        return "|".join(sorted(t))
    return str(t)


def _constraints_of(prop: dict[str, Any]) -> dict[str, Any]:
    """Extract validation constraints (enum, pattern, min/max, etc.)."""
    keys = {
        "enum",
        "pattern",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "const",
        "format",
    }
    return {k: v for k, v in prop.items() if k in keys}


class ParamDivergenceDetector:
    """Detects parameter schema changes between static and live tool lists."""

    name: str = "param_divergence"

    def scan_delta(
        self,
        baseline: list[ToolInfo],
        current: list[ToolInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        baseline_map: dict[str, ToolInfo] = {t.name: t for t in baseline}
        current_map: dict[str, ToolInfo] = {t.name: t for t in current}

        # Only inspect tools that exist in both lists
        common = set(baseline_map) & set(current_map)
        for tool_name in sorted(common):
            base = baseline_map[tool_name]
            live = current_map[tool_name]

            # Quick check — if content hashes match, nothing changed
            if base.content_hash() == live.content_hash():
                continue

            # --- Description change (rug pull indicator) ---
            if base.description != live.description:
                findings.append(
                    Finding(
                        rule_id="param_divergence",
                        severity=Severity.HIGH,
                        surface=Surface.RUNTIME_DELTA,
                        title=(f"Description changed at runtime: {tool_name}"),
                        evidence=(
                            f"Static: {_truncate(base.description, 120)}\n"
                            f"Live:   {_truncate(live.description, 120)}"
                        ),
                        location=tool_name,
                        detail=(
                            "A description change between static source and "
                            "live server may indicate a rug pull — the tool "
                            "was advertised with one behavior but now "
                            "describes another."
                        ),
                    )
                )

            # --- Schema-level comparison ---
            base_props = _get_properties(base.input_schema)
            live_props = _get_properties(live.input_schema)
            base_req = _get_required(base.input_schema)
            live_req = _get_required(live.input_schema)

            # New required parameters
            new_required = live_req - base_req
            for param in sorted(new_required):
                findings.append(
                    Finding(
                        rule_id="param_divergence",
                        severity=Severity.MEDIUM,
                        surface=Surface.RUNTIME_DELTA,
                        title=(
                            f"New required parameter at runtime: "
                            f"{tool_name}.{param}"
                        ),
                        evidence=(
                            f"Parameter '{param}' is required in the live "
                            f"schema but was not required (or absent) in "
                            f"the static schema."
                        ),
                        location=tool_name,
                        detail=(
                            "New required parameters can force the LLM to "
                            "provide extra data it would not normally share."
                        ),
                    )
                )

            # Type changes for existing properties
            for param in sorted(set(base_props) & set(live_props)):
                base_type = _type_of(base_props[param])
                live_type = _type_of(live_props[param])
                if base_type and live_type and base_type != live_type:
                    findings.append(
                        Finding(
                            rule_id="param_divergence",
                            severity=Severity.MEDIUM,
                            surface=Surface.RUNTIME_DELTA,
                            title=(f"Type changed at runtime: " f"{tool_name}.{param}"),
                            evidence=(
                                f"Static type: {base_type} -> "
                                f"Live type: {live_type}"
                            ),
                            location=tool_name,
                            detail=(
                                "A type change can alter validation behavior "
                                "and potentially allow unexpected input."
                            ),
                        )
                    )

                # Constraint removal
                base_constraints = _constraints_of(base_props[param])
                live_constraints = _constraints_of(live_props[param])
                removed = set(base_constraints) - set(live_constraints)
                for c in sorted(removed):
                    findings.append(
                        Finding(
                            rule_id="param_divergence",
                            severity=Severity.MEDIUM,
                            surface=Surface.RUNTIME_DELTA,
                            title=(
                                f"Constraint removed at runtime: "
                                f"{tool_name}.{param}.{c}"
                            ),
                            evidence=(
                                f"Static had {c}={base_constraints[c]!r}, "
                                f"live schema has removed it."
                            ),
                            location=tool_name,
                            detail=(
                                "Removing validation constraints at runtime "
                                "can widen the attack surface by accepting "
                                "previously rejected input."
                            ),
                        )
                    )

            # New properties that didn't exist in baseline
            added_props = set(live_props) - set(base_props)
            for param in sorted(added_props):
                sev = Severity.MEDIUM if param in live_req else Severity.LOW
                findings.append(
                    Finding(
                        rule_id="param_divergence",
                        severity=sev,
                        surface=Surface.RUNTIME_DELTA,
                        title=(f"New parameter at runtime: " f"{tool_name}.{param}"),
                        evidence=(
                            f"Parameter '{param}' added in live schema "
                            f"(required={param in live_req})."
                        ),
                        location=tool_name,
                        detail=(
                            "New parameters may collect additional data "
                            "from the LLM context."
                        ),
                    )
                )

        return findings


def _truncate(text: str, max_len: int) -> str:
    """Truncate text for evidence display."""
    text = text.replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
