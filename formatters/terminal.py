"""Terminal formatters for MCP Shield v2.

Produces colored/boxed output for CLI display and Markdown reports.
"""

from __future__ import annotations

from mcp_shield.core.models import AuditResult, Finding, Severity, Surface


# ANSI color codes
_COLORS = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.HIGH: "\033[93m",  # yellow
    Severity.MEDIUM: "\033[33m",  # orange-ish
    Severity.LOW: "\033[36m",  # cyan
    Severity.INFO: "\033[37m",  # white
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _severity_icon(sev: Severity) -> str:
    icons = {
        Severity.CRITICAL: "[!!]",
        Severity.HIGH: "[!]",
        Severity.MEDIUM: "[~]",
        Severity.LOW: "[.]",
        Severity.INFO: "[i]",
    }
    return icons.get(sev, "[?]")


def _pad(text: str, width: int) -> str:
    """Pad text to width, truncating if necessary."""
    if len(text) > width:
        return text[: width - 1] + "\u2026"
    return text.ljust(width)


def format_summary(result: AuditResult) -> str:
    """5-line executive summary box."""
    by_sev = result.findings_by_severity()
    counts = {
        "critical": len(by_sev.get(Severity.CRITICAL, [])),
        "high": len(by_sev.get(Severity.HIGH, [])),
        "medium": len(by_sev.get(Severity.MEDIUM, [])),
        "low": len(by_sev.get(Severity.LOW, [])),
    }

    n_tools = len(result.tools_live or result.tools_static)
    n_deps = len(result.deps) if result.deps else 0
    n_urls = len(result.urls) if result.urls else 0
    n_static = len(result.tools_static)
    n_live = len(result.tools_live)

    # Top finding
    top_finding = ""
    if result.findings:
        sorted_findings = sorted(result.findings, key=lambda f: f.severity)
        top_finding = sorted_findings[0].title

    # Box width
    w = 50

    line1 = f"{result.name:<16} {n_tools} tools   Grade: {result.grade.value}  Score: {result.total_score}"
    line2 = (
        f"Critical: {counts['critical']} | High: {counts['high']} "
        f"| Medium: {counts['medium']} | Low: {counts['low']}"
    )
    line3 = (
        f"Deps: {n_deps} | URLs: {n_urls} | Static tools: {n_static} | Live: {n_live}"
    )
    line4 = f"-> {top_finding}" if top_finding else "-> No findings"

    # AIVSS line if available
    line5 = ""
    if result.aivss and hasattr(result.aivss, "score"):
        line5 = f"AIVSS: {result.aivss.score}/10 ({result.aivss.severity})"

    inner_w = max(len(line1), len(line2), len(line3), len(line4), len(line5), w)

    top = f"+== MCP Shield {'=' * (inner_w - 11)}+"
    bot = f"+{'=' * (inner_w + 2)}+"

    def row(text: str) -> str:
        return f"| {_pad(text, inner_w)} |"

    lines = [
        top,
        row(line1),
        row(line2),
        row(line3),
        row(line4),
    ]
    if line5:
        lines.append(row(line5))
    lines.append(bot)
    return "\n".join(lines)


def format_findings(result: AuditResult) -> str:
    """Detailed findings grouped by severity."""
    if not result.findings:
        return "No findings."

    sections: list[str] = []
    by_sev = result.findings_by_severity()

    for sev in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        findings = by_sev.get(sev, [])
        if not findings:
            continue

        color = _COLORS.get(sev, "")
        header = f"{color}{_BOLD}{sev.value.upper()} ({len(findings)}){_RESET}"
        sections.append(header)
        sections.append("-" * 60)

        for f in findings:
            icon = _severity_icon(f.severity)
            sections.append(f"  {color}{icon}{_RESET} {f.title}")
            sections.append(f"      Rule: {f.rule_id}  |  Location: {f.location}")
            sections.append(f"      Evidence: {f.evidence[:120]}")
            if f.detail:
                sections.append(f"      Detail: {f.detail[:200]}")
            sections.append("")

    return "\n".join(sections)


def format_full_report(result: AuditResult) -> str:
    """Complete Markdown report from AuditResult."""
    lines: list[str] = []

    # Header
    lines.append(f"# MCP Shield Audit Report: {result.name}")
    lines.append("")
    lines.append(f"- **Source:** `{result.source}`")
    lines.append(f"- **Timestamp:** {result.timestamp}")
    lines.append(f"- **Grade:** {result.grade.value} (score: {result.total_score})")
    lines.append("")

    # Summary counts
    by_sev = result.findings_by_severity()
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        count = len(by_sev.get(sev, []))
        if count > 0:
            lines.append(f"| {sev.value.capitalize()} | {count} |")
    lines.append("")

    # Tools
    all_tools = result.tools_live or result.tools_static
    if all_tools:
        lines.append("## Tools")
        lines.append("")
        lines.append("| Name | Source | Destructive | Description |")
        lines.append("|------|--------|-------------|-------------|")
        for t in all_tools:
            dest = "Yes" if t.is_destructive else "No"
            desc = t.description[:80].replace("|", "\\|") if t.description else "-"
            lines.append(f"| `{t.name}` | {t.source} | {dest} | {desc} |")
        lines.append("")

    # Findings detail
    if result.findings:
        lines.append("## Findings")
        lines.append("")
        for sev in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            findings = by_sev.get(sev, [])
            if not findings:
                continue
            lines.append(f"### {sev.value.capitalize()}")
            lines.append("")
            for f in findings:
                lines.append(f"- **{f.title}** (`{f.rule_id}`)")
                lines.append(f"  - Location: `{f.location}`")
                lines.append(f"  - Evidence: `{f.evidence[:150]}`")
                if f.detail:
                    lines.append(f"  - Detail: {f.detail}")
            lines.append("")

    # Health
    if result.health:
        lines.append("## Repository Health")
        lines.append("")
        for key, val in result.health.items():
            label = key.replace("_", " ").capitalize()
            if isinstance(val, bool):
                lines.append(f"- {label}: {'Yes' if val else 'No'}")
            else:
                lines.append(f"- {label}: {val}")
        lines.append("")

    # --- Section: Dependencies ---
    if result.deps:
        lines.append("## Dependencies")
        lines.append("")
        dep_type = result.deps.get("type", "unknown")
        total = result.deps.get("total_count", 0)
        native = result.deps.get("native_in_deps", [])
        phonehome = result.deps.get("phonehome", [])
        phantom = result.deps.get("phantom", [])
        postinstall = result.deps.get("postinstall")
        unpinned = result.deps.get("unpinned", [])
        lines.append(f"- **Type:** {dep_type}")
        lines.append(f"- **Total count:** {total}")
        if native:
            lines.append(f"- **Native modules in deps:** {', '.join(native)}")
        if phonehome:
            lines.append(f"- **Phone-home deps:** {', '.join(phonehome)}")
        if phantom:
            lines.append(f"- **Phantom deps:** {', '.join(phantom)}")
        if postinstall:
            lines.append(f"- **Postinstall scripts:** `{postinstall}`")
        if unpinned:
            lines.append(f"- **Unpinned count:** {len(unpinned)}")
        lines.append("")

    # --- Section: URLs ---
    if result.urls:
        lines.append("## URLs")
        lines.append("")
        # Group by classification
        groups: dict[str, list[str]] = {}
        for entry in result.urls:
            cls = entry.get("classification", "unknown")
            url = entry.get("url", str(entry))
            groups.setdefault(cls, []).append(url)
        for cls in ["suspicious", "unknown", "safe", "local"]:
            urls_in_group = groups.get(cls, [])
            if not urls_in_group:
                continue
            lines.append(f"### {cls.capitalize()} ({len(urls_in_group)})")
            lines.append("")
            for url in urls_in_group[:10]:
                lines.append(f"- `{url}`")
            if len(urls_in_group) > 10:
                lines.append(f"- ... and {len(urls_in_group) - 10} more")
            lines.append("")

    # --- Section: npm vs GitHub comparison ---
    if result.npm_github_diff and result.npm_github_diff.get("status"):
        lines.append("## npm vs GitHub Comparison")
        lines.append("")
        diff = result.npm_github_diff
        lines.append(f"- **Status:** {diff.get('status', 'unknown')}")
        mismatches = diff.get("mismatches", [])
        extra = diff.get("extra_files", [])
        if mismatches:
            lines.append(f"- **Mismatches ({len(mismatches)}):**")
            for m in mismatches[:10]:
                lines.append(f"  - `{m}`")
        if extra:
            lines.append(f"- **Extra files in npm ({len(extra)}):**")
            for e in extra[:10]:
                lines.append(f"  - `{e}`")
        lines.append("")

    # --- Section: Vulnerability audit (direct) ---
    if result.dep_audit:
        lines.append("## Vulnerability Audit (direct)")
        lines.append("")
        lines.append("```")
        lines.append(result.dep_audit.strip())
        lines.append("```")
        lines.append("")

    # --- Section: Transitive dependency audit ---
    if result.transitive_audit:
        lines.append("## Transitive Dependency Audit")
        lines.append("")
        lines.append("```")
        lines.append(result.transitive_audit.strip())
        lines.append("```")
        lines.append("")

    # --- Section: Version pinning ---
    if result.pinned_version and any(result.pinned_version.values()):
        lines.append("## Version Pinning")
        lines.append("")
        pv = result.pinned_version
        if pv.get("npm"):
            lines.append(f"- **npm version:** `{pv['npm']}`")
        if pv.get("pip"):
            lines.append(f"- **pip version:** `{pv['pip']}`")
        if pv.get("git_commit"):
            lines.append(f"- **Git commit to lock:** `{pv['git_commit']}`")
        lines.append("")

    # --- Section: AIVSS score detailed ---
    if result.aivss and hasattr(result.aivss, "score"):
        aivss = result.aivss
        lines.append("## AIVSS Score")
        lines.append("")
        lines.append(f"- **Score:** {aivss.score}/10")
        lines.append(f"- **Severity:** {aivss.severity}")
        lines.append(f"- **Exploitation:** {aivss.exploitation}/10")
        lines.append(f"- **Impact:** {aivss.impact}/10")
        lines.append(f"- **Trust:** {aivss.trust}/10")
        lines.append("")

    # --- Section: Score breakdown table ---
    if result.findings:
        lines.append("## Score Breakdown")
        lines.append("")
        lines.append("| Rule ID | Points |")
        lines.append("|---------|--------|")
        # Aggregate points per rule_id
        rule_points: dict[str, int] = {}
        for f in result.findings:
            rule_points[f.rule_id] = rule_points.get(f.rule_id, 0) + f.weight
        for rule_id, pts in sorted(rule_points.items(), key=lambda x: -x[1]):
            if pts > 0:
                lines.append(f"| `{rule_id}` | {pts} |")
        lines.append(f"| **TOTAL** | **{result.total_score}** |")
        lines.append("")

    # --- Section: v1.1 checks ---
    has_v11 = result.deprecated_msg or result.sdk_info or result.rate_limited_tools
    if has_v11:
        lines.append("## v1.1 Checks")
        lines.append("")
        if result.deprecated_msg:
            lines.append(f"- **Deprecated:** {result.deprecated_msg}")
        if result.sdk_info:
            sdk = result.sdk_info
            sdk_name = sdk.get("name", "unknown")
            sdk_ver = sdk.get("version", "unknown")
            lines.append(f"- **SDK:** {sdk_name} v{sdk_ver}")
        if result.rate_limited_tools:
            lines.append(
                f"- **Rate-limited tools ({len(result.rate_limited_tools)}):** "
                + ", ".join(f"`{t}`" for t in result.rate_limited_tools)
            )
        lines.append("")

    # --- Section: Actions required ---
    lines.append("## Actions Required")
    lines.append("")
    grade = result.grade.value
    if grade in ("A+", "A"):
        lines.append(
            "> **SAFE** — No critical issues found. "
            "This MCP server can be used with standard precautions."
        )
    elif grade == "B":
        lines.append(
            "> **CAUTION** — Minor issues detected. "
            "Review the findings above and consider applying deny rules "
            "for destructive tools."
        )
    elif grade == "C":
        lines.append(
            "> **WARNING** — Significant issues detected. "
            "Apply deny rules, restrict tool access, and audit the "
            "source code before use in production."
        )
    else:
        lines.append(
            "> **DANGER** — Critical security issues detected. "
            "Do NOT use this MCP server without thorough manual review. "
            "Apply all deny rules and consider alternative servers."
        )
    lines.append("")

    # Deny rules
    deny = result.deny_rules()
    if deny:
        lines.append("## Recommended Deny Rules")
        lines.append("")
        lines.append("```json")
        lines.append("[")
        for i, rule in enumerate(deny):
            comma = "," if i < len(deny) - 1 else ""
            lines.append(f'  "{rule}"{comma}')
        lines.append("]")
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by MCP Shield v2*")

    return "\n".join(lines)
