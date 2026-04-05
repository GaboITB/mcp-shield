"""HTML report formatter for MCP Shield v3.

Generates a standalone, self-contained HTML report:
- Inline CSS (no external stylesheets)
- Zero external JavaScript
- Single file output
- Responsive design
- Severity-colored finding cards
- Score gauge with grade
- Collapsible sections via CSS-only <details>
"""

from __future__ import annotations

from datetime import datetime
from html import escape

from mcp_shield.core.models import AuditResult, Finding, Grade, Severity, Surface

# ---------------------------------------------------------------------------
# Color mappings
# ---------------------------------------------------------------------------

_SEV_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}

_SEV_BG: dict[Severity, str] = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH: "#fff7ed",
    Severity.MEDIUM: "#fefce8",
    Severity.LOW: "#eff6ff",
    Severity.INFO: "#f9fafb",
}

_GRADE_COLORS: dict[Grade, str] = {
    Grade.A_PLUS: "#16a34a",
    Grade.A: "#22c55e",
    Grade.B: "#ca8a04",
    Grade.C: "#ea580c",
    Grade.D: "#ef4444",
    Grade.F: "#dc2626",
}

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #0f172a;
  --surface: #1e293b;
  --surface2: #334155;
  --text: #e2e8f0;
  --text-dim: #94a3b8;
  --border: #475569;
  --accent: #3b82f6;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  padding: 2rem;
  max-width: 960px;
  margin: 0 auto;
}
h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.3rem; margin: 1.5rem 0 0.75rem; color: var(--accent); }
h3 { font-size: 1rem; margin: 0.5rem 0; }
.header {
  text-align: center;
  padding: 2rem 0;
  border-bottom: 1px solid var(--border);
  margin-bottom: 2rem;
}
.header .subtitle { color: var(--text-dim); font-size: 0.9rem; }
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.meta-card {
  background: var(--surface);
  border-radius: 8px;
  padding: 1rem;
  border: 1px solid var(--border);
}
.meta-card .label { color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.meta-card .value { font-size: 1.5rem; font-weight: 700; margin-top: 0.25rem; }
.grade-badge {
  display: inline-block;
  font-size: 2.5rem;
  font-weight: 900;
  padding: 0.5rem 1.5rem;
  border-radius: 12px;
  border: 3px solid;
}
.findings-section { margin-bottom: 1.5rem; }
.finding-card {
  background: var(--surface);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 0.75rem;
  border-left: 4px solid;
}
.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}
.finding-title { font-weight: 600; font-size: 0.95rem; }
.sev-badge {
  font-size: 0.7rem;
  font-weight: 700;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.finding-evidence {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.8rem;
  color: var(--text-dim);
  background: var(--bg);
  padding: 0.5rem;
  border-radius: 4px;
  margin-top: 0.5rem;
  word-break: break-all;
}
.finding-location { font-size: 0.75rem; color: var(--text-dim); }
.finding-detail { font-size: 0.8rem; color: var(--text-dim); margin-top: 0.25rem; }
details { margin-bottom: 0.5rem; }
details summary {
  cursor: pointer;
  font-weight: 600;
  padding: 0.5rem;
  background: var(--surface);
  border-radius: 6px;
  border: 1px solid var(--border);
}
details summary:hover { background: var(--surface2); }
details[open] summary { border-radius: 6px 6px 0 0; }
.tools-table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
.tools-table th, .tools-table td {
  text-align: left;
  padding: 0.5rem;
  border-bottom: 1px solid var(--border);
  font-size: 0.85rem;
}
.tools-table th { color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; }
.footer {
  text-align: center;
  color: var(--text-dim);
  font-size: 0.75rem;
  margin-top: 3rem;
  padding-top: 1.5rem;
  border-top: 1px solid var(--border);
}
.bar-chart { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 0.5rem 0; }
.bar-segment { height: 100%; }
@media (max-width: 600px) {
  body { padding: 1rem; }
  .meta-grid { grid-template-columns: 1fr 1fr; }
}
"""


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------


def format_html_report(result: AuditResult) -> str:
    """Generate a complete standalone HTML report from an AuditResult."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    grade = result.grade
    grade_color = _GRADE_COLORS.get(grade, "#6b7280")

    # Count by severity
    counts: dict[Severity, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = len(result.findings)
    critical = counts.get(Severity.CRITICAL, 0)
    high = counts.get(Severity.HIGH, 0)
    medium = counts.get(Severity.MEDIUM, 0)
    low = counts.get(Severity.LOW, 0)
    info = counts.get(Severity.INFO, 0)

    # Build severity bar
    bar_html = ""
    if total > 0:
        bar_html = '<div class="bar-chart">'
        for sev, count in sorted(counts.items(), key=lambda x: x[0].value):
            if count > 0:
                pct = count / total * 100
                color = _SEV_COLORS[sev]
                bar_html += f'<div class="bar-segment" style="width:{pct:.1f}%;background:{color}" title="{sev.value}: {count}"></div>'
        bar_html += "</div>"

    # Build findings HTML
    findings_html = _render_findings(result.findings)

    # Build tools HTML
    tools_html = _render_tools(result)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Shield Report — {escape(result.name)}</title>
<style>{_CSS}</style>
</head>
<body>

<div class="header">
  <h1>MCP Shield — Security Audit Report</h1>
  <p class="subtitle">{escape(result.name)} | {escape(now)}</p>
</div>

<div class="meta-grid">
  <div class="meta-card" style="text-align:center">
    <div class="label">Grade</div>
    <div class="grade-badge" style="color:{grade_color};border-color:{grade_color}">{grade.value}</div>
  </div>
  <div class="meta-card">
    <div class="label">Score</div>
    <div class="value">{result.total_score}</div>
  </div>
  <div class="meta-card">
    <div class="label">Findings</div>
    <div class="value">{total}</div>
  </div>
  <div class="meta-card">
    <div class="label">Critical / High</div>
    <div class="value" style="color:{_SEV_COLORS[Severity.CRITICAL]}">{critical}</div>
    <div class="value" style="color:{_SEV_COLORS[Severity.HIGH]};font-size:1.2rem">/ {high}</div>
  </div>
</div>

{bar_html}

<h2>Findings ({total})</h2>
{findings_html}

{tools_html}

<div class="footer">
  Generated by MCP Shield v3 — <a href="https://github.com/GaboITB/mcp-shield" style="color:var(--accent)">github.com/GaboITB/mcp-shield</a><br>
  {escape(now)} | {total} findings | Grade {grade.value} | Score {result.total_score}
</div>

</body>
</html>"""

    return html


def _render_findings(findings: list[Finding]) -> str:
    """Render findings grouped by severity."""
    if not findings:
        return '<p style="color:var(--text-dim)">No findings detected. This MCP server looks clean.</p>'

    # Group by severity
    by_sev: dict[Severity, list[Finding]] = {}
    for f in sorted(findings, key=lambda x: x.severity):
        by_sev.setdefault(f.severity, []).append(f)

    html_parts: list[str] = []

    for sev in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        group = by_sev.get(sev, [])
        if not group:
            continue

        color = _SEV_COLORS[sev]
        bg = _SEV_BG[sev]

        html_parts.append(
            f'<details open class="findings-section">'
            f'<summary style="color:{color}">{sev.value.upper()} ({len(group)})</summary>'
        )

        for f in group:
            detail_html = ""
            if f.detail:
                detail_html = f'<div class="finding-detail">{escape(f.detail)}</div>'

            html_parts.append(
                f"""
<div class="finding-card" style="border-left-color:{color}">
  <div class="finding-header">
    <span class="finding-title">{escape(f.title)}</span>
    <span class="sev-badge" style="background:{color};color:white">{sev.value}</span>
  </div>
  <span class="finding-location">{escape(f.rule_id)} | {escape(f.location)}</span>
  {detail_html}
  <div class="finding-evidence">{escape(f.evidence[:300])}</div>
</div>"""
            )

        html_parts.append("</details>")

    return "\n".join(html_parts)


def _render_tools(result: AuditResult) -> str:
    """Render tools section if tools were discovered."""
    tools = result.tools_live or result.tools_static
    if not tools:
        return ""

    rows = []
    for t in tools:
        destructive = "Yes" if t.is_destructive else ""
        rows.append(
            f"<tr><td>{escape(t.name)}</td>"
            f"<td>{escape(t.description[:100])}</td>"
            f'<td style="color:#dc2626">{destructive}</td></tr>'
        )

    return f"""
<h2>Tools ({len(tools)})</h2>
<details>
<summary>View discovered tools</summary>
<table class="tools-table">
<thead><tr><th>Name</th><th>Description</th><th>Destructive</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</details>"""
