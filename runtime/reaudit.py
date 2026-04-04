"""Re-audit installed MCP servers for post-install compromise detection.

Checks installed MCPs against their last audit to detect:
- Stale audits (age > 14/30 days)
- Version drift (new npm version since last audit)
- MCPs with no audit at all

Ported from mcp_reaudit.py (v1) with fixes:
- Configurable .claude.json path (no longer hardcoded)
- Uses shared npm_cmd() from engine module
- Generates v2 Finding objects
- All text in English
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_shield.core.engine import npm_cmd
from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_CLAUDE_JSON = Path.home() / ".claude.json"
DEFAULT_AUDIT_DIR = Path.home() / ".config" / "mcp-shield" / "audits"

# Thresholds (days)
AUDIT_STALE_DAYS = 30
AUDIT_OLD_DAYS = 14


# ---------------------------------------------------------------------------
# MCP discovery
# ---------------------------------------------------------------------------


def get_installed_mcps(
    claude_json_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Read installed MCP servers from ``.claude.json``.

    Parameters
    ----------
    claude_json_path:
        Path to the Claude configuration file.
        Defaults to ``~/.claude.json``.

    Returns
    -------
    dict[str, dict]
        Mapping of MCP name -> config dict with keys:
        scope, command, args.
    """
    path = claude_json_path or DEFAULT_CLAUDE_JSON
    mcps: dict[str, dict[str, Any]] = {}

    if not path.exists():
        return mcps

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return mcps

    # Global MCP servers
    for name, config in data.get("mcpServers", {}).items():
        mcps[name] = {
            "scope": "global",
            "command": config.get("command", ""),
            "args": config.get("args", []),
        }

    # Project-scoped MCP servers
    for project_path, project_data in data.get("projects", {}).items():
        for name, config in project_data.get("mcpServers", {}).items():
            mcps[name] = {
                "scope": f"project:{project_path}",
                "command": config.get("command", ""),
                "args": config.get("args", []),
            }

    return mcps


# ---------------------------------------------------------------------------
# npm version check
# ---------------------------------------------------------------------------


def _check_npm_version(package_name: str) -> dict[str, str]:
    """Query npm registry for the latest version of *package_name*."""
    try:
        r = subprocess.run(
            npm_cmd(["view", package_name, "version", "--json"]),
            capture_output=True,
            timeout=15,
        )
        if r.returncode == 0:
            output = r.stdout.decode().strip()
            version = json.loads(output) if output else "?"
            return {"latest": str(version), "status": "ok"}
    except Exception as exc:
        return {"latest": "?", "status": f"error: {exc}"}
    return {"latest": "?", "status": "not found"}


# ---------------------------------------------------------------------------
# Audit file helpers
# ---------------------------------------------------------------------------


def _find_last_audit(
    mcp_name: str,
    audit_dir: Path | None = None,
) -> Path | None:
    """Find the most recent audit JSON for *mcp_name*."""
    directory = audit_dir or DEFAULT_AUDIT_DIR
    if not directory.exists():
        return None
    audits = sorted(
        directory.glob(f"audit_{mcp_name}_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return audits[0] if audits else None


def _load_audit_data(audit_file: Path) -> dict[str, Any]:
    try:
        return json.loads(audit_file.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _extract_npm_package(args: list[Any]) -> str | None:
    """Extract the npm package name from MCP command args."""
    skip = {"/c", "npx", "-y", "cmd", "node", "python", "python3"}
    for arg in args:
        arg = str(arg)
        if arg.startswith("@") or (
            not arg.startswith("-") and "/" not in arg and "." not in arg
        ):
            if arg not in skip:
                return arg
    return None


# ---------------------------------------------------------------------------
# Single MCP re-audit
# ---------------------------------------------------------------------------


def reaudit_mcp(
    name: str,
    config: dict[str, Any],
    audit_dir: Path | None = None,
) -> dict[str, Any]:
    """Check a single installed MCP for staleness / version drift.

    Returns a result dict with keys:
        name, scope, status, alerts, last_audit, version_check.
    """
    result: dict[str, Any] = {
        "name": name,
        "scope": config.get("scope", "unknown"),
        "status": "ok",
        "alerts": [],
        "last_audit": None,
        "version_check": None,
    }

    # --- Last audit check ---
    last = _find_last_audit(name, audit_dir)
    if last:
        audit_data = _load_audit_data(last)
        mtime = datetime.fromtimestamp(last.stat().st_mtime)
        age_days = (datetime.now() - mtime).days

        result["last_audit"] = {
            "file": str(last),
            "date": mtime.strftime("%Y-%m-%d"),
            "verdict": audit_data.get("verdict", "?"),
            "score": audit_data.get("score", "?"),
        }

        if age_days > AUDIT_STALE_DAYS:
            result["alerts"].append(f"Stale audit ({age_days} days old)")
        elif age_days > AUDIT_OLD_DAYS:
            result["alerts"].append(f"Aging audit ({age_days} days old)")
    else:
        result["alerts"].append("NO AUDIT — MCP installed without security audit!")
        result["status"] = "warning"

    # --- npm version check ---
    npm_pkg = _extract_npm_package(config.get("args", []))
    if npm_pkg:
        version_info = _check_npm_version(npm_pkg)
        result["version_check"] = version_info

        if last:
            audit_data = _load_audit_data(last)
            pinned = audit_data.get("pinned_version", {})
            audited_version = pinned.get("npm", "")
            latest = version_info.get("latest", "")
            if audited_version and latest and latest != audited_version:
                result["alerts"].append(
                    f"Version drift: latest {latest} (audited: {audited_version})"
                )

    if result["alerts"] and result["status"] == "ok":
        result["status"] = "warning"

    return result


# ---------------------------------------------------------------------------
# Batch re-audit
# ---------------------------------------------------------------------------


def reaudit_all(
    claude_json_path: Path | None = None,
    audit_dir: Path | None = None,
    name_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Re-audit all (or filtered) installed MCPs.

    Parameters
    ----------
    claude_json_path:
        Path to .claude.json. Defaults to the standard location.
    audit_dir:
        Where audit JSON files are stored.
    name_filter:
        If set, only MCPs whose name contains this substring (case-insensitive).

    Returns
    -------
    list[dict]
        One result dict per audited MCP.
    """
    mcps = get_installed_mcps(claude_json_path)
    results: list[dict[str, Any]] = []

    for mcp_name, config in mcps.items():
        if name_filter and name_filter.lower() not in mcp_name.lower():
            continue
        results.append(reaudit_mcp(mcp_name, config, audit_dir))

    return results


# ---------------------------------------------------------------------------
# Finding conversion
# ---------------------------------------------------------------------------


def results_to_findings(results: list[dict[str, Any]]) -> list[Finding]:
    """Convert re-audit results to v2 Finding objects."""
    findings: list[Finding] = []
    for res in results:
        for alert in res.get("alerts", []):
            if "NO AUDIT" in alert:
                sev = Severity.HIGH
                rule = "reaudit_no_audit"
            elif "Stale" in alert:
                sev = Severity.MEDIUM
                rule = "reaudit_stale"
            elif "Version drift" in alert:
                sev = Severity.MEDIUM
                rule = "reaudit_version_drift"
            else:
                sev = Severity.LOW
                rule = "reaudit_aging"

            findings.append(
                Finding(
                    rule_id=rule,
                    severity=sev,
                    surface=Surface.RUNTIME_DELTA,
                    title=alert,
                    evidence=res["name"],
                    location=res.get("scope", "unknown"),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def generate_reaudit_report(results: list[dict[str, Any]]) -> str:
    """Generate a markdown re-audit report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    alerts_total = sum(len(r.get("alerts", [])) for r in results)

    lines = [
        f"# MCP Re-Audit Report — {now}",
        f"**MCPs checked**: {len(results)}",
        f"**Alerts**: {alerts_total}",
        "",
    ]

    # Show MCPs with alerts first
    sorted_results = sorted(results, key=lambda x: -len(x.get("alerts", [])))

    for res in sorted_results:
        status_tag = "ALERT" if res.get("alerts") else "OK"
        lines.append(f"### {res['name']} [{status_tag}]")
        lines.append(f"- Scope: {res.get('scope', 'unknown')}")

        if res.get("last_audit"):
            la = res["last_audit"]
            lines.append(
                f"- Last audit: {la['date']} — {la['verdict']} (score: {la['score']})"
            )
        else:
            lines.append("- Last audit: **NONE**")

        if res.get("version_check"):
            lines.append(f"- Latest version: {res['version_check'].get('latest', '?')}")

        for alert in res.get("alerts", []):
            lines.append(f"- **{alert}**")

        lines.append("")

    lines.append("---")
    lines.append("*Generated by MCP Shield v2 — GaboLabs*")
    return "\n".join(lines)
