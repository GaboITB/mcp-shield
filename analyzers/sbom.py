"""SBOM generator — simplified CycloneDX format.

Produces a Software Bill of Materials listing all direct dependencies
with Package URL (purl) identifiers for npm, pip, and Go packages.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path


_DEFAULT_AUDIT_DIR = str(Path.home() / ".config" / "mcp-shield" / "audits")
AUDIT_DIR = Path(os.environ.get("MCP_AUDIT_DIR", _DEFAULT_AUDIT_DIR))


def generate_sbom(deps: dict, name: str) -> dict:
    """Generate a CycloneDX-simplified SBOM from a dependency dict.

    Args:
        deps: Dictionary with ``type`` (npm/pip/go) and ``deps`` mapping
              package names to version specifiers.
        name: Name of the audited component.

    Returns:
        The SBOM dict (also saved to the audit directory as JSON).
    """
    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": name,
                "version": "audited",
            },
            "timestamp": datetime.now().isoformat(),
            "tools": [{"name": "mcp-shield", "version": "2.0.0"}],
        },
        "components": [],
    }

    dep_type = deps.get("type", "unknown")
    for dep_name, version in deps.get("deps", {}).items():
        clean_version = str(version).lstrip("^~>=<! ") or "unknown"
        component: dict = {
            "type": "library",
            "name": dep_name,
            "version": clean_version,
            "purl": "",
        }
        if dep_type == "npm":
            component["purl"] = f"pkg:npm/{dep_name}@{clean_version}"
        elif dep_type == "pip":
            component["purl"] = f"pkg:pypi/{dep_name}@{clean_version}"
        elif dep_type == "go":
            component["purl"] = f"pkg:golang/{dep_name}@{clean_version}"
        sbom["components"].append(component)

    # Persist to audit directory
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    sbom_file = AUDIT_DIR / f"sbom_{name}_{ts}.json"
    sbom_file.write_text(
        json.dumps(sbom, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"    SBOM: {sbom_file} ({len(sbom['components'])} components)")

    return sbom
