"""Version pinning and transitive dependency audit.

Provides utilities to resolve exact package versions (git commit, npm,
pip) and to audit the full transitive dependency tree for known
vulnerabilities and suspicious lifecycle scripts.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from mcp_shield.core.engine import npm_cmd
from mcp_shield.core.models import Finding, Severity, Surface


def resolve_pinned_version(
    repo_path: Path,
    npm_package: str | None = None,
) -> dict[str, str | None]:
    """Resolve exact versions for version pinning.

    Args:
        repo_path: Path to the cloned repository.
        npm_package: Optional npm package specifier.

    Returns:
        Dict with keys ``git_commit``, ``npm``, ``pip`` — each a version
        string or ``None``.
    """
    result: dict[str, str | None] = {
        "git_commit": None,
        "npm": None,
        "pip": None,
    }

    # Git commit hash
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            timeout=10,
            cwd=str(repo_path),
        )
        if r.returncode == 0:
            result["git_commit"] = r.stdout.decode().strip()[:12]
    except Exception:
        pass

    # npm version
    if npm_package:
        try:
            r = subprocess.run(
                npm_cmd(["view", npm_package, "version"]),
                capture_output=True,
                timeout=15,
            )
            if r.returncode == 0:
                result["npm"] = r.stdout.decode().strip()
        except Exception:
            pass

    # pip version from pyproject.toml
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if m:
                result["pip"] = m.group(1)
        except Exception:
            pass

    return result


def audit_transitive_deps(
    repo_path: Path,
    dep_type: str,
    tmp_dir: Path,
    *,
    quiet: bool = False,
) -> str | None:
    """Install deps in isolation and audit the full transitive tree.

    For npm: copies package.json into a temp dir, runs
    ``npm install --ignore-scripts``, then ``npm audit --json --all``,
    counts transitive deps, and scans for lifecycle scripts
    (postinstall, preinstall, install) in node_modules.

    For pip: runs ``pip-audit -r requirements.txt``.

    Args:
        repo_path: Path to the repository.
        dep_type: ``"npm"`` or ``"pip"``.
        tmp_dir: Temporary directory for isolated install.

    Returns:
        A human-readable summary string, or ``None`` if not applicable.
    """
    if dep_type == "npm" and (repo_path / "package.json").exists():
        return _audit_transitive_npm(repo_path, tmp_dir, quiet=quiet)

    if dep_type == "pip":
        return _audit_transitive_pip(repo_path, quiet=quiet)

    return None


def run_dep_audit(
    repo_path: Path,
    dep_type: str,
    *,
    quiet: bool = False,
) -> str | None:
    """Run a direct dependency audit (npm audit or pip-audit).

    Unlike :func:`audit_transitive_deps` this does not install deps in
    isolation — it runs the audit tool directly in the repo.

    Args:
        repo_path: Path to the repository.
        dep_type: ``"npm"`` or ``"pip"``.

    Returns:
        A human-readable summary string, or ``None`` if not applicable.
    """
    if dep_type == "npm" and (repo_path / "package.json").exists():
        if not quiet:
            print("[*] npm audit...", file=sys.stderr)
        try:
            r = subprocess.run(
                npm_cmd(["audit", "--json"]),
                capture_output=True,
                timeout=30,
                cwd=str(repo_path),
            )
            data = json.loads(r.stdout)
            vulns = data.get("vulnerabilities", {})
            if vulns:
                lines = []
                for name, info in vulns.items():
                    sev = info.get("severity", "?")
                    lines.append(f"  - {name}: {sev}")
                return "\n".join(lines)
            return "No known vulnerabilities"
        except Exception:
            return "npm audit unavailable"

    if dep_type == "pip":
        req = repo_path / "requirements.txt"
        if req.exists():
            if not quiet:
                print("[*] pip-audit...", file=sys.stderr)
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pip_audit", "-r", str(req)],
                    capture_output=True,
                    timeout=60,
                )
                return r.stdout.decode("utf-8", errors="ignore")[:2000]
            except FileNotFoundError:
                return "pip-audit not installed (pip install pip-audit)"

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _audit_transitive_npm(
    repo_path: Path, tmp_dir: Path, *, quiet: bool = False
) -> str:
    """Isolated npm transitive audit."""
    if not quiet:
        print(
            "[*] Transitive dep audit (npm install --ignore-scripts + npm audit)...",
            file=sys.stderr,
        )
    audit_dir = tmp_dir / "transitive_audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    # Copy manifest files
    shutil.copy2(repo_path / "package.json", audit_dir / "package.json")
    lock = repo_path / "package-lock.json"
    if lock.exists():
        shutil.copy2(lock, audit_dir / "package-lock.json")

    try:
        # Install without executing lifecycle scripts
        subprocess.run(
            npm_cmd(["install", "--ignore-scripts", "--no-optional"]),
            capture_output=True,
            timeout=120,
            cwd=str(audit_dir),
        )

        # Full transitive audit
        r = subprocess.run(
            npm_cmd(["audit", "--json", "--all"]),
            capture_output=True,
            timeout=30,
            cwd=str(audit_dir),
        )
        data = json.loads(r.stdout) if r.stdout else {}
        vulns = data.get("vulnerabilities", {})
        total = len(vulns)
        critical = sum(1 for v in vulns.values() if v.get("severity") == "critical")
        high = sum(1 for v in vulns.values() if v.get("severity") == "high")

        summary = f"Total: {total} vulns ({critical} critical, {high} high)\n"
        for name, info in list(vulns.items())[:15]:
            sev = info.get("severity", "?")
            via_raw = info.get("via", [])
            via_strs: list[str] = []
            if isinstance(via_raw, list):
                via_strs = [
                    v if isinstance(v, str) else v.get("name", str(v))
                    for v in via_raw[:3]
                ]
            via = ", ".join(via_strs)
            summary += f"  - {name} ({sev}){' via ' + via if via else ''}\n"
        if total > 15:
            summary += f"  ... and {total - 15} more\n"

        # Scan for lifecycle scripts in transitive dependencies
        node_modules = audit_dir / "node_modules"
        if node_modules.exists():
            postinstall_found = _find_lifecycle_scripts(node_modules)
            if postinstall_found:
                summary += f"\nLifecycle scripts in transitive deps ({len(postinstall_found)}):\n"
                for ps in postinstall_found[:10]:
                    summary += f"  ! {ps}\n"
                if len(postinstall_found) > 10:
                    summary += f"  ... and {len(postinstall_found) - 10} more\n"

        # Count total transitive dependencies
        try:
            ls_r = subprocess.run(
                npm_cmd(["ls", "--all", "--json"]),
                capture_output=True,
                timeout=30,
                cwd=str(audit_dir),
            )
            ls_out = ls_r.stdout.decode("utf-8", errors="ignore") if ls_r.stdout else ""
            dep_count = ls_out.count('"version"')
            summary = f"Transitive deps: ~{dep_count}\n" + summary
        except Exception:
            pass

        return summary

    except Exception as exc:
        return f"Transitive audit error: {exc}"


def _audit_transitive_pip(repo_path: Path, *, quiet: bool = False) -> str | None:
    """pip-audit on requirements.txt."""
    if not quiet:
        print("[*] Transitive dep audit (pip)...", file=sys.stderr)
    req = repo_path / "requirements.txt"
    if not req.exists():
        return None
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", str(req)],
            capture_output=True,
            timeout=120,
        )
        return r.stdout.decode("utf-8", errors="ignore")[:2000]
    except Exception:
        return "pip-audit unavailable"


def _find_lifecycle_scripts(node_modules: Path) -> list[str]:
    """Scan node_modules for packages with install lifecycle scripts."""
    found: list[str] = []
    hooks = ("postinstall", "preinstall", "install")
    for pkg_json in node_modules.rglob("package.json"):
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            scripts = pkg.get("scripts", {})
            for hook in hooks:
                if hook in scripts:
                    pkg_name = pkg.get("name", pkg_json.parent.name)
                    found.append(f"{pkg_name}: {hook}={scripts[hook][:80]}")
        except Exception:
            pass
    return found
