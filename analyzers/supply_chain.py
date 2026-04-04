"""Supply chain analyzer — compare npm published package vs GitHub source.

Detects tampering by hashing files in both sources and flagging
mismatches or extra files that only exist in the published package.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from mcp_shield.core.engine import npm_cmd, CODE_EXTENSIONS, IGNORE_DIRS
from mcp_shield.core.models import Finding, Severity, Surface


# Build artifact directories that are expected to differ from source
_BUILD_DIRS = {"dist", "build", "lib", "out", "cjs", "esm"}


def compare_published_vs_source(
    repo_path: Path,
    npm_package: str,
    tmp_dir: Path,
) -> tuple[dict, list[Finding]]:
    """Compare npm-published package against cloned GitHub source.

    Args:
        repo_path: Path to the cloned GitHub repository.
        npm_package: npm package specifier (e.g. ``@org/pkg``).
        tmp_dir: Temporary directory for downloading the npm tarball.

    Returns:
        A tuple of (comparison_dict, list_of_findings).
        The dict contains status, mismatches, extra_files, missing_files.
    """
    findings: list[Finding] = []
    result: dict = {
        "status": "ok",
        "mismatches": [],
        "extra_files": [],
        "missing_files": [],
    }

    npm_dir = tmp_dir / "npm_published"
    npm_dir.mkdir(parents=True, exist_ok=True)

    # Download and extract the published tarball
    try:
        subprocess.run(
            npm_cmd(["pack", npm_package, "--pack-destination", str(npm_dir)]),
            capture_output=True,
            timeout=60,
            check=True,
        )
        for tgz in npm_dir.glob("*.tgz"):
            subprocess.run(
                ["tar", "xzf", str(tgz), "-C", str(npm_dir)],
                capture_output=True,
                timeout=30,
                check=True,
            )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return {"status": "error", "reason": str(exc)}, findings

    npm_pkg = npm_dir / "package"
    if not npm_pkg.exists():
        return {"status": "error", "reason": "npm package not extracted"}, findings

    # Hash all code files in the npm package
    npm_files: dict[str, str] = {}
    for f in npm_pkg.rglob("*"):
        if f.is_file() and f.suffix in CODE_EXTENSIONS:
            rel = str(f.relative_to(npm_pkg))
            npm_files[rel] = hashlib.sha256(f.read_bytes()).hexdigest()

    # Hash all code files in the GitHub repo
    github_files: dict[str, str] = {}
    for f in repo_path.rglob("*"):
        if any(d in f.parts for d in IGNORE_DIRS):
            continue
        if f.is_file() and f.suffix in CODE_EXTENSIONS:
            rel = str(f.relative_to(repo_path))
            github_files[rel] = hashlib.sha256(f.read_bytes()).hexdigest()

    # Compare: files in npm but not in GitHub
    for rel, h in npm_files.items():
        if rel not in github_files:
            # Check if a source file with the same stem exists (e.g. dist/index.js -> src/index.ts)
            stem = Path(rel).stem
            found_source = any(Path(gh_rel).stem == stem for gh_rel in github_files)
            # Accept files inside known build artifact directories
            is_build_artifact = any(part in _BUILD_DIRS for part in Path(rel).parts)

            if not found_source and not is_build_artifact:
                result["extra_files"].append(rel)
                findings.append(
                    Finding(
                        rule_id="npm_extra_file",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title=f"npm file absent from GitHub: {rel}",
                        evidence=rel,
                        location=rel,
                        detail=(
                            "This file exists in the published npm package "
                            "but not in the GitHub repository source code."
                        ),
                    )
                )
        elif h != github_files[rel]:
            result["mismatches"].append(rel)
            findings.append(
                Finding(
                    rule_id="npm_github_mismatch",
                    severity=Severity.CRITICAL,
                    surface=Surface.SOURCE_CODE,
                    title=f"npm file differs from GitHub: {rel}",
                    evidence=f"npm={h[:12]} github={github_files[rel][:12]}",
                    location=rel,
                    detail=(
                        "The file content differs between the published "
                        "npm package and the GitHub repository."
                    ),
                )
            )

    if result["extra_files"] or result["mismatches"]:
        result["status"] = "MISMATCH"

    return result, findings
