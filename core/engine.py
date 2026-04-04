"""Audit engine — orchestrates the three detection pipelines.

The engine coordinates: source acquisition, file scanning,
metadata scanning, live fetching, and delta comparison.
It produces a single AuditResult with all findings aggregated.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from mcp_shield.core.models import AuditResult, Finding, ToolInfo
from mcp_shield.core.registry import DetectorRegistry


# File extensions to scan
CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".mjs",
    ".cjs",
    ".jsx",
    ".tsx",
    ".go",
    ".rs",
    ".rb",
    ".sh",
    ".bash",
}

# Directories to skip
IGNORE_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "vendor",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
    ".turbo",
    ".cache",
    ".parcel-cache",
}

IGNORE_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "Pipfile.lock",
    "poetry.lock",
}

IS_WINDOWS = sys.platform == "win32"


def npm_cmd(args: list[str]) -> list[str]:
    """Wrap npm for Windows (cmd /c npm) and Unix (npm direct)."""
    if IS_WINDOWS:
        return ["cmd", "/c", "npm"] + args
    return ["npm"] + args


class AuditEngine:
    """Main audit orchestrator."""

    def __init__(self, registry: DetectorRegistry) -> None:
        self.registry = registry
        self._tmp_dir: Path | None = None
        self._is_local: bool = False

    @staticmethod
    def _validate_source(source: str) -> None:
        """Validate that source is a legitimate URL or npm package name.

        Prevents git flag injection (source starting with ``-``) and
        rejects values that are neither a valid URL nor a valid npm
        package identifier.

        Raises ``ValueError`` on invalid input.
        """
        if source.startswith("-"):
            raise ValueError(
                f"Invalid source (starts with '-', possible git injection): {source}"
            )
        # Git / HTTPS URL
        if source.startswith("git@") or source.startswith("http"):
            return
        # Local path (absolute or relative)
        if Path(source).exists():
            return
        # npm package name (optionally scoped)
        if re.match(r"^@?[a-zA-Z0-9][\w./-]*$", source):
            return
        raise ValueError(
            f"Suspicious source (neither a URL nor a valid package name): {source}"
        )

    def run(
        self,
        source: str,
        name: str | None = None,
        npm_package: str | None = None,
        keep: bool = False,
    ) -> AuditResult:
        """Run a full audit on a source (GitHub URL or npm package).

        Parameters
        ----------
        keep:
            If ``True``, do not remove the temporary directory after the
            audit so the user can inspect the cloned source.
        """
        # Validate source before any network/subprocess call
        self._validate_source(source)

        is_github = "github.com" in source or source.startswith("git@")

        if name is None:
            if is_github:
                name = source.rstrip("/").split("/")[-1].replace(".git", "")
            else:
                name = source.replace("/", "_").replace("@", "")

        result = AuditResult(
            name=name,
            source=source,
            timestamp=datetime.now().isoformat(),
        )

        try:
            # Phase 1: Acquire source
            repo_path = self._acquire(source, name, is_github)

            # Phase 2: Scan source code
            files = self._get_code_files(repo_path)
            print(f"[*] Scanning {len(files)} source files...")
            for filepath in files:
                content = self._read_file(filepath)
                if not content:
                    continue
                rel = str(filepath.relative_to(repo_path))
                for detector in self.registry.source_detectors:
                    result.findings.extend(detector.scan_file(rel, content))

            # Phase 3: Extract tools statically
            result.tools_static = self._extract_tools_static(repo_path)

            # Phase 4: Scan metadata (tool descriptions, schemas)
            all_tools = result.tools_live or result.tools_static
            print(f"[*] Scanning {len(all_tools)} tool metadata...")
            for tool in all_tools:
                for detector in self.registry.meta_detectors:
                    result.findings.extend(
                        detector.scan_tool(
                            tool.name,
                            tool.description,
                            tool.input_schema,
                            tool.annotations,
                        )
                    )

            # Phase 5: Dependency analysis
            print("[*] Analyzing dependencies...")
            from mcp_shield.analyzers.deps import (
                analyze_dependencies,
                find_phantom_deps,
            )

            deps_result, deps_findings = analyze_dependencies(repo_path)
            result.deps = deps_result.as_dict()
            result.findings.extend(deps_findings)
            phantoms, phantom_findings = find_phantom_deps(repo_path, deps_result)
            deps_result.phantom = phantoms
            result.findings.extend(phantom_findings)

            # Phase 5b: Direct and transitive dependency audit
            from mcp_shield.analyzers.version_pin import (
                run_dep_audit,
                audit_transitive_deps,
            )

            dep_type = deps_result.type or ""
            dep_audit_out = run_dep_audit(repo_path, dep_type)
            if dep_audit_out:
                result.dep_audit = dep_audit_out
            if self._tmp_dir:
                trans_audit_out = audit_transitive_deps(
                    repo_path, dep_type, self._tmp_dir
                )
                if trans_audit_out:
                    result.transitive_audit = trans_audit_out

            # Phase 6: URL extraction and classification
            print("[*] Extracting and classifying URLs...")
            from mcp_shield.analyzers.urls import extract_urls

            url_results, url_findings = extract_urls(repo_path)
            result.urls = url_results
            result.findings.extend(url_findings)

            # Phase 7: npm-specific checks
            from mcp_shield.analyzers.npm_checks import (
                check_npm_deprecated,
                check_mcp_sdk_version,
                check_rate_limiting,
            )

            dep_type = deps_result.type or ""
            if dep_type == "npm":
                deprecated_msg, dep_findings = check_npm_deprecated(repo_path)
                result.deprecated_msg = deprecated_msg or ""
                result.findings.extend(dep_findings)

            sdk_info, sdk_findings = check_mcp_sdk_version(deps_result.as_dict())
            result.sdk_info = sdk_info or {}
            result.findings.extend(sdk_findings)

            all_tools = result.tools_live or result.tools_static
            tools_as_dicts = [{"name": t.name} for t in all_tools]
            rl_tool_names, rl_findings = check_rate_limiting(repo_path, tools_as_dicts)
            result.rate_limited_tools = rl_tool_names
            result.findings.extend(rl_findings)

            # Phase 8: Supply chain comparison (if npm_package specified)
            if npm_package and is_github and self._tmp_dir:
                print("[*] Comparing npm vs GitHub...")
                from mcp_shield.analyzers.supply_chain import (
                    compare_published_vs_source,
                )

                sc_result, sc_findings = compare_published_vs_source(
                    repo_path, npm_package, self._tmp_dir
                )
                result.npm_github_diff = sc_result
                result.findings.extend(sc_findings)

            # Phase 9: Version pinning
            from mcp_shield.analyzers.version_pin import resolve_pinned_version

            result.pinned_version = resolve_pinned_version(repo_path, npm_package)

            # Phase 9b: SBOM generation
            print("[*] Generating SBOM...")
            from mcp_shield.analyzers.sbom import generate_sbom

            result.sbom = generate_sbom(result.deps, result.name)

            # Phase 10: Repo health
            result.health = self._check_health(repo_path, files)

            # Phase 11: AIVSS scoring
            from mcp_shield.scoring.aivss import compute_aivss

            result.aivss = compute_aivss(result.findings)

            print(
                f"[*] Audit complete: {len(result.findings)} findings, "
                f"grade {result.grade.value}, AIVSS {result.aivss.score}/10"
            )

        finally:
            if self._tmp_dir and not keep:
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
            elif self._tmp_dir and keep:
                print(f"[*] Keeping temp directory: {self._tmp_dir}")

        return result

    def run_live(
        self,
        result: AuditResult,
        command: str,
        args: list[str],
        env: dict[str, str] | None = None,
    ) -> AuditResult:
        """Run live analysis: fetch tools via MCP protocol and compare."""
        from mcp_shield.fetcher.live import fetch_live_tools

        print("[*] Fetching live tools via MCP protocol...")
        live_tools = fetch_live_tools(command, args, env)
        if live_tools is None:
            print("[!] Could not connect to MCP server")
            return result

        result.tools_live = live_tools
        print(f"[*] Got {len(live_tools)} live tools")

        # Run meta detectors on live tools
        for tool in live_tools:
            for detector in self.registry.meta_detectors:
                result.findings.extend(
                    detector.scan_tool(
                        tool.name,
                        tool.description,
                        tool.input_schema,
                        tool.annotations,
                    )
                )

        # Run delta detectors
        if result.tools_static and result.tools_live:
            print("[*] Running delta analysis (static vs live)...")
            for detector in self.registry.runtime_detectors:
                result.findings.extend(
                    detector.scan_delta(result.tools_static, result.tools_live)
                )

        # Deduplicate findings
        seen = set()
        unique = []
        for f in result.findings:
            key = (f.rule_id, f.location, f.evidence[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        result.findings = unique

        return result

    def _acquire(self, source: str, name: str, is_github: bool) -> Path:
        """Clone, download, or use local path as source."""
        # Local path — use directly, no tmp dir needed
        local = Path(source)
        if local.exists() and local.is_dir():
            print(f"[*] Using local path: {source}")
            self._is_local = True
            return local

        self._tmp_dir = Path(tempfile.mkdtemp(prefix="mcp_shield_"))
        repo_path = self._tmp_dir / name

        if is_github:
            print(f"[*] Cloning {source}...")
            r = subprocess.run(
                ["git", "clone", "--depth=1", source, str(repo_path)],
                capture_output=True,
                timeout=120,
            )
            if r.returncode != 0:
                raise RuntimeError(f"Clone failed: {r.stderr.decode()[:200]}")
        else:
            print(f"[*] Downloading npm package: {source}...")
            repo_path.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                npm_cmd(["pack", source, "--pack-destination", str(repo_path)]),
                capture_output=True,
                timeout=60,
            )
            if r.returncode == 0:
                for tgz in repo_path.glob("*.tgz"):
                    subprocess.run(
                        ["tar", "xzf", str(tgz), "-C", str(repo_path)],
                        capture_output=True,
                        timeout=30,
                    )
                pkg_dir = repo_path / "package"
                if pkg_dir.exists():
                    repo_path = pkg_dir

        return repo_path

    def _get_code_files(self, repo_path: Path) -> list[Path]:
        """List scannable source files."""
        # For local installed packages, scan dist/build too (they're the only source)
        skip_dirs = (
            IGNORE_DIRS
            if not self._is_local
            else IGNORE_DIRS - {"dist", "build", "lib", "out"}
        )
        files = []
        repo_depth = len(repo_path.parts)
        for f in repo_path.rglob("*"):
            # Only check ignore dirs for path components UNDER repo_path
            rel_parts = f.parts[repo_depth:]
            if any(d in rel_parts for d in skip_dirs):
                continue
            if f.name in IGNORE_FILES:
                continue
            if f.suffix in CODE_EXTENSIONS and f.is_file():
                try:
                    if f.stat().st_size < 500_000:
                        files.append(f)
                except OSError:
                    pass
        return files

    @staticmethod
    def _read_file(filepath: Path) -> str:
        try:
            return filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _extract_tools_static(self, repo_path: Path) -> list[ToolInfo]:
        """Extract MCP tools from source code via regex."""
        import re

        tools: list[ToolInfo] = []
        seen: set[str] = set()

        py_decorator = re.compile(r"@(?:mcp|server|app)\.tool\s*\(")
        js_tool = re.compile(r"(?:server|mcp)\.tool\s*\(\s*['\"]([a-zA-Z_][\w-]*)['\"]")
        go_tool = re.compile(r"(?:mcp\.NewTool|AddTool|RegisterTool)\s*\(")
        func_def = re.compile(r"\s*(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(")
        name_str = re.compile(r'["\']([a-zA-Z_][\w-]*)["\']')

        for filepath in self._get_code_files(repo_path):
            content = self._read_file(filepath)
            if not content:
                continue
            lines = content.split("\n")
            rel = str(filepath.relative_to(repo_path))

            for i, line in enumerate(lines):
                tool_name = None
                desc = ""

                if py_decorator.search(line):
                    for j in range(i + 1, min(i + 10, len(lines))):
                        m = func_def.match(lines[j])
                        if m:
                            tool_name = m.group(1)
                            for k in range(j + 1, min(j + 5, len(lines))):
                                dm = re.match(r'\s*"""(.+?)"""', lines[k])
                                if dm:
                                    desc = dm.group(1)
                                    break
                            break

                elif js_m := js_tool.search(line):
                    tool_name = js_m.group(1)
                    for j in range(i, min(i + 10, len(lines))):
                        dm = re.search(
                            r"description\s*[:=]\s*['\"`](.+?)['\"`]", lines[j]
                        )
                        if dm:
                            desc = dm.group(1)
                            break

                elif go_tool.search(line):
                    nm = name_str.search(line)
                    if nm:
                        tool_name = nm.group(1)

                if tool_name and tool_name not in seen:
                    seen.add(tool_name)
                    tools.append(
                        ToolInfo(
                            name=tool_name,
                            description=desc[:200],
                            source="static",
                            file=rel,
                            line=i + 1,
                        )
                    )

        return tools

    @staticmethod
    def _check_health(repo_path: Path, files: list[Path]) -> dict:
        """Check repository health indicators."""
        code_lines = 0
        for f in files:
            try:
                code_lines += len(
                    f.read_text(encoding="utf-8", errors="ignore").splitlines()
                )
            except Exception:
                pass

        return {
            "has_readme": (repo_path / "README.md").exists(),
            "has_license": any(
                (repo_path / f).exists()
                for f in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"]
            ),
            "has_tests": any(
                d.name in ("test", "tests", "__tests__", "spec", "e2e")
                for d in repo_path.iterdir()
                if d.is_dir()
            ),
            "has_ci": any(
                (repo_path / d).exists()
                for d in [
                    ".github/workflows",
                    ".gitlab-ci.yml",
                    "Jenkinsfile",
                    ".circleci",
                ]
            ),
            "has_dockerfile": (repo_path / "Dockerfile").exists(),
            "file_count": len(files),
            "code_lines": code_lines,
        }
