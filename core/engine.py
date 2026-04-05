"""Audit engine — orchestrates the three detection pipelines.

The engine coordinates: source acquisition, file scanning,
metadata scanning, live fetching, and delta comparison.
It produces a single AuditResult with all findings aggregated.
"""

from __future__ import annotations

import fnmatch
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

# Binary extensions — analyzed by binary_analysis detector
BINARY_EXTENSIONS = {
    ".exe",
    ".bin",
    ".elf",
    ".so",
    ".dll",
    ".dylib",
}

# Max size for source files (500 KB) vs binaries (100 MB)
MAX_SOURCE_SIZE = 500_000
MAX_BINARY_SIZE = 100_000_000

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


_RE_SAFE_PKG_NAME = re.compile(r"^@?[a-zA-Z0-9][\w./-]*$")


def validate_package_name(name: str) -> str:
    """Validate and return an npm/pip package name.

    Raises ValueError if the name contains shell-unsafe characters.
    """
    if not _RE_SAFE_PKG_NAME.match(name) or ".." in name:
        raise ValueError(f"Unsafe package name: {name!r}")
    return name


def npm_cmd(args: list[str]) -> list[str]:
    """Wrap npm for Windows (npm.cmd) and Unix (npm direct).

    Uses npm.cmd on Windows instead of cmd /c to avoid command injection
    through shell metacharacters in arguments.
    """
    if IS_WINDOWS:
        return ["npm.cmd"] + args
    return ["npm"] + args


def _safe_extract_tar(tar_path: Path, dest: Path) -> None:
    """Extract a tarball with protection against tar slip and symlink attacks.

    Rejects:
    - Members with absolute paths or path traversal (../)
    - Symlinks pointing outside the destination
    - Excessively large files (>100 MB)
    """
    import tarfile

    dest = dest.resolve()
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            member_path = (dest / member.name).resolve()
            # Block path traversal
            if not str(member_path).startswith(str(dest)):
                raise ValueError(
                    f"Tar slip detected: {member.name!r} resolves outside {dest}"
                )
            # Block absolute paths
            if member.name.startswith("/") or member.name.startswith("\\"):
                raise ValueError(f"Absolute path in tarball: {member.name!r}")
            # Block symlinks pointing outside dest
            if member.issym() or member.islnk():
                link_target = Path(member.linkname)
                if link_target.is_absolute():
                    raise ValueError(
                        f"Absolute symlink in tarball: {member.name!r} -> {member.linkname!r}"
                    )
                resolved = (dest / Path(member.name).parent / link_target).resolve()
                if not str(resolved).startswith(str(dest)):
                    raise ValueError(
                        f"Symlink escape: {member.name!r} -> {member.linkname!r}"
                    )
            # Block oversized files
            if member.size > MAX_BINARY_SIZE:
                raise ValueError(
                    f"Oversized tar member: {member.name!r} ({member.size} bytes)"
                )
            tf.extract(member, dest)


# Max findings per rule_id — prevents score inflation from repeated patterns
_MAX_PER_RULE = 5

# File patterns to skip for source code scanning (test/example/fixture files)
_TEST_FILE_PATTERNS = {
    "test_",
    "tests/",
    "test/",
    "__tests__/",
    "spec/",
    "e2e/",
    "example/",
    "examples/",
    "fixture/",
    "fixtures/",
    "mock/",
    "mocks/",
    ".test.",
    ".spec.",
    "_test.",
    "_spec.",
}


def _is_test_file(rel_path: str) -> bool:
    """Check if a relative path looks like a test/example file."""
    lower = rel_path.lower().replace("\\", "/")
    return any(pat in lower for pat in _TEST_FILE_PATTERNS)


def _dedup_and_cap(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings and cap per rule_id.

    - Removes exact duplicates (same rule_id + location + evidence prefix)
    - Caps each rule_id at _MAX_PER_RULE findings (keeps highest-severity)
    - Deprioritizes findings from test/example files
    """
    # Step 1: Dedup
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.location, f.evidence[:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Step 2: Cap per rule_id — keep most severe, prefer non-test files
    from collections import defaultdict

    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in unique:
        by_rule[f.rule_id].append(f)

    capped: list[Finding] = []
    for rule_id, rule_findings in by_rule.items():
        # Sort: severity ascending (CRITICAL first), non-test first
        rule_findings.sort(key=lambda f: (f.severity, _is_test_file(f.location)))
        capped.extend(rule_findings[:_MAX_PER_RULE])

    return capped


def _load_ignore_patterns(repo_path: Path) -> list[str]:
    """Load glob patterns from a .mcpshieldignore file at repo root.

    Returns a list of patterns (one per line).  Blank lines and lines
    starting with ``#`` are skipped.  Trailing slashes on directory
    patterns are preserved so ``fnmatch`` can match path prefixes.
    """
    ignore_file = repo_path / ".mcpshieldignore"
    if not ignore_file.is_file():
        return []
    try:
        text = ignore_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    patterns: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def _matches_ignore(rel_posix: str, patterns: list[str]) -> bool:
    """Return True if *rel_posix* matches any ignore pattern.

    Matching rules (gitignore-like, simplified):
    - ``*.test.js``  — matched against the full relative path **and** the
      basename so ``src/foo.test.js`` is caught.
    - ``tests/``     — any path whose prefix starts with ``tests/``.
    - ``vendor/**``  — any path under ``vendor/``.
    """
    for pat in patterns:
        # Directory pattern (trailing slash): match as path prefix
        if pat.endswith("/"):
            if rel_posix.startswith(pat) or ("/" + pat) in ("/" + rel_posix):
                return True
            # Also match if any path component equals the dir name
            dir_name = pat.rstrip("/")
            parts = rel_posix.split("/")
            if dir_name in parts[:-1]:
                return True
            continue
        # fnmatch against full relative path
        if fnmatch.fnmatch(rel_posix, pat):
            return True
        # Also match against basename only (e.g. *.test.js)
        basename = rel_posix.rsplit("/", 1)[-1]
        if fnmatch.fnmatch(basename, pat):
            return True
    return False


class AuditEngine:
    """Main audit orchestrator."""

    def __init__(
        self,
        registry: DetectorRegistry,
        *,
        quiet: bool = False,
        log_stream=None,
    ) -> None:
        self.registry = registry
        self._tmp_dir: Path | None = None
        self._is_local: bool = False
        self._no_ignore: bool = False
        self._quiet: bool = quiet
        self._log_stream = log_stream  # None = stdout, sys.stderr for structured output

    def _log(self, msg: str) -> None:
        """Print a message unless quiet mode is active."""
        if not self._quiet:
            print(msg, file=self._log_stream)

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
        # npm package name (optionally scoped) — check BEFORE local path heuristics
        # because scoped packages like @scope/name contain a '/' which would
        # otherwise be misidentified as a local path.
        if re.match(r"^@[a-zA-Z0-9][\w.-]*/[a-zA-Z0-9][\w.-]*$", source):
            return
        # Local path (absolute or relative)
        if Path(source).exists():
            return
        # Looks like a local path but doesn't exist
        if (
            "/" in source
            or "\\" in source
            or source.startswith(".")
            or (len(source) >= 2 and source[1] == ":")
        ):
            raise ValueError(f"Path not found: {source}")
        # npm package name (unscoped)
        if re.match(r"^[a-zA-Z0-9][\w.-]*$", source):
            return
        raise ValueError(
            f"Invalid source: {source}\n"
            f"Expected: GitHub URL, npm package name, or local path"
        )

    def run(
        self,
        source: str,
        name: str | None = None,
        npm_package: str | None = None,
        keep: bool = False,
        no_ignore: bool = False,
    ) -> AuditResult:
        """Run a full audit on a source (GitHub URL or npm package).

        Parameters
        ----------
        keep:
            If ``True``, do not remove the temporary directory after the
            audit so the user can inspect the cloned source.
        """
        self._no_ignore = no_ignore

        # Validate source before any network/subprocess call
        self._validate_source(source)

        is_github = "github.com" in source or source.startswith("git@")

        if name is None:
            if is_github:
                name = source.rstrip("/").split("/")[-1].replace(".git", "")
            elif Path(source).exists():
                # Local path: use directory name, or parent if it's a file
                p = Path(source).resolve()
                name = p.name if p.is_dir() else p.parent.name
            else:
                # npm package: strip scope prefix for display
                name = source.split("/")[-1] if "/" in source else source

        # Check if source is from a trusted publisher
        from mcp_shield.core.trusted import is_trusted_source

        is_trusted, publisher = is_trusted_source(source, name=name or "")

        result = AuditResult(
            name=name,
            source=source,
            timestamp=datetime.now().isoformat(),
            trusted_publisher=publisher if is_trusted else "",
        )

        try:
            # Phase 1: Acquire source
            repo_path = self._acquire(source, name, is_github)

            # Phase 2: Scan source code
            files = self._get_code_files(repo_path)
            self._log(f"[*] Scanning {len(files)} source files...")
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
            self._log(f"[*] Scanning {len(all_tools)} tool metadata...")
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
            self._log("[*] Analyzing dependencies...")
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
            dep_audit_out = run_dep_audit(repo_path, dep_type, quiet=self._quiet)
            if dep_audit_out:
                result.dep_audit = dep_audit_out
            if self._tmp_dir:
                trans_audit_out = audit_transitive_deps(
                    repo_path, dep_type, self._tmp_dir, quiet=self._quiet
                )
                if trans_audit_out:
                    result.transitive_audit = trans_audit_out

            # Phase 6: URL extraction and classification
            self._log("[*] Extracting and classifying URLs...")
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
                self._log("[*] Comparing npm vs GitHub...")
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
            self._log("[*] Generating SBOM...")
            from mcp_shield.analyzers.sbom import generate_sbom

            result.sbom = generate_sbom(result.deps, result.name, quiet=self._quiet)

            # Phase 10: Deduplicate + cap findings per rule_id
            result.findings = _dedup_and_cap(result.findings)

            # Phase 11: Repo health
            result.health = self._check_health(repo_path, files)

            # Phase 12: AIVSS scoring
            from mcp_shield.scoring.aivss import compute_aivss

            result.aivss = compute_aivss(result.findings)

            self._log(
                f"[*] Audit complete: {len(result.findings)} findings, "
                f"grade {result.grade.value}, AIVSS {result.aivss.score}/10"
            )

        finally:
            if self._tmp_dir and not keep:
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
            elif self._tmp_dir and keep:
                self._log(f"[*] Keeping temp directory: {self._tmp_dir}")

        return result

    def run_live(
        self,
        result: AuditResult,
        command: str,
        args: list[str],
        env: dict[str, str] | None = None,
    ) -> AuditResult:
        """Run live analysis: fetch tools, resources, prompts via MCP protocol."""
        from mcp_shield.fetcher.live import fetch_live_all

        self._log("[*] Fetching live tools/resources/prompts via MCP protocol...")
        live_result = fetch_live_all(command, args, env)
        if live_result is None:
            self._log("[!] Could not connect to MCP server")
            return result

        live_tools, live_resources, live_prompts, capabilities = live_result

        if live_tools is not None:
            result.tools_live = live_tools
            self._log(f"[*] Got {len(live_tools)} live tools")

        if live_resources is not None:
            result.resources = live_resources
            self._log(f"[*] Got {len(live_resources)} live resources")

        if live_prompts is not None:
            result.prompts = live_prompts
            self._log(f"[*] Got {len(live_prompts)} live prompts")

        if capabilities is not None:
            result.capabilities = capabilities

        # Run meta detectors on live tools
        for tool in live_tools or []:
            for detector in self.registry.meta_detectors:
                result.findings.extend(
                    detector.scan_tool(
                        tool.name,
                        tool.description,
                        tool.input_schema,
                        tool.annotations,
                    )
                )

        # Scan resources for injection
        if live_resources:
            from mcp_shield.detectors.meta.resource_injection import (
                ResourceInjectionDetector,
            )

            self._log(f"[*] Scanning {len(live_resources)} resources for injection...")
            res_detector = ResourceInjectionDetector()
            result.findings.extend(res_detector.scan_resources(live_resources))

        # Scan prompts for injection
        if live_prompts:
            from mcp_shield.detectors.meta.prompt_template import (
                PromptTemplateDetector,
            )

            self._log(f"[*] Scanning {len(live_prompts)} prompts for injection...")
            prompt_detector = PromptTemplateDetector()
            result.findings.extend(prompt_detector.scan_prompts(live_prompts))

        # Check sampling capability
        if capabilities:
            from mcp_shield.detectors.meta.sampling_detector import SamplingDetector

            sampling_detector = SamplingDetector()
            result.findings.extend(
                sampling_detector.scan_capabilities(capabilities, result.name)
            )

        # Run delta detectors
        if result.tools_static and result.tools_live:
            self._log("[*] Running delta analysis (static vs live)...")
            for detector in self.registry.runtime_detectors:
                result.findings.extend(
                    detector.scan_delta(result.tools_static, result.tools_live)
                )

        # Deduplicate and cap findings (same logic as run())
        result.findings = _dedup_and_cap(result.findings)

        return result

    def _acquire(self, source: str, name: str, is_github: bool) -> Path:
        """Clone, download, or use local path as source."""
        # Local path — use directly, no tmp dir needed
        local = Path(source)
        if local.exists() and local.is_dir():
            self._log(f"[*] Using local path: {source}")
            self._is_local = True
            return local

        self._tmp_dir = Path(tempfile.mkdtemp(prefix="mcp_shield_"))
        repo_path = self._tmp_dir / name

        if is_github:
            self._log(f"[*] Cloning {source}...")
            r = subprocess.run(
                ["git", "clone", "--depth=1", source, str(repo_path)],
                capture_output=True,
                timeout=120,
            )
            if r.returncode != 0:
                raise RuntimeError(f"Clone failed: {r.stderr.decode()[:200]}")
        else:
            self._log(f"[*] Downloading npm package: {source}...")
            validate_package_name(source)
            repo_path.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                npm_cmd(["pack", source, "--pack-destination", str(repo_path)]),
                capture_output=True,
                timeout=60,
            )
            if r.returncode != 0:
                stderr = r.stderr.decode(errors="replace")[:200].strip()
                raise RuntimeError(
                    f"npm pack failed for '{source}': {stderr or 'package not found'}"
                )
            for tgz in repo_path.glob("*.tgz"):
                _safe_extract_tar(tgz, repo_path)
            pkg_dir = repo_path / "package"
            if pkg_dir.exists():
                repo_path = pkg_dir

        return repo_path

    def _get_code_files(self, repo_path: Path) -> list[Path]:
        """List scannable source files.

        Respects a ``.mcpshieldignore`` file at the repo root if present.
        """
        # For local installed packages, scan dist/build too (they're the only source)
        skip_dirs = (
            IGNORE_DIRS
            if not self._is_local
            else IGNORE_DIRS - {"dist", "build", "lib", "out"}
        )
        ignore_patterns = _load_ignore_patterns(repo_path)
        if ignore_patterns and not self._no_ignore:
            self._log(
                f"[!] WARNING: .mcpshieldignore found in scanned repo "
                f"({len(ignore_patterns)} pattern(s)). "
                f"Files may be hidden from analysis. "
                f"Use --no-ignore to override."
            )
        if self._no_ignore:
            ignore_patterns = []
        files = []
        repo_depth = len(repo_path.parts)
        for f in repo_path.rglob("*"):
            # Only check ignore dirs for path components UNDER repo_path
            rel_parts = f.parts[repo_depth:]
            if any(d in rel_parts for d in skip_dirs):
                continue
            if f.name in IGNORE_FILES:
                continue
            if f.is_file():
                ext = f.suffix.lower()
                try:
                    size = f.stat().st_size
                except OSError:
                    continue
                # Apply .mcpshieldignore patterns (use forward slashes)
                if ignore_patterns:
                    rel_posix = "/".join(rel_parts)
                    if _matches_ignore(rel_posix, ignore_patterns):
                        continue
                if ext in CODE_EXTENSIONS and size < MAX_SOURCE_SIZE:
                    files.append(f)
                elif ext in BINARY_EXTENSIONS and size < MAX_BINARY_SIZE:
                    files.append(f)
        return files

    @staticmethod
    def _read_file(filepath: Path) -> str:
        try:
            size = filepath.stat().st_size
            is_binary = filepath.suffix.lower() in BINARY_EXTENSIONS
            limit = MAX_BINARY_SIZE if is_binary else MAX_SOURCE_SIZE
            if size > limit:
                return ""
            if is_binary:
                return filepath.read_bytes().decode("latin-1")
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
