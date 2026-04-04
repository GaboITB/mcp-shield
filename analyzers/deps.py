"""Dependency analysis for MCP Shield v2.

Ports analyze_dependencies() and find_phantom_deps() from mcp_audit.py v1.
Parses npm (package.json), pip (requirements.txt, pyproject.toml), and Go (go.mod).
Generates Finding objects for security issues found in dependencies.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NATIVE_NODE_MODULES: frozenset[str] = frozenset(
    {
        "child_process",
        "https",
        "http",
        "fs",
        "path",
        "os",
        "util",
        "crypto",
        "net",
        "tls",
        "stream",
        "events",
        "buffer",
        "readline",
        "cluster",
        "dgram",
        "dns",
        "domain",
    }
)

PHONEHOME_DEPS: frozenset[str] = frozenset(
    {
        "update-notifier",
        "analytics-node",
        "mixpanel",
        "@sentry/node",
        "posthog-node",
        "amplitude-js",
        "sentry",
        "@sentry/browser",
    }
)

CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
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
)

IGNORE_DIRS: frozenset[str] = frozenset(
    {
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
)

IGNORE_FILES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.sum",
        "Pipfile.lock",
        "poetry.lock",
    }
)

_TEST_FILE_RE = re.compile(
    r"(_test\.go|\.test\.\w+|\.spec\.\w+|_test\.py|test_\w+\.py)$"
)
_MAX_FILE_SIZE = 500_000


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class DepsResult:
    """Typed result from dependency analysis."""

    type: str | None = None
    deps: dict[str, str] = field(default_factory=dict)
    dev_deps: dict[str, str] = field(default_factory=dict)
    suspicious: list[str] = field(default_factory=list)
    phonehome: list[str] = field(default_factory=list)
    unpinned: list[str] = field(default_factory=list)
    native_in_deps: list[str] = field(default_factory=list)
    phantom: list[str] = field(default_factory=list)
    total_count: int = 0
    postinstall: str | None = None

    def as_dict(self) -> dict:
        """Serialise to a plain dict (for AuditResult.deps)."""
        return {
            "type": self.type,
            "deps": self.deps,
            "dev_deps": self.dev_deps,
            "suspicious": self.suspicious,
            "phonehome": self.phonehome,
            "unpinned": self.unpinned,
            "native_in_deps": self.native_in_deps,
            "phantom": self.phantom,
            "total_count": self.total_count,
            "postinstall": self.postinstall,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_code_files(repo_path: Path, *, include_tests: bool = False) -> Iterator[Path]:
    """Yield code files inside *repo_path*, skipping ignored dirs/files."""
    for f in repo_path.rglob("*"):
        if any(d in f.parts for d in IGNORE_DIRS):
            continue
        if f.name in IGNORE_FILES:
            continue
        if not include_tests and _TEST_FILE_RE.search(f.name):
            continue
        if f.suffix in CODE_EXTENSIONS and f.is_file():
            try:
                if f.stat().st_size < _MAX_FILE_SIZE:
                    yield f
            except OSError:
                pass


def _read_file(filepath: Path) -> str:
    """Read a single file, returning its text (empty string on error)."""
    try:
        return filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _parse_pyproject_toml(path: Path) -> dict[str, str]:
    """Parse dependencies from pyproject.toml.

    Uses tomllib (stdlib on Python 3.11+) when available, falls back to
    a simple regex parser for the ``[project] dependencies = [...]`` list.
    """
    content = path.read_text(encoding="utf-8", errors="ignore")
    deps: dict[str, str] = {}

    # Try tomllib first (Python 3.11+)
    if sys.version_info >= (3, 11):
        try:
            import tomllib

            data = tomllib.loads(content)
            raw_deps = data.get("project", {}).get("dependencies", [])
            for raw in raw_deps:
                m = re.match(r"([a-zA-Z][a-zA-Z0-9._-]*)\s*([><=~!][^\s]*)?", raw)
                if m:
                    deps[m.group(1)] = m.group(2) or ""
            return deps
        except Exception:
            pass  # fall through to regex

    # Regex fallback: parse ``dependencies = [...]`` block
    in_deps = False
    for line in content.splitlines():
        if re.match(r"^\s*dependencies\s*=\s*\[", line):
            in_deps = True
            continue
        if in_deps:
            if line.strip() == "]":
                break
            dep_match = re.match(
                r"""\s*["']([a-zA-Z][a-zA-Z0-9._-]*)\s*([><=~!][^"']*)?["']""",
                line,
            )
            if dep_match:
                deps[dep_match.group(1)] = dep_match.group(2) or ""

    return deps


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_dependencies(repo_path: Path) -> tuple[DepsResult, list[Finding]]:
    """Analyse dependencies declared in *repo_path*.

    Returns a ``DepsResult`` plus a list of ``Finding`` objects for anything
    noteworthy (unpinned deps, phone-home deps, native modules, postinstall
    scripts).
    """
    result = DepsResult()
    findings: list[Finding] = []

    # --- npm (package.json) ------------------------------------------------
    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            result.type = "npm"
            result.deps = data.get("dependencies", {})
            result.dev_deps = data.get("devDependencies", {})

            # Lifecycle scripts
            scripts = data.get("scripts", {})
            for key in ("postinstall", "preinstall", "install", "prepare"):
                if key in scripts:
                    result.postinstall = f"{key}: {scripts[key]}"
                    findings.append(
                        Finding(
                            rule_id="postinstall_script",
                            severity=Severity.CRITICAL,
                            surface=Surface.SOURCE_CODE,
                            title=f"npm lifecycle script: {key}",
                            evidence=scripts[key][:150],
                            location="package.json:0",
                            detail="Lifecycle scripts can execute arbitrary code at install time",
                        )
                    )
        except json.JSONDecodeError:
            pass

    # --- pip: requirements.txt --------------------------------------------
    req_txt = repo_path / "requirements.txt"
    if req_txt.exists() and result.type is None:
        result.type = "pip"
        for line in req_txt.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            parts = re.split(r"[><=~!;]", line, maxsplit=1)
            name = parts[0].strip()
            version = line[len(name) :].strip() if len(parts) > 1 else ""
            if name and re.match(r"^[a-zA-Z][a-zA-Z0-9._-]*$", name):
                result.deps[name] = version

    # --- pip: pyproject.toml -----------------------------------------------
    pyproject = repo_path / "pyproject.toml"
    if pyproject.exists() and result.type is None:
        result.type = "pip"
        result.deps = _parse_pyproject_toml(pyproject)

    # --- go: go.mod --------------------------------------------------------
    go_mod = repo_path / "go.mod"
    if go_mod.exists():
        result.type = "go"
        for line in go_mod.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s+([\w./\-]+)\s+(v[\w.\-]+)", line)
            if m:
                result.deps[m.group(1)] = m.group(2)

    # --- Analyse all declared deps -----------------------------------------
    all_deps = {**result.deps, **result.dev_deps}
    result.total_count = len(all_deps)

    manifest_file = {
        "npm": "package.json",
        "pip": "requirements.txt",
        "go": "go.mod",
    }.get(result.type or "", "unknown")

    for dep_name in all_deps:
        dep_lower = dep_name.lower()

        # Native Node module listed as npm dependency (typosquatting risk)
        if dep_lower in NATIVE_NODE_MODULES and result.type == "npm":
            result.native_in_deps.append(dep_name)
            findings.append(
                Finding(
                    rule_id="native_module_dep",
                    severity=Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title=f"Native Node module in package.json: {dep_name}",
                    evidence=dep_name,
                    location=f"{manifest_file}:0",
                    detail="Native module installed as npm dep — potential typosquatting",
                )
            )

        # Phone-home / telemetry dependency
        if dep_lower in PHONEHOME_DEPS:
            result.phonehome.append(dep_name)
            findings.append(
                Finding(
                    rule_id="telemetry_phonehome",
                    severity=Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title=f"Phone-home dependency: {dep_name}",
                    evidence=dep_name,
                    location=f"{manifest_file}:0",
                    detail="Dependency known for sending telemetry/analytics data",
                )
            )

    # Unpinned deps (production deps only)
    for dep_name, version in result.deps.items():
        if version and str(version).startswith(("^", "~", ">=", ">", "*", "latest")):
            result.unpinned.append(f"{dep_name}: {version}")
            findings.append(
                Finding(
                    rule_id="unpinned_dependency",
                    severity=Severity.LOW,
                    surface=Surface.SOURCE_CODE,
                    title=f"Unpinned dependency: {dep_name}",
                    evidence=f"{dep_name}: {version}",
                    location=f"{manifest_file}:0",
                    detail="Dependency version range allows automatic updates — supply-chain risk",
                )
            )

    return result, findings


# ---------------------------------------------------------------------------
# Phantom dependency detection
# ---------------------------------------------------------------------------


def _dep_search_names(dep_name: str) -> list[str]:
    """Generate search name variants for a dependency."""
    names = [dep_name]
    # Scoped package — also search the short name
    if "/" in dep_name:
        names.append(dep_name.split("/")[-1])
    # dash to underscore (python-dotenv -> python_dotenv)
    names.append(dep_name.replace("-", "_").replace(".", "_"))
    # no dashes (python-dotenv -> pythondotenv)
    names.append(dep_name.replace("-", ""))
    # strip python- prefix
    if dep_name.startswith("python-"):
        names.append(dep_name[7:])
        names.append(dep_name[7:].replace("-", "_"))
    # strip py prefix (pyyaml -> yaml)
    if dep_name.startswith("py") and len(dep_name) > 3:
        names.append(dep_name[2:])
        names.append(dep_name[2:].replace("-", "_"))
    # strip common suffixes
    for suffix in ("-client", "-sdk", "-api-client", "-server"):
        if dep_name.endswith(suffix):
            base = dep_name[: -len(suffix)]
            names.append(base)
            names.append(base.replace("-", "_"))
    return names


def find_phantom_deps(
    repo_path: Path,
    deps_result: DepsResult,
) -> tuple[list[str], list[Finding]]:
    """Detect declared deps that are never imported in code.

    Fixed from v1: searches file-by-file instead of concatenating all code
    into a single string (O(n*m) memory).

    Skips Go projects — go.mod is managed by the compiler.
    """
    if deps_result.type == "go":
        return [], []

    findings: list[Finding] = []
    phantoms: list[str] = []

    declared_deps = deps_result.deps
    if not declared_deps:
        return [], []

    # Pre-compute search names per dep
    dep_search_map: dict[str, list[str]] = {}
    for dep_name in declared_deps:
        if dep_name.lower() in NATIVE_NODE_MODULES:
            continue
        dep_search_map[dep_name] = [n.lower() for n in _dep_search_names(dep_name)]

    # Track which deps have been found
    found_deps: set[str] = set()

    # Search file-by-file (avoids O(n^2) memory from concatenation)
    for code_file in _iter_code_files(repo_path):
        if not dep_search_map:
            break  # all found early
        content_lower = _read_file(code_file).lower()
        if not content_lower:
            continue

        still_missing = set(dep_search_map.keys()) - found_deps
        for dep_name in still_missing:
            for search_name in dep_search_map[dep_name]:
                if search_name in content_lower:
                    found_deps.add(dep_name)
                    break

    # Anything not found is a phantom
    manifest_file = {
        "npm": "package.json",
        "pip": "requirements.txt",
    }.get(deps_result.type or "", "manifest")

    for dep_name in dep_search_map:
        if dep_name not in found_deps:
            phantoms.append(dep_name)
            findings.append(
                Finding(
                    rule_id="phantom_dependency",
                    severity=Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title=f"Phantom dependency: {dep_name}",
                    evidence=dep_name,
                    location=f"{manifest_file}:0",
                    detail="Declared in dependencies but never imported in code",
                )
            )

    return phantoms, findings
