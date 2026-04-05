"""Docker sandbox for MCP runtime analysis.

Launches an MCP server inside an isolated Docker container and captures:
- Network traffic (tcpdump)
- Filesystem changes (inotifywait)
- System calls (strace)

Ported from mcp_sandbox.py (v1) with fixes:
- Separate volume mounts for logs and captures (fixes double-mount bug)
- Proper temp directory cleanup (fixes tmpdir leak)
- Structured return via dataclass
- Integration with v2 Finding model
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

from mcp_shield.core.paths import get_audit_dir

SCRIPT_DIR = Path(__file__).resolve().parent.parent  # .../mcp_shield/
AUDIT_DIR = get_audit_dir()
IMAGE_NAME = "mcp-shield-sandbox"
DOCKERFILE_NAME = "Dockerfile.mcp-audit"
ENTRYPOINT_NAME = "sandbox-entrypoint.sh"


# ---------------------------------------------------------------------------
# Docker availability check
# ---------------------------------------------------------------------------


def docker_available() -> bool:
    """Check if Docker is installed and the daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_sandbox_prerequisites() -> tuple[bool, str]:
    """Check all prerequisites for sandbox mode.

    Returns (ok, message) tuple.
    """
    if not docker_available():
        return False, (
            "Docker is not available. Install Docker and ensure the daemon "
            "is running to use sandbox mode. Sandbox is optional -- "
            "static analysis works without it."
        )

    # Check Dockerfile exists
    dockerfile = SCRIPT_DIR / DOCKERFILE_NAME
    if not dockerfile.exists():
        return False, f"Dockerfile not found at {dockerfile}"

    entrypoint = SCRIPT_DIR / ENTRYPOINT_NAME
    if not entrypoint.exists():
        return False, f"Entrypoint script not found at {entrypoint}"

    return True, "All prerequisites met"


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class SandboxResult:
    """Structured result from a sandbox run."""

    status: str = "ok"
    exit_code: int = -1
    verdict: str = "CLEAN"

    dns_queries: list[str] = field(default_factory=list)
    tcp_connections: list[str] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    sensitive_files_accessed: list[str] = field(default_factory=list)
    processes_launched: list[str] = field(default_factory=list)
    external_connections: list[str] = field(default_factory=list)

    raw_stdout: str = ""
    raw_stderr: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (JSON-safe)."""
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "verdict": self.verdict,
            "dns_queries": self.dns_queries,
            "tcp_connections": self.tcp_connections,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "sensitive_files_accessed": self.sensitive_files_accessed,
            "processes_launched": self.processes_launched,
            "external_connections": self.external_connections,
            "raw_stdout": self.raw_stdout,
            "raw_stderr": self.raw_stderr,
        }

    def to_findings(self) -> list[Finding]:
        """Convert sandbox observations into v2 Finding objects."""
        findings: list[Finding] = []

        for path in self.sensitive_files_accessed:
            findings.append(
                Finding(
                    rule_id="sandbox_sensitive_file",
                    severity=Severity.CRITICAL,
                    surface=Surface.RUNTIME_DELTA,
                    title="Sensitive file accessed in sandbox",
                    evidence=path,
                    location="sandbox",
                )
            )

        for conn in self.external_connections:
            findings.append(
                Finding(
                    rule_id="sandbox_external_connection",
                    severity=Severity.HIGH,
                    surface=Surface.RUNTIME_DELTA,
                    title="External connection detected in sandbox",
                    evidence=conn,
                    location="sandbox",
                )
            )

        for query in self.dns_queries:
            findings.append(
                Finding(
                    rule_id="sandbox_dns_query",
                    severity=Severity.MEDIUM,
                    surface=Surface.RUNTIME_DELTA,
                    title="DNS query from sandbox",
                    evidence=query,
                    location="sandbox",
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Docker image management
# ---------------------------------------------------------------------------


def ensure_image_built(dockerfile_dir: Path | None = None) -> bool:
    """Ensure the sandbox Docker image exists; build it if needed."""
    if not docker_available():
        print("[!] Docker is not available")
        return False

    result = subprocess.run(
        ["docker", "images", "-q", IMAGE_NAME],
        capture_output=True,
    )
    if result.stdout.strip():
        return True

    print(f"[*] Building Docker image {IMAGE_NAME}...")
    base = dockerfile_dir or SCRIPT_DIR
    dockerfile = base / DOCKERFILE_NAME
    entrypoint = base / ENTRYPOINT_NAME

    if not dockerfile.exists():
        print(f"[!] Dockerfile not found: {dockerfile}")
        return False
    if not entrypoint.exists():
        print(f"[!] Entrypoint not found: {entrypoint}")
        return False

    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, "-f", str(dockerfile), str(base)],
        timeout=600,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Sandbox runner
# ---------------------------------------------------------------------------


def run_sandbox(
    source: str,
    name: str,
    mcp_type: str = "npm",
    duration: int = 60,
    audit_dir: Path | None = None,
    network: str = "none",
) -> SandboxResult:
    """Launch an MCP in a Docker sandbox and collect runtime observations.

    Parameters
    ----------
    source:
        GitHub URL or npm/pip package identifier.
    name:
        Human-readable name for the MCP.
    mcp_type:
        One of "npm", "pip", "git".
    duration:
        Observation window in seconds.
    audit_dir:
        Where to write reports. Defaults to ``~/.config/mcp-shield/audits``.
    network:
        Docker network mode. "none" (default) = fully isolated,
        "bridge" = monitored network access. Use "none" for maximum
        security; use "bridge" to observe what the MCP tries to connect to.

    Returns
    -------
    SandboxResult
        Structured result with all captured data.
    """
    # Graceful Docker check
    ok, msg = check_sandbox_prerequisites()
    if not ok:
        print(f"[!] Sandbox skipped: {msg}", file=sys.stderr)
        return SandboxResult(status="skipped", verdict="SKIPPED")

    if not ensure_image_built():
        return SandboxResult(status="error", verdict="ERROR")

    # Validate network mode
    if network not in ("none", "bridge"):
        network = "none"

    out_dir = audit_dir or AUDIT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    net_label = "isolated (no network)" if network == "none" else "bridge (monitored)"
    print(f"[*] Starting sandbox: {name} ({mcp_type}, {duration}s, {net_label})")
    print(f"[*] Source: {source}")

    # Create separate temp directories for logs and captures
    # (v1 bug: same dir mounted to both /audit/logs and /audit/capture)
    logs_dir: Path | None = None
    capture_dir: Path | None = None

    try:
        logs_dir = Path(tempfile.mkdtemp(prefix="mcp_sandbox_logs_"))
        capture_dir = Path(tempfile.mkdtemp(prefix="mcp_sandbox_capture_"))

        # Build docker command
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            f"--network={network}",
            "--cap-add=NET_RAW",  # tcpdump
            "--cap-add=SYS_PTRACE",  # strace
            "--security-opt=no-new-privileges",
            "--memory=512m",
            "--cpus=1",
            "--pids-limit=100",
            "-v",
            f"{logs_dir}:/audit/logs",
            "-v",
            f"{capture_dir}:/audit/capture",
        ]

        # For local paths, mount the source as a volume and use "local" type
        source_path = Path(source)
        if source_path.is_dir():
            # Resolve to absolute path for Docker volume mount
            abs_source = str(source_path.resolve()).replace("\\", "/")
            docker_cmd.extend(["-v", f"{abs_source}:/audit/source:ro"])
            container_source = "/audit/source"
            effective_type = "local"
        else:
            container_source = source
            effective_type = mcp_type

        docker_cmd.extend(
            [
                IMAGE_NAME,
                container_source,
                effective_type,
                str(duration),
            ]
        )

        # MSYS_NO_PATHCONV prevents Git Bash (MSYS2) on Windows from
        # converting Unix paths like /audit/source to C:/Program Files/...
        import os

        run_env = {**os.environ, "MSYS_NO_PATHCONV": "1"}

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            timeout=duration + 120,
            env=run_env,
        )

        stdout = result.stdout.decode("utf-8", errors="ignore")
        stderr = result.stderr.decode("utf-8", errors="ignore")

        sandbox_result = _parse_sandbox_output(stdout)
        sandbox_result.exit_code = result.returncode
        sandbox_result.raw_stdout = stdout[-2000:]
        sandbox_result.raw_stderr = stderr[-1000:]

        # Write reports — sanitize name for safe filenames
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)[:100] or "unknown"
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        report_file = out_dir / f"sandbox_{safe_name}_{ts}.md"
        report_file.write_text(
            _generate_markdown_report(name, source, sandbox_result),
            encoding="utf-8",
        )

        json_file = out_dir / f"sandbox_{safe_name}_{ts}.json"
        json_file.write_text(
            json.dumps(sandbox_result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[*] Sandbox report: {report_file}")

        return sandbox_result

    except subprocess.TimeoutExpired:
        print(f"[!] Sandbox timeout after {duration + 120}s")
        return SandboxResult(status="timeout", verdict="TIMEOUT")

    except Exception as exc:
        print(f"[!] Sandbox error: {exc}", file=sys.stderr)
        return SandboxResult(status="error", verdict="ERROR")

    finally:
        # Clean up temp directories (v1 bug: never cleaned up)
        if logs_dir and logs_dir.exists():
            shutil.rmtree(logs_dir, ignore_errors=True)
        if capture_dir and capture_dir.exists():
            shutil.rmtree(capture_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

# Section header keywords (from the container's report script)
_SECTION_MAP: dict[str, str] = {
    "Requetes DNS": "dns",
    "DNS queries": "dns",
    "Connexions TCP": "tcp",
    "TCP connections": "tcp",
    "Fichiers crees/modifies": "files",
    "Files created/modified": "files",
    "Fichiers sensibles": "sensitive",
    "Sensitive files": "sensitive",
    "PROCESSUS LANCES": "processes",
    "Processes launched": "processes",
    "CONNEXIONS (connect": "connections",
    "External connections": "connections",
}

_EMPTY_MARKERS = frozenset(
    {
        "(aucune)",
        "(aucun)",
        "(aucun suspect)",
        "(aucune externe)",
        "(pas de capture)",
        "(pas de log filesystem)",
        "(pas de log strace)",
        "(none)",
        "(no capture)",
        "(no filesystem log)",
        "(no strace log)",
    }
)


def _parse_sandbox_output(stdout: str) -> SandboxResult:
    """Parse the structured text output from the sandbox container."""
    result = SandboxResult()
    section: str | None = None

    for line in stdout.splitlines():
        line = line.strip()

        # Detect section headers
        matched = False
        for header, sec_name in _SECTION_MAP.items():
            if header in line:
                section = sec_name
                matched = True
                break
        if matched:
            continue

        if line.startswith("===") or line.startswith("---"):
            continue

        if not line or line in _EMPTY_MARKERS or section is None:
            continue

        if section == "dns":
            result.dns_queries.append(line)
        elif section == "tcp":
            result.tcp_connections.append(line)
        elif section == "files":
            result.files_created.append(line)
        elif section == "sensitive":
            result.sensitive_files_accessed.append(line)
        elif section == "processes":
            result.processes_launched.append(line)
        elif section == "connections":
            result.external_connections.append(line)

    # Determine verdict
    if result.sensitive_files_accessed:
        result.verdict = "DANGER"
    elif result.external_connections:
        result.verdict = "SUSPECT"
    elif result.dns_queries:
        result.verdict = "REVIEW"
    else:
        result.verdict = "CLEAN"

    # Check if the MCP actually started — "No entry point found" or
    # "ENOENT" in stdout means the sandbox ran but tested nothing
    raw = result.raw_stdout or ""
    if "No entry point found" in raw or "ENOENT" in raw:
        result.verdict = "INCOMPLETE"
        result.status = "incomplete"

    return result


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _generate_markdown_report(
    name: str,
    source: str,
    result: SandboxResult,
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        f"# Sandbox Report: {name}",
        f"**Date**: {now}",
        f"**Source**: {source}",
        f"**Verdict**: **{result.verdict}**",
        "",
        "## DNS Queries",
    ]

    for q in result.dns_queries:
        lines.append(f"- {q}")
    if not result.dns_queries:
        lines.append("No DNS queries observed.")
    lines.append("")

    lines.append("## Outbound TCP Connections")
    for c in result.tcp_connections:
        lines.append(f"- {c}")
    if not result.tcp_connections:
        lines.append("No outbound TCP connections.")
    lines.append("")

    lines.append("## Sensitive Files Accessed")
    for f in result.sensitive_files_accessed:
        lines.append(f"- **{f}**")
    if not result.sensitive_files_accessed:
        lines.append("No sensitive files accessed.")
    lines.append("")

    lines.append("## Processes Launched")
    for p in result.processes_launched:
        lines.append(f"- {p}")
    if not result.processes_launched:
        lines.append("No suspicious processes launched.")
    lines.append("")

    lines.append("## External Connections (strace)")
    for c in result.external_connections:
        lines.append(f"- {c}")
    if not result.external_connections:
        lines.append("No external connections detected.")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by MCP Shield v3 — GaboLabs*")
    return "\n".join(lines)
