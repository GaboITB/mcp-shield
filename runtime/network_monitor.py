"""Runtime network monitor for MCP processes.

Parses netstat output (Windows) to detect suspicious outbound connections
from known MCP processes. Alerts are logged to a JSONL file and can
optionally produce Finding objects for integration with the audit engine.

Ported from mcp_network_monitor.py (v1) with fixes:
- Proper private IP detection via ipaddress module (fixes 172.x false negatives)
- JSONL alert log format
- Configurable known ports / processes
- Deduplication in watch mode
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent.parent.parent  # …/security/
SAFE_URLS_FILE = SCRIPT_DIR / "known_safe_urls.json"

DEFAULT_LOG_DIR = Path.home() / ".config" / "mcp-shield" / "logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "mcp_network.jsonl"

DEFAULT_KNOWN_PORTS: set[int] = {
    9222,  # Chrome DevTools CDP (standard)
}

DEFAULT_KNOWN_PROCESSES: set[str] = {
    "node",
    "npx",
    "python",
    "python3",
    "py",
}

# ---------------------------------------------------------------------------
# Safe domain loader
# ---------------------------------------------------------------------------


def load_safe_domains(path: Path | None = None) -> set[str]:
    """Load whitelisted domains from the known_safe_urls.json file."""
    path = path or SAFE_URLS_FILE
    domains: set[str] = set()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            domains.update(data.get("domains", {}).keys())
        except (json.JSONDecodeError, OSError):
            pass
    return domains


# ---------------------------------------------------------------------------
# Network connection parsing
# ---------------------------------------------------------------------------


def get_network_connections() -> list[dict[str, Any]]:
    """Parse active TCP connections from ``netstat -nob`` (Windows).

    Returns a list of dicts with keys:
        local_addr, local_port, remote_addr, remote_port, state, process
    """
    connections: list[dict[str, Any]] = []
    try:
        result = subprocess.run(
            ["netstat", "-nob"],
            capture_output=True,
            timeout=15,
        )
        output = result.stdout.decode("utf-8", errors="ignore")

        current_process: str = "unknown"
        for line in output.splitlines():
            line = line.strip()

            # Process name lines produced by netstat -b on Windows
            if line.startswith("[") and line.endswith("]"):
                current_process = line[1:-1].lower()
                continue

            match = re.match(r"TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\w+)", line)
            if match:
                connections.append(
                    {
                        "local_addr": match.group(1),
                        "local_port": int(match.group(2)),
                        "remote_addr": match.group(3),
                        "remote_port": int(match.group(4)),
                        "state": match.group(5),
                        "process": current_process,
                    }
                )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        print(f"[!] netstat error: {exc}", file=sys.stderr)

    return connections


# ---------------------------------------------------------------------------
# Private IP helper
# ---------------------------------------------------------------------------


def _is_private_ip(addr: str) -> bool:
    """Return True if *addr* is a private / reserved IP (RFC 1918, link-local, loopback, etc.).

    Uses ``ipaddress.ip_address().is_private`` which correctly handles
    all reserved ranges including 172.16.0.0/12.
    """
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Connection checker
# ---------------------------------------------------------------------------


def check_mcp_connections(
    known_ports: set[int] | None = None,
    known_processes: set[str] | None = None,
    safe_domains: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect suspicious outbound connections from MCP processes.

    Parameters
    ----------
    known_ports:
        Ports that are expected on the LAN (connections to private IPs on
        these ports are silently ignored).
    known_processes:
        Process-name substrings that identify MCP server processes.
    safe_domains:
        Domain whitelist (currently informational — netstat provides IPs,
        not domain names, so this is reserved for future reverse-DNS).

    Returns
    -------
    list[dict]
        Each dict has: timestamp, process, remote, state, suspicious.
    """
    ports = known_ports if known_ports is not None else DEFAULT_KNOWN_PORTS
    procs = known_processes if known_processes is not None else DEFAULT_KNOWN_PROCESSES
    if safe_domains is None:
        safe_domains = load_safe_domains()

    alerts: list[dict[str, Any]] = []
    connections = get_network_connections()

    for conn in connections:
        proc = conn["process"]

        # Only inspect known MCP processes
        if not any(known in proc for known in procs):
            continue

        remote = conn["remote_addr"]
        port = conn["remote_port"]

        # Skip loopback
        if remote in ("127.0.0.1", "::1", "0.0.0.0"):
            continue

        is_lan = _is_private_ip(remote)

        # Allow known MCP ports on the LAN
        if is_lan and port in ports:
            continue

        # Flag any ESTABLISHED connection to a non-private IP
        if not is_lan and conn["state"] == "ESTABLISHED":
            alerts.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "process": proc,
                    "remote": f"{remote}:{port}",
                    "state": conn["state"],
                    "suspicious": True,
                }
            )

    return alerts


# ---------------------------------------------------------------------------
# Alert logging (JSONL)
# ---------------------------------------------------------------------------


def log_alerts(
    alerts: list[dict[str, Any]],
    log_file: Path | None = None,
) -> None:
    """Append alerts to a JSONL log file and print to stderr."""
    if not alerts:
        return

    log_path = log_file or DEFAULT_LOG_FILE
    log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "a", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
            print(
                f"[!] MCP ALERT: {alert['process']} -> {alert['remote']}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Watch (continuous monitoring) mode
# ---------------------------------------------------------------------------


def watch_mode(
    interval: int = 30,
    known_ports: set[int] | None = None,
    known_processes: set[str] | None = None,
    log_file: Path | None = None,
) -> None:
    """Continuously monitor MCP network connections.

    Deduplicates alerts so the same (process, remote) pair is only
    reported once per session.  Runs until interrupted with Ctrl-C.
    """
    print(f"[*] MCP Network Monitor — polling every {interval}s")
    print(f"[*] Log: {log_file or DEFAULT_LOG_FILE}")

    seen: set[str] = set()

    try:
        while True:
            alerts = check_mcp_connections(known_ports, known_processes)
            new_alerts = [
                a for a in alerts if f"{a['process']}:{a['remote']}" not in seen
            ]
            for a in new_alerts:
                seen.add(f"{a['process']}:{a['remote']}")

            if new_alerts:
                log_alerts(new_alerts, log_file)
            else:
                now = datetime.now().strftime("%H:%M:%S")
                print(
                    f"  [{now}] OK — no suspicious connections",
                    file=sys.stderr,
                )

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped.")


# ---------------------------------------------------------------------------
# Finding conversion (for audit engine integration)
# ---------------------------------------------------------------------------


def alerts_to_findings(alerts: list[dict[str, Any]]) -> list[Finding]:
    """Convert raw alert dicts to v2 Finding objects."""
    findings: list[Finding] = []
    for alert in alerts:
        findings.append(
            Finding(
                rule_id="runtime_suspicious_connection",
                severity=Severity.HIGH,
                surface=Surface.RUNTIME_DELTA,
                title=f"Suspicious outbound connection from {alert['process']}",
                evidence=alert["remote"],
                location=alert["process"],
                detail=f"State: {alert['state']} at {alert['timestamp']}",
            )
        )
    return findings
