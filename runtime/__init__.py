"""Runtime analysis modules for MCP Shield v2.

Submodules:
    network_monitor — live network connection monitoring
    sandbox         — Docker-based isolated MCP execution
    reaudit         — periodic re-audit of installed MCPs
"""

from mcp_shield.runtime.network_monitor import (
    alerts_to_findings,
    check_mcp_connections,
    get_network_connections,
    load_safe_domains,
    log_alerts,
    watch_mode,
)
from mcp_shield.runtime.reaudit import (
    generate_reaudit_report,
    get_installed_mcps,
    reaudit_all,
    reaudit_mcp,
    results_to_findings,
)
from mcp_shield.runtime.sandbox import SandboxResult, run_sandbox

__all__ = [
    # network_monitor
    "get_network_connections",
    "check_mcp_connections",
    "watch_mode",
    "load_safe_domains",
    "log_alerts",
    "alerts_to_findings",
    # sandbox
    "SandboxResult",
    "run_sandbox",
    # reaudit
    "get_installed_mcps",
    "reaudit_mcp",
    "reaudit_all",
    "generate_reaudit_report",
    "results_to_findings",
]
