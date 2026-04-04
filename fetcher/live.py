"""Live MCP Fetcher — MCP Shield v2.

Connects to an MCP server via stdio (subprocess), performs the JSON-RPC
handshake (initialize + tools/list), and returns the tool list.

Uses a randomized clientInfo name to avoid detection by servers that
alter behavior when audited.
"""

from __future__ import annotations

import json
import logging
import random
import string
import subprocess
import sys
from typing import Any

from mcp_shield.core.models import (
    PromptInfo,
    ResourceInfo,
    ServerCapabilities,
    ToolInfo,
)

logger = logging.getLogger("mcp_shield.fetcher.live")

TIMEOUT_SECONDS = 30

# Pool of innocuous client names to randomize identity
_CLIENT_NAME_POOL: list[str] = [
    "vscode-mcp-client",
    "cursor-ide",
    "copilot-chat",
    "windsurf-editor",
    "zed-mcp-bridge",
    "jetbrains-mcp",
    "continue-dev",
    "cline-extension",
]


def _random_client_info() -> dict[str, str]:
    """Generate a plausible-looking randomized clientInfo."""
    name = random.choice(_CLIENT_NAME_POOL)
    major = random.randint(1, 5)
    minor = random.randint(0, 12)
    patch = random.randint(0, 99)
    return {"name": name, "version": f"{major}.{minor}.{patch}"}


def _make_jsonrpc(method: str, params: dict[str, Any], req_id: int) -> str:
    """Build a JSON-RPC 2.0 request string (with trailing newline)."""
    msg = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
        "params": params,
    }
    return json.dumps(msg, ensure_ascii=False) + "\n"


def _read_response(proc: subprocess.Popen, req_id: int) -> dict[str, Any] | None:
    """Read lines from the process stdout until we get a JSON-RPC response
    matching *req_id*. Skips notifications (no 'id' field)."""
    assert proc.stdout is not None
    while True:
        line = proc.stdout.readline()
        if not line:
            logger.warning("Server closed stdout before responding (id=%d)", req_id)
            return None

        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            # Some servers emit non-JSON logging — skip
            continue

        # Skip notifications (no id)
        if "id" not in msg:
            continue

        if msg.get("id") == req_id:
            return msg

    return None  # unreachable but satisfies type checker


def _parse_tool(raw: dict[str, Any]) -> ToolInfo:
    """Convert a raw MCP tool dict to ToolInfo."""
    return ToolInfo(
        name=raw.get("name", ""),
        description=raw.get("description", ""),
        input_schema=raw.get("inputSchema", {}),
        output_schema=raw.get("outputSchema", {}),
        annotations=raw.get("annotations", {}),
        source="live",
    )


def fetch_live_tools(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> list[ToolInfo] | None:
    """Connect to an MCP server via stdio and fetch its tool list.

    Args:
        command: The executable to run (e.g., "node", "npx", "python").
        args: Command-line arguments for the server process.
        env: Optional environment variables (merged with current env).

    Returns:
        List of ToolInfo from the server, or None on failure.
    """
    import os

    merged_env = {**os.environ, **(env or {})}
    cmd = [command] + (args or [])

    logger.info("Starting MCP server: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=merged_env,
            bufsize=1,  # line-buffered
        )
    except FileNotFoundError:
        logger.error("Command not found: %s", command)
        return None
    except OSError as exc:
        logger.error("Failed to start server process: %s", exc)
        return None

    try:
        return _do_handshake(proc)
    except Exception:
        logger.exception("Unexpected error during MCP handshake")
        return None
    finally:
        _cleanup(proc)


def _do_handshake(proc: subprocess.Popen) -> list[ToolInfo] | None:
    """Perform the JSON-RPC initialize + tools/list exchange."""
    assert proc.stdin is not None

    client_info = _random_client_info()

    # Step 1: initialize
    init_req = _make_jsonrpc(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": client_info,
        },
        req_id=1,
    )
    proc.stdin.write(init_req)
    proc.stdin.flush()

    init_resp = _read_response(proc, req_id=1)
    if init_resp is None:
        logger.error("No response to initialize request")
        return None

    if "error" in init_resp:
        logger.error("Initialize error: %s", init_resp["error"])
        return None

    # Step 2: send initialized notification (no id)
    notif = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
            ensure_ascii=False,
        )
        + "\n"
    )
    proc.stdin.write(notif)
    proc.stdin.flush()

    # Step 3: tools/list
    tools_req = _make_jsonrpc("tools/list", {}, req_id=2)
    proc.stdin.write(tools_req)
    proc.stdin.flush()

    tools_resp = _read_response(proc, req_id=2)
    if tools_resp is None:
        logger.error("No response to tools/list request")
        return None

    if "error" in tools_resp:
        logger.error("tools/list error: %s", tools_resp["error"])
        return None

    result = tools_resp.get("result", {})
    raw_tools = result.get("tools", [])

    tools = [_parse_tool(t) for t in raw_tools]
    logger.info(
        "Fetched %d tools from server (clientInfo=%s)",
        len(tools),
        client_info["name"],
    )
    return tools


def _cleanup(proc: subprocess.Popen) -> None:
    """Terminate the server process gracefully."""
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except OSError:
        pass  # process may have already exited


def fetch_live_resources(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> list[ResourceInfo] | None:
    """Fetch MCP resources from a live server.

    Stub — will be implemented when resource auditing is needed.
    Follows the same pattern as fetch_live_tools but calls
    resources/list instead.
    """
    # TODO: implement resources/list JSON-RPC call
    logger.info("fetch_live_resources: not yet implemented")
    return None


def fetch_live_prompts(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> list[PromptInfo] | None:
    """Fetch MCP prompts from a live server.

    Stub — will be implemented when prompt auditing is needed.
    Follows the same pattern as fetch_live_tools but calls
    prompts/list instead.
    """
    # TODO: implement prompts/list JSON-RPC call
    logger.info("fetch_live_prompts: not yet implemented")
    return None
