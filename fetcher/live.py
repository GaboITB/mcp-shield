"""Live MCP Fetcher — MCP Shield v3.

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


_MAX_LINE_BYTES = 1_048_576  # 1 MB — prevents DoS via infinite-length line
_MAX_RESPONSE_LINES = 10_000  # bail out after this many lines without a match
_MAX_JSON_SIZE = 5_242_880  # 5 MB — reject absurdly large JSON responses


def _read_response(proc: subprocess.Popen, req_id: int) -> dict[str, Any] | None:
    """Read lines from the process stdout until we get a JSON-RPC response
    matching *req_id*. Skips notifications (no 'id' field).

    Safety limits:
    - Each readline() is capped at 1 MB.
    - Overall loop is bounded by TIMEOUT_SECONDS and _MAX_RESPONSE_LINES.
    """
    import time

    assert proc.stdout is not None
    deadline = time.monotonic() + TIMEOUT_SECONDS
    lines_read = 0

    while time.monotonic() < deadline and lines_read < _MAX_RESPONSE_LINES:
        line = proc.stdout.readline(_MAX_LINE_BYTES)
        if not line:
            logger.warning("Server closed stdout before responding (id=%d)", req_id)
            return None

        lines_read += 1
        line = line.strip()
        if not line:
            continue

        if len(line) > _MAX_JSON_SIZE:
            logger.warning("Skipping oversized JSON line (%d bytes)", len(line))
            continue

        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            # Some servers emit non-JSON logging — skip
            continue

        if not isinstance(msg, dict):
            continue

        # Skip notifications (no id)
        if "id" not in msg:
            continue

        if msg.get("id") == req_id:
            return msg

    logger.warning("Timeout or line limit reached waiting for response (id=%d)", req_id)
    return None


def _parse_tool(raw: Any) -> ToolInfo | None:
    """Convert a raw MCP tool dict to ToolInfo.

    Returns None if raw is not a valid dict with a string name.
    """
    if not isinstance(raw, dict):
        logger.warning("Skipping non-dict tool entry: %s", type(raw).__name__)
        return None
    name = raw.get("name", "")
    if not isinstance(name, str) or not name:
        logger.warning("Skipping tool with invalid name: %r", name)
        return None
    desc = raw.get("description", "")
    if not isinstance(desc, str):
        desc = str(desc)[:500]
    input_schema = raw.get("inputSchema", {})
    if not isinstance(input_schema, dict):
        input_schema = {}
    output_schema = raw.get("outputSchema", {})
    if not isinstance(output_schema, dict):
        output_schema = {}
    annotations = raw.get("annotations", {})
    if not isinstance(annotations, dict):
        annotations = {}
    return ToolInfo(
        name=name,
        description=desc[:2000],
        input_schema=input_schema,
        output_schema=output_schema,
        annotations=annotations,
        source="live",
    )


def fetch_live_tools(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    client_info: dict[str, str] | None = None,
) -> list[ToolInfo] | None:
    """Connect to an MCP server via stdio and fetch its tool list.

    Args:
        command: The executable to run (e.g., "node", "npx", "python").
        args: Command-line arguments for the server process.
        env: Optional environment variables (merged with current env).
        client_info: Optional clientInfo dict {"name": ..., "version": ...}.
            If None, a random identity from the pool is used.

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
        return _do_handshake(proc, client_info=client_info)
    except Exception:
        logger.exception("Unexpected error during MCP handshake")
        return None
    finally:
        _cleanup(proc)


def _do_handshake(
    proc: subprocess.Popen,
    client_info: dict[str, str] | None = None,
) -> list[ToolInfo] | None:
    """Perform the JSON-RPC initialize + tools/list exchange."""
    assert proc.stdin is not None

    if client_info is None:
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
    if not isinstance(result, dict):
        logger.error("tools/list result is not a dict: %s", type(result).__name__)
        return None
    raw_tools = result.get("tools", [])
    if not isinstance(raw_tools, list):
        logger.error("tools list is not an array: %s", type(raw_tools).__name__)
        return None

    tools = [t for raw in raw_tools if (t := _parse_tool(raw)) is not None]
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


def _parse_resource(raw: Any) -> ResourceInfo | None:
    """Convert a raw MCP resource dict to ResourceInfo."""
    if not isinstance(raw, dict):
        logger.warning("Skipping non-dict resource entry: %s", type(raw).__name__)
        return None
    uri = raw.get("uri", "")
    if not isinstance(uri, str) or not uri:
        logger.warning("Skipping resource with invalid uri: %r", uri)
        return None
    name = raw.get("name", "")
    if not isinstance(name, str):
        name = str(name)[:500]
    desc = raw.get("description", "")
    if not isinstance(desc, str):
        desc = str(desc)[:500]
    mime_type = raw.get("mimeType", "")
    if not isinstance(mime_type, str):
        mime_type = ""
    return ResourceInfo(
        uri=uri,
        name=name[:500],
        description=desc[:2000],
        mime_type=mime_type[:200],
    )


def _parse_prompt(raw: Any) -> PromptInfo | None:
    """Convert a raw MCP prompt dict to PromptInfo."""
    if not isinstance(raw, dict):
        logger.warning("Skipping non-dict prompt entry: %s", type(raw).__name__)
        return None
    name = raw.get("name", "")
    if not isinstance(name, str) or not name:
        logger.warning("Skipping prompt with invalid name: %r", name)
        return None
    desc = raw.get("description", "")
    if not isinstance(desc, str):
        desc = str(desc)[:500]
    arguments = raw.get("arguments", [])
    if not isinstance(arguments, list):
        arguments = []
    # Validate each argument is a dict
    safe_args = [a for a in arguments if isinstance(a, dict)]
    return PromptInfo(
        name=name,
        description=desc[:2000],
        arguments=safe_args,
    )


def fetch_live_all(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    client_info: dict[str, str] | None = None,
) -> (
    tuple[
        list[ToolInfo] | None,
        list[ResourceInfo] | None,
        list[PromptInfo] | None,
        ServerCapabilities | None,
    ]
    | None
):
    """Connect to an MCP server and fetch tools, resources, prompts, and capabilities.

    Returns a tuple (tools, resources, prompts, capabilities) or None on failure.
    Only fetches resources/prompts if the server declares those capabilities.
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
            bufsize=1,
        )
    except FileNotFoundError:
        logger.error("Command not found: %s", command)
        return None
    except OSError as exc:
        logger.error("Failed to start server process: %s", exc)
        return None

    try:
        return _do_full_handshake(proc, client_info=client_info)
    except Exception:
        logger.exception("Unexpected error during MCP handshake")
        return None
    finally:
        _cleanup(proc)


def _do_full_handshake(
    proc: subprocess.Popen,
    client_info: dict[str, str] | None = None,
) -> (
    tuple[
        list[ToolInfo] | None,
        list[ResourceInfo] | None,
        list[PromptInfo] | None,
        ServerCapabilities | None,
    ]
    | None
):
    """Full JSON-RPC handshake: initialize + tools/list + resources/list + prompts/list."""
    assert proc.stdin is not None

    if client_info is None:
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

    # Parse server capabilities
    server_caps_raw = init_resp.get("result", {}).get("capabilities", {})
    capabilities = ServerCapabilities(
        tools="tools" in server_caps_raw,
        resources="resources" in server_caps_raw,
        prompts="prompts" in server_caps_raw,
        sampling="sampling" in server_caps_raw,
        logging="logging" in server_caps_raw,
    )

    # Step 2: send initialized notification
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

    req_id = 2

    # Step 3: tools/list
    tools: list[ToolInfo] | None = None
    tools_req = _make_jsonrpc("tools/list", {}, req_id=req_id)
    proc.stdin.write(tools_req)
    proc.stdin.flush()

    tools_resp = _read_response(proc, req_id=req_id)
    if tools_resp and "error" not in tools_resp:
        result = tools_resp.get("result", {})
        if isinstance(result, dict):
            raw_tools = result.get("tools", [])
            if isinstance(raw_tools, list):
                tools = [t for raw in raw_tools if (t := _parse_tool(raw)) is not None]
    req_id += 1

    # Step 4: resources/list (only if server declares resources capability)
    resources: list[ResourceInfo] | None = None
    if capabilities.resources:
        res_req = _make_jsonrpc("resources/list", {}, req_id=req_id)
        proc.stdin.write(res_req)
        proc.stdin.flush()

        res_resp = _read_response(proc, req_id=req_id)
        if res_resp and "error" not in res_resp:
            result = res_resp.get("result", {})
            if isinstance(result, dict):
                raw_resources = result.get("resources", [])
                if isinstance(raw_resources, list):
                    resources = [
                        r
                        for raw in raw_resources
                        if (r := _parse_resource(raw)) is not None
                    ]
        req_id += 1

    # Step 5: prompts/list (only if server declares prompts capability)
    prompts: list[PromptInfo] | None = None
    if capabilities.prompts:
        prompts_req = _make_jsonrpc("prompts/list", {}, req_id=req_id)
        proc.stdin.write(prompts_req)
        proc.stdin.flush()

        prompts_resp = _read_response(proc, req_id=req_id)
        if prompts_resp and "error" not in prompts_resp:
            result = prompts_resp.get("result", {})
            if isinstance(result, dict):
                raw_prompts = result.get("prompts", [])
                if isinstance(raw_prompts, list):
                    prompts = [
                        p
                        for raw in raw_prompts
                        if (p := _parse_prompt(raw)) is not None
                    ]

    logger.info(
        "Fetched %d tools, %d resources, %d prompts (clientInfo=%s)",
        len(tools or []),
        len(resources or []),
        len(prompts or []),
        client_info["name"],
    )
    return tools, resources, prompts, capabilities


def fetch_live_resources(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> list[ResourceInfo] | None:
    """Fetch MCP resources from a live server via resources/list."""
    result = fetch_live_all(command, args, env)
    if result is None:
        return None
    return result[1]


def fetch_live_prompts(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> list[PromptInfo] | None:
    """Fetch MCP prompts from a live server via prompts/list."""
    result = fetch_live_all(command, args, env)
    if result is None:
        return None
    return result[2]
