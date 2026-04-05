// DAMN VULNERABLE MCP #01 — Shell Injection
// INTENTIONALLY VULNERABLE — for security scanner testing only.
// Expected detections: shell_injection (CRITICAL), shell_hardcoded
//
// This file contains INTENTIONAL vulnerabilities for testing MCP Shield.
// DO NOT use this code in production. DO NOT run this server.

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");

// NOTE: These require() calls are detection targets for the scanner.
// They demonstrate patterns that MCP Shield should catch.
const child_process = require("child_process");
const { spawn: spawnProc, fork: forkProc } = require("child_process");

const server = new Server({ name: "vuln-shell-mcp", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

// VULN 1: execSync with template literal (CRITICAL — shell injection)
server.setRequestHandler("tools/call", async (request) => {
  if (request.params.name === "run_command") {
    const userCmd = request.params.arguments.command;
    const result = child_process.execSync(`${userCmd} 2>&1`);
    return { content: [{ type: "text", text: result.toString() }] };
  }

  // VULN 2: spawn with dynamic arguments
  if (request.params.name === "git_clone") {
    const repo = request.params.arguments.repository;
    child_process.spawn("git", ["clone", `${repo}`]);
    return { content: [{ type: "text", text: "Cloning..." }] };
  }

  // VULN 3: destructured spawn with user input
  if (request.params.name === "search_files") {
    const pattern = request.params.arguments.pattern;
    spawnProc("grep", ["-r", pattern + " /"]);
    return { content: [{ type: "text", text: "Searching..." }] };
  }

  // VULN 4: fork with user-controlled module path
  if (request.params.name === "run_worker") {
    const script = request.params.arguments.script_path;
    forkProc(script);
    return { content: [{ type: "text", text: "Worker started" }] };
  }

  // VULN 5: shell: true in spawn options
  if (request.params.name === "list_files") {
    const dir = request.params.arguments.directory;
    child_process.spawn("ls", ["-la", dir], { shell: true });
    return { content: [{ type: "text", text: "Listed" }] };
  }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [
    { name: "run_command", description: "Run a shell command", inputSchema: { type: "object", properties: { command: { type: "string" } }, required: ["command"] } },
    { name: "git_clone", description: "Clone a git repository", inputSchema: { type: "object", properties: { repository: { type: "string" } }, required: ["repository"] } },
    { name: "search_files", description: "Search for files", inputSchema: { type: "object", properties: { pattern: { type: "string" } }, required: ["pattern"] } },
    { name: "run_worker", description: "Run a worker script", inputSchema: { type: "object", properties: { script_path: { type: "string" } }, required: ["script_path"] } },
    { name: "list_files", description: "List files in directory", inputSchema: { type: "object", properties: { directory: { type: "string" } }, required: ["directory"] } },
  ]
}));

const transport = new StdioServerTransport();
server.connect(transport);
