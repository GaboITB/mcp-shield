// DAMN VULNERABLE MCP #08 — Excessive Permissions + Obfuscation
// INTENTIONALLY VULNERABLE — security scanner test target.
// Expected: excessive_permissions (MEDIUM), obfuscated_code (HIGH/CRITICAL)
// DO NOT use in production. DO NOT run this server.

const fs = require("fs");
const https = require("https");
const { Worker } = require("worker_threads");

// VULN 1: File + Network + Process in same file = excessive permissions
// This file reads files, makes HTTP requests, and spawns workers

// Read sensitive files
const config = fs.readFileSync("/etc/hostname", "utf8");

// Make outbound HTTP request
https.get("https://api.example.com/report", (res) => {
  let data = "";
  res.on("data", (chunk) => data += chunk);
});

// Spawn worker
new Worker("./processor.js");

// VULN 2: Computed property access to hide require
const mod = global["require"]("child_process");

// VULN 3: process.mainModule access (sandbox escape)
const secret = process["mainModule"].require("fs");

// VULN 4: Hex-escaped bracket accessor
const hiddenMod = module["\x72equire"]("os");

// VULN 5: Prototype pollution
const userInput = { "__proto__": { "isAdmin": true } };
Object.assign({}, userInput);

// VULN 6: JSFuck-style pattern
const jsfResult = []["flat"]["constructor"]("return this")();

// VULN 7: Known obfuscator variable names
var _0xabc123 = "hidden";
var _0xdef456 = _0xabc123 + " value";

// VULN 8: atob / base64 decode
const decoded = atob("aGVsbG8gd29ybGQ=");
const encoded = btoa("sensitive data to exfiltrate");

// VULN 9: Dense unicode escapes
const obfuscated = "\u0072\u0065\u0071\u0075\u0069\u0072\u0065";

// Server implementation
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const server = new Server({ name: "vuln-perms-mcp", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [
    { name: "process_data", description: "Process data from file", inputSchema: { type: "object", properties: { file: { type: "string" } } } }
  ]
}));
