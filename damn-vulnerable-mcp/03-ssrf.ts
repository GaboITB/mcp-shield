// DAMN VULNERABLE MCP #03 — SSRF (Server-Side Request Forgery)
// INTENTIONALLY VULNERABLE — security scanner test target.
// Expected: ssrf_dynamic_url (HIGH), ssrf_env_url (MEDIUM)
// DO NOT use in production. DO NOT run this server.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import net from "net";
import dns from "dns";

const server = new Server({ name: "vuln-ssrf-mcp", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/call", async (request: any) => {
  const args = request.params.arguments;

  // VULN 1: fetch() with user-controlled URL (HIGH)
  if (request.params.name === "proxy_request") {
    const resp = await fetch(`${req.params.target_url}/api/data`);
    return { content: [{ type: "text", text: await resp.text() }] };
  }

  // VULN 2: fetch() with env-sourced URL (MEDIUM)
  if (request.params.name === "get_config") {
    const resp = await fetch(process.env.CONFIG_URL + "/settings");
    return { content: [{ type: "text", text: await resp.text() }] };
  }

  // VULN 3: net.connect with dynamic host
  if (request.params.name === "check_port") {
    const host = args.hostname;
    const port = args.port;
    const socket = net.connect({ host: `${host}`, port: port });
    return { content: [{ type: "text", text: "Connected" }] };
  }

  // VULN 4: DNS resolution with user input
  if (request.params.name === "resolve_host") {
    const hostname = args.hostname;
    dns.resolve(process.env.DNS_SERVER + hostname, (err, addresses) => {});
    return { content: [{ type: "text", text: "Resolving..." }] };
  }

  // VULN 5: WebSocket with dynamic URL
  if (request.params.name === "ws_connect") {
    const endpoint = args.endpoint;
    const ws = new WebSocket(`ws://${endpoint}/stream`);
    return { content: [{ type: "text", text: "WebSocket connected" }] };
  }

  // VULN 6: Axios with config-sourced URL
  if (request.params.name === "fetch_data") {
    const axios = require("axios");
    const resp = await axios.get(config.apiBaseUrl + "/data");
    return { content: [{ type: "text", text: resp.data }] };
  }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [
    { name: "proxy_request", description: "Proxy an HTTP request", inputSchema: { type: "object", properties: { target_url: { type: "string" } }, required: ["target_url"] } },
    { name: "get_config", description: "Get remote config", inputSchema: { type: "object", properties: {} } },
    { name: "check_port", description: "Check if a port is open", inputSchema: { type: "object", properties: { hostname: { type: "string" }, port: { type: "number" } }, required: ["hostname", "port"] } },
    { name: "resolve_host", description: "Resolve a hostname", inputSchema: { type: "object", properties: { hostname: { type: "string" } }, required: ["hostname"] } },
    { name: "ws_connect", description: "Connect via WebSocket", inputSchema: { type: "object", properties: { endpoint: { type: "string" } }, required: ["endpoint"] } },
    { name: "fetch_data", description: "Fetch data from API", inputSchema: { type: "object", properties: {} } },
  ]
}));
