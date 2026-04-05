// DAMN VULNERABLE MCP #02 — Eval / Dynamic Code Execution
// INTENTIONALLY VULNERABLE — for security scanner testing only.
// Expected: eval_exec_dynamic (CRITICAL), eval_exec_static
// DO NOT use in production. DO NOT run this server.
// This is a SECURITY TEST TARGET for MCP Shield scanner validation.

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const vm = require("vm");

const server = new Server({ name: "vuln-eval-mcp", version: "1.0.0" }, {
  capabilities: { tools: {} }
});

server.setRequestHandler("tools/call", async (request) => {
  const args = request.params.arguments;

  // VULN 1: Direct eval with user input (CRITICAL)
  if (request.params.name === "evaluate") {
    const code = args.expression;
    // Security scanner target: direct eval
    const result = eval(code);
    return { content: [{ type: "text", text: String(result) }] };
  }

  // VULN 2: Indirect eval — bypasses strict mode
  if (request.params.name === "evaluate_global") {
    const code = args.expression;
    const result = (0, eval)(code);
    return { content: [{ type: "text", text: String(result) }] };
  }

  // VULN 3: Function constructor
  if (request.params.name === "make_function") {
    const body = args.function_body;
    const fn = Function("input", body);
    return { content: [{ type: "text", text: String(fn(args.input)) }] };
  }

  // VULN 4: Constructor chain escape
  if (request.params.name === "sandbox_run") {
    const code = args.code;
    const result = [].constructor.constructor("return " + code)();
    return { content: [{ type: "text", text: String(result) }] };
  }

  // VULN 5: vm.runInNewContext (escapable sandbox)
  if (request.params.name === "safe_eval") {
    const code = args.code;
    const sandbox = { result: null };
    vm.runInNewContext(`result = ${code}`, sandbox);
    return { content: [{ type: "text", text: String(sandbox.result) }] };
  }

  // VULN 6: Dynamic import with user path
  if (request.params.name === "load_plugin") {
    const modulePath = args.module;
    const mod = await import(modulePath);
    return { content: [{ type: "text", text: "Plugin loaded" }] };
  }

  // VULN 7: setTimeout with string (implicit eval)
  if (request.params.name === "delayed_run") {
    const code = args.code;
    setTimeout("console.log(" + code + ")", 1000);
    return { content: [{ type: "text", text: "Scheduled" }] };
  }
});

server.setRequestHandler("tools/list", async () => ({
  tools: [
    { name: "evaluate", description: "Evaluate an expression", inputSchema: { type: "object", properties: { expression: { type: "string" } }, required: ["expression"] } },
    { name: "evaluate_global", description: "Evaluate in global scope", inputSchema: { type: "object", properties: { expression: { type: "string" } }, required: ["expression"] } },
    { name: "make_function", description: "Create and run a function", inputSchema: { type: "object", properties: { function_body: { type: "string" }, input: { type: "string" } }, required: ["function_body"] } },
    { name: "sandbox_run", description: "Run code in sandbox", inputSchema: { type: "object", properties: { code: { type: "string" } }, required: ["code"] } },
    { name: "safe_eval", description: "Safely evaluate code", inputSchema: { type: "object", properties: { code: { type: "string" } }, required: ["code"] } },
    { name: "load_plugin", description: "Load a plugin module", inputSchema: { type: "object", properties: { module: { type: "string" } }, required: ["module"] } },
    { name: "delayed_run", description: "Run code after delay", inputSchema: { type: "object", properties: { code: { type: "string" } }, required: ["code"] } },
  ]
}));
