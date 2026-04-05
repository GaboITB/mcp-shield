// DAMN VULNERABLE MCP #09 — Deno/Bun Runtime Vulnerabilities
// INTENTIONALLY VULNERABLE — security scanner test target.
// Expected: shell_injection, ssrf, path_traversal, eval_exec
// Tests detection of Deno and Bun-specific APIs.
// DO NOT use in production.

// === DENO VULNERABILITIES ===

// VULN 1: Deno.Command with user input (shell injection)
async function runDenoCommand(userCmd: string) {
  const cmd = new Deno.Command(`${userCmd}`, { args: ["-la"] });
  const output = await cmd.output();
  return new TextDecoder().decode(output.stdout);
}

// VULN 2: Deno.run (deprecated but still works)
async function runLegacy(cmd: string) {
  const proc = Deno.run({ cmd: [`${cmd}`] });
  await proc.status();
}

// VULN 3: Deno.readFile with user path (path traversal)
async function readUserFile(ctx: any) {
  const data = await Deno.readFile(ctx.params.path);
  return new TextDecoder().decode(data);
}

// VULN 4: Deno.open with user input
async function openFile(req: any) {
  const file = await Deno.open(req.params.file, { read: true });
  return file;
}

// VULN 5: Deno.writeFile with user path
async function writeUserFile(ctx: any) {
  await Deno.writeTextFile(ctx.params.path, ctx.params.content);
}

// VULN 6: Deno.fetch with env URL (SSRF)
async function fetchConfig() {
  const resp = await Deno.fetch(Deno.env.get("API_URL") + "/config");
  return await resp.json();
}

// VULN 7: Deno.connect with dynamic host (SSRF)
async function connectToHost(host: string) {
  const conn = await Deno.connect({ hostname: `${host}`, port: 80 });
  return conn;
}

// === BUN VULNERABILITIES ===

// VULN 8: Bun.spawn with user input (shell injection)
function bunExec(cmd: string) {
  const proc = Bun.spawn([cmd, "--version"]);
  return proc;
}

// VULN 9: Bun.spawnSync with dynamic args
function bunExecSync(args: string[]) {
  const result = Bun.spawnSync(["node", ...args]);
  return result;
}

// VULN 10: Bun.file with user path (path traversal)
function bunReadFile(req: any) {
  const file = Bun.file(req.params.path);
  return file.text();
}

// VULN 11: Bun.write with user path
async function bunWriteFile(req: any) {
  await Bun.write(req.body.path, req.body.content);
}

// VULN 12: Bun.fetch with dynamic URL (SSRF)
async function bunFetch(endpoint: string) {
  const resp = await Bun.fetch(`${endpoint}/api/data`);
  return await resp.json();
}

// Server setup
export default {
  tools: [
    { name: "run_command", description: "Run a system command" },
    { name: "read_file", description: "Read a file from disk" },
    { name: "fetch_url", description: "Fetch data from URL" },
    { name: "write_file", description: "Write content to file" },
  ]
};
