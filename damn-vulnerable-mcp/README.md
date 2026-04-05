# damn-vulnerable-mcp

> 10 intentionally vulnerable MCP servers for testing security scanners.

This collection is a **test suite and educational resource** for [MCP Shield](https://github.com/GaboITB/mcp-shield). Each file is a minimal but realistic MCP server containing intentional vulnerabilities that MCP Shield should detect.

**DO NOT run these servers. DO NOT use this code in production. All credentials are fake.**

## The 10 Vulnerable MCPs

| # | File | Vulnerability Type | Surface | Key Findings |
|---|------|-------------------|---------|--------------|
| 01 | `01-shell-injection.js` | Command injection via child\_process | Code | shell\_injection, shell\_hardcoded |
| 02 | `02-eval-exec.js` | Dynamic code execution (eval, Function, vm) | Code | eval\_exec\_dynamic, eval\_exec\_static |
| 03 | `03-ssrf.ts` | Server-side request forgery (fetch, net, dns) | Code | ssrf\_dynamic\_url, ssrf\_env\_url |
| 04 | `04-secrets.py` | Hardcoded credentials (12 token types) | Code | secrets\_hardcoded, tls\_disabled |
| 05 | `05-path-traversal.js` | Directory traversal via fs operations | Code | path\_traversal |
| 06 | `06-postinstall-supply-chain/` | Supply chain attack + obfuscation | Code | postinstall\_script, obfuscated\_code |
| 07 | `07-prompt-injection.json` | Prompt injection + schema injection | Meta | prompt\_injection, schema\_injection |
| 08 | `08-permissions-excessive.js` | Excessive permissions + obfuscation | Code | excessive\_permissions, obfuscated\_code |
| 09 | `09-deno-bun-runtime.ts` | Deno + Bun runtime-specific vulns | Code | shell\_injection, path\_traversal, ssrf |
| 10 | `10-kitchen-sink.py` | Multiple vulnerability types combined | Code | shell\_injection, eval\_exec, ssrf, secrets |

## Validation

Run the validation script to verify MCP Shield catches all expected vulnerabilities:

```bash
cd mcp_shield/
python3 damn-vulnerable-mcp/validate.py
```

Expected: **11 passed, 0 failed, 100 total findings** across all 10 targets.

## Vulnerability Details

### 01 — Shell Injection (5 vectors)
Demonstrates child\_process methods with unsanitized user input: execSync with template literals, spawn with dynamic args, destructured imports, fork with user-controlled paths, and shell:true options.

### 02 — Eval / Dynamic Code Execution (7 vectors)
Direct eval, indirect eval (0,eval)(), Function constructor, constructor chain escape, vm.runInNewContext, dynamic import(), setTimeout with string.

### 03 — SSRF (6 vectors)
fetch with user URLs, env-sourced URLs, net.connect with dynamic host, dns.resolve, WebSocket, axios with config URLs.

### 04 — Hardcoded Secrets (12 types)
AWS keys, GitHub/GitLab/npm/Stripe/Slack/OpenAI tokens, JWTs, PEM keys, connection strings with passwords, TLS disabled, passwords in CLI arguments.

### 05 — Path Traversal (10 vectors)
fs.readFileSync, writeFile, open, stat, symlink, rename, copyFile, fs.promises, res.sendFile, path.join bypass.

### 06 — Supply Chain (postinstall + obfuscation)
Malicious npm scripts (postinstall/preinstall/prepare), String.fromCharCode, base64 Buffer.from, hex escapes, _0x obfuscator vars, packed functions, telemetry phone-home.

### 07 — Prompt Injection (metadata)
Hidden system instructions, HTML comment injection, zero-width chars in names, SQL injection in enums, image exfiltration via markdown, javascript: links, homoglyph spoofing.

### 08 — Excessive Permissions + Obfuscation
fs+net+proc in same file, global["require"] bypass, process["mainModule"] escape, hex-escaped brackets, prototype pollution, JSFuck, _0x vars, atob/btoa.

### 09 — Deno/Bun Runtime (12 vectors)
Deno.Command, Deno.run, Deno.readFile, Deno.open, Deno.fetch, Deno.connect + Bun.spawn, Bun.spawnSync, Bun.file, Bun.write, Bun.fetch.

### 10 — Kitchen Sink (combined)
Real-world Python MCP server combining subprocess shell=True, eval with user input, requests with user URL + TLS disabled, hardcoded secrets, open() with user paths, SQL multi-statement, sensitive file access.

## Contributing

1. Create a file with intentional, documented vulnerabilities
2. Add expected detections to `EXPECTED` in `validate.py`
3. Run `validate.py` to verify
4. Submit a PR

## License

MIT
