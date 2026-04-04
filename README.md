# MCP Shield v2

> Security audit framework for MCP (Model Context Protocol) servers.

MCP Shield scans MCP servers **before installation** to detect supply chain attacks, prompt injection, tool poisoning, and other threats specific to the AI agent ecosystem.

## Features

### 15 Security Detectors across 3 Surfaces

**Source Code Analysis** (6 detectors)
- `shell_injection` — `shell=True` with dynamic input, `os.system`
- `eval_exec` — Dynamic code evaluation with untrusted input
- `ssrf` — HTTP requests with dynamic URLs from env/config (12+ HTTP libraries)
- `secrets` — Hardcoded tokens, API keys, passwords, TLS disabled
- `path_traversal` — File operations with unsanitized user paths
- `permissions` — Excessive permissions, postinstall scripts, code obfuscation

**MCP Metadata Analysis** (6 detectors)
- `prompt_injection` — Hidden instructions in tool descriptions (18+ patterns)
- `unicode_invisible` — Zero-width characters, BOM, control chars in tool names
- `homoglyph_spoofing` — Cyrillic/Greek lookalikes substituted for Latin characters
- `schema_injection` — Malicious defaults, enum payloads in input schemas
- `markdown_injection` — `javascript:` links, image exfiltration, HTML injection
- `description_heuristic` — Oversized descriptions, imperative overload, empty descriptions

**Runtime Delta Analysis** (3 detectors)
- `tool_shadowing` — Tools that appear live but not in source code (dynamic injection)
- `param_divergence` — Schema/description changes between source and runtime (rug pull)
- `capability_drift` — Annotation changes, polymorphic server behavior

## Installation

No external dependencies required — stdlib only (Python 3.10+).

```bash
git clone https://github.com/GaboITB/mcp-shield.git
cd mcp-shield
```

## Usage

### Scan a MCP server before installation

```bash
# From GitHub
py -3 -m mcp_shield scan https://github.com/user/mcp-server

# From npm
py -3 -m mcp_shield scan @user/mcp-server --name my-mcp

# JSON output for CI/CD
py -3 -m mcp_shield scan https://github.com/user/repo --format json
```

### Fetch live tools and compare

```bash
py -3 -m mcp_shield live my-mcp
```

### Approve a scanned MCP

```bash
py -3 -m mcp_shield approve my-mcp
```

### View approved MCPs

```bash
py -3 -m mcp_shield report
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no critical or high findings |
| 1 | Warnings — high severity findings detected |
| 2 | Critical — critical findings or dangerous patterns |

## Design Philosophy

1. **Three detection surfaces** — Source code, MCP metadata, and runtime delta each have their own Protocol and detector implementations
2. **Zero dependencies** — stdlib only (`ast`, `re`, `argparse`, `dataclasses`, `json`)
3. **Plugin architecture** — Add a detector by creating one file implementing a Protocol
4. **CLI-first** — Not an MCP server (avoids circular trust). Hooks for runtime protection
5. **Approval workflow** — Backup settings.json before any modification, diff + confirm

## Threat Coverage

| Threat | Detected | Surface |
|--------|----------|---------|
| Command injection (shell=True) | Yes | Code |
| Prompt injection in tool descriptions | Yes | Meta |
| Tool name spoofing (homoglyphs) | Yes | Meta |
| Invisible Unicode in names | Yes | Meta |
| Rug pull (description change post-approval) | Yes | Delta |
| Dynamic tool injection | Yes | Delta |
| Supply chain (postinstall scripts) | Yes | Code |
| SSRF via env variables | Yes | Code |
| Hardcoded secrets/tokens | Yes | Code |
| Schema default payloads | Yes | Meta |
| TLS disabled | Yes | Code |
| Code obfuscation | Yes | Code |

## Architecture

Three Protocols, unified by the `Finding` dataclass:

- `SourceDetector.scan_file(path, content) -> list[Finding]`
- `MetadataDetector.scan_tool(name, desc, schema, annotations) -> list[Finding]`
- `RuntimeDetector.scan_delta(baseline, current) -> list[Finding]`

Adding a new detector = one file, zero changes elsewhere.

## License

MIT

---

*Built by [GaboLabs](https://github.com/GaboITB) — Designed through multi-expert AI debate (5 experts, 4 rounds).*
