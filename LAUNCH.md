# MCP Shield v3.0 — Launch Plan

## Posts prêts à publier

---

### Hacker News (news.ycombinator.com/submit)

**Title:** MCP Shield – Audit MCP servers for supply chain attacks before installing them

**URL:** https://github.com/GaboITB/mcp-shield

**Text (si self-post):**
(laisser vide si on poste juste l'URL — HN préfère les liens directs)

---

### Reddit r/ChatGPT

**Title:** I built a tool that scans MCP servers for security issues before you install them — found real vulnerabilities in popular servers

**Body:**

MCP servers run with your AI agent's permissions — a malicious one can exfiltrate your codebase, inject prompts, or run arbitrary commands while appearing legitimate.

I built **MCP Shield**, a zero-dependency Python tool that audits MCP servers across 3 surfaces:

- **Source code** — shell injection, SSRF, hardcoded secrets, eval/exec
- **MCP metadata** — prompt injection in tool descriptions, schema injection
- **Runtime behavior** — bait-and-switch detection (server changes behavior based on which AI client connects)

**What it found on real servers:**
- Notion MCP: auth tokens passed as CLI arguments (visible in process list)
- Proxmox MCP: Grade D, 280 risk score, 32 findings
- Multiple official MCP SDK servers: outdated dependencies, unpinned versions

```
pip install mcp-shield-audit
mcp-shield scan --all    # scans every MCP on your system
```

It also includes a Docker sandbox that monitors network traffic and filesystem access, and a bait-and-switch detector that connects with 6 different client identities to catch servers that serve different tools to different clients.

359 tests, zero dependencies, tested on 31+ real MCP servers.

GitHub: https://github.com/GaboITB/mcp-shield
PyPI: https://pypi.org/project/mcp-shield-audit/

---

### Reddit r/netsec

**Title:** MCP Shield v3 — Static + runtime security auditing for MCP (Model Context Protocol) servers [tool release]

**Body:**

Releasing MCP Shield v3, a security audit framework for MCP servers. MCP is the protocol used by Claude, Cursor, Windsurf etc. to connect AI agents to external tools.

**Attack surfaces covered:**
- Supply chain (postinstall scripts, phantom deps, unpinned versions)
- Code injection (shell injection via subprocess, eval/exec, SSRF)
- Prompt injection (tool descriptions, schema injection, invisible Unicode)
- Runtime rug-pull (bait-and-switch: different tools served to different clients)
- Credential exposure (secrets in source, args visible in process list)

**Detection approach:**
- Layer 1: AST-based Python analysis + regex fallback for JS/TS/Go
- Layer 1b: Live MCP protocol handshake (tools/list, resources/list, prompts/list)
- Layer 2: Docker sandbox with tcpdump + strace (network isolation, filesystem monitoring)
- Layer 3: Multi-identity bait-and-switch probe (6 client identities)

17 detectors, AIVSS scoring (AI-specific CVSS variant), CWE mappings, SARIF output for CI/CD integration.

Zero runtime dependencies. 359 tests. Tested on 31+ real MCP servers.

Includes `damn-vulnerable-mcp` — 10 intentionally vulnerable MCP servers for testing (like DVWA but for MCP).

GitHub: https://github.com/GaboITB/mcp-shield

---

### Reddit r/LocalLLaMA

**Title:** Security scanner for MCP servers — found real vulnerabilities in popular servers including Notion and Proxmox MCPs

**Body:**

If you use MCP servers with Claude Desktop, Cursor, or any MCP client — you might want to audit them first.

I built MCP Shield, a Python tool that scans MCP servers before you install them. Zero dependencies, one command:

```
pip install mcp-shield-audit
mcp-shield scan --all
```

It found real issues: Notion MCP exposes auth tokens in CLI args, Proxmox MCP scored Grade D (280 risk score), and most official SDK servers have unpinned dependencies.

The coolest feature is bait-and-switch detection — it connects to the MCP server pretending to be 6 different AI clients (Claude, Cursor, Windsurf...) to check if the server serves different tools depending on who's asking.

GitHub: https://github.com/GaboITB/mcp-shield

---

### LinkedIn

**Title:** Releasing MCP Shield v3.0 — Security Audit Framework for AI Tool Servers

**Body:**

Excited to release MCP Shield v3.0, an open-source security audit framework I built for MCP (Model Context Protocol) servers.

MCP is the protocol that connects AI agents (Claude, Cursor, Windsurf) to external tools. But these servers run with your agent's permissions — a compromised one can exfiltrate code, inject prompts, or execute arbitrary commands.

MCP Shield scans servers across 3 detection surfaces:
- Source code analysis (17 detectors)
- MCP protocol metadata inspection
- Runtime behavior monitoring (Docker sandbox + bait-and-switch detection)

Key results from testing on 31+ real-world servers:
- Found credential exposure in Notion's MCP server
- Identified supply chain risks in multiple popular servers
- Detected outdated SDKs across the ecosystem

Technical highlights:
- Zero runtime dependencies (Python stdlib only)
- 359 automated tests
- SARIF output for CI/CD integration
- Includes "damn-vulnerable-mcp" — 10 intentionally vulnerable servers for security training

Available now:
- GitHub: https://github.com/GaboITB/mcp-shield
- PyPI: pip install mcp-shield-audit

#cybersecurity #AI #MCP #opensource #supplychainsecurity

---

## Issues GitHub à ouvrir

### 1. Notion MCP — credential_in_args
**Repo:** https://github.com/notionhq/notion-mcp-server
**Title:** [Security] Auth token passed as CLI argument — visible in process list
**Body:** MCP Shield detected that `--auth-token` is parsed from CLI arguments, making the token visible in `ps aux` / Task Manager. Consider using environment variables instead.

### 2. Proxmox MCP — HIGH RISK score
**Repo:** (vérifier le repo de proxmox-mcp)
**Title:** [Security] MCP Shield audit: Grade D, 280 risk score — multiple supply chain concerns
**Body:** Detailed findings from MCP Shield scan.

---

## Communautés à poster

- [ ] Hacker News
- [ ] Reddit r/ChatGPT
- [ ] Reddit r/netsec
- [ ] Reddit r/LocalLLaMA
- [ ] LinkedIn
- [ ] Discord Anthropic (#mcp channel)
- [ ] Discord Cursor
- [ ] GitHub issue sur Notion MCP
- [ ] GitHub issue sur Proxmox MCP
- [ ] Awesome MCP lists (PR)
