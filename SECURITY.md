# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 3.x     | Yes                |
| 2.x     | No                 |
| < 2.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in MCP Shield, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. Email: **security@gabolabs.dev** with the subject line `[MCP Shield] Security Report`.
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours.
- **Assessment** within 7 days.
- **Fix timeline** communicated within 14 days.
- **Credit** given in the release notes (unless you prefer anonymity).

### Scope

The following are in scope:

- **MCP Shield CLI** — command injection, path traversal, arbitrary code execution
- **Sandbox escape** — Docker container breakout, privilege escalation
- **Scanner bypass** — techniques to hide malicious code from detection
- **Report injection** — XSS in HTML reports, injection in SARIF/JSON output
- **Supply chain** — compromised dependencies (we have zero, but the packaging pipeline counts)

### Out of Scope

- Vulnerabilities in MCP servers being scanned (report those to the respective maintainers)
- Social engineering attacks
- Denial of service against the CLI tool itself

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission
- Report vulnerabilities through the process described above

## Security Design Principles

MCP Shield follows these security principles:

1. **Zero runtime dependencies** — eliminates supply chain risk
2. **Input validation** — all sources validated before processing (git injection, path traversal, package name injection)
3. **Sandbox isolation** — Docker with dropped capabilities, memory limits, PID limits, network isolation
4. **No shell=True** — all subprocess calls use argument arrays
5. **Tar slip protection** — archive extraction validates paths
6. **Secret redaction** — environment values redacted in reports and logs
