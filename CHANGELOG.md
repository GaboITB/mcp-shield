# Changelog

All notable changes to MCP Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MCP Resources scanner — detects prompt injection via resource URIs, descriptions, MIME types (dangerous schemes, internal URIs, wildcard patterns, executable MIME)
- MCP Prompts scanner — detects injection in prompt descriptions, argument descriptions, and long default values
- MCP Sampling detector — flags servers declaring sampling capability (LLM output control)
- Annotation coherence checker — detects readOnlyHint/destructiveHint/idempotentHint mismatches vs actual tool behavior
- Full `fetch_live_all()` — single connection fetches tools + resources + prompts + capabilities
- Server capabilities parsing from initialize response
- JSON Schema for audit output validation (`schemas/audit-output.schema.json`)
- MANIFEST.in for proper sdist packaging
- CHANGELOG.md (this file)
- CWE mappings for 7 new rule IDs
- Remediation guidance for 7 new rule IDs
- `--no-ignore` flag — bypass `.mcpshieldignore` in scanned repos to prevent attacker-controlled exclusions
- Warning when `.mcpshieldignore` is found in a scanned repo (with pattern count)
- `SECURITY.md` — responsible disclosure policy for a security tool
- `CONTRIBUTING.md` — full contributor guide (dev setup, conventions, detector howto)
- GitHub issue templates: bug report, false positive report, feature request
- GitHub pull request template
- JSON output metadata: `mcp_shield_version`, `$schema`, `generated_at` fields
- 32 new tests for formatters (terminal, JSON, SARIF, HTML) and CLI (parser, exit codes, sanitization, roundtrip)
- Centralized `core/paths.py` — platform-appropriate data directory (`%APPDATA%` on Windows, `~/.config/` on Linux/macOS)
- `network_monitor.py` cross-platform support — `ss` on Linux, `lsof` on macOS (was Windows-only `netstat -nob`)

### Changed
- `run_live()` now fetches resources and prompts alongside tools
- Registry: 17 detectors (was 16) — added AnnotationCoherenceDetector
- Live fetcher: `_parse_resource()` and `_parse_prompt()` with full type validation
- **CLI refactored**: monolithic `cli.py` (1257 lines) split into 6 submodules (`cli/_parser.py`, `cli/_utils.py`, `cli/_layers.py`, `cli/_cmd_scan.py`, `cli/_cmd_live.py`, `cli/_cmd_other.py`)
- Unified `has_interpolation()` — 3 duplicate implementations merged into single source in `detectors/code/_utils.py`
- `AuditResult.grade` now delegates to `compute_grade()` from `scoring/verdict.py` (eliminated DRY violation)
- `run_live()` deduplication now uses `_dedup_and_cap()` with proper rule_id cap (was inline-only dedup)
- Argparse subcommand dispatch uses `dest="subcommand"` to avoid collision with `bait-switch` positional `command` arg
- `--quiet` mode fully implemented — engine, analyzers, and CLI all respect the flag (zero output, exit code only)
- Non-text formats (`json`, `sarif`, `html`, `markdown`) redirect progress logs to stderr, keeping stdout clean for piping
- `--name` argument sanitized on input via `sanitize_filename()` to prevent path traversal and OS errors
- `--suppress` warns on stderr when rule IDs don't match any findings

### Security
- Docker sandbox: added `--security-opt=no-new-privileges` to prevent privilege escalation inside container
- Sandbox entrypoint: quoted `${ENTRY_BIN}` and `${ENTRY_POINT}` variables to prevent word-splitting injection
- `--name` sanitized to block path traversal (`../../etc/passwd`) and special characters (`<>|&;`)

### Fixed
- Scoped npm packages (`@scope/name`) were rejected as "Path not found" due to `/` triggering local path heuristic — now checked before path detection
- Argparse `dest="command"` collision with `bait-switch` positional argument caused silent dispatch failure
- Nonexistent npm packages silently produced Grade A+ instead of error — now raises `RuntimeError` with npm 404 message
- `--quiet` had no effect on scan output — engine and analyzers printed directly to stdout bypassing the flag
- `pyproject.toml` classifier `License :: OSI Approved :: MIT License` incompatible with PEP 639 `license = "MIT"` — classifier removed

## [2.0.0] - 2025-12-15

### Added
- Complete rewrite: 16 detectors across 3 surfaces (source code, MCP metadata, runtime delta)
- TypeScript/JavaScript scanning: 6 code detectors with 30+ fs method patterns, 16 token types
- Binary analysis: ELF/PE/Mach-O heuristic scanning (strings, entropy, C2 indicators)
- Bait-and-switch detection: multi-identity probing for rug-pull behavior
- Docker sandbox: isolated runtime analysis with tcpdump + strace
- Auto-detect: finds MCP configs across 7 known clients
- HTML reports: standalone dark theme with interactive findings
- GitHub Action: composite action for CI/CD integration
- SARIF output: standard format for code scanning integrations
- CWE mapping: 55 rule IDs mapped to CWE identifiers
- Remediation guidance: 59 rule IDs with actionable fix advice
- `.mcpshieldignore` support: gitignore-like file exclusion
- AIVSS scoring: AI-specific vulnerability scoring system
- SBOM generation: CycloneDX-compatible software bill of materials
- damn-vulnerable-mcp: 10 intentionally vulnerable MCP servers for testing
- HMAC-SHA256 approval store with restricted file permissions
- 279 tests covering all detectors and integration scenarios

### Security
- Fixed: command injection via npm package names (C1) — uses `npm.cmd` array, not `cmd /c`
- Fixed: sandbox entrypoint injection (C2) — regex validation, no `sh -c`
- Fixed: GitHub Action input injection (C3) — inputs via env variables
- Fixed: DoS via unbounded readline (C4) — capped at 1 MB
- Fixed: infinite loop in `_read_response` (C5) — monotonic deadline + line limit
- Fixed: tar slip and symlink attacks (H1, H2) — path validation on extract
- Fixed: unsigned approval records (H6) — HMAC-SHA256 integrity
- Fixed: ReDoS in `RE_GCP_SERVICE_ACCOUNT` — bounded quantifiers
- Fixed: world-readable approval files (H13) — `chmod 0o600`
- Fixed: path traversal in report filenames (H14) — sanitized output names

## [1.0.0] - 2025-11-01

### Added
- Initial release: basic MCP server auditing
- Source code scanning for common vulnerability patterns
- npm dependency analysis
- CLI with scan/approve/live commands

[Unreleased]: https://github.com/GaboITB/mcp-shield/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/GaboITB/mcp-shield/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/GaboITB/mcp-shield/releases/tag/v1.0.0
