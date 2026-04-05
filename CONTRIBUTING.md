# Contributing to MCP Shield

Thanks for your interest in contributing to MCP Shield! This guide will help you get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/GaboITB/mcp-shield.git
cd mcp-shield

# No dependencies to install — MCP Shield is zero-deps (stdlib only)
# Just make sure you have Python 3.10+

# Run the test suite
python -m unittest discover -s tests -p "test_*.py" -v

# Run DVMCP validation (10 vulnerable servers, 100 expected findings)
python damn-vulnerable-mcp/validate.py
```

## Project Structure

```
mcp_shield/
  core/           # Engine, models, registry, CWE mappings, remediation
  detectors/
    code/         # Source code detectors (shell injection, SSRF, secrets, etc.)
    meta/         # MCP metadata detectors (descriptions, annotations, prompts)
    delta/        # Runtime delta detectors (bait-and-switch, capability drift)
  analyzers/      # Dependency analysis, supply chain checks
  scoring/        # AIVSS scoring, verdict computation
  formatters/     # Output: terminal, HTML, JSON, SARIF, markdown
  fetcher/        # Live MCP server communication (stdio transport)
  runtime/        # Docker sandbox, bait-and-switch, network monitor
  approval/       # Approval workflow for live/sandbox operations
  tests/          # Unit tests
  damn-vulnerable-mcp/  # 10 intentionally vulnerable MCP servers for testing
```

## How to Add a New Detector

1. Create a file in the appropriate `detectors/` subdirectory.
2. Implement the correct protocol (`SourceDetector`, `MetadataDetector`, or `RuntimeDetector`) from `core/models.py`.
3. Register it in `core/registry.py` → `create_default_registry()`.
4. Add CWE mapping in `core/cwe.py` and remediation in `core/remediation.py`.
5. Add severity weight in `core/models.py` → `SEVERITY_WEIGHTS`.
6. Write tests in `tests/test_<detector_name>.py`.
7. Update `CHANGELOG.md`.

## Code Conventions

- **Language**: Code, comments, docstrings, and commits in English.
- **Style**: PEP 8, 88-char line length (Black-compatible).
- **Zero dependencies**: Only Python stdlib. No exceptions.
- **Type hints**: Required on all public functions.
- **Tests**: Required for every new detector (aim for both positive and negative cases).
- **Commits**: Conventional format — `feat:`, `fix:`, `docs:`, `refactor:`, `test:`.

## Pull Request Process

1. Fork the repo and create a branch from `master` (`feature/my-feature` or `fix/my-fix`).
2. Make your changes with tests.
3. Run the full test suite: `python -m unittest discover -s tests -p "test_*.py"`.
4. Run DVMCP validation: `python damn-vulnerable-mcp/validate.py`.
5. Update `CHANGELOG.md` under `[Unreleased]`.
6. Open a PR with a clear description of what and why.

## Reporting Issues

- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do NOT open a public issue.
- **False positives**: Open an issue with the rule ID, the code that triggered it, and why you think it's a false positive.
- **False negatives**: Open an issue with the malicious pattern that was missed.
- **Bugs**: Include the full command, output, and Python version.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
