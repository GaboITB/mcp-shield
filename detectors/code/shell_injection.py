"""Shell injection detector for MCP Shield v2.

Detects dangerous subprocess usage patterns:
- shell=True with string interpolation (CRITICAL)
- shell=True with hardcoded commands (LOW)
- os.system(), os.popen(), child_process.exec() usage
- Checks for input validation/sanitization as mitigating factors
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Python patterns (fallback when AST fails)
RE_SUBPROCESS_SHELL = re.compile(
    r"""subprocess\.\w+\s*\([^)]*shell\s*=\s*True""",
    re.DOTALL,
)
RE_OS_SYSTEM = re.compile(r"""\bos\.system\s*\(""")
RE_OS_POPEN = re.compile(r"""\bos\.popen\s*\(""")

# JS/TS patterns
RE_CHILD_PROCESS_EXEC = re.compile(r"""\bchild_process\.exec\s*\(""")
RE_CHILD_PROCESS_EXEC_SYNC = re.compile(r"""\bchild_process\.execSync\s*\(""")
RE_EXEC_REQUIRE = re.compile(r"""(?:exec|execSync|spawn|spawnSync)\s*\(""")
RE_SHELL_OPTION_JS = re.compile(r"""shell\s*:\s*true""", re.IGNORECASE)

# Go patterns
RE_EXEC_COMMAND_GO = re.compile(r"""\bexec\.Command\s*\(""")

# String interpolation indicators
RE_FSTRING = re.compile(r"""f["'][^"']*\{[^}]+\}""")
RE_FORMAT_CALL = re.compile(r"""\.format\s*\(""")
RE_PERCENT_FORMAT = re.compile(r"""%\s*[(\w]""")
RE_TEMPLATE_LITERAL = re.compile(r"""`[^`]*\$\{[^}]+\}[^`]*`""")
RE_CONCAT_VAR = re.compile(r"""\+\s*\w+\s*\+""")

# Force push patterns (dangerous git operations)
# Excludes fs.rm/unlink/mkdir {force: true} which is unrelated to git
RE_FORCE_PUSH = re.compile(
    r"""(?:forcePush|force-push|--force\b|"""
    r"""git\s+push\s+-f\b|updateReference.*force|"""
    r"""(?:push|createOrUpdateRef|updateRef)\s*\([^)]*force\s*:\s*true)""",
    re.IGNORECASE,
)

# Sanitization indicators (mitigation)
RE_SANITIZE = re.compile(
    r"""\b(?:shlex\.quote|shlex\.split|pipes\.quote|sanitize|whitelist|"""
    r"""allowlist|validate|escape|shellescape|shell_escape)\b""",
    re.IGNORECASE,
)

# File extension helpers
PY_EXTENSIONS = {".py", ".pyw"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
GO_EXTENSIONS = {".go"}


def _ext(path: str) -> str:
    """Return lowercased file extension."""
    dot = path.rfind(".")
    return path[dot:].lower() if dot != -1 else ""


def _has_interpolation(line: str) -> bool:
    """Check if a line contains string interpolation / concatenation."""
    return bool(
        RE_FSTRING.search(line)
        or RE_FORMAT_CALL.search(line)
        or RE_PERCENT_FORMAT.search(line)
        or RE_TEMPLATE_LITERAL.search(line)
        or RE_CONCAT_VAR.search(line)
    )


def _file_has_sanitization(content: str) -> bool:
    """Check if the file contains evidence of input sanitization."""
    return bool(RE_SANITIZE.search(content))


# ---------------------------------------------------------------------------
# AST-based Python analysis
# ---------------------------------------------------------------------------


class _ShellTrueVisitor(ast.NodeVisitor):
    """Walk a Python AST looking for shell=True in subprocess calls."""

    SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}

    def __init__(self, content: str, has_sanitization: bool) -> None:
        self.lines = content.splitlines()
        self.findings: list[Finding] = []
        self.has_sanitization = has_sanitization

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func

        # Match subprocess.xxx(... shell=True ...)
        if isinstance(func, ast.Attribute) and func.attr in self.SUBPROCESS_FUNCS:
            value = func.value
            if isinstance(value, ast.Name) and value.id == "subprocess":
                self._check_shell_kwarg(node)

        # Match os.system(...) and os.popen(...)
        if isinstance(func, ast.Attribute) and func.attr in ("system", "popen"):
            value = func.value
            if isinstance(value, ast.Name) and value.id == "os":
                line_text = (
                    self.lines[node.lineno - 1]
                    if node.lineno <= len(self.lines)
                    else ""
                )
                dynamic = self._arg_is_dynamic(node.args[0]) if node.args else False
                severity = Severity.CRITICAL if dynamic else Severity.MEDIUM
                if self.has_sanitization and severity != Severity.CRITICAL:
                    severity = Severity.LOW
                self.findings.append(
                    Finding(
                        rule_id="shell_injection",
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title=f"os.{func.attr}() call detected",
                        evidence=line_text.strip(),
                        location=f"line {node.lineno}",
                        detail=(
                            "os.system/popen execute commands through the shell. "
                            "Dynamic arguments risk command injection."
                        ),
                    )
                )

        self.generic_visit(node)

    def _check_shell_kwarg(self, node: ast.Call) -> None:
        """Check if shell=True is present and classify severity."""
        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                line_text = (
                    self.lines[node.lineno - 1]
                    if node.lineno <= len(self.lines)
                    else ""
                )
                # Determine if command argument is dynamic
                dynamic = False
                if node.args:
                    dynamic = self._arg_is_dynamic(node.args[0])
                if dynamic:
                    severity = (
                        Severity.HIGH if self.has_sanitization else Severity.CRITICAL
                    )
                    rule_id = "shell_injection"
                    title = "shell=True with dynamic input"
                else:
                    severity = Severity.LOW
                    rule_id = "shell_hardcoded"
                    title = "shell=True with hardcoded command"
                self.findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title=title,
                        evidence=line_text.strip(),
                        location=f"line {node.lineno}",
                        detail=(
                            "subprocess with shell=True passes the command through "
                            "the system shell, enabling injection if input is unsanitized."
                        ),
                    )
                )

    def _arg_is_dynamic(self, node: ast.AST) -> bool:
        """Heuristic: is the argument anything other than a plain string literal?"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return False
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(self._arg_is_dynamic(elt) for elt in node.elts)
        # JoinedStr = f-string, BinOp = concatenation, Call = .format(), Name/Attribute = variable
        return True


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class ShellInjectionDetector:
    """Detect shell injection vulnerabilities in source code."""

    name: str = "shell_injection"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        ext = _ext(path)
        findings: list[Finding] = []
        if ext in PY_EXTENSIONS:
            findings.extend(self._scan_python(path, content))
        elif ext in JS_EXTENSIONS:
            findings.extend(self._scan_js(path, content))
        elif ext in GO_EXTENSIONS:
            findings.extend(self._scan_go(path, content))

        # Force push detection applies to all code file types
        if ext in PY_EXTENSIONS | JS_EXTENSIONS | GO_EXTENSIONS:
            findings.extend(self._scan_force_push(content))

        return findings

    # -- Python (AST-first, regex fallback) --------------------------------

    def _scan_python(self, path: str, content: str) -> list[Finding]:
        has_sanitization = _file_has_sanitization(content)
        try:
            tree = ast.parse(content, filename=path)
            visitor = _ShellTrueVisitor(content, has_sanitization)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            return self._scan_python_regex(path, content, has_sanitization)

    def _scan_python_regex(
        self, path: str, content: str, has_sanitization: bool
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            lineno = f"line {i}"
            stripped = line.strip()

            if RE_SUBPROCESS_SHELL.search(line):
                dynamic = _has_interpolation(line)
                if dynamic:
                    severity = Severity.HIGH if has_sanitization else Severity.CRITICAL
                    rule_id = "shell_injection"
                    title = "shell=True with dynamic input (regex)"
                else:
                    severity = Severity.LOW
                    rule_id = "shell_hardcoded"
                    title = "shell=True with hardcoded command (regex)"
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title=title,
                        evidence=stripped,
                        location=lineno,
                    )
                )

            if RE_OS_SYSTEM.search(line) or RE_OS_POPEN.search(line):
                func_name = "os.system" if RE_OS_SYSTEM.search(line) else "os.popen"
                dynamic = _has_interpolation(line)
                severity = Severity.CRITICAL if dynamic else Severity.MEDIUM
                if has_sanitization and severity != Severity.CRITICAL:
                    severity = Severity.LOW
                findings.append(
                    Finding(
                        rule_id="shell_injection",
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title=f"{func_name}() call detected (regex)",
                        evidence=stripped,
                        location=lineno,
                    )
                )
        return findings

    # -- JavaScript / TypeScript -------------------------------------------
    # NOTE: This detector intentionally matches child_process.exec patterns
    # in scanned target code to flag potential shell injection vulnerabilities.

    def _scan_js(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        has_sanitization = _file_has_sanitization(content)
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            for pattern, label in (
                (RE_CHILD_PROCESS_EXEC, "child_process.exec()"),
                (RE_CHILD_PROCESS_EXEC_SYNC, "child_process.execSync()"),
            ):
                if pattern.search(line):
                    dynamic = _has_interpolation(line) or RE_TEMPLATE_LITERAL.search(
                        line
                    )
                    severity = Severity.CRITICAL if dynamic else Severity.MEDIUM
                    if has_sanitization:
                        severity = (
                            Severity.LOW
                            if severity == Severity.MEDIUM
                            else Severity.HIGH
                        )
                    findings.append(
                        Finding(
                            rule_id="shell_injection",
                            severity=severity,
                            surface=Surface.SOURCE_CODE,
                            title=f"{label} call detected",
                            evidence=stripped,
                            location=f"line {i}",
                            detail="child_process exec runs commands in a shell.",
                        )
                    )

            if RE_SHELL_OPTION_JS.search(line):
                findings.append(
                    Finding(
                        rule_id="shell_hardcoded",
                        severity=Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="shell: true option in spawn/exec",
                        evidence=stripped,
                        location=f"line {i}",
                    )
                )

        return findings

    # -- Go ----------------------------------------------------------------

    def _scan_go(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if RE_EXEC_COMMAND_GO.search(line):
                dynamic = RE_CONCAT_VAR.search(line) or "fmt.Sprintf" in line
                severity = Severity.HIGH if dynamic else Severity.LOW
                findings.append(
                    Finding(
                        rule_id="shell_injection" if dynamic else "shell_hardcoded",
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title="exec.Command() call detected",
                        evidence=line.strip(),
                        location=f"line {i}",
                    )
                )
        return findings

    # -- Force push detection (all languages) ------------------------------

    def _scan_force_push(self, content: str) -> list[Finding]:
        """Detect dangerous force push patterns in source code."""
        findings: list[Finding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue
            if RE_FORCE_PUSH.search(line):
                findings.append(
                    Finding(
                        rule_id="force_push",
                        severity=Severity.HIGH,
                        surface=Surface.SOURCE_CODE,
                        title="Force push pattern detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "Force push can overwrite remote history, causing data "
                            "loss. An MCP tool with force push capability is dangerous."
                        ),
                    )
                )
        return findings
