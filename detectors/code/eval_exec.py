"""Eval/exec detector for MCP Shield v2.

Detects dangerous dynamic code execution:
- Python: eval(), exec() with dynamic vs static arguments
- JS/TS: new Function(), execSync()
- Filters false positives like regex.exec() in JavaScript

NOTE: This is a security scanner — it intentionally contains string patterns
matching dangerous functions (eval, exec, execSync) for detection purposes.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Python regex fallback
RE_PY_EVAL = re.compile(r"""\beval\s*\(""")
RE_PY_EXEC = re.compile(r"""\bexec\s*\(""")

# JS/TS patterns
RE_JS_EVAL = re.compile(r"""\beval\s*\(""")
RE_JS_NEW_FUNCTION = re.compile(r"""\bnew\s+Function\s*\(""")
RE_JS_EXEC_SYNC = re.compile(r"""\bexecSync\s*\(""")
RE_JS_SET_TIMEOUT_STR = re.compile(r"""\bsetTimeout\s*\(\s*["'`]""")
RE_JS_SET_INTERVAL_STR = re.compile(r"""\bsetInterval\s*\(\s*["'`]""")

# False positive filter: standalone eval, not obj.eval or .exec
RE_JS_STANDALONE_EVAL = re.compile(r"""(?<!\w)(?<!\.)eval\s*\(""")

# Dynamic input indicators
RE_FSTRING = re.compile(r"""f["'][^"']*\{[^}]+\}""")
RE_FORMAT_CALL = re.compile(r"""\.format\s*\(""")
RE_TEMPLATE_LITERAL = re.compile(r"""`[^`]*\$\{[^}]+\}[^`]*`""")
RE_CONCAT = re.compile(r"""\+\s*\w+""")

# File extensions
PY_EXTENSIONS = {".py", ".pyw"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}


def _ext(path: str) -> str:
    dot = path.rfind(".")
    return path[dot:].lower() if dot != -1 else ""


def _looks_dynamic(line: str) -> bool:
    """Heuristic: does the line suggest dynamic/user-controlled input?"""
    return bool(
        RE_FSTRING.search(line)
        or RE_FORMAT_CALL.search(line)
        or RE_TEMPLATE_LITERAL.search(line)
        or RE_CONCAT.search(line)
    )


# ---------------------------------------------------------------------------
# AST-based Python analysis
# ---------------------------------------------------------------------------


class _EvalExecVisitor(ast.NodeVisitor):
    """Walk Python AST for eval() and exec() calls."""

    DANGEROUS = {"eval", "exec"}

    def __init__(self, content: str) -> None:
        self.lines = content.splitlines()
        self.findings: list[Finding] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = None
        if isinstance(node.func, ast.Name) and node.func.id in self.DANGEROUS:
            func_name = node.func.id
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in self.DANGEROUS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "builtins"
        ):
            func_name = node.func.attr

        if func_name:
            dynamic = self._arg_is_dynamic(node.args[0]) if node.args else True
            line_text = (
                self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
            )
            if dynamic:
                self.findings.append(
                    Finding(
                        rule_id="eval_exec_dynamic",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title=f"{func_name}() with dynamic input",
                        evidence=line_text.strip(),
                        location=f"line {node.lineno}",
                        detail=(
                            f"{func_name}() executes arbitrary code. Dynamic arguments "
                            "allow attackers to inject malicious code."
                        ),
                    )
                )
            else:
                self.findings.append(
                    Finding(
                        rule_id="eval_exec_static",
                        severity=Severity.LOW,
                        surface=Surface.SOURCE_CODE,
                        title=f"{func_name}() with static string",
                        evidence=line_text.strip(),
                        location=f"line {node.lineno}",
                        detail=(
                            f"{func_name}() with a static string is low risk but "
                            "should be replaced with safer alternatives when possible."
                        ),
                    )
                )

        self.generic_visit(node)

    def _arg_is_dynamic(self, node: ast.AST) -> bool:
        """Check if the argument is a plain string constant."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return False
        return True


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class EvalExecDetector:
    """Detect eval/exec and dynamic code execution patterns."""

    name: str = "eval_exec"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        ext = _ext(path)
        if ext in PY_EXTENSIONS:
            return self._scan_python(path, content)
        if ext in JS_EXTENSIONS:
            return self._scan_js(path, content)
        return []

    # -- Python (AST-first, regex fallback) --------------------------------

    def _scan_python(self, path: str, content: str) -> list[Finding]:
        try:
            tree = ast.parse(content, filename=path)
            visitor = _EvalExecVisitor(content)
            visitor.visit(tree)
            return visitor.findings
        except SyntaxError:
            return self._scan_python_regex(content)

    def _scan_python_regex(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, func_name in (
                (RE_PY_EVAL, "eval"),
                (RE_PY_EXEC, "exec"),
            ):
                if pattern.search(line):
                    dynamic = _looks_dynamic(line)
                    findings.append(
                        Finding(
                            rule_id=(
                                "eval_exec_dynamic" if dynamic else "eval_exec_static"
                            ),
                            severity=Severity.CRITICAL if dynamic else Severity.LOW,
                            surface=Surface.SOURCE_CODE,
                            title=f"{func_name}() detected (regex)",
                            evidence=stripped,
                            location=f"line {i}",
                        )
                    )
        return findings

    # -- JavaScript / TypeScript -------------------------------------------

    def _scan_js(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            # eval() — filter out regex.exec() and obj.eval() false positives
            if RE_JS_STANDALONE_EVAL.search(line):
                dynamic = _looks_dynamic(line) or RE_TEMPLATE_LITERAL.search(line)
                findings.append(
                    Finding(
                        rule_id="eval_exec_dynamic" if dynamic else "eval_exec_static",
                        severity=Severity.CRITICAL if dynamic else Severity.LOW,
                        surface=Surface.SOURCE_CODE,
                        title="eval() call detected",
                        evidence=stripped,
                        location=f"line {i}",
                        detail="eval() executes arbitrary JavaScript code.",
                    )
                )

            # new Function()
            if RE_JS_NEW_FUNCTION.search(line):
                dynamic = _looks_dynamic(line) or RE_TEMPLATE_LITERAL.search(line)
                findings.append(
                    Finding(
                        rule_id="eval_exec_dynamic" if dynamic else "eval_exec_static",
                        severity=Severity.CRITICAL if dynamic else Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="new Function() constructor detected",
                        evidence=stripped,
                        location=f"line {i}",
                        detail=(
                            "new Function() compiles and executes a string as code, "
                            "equivalent to eval()."
                        ),
                    )
                )

            # execSync() — flag as code execution vector
            if RE_JS_EXEC_SYNC.search(line):
                # Filter: only flag standalone execSync, not regex.execSync
                if not line.strip().startswith("//"):
                    dynamic = _looks_dynamic(line) or RE_TEMPLATE_LITERAL.search(line)
                    findings.append(
                        Finding(
                            rule_id=(
                                "eval_exec_dynamic" if dynamic else "eval_exec_static"
                            ),
                            severity=Severity.HIGH if dynamic else Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title="execSync() call detected",
                            evidence=stripped,
                            location=f"line {i}",
                            detail="execSync() runs a shell command synchronously.",
                        )
                    )

            # setTimeout/setInterval with string argument (implicit eval)
            for pattern, func_name in (
                (RE_JS_SET_TIMEOUT_STR, "setTimeout"),
                (RE_JS_SET_INTERVAL_STR, "setInterval"),
            ):
                if pattern.search(line):
                    findings.append(
                        Finding(
                            rule_id="eval_exec_dynamic",
                            severity=Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title=f"{func_name}() with string argument",
                            evidence=stripped,
                            location=f"line {i}",
                            detail=(
                                f"{func_name}() with a string argument executes it as "
                                "code via implicit eval. Pass a function reference instead."
                            ),
                        )
                    )

        return findings
