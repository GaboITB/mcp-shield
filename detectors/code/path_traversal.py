"""Path traversal detector for MCP Shield v3.

Detects file operations with unsanitized user-controlled paths:
- Python: open(), pathlib.Path, os.path.join with user input (AST-based)
- JS/TS: fs.readFile, fs.writeFile, path.join with req.params/user input
- Checks for sanitization: os.path.abspath, realpath, resolve, path.normalize
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Python patterns (regex fallback)
RE_PY_OPEN = re.compile(r"""\bopen\s*\(""")
RE_PY_PATHLIB_OPEN = re.compile(
    r"""Path\s*\([^)]*\)\s*\.(?:open|read_text|read_bytes|write_text|write_bytes)\s*\("""
)
RE_PY_OS_PATH_JOIN = re.compile(r"""\bos\.path\.join\s*\(""")
RE_PY_PATHLIB_CONSTRUCT = re.compile(r"""\bPath\s*\(""")
RE_PY_SHUTIL = re.compile(r"""\bshutil\.(copy|copy2|copytree|move|rmtree)\s*\(""")
RE_PY_OS_REMOVE = re.compile(
    r"""\bos\.(remove|unlink|rmdir|makedirs|listdir|scandir)\s*\("""
)

# JS/TS patterns -- comprehensive fs coverage
RE_JS_FS_READ = re.compile(
    r"""\bfs\w*\.(readFile|readFileSync|readdir|readdirSync|"""
    r"""access|accessSync|open|openSync|"""
    r"""stat|statSync|lstat|lstatSync|fstat|"""
    r"""realpath|realpathSync|"""
    r"""exists|existsSync)\s*\("""
)
RE_JS_FS_WRITE = re.compile(
    r"""\bfs\w*\.(writeFile|writeFileSync|appendFile|appendFileSync|"""
    r"""createWriteStream|createReadStream|mkdir|mkdirSync|"""
    r"""unlink|unlinkSync|rmdir|rmdirSync|rm|rmSync|"""
    r"""rename|renameSync|copyFile|copyFileSync|"""
    r"""symlink|symlinkSync|link|linkSync|"""
    r"""chmod|chmodSync|chown|chownSync|"""
    r"""truncate|truncateSync)\s*\("""
)
RE_JS_PATH_JOIN = re.compile(r"""\bpath\.(?:join|resolve)\s*\(""")
RE_JS_FS_PROMISES = re.compile(
    r"""\bfs\.promises\.(readFile|writeFile|readdir|unlink|rmdir|mkdir|access|"""
    r"""open|stat|lstat|realpath|rename|copyFile|symlink|link|chmod|chown|truncate)\s*\("""
)

# Express/Koa/Hono static file serving
RE_JS_STATIC_SERVE = re.compile(
    r"""\b(?:express\.static|serve[-_]?[Ss]tatic|"""
    r"""ctx\.sendFile|c\.file|res\.sendFile|res\.download|"""
    r"""res\.attachment|Koa\.send|send)\s*\("""
)

# File upload libraries (multer, formidable, busboy)
RE_JS_UPLOAD = re.compile(r"""\b(?:multer|formidable|busboy|Busboy)\s*\(""")
RE_JS_UPLOAD_DEST = re.compile(
    r"""\b(?:dest|destination|uploadDir|upload_dir|savePath)\s*[:=]"""
)

# Deno file APIs
RE_JS_DENO_FS = re.compile(
    r"""\bDeno\.(?:readFile|readTextFile|writeFile|writeTextFile|"""
    r"""open|create|mkdir|remove|rename|stat|lstat|"""
    r"""readDir|copyFile|symlink|link|chmod|chown|truncate|"""
    r"""readLink|makeTempDir|makeTempFile)\s*\("""
)

# Bun file APIs
RE_JS_BUN_FS = re.compile(r"""\bBun\.(?:file|write)\s*\(""")

# User input indicators
RE_PY_USER_INPUT = re.compile(
    r"""\b(?:request\.\w+|args\.\w+|params\.\w+|kwargs\[|"""
    r"""argv\[|sys\.argv|input\s*\(|"""
    r"""flask\.request|bottle\.request|"""
    r"""data\[|form\[|query\[)\b""",
    re.IGNORECASE,
)
RE_JS_USER_INPUT = re.compile(
    r"""\b(?:req\.params|req\.query|req\.body|req\.headers|"""
    r"""request\.params|request\.query|request\.body|"""
    r"""ctx\.params|ctx\.query|"""
    r"""event\.pathParameters|event\.queryStringParameters|"""
    r"""args\[|argv\[|userInput|user_input)\b""",
)

# Path sanitization (mitigation)
RE_PY_SANITIZE = re.compile(
    r"""\b(?:os\.path\.(?:abspath|realpath|normpath)|"""
    r"""pathlib\.Path\([^)]*\)\.resolve|\.resolve\(\)|"""
    r"""os\.path\.commonpath|os\.path\.commonprefix|"""
    r"""secure_filename|werkzeug\.utils\.secure_filename)\b""",
    re.IGNORECASE,
)
RE_JS_SANITIZE = re.compile(
    r"""\b(?:path\.normalize|path\.resolve|"""
    r"""\.replace\(\s*['"]\.\.['"]\s*,|"""
    r"""sanitize|secure_filename|"""
    r"""realpath|realpathSync)\b""",
    re.IGNORECASE,
)

# Traversal string indicators
RE_DOTDOT = re.compile(r"""\.\.""")

# File extensions
PY_EXTENSIONS = {".py", ".pyw"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}


from mcp_shield.detectors.code._utils import file_ext as _ext  # noqa: E402


# ---------------------------------------------------------------------------
# AST-based Python analysis
# ---------------------------------------------------------------------------


class _PathTraversalVisitor(ast.NodeVisitor):
    """Walk Python AST looking for open() / Path() with user-controlled args."""

    # Names that typically hold user input
    USER_INPUT_NAMES = {
        "filename",
        "filepath",
        "file_path",
        "path",
        "fname",
        "file_name",
        "name",
        "target",
        "dest",
        "destination",
        "source",
        "src",
        "upload",
        "download",
    }

    # Function parameters (collected from enclosing function)
    DANGEROUS_BUILTINS = {"open"}

    def __init__(self, content: str, has_sanitization: bool) -> None:
        self.lines = content.splitlines()
        self.findings: list[Finding] = []
        self.has_sanitization = has_sanitization
        self._func_params: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        # Track function parameters as potential user input
        old_params = self._func_params
        self._func_params = {arg.arg for arg in node.args.args}
        self.generic_visit(node)
        self._func_params = old_params

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # open(...)
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                self._check_path_arg(node, "open()", node.args[0])

        # os.path.join(base, user_input)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "path"
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "os"
        ):
            # Check all arguments after the first (base) for user input
            for arg in node.args[1:]:
                if self._arg_from_user(arg):
                    line_text = (
                        self.lines[node.lineno - 1]
                        if node.lineno <= len(self.lines)
                        else ""
                    )
                    severity = (
                        Severity.MEDIUM if self.has_sanitization else Severity.HIGH
                    )
                    self.findings.append(
                        Finding(
                            rule_id="path_traversal",
                            severity=severity,
                            surface=Surface.SOURCE_CODE,
                            title="os.path.join() with user-controlled segment",
                            evidence=line_text.strip(),
                            location=f"line {node.lineno}",
                            detail=(
                                "os.path.join does NOT prevent traversal — "
                                "an absolute path in a later argument replaces the base. "
                                "Use os.path.realpath + prefix check."
                            ),
                        )
                    )
                    break

        # shutil operations
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "shutil"
            and node.func.attr in ("copy", "copy2", "copytree", "move", "rmtree")
        ):
            for arg in node.args:
                if self._arg_from_user(arg):
                    line_text = (
                        self.lines[node.lineno - 1]
                        if node.lineno <= len(self.lines)
                        else ""
                    )
                    severity = (
                        Severity.MEDIUM if self.has_sanitization else Severity.HIGH
                    )
                    self.findings.append(
                        Finding(
                            rule_id="path_traversal",
                            severity=severity,
                            surface=Surface.SOURCE_CODE,
                            title=f"shutil.{node.func.attr}() with user-controlled path",
                            evidence=line_text.strip(),
                            location=f"line {node.lineno}",
                            detail=(
                                "File operations with user-controlled paths can lead "
                                "to reading/writing/deleting arbitrary files."
                            ),
                        )
                    )
                    break

        self.generic_visit(node)

    def _check_path_arg(self, node: ast.Call, func_label: str, arg: ast.AST) -> None:
        """Check if the path argument to open() comes from user input."""
        if self._arg_from_user(arg):
            line_text = (
                self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
            )
            severity = Severity.MEDIUM if self.has_sanitization else Severity.HIGH
            self.findings.append(
                Finding(
                    rule_id="path_traversal",
                    severity=severity,
                    surface=Surface.SOURCE_CODE,
                    title=f"{func_label} with user-controlled path",
                    evidence=line_text.strip(),
                    location=f"line {node.lineno}",
                    detail=(
                        "Opening files with user-controlled paths enables directory "
                        "traversal attacks (../../etc/passwd). Validate and resolve "
                        "the path against a safe base directory."
                    ),
                )
            )

    def _arg_from_user(self, node: ast.AST) -> bool:
        """Heuristic: does this AST node look like it comes from user input?"""
        if isinstance(node, ast.Name):
            name = node.id.lower()
            if name in self._func_params:
                return True
            if name in self.USER_INPUT_NAMES:
                return True
        if isinstance(node, ast.Attribute):
            # request.args.get(...), params.path, etc.
            attr_chain = self._flatten_attr(node)
            if any(
                kw in attr_chain
                for kw in ("request", "args", "params", "form", "query", "data")
            ):
                return True
        if isinstance(node, ast.Subscript):
            # kwargs["path"], data["file"], etc.
            return self._arg_from_user(node.value)
        if isinstance(node, ast.JoinedStr):
            # f-string: check if any value is user-controlled
            return any(
                self._arg_from_user(v.value)
                for v in node.values
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp):
            # Concatenation
            return self._arg_from_user(node.left) or self._arg_from_user(node.right)
        if isinstance(node, ast.Call):
            # Check for calls like os.path.join(base, user_param)
            for arg in getattr(node, "args", []):
                if self._arg_from_user(arg):
                    return True
        return False

    def _flatten_attr(self, node: ast.AST) -> str:
        """Flatten an attribute chain: request.args.get -> 'request.args.get'."""
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts)).lower()


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class PathTraversalDetector:
    """Detect path traversal vulnerabilities in file operations."""

    name: str = "path_traversal"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        ext = _ext(path)
        if ext in PY_EXTENSIONS:
            return self._scan_python(path, content)
        if ext in JS_EXTENSIONS:
            return self._scan_js(path, content)
        return []

    # -- Python (AST-first, regex fallback) --------------------------------

    def _scan_python(self, path: str, content: str) -> list[Finding]:
        has_sanitization = bool(RE_PY_SANITIZE.search(content))
        try:
            tree = ast.parse(content, filename=path)
            visitor = _PathTraversalVisitor(content, has_sanitization)
            visitor.visit(tree)
            return visitor.findings
        except (SyntaxError, RecursionError):
            return self._scan_python_regex(content, has_sanitization)

    def _scan_python_regex(self, content: str, has_sanitization: bool) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            has_file_op = (
                RE_PY_OPEN.search(line)
                or RE_PY_PATHLIB_OPEN.search(line)
                or RE_PY_OS_PATH_JOIN.search(line)
                or RE_PY_SHUTIL.search(line)
                or RE_PY_OS_REMOVE.search(line)
            )
            if has_file_op and RE_PY_USER_INPUT.search(line):
                severity = Severity.MEDIUM if has_sanitization else Severity.HIGH
                findings.append(
                    Finding(
                        rule_id="path_traversal",
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title="File operation with user-controlled path (regex)",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "A file operation uses a path that appears to come from "
                            "user input. Validate with realpath + prefix check."
                        ),
                    )
                )

        return findings

    # -- JavaScript / TypeScript -------------------------------------------

    def _scan_js(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        has_sanitization = bool(RE_JS_SANITIZE.search(content))
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue

            has_user_input = RE_JS_USER_INPUT.search(line)

            # Node.js fs operations
            has_file_op = (
                RE_JS_FS_READ.search(line)
                or RE_JS_FS_WRITE.search(line)
                or RE_JS_FS_PROMISES.search(line)
            )
            has_path_join = RE_JS_PATH_JOIN.search(line)

            # Deno/Bun file operations
            has_deno_fs = RE_JS_DENO_FS.search(line)
            has_bun_fs = RE_JS_BUN_FS.search(line)

            # Static file serving (express.static, res.sendFile, ctx.sendFile)
            has_static_serve = RE_JS_STATIC_SERVE.search(line)

            any_file_op = has_file_op or has_deno_fs or has_bun_fs or has_static_serve

            if (any_file_op or has_path_join) and has_user_input:
                severity = Severity.MEDIUM if has_sanitization else Severity.HIGH
                if has_static_serve:
                    op_type = "Static file serve"
                elif has_deno_fs:
                    op_type = "Deno file operation"
                elif has_bun_fs:
                    op_type = "Bun file operation"
                elif has_file_op:
                    op_type = "File operation"
                else:
                    op_type = "path.join/resolve"
                findings.append(
                    Finding(
                        rule_id="path_traversal",
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title=f"{op_type} with user-controlled path",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "File system access with user-controlled paths enables "
                            "directory traversal. Use path.resolve + startsWith check "
                            "against a safe base directory."
                        ),
                    )
                )

            # Upload destination with user input
            if RE_JS_UPLOAD_DEST.search(line) and has_user_input:
                already = any(f.location == f"line {i}" for f in findings)
                if not already:
                    findings.append(
                        Finding(
                            rule_id="path_traversal",
                            severity=(
                                Severity.MEDIUM if has_sanitization else Severity.HIGH
                            ),
                            surface=Surface.SOURCE_CODE,
                            title="Upload destination with user-controlled path",
                            evidence=stripped[:200],
                            location=f"line {i}",
                            detail=(
                                "File upload destination derived from user input "
                                "enables writing files to arbitrary locations."
                            ),
                        )
                    )

            # Detect direct string concatenation for paths with user input
            if RE_DOTDOT.search(line) and has_user_input:
                already = any(f.location == f"line {i}" for f in findings)
                if not already:
                    findings.append(
                        Finding(
                            rule_id="path_traversal",
                            severity=Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title="Potential path traversal string in user input context",
                            evidence=stripped[:200],
                            location=f"line {i}",
                        )
                    )

        return findings
