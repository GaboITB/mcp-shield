"""Excessive permissions and obfuscation detector for MCP Shield v3.

Detects three categories of risk:
1. Excessive permissions: filesystem + network + process spawning in same file
2. Suspicious install scripts: postinstall/preinstall in package.json
3. Code obfuscation: String.fromCharCode, hex/unicode escapes, atob/btoa

NOTE: This is a security scanner — it intentionally contains string patterns
matching dangerous constructs (eval, obfuscation signatures) for detection.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled regex patterns — Permission categories
# ---------------------------------------------------------------------------

# Filesystem access indicators
RE_FS_PYTHON = re.compile(
    r"""\b(?:open\s*\(|os\.(path|remove|unlink|listdir|scandir|makedirs|rename)|"""
    r"""shutil\.\w+|pathlib\.Path|"""
    r"""with\s+open|file\.read|file\.write)\b"""
)
RE_FS_JS = re.compile(
    r"""\b(?:fs\w*\.(?:read|write|unlink|mkdir|rmdir|access|stat|chmod|rename|copyFile|"""
    r"""open|symlink|link|lstat|chown|truncate|appendFile|createReadStream|createWriteStream)\w*|"""
    r"""fs\.promises\.\w+|createReadStream|createWriteStream|"""
    r"""Deno\.(?:readFile|writeFile|open|create|mkdir|remove|rename|stat|readDir|copyFile)\w*|"""
    r"""Bun\.(?:file|write)\w*)"""
)

# Network access indicators
RE_NET_PYTHON = re.compile(
    r"""\b(?:requests\.\w+|urllib\.\w+|httpx\.\w+|aiohttp\.\w+|"""
    r"""socket\.socket|http\.client|xmlrpc\.client|ftplib|smtplib|"""
    r"""websocket|socketio)\b"""
)
RE_NET_JS = re.compile(
    r"""\b(?:fetch\s*\(|axios\.\w+|http\.(?:get|request)\w*|https\.(?:get|request)\w*|"""
    r"""got\.\w+|undici\.\w+|net\.(?:connect|createConnection|createServer|Socket)\w*|"""
    r"""tls\.(?:connect|TLSSocket|createServer)\w*|"""
    r"""dgram\.(?:createSocket|Socket)\w*|dns\.(?:resolve|lookup)\w*|"""
    r"""WebSocket|socket\.io|XMLHttpRequest|superagent|"""
    r"""Deno\.(?:fetch|connect|connectTls|listen)\w*|"""
    r"""Bun\.(?:fetch|connect|serve)\w*)"""
)

# Process spawning indicators
RE_PROC_PYTHON = re.compile(
    r"""\b(?:subprocess\.\w+|os\.system|os\.popen|os\.exec\w+|"""
    r"""multiprocessing\.\w+|threading\.Thread|"""
    r"""Popen|ctypes\.\w+)\b"""
)
RE_PROC_JS = re.compile(
    r"""\b(?:child_process\.\w+|spawn\s*\(|fork\s*\(|"""
    r"""new\s+Worker\s*\(|Worker\s*\(|worker_threads|"""
    r"""cluster\.fork|process\.kill|process\.binding|"""
    r"""execFile\s*\(|execFileSync\s*\(|"""
    r"""Deno\.(?:run|Command)|Bun\.(?:spawn|spawnSync))\b"""
)

# ---------------------------------------------------------------------------
# Compiled regex patterns — Obfuscation
# ---------------------------------------------------------------------------

RE_FROM_CHAR_CODE = re.compile(r"""\bString\.fromCharCode\s*\(""")
RE_CHAR_CODE_AT = re.compile(r"""\.charCodeAt\s*\(""")
RE_ATOB = re.compile(r"""\batob\s*\(""")
RE_BTOA = re.compile(r"""\bbtoa\s*\(""")
RE_BUFFER_FROM_B64 = re.compile(r"""\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)""")
RE_PY_B64_DECODE = re.compile(
    r"""\bbase64\.(?:b64decode|decodebytes|urlsafe_b64decode)\s*\("""
)

# Hex/unicode escape sequences (suspicious density)
RE_HEX_ESCAPE = re.compile(r"""\\x[0-9a-fA-F]{2}""")
RE_UNICODE_ESCAPE = re.compile(r"""\\u[0-9a-fA-F]{4}""")
RE_UNICODE_BRACE = re.compile(r"""\\u\{[0-9a-fA-F]+\}""")

# Obfuscation tools signatures
RE_OBFUSCATOR_SIGNATURE = re.compile(r"""\b(?:_0x[a-f0-9]{4,}|_0X[A-F0-9]{4,})\b""")
# Packer pattern: function(p,a,c,k,e,...) used to pack/hide code
RE_PACKED_FUNC = re.compile(r"""\bfunction\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e""")
RE_JSF_PATTERN = re.compile(r"""\[\]\[['"][^'"]+['"]\]\[['"][^'"]+['"]\]\s*\(""")

# Advanced obfuscation: computed property access to hide require/eval
RE_BRACKET_REQUIRE = re.compile(
    r"""\bglobal\s*\[\s*['"]require['"]\s*\]|"""
    r"""process\s*\[\s*['"](?:mainModule|binding)['"]\s*\]|"""
    r"""\w+\s*\[\s*['"](?:constructor|__proto__|prototype)['"]\s*\]"""
)
# Obfuscated require: module["\x72equire"] or similar
RE_OBFUSCATED_REQUIRE = re.compile(r"""\[\s*['"]\\x[0-9a-fA-F]{2}[^'"]*['"]\s*\]""")
# Prototype pollution patterns
RE_PROTO_POLLUTION = re.compile(
    r"""__proto__|Object\.(?:setPrototypeOf|assign\s*\([^,]+,\s*(?:req|body|params|query))"""
)

# Minimum thresholds for hex/unicode density
HEX_ESCAPE_THRESHOLD = 8  # per line
UNICODE_ESCAPE_THRESHOLD = 6  # per line

# ---------------------------------------------------------------------------
# Compiled regex patterns — Install scripts
# ---------------------------------------------------------------------------

# Telemetry / phone-home patterns in source code
RE_TELEMETRY_CODE = re.compile(
    r"""\b(?:telemetry|analytics|sentry|mixpanel|posthog|amplitude|phone.?home)\b""",
    re.IGNORECASE,
)
# False positive filter: telemetry mentioned only in descriptions/comments
RE_TELEMETRY_FP = re.compile(
    r"""(?:['"].*(?:disable|enable|opt.?out|config|description|about|doc).*['"])""",
    re.IGNORECASE,
)

RE_INSTALL_SCRIPT_KEYS = re.compile(
    r"""["'](?:preinstall|postinstall|preuninstall|postuninstall|"""
    r"""prepare|prepublish|prepublishOnly)["']"""
)

# File extensions
PY_EXTENSIONS = {".py", ".pyw"}
JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx"}
ALL_CODE_EXTENSIONS = PY_EXTENSIONS | JS_EXTENSIONS | {".go"}


from mcp_shield.detectors.code._utils import file_ext as _ext  # noqa: E402


def _basename(path: str) -> str:
    """Get the filename from a path."""
    sep = max(path.rfind("/"), path.rfind("\\"))
    return path[sep + 1 :] if sep != -1 else path


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class PermissionsDetector:
    """Detect excessive permissions, install scripts, and code obfuscation."""

    name: str = "permissions"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        ext = _ext(path)
        basename = _basename(path)

        # Package.json install scripts
        if basename == "package.json":
            findings.extend(self._scan_package_json(content))

        # Code obfuscation (JS/TS and Python)
        if ext in ALL_CODE_EXTENSIONS:
            findings.extend(self._scan_obfuscation(content, ext))

        # Excessive permissions (filesystem + network + process in same file)
        if ext in ALL_CODE_EXTENSIONS:
            findings.extend(self._scan_excessive_permissions(content, ext))

        # Telemetry / phone-home detection in source code
        if ext in ALL_CODE_EXTENSIONS:
            findings.extend(self._scan_telemetry(content))

        return findings

    # -- Package.json install scripts --------------------------------------

    def _scan_package_json(self, content: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return findings

        scripts = data.get("scripts", {})
        if not isinstance(scripts, dict):
            return findings

        dangerous_hooks = {
            "preinstall",
            "postinstall",
            "preuninstall",
            "postuninstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
        }

        for hook_name in dangerous_hooks:
            if hook_name in scripts:
                command = scripts[hook_name]
                severity = Severity.HIGH
                # Flag higher if the hook runs suspicious commands
                if any(
                    kw in str(command).lower()
                    for kw in ("curl", "wget", "fetch", "http", "base64", "node -e")
                ):
                    severity = Severity.CRITICAL
                findings.append(
                    Finding(
                        rule_id="postinstall_script",
                        severity=severity,
                        surface=Surface.SOURCE_CODE,
                        title=f"'{hook_name}' install script in package.json",
                        evidence=f"{hook_name}: {str(command)[:150]}",
                        location="package.json",
                        detail=(
                            f"The '{hook_name}' script runs automatically during "
                            "npm install. Malicious packages abuse this for supply "
                            "chain attacks. Review the command carefully."
                        ),
                    )
                )

        return findings

    # -- Obfuscation detection ---------------------------------------------

    def _scan_obfuscation(self, content: str, ext: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            # String.fromCharCode (JS obfuscation)
            if RE_FROM_CHAR_CODE.search(line):
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.HIGH,
                        surface=Surface.SOURCE_CODE,
                        title="String.fromCharCode() — potential obfuscation",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "String.fromCharCode() is commonly used to obfuscate "
                            "malicious payloads by encoding strings as char codes."
                        ),
                    )
                )

            # atob() — base64 decode in browser/Node
            if RE_ATOB.search(line):
                findings.append(
                    Finding(
                        rule_id="base64_decode",
                        severity=Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="atob() base64 decoding — potential obfuscation",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "atob() decodes base64 strings at runtime. Malicious "
                            "packages use this to hide payloads."
                        ),
                    )
                )

            # btoa() — base64 encode in browser/Node
            if RE_BTOA.search(line):
                findings.append(
                    Finding(
                        rule_id="base64_decode",
                        severity=Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="btoa() base64 encoding — potential data exfiltration",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "btoa() encodes data to base64 at runtime. This can be "
                            "used to obfuscate exfiltrated data."
                        ),
                    )
                )

            # Buffer.from(..., 'base64') in Node
            if RE_BUFFER_FROM_B64.search(line):
                findings.append(
                    Finding(
                        rule_id="base64_decode",
                        severity=Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="Buffer.from(base64) — potential obfuscation",
                        evidence=stripped[:200],
                        location=f"line {i}",
                    )
                )

            # Python base64 decode
            if ext in PY_EXTENSIONS and RE_PY_B64_DECODE.search(line):
                findings.append(
                    Finding(
                        rule_id="base64_decode",
                        severity=Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="base64 decode — potential obfuscation",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "Runtime base64 decoding can hide malicious payloads. "
                            "Verify the decoded content is benign."
                        ),
                    )
                )

            # High density of hex/unicode escapes on a single line
            hex_count = len(RE_HEX_ESCAPE.findall(line))
            unicode_count = len(RE_UNICODE_ESCAPE.findall(line)) + len(
                RE_UNICODE_BRACE.findall(line)
            )

            if hex_count >= HEX_ESCAPE_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.HIGH,
                        surface=Surface.SOURCE_CODE,
                        title=f"Dense hex escapes ({hex_count} on one line)",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "A high density of hex escape sequences suggests "
                            "obfuscated code hiding its true intent."
                        ),
                    )
                )

            if unicode_count >= UNICODE_ESCAPE_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.HIGH,
                        surface=Surface.SOURCE_CODE,
                        title=f"Dense unicode escapes ({unicode_count} on one line)",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "A high density of unicode escape sequences suggests "
                            "obfuscated code hiding its true intent."
                        ),
                    )
                )

            # Known obfuscator variable patterns (_0x4a3b, etc.)
            if RE_OBFUSCATOR_SIGNATURE.search(line):
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title="JavaScript obfuscator signature detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "Variable names matching _0x[hex] are a signature of "
                            "javascript-obfuscator. This is a strong indicator of "
                            "intentionally hidden malicious code."
                        ),
                    )
                )

            # Packer pattern: function(p,a,c,k,e,...) used to pack/hide code
            if RE_PACKED_FUNC.search(line):
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title="Packed/packer obfuscation pattern detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "function(p,a,c,k,e...) is a classic JavaScript "
                            "packer pattern used to hide malicious code."
                        ),
                    )
                )

            # JSFuck-style obfuscation
            if RE_JSF_PATTERN.search(line):
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title="JSFuck-style obfuscation pattern detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                    )
                )

            # Computed property access to hide require/eval
            if RE_BRACKET_REQUIRE.search(line):
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.HIGH,
                        surface=Surface.SOURCE_CODE,
                        title="Computed property access hiding dangerous call",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "Bracket notation to access require/constructor/binding "
                            "is a common obfuscation technique to bypass static analysis."
                        ),
                    )
                )

            # Obfuscated require with hex escapes in bracket notation
            if RE_OBFUSCATED_REQUIRE.search(line):
                if not any(f.location == f"line {i}" for f in findings):
                    findings.append(
                        Finding(
                            rule_id="obfuscated_code",
                            severity=Severity.HIGH,
                            surface=Surface.SOURCE_CODE,
                            title="Hex-escaped string in bracket accessor",
                            evidence=stripped[:200],
                            location=f"line {i}",
                            detail=(
                                "Hex-escaped strings in bracket accessors hide the "
                                "actual property being accessed from static analysis."
                            ),
                        )
                    )

            # Prototype pollution
            if RE_PROTO_POLLUTION.search(line):
                findings.append(
                    Finding(
                        rule_id="obfuscated_code",
                        severity=Severity.HIGH,
                        surface=Surface.SOURCE_CODE,
                        title="Prototype pollution pattern detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "__proto__ or Object.setPrototypeOf with user input "
                            "enables prototype pollution attacks."
                        ),
                    )
                )

        return findings

    # -- Excessive permissions detection -----------------------------------

    def _scan_excessive_permissions(self, content: str, ext: str) -> list[Finding]:
        """Flag files that combine filesystem + network + process capabilities."""
        findings: list[Finding] = []

        if ext in PY_EXTENSIONS:
            has_fs = bool(RE_FS_PYTHON.search(content))
            has_net = bool(RE_NET_PYTHON.search(content))
            has_proc = bool(RE_PROC_PYTHON.search(content))
        elif ext in JS_EXTENSIONS:
            has_fs = bool(RE_FS_JS.search(content))
            has_net = bool(RE_NET_JS.search(content))
            has_proc = bool(RE_PROC_JS.search(content))
        else:
            return findings

        capabilities = []
        if has_fs:
            capabilities.append("filesystem")
        if has_net:
            capabilities.append("network")
        if has_proc:
            capabilities.append("process_spawn")

        # Flag if 3 capabilities are present in same file
        if len(capabilities) >= 3:
            findings.append(
                Finding(
                    rule_id="excessive_permissions",
                    severity=Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title="Excessive permissions: filesystem + network + process",
                    evidence=f"Capabilities detected: {', '.join(capabilities)}",
                    location="file-level",
                    detail=(
                        "This file combines filesystem access, network requests, "
                        "and process spawning. While this can be legitimate, it "
                        "matches the pattern of malicious packages that exfiltrate "
                        "data or install backdoors. Review carefully."
                    ),
                )
            )
        # Also flag fs + net (common exfiltration pattern) but lower severity
        elif has_fs and has_net and not has_proc:
            findings.append(
                Finding(
                    rule_id="excessive_permissions",
                    severity=Severity.LOW,
                    surface=Surface.SOURCE_CODE,
                    title="Combined filesystem + network access",
                    evidence=f"Capabilities detected: {', '.join(capabilities)}",
                    location="file-level",
                    detail=(
                        "This file has both filesystem and network access. "
                        "Verify that file contents are not being exfiltrated."
                    ),
                )
            )

        return findings

    # -- Telemetry / phone-home detection ----------------------------------

    def _scan_telemetry(self, content: str) -> list[Finding]:
        """Detect telemetry and phone-home code in source files."""
        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            if RE_TELEMETRY_CODE.search(line):
                # Filter false positives: config/description strings
                if RE_TELEMETRY_FP.search(line):
                    continue
                findings.append(
                    Finding(
                        rule_id="telemetry_phonehome",
                        severity=Severity.LOW,
                        surface=Surface.SOURCE_CODE,
                        title="Telemetry / phone-home code detected",
                        evidence=stripped[:200],
                        location=f"line {i}",
                        detail=(
                            "This code references a telemetry or analytics service. "
                            "An MCP tool with telemetry may send usage data or "
                            "sensitive context to third-party services."
                        ),
                    )
                )

        return findings
