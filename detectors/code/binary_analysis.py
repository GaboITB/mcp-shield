"""Binary analysis detector for MCP Shield v3.

Analyzes compiled Go/Rust/C MCP server binaries using 100% stdlib.
Extracts strings, measures entropy, and detects suspicious patterns
without executing the binary.

Capabilities:
- Magic byte detection (ELF, PE, Mach-O)
- Printable string extraction (like Unix `strings`)
- Shannon entropy calculation (detects packed/encrypted sections)
- Suspicious string pattern matching (URLs, IPs, shell commands)
- Go/Rust import detection (net/http, os/exec, crypto)
- Hardcoded credential patterns in binary strings

Zero dependencies — uses only struct, re, math from stdlib.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# File type detection via magic bytes
# ---------------------------------------------------------------------------

# ELF: \x7fELF
MAGIC_ELF = b"\x7fELF"
# PE: MZ
MAGIC_PE = b"MZ"
# Mach-O: \xfe\xed\xfa\xce (32-bit) or \xfe\xed\xfa\xcf (64-bit) or \xcf\xfa\xed\xfe (LE)
MAGIC_MACHO = (
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
)

BINARY_EXTENSIONS = {".exe", ".bin", ".elf", ".so", ".dll", ".dylib", ""}

# Minimum file size to analyze (skip tiny files)
MIN_BINARY_SIZE = 4096
# Minimum string length to extract
MIN_STRING_LEN = 6
# Maximum file size to analyze (skip huge files to avoid memory issues)
MAX_BINARY_SIZE = 100 * 1024 * 1024  # 100 MB


def _is_binary(path: str, content: str) -> bool:
    """Check if a file is a compiled binary based on magic bytes and extension."""
    raw = (
        content.encode("latin-1", errors="replace")
        if isinstance(content, str)
        else content
    )

    if len(raw) < 4:
        return False

    # Check magic bytes
    if raw[:4] == MAGIC_ELF:
        return True
    if raw[:2] == MAGIC_PE:
        return True
    for magic in MAGIC_MACHO:
        if raw[:4] == magic:
            return True

    # Check extension
    dot = path.rfind(".")
    ext = path[dot:].lower() if dot != -1 else ""
    if ext in BINARY_EXTENSIONS and _has_high_null_ratio(raw[:1024]):
        return True

    return False


def _has_high_null_ratio(data: bytes) -> bool:
    """Check if data has a high ratio of null bytes (binary indicator)."""
    if not data:
        return False
    null_count = data.count(b"\x00")
    return null_count / len(data) > 0.1


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

# Match sequences of printable ASCII characters
RE_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)


def _extract_strings(raw: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    """Extract printable ASCII strings from binary data (like `strings`)."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.group(0).decode("ascii", errors="replace") for m in pattern.finditer(raw)]


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0

    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def _section_entropies(raw: bytes, section_size: int = 65536) -> list[float]:
    """Calculate entropy for each section of the binary."""
    entropies = []
    for i in range(0, len(raw), section_size):
        section = raw[i : i + section_size]
        if len(section) >= 256:  # Skip tiny trailing sections
            entropies.append(_shannon_entropy(section))
    return entropies


# ---------------------------------------------------------------------------
# Suspicious pattern detection in extracted strings
# ---------------------------------------------------------------------------

# Network-related strings (Go/Rust imports and URLs)
RE_HTTP_URL = re.compile(r"https?://[^\s\"'<>]{5,}")
RE_IP_ADDR = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b")
RE_DOMAIN = re.compile(r"\b[a-z0-9][-a-z0-9]*\.[a-z]{2,}\b", re.IGNORECASE)

# Go import paths — suspicious capabilities
RE_GO_NET = re.compile(r"net/http|net/rpc|net\.Dial|net\.Listen")
RE_GO_EXEC = re.compile(r"os/exec|syscall\.Exec|syscall\.ForkExec")
RE_GO_FILE = re.compile(r"os\.Open|os\.Create|os\.ReadFile|os\.WriteFile|io/ioutil")
RE_GO_CRYPTO = re.compile(r"crypto/aes|crypto/cipher|crypto/tls|crypto/rand")
RE_GO_UNSAFE = re.compile(r"\bunsafe\.Pointer\b")
RE_GO_CGO = re.compile(r"\b_cgo_|cgo_import_dynamic\b")
RE_GO_REFLECT = re.compile(r"\breflect\.(?:Value|Type|SliceHeader)\b")

# Rust patterns
RE_RUST_NET = re.compile(r"std::net|tokio::net|hyper::|reqwest::|TcpStream")
RE_RUST_EXEC = re.compile(r"std::process::Command|nix::unistd::exec")
RE_RUST_FILE = re.compile(r"std::fs::|tokio::fs::|std::io::Read|std::io::Write")
RE_RUST_UNSAFE = re.compile(r"\bunsafe\s*\{|\bunsafe\s+fn\b")

# Shell commands embedded in binary
RE_SHELL_CMD = re.compile(
    r"(?:/bin/(?:sh|bash|zsh|dash)\b|/usr/bin/env\s+(?:sh|bash|python|node)|"
    r"\bcmd\.exe\b|\bpowershell\b|\bcurl\s|\bwget\s|\bnc\s+-|\bncat\s|\bsocat\s)"
)

# Credential/secret patterns in strings
RE_BINARY_SECRET = re.compile(
    r"(?:password|passwd|secret|api_key|apikey|token|bearer|auth)" r"\s*[=:]\s*\S{4,}",
    re.IGNORECASE,
)

# Suspicious base64 blobs (high entropy strings that look like base64)
RE_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# C2/backdoor indicators — must be specific to avoid false positives
# on legitimate Go/Rust binaries (payload, beacon, screenshot are too generic)
RE_C2_PATTERN = re.compile(
    r"(?:reverse.?shell|bind.?shell|meterpreter|cobalt.?strike|"
    r"\bc2[-_](?:server|channel|beacon|callback)\b|"
    r"backdoor.?(?:install|connect|listen)|"
    r"rootkit|keylogger|"
    r"exfiltrat(?:e|ion).?(?:data|file|secret)|"
    r"shellcode|inject.?payload|dropper)",
    re.IGNORECASE,
)

# Known malicious user-agents
RE_SUSPICIOUS_UA = re.compile(
    r"(?:Mozilla/4\.0|MSIE\s+6\.0|python-requests/1\.)",
    re.IGNORECASE,
)

# High entropy threshold (packed/encrypted sections)
HIGH_ENTROPY_THRESHOLD = 7.5  # Max is 8.0, normal code is ~5-6
# Percentage of high-entropy sections to flag
HIGH_ENTROPY_PERCENT = 0.6


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------


@dataclass
class BinaryAnalysisDetector:
    """Detect suspicious patterns in compiled binary MCP servers."""

    name: str = "binary_analysis"

    def scan_file(self, path: str, content: str) -> list[Finding]:
        """Analyze a binary file for suspicious patterns."""
        # Convert content to bytes for binary analysis
        raw = content.encode("latin-1", errors="replace")

        # Only analyze binary files
        if not _is_binary(path, content):
            return []

        if len(raw) < MIN_BINARY_SIZE:
            return []

        if len(raw) > MAX_BINARY_SIZE:
            return [
                Finding(
                    rule_id="binary_oversized",
                    severity=Severity.LOW,
                    surface=Surface.SOURCE_CODE,
                    title="Binary file too large to analyze",
                    evidence=f"Size: {len(raw) / 1024 / 1024:.1f} MB (limit: {MAX_BINARY_SIZE / 1024 / 1024:.0f} MB)",
                    location=path,
                )
            ]

        findings: list[Finding] = []

        # Detect binary type
        bin_type = self._detect_type(raw)
        if bin_type:
            findings.append(
                Finding(
                    rule_id="binary_detected",
                    severity=Severity.INFO,
                    surface=Surface.SOURCE_CODE,
                    title=f"Compiled {bin_type} binary detected",
                    evidence=f"File: {path} ({len(raw)} bytes)",
                    location=path,
                    detail=(
                        "This MCP server is distributed as a compiled binary. "
                        "Source code is not available for full analysis. "
                        "Binary analysis results follow."
                    ),
                )
            )

        # Extract strings
        strings = _extract_strings(raw)

        # Detect if this is a Go binary (used to reduce FP severity)
        all_strings_text = "\n".join(strings)
        is_go = bool(
            re.search(r"runtime\.gopanic|go\.buildid|GOROOT|GOPATH", all_strings_text)
        )

        # Analyze strings for suspicious patterns
        findings.extend(self._analyze_strings(strings, path, is_go=is_go))

        # Entropy analysis
        findings.extend(self._analyze_entropy(raw, path))

        # Go/Rust import detection
        findings.extend(self._detect_imports(strings, path))

        return findings

    def _detect_type(self, raw: bytes) -> str | None:
        """Identify the binary format."""
        if raw[:4] == MAGIC_ELF:
            return "ELF (Linux)"
        if raw[:2] == MAGIC_PE:
            return "PE (Windows)"
        for magic in MAGIC_MACHO:
            if raw[:4] == magic:
                return "Mach-O (macOS)"
        return None

    def _analyze_strings(
        self, strings: list[str], path: str, is_go: bool = False
    ) -> list[Finding]:
        """Analyze extracted strings for suspicious patterns."""
        findings: list[Finding] = []
        seen_urls: set[str] = set()

        # Cap per rule to avoid flooding on large binaries
        MAX_PER_RULE = 5
        rule_counts: dict[str, int] = {}

        def _add(finding: Finding) -> None:
            rid = finding.rule_id
            rule_counts[rid] = rule_counts.get(rid, 0) + 1
            if rule_counts[rid] <= MAX_PER_RULE:
                findings.append(finding)

        for s in strings:
            # HTTP URLs (potential C2 or exfiltration endpoints)
            for m in RE_HTTP_URL.finditer(s):
                url = m.group(0)
                if url not in seen_urls:
                    seen_urls.add(url)
                    # Skip common legitimate URLs (Go/Rust/Node ecosystem)
                    if not any(
                        safe in url
                        for safe in (
                            "golang.org",
                            "go.dev",
                            "github.com",
                            "githubusercontent.com",
                            "googleapis.com",
                            "google.com",
                            "microsoft.com",
                            "azure.com",
                            "amazonaws.com",
                            "cloudflare.com",
                            "rust-lang.org",
                            "crates.io",
                            "npmjs.org",
                            "npmjs.com",
                            "nodejs.org",
                            "openssl.org",
                            "w3.org",
                            "ietf.org",
                            "mozilla.org",
                            "apache.org",
                            "json-schema.org",
                            "schema.org",
                            "graphql.org",
                            "localhost",
                            "127.0.0.1",
                            "0.0.0.0",
                            "example.com",
                            "example.org",
                            "tools.ietf.org",
                            "creativecommons.org",
                            "spdx.org",
                        )
                    ):
                        _add(
                            Finding(
                                rule_id="binary_url",
                                severity=Severity.LOW,
                                surface=Surface.SOURCE_CODE,
                                title="URL found in binary",
                                evidence=url[:200],
                                location=path,
                                detail=(
                                    "An HTTP URL was found in the binary. This may be "
                                    "a legitimate API endpoint or a C2/exfiltration target."
                                ),
                            )
                        )

            # Shell commands — LOW for Go (stdlib help strings)
            if RE_SHELL_CMD.search(s):
                _add(
                    Finding(
                        rule_id="binary_shell_cmd",
                        severity=Severity.LOW if is_go else Severity.MEDIUM,
                        surface=Surface.SOURCE_CODE,
                        title="Shell command reference in binary",
                        evidence=s[:200],
                        location=path,
                        detail=(
                            "A reference to a shell interpreter or command-line tool "
                            "was found in the binary strings."
                        ),
                    )
                )

            # Credential patterns — filter help/usage strings
            m_secret = RE_BINARY_SECRET.search(s)
            if m_secret:
                val = m_secret.group(0)
                # Skip common false positives in binaries
                is_fp = len(val) < 15 or any(  # too short
                    kw in s.lower()
                    for kw in (
                        "usage",
                        "help",
                        "flag",
                        "option",
                        "config",
                        "example",
                        "placeholder",
                        "default",
                        "format",
                        "description",
                        "specify",
                        "provide",
                        "required",
                    )
                )
                if not is_fp:
                    _add(
                        Finding(
                            rule_id="binary_secret",
                            severity=Severity.MEDIUM,
                            surface=Surface.SOURCE_CODE,
                            title="Credential pattern in binary strings",
                            evidence=s[:100] + "...",
                            location=path,
                            detail=(
                                "A string matching a credential assignment pattern was "
                                "found in the binary. This may be a hardcoded secret."
                            ),
                        )
                    )

            # C2/backdoor indicators
            if RE_C2_PATTERN.search(s):
                _add(
                    Finding(
                        rule_id="binary_c2_indicator",
                        severity=Severity.CRITICAL,
                        surface=Surface.SOURCE_CODE,
                        title="C2/backdoor indicator in binary",
                        evidence=s[:200],
                        location=path,
                        detail=(
                            "A string associated with command-and-control frameworks "
                            "or backdoor tools was found in the binary."
                        ),
                    )
                )

        # Large base64 blobs (potential embedded payloads)
        all_text = " ".join(strings)
        b64_matches = RE_BASE64_BLOB.findall(all_text)
        large_b64 = [b for b in b64_matches if len(b) > 200]
        if len(large_b64) > 10:
            _add(
                Finding(
                    rule_id="binary_embedded_payload",
                    severity=Severity.LOW if is_go else Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title=f"Multiple large base64 blobs ({len(large_b64)}) in binary",
                    evidence=f"Found {len(large_b64)} base64 strings > 100 chars",
                    location=path,
                    detail=(
                        "Multiple large base64-encoded strings suggest embedded "
                        "payloads or obfuscated data in the binary."
                    ),
                )
            )

        return findings

    def _analyze_entropy(self, raw: bytes, path: str) -> list[Finding]:
        """Check for high-entropy sections (packed/encrypted binary)."""
        findings: list[Finding] = []
        entropies = _section_entropies(raw)

        if not entropies:
            return findings

        avg_entropy = sum(entropies) / len(entropies)
        high_sections = sum(1 for e in entropies if e > HIGH_ENTROPY_THRESHOLD)
        high_ratio = high_sections / len(entropies) if entropies else 0

        if high_ratio > HIGH_ENTROPY_PERCENT:
            findings.append(
                Finding(
                    rule_id="binary_high_entropy",
                    severity=Severity.LOW,
                    surface=Surface.SOURCE_CODE,
                    title="Binary has high entropy (likely packed/encrypted)",
                    evidence=(
                        f"Avg entropy: {avg_entropy:.2f}/8.0, "
                        f"{high_sections}/{len(entropies)} sections > {HIGH_ENTROPY_THRESHOLD}"
                    ),
                    location=path,
                    detail=(
                        "A high percentage of the binary has near-maximum entropy, "
                        "suggesting it is packed, encrypted, or contains compressed "
                        "payloads. Legitimate Go/Rust binaries typically have "
                        "entropy around 5-6."
                    ),
                )
            )

        max_entropy = max(entropies) if entropies else 0
        if max_entropy > 7.9:
            findings.append(
                Finding(
                    rule_id="binary_encrypted_section",
                    severity=Severity.MEDIUM,
                    surface=Surface.SOURCE_CODE,
                    title="Binary section with near-maximum entropy",
                    evidence=f"Max section entropy: {max_entropy:.3f}/8.0",
                    location=path,
                    detail=(
                        "At least one section has near-random entropy (>7.9), "
                        "suggesting encryption or strong compression."
                    ),
                )
            )

        return findings

    def _detect_imports(self, strings: list[str], path: str) -> list[Finding]:
        """Detect Go/Rust imports and capabilities from strings."""
        findings: list[Finding] = []
        all_text = "\n".join(strings)

        # Detect if this is a Go binary — Go binaries always contain
        # runtime strings like "runtime.gopanic", "go.buildid", etc.
        is_go = bool(re.search(r"runtime\.gopanic|go\.buildid|GOROOT|GOPATH", all_text))

        # Go capabilities are expected in Go MCP servers (they need net/http
        # for the protocol and often os/exec for commands). Reduce severity
        # to INFO for Go binaries.
        cap_severity = Severity.INFO if is_go else Severity.MEDIUM
        combo_severity = Severity.MEDIUM if is_go else Severity.HIGH

        # Go imports
        go_capabilities: list[tuple[re.Pattern, str, str]] = [
            (
                RE_GO_EXEC,
                "Go os/exec",
                "Process execution capability (os/exec or syscall)",
            ),
            (RE_GO_NET, "Go net/http", "Network capability (HTTP client/server)"),
            (RE_GO_UNSAFE, "Go unsafe", "Unsafe memory operations (unsafe.Pointer)"),
            (RE_GO_CGO, "Go CGO", "CGO bindings (native code execution)"),
        ]

        # Rust imports
        rust_capabilities: list[tuple[re.Pattern, str, str]] = [
            (
                RE_RUST_EXEC,
                "Rust process",
                "Process execution capability (std::process::Command)",
            ),
            (RE_RUST_NET, "Rust network", "Network capability (TCP/HTTP client)"),
            (RE_RUST_UNSAFE, "Rust unsafe", "Unsafe blocks (raw pointer operations)"),
        ]

        for pattern, label, detail in go_capabilities + rust_capabilities:
            matches = pattern.findall(all_text)
            if matches:
                findings.append(
                    Finding(
                        rule_id="binary_capability",
                        severity=cap_severity,
                        surface=Surface.SOURCE_CODE,
                        title=f"Binary capability: {label}",
                        evidence=", ".join(set(matches[:5])),
                        location=path,
                        detail=detail
                        + (" (expected for Go binaries)" if is_go else ""),
                    )
                )

        # Check for combined dangerous capabilities
        has_exec = bool(RE_GO_EXEC.search(all_text) or RE_RUST_EXEC.search(all_text))
        has_net = bool(RE_GO_NET.search(all_text) or RE_RUST_NET.search(all_text))
        has_file = bool(RE_GO_FILE.search(all_text) or RE_RUST_FILE.search(all_text))

        if has_exec and has_net:
            findings.append(
                Finding(
                    rule_id="binary_excessive_caps",
                    severity=combo_severity,
                    surface=Surface.SOURCE_CODE,
                    title="Binary has both execution and network capabilities",
                    evidence="Process execution + network access detected in binary imports"
                    + (" (standard for Go MCP servers)" if is_go else ""),
                    location=path,
                    detail=(
                        "The binary can both execute processes and make network "
                        "requests. This combination enables command-and-control "
                        "and data exfiltration patterns."
                    ),
                )
            )

        if has_exec and has_net and has_file:
            findings.append(
                Finding(
                    rule_id="binary_excessive_caps",
                    severity=combo_severity,
                    surface=Surface.SOURCE_CODE,
                    title="Binary has exec + network + filesystem capabilities",
                    evidence="Full capability triad: exec + net + fs"
                    + (" (standard for Go MCP servers)" if is_go else ""),
                    location=path,
                    detail=(
                        "The binary combines process execution, network access, "
                        "and filesystem operations. This is the classic malware "
                        "capability pattern: read files, execute commands, exfiltrate."
                    ),
                )
            )

        return findings
