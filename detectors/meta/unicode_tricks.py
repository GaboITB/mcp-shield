"""Unicode-based attack detectors for MCP tool metadata.

Two detectors in one module:
- UnicodeInvisibleDetector: zero-width chars, invisible formatters, control chars
- HomoglyphDetector: Cyrillic/Greek lookalikes substituted for Latin letters
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Invisible / control character ranges
# ---------------------------------------------------------------------------

# Zero-width and invisible formatting characters
_INVISIBLE_RANGES: list[tuple[int, int, str]] = [
    (0x200B, 0x200F, "zero-width / directional mark"),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    (
        0x2028,
        0x202F,
        "line/paragraph separator / embedding",
    ),  # LS, PS, LRE, RLE, PDF, LRO, RLO, NNBSP
    (
        0x2060,
        0x206F,
        "invisible operator / inhibitor",
    ),  # WJ, function application, etc.
    (0xFEFF, 0xFEFF, "byte order mark (BOM)"),  # BOM / ZWNBSP
    (0xFFF0, 0xFFF8, "specials block"),  # interlinear annotation anchors
]

# C0 control characters (except \t=0x09, \n=0x0A, \r=0x0D)
_C0_ALLOWED = {0x09, 0x0A, 0x0D}

# C1 control characters
_C1_RANGE = (0x007F, 0x009F)

# Build a single regex class for invisible chars
_invisible_chars = ""
for start, end, _ in _INVISIBLE_RANGES:
    _invisible_chars += f"\\u{start:04X}-\\u{end:04X}"
_RE_INVISIBLE = re.compile(f"[{_invisible_chars}]")

# Control character patterns
_RE_C0_CONTROL = re.compile(r"[\u0000-\u0008\u000B\u000C\u000E-\u001F]")
_RE_C1_CONTROL = re.compile(r"[\u007F-\u009F]")


def _find_invisible(text: str) -> list[tuple[str, int, str]]:
    """Return list of (char_repr, position, category) for invisible chars."""
    hits: list[tuple[str, int, str]] = []

    for m in _RE_INVISIBLE.finditer(text):
        cp = ord(m.group())
        cat = "invisible unicode"
        for start, end, label in _INVISIBLE_RANGES:
            if start <= cp <= end:
                cat = label
                break
        hits.append((f"U+{cp:04X}", m.start(), cat))

    for m in _RE_C0_CONTROL.finditer(text):
        cp = ord(m.group())
        if cp not in _C0_ALLOWED:
            hits.append((f"U+{cp:04X}", m.start(), "C0 control character"))

    for m in _RE_C1_CONTROL.finditer(text):
        cp = ord(m.group())
        hits.append((f"U+{cp:04X}", m.start(), "C1 control character"))

    return hits


class UnicodeInvisibleDetector:
    """Detect invisible Unicode characters and control characters in metadata."""

    name: str = "unicode_invisible"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Scan tool name (higher severity — names should be pure ASCII)
        for char_repr, pos, category in _find_invisible(tool_name):
            findings.append(
                Finding(
                    rule_id="unicode_invisible",
                    severity=Severity.CRITICAL,
                    surface=Surface.MCP_METADATA,
                    title=f"Invisible character in tool name: {char_repr}",
                    evidence=f"char {char_repr} at position {pos} ({category})",
                    location=tool_name,
                    detail=(
                        f"Tool name contains {category} character {char_repr}. "
                        "This can hide malicious content or confuse tool routing."
                    ),
                )
            )

        # Scan description
        for char_repr, pos, category in _find_invisible(description):
            findings.append(
                Finding(
                    rule_id="unicode_invisible",
                    severity=Severity.HIGH,
                    surface=Surface.MCP_METADATA,
                    title=f"Invisible character in description: {char_repr}",
                    evidence=f"char {char_repr} at position {pos} ({category})",
                    location=tool_name,
                    detail=(
                        f"Description contains {category} character {char_repr}. "
                        "Invisible characters can hide injected instructions."
                    ),
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Homoglyph detection
# ---------------------------------------------------------------------------

# Mapping: confusable codepoint -> (ASCII equivalent, script name)
_HOMOGLYPH_MAP: dict[str, tuple[str, str]] = {
    # Cyrillic lookalikes
    "\u0430": ("a", "Cyrillic"),  # а
    "\u0435": ("e", "Cyrillic"),  # е
    "\u0454": ("e", "Cyrillic"),  # є (Ukrainian)
    "\u043e": ("o", "Cyrillic"),  # о
    "\u043f": ("n", "Cyrillic"),  # п (visually similar to n in some fonts)
    "\u0440": ("p", "Cyrillic"),  # р
    "\u0441": ("c", "Cyrillic"),  # с
    "\u0443": ("y", "Cyrillic"),  # у
    "\u0445": ("x", "Cyrillic"),  # х
    "\u0456": ("i", "Cyrillic"),  # і (Ukrainian/Belarusian)
    "\u0458": ("j", "Cyrillic"),  # ј (Serbian)
    "\u04bb": ("h", "Cyrillic"),  # һ (Bashkir)
    "\u0501": ("d", "Cyrillic"),  # ԁ
    "\u051b": ("q", "Cyrillic"),  # ԛ
    "\u051d": ("w", "Cyrillic"),  # ԝ
    # Cyrillic uppercase
    "\u0410": ("A", "Cyrillic"),  # А
    "\u0412": ("B", "Cyrillic"),  # В
    "\u0415": ("E", "Cyrillic"),  # Е
    "\u041a": ("K", "Cyrillic"),  # К
    "\u041c": ("M", "Cyrillic"),  # М
    "\u041d": ("H", "Cyrillic"),  # Н
    "\u041e": ("O", "Cyrillic"),  # О
    "\u0420": ("P", "Cyrillic"),  # Р
    "\u0421": ("C", "Cyrillic"),  # С
    "\u0422": ("T", "Cyrillic"),  # Т
    "\u0425": ("X", "Cyrillic"),  # Х
    # Greek lookalikes
    "\u03b1": ("a", "Greek"),  # α
    "\u03b5": ("e", "Greek"),  # ε (less confusable but flagged)
    "\u03bf": ("o", "Greek"),  # ο
    "\u03c1": ("p", "Greek"),  # ρ
    "\u03c5": ("u", "Greek"),  # υ
    "\u03ba": ("k", "Greek"),  # κ
    "\u03bd": ("v", "Greek"),  # ν
    # Latin extended lookalikes
    "\u0131": ("i", "Latin Extended"),  # ı (dotless i)
    "\u1d00": ("A", "Latin Phonetic"),  # ᴀ (small capital)
}

# Regex: any non-ASCII character
_RE_NON_ASCII = re.compile(r"[^\x00-\x7F]")


class HomoglyphDetector:
    """Detect homoglyph (lookalike character) substitutions in tool metadata."""

    name: str = "homoglyph_spoofing"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # --- Tool name: check for known homoglyphs ---
        homoglyphs_found: list[tuple[str, str, str, int]] = []
        for i, ch in enumerate(tool_name):
            if ch in _HOMOGLYPH_MAP:
                ascii_eq, script = _HOMOGLYPH_MAP[ch]
                homoglyphs_found.append((ch, ascii_eq, script, i))

        if homoglyphs_found:
            evidence_parts = [
                f"'{h[0]}' (U+{ord(h[0]):04X}, {h[2]}) looks like '{h[1]}' at pos {h[3]}"
                for h in homoglyphs_found
            ]
            findings.append(
                Finding(
                    rule_id="homoglyph_spoofing",
                    severity=Severity.CRITICAL,
                    surface=Surface.MCP_METADATA,
                    title=f"Homoglyph characters in tool name ({len(homoglyphs_found)} found)",
                    evidence="; ".join(evidence_parts)[:300],
                    location=tool_name,
                    detail=(
                        "Tool name contains characters from non-Latin scripts that "
                        "visually resemble ASCII letters. This is a classic spoofing "
                        "technique to impersonate legitimate tools."
                    ),
                )
            )

        # --- Tool name: flag any remaining non-ASCII (even if not known homoglyph) ---
        non_ascii_matches = _RE_NON_ASCII.findall(tool_name)
        # Filter out chars already reported as homoglyphs
        unknown_non_ascii = [ch for ch in non_ascii_matches if ch not in _HOMOGLYPH_MAP]
        if unknown_non_ascii:
            chars_repr = ", ".join(f"U+{ord(c):04X}" for c in unknown_non_ascii[:10])
            findings.append(
                Finding(
                    rule_id="homoglyph_spoofing",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title="Non-ASCII characters in tool name",
                    evidence=f"Characters: {chars_repr}",
                    location=tool_name,
                    detail=(
                        "Tool names should be pure ASCII. Non-ASCII characters "
                        "may indicate homoglyph spoofing with unmapped confusables."
                    ),
                )
            )

        # --- Description: check for homoglyphs (lower severity, higher noise) ---
        desc_homoglyphs: list[tuple[str, str, str]] = []
        for ch in description:
            if ch in _HOMOGLYPH_MAP:
                ascii_eq, script = _HOMOGLYPH_MAP[ch]
                if (ch, ascii_eq, script) not in desc_homoglyphs:
                    desc_homoglyphs.append((ch, ascii_eq, script))

        if desc_homoglyphs:
            evidence_parts = [
                f"'{h[0]}' (U+{ord(h[0]):04X}, {h[2]}) ≈ '{h[1]}'"
                for h in desc_homoglyphs[:5]
            ]
            findings.append(
                Finding(
                    rule_id="homoglyph_spoofing",
                    severity=Severity.HIGH,
                    surface=Surface.MCP_METADATA,
                    title=f"Homoglyph characters in description ({len(desc_homoglyphs)} unique)",
                    evidence="; ".join(evidence_parts)[:300],
                    location=tool_name,
                    detail=(
                        "Description contains visually confusable characters from "
                        "non-Latin scripts. May be used to hide injected instructions."
                    ),
                )
            )

        return findings
