# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
Lexical analysis for .netrc file content.

Turns raw .netrc text into a flat token list, handling comments and
the quoted-string form introduced in curl 7.84.0. Newline tokens are
preserved so the parser can detect the blank line that terminates a
``macdef`` section.
"""

from __future__ import annotations

import re

# Regex for quoted strings with escape sequences
QUOTED_STRING_PATTERN = re.compile(r'"(?:[^"\\]|\\.)*"')

# Escape sequences recognised inside quoted netrc values, mapped to the
# character they produce. Sequences absent from this table are preserved
# verbatim (backslash included), so adding support for a new escape is a
# one-line data change rather than another branch.
_ESCAPE_REPLACEMENTS = {
    '"': '"',
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "\\": "\\",
}

# Marker wrapped around quoted strings while splitting on whitespace.
_PLACEHOLDER_MARKER = "\x00QUOTED"


def unescape_quoted_string(s: str) -> str:
    """
    Unescape a quoted string from netrc format.

    Handles escape sequences: \\", \\n, \\r, \\t

    Args:
        s: Quoted string including surrounding quotes.

    Returns:
        Unescaped string content without quotes.
    """
    # Remove surrounding quotes
    inner = s[1:-1]
    # Process escape sequences
    result: list[str] = []
    i = 0
    while i < len(inner):
        if inner[i] == "\\" and i + 1 < len(inner):
            escape = inner[i : i + 2]
            # Unknown escapes fall back to the raw two-character sequence.
            result.append(_ESCAPE_REPLACEMENTS.get(inner[i + 1], escape))
            i += 2
        else:
            result.append(inner[i])
            i += 1
    return "".join(result)


def strip_inline_comment(text: str) -> str:
    """Strip inline comment from a line, respecting quotes."""
    if "#" not in text:
        return text
    in_quotes = False
    for i, char in enumerate(text):
        if char == '"' and (i == 0 or text[i - 1] != "\\"):
            in_quotes = not in_quotes
        elif char == "#" and not in_quotes:
            return text[:i]
    return text


def _strip_comments(content: str) -> list[str]:
    """Return content lines with comments removed.

    Whole-line comments collapse to an empty string so that the blank-line
    bookkeeping used for macdef parsing stays intact.
    """
    lines: list[str] = []
    for raw_line in content.splitlines():
        # Strip leading whitespace to check for comment
        stripped = raw_line.lstrip()
        if stripped.startswith("#"):
            # Preserve blank line marker for macdef parsing
            lines.append("")
            continue
        # Handle inline comments
        lines.append(strip_inline_comment(raw_line))
    return lines


def _restore_placeholders(raw_token: str, placeholders: dict[str, str]) -> str:
    """Substitute any quoted-string placeholders embedded in a token."""
    processed_token = raw_token
    for placeholder, quoted in placeholders.items():
        if placeholder in processed_token:
            processed_token = processed_token.replace(
                placeholder, unescape_quoted_string(quoted)
            )
    return processed_token


def tokenize(content: str) -> list[str]:
    """
    Tokenize netrc content, handling quoted strings.

    Preserves newline tokens ("\n") to support proper macdef parsing.
    Per netrc spec, macdef sections end at a blank line (two consecutive
    newlines), so we need to preserve newline information.

    Args:
        content: Raw netrc file content.

    Returns:
        List of tokens, including "\n" tokens for line boundaries.
    """
    tokens: list[str] = []
    # Process line by line to preserve newline information
    lines = _strip_comments(content)

    # Find all quoted strings and replace with placeholders
    placeholders: dict[str, str] = {}
    placeholder_idx = 0

    def replace_quoted(match: re.Match[str]) -> str:
        nonlocal placeholder_idx
        placeholder = f"{_PLACEHOLDER_MARKER}{placeholder_idx}\x00"
        placeholders[placeholder] = match.group(0)
        placeholder_idx += 1
        return placeholder

    # Process each line, preserving newline tokens
    for line in lines:
        # Replace quoted strings with placeholders
        processed_line = QUOTED_STRING_PATTERN.sub(replace_quoted, line)

        # Split on whitespace
        raw_tokens = processed_line.split()

        # Restore quoted strings and unescape
        for raw_token in raw_tokens:
            if raw_token in placeholders:
                tokens.append(unescape_quoted_string(placeholders[raw_token]))
            elif _PLACEHOLDER_MARKER in raw_token:
                # Handle case where placeholder is part of larger token
                tokens.append(_restore_placeholders(raw_token, placeholders))
            else:
                tokens.append(raw_token)

        # Add newline token to mark end of line
        tokens.append("\n")

    return tokens


__all__ = [
    "QUOTED_STRING_PATTERN",
    "strip_inline_comment",
    "tokenize",
    "unescape_quoted_string",
]
