# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
Grammar-level parsing of .netrc content.

Consumes the token stream produced by :mod:`tag_validate.netrc_tokenizer`
and builds the machine and default credential entries.
"""

from __future__ import annotations

from .netrc_tokenizer import (
    QUOTED_STRING_PATTERN,
    strip_inline_comment,
    tokenize,
    unescape_quoted_string,
)
from .netrc_types import (
    _TOKEN_DEFAULT,
    _TOKEN_LOGIN,
    _TOKEN_MACDEF,
    _TOKEN_MACHINE,
    _TOKEN_PASSWORD,
    NetrcCredentials,
    NetrcParseError,
)

# Tokens that terminate the current entry when encountered mid-entry.
_ENTRY_TERMINATORS = frozenset({_TOKEN_MACHINE, _TOKEN_DEFAULT})


def _skip_newlines(tokens: list[str], i: int) -> int:
    """Return the index of the first non-newline token at or after ``i``."""
    while i < len(tokens) and tokens[i] == "\n":
        i += 1
    return i


def _read_value(tokens: list[str], i: int, keyword: str) -> tuple[int, str]:
    """Read the value following a keyword token at index ``i``.

    Args:
        tokens: Full token stream.
        i: Index of the keyword token itself.
        keyword: Keyword name, used for the error message.

    Returns:
        Tuple of (index after the value, value).

    Raises:
        NetrcParseError: If the stream ends before a value is found.
    """
    msg = f"Expected {keyword} value after '{keyword}'"
    if i + 1 >= len(tokens):
        raise NetrcParseError(msg)
    # Skip any newlines before the value
    i = _skip_newlines(tokens, i + 1)
    if i >= len(tokens):
        raise NetrcParseError(msg)
    return i + 1, tokens[i]


def _skip_macdef(tokens: list[str], i: int) -> int:
    """Skip a macdef section starting at the 'macdef' token index ``i``."""
    # Skip over the 'macdef' token itself
    i += 1
    # Skip over the macro name, if present
    if i < len(tokens) and tokens[i] != "\n":
        i += 1
    # Per netrc spec, the macro body continues until a blank line.
    # A blank line is detected as two consecutive newline tokens.
    consecutive_newlines = 0
    while i < len(tokens):
        if tokens[i] == "\n":
            consecutive_newlines += 1
            if consecutive_newlines >= 2:
                # Found blank line - end of macdef
                i += 1
                break
        else:
            # Any non-newline token resets the blank-line check
            consecutive_newlines = 0
        i += 1
    return i


class NetrcParser:
    """
    Parser for .netrc files.

    Supports the standard netrc format with machine, login, password,
    and default tokens. Also supports quoted strings with escape
    sequences as introduced in curl 7.84.0.
    """

    # Regex for quoted strings with escape sequences
    _QUOTED_STRING_PATTERN = QUOTED_STRING_PATTERN

    def __init__(self, content: str) -> None:
        """
        Initialize parser with file content.

        Args:
            content: The raw content of a .netrc file.
        """
        self._content = content
        self._entries: dict[str, NetrcCredentials] = {}
        self._default: NetrcCredentials | None = None
        self._parse()

    def _unescape_quoted_string(self, s: str) -> str:
        """Unescape a quoted string from netrc format."""
        return unescape_quoted_string(s)

    def _strip_inline_comment(self, text: str) -> str:
        """Strip inline comment from a line, respecting quotes."""
        return strip_inline_comment(text)

    def _tokenize(self, content: str) -> list[str]:
        """Tokenize netrc content, handling quoted strings."""
        return tokenize(content)

    def _parse_machine_entry(
        self, tokens: list[str], start_idx: int
    ) -> tuple[int, NetrcCredentials | None]:
        """Parse a machine entry starting at start_idx."""
        # Skip any newlines after 'machine' keyword
        i = _skip_newlines(tokens, start_idx + 1)
        if i >= len(tokens):
            msg = "Expected machine name after 'machine'"
            raise NetrcParseError(msg)

        machine = tokens[i]
        i, login, password = self._parse_entry_body(tokens, i + 1, macdef=True)

        creds = None
        if login and password:
            creds = NetrcCredentials(
                machine=machine,
                login=login,
                password=password,
            )
        return i, creds

    def _parse_default_entry(
        self, tokens: list[str], start_idx: int
    ) -> tuple[int, NetrcCredentials | None]:
        """Parse a default entry starting at start_idx."""
        i, login, password = self._parse_entry_body(tokens, start_idx + 1, macdef=False)

        creds = None
        if login and password:
            creds = NetrcCredentials(
                machine=_TOKEN_DEFAULT,
                login=login,
                password=password,
            )
        return i, creds

    def _parse_entry_body(
        self, tokens: list[str], start_idx: int, *, macdef: bool
    ) -> tuple[int, str | None, str | None]:
        """Collect login/password tokens until the entry ends.

        Args:
            tokens: Full token stream.
            start_idx: Index of the first token inside the entry body.
            macdef: Whether ``macdef`` sections should be skipped. Only
                machine entries may carry a macro definition.

        Returns:
            Tuple of (index after the entry, login, password).
        """
        i = start_idx
        login: str | None = None
        password: str | None = None

        while i < len(tokens):
            token = tokens[i]
            # Skip newline tokens in normal parsing
            if token == "\n":
                i += 1
                continue
            next_token = token.lower()
            if next_token == _TOKEN_LOGIN:
                i, login = _read_value(tokens, i, _TOKEN_LOGIN)
            elif next_token == _TOKEN_PASSWORD:
                i, password = _read_value(tokens, i, _TOKEN_PASSWORD)
            elif next_token in _ENTRY_TERMINATORS:
                break
            elif macdef and next_token == _TOKEN_MACDEF:
                i = _skip_macdef(tokens, i)
            else:
                i += 1

        return i, login, password

    def _parse(self) -> None:
        """Parse the netrc content into entries."""
        tokens = self._tokenize(self._content)

        i = 0
        while i < len(tokens):
            token = tokens[i]
            # Skip newline tokens at top level
            if token == "\n":
                i += 1
                continue
            current_token = token.lower()

            if current_token == _TOKEN_MACHINE:
                i, creds = self._parse_machine_entry(tokens, i)
                if creds:
                    self._entries[creds.machine.lower()] = creds
            elif current_token == _TOKEN_DEFAULT:
                i, creds = self._parse_default_entry(tokens, i)
                if creds:
                    self._default = creds
            else:
                i += 1

    def get_credentials(self, machine: str) -> NetrcCredentials | None:
        """
        Get credentials for a specific machine.

        Args:
            machine: The hostname to look up credentials for.

        Returns:
            NetrcCredentials if found, None otherwise.
            Falls back to default entry if no specific match.
        """
        # Normalize machine name (case-insensitive lookup)
        normalized = machine.lower().strip()

        # Try exact match first
        if normalized in self._entries:
            return self._entries[normalized]

        # Fall back to default
        return self._default

    @property
    def machines(self) -> list[str]:
        """Return list of all machine names with entries."""
        return list(self._entries.keys())

    @property
    def has_default(self) -> bool:
        """Return True if a default entry exists."""
        return self._default is not None


__all__ = ["NetrcParser"]
