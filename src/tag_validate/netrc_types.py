# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
Shared types and token constants for .netrc handling.

This module holds the vocabulary used across the netrc modules:
the netrc keyword constants, the parse error, and the credential
data structures produced by parsing and resolution.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# Token constants to avoid S105 false positives
_TOKEN_MACHINE = "machine"  # noqa: S105
_TOKEN_LOGIN = "login"  # noqa: S105
_TOKEN_PASSWORD = "password"  # noqa: S105
_TOKEN_DEFAULT = "default"  # noqa: S105
_TOKEN_MACDEF = "macdef"  # noqa: S105


def _normalize_host_for_netrc_lookup(host: str) -> str:
    """Normalize a host string for .netrc lookup.

    Strips scheme (http://, https://), path components, and port numbers
    to produce a clean hostname for credential lookup.

    Args:
        host: Raw host string, may include scheme, port, or path.

    Returns:
        Normalized hostname in lowercase.

    Examples:
        >>> _normalize_host_for_netrc_lookup("https://gerrit.example.org/r")
        'gerrit.example.org'
        >>> _normalize_host_for_netrc_lookup("gerrit.example.org:8080")
        'gerrit.example.org'
        >>> _normalize_host_for_netrc_lookup("GERRIT.EXAMPLE.ORG")
        'gerrit.example.org'
    """
    normalized = host.lower().strip()
    # Remove scheme (http://, https://, etc.)
    if "://" in normalized:
        normalized = normalized.split("://", 1)[1]
    # Remove path components
    if "/" in normalized:
        normalized = normalized.split("/", 1)[0]
    # Remove port number
    if ":" in normalized:
        normalized = normalized.rsplit(":", 1)[0]
    return normalized


class NetrcParseError(Exception):
    """Raised when a .netrc file cannot be parsed."""


class CredentialSource(Enum):
    """Enum indicating the source of resolved credentials."""

    NETRC = "netrc"
    ENVIRONMENT = "environment"
    CLI_ARGUMENT = "cli_argument"
    NONE = "none"


@dataclass(frozen=True)
class GerritCredentials:
    """Resolved Gerrit credentials with source metadata.

    This is the canonical data structure for Gerrit authentication
    credentials. All credential resolution should produce this type,
    and all consumers should accept this type.
    """

    username: str
    password: str
    source: CredentialSource
    source_detail: str  # e.g., "/path/to/.netrc" or "GERRIT_USERNAME"

    def __repr__(self) -> str:
        """Mask password in repr for security."""
        return (
            f"GerritCredentials(username={self.username!r}, "
            f"password='****', source={self.source.value!r}, "
            f"source_detail={self.source_detail!r})"
        )

    @property
    def is_valid(self) -> bool:
        """Return True if credentials are present and non-empty."""
        return bool(self.username and self.password)

    def auth_method_display(self) -> str:
        """Return a human-readable description of the auth method for display."""
        if self.source == CredentialSource.NETRC:
            return f".netrc file ({self.source_detail})"
        elif self.source == CredentialSource.ENVIRONMENT:
            return f"Environment variables ({self.source_detail})"
        elif self.source == CredentialSource.CLI_ARGUMENT:
            return "CLI arguments"
        else:
            return "None"


@dataclass(frozen=True)
class NetrcCredentials:
    """Credentials retrieved from a .netrc file entry."""

    machine: str
    login: str
    password: str

    def __repr__(self) -> str:
        """Mask password in repr for security."""
        return (
            f"NetrcCredentials(machine={self.machine!r}, "
            f"login={self.login!r}, password='****')"
        )


__all__ = [
    "CredentialSource",
    "GerritCredentials",
    "NetrcCredentials",
    "NetrcParseError",
]
