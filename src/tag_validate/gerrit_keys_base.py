# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Configuration and credential handling for the Gerrit keys client.

Owns server resolution and the credential precedence rules, leaving the
REST transport and key operations to the subclasses.
"""

import logging
from pathlib import Path
from urllib.parse import urlparse

from pygerrit2 import GerritRestAPI

from .gerrit_keys_errors import GerritKeysError
from .netrc import GerritCredentials, resolve_gerrit_credentials

# Bound to the public module's name so log records keep reporting
# `tag_validate.gerrit_keys` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.gerrit_keys")


class GerritKeysClientBase:
    """Server and credential configuration shared by Gerrit key clients."""

    def __init__(
        self,
        server: str | None = None,
        github_org: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 30.0,
        logger_instance: logging.Logger | None = None,
        use_netrc: bool = True,
        netrc_file: Path | None = None,
        credentials: GerritCredentials | None = None,
    ):
        """
        Initialize Gerrit keys client.

        Args:
            server: Gerrit server hostname or URL. If None, will be
                auto-discovered from github_org.
            github_org: GitHub organization name for server discovery
                (e.g., "onap" -> "gerrit.onap.org").
            username: Gerrit username for HTTP authentication (optional, deprecated).
            password: Gerrit HTTP password for authentication (optional, deprecated).
            timeout: Request timeout in seconds.
            logger_instance: Optional logger instance for client messages.
            use_netrc: Whether to try .netrc for credentials (default: True).
            netrc_file: Explicit path to a .netrc file (optional).
            credentials: Pre-resolved GerritCredentials object (preferred).

        Credential Resolution Order:
            1. Pre-resolved GerritCredentials object (if provided)
            2. Explicit username/password arguments
            3. .netrc file (if use_netrc=True)
            4. Environment variables: GERRIT_USERNAME/GERRIT_PASSWORD

        Security Note:
            Credentials (password) are stored in memory only for the duration
            of operations and are never logged or included in error messages.
            The password is masked in string representations to prevent
            accidental exposure in debugging output.

        Raises:
            GerritKeysError: If neither server nor github_org is provided.
        """
        self.logger: logging.Logger = logger_instance or logger
        self.timeout: float = timeout

        # Determine which server we're connecting to
        if server:
            self.server = self._normalize_server_url(server)
        elif github_org:
            self.server = self._discover_server_from_github_org(github_org)
        else:
            raise GerritKeysError("Either server or github_org must be provided")

        # Store the resolved credentials for later access
        self._credentials: GerritCredentials | None = None

        # Initialize credentials with explicit type annotations
        self.username: str | None = None
        self.password: str | None = None

        self._apply_credentials(
            credentials=credentials,
            username=username,
            password=password,
            use_netrc=use_netrc,
            netrc_file=netrc_file,
        )

        self._rest: GerritRestAPI | None = None
        self._base_url: str = ""

    def _apply_credentials(
        self,
        *,
        credentials: GerritCredentials | None,
        username: str | None,
        password: str | None,
        use_netrc: bool,
        netrc_file: Path | None,
    ) -> None:
        """Resolve and store credentials following the documented precedence."""
        # Use pre-resolved credentials if provided
        if credentials is not None and credentials.is_valid:
            self.username = credentials.username
            self.password = credentials.password
            self._credentials = credentials
            self.logger.debug(
                "Using pre-resolved credentials from %s",
                credentials.auth_method_display(),
            )
            return

        # Resolve credentials using centralized function
        resolved = resolve_gerrit_credentials(
            host=self.server,
            explicit_username=username,
            explicit_password=password,
            use_netrc=use_netrc,
            netrc_file=netrc_file,
            env_username_var="GERRIT_USERNAME",
            env_password_var="GERRIT_PASSWORD",
        )

        if resolved is not None and resolved.is_valid:
            self.username = resolved.username
            self.password = resolved.password
            self._credentials = resolved
            self.logger.debug(
                "Using credentials from %s",
                resolved.auth_method_display(),
            )
        else:
            self.username = None
            self.password = None

    def __repr__(self) -> str:
        """Return string representation with masked credentials.

        Security: Password is never exposed in string representation.
        """
        password_status = "set" if self.password else "not set"
        username_display = repr(self.username) if self.username else "None"
        return (
            f"GerritKeysClient(server={self.server!r}, "
            f"username={username_display}, "
            f"password=***{password_status}***)"
        )

    def _ensure_client(self) -> GerritRestAPI:
        """Ensure client is initialized."""
        if not self._rest:
            raise RuntimeError(
                "GerritKeysClient must be used as an async context manager. "
                "Use 'async with GerritKeysClient(...) as client:'"
            )
        return self._rest

    def _normalize_server_url(self, server: str) -> str:
        """
        Normalize server URL to just the hostname.

        Args:
            server: Server hostname or URL

        Returns:
            Normalized hostname
        """
        if server.startswith(("http://", "https://")):
            # Extract hostname from URL
            parsed = urlparse(server)
            return parsed.netloc
        return server

    def _discover_server_from_github_org(self, github_org: str) -> str:
        """
        Discover Gerrit server from GitHub organization name.

        Uses the pattern: [GITHUB_ORG] -> gerrit.[GITHUB_ORG].org

        Args:
            github_org: GitHub organization name

        Returns:
            Gerrit server hostname
        """
        return f"gerrit.{github_org}.org"


__all__ = ["GerritKeysClientBase"]
