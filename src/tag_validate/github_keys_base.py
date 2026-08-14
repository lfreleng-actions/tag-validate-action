# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
Connection handling for the GitHub keys API client.

Holds the error type and the base class that owns configuration and the
async context-manager lifecycle of the underlying GitHubAsync client.
"""

import logging
import os
from typing import TypeVar

from dependamerge.github_async import GitHubAsync

from .github_keys_parsers import resolve_server_hostname

# Bound to the public module's name so log records keep reporting
# `tag_validate.github_keys` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.github_keys")

# Bound to the base so ``async with SubClass(...) as client`` keeps the
# subclass type rather than widening to the base.
_ClientT = TypeVar("_ClientT", bound="GitHubKeysClientBase")


class GitHubKeysError(Exception):
    """Raised when GitHub Keys API operations fail."""

    pass


class GitHubKeysClientBase:
    """
    Configuration and connection lifecycle for GitHub keys API access.

    Subclasses add the key-specific operations; this base owns the token,
    endpoint URLs, and the underlying GitHubAsync client.
    """

    def __init__(
        self,
        token: str | None = None,
        api_url: str = "https://api.github.com",
        graphql_url: str = "https://api.github.com/graphql",
        logger_instance: logging.Logger | None = None,
    ):
        """
        Initialize GitHub keys client.

        Args:
            token: GitHub personal access token. If None, reads from GITHUB_TOKEN env var.
            api_url: Base URL for GitHub REST API (for GitHub Enterprise Server).
            graphql_url: GraphQL endpoint URL (for GitHub Enterprise Server).
            logger_instance: Optional logger instance for client messages.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.api_url = api_url
        self.graphql_url = graphql_url
        self.logger = logger_instance or logger
        self._client: GitHubAsync | None = None

        # Extract server hostname from api_url (e.g., "api.github.com" -> "github.com")
        # For GitHub.com, use "github.com", for GHE use the hostname
        self.server = resolve_server_hostname(api_url)

    async def __aenter__(self: _ClientT) -> _ClientT:
        """Async context manager entry."""
        self._client = GitHubAsync(
            token=self.token,
            api_url=self.api_url,
            graphql_url=self.graphql_url,
            logger=self.logger,
        )
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.__aexit__(exc_type, exc_val, exc_tb)
            self._client = None

    def _ensure_client(self) -> GitHubAsync:
        """Ensure client is initialized."""
        if not self._client:
            raise RuntimeError(
                "GitHubKeysClient must be used as an async context manager. "
                "Use 'async with GitHubKeysClient(...) as client:'"
            )
        return self._client


__all__ = ["GitHubKeysClientBase", "GitHubKeysError"]
