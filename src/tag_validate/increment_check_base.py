# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Shared foundations for the increment-check modules.

Holds the repository context object and the tuning constants used by the
individual release-gating checks, so the check modules can depend on them
without importing each other.
"""

import logging
import os
import re

# Bound to the public module's name so log records keep reporting
# `tag_validate.increment_check` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.increment_check")

# Timeout (seconds) for network git operations (fetch/ls-remote)
GIT_NETWORK_TIMEOUT = 60


class RepoContext:
    """GitHub repository context for API operations."""

    def __init__(self, host: str, owner: str, repo: str):
        """Initialize repository context.

        Args:
            host: Git hosting server hostname (e.g. github.com)
            owner: Repository owner (user or organization)
            repo: Repository name
        """
        self.host = host
        self.owner = owner
        self.repo = repo

    @property
    def api_url(self) -> str:
        """Return the REST API base URL for this host.

        Uses GITHUB_API_URL when this host equals the GITHUB_SERVER_URL
        host, https://api.github.com for github.com, and the
        conventional /api/v3 path for GitHub Enterprise Server hosts.
        """
        env_api = os.environ.get("GITHUB_API_URL")
        env_server = os.environ.get("GITHUB_SERVER_URL", "")
        if env_api and env_server:
            server_host = (
                re.sub(r"^https?://", "", env_server).split("/")[0].split(":")[0]
            )
            if server_host.lower() == self.host.split(":")[0].lower():
                return env_api
        if self.host == "github.com":
            return "https://api.github.com"
        # aislop-ignore-next-line ai-slop/hardcoded-url -- canonical GHES REST API path convention
        return f"https://{self.host}/api/v3"

    def __repr__(self) -> str:
        """Return string representation."""
        return f"RepoContext({self.host}/{self.owner}/{self.repo})"


__all__ = ["GIT_NETWORK_TIMEOUT", "RepoContext", "logger"]
