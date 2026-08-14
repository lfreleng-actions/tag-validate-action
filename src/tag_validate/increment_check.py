# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tag increment and branch containment checks.

This module implements release-gating checks used by the validation
workflow:

- Increment enforcement: a pushed tag must be strictly greater than the
  highest existing comparable tag in the repository (prevents accidental
  re-release of older versions, e.g. stale tags pushed from out-of-sync
  forks).
- Branch containment: a tag must point to a commit reachable from a
  given branch (prevents releases from unreviewed/orphaned commits).

Tag enumeration and commit comparison prefer the GitHub API when a
repository context and network access are available (this works with
shallow checkouts as performed by actions/checkout), falling back to
local git operations otherwise.
"""

import logging
import os
import re
from pathlib import Path

from dependamerge.git_ops import redact_text, run_git

from .increment_check_age import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    DEFAULT_TAG_AGE_MINUTES,
    _format_age,
    check_tag_age,
)
from .increment_check_base import GIT_NETWORK_TIMEOUT, RepoContext
from .increment_check_branch import _git_branch_contains, check_branch_containment
from .increment_check_compare import (
    _schemes_for,
    _semver_identifier_cmp,
    check_increment,
    compare_calver,
    compare_semver,
)
from .increment_check_latest import (
    _branch_tip_via_api,
    _branch_tip_via_git,
    check_latest_commit,
)
from .increment_check_tags import (
    _list_tags_via_api,
    _list_tags_via_git,
    list_repository_tags,
)

logger = logging.getLogger(__name__)

# Patterns for extracting owner/repo from git remote URLs
_REMOTE_URL_PATTERNS = [
    # scp-style ssh: git@github.com:owner/repo.git
    re.compile(
        r"^(?:[\w.-]+@)?(?P<host>[\w.-]+):(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
    ),
    # ssh url: ssh://git@github.com:2222/owner/repo.git
    # (the port is SSH transport, not the HTTPS API port, so it is
    # deliberately excluded from the host)
    re.compile(
        r"^ssh://(?:[\w.-]+@)?(?P<host>[\w.-]+)(?::\d+)?/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
    ),
    # https: https://github.com/owner/repo.git
    # (an explicit port is part of the API base URL, so keep it in the
    # host)
    re.compile(
        r"^https?://(?:[\w.-]+@)?(?P<host>[\w.-]+(?::\d+)?)/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
    ),
]


def _default_host() -> str:
    """Return the git hosting server hostname for the runtime environment.

    Derives the host from GITHUB_SERVER_URL (supports GitHub Enterprise
    Server), falling back to github.com.

    Returns:
        Hostname (e.g. github.com or a GHES hostname)
    """
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    host = re.sub(r"^https?://", "", server).split("/")[0]
    return host or "github.com"


def detect_repo_context(
    repo_path: Path,
    owner: str | None = None,
    repo: str | None = None,
) -> RepoContext | None:
    """Determine the GitHub repository context for API operations.

    Priority:
    1. Explicit owner/repo arguments (from remote tag locations)
    2. The 'origin' remote URL of the local repository
    3. The GITHUB_REPOSITORY environment variable (GitHub Actions)

    Args:
        repo_path: Path to the local Git repository
        owner: Explicit repository owner (optional)
        repo: Explicit repository name (optional)

    Returns:
        RepoContext when a context can be determined, otherwise None
    """
    if owner and repo:
        return RepoContext(_default_host(), owner, repo)

    # Try the origin remote URL
    try:
        result = run_git(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=repo_path,
            check=False,
        )
        url = (result.stdout or "").strip()
        if url:
            for pattern in _REMOTE_URL_PATTERNS:
                match = pattern.match(url)
                if match:
                    return RepoContext(
                        match.group("host"),
                        match.group("owner"),
                        match.group("repo"),
                    )
    except Exception as e:
        # Redact for defense-in-depth: the origin URL handled here could
        # carry embedded credentials in a legacy config, so never log the
        # raw exception text verbatim.
        logger.debug(f"Could not read origin remote URL: {redact_text(str(e))}")

    # Fall back to GitHub Actions environment
    gh_repository = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in gh_repository:
        gh_owner, _, gh_repo = gh_repository.partition("/")
        return RepoContext(_default_host(), gh_owner, gh_repo)

    return None


async def resolve_default_branch(
    repo_path: Path,
    context: RepoContext | None = None,
    token: str | None = None,
) -> str | None:
    """Determine the repository default branch.

    Args:
        repo_path: Path to the local Git repository
        context: Repository context for API access (optional)
        token: GitHub API token (optional)

    Returns:
        Default branch name, or None when it cannot be determined
    """
    if context:
        try:
            from .github_keys import GitHubKeysClient

            async with GitHubKeysClient(token=token, api_url=context.api_url) as client:
                github = client._ensure_client()
                data = await github.get(f"/repos/{context.owner}/{context.repo}")
                if isinstance(data, dict):
                    branch = data.get("default_branch")
                    if branch:
                        logger.debug(f"Default branch via API: {branch}")
                        return str(branch)
        except Exception as e:
            logger.debug(f"Default branch API lookup failed: {e}")

    # git fallback: origin/HEAD symbolic ref
    try:
        result = run_git(
            ["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            cwd=repo_path,
            check=False,
        )
        ref: str = str(result.stdout or "").strip()
        if ref.startswith("origin/"):
            return ref[len("origin/") :]
    except Exception as e:
        logger.debug(f"origin/HEAD lookup failed: {e}")

    # git fallback: ask the remote directly
    try:
        result = run_git(
            ["git", "ls-remote", "--symref", "origin", "HEAD"],
            cwd=repo_path,
            check=False,
            timeout=GIT_NETWORK_TIMEOUT,
            token=token,
        )
        match = re.search(r"ref:\s+refs/heads/(\S+)\s+HEAD", result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        # Redact: a git network error may surface a credential-bearing
        # remote URL from a legacy config.
        logger.debug(f"ls-remote HEAD lookup failed: {redact_text(str(e))}")

    return None


# The public surface of this module. Underscore-prefixed helpers live in
# sibling modules but stay re-exported here: this module is the single
# import site for the increment checks, and callers patch attributes on
# it (rather than on the sibling that happens to hold the code).
__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "DEFAULT_TAG_AGE_MINUTES",
    "GIT_NETWORK_TIMEOUT",
    "RepoContext",
    "_branch_tip_via_api",
    "_branch_tip_via_git",
    "_format_age",
    "_git_branch_contains",
    "_list_tags_via_api",
    "_list_tags_via_git",
    "_schemes_for",
    "_semver_identifier_cmp",
    "check_branch_containment",
    "check_increment",
    "check_latest_commit",
    "check_tag_age",
    "compare_calver",
    "compare_semver",
    "detect_repo_context",
    "list_repository_tags",
    "resolve_default_branch",
]
