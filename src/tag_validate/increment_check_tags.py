# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Repository tag enumeration.

Lists the tags of a repository, preferring the GitHub API (which works
with the shallow checkouts produced by actions/checkout) and falling back
to local git.
"""

from pathlib import Path

from dependamerge.git_ops import redact_text

from .increment_check_base import GIT_NETWORK_TIMEOUT, RepoContext, logger


async def _list_tags_via_api(context: RepoContext, token: str | None) -> list[str]:
    """List repository tags using the GitHub REST API.

    Args:
        context: Repository context (host/owner/repo)
        token: GitHub API token (optional for public repositories)

    Returns:
        List of tag names

    Raises:
        Exception: If the API request fails
    """
    from .github_keys import GitHubKeysClient

    tags: list[str] = []
    async with GitHubKeysClient(token=token, api_url=context.api_url) as client:
        github = client._ensure_client()
        async for page in github.get_paginated(
            f"/repos/{context.owner}/{context.repo}/tags"
        ):
            if isinstance(page, list):
                for entry in page:
                    if not isinstance(entry, dict):
                        continue
                    name = entry.get("name")
                    if name:
                        tags.append(name)
    logger.debug(f"Enumerated {len(tags)} tags via GitHub API for {context}")
    return tags


def _list_tags_via_git(repo_path: Path, token: str | None = None) -> list[str]:
    """List repository tags using local git, after a best-effort fetch.

    Args:
        repo_path: Path to the local Git repository
        token: Optional token for authenticated fetch (askpass-based)

    Returns:
        List of tag names

    Raises:
        Exception: If local tag enumeration fails
    """
    # Resolved through the public module so that anything patching
    # `tag_validate.increment_check` attributes still intercepts these calls.
    from . import increment_check

    # Best-effort fetch of remote tags (shallow checkouts only contain
    # the pushed tag); failures are non-fatal. Deliberately not forced:
    # existing local tag refs (already inspected by earlier validation
    # steps) must never be rewritten mid-validation
    try:
        remotes = increment_check.run_git(
            ["git", "remote"], cwd=repo_path, check=False
        ).stdout.strip()
        if remotes:
            increment_check.run_git(
                ["git", "fetch", "--tags", "--quiet"],
                cwd=repo_path,
                check=False,
                timeout=GIT_NETWORK_TIMEOUT,
                token=token,
            )
    except Exception as e:
        # Redact: a git network error may surface a credential-bearing
        # remote URL from a legacy config.
        logger.debug(
            f"Best-effort tag fetch failed (continuing): {redact_text(str(e))}"
        )

    result = increment_check.run_git(["git", "tag", "--list"], cwd=repo_path)
    tags = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    logger.debug(f"Enumerated {len(tags)} tags via git in {repo_path}")
    return tags


async def list_repository_tags(
    repo_path: Path,
    context: RepoContext | None = None,
    token: str | None = None,
) -> tuple[list[str], str]:
    """Enumerate all repository tags.

    Combines the GitHub API (complete even for shallow checkouts) with
    local git enumeration. Either source failing is tolerated provided
    the other succeeds.

    Args:
        repo_path: Path to the local Git repository
        context: Repository context for API access (optional)
        token: GitHub API token (optional)

    Returns:
        Tuple of (tag names, source description)

    Raises:
        RuntimeError: If tags cannot be enumerated from any source
    """
    tags: set[str] = set()
    sources: list[str] = []
    api_error: Exception | None = None
    git_error: Exception | None = None

    if context:
        try:
            tags.update(await _list_tags_via_api(context, token))
            sources.append("api")
        except Exception as e:
            api_error = e
            logger.debug(f"GitHub API tag enumeration failed: {e}")

    try:
        tags.update(_list_tags_via_git(repo_path, token))
        sources.append("git")
    except Exception as e:
        git_error = e
        logger.debug(f"Local git tag enumeration failed: {e}")

    if not sources:
        raise RuntimeError(
            f"Could not enumerate repository tags (api: {api_error}, git: {git_error})"
        )

    return sorted(tags), "+".join(sources)


__all__ = ["list_repository_tags"]
