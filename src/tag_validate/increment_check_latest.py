# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Branch-tip (latest commit) checks.

Confirms that a tag points at the current tip of its branch, preferring
the GitHub API and falling back to ``git ls-remote``.
"""

from pathlib import Path
from urllib.parse import quote

from dependamerge.git_ops import redact_text

from .increment_check_base import GIT_NETWORK_TIMEOUT, RepoContext, logger
from .models import LatestCheckInfo


async def _branch_tip_via_api(
    branch: str,
    context: RepoContext,
    token: str | None,
) -> str | None:
    """Fetch the tip commit SHA of a branch via the GitHub API.

    Args:
        branch: Branch name
        context: Repository context (host/owner/repo)
        token: GitHub API token (optional)

    Returns:
        Tip commit SHA, or None when it cannot be determined
    """
    from .github_keys import GitHubKeysClient

    async with GitHubKeysClient(token=token, api_url=context.api_url) as client:
        github = client._ensure_client()
        encoded_branch = quote(branch, safe="")
        data = await github.get(
            f"/repos/{context.owner}/{context.repo}/branches/{encoded_branch}"
        )
        if isinstance(data, dict):
            commit = data.get("commit")
            if isinstance(commit, dict) and commit.get("sha"):
                return str(commit["sha"])
    return None


def _branch_tip_via_git(
    branch: str, repo_path: Path, token: str | None = None
) -> str | None:
    """Fetch the tip commit SHA of a branch via git ls-remote.

    Queries the remote directly rather than local refs, because local
    remote-tracking refs can be stale (a stale ref could incorrectly
    pass or fail the latest-commit gate).

    Args:
        branch: Branch name
        repo_path: Path to the local Git repository
        token: Optional token for authenticated lookup (askpass-based)

    Returns:
        Tip commit SHA, or None when it cannot be determined
    """
    # Resolved through the public module so that anything patching
    # `tag_validate.increment_check` attributes still intercepts these calls.
    from . import increment_check

    result = increment_check.run_git(
        ["git", "ls-remote", "origin", f"refs/heads/{branch}"],
        cwd=repo_path,
        check=False,
        timeout=GIT_NETWORK_TIMEOUT,
        token=token,
    )
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == f"refs/heads/{branch}":
            return parts[0]
    return None


async def check_latest_commit(
    tag_name: str,
    commit_sha: str,
    branch: str,
    repo_path: Path,
    context: RepoContext | None = None,
    token: str | None = None,
) -> LatestCheckInfo:
    """Check that a tag commit is the current tip of a branch.

    Prefers the GitHub API, falling back to git ls-remote against the
    origin remote. Both sources query the authoritative remote; stale
    local remote-tracking refs are deliberately not used. The check
    fails closed: if the branch tip cannot be determined, the result
    is not valid.

    Args:
        tag_name: Tag being validated (for messages)
        commit_sha: Commit SHA the tag points to (peeled)
        branch: Branch name, or 'true' to auto-detect the default branch
        repo_path: Path to the local Git repository
        context: Repository context for API access (optional)
        token: GitHub API token (optional)

    Returns:
        LatestCheckInfo with the comparison outcome
    """
    # Resolved through the public module so that anything patching
    # `tag_validate.increment_check` attributes still intercepts these calls.
    from . import increment_check

    info = LatestCheckInfo(checked=True, tag_sha=commit_sha)

    # Resolve the documented 'true' sentinel to the repository
    # default branch; any other value is a literal branch name
    if branch.lower() == "true":
        resolved = await increment_check.resolve_default_branch(
            repo_path, context, token
        )
        if not resolved:
            info.latest = None
            info.errors.append(
                "require_latest was set but the default branch could not be determined"
            )
            return info
        branch = resolved

    info.branch = branch

    tip_sha: str | None = None
    if context:
        try:
            tip_sha = await _branch_tip_via_api(branch, context, token)
            if tip_sha:
                info.method = "api"
        except Exception as e:
            logger.debug(f"Branch tip API lookup failed: {e}")

    if not tip_sha:
        try:
            tip_sha = _branch_tip_via_git(branch, repo_path, token)
            if tip_sha:
                info.method = "git"
        except Exception as e:
            # Redact: a git network error may surface a credential-bearing
            # remote URL from a legacy config.
            logger.debug(f"Branch tip ls-remote lookup failed: {redact_text(str(e))}")

    if not tip_sha:
        info.latest = None
        info.errors.append(
            f"Could not determine the tip commit of branch '{branch}' "
            f"to verify tag '{tag_name}' points to the latest commit"
        )
        return info

    info.branch_sha = tip_sha
    info.latest = tip_sha.lower() == commit_sha.lower()
    if not info.latest:
        info.errors.append(
            f"Tag '{tag_name}' points to commit {commit_sha[:12]} but "
            f"branch '{branch}' is at {tip_sha[:12]}; the tag must "
            f"point to the latest commit on '{branch}'"
        )
    return info


__all__ = ["check_latest_commit"]
