# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Branch containment checks.

Verifies that the commit a tag points at is reachable from a given
branch, so releases cannot be cut from unreviewed or orphaned commits.
"""

from pathlib import Path
from urllib.parse import quote

from dependamerge.git_ops import redact_text

from .increment_check_base import GIT_NETWORK_TIMEOUT, RepoContext, logger
from .models import BranchCheckInfo


def _git_branch_contains(
    commit_sha: str,
    branch: str,
    repo_path: Path,
    token: str | None = None,
) -> bool | None:
    """Check branch containment using local git.

    Args:
        commit_sha: Commit SHA to test
        branch: Branch name
        repo_path: Path to the local Git repository
        token: Optional token for authenticated fetch (askpass-based)

    Returns:
        True/False when determined, None when indeterminate
    """
    # Resolved through the public module so that anything patching
    # `tag_validate.increment_check` attributes still intercepts these calls.
    from . import increment_check

    # Ensure some ref for the branch exists locally (best-effort fetch)
    candidate_refs = [f"refs/remotes/origin/{branch}", f"refs/heads/{branch}"]
    existing_ref = None
    for ref in candidate_refs:
        result = increment_check.run_git(
            ["git", "rev-parse", "--verify", "--quiet", ref],
            cwd=repo_path,
            check=False,
        )
        if result.returncode == 0:
            existing_ref = ref
            break

    if existing_ref is None:
        try:
            increment_check.run_git(
                ["git", "fetch", "--quiet", "origin", branch],
                cwd=repo_path,
                check=False,
                timeout=GIT_NETWORK_TIMEOUT,
                token=token,
            )
        except Exception as e:
            # Redact: a git network error may surface a credential-bearing
            # remote URL from a legacy config.
            logger.debug(f"Branch fetch failed: {redact_text(str(e))}")
        for ref in candidate_refs + ["FETCH_HEAD"]:
            result = increment_check.run_git(
                ["git", "rev-parse", "--verify", "--quiet", ref],
                cwd=repo_path,
                check=False,
            )
            if result.returncode == 0:
                existing_ref = ref
                break

    if existing_ref is None:
        logger.debug(f"No local ref found for branch '{branch}'")
        return None

    result = increment_check.run_git(
        ["git", "merge-base", "--is-ancestor", commit_sha, existing_ref],
        cwd=repo_path,
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        # Shallow histories can make ancestry unprovable locally; treat
        # a definite 'not ancestor' in a shallow clone as indeterminate
        shallow = increment_check.run_git(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=repo_path,
            check=False,
        ).stdout.strip()
        if shallow == "true":
            logger.debug(
                "merge-base returned not-ancestor in a shallow clone; "
                "treating as indeterminate"
            )
            return None
        return False
    return None


async def check_branch_containment(
    tag_name: str,
    commit_sha: str,
    branch: str,
    repo_path: Path,
    context: RepoContext | None = None,
    token: str | None = None,
) -> BranchCheckInfo:
    """Check that a tag commit is reachable from a branch.

    Prefers the GitHub compare API (reliable with shallow checkouts),
    falling back to local git ancestry checks. The check fails closed:
    if containment cannot be determined, the result is not valid.

    Args:
        tag_name: Tag being validated (for messages)
        commit_sha: Commit SHA the tag points to
        branch: Branch name, or 'true' to auto-detect the default branch
        repo_path: Path to the local Git repository
        context: Repository context for API access (optional)
        token: GitHub API token (optional)

    Returns:
        BranchCheckInfo with the containment outcome
    """
    # Resolved through the public module so that anything patching
    # `tag_validate.increment_check` attributes still intercepts these calls.
    from . import increment_check

    info = BranchCheckInfo(checked=True)

    # Resolve the documented 'true' sentinel to the repository
    # default branch; any other value is treated as a literal
    # branch name (including a branch actually named 'default')
    if branch.lower() == "true":
        resolved = await increment_check.resolve_default_branch(
            repo_path, context, token
        )
        if not resolved:
            info.contains = None
            info.errors.append(
                "require_branch was set to auto-detect but the default "
                "branch could not be determined"
            )
            return info
        branch = resolved

    info.branch = branch

    # Prefer the compare API when a repository context is available
    if context:
        try:
            from .github_keys import GitHubKeysClient

            async with GitHubKeysClient(token=token, api_url=context.api_url) as client:
                github = client._ensure_client()
                # Branch names can contain slashes (e.g. release/2.x)
                # and must be URL-encoded in the compare path
                encoded_branch = quote(branch, safe="")
                data = await github.get(
                    f"/repos/{context.owner}/{context.repo}/compare/"
                    f"{encoded_branch}...{commit_sha}"
                )
                if isinstance(data, dict) and "status" in data:
                    status = data["status"]
                    info.method = "api"
                    info.contains = status in ("identical", "behind")
                    if not info.contains:
                        info.errors.append(
                            f"Tag '{tag_name}' points to commit "
                            f"{commit_sha[:12]} which is not reachable "
                            f"from branch '{branch}' "
                            f"(compare status: {status})"
                        )
                    return info
        except Exception as e:
            logger.debug(f"Compare API branch check failed: {e}")

    # Fall back to local git ancestry
    contains = _git_branch_contains(commit_sha, branch, repo_path, token)
    info.method = "git"
    info.contains = contains
    if contains is None:
        info.errors.append(
            f"Could not determine whether commit {commit_sha[:12]} "
            f"(tag '{tag_name}') is reachable from branch '{branch}'"
        )
    elif not contains:
        info.errors.append(
            f"Tag '{tag_name}' points to commit {commit_sha[:12]} "
            f"which is not reachable from branch '{branch}'"
        )
    return info


__all__ = ["check_branch_containment"]
