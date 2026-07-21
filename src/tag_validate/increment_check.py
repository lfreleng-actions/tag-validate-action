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
import math
import os
import re
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
from urllib.parse import quote

from dependamerge.git_ops import run_git

from .models import (
    BranchCheckInfo,
    IncrementCheckInfo,
    LatestCheckInfo,
    TagAgeCheckInfo,
    TagInfo,
    VersionInfo,
)
from .validation import TagValidator

logger = logging.getLogger(__name__)

# Timeout (seconds) for network git operations (fetch/ls-remote)
GIT_NETWORK_TIMEOUT = 60

# Default window (minutes) for the tag age (require_recent) check
DEFAULT_TAG_AGE_MINUTES = 3.0

# Tolerance (seconds) for tag timestamps slightly in the future
# (tagger machine clocks are rarely perfectly synchronized)
CLOCK_SKEW_TOLERANCE_SECONDS = 300

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
                re.sub(r"^https?://", "", env_server)
                .split("/")[0]
                .split(":")[0]
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
        logger.debug(f"Could not read origin remote URL: {e}")

    # Fall back to GitHub Actions environment
    gh_repository = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in gh_repository:
        gh_owner, _, gh_repo = gh_repository.partition("/")
        return RepoContext(_default_host(), gh_owner, gh_repo)

    return None


def _semver_identifier_cmp(a: str | None, b: str | None) -> int:
    """Compare two dot-separated pre-release identifiers (SemVer rules).

    Absence of a pre-release identifier sorts HIGHER than presence
    (a release is greater than its pre-releases).

    Args:
        a: First pre-release identifier (or None)
        b: Second pre-release identifier (or None)

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    if a is None and b is None:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1

    for x, y in zip_longest(a.split("."), b.split(".")):
        if x is None:
            # Shorter identifier set has lower precedence
            return -1
        if y is None:
            return 1
        x_numeric, y_numeric = x.isdigit(), y.isdigit()
        if x_numeric and y_numeric:
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
        elif x_numeric:
            # Numeric identifiers have lower precedence than alphanumeric
            return -1
        elif y_numeric:
            return 1
        elif x != y:
            return -1 if x < y else 1
    return 0


def compare_semver(a: VersionInfo, b: VersionInfo) -> int:
    """Compare two parsed SemVer versions using SemVer precedence rules.

    Build metadata is ignored, as required by the SemVer specification.

    Args:
        a: First parsed version
        b: Second parsed version

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    tuple_a = (a.major or 0, a.minor or 0, a.patch or 0)
    tuple_b = (b.major or 0, b.minor or 0, b.patch or 0)
    if tuple_a != tuple_b:
        return -1 if tuple_a < tuple_b else 1
    return _semver_identifier_cmp(a.prerelease, b.prerelease)


def compare_calver(a: VersionInfo, b: VersionInfo) -> int:
    """Compare two parsed CalVer versions.

    Compares (year, month, day, micro) numerically, then applies
    pre-release style precedence to any modifier (a version without a
    modifier is greater than the same version with one).

    Args:
        a: First parsed version
        b: Second parsed version

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    tuple_a = (a.year or 0, a.month or 0, a.day or 0, a.micro or 0)
    tuple_b = (b.year or 0, b.month or 0, b.day or 0, b.micro or 0)
    if tuple_a != tuple_b:
        return -1 if tuple_a < tuple_b else 1
    return _semver_identifier_cmp(a.modifier, b.modifier)


def _schemes_for(version: VersionInfo) -> set[str]:
    """Return the set of comparable schemes a version belongs to.

    Args:
        version: Parsed version information

    Returns:
        Subset of {'semver', 'calver'} (empty for 'other' versions)
    """
    if version.version_type == "both":
        return {"semver", "calver"}
    if version.version_type in ("semver", "calver"):
        return {version.version_type}
    return set()


def check_increment(
    tag_name: str,
    existing_tags: list[str],
    validator: TagValidator | None = None,
    tag_source: str | None = None,
) -> IncrementCheckInfo:
    """Check that a tag is strictly greater than existing comparable tags.

    The pushed tag must compare strictly greater than every existing tag
    that parses under a shared versioning scheme (SemVer and/or CalVer).
    The pushed tag itself is excluded from the baseline, so re-pushing
    the current highest tag passes, but pushing any lower or equal value
    fails.

    Fail-closed behaviors:
    - The pushed tag does not parse as SemVer or CalVer: the check fails
      because ordering cannot be established.
    - No same-scheme tags exist but the repository has version tags
      under a different scheme: the check fails to prevent scheme
      switching from bypassing the gate.

    Parsing is deliberately lenient (prefixes allowed, non-strict
    SemVer) and independent of the workflow's format policy: the
    baseline must include every historical version tag even when the
    current policy would reject its format, otherwise a policy change
    (e.g. disallowing 'v' prefixes) would empty the baseline and let a
    stale tag pass as the first version tag. Format policy for the
    pushed tag is enforced separately by version validation.

    Reporting:
    - ``latest_tags`` maps each shared scheme to the highest existing
      tag under that scheme (tags typed 'both' compare under calver and
      semver independently).
    - ``latest_tag`` is a scalar convenience: the baseline that blocked
      the push when the check fails, otherwise the baseline from the
      scheme with the most comparable tags (ties broken by scheme name).

    Args:
        tag_name: The tag being validated
        existing_tags: All tags present in the repository
        validator: TagValidator instance (created when omitted)
        tag_source: Where the tag list came from (for reporting)

    Returns:
        IncrementCheckInfo with the comparison outcome
    """
    validator = validator or TagValidator()
    info = IncrementCheckInfo(checked=True, tag_source=tag_source)

    pushed = validator.validate_version(tag_name)
    pushed_schemes = _schemes_for(pushed)

    if not pushed_schemes:
        info.incremental = False
        info.errors.append(
            f"Tag '{tag_name}' does not parse as SemVer or CalVer; "
            "cannot establish version ordering for enforce_increment"
        )
        return info

    info.scheme = "+".join(sorted(pushed_schemes))

    # Parse all other tags once, tracking any valid version tags that
    # do not share a scheme with the pushed tag
    comparable: dict[str, list[tuple[str, VersionInfo]]] = {
        scheme: [] for scheme in pushed_schemes
    }
    other_scheme_tags: list[str] = []

    for existing in existing_tags:
        if existing == tag_name:
            continue
        parsed = validator.validate_version(existing)
        schemes = _schemes_for(parsed)
        if not schemes:
            continue
        shared = schemes & pushed_schemes
        if shared:
            for scheme in shared:
                # CalVer fields are absent from 'both' results (which
                # carry SemVer fields), so re-parse per scheme
                if scheme == "calver":
                    calver_parsed = validator.validate_calver(existing)
                    comparable[scheme].append((existing, calver_parsed))
                else:
                    semver_parsed = validator.validate_semver(existing)
                    comparable[scheme].append((existing, semver_parsed))
        else:
            other_scheme_tags.append(existing)

    candidate_names = {name for pairs in comparable.values() for name, _ in pairs}
    info.candidate_count = len(candidate_names)

    if not candidate_names:
        if other_scheme_tags:
            info.incremental = False
            info.errors.append(
                f"No existing tags share a versioning scheme with "
                f"'{tag_name}' ({info.scheme}), but the repository has "
                f"{len(other_scheme_tags)} version tag(s) under a "
                "different scheme (e.g. "
                f"'{other_scheme_tags[0]}'); refusing to bypass "
                "increment enforcement"
            )
        else:
            # First version tag in the repository
            info.incremental = True
        return info

    # The pushed tag must be strictly greater than the highest existing
    # tag under every shared scheme
    incremental = True
    blocking_tag: str | None = None

    for scheme, pairs in sorted(comparable.items()):
        if not pairs:
            continue
        compare = compare_semver if scheme == "semver" else compare_calver
        if scheme == "calver":
            pushed_parsed = validator.validate_calver(tag_name)
        else:
            pushed_parsed = validator.validate_semver(tag_name)

        latest_name, latest_parsed = pairs[0]
        for name, parsed in pairs[1:]:
            if compare(parsed, latest_parsed) > 0:
                latest_name, latest_parsed = name, parsed

        info.latest_tags[scheme] = latest_name

        comparison = compare(pushed_parsed, latest_parsed)
        if comparison <= 0:
            incremental = False
            if blocking_tag is None:
                blocking_tag = latest_name
            relation = "equal to" if comparison == 0 else "lower than"
            info.errors.append(
                f"Tag '{tag_name}' is {relation} existing tag "
                f"'{latest_name}' ({scheme} comparison); pushed tags "
                "must increment the repository version"
            )

    info.incremental = incremental
    if blocking_tag is not None:
        info.latest_tag = blocking_tag
    elif info.latest_tags:
        # Multi-scheme ('both') pushes have one baseline per scheme;
        # report the one from the scheme with the most comparable tags
        # (the repository's dominant scheme), ties broken by scheme name
        dominant = min(
            info.latest_tags,
            key=lambda name: (-len(comparable[name]), name),
        )
        info.latest_tag = info.latest_tags[dominant]
    return info


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


def _list_tags_via_git(repo_path: Path) -> list[str]:
    """List repository tags using local git, after a best-effort fetch.

    Args:
        repo_path: Path to the local Git repository

    Returns:
        List of tag names

    Raises:
        Exception: If local tag enumeration fails
    """
    # Best-effort fetch of remote tags (shallow checkouts only contain
    # the pushed tag); failures are non-fatal. Deliberately not forced:
    # existing local tag refs (already inspected by earlier validation
    # steps) must never be rewritten mid-validation
    try:
        remotes = run_git(["git", "remote"], cwd=repo_path, check=False).stdout.strip()
        if remotes:
            run_git(
                ["git", "fetch", "--tags", "--quiet"],
                cwd=repo_path,
                check=False,
                timeout=GIT_NETWORK_TIMEOUT,
            )
    except Exception as e:
        logger.debug(f"Best-effort tag fetch failed (continuing): {e}")

    result = run_git(["git", "tag", "--list"], cwd=repo_path)
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
        tags.update(_list_tags_via_git(repo_path))
        sources.append("git")
    except Exception as e:
        git_error = e
        logger.debug(f"Local git tag enumeration failed: {e}")

    if not sources:
        raise RuntimeError(
            f"Could not enumerate repository tags (api: {api_error}, git: {git_error})"
        )

    return sorted(tags), "+".join(sources)


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
        )
        match = re.search(r"ref:\s+refs/heads/(\S+)\s+HEAD", result.stdout)
        if match:
            return match.group(1)
    except Exception as e:
        logger.debug(f"ls-remote HEAD lookup failed: {e}")

    return None


def _git_branch_contains(
    commit_sha: str,
    branch: str,
    repo_path: Path,
) -> bool | None:
    """Check branch containment using local git.

    Args:
        commit_sha: Commit SHA to test
        branch: Branch name
        repo_path: Path to the local Git repository

    Returns:
        True/False when determined, None when indeterminate
    """
    # Ensure some ref for the branch exists locally (best-effort fetch)
    candidate_refs = [f"refs/remotes/origin/{branch}", f"refs/heads/{branch}"]
    existing_ref = None
    for ref in candidate_refs:
        result = run_git(
            ["git", "rev-parse", "--verify", "--quiet", ref],
            cwd=repo_path,
            check=False,
        )
        if result.returncode == 0:
            existing_ref = ref
            break

    if existing_ref is None:
        try:
            run_git(
                ["git", "fetch", "--quiet", "origin", branch],
                cwd=repo_path,
                check=False,
                timeout=GIT_NETWORK_TIMEOUT,
            )
        except Exception as e:
            logger.debug(f"Branch fetch failed: {e}")
        for ref in candidate_refs + ["FETCH_HEAD"]:
            result = run_git(
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

    result = run_git(
        ["git", "merge-base", "--is-ancestor", commit_sha, existing_ref],
        cwd=repo_path,
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        # Shallow histories can make ancestry unprovable locally; treat
        # a definite 'not ancestor' in a shallow clone as indeterminate
        shallow = run_git(
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
    info = BranchCheckInfo(checked=True)

    # Resolve the documented 'true' sentinel to the repository
    # default branch; any other value is treated as a literal
    # branch name (including a branch actually named 'default')
    if branch.lower() == "true":
        resolved = await resolve_default_branch(repo_path, context, token)
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
    contains = _git_branch_contains(commit_sha, branch, repo_path)
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


def _format_age(seconds: float) -> str:
    """Format an age in seconds as a human-readable duration.

    Args:
        seconds: Age in seconds

    Returns:
        Human-readable duration (e.g. '2.5 minutes', '3.2 days')
    """
    if seconds < 120:
        return f"{seconds:.0f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def check_tag_age(
    tag_info: TagInfo,
    max_age_minutes: float,
    now: datetime | None = None,
) -> TagAgeCheckInfo:
    """Check that a tag was created within the allowed time window.

    Uses the tag object's tagger timestamp, so the check only works
    for annotated (including signed) tags. Lightweight tags carry no
    creation timestamp and fail closed: falling back to the commit
    date would reject legitimate releases, because release commits
    are usually older than the freshness window.

    Note: tagger timestamps come from the tag creator's clock and are
    not tamper-proof; this gate prevents accidental pushes of stale
    tags rather than deliberate forgery. Combine with require_latest
    for a check that cannot be forged. Timestamps more than a small
    skew tolerance in the future also fail closed, because they
    indicate the timestamp cannot be trusted.

    Args:
        tag_info: Tag metadata (provides tag type and creation date)
        max_age_minutes: Maximum permitted tag age, in minutes
        now: Reference time for age calculation (defaults to UTC now)

    Returns:
        TagAgeCheckInfo with the age check outcome
    """
    info = TagAgeCheckInfo(checked=True, max_age_minutes=max_age_minutes)
    tag_name = tag_info.tag_name

    # Defense in depth: the CLI validates its input, but programmatic
    # callers could pass a non-finite or non-positive window, and NaN
    # comparisons are always False (the gate would fail open)
    if not math.isfinite(max_age_minutes) or max_age_minutes <= 0:
        info.recent = None
        info.errors.append(
            f"Invalid tag age window '{max_age_minutes}': the window "
            "must be a finite positive number of minutes"
        )
        return info

    if tag_info.tag_type != "annotated":
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' is a lightweight tag with no creation "
            "timestamp; tag age cannot be verified. Use an annotated "
            "(or signed) tag, or disable require_recent"
        )
        return info

    if not tag_info.tag_date:
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' is an annotated tag but its creation "
            "timestamp could not be determined; tag age cannot be "
            "verified"
        )
        return info

    try:
        created = datetime.fromisoformat(tag_info.tag_date)
    except ValueError as e:
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' has an unparsable creation timestamp "
            f"'{tag_info.tag_date}': {e}"
        )
        return info
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    reference = now or datetime.now(timezone.utc)
    age_seconds = (reference - created).total_seconds()
    info.tag_date = tag_info.tag_date

    if age_seconds < -CLOCK_SKEW_TOLERANCE_SECONDS:
        # No age reported: an untrusted future timestamp has no
        # meaningful age, and a clamped zero would look fresh
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' has a creation timestamp "
            f"{_format_age(-age_seconds)} in the future "
            f"({tag_info.tag_date}); the timestamp cannot be trusted"
        )
        return info

    # Report a non-negative age: tolerated future skew would otherwise
    # surface as a confusing negative age in JSON output and summaries.
    # The signed value is retained for the window comparison below.
    info.age_seconds = max(age_seconds, 0.0)

    if age_seconds > max_age_minutes * 60:
        info.recent = False
        info.errors.append(
            f"Tag '{tag_name}' was created {_format_age(age_seconds)} "
            f"ago ({tag_info.tag_date}), exceeding the require_recent "
            f"window of {max_age_minutes:g} minute(s); stale tags must "
            "be recreated before release"
        )
    else:
        info.recent = True
    return info


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


def _branch_tip_via_git(branch: str, repo_path: Path) -> str | None:
    """Fetch the tip commit SHA of a branch via git ls-remote.

    Queries the remote directly rather than local refs, because local
    remote-tracking refs can be stale (a stale ref could incorrectly
    pass or fail the latest-commit gate).

    Args:
        branch: Branch name
        repo_path: Path to the local Git repository

    Returns:
        Tip commit SHA, or None when it cannot be determined
    """
    result = run_git(
        ["git", "ls-remote", "origin", f"refs/heads/{branch}"],
        cwd=repo_path,
        check=False,
        timeout=GIT_NETWORK_TIMEOUT,
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
    info = LatestCheckInfo(checked=True, tag_sha=commit_sha)

    # Resolve the documented 'true' sentinel to the repository
    # default branch; any other value is a literal branch name
    if branch.lower() == "true":
        resolved = await resolve_default_branch(repo_path, context, token)
        if not resolved:
            info.latest = None
            info.errors.append(
                "require_latest was set but the default branch could "
                "not be determined"
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
            tip_sha = _branch_tip_via_git(branch, repo_path)
            if tip_sha:
                info.method = "git"
        except Exception as e:
            logger.debug(f"Branch tip ls-remote lookup failed: {e}")

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
