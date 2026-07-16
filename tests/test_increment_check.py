# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tests for tag increment and branch containment checks."""

import subprocess
from pathlib import Path

import pytest

from tag_validate.increment_check import (
    RepoContext,
    check_branch_containment,
    check_increment,
    compare_calver,
    compare_semver,
    detect_repo_context,
    list_repository_tags,
    resolve_default_branch,
)
from tag_validate.models import ValidationConfig
from tag_validate.validation import TagValidator
from tag_validate.workflow import ValidationWorkflow

VALIDATOR = TagValidator()


def _sv(tag: str):
    """Parse a tag as SemVer for comparison tests."""
    return VALIDATOR.validate_semver(tag)


def _cv(tag: str):
    """Parse a tag as CalVer for comparison tests."""
    return VALIDATOR.validate_calver(tag)


def _git(repo: Path, *args: str) -> str:
    """Run a git command in a test repository and return stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.fixture
def git_repo(tmp_path):
    """Create a real git repository with an initial commit on main."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test User")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "tag.gpgsign", "false")
    (repo / "file.txt").write_text("one\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "Initial commit")
    return repo


@pytest.fixture
def no_actions_env(monkeypatch):
    """Remove GitHub Actions environment variables for deterministic tests."""
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
    monkeypatch.delenv("GITHUB_API_URL", raising=False)


class TestCompareSemver:
    """Tests for SemVer precedence comparison."""

    @pytest.mark.parametrize(
        "lower,higher",
        [
            ("1.0.0", "1.0.1"),
            ("1.0.1", "1.1.0"),
            ("1.1.0", "2.0.0"),
            ("1.9.9", "1.10.0"),
            ("0.9.0", "0.10.0"),
            # Pre-release precedence chain from the SemVer specification
            ("1.0.0-alpha", "1.0.0-alpha.1"),
            ("1.0.0-alpha.1", "1.0.0-alpha.beta"),
            ("1.0.0-alpha.beta", "1.0.0-beta"),
            ("1.0.0-beta", "1.0.0-beta.2"),
            ("1.0.0-beta.2", "1.0.0-beta.11"),
            ("1.0.0-beta.11", "1.0.0-rc.1"),
            ("1.0.0-rc.1", "1.0.0"),
        ],
    )
    def test_ordering(self, lower, higher):
        """Lower versions compare less than higher versions."""
        assert compare_semver(_sv(lower), _sv(higher)) == -1
        assert compare_semver(_sv(higher), _sv(lower)) == 1

    def test_equal(self):
        """Identical versions compare equal."""
        assert compare_semver(_sv("1.2.3"), _sv("1.2.3")) == 0

    def test_prefix_ignored(self):
        """A 'v' prefix does not affect precedence."""
        assert compare_semver(_sv("v1.2.3"), _sv("1.2.3")) == 0

    def test_build_metadata_ignored(self):
        """Build metadata is excluded from precedence per the spec."""
        assert compare_semver(_sv("1.2.3+build.1"), _sv("1.2.3+build.2")) == 0


class TestCompareCalver:
    """Tests for CalVer comparison."""

    @pytest.mark.parametrize(
        "lower,higher",
        [
            ("2024.1.15", "2025.1.15"),
            ("2025.1.15", "2025.2.15"),
            ("2025.1.15", "2025.1.16"),
            ("2025.1.15.1", "2025.1.15.2"),
            ("2025.1.15", "2025.1.15.1"),
        ],
    )
    def test_ordering(self, lower, higher):
        """Older dates compare less than newer dates."""
        assert compare_calver(_cv(lower), _cv(higher)) == -1
        assert compare_calver(_cv(higher), _cv(lower)) == 1

    def test_equal(self):
        """Identical dates compare equal."""
        assert compare_calver(_cv("2025.1.15"), _cv("2025.1.15")) == 0

    def test_modifier_lower_than_release(self):
        """A modifier (pre-release) sorts below the plain release."""
        assert compare_calver(_cv("2025.1.15-rc1"), _cv("2025.1.15")) == -1


class TestCheckIncrement:
    """Tests for the increment enforcement logic."""

    def test_first_tag_passes(self):
        """The first version tag in a repository is incremental."""
        info = check_increment("v1.0.0", [])
        assert info.checked is True
        assert info.incremental is True
        assert info.latest_tag is None

    def test_higher_tag_passes(self):
        """A tag above the existing baseline is incremental."""
        info = check_increment("v1.2.0", ["v1.0.0", "v1.1.0"])
        assert info.incremental is True
        assert info.latest_tag == "v1.1.0"

    def test_lower_tag_fails(self):
        """A tag below the existing baseline is rejected."""
        info = check_increment("v1.0.5", ["v1.0.0", "v2.0.0"])
        assert info.incremental is False
        assert info.latest_tag == "v2.0.0"
        assert any("lower than" in e for e in info.errors)

    def test_equal_tag_fails(self):
        """A tag equal in value to an existing tag is rejected."""
        info = check_increment("1.2.3", ["v1.2.3"])
        assert info.incremental is False
        assert any("equal to" in e for e in info.errors)

    def test_self_exclusion(self):
        """Re-pushing the current highest tag passes (self excluded)."""
        info = check_increment("v2.0.0", ["v1.0.0", "v2.0.0"])
        assert info.incremental is True
        assert info.latest_tag == "v1.0.0"

    def test_unparseable_tag_fails_closed(self):
        """A tag that is neither SemVer nor CalVer fails the check."""
        info = check_increment("release-foo", ["v1.0.0"])
        assert info.incremental is False
        assert any("does not parse" in e for e in info.errors)

    def test_cross_scheme_fails_closed(self):
        """Switching schemes cannot bypass increment enforcement."""
        # Leading-zero components are valid CalVer but invalid SemVer
        info = check_increment("v1.0.0", ["2025.01.15", "2025.02.15"])
        assert info.incremental is False
        assert any("different scheme" in e for e in info.errors)

    def test_other_tags_ignored(self):
        """Non-version tags do not contribute to the baseline."""
        info = check_increment("v1.1.0", ["v1.0.0", "latest", "some-label"])
        assert info.incremental is True
        assert info.latest_tag == "v1.0.0"
        assert info.candidate_count == 1

    def test_calver_increment_passes(self):
        """A newer CalVer date is incremental."""
        info = check_increment("2025.3.10", ["2025.1.15", "2025.2.20"])
        assert info.incremental is True
        assert info.latest_tag == "2025.2.20"

    def test_calver_older_date_fails(self):
        """An older CalVer date is rejected."""
        info = check_increment("2025.1.15", ["2025.2.20"])
        assert info.incremental is False

    def test_mixed_repo_semver_baseline(self):
        """SemVer tags compare against the SemVer baseline only."""
        info = check_increment("v2.0.0", ["v1.0.0", "not-a-version", "v1.5.0"])
        assert info.incremental is True
        assert info.latest_tag == "v1.5.0"
        assert info.latest_tags == {"semver": "v1.5.0"}

    def test_both_scheme_tracks_per_scheme_baselines(self):
        """A 'both'-typed push records a baseline for each scheme."""
        # 2025.01.15 is CalVer-only (leading zero); 2025.13.1 is
        # SemVer-only (month 13 is invalid CalVer)
        info = check_increment("2026.1.1", ["2025.01.15", "2025.13.1"])
        assert info.scheme == "calver+semver"
        assert info.incremental is True
        assert info.latest_tags == {
            "calver": "2025.01.15",
            "semver": "2025.13.1",
        }
        # Equal candidate counts: tie broken by scheme name
        assert info.latest_tag == "2025.01.15"

    def test_both_scheme_dominant_baseline_on_success(self):
        """On success, latest_tag comes from the dominant scheme."""
        info = check_increment("2026.1.1", ["2025.01.15", "2025.13.1", "2025.14.1"])
        assert info.incremental is True
        assert info.latest_tags == {
            "calver": "2025.01.15",
            "semver": "2025.14.1",
        }
        # SemVer has the most comparable tags, so its baseline wins
        assert info.latest_tag == "2025.14.1"

    def test_both_scheme_failure_reports_blocking_tag(self):
        """On failure, latest_tag names the tag that blocked the push."""
        # 2025.6.1 exceeds the CalVer baseline but not the SemVer one
        info = check_increment("2025.6.1", ["2025.01.15", "2025.13.1"])
        assert info.incremental is False
        assert info.latest_tags == {
            "calver": "2025.01.15",
            "semver": "2025.13.1",
        }
        assert info.latest_tag == "2025.13.1"
        assert any("2025.13.1" in e for e in info.errors)

    def test_prerelease_of_existing_release_fails(self):
        """A pre-release below the current release is rejected."""
        info = check_increment("v1.2.3-rc.1", ["v1.2.3"])
        assert info.incremental is False

    def test_prerelease_above_release_passes(self):
        """A pre-release of the next version is incremental."""
        info = check_increment("v1.3.0-rc.1", ["v1.2.3"])
        assert info.incremental is True

    def test_tag_source_recorded(self):
        """The tag source is carried through to the result."""
        info = check_increment("v1.0.0", [], tag_source="api+git")
        assert info.tag_source == "api+git"


class TestDetectRepoContext:
    """Tests for repository context detection."""

    def test_explicit_owner_repo(self, tmp_path):
        """Explicit owner/repo takes priority."""
        context = detect_repo_context(tmp_path, "lfreleng-actions", "test")
        assert context is not None
        assert context.owner == "lfreleng-actions"
        assert context.repo == "test"

    def test_explicit_owner_repo_ghes_host(self, tmp_path, monkeypatch):
        """Explicit owner/repo derives the host from GITHUB_SERVER_URL."""
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.example.com")
        monkeypatch.delenv("GITHUB_API_URL", raising=False)
        context = detect_repo_context(tmp_path, "org", "repo")
        assert context is not None
        assert context.host == "github.example.com"
        assert context.api_url == "https://github.example.com/api/v3"

    def test_origin_remote(self, git_repo, no_actions_env):
        """The origin remote URL is parsed for owner/repo."""
        _git(
            git_repo,
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/example-repo.git",
        )
        context = detect_repo_context(git_repo)
        assert context is not None
        assert context.host == "github.com"
        assert context.owner == "example-org"
        assert context.repo == "example-repo"

    def test_https_remote_with_port(self, git_repo, no_actions_env):
        """HTTPS remote URLs keep an explicit port in the host."""
        _git(
            git_repo,
            "remote",
            "add",
            "origin",
            "https://github.example.com:8443/example-org/example-repo.git",
        )
        context = detect_repo_context(git_repo)
        assert context is not None
        assert context.host == "github.example.com:8443"
        assert context.owner == "example-org"
        assert context.repo == "example-repo"
        assert context.api_url == "https://github.example.com:8443/api/v3"

    def test_ssh_remote(self, git_repo, no_actions_env):
        """SSH-style remote URLs are parsed for owner/repo."""
        _git(
            git_repo,
            "remote",
            "add",
            "origin",
            "git@github.com:example-org/example-repo.git",
        )
        context = detect_repo_context(git_repo)
        assert context is not None
        assert context.owner == "example-org"
        assert context.repo == "example-repo"

    def test_ssh_url_remote(self, git_repo, no_actions_env):
        """ssh:// remote URLs are parsed for owner/repo."""
        _git(
            git_repo,
            "remote",
            "add",
            "origin",
            "ssh://git@github.example.com/example-org/example-repo.git",
        )
        context = detect_repo_context(git_repo)
        assert context is not None
        assert context.host == "github.example.com"
        assert context.owner == "example-org"
        assert context.repo == "example-repo"

    def test_ssh_url_remote_with_port(self, git_repo, no_actions_env):
        """ssh:// remote URLs with a port parse host and owner/repo."""
        _git(
            git_repo,
            "remote",
            "add",
            "origin",
            "ssh://git@github.example.com:2222/example-org/example-repo.git",
        )
        context = detect_repo_context(git_repo)
        assert context is not None
        assert context.host == "github.example.com"
        assert context.owner == "example-org"
        assert context.repo == "example-repo"

    def test_environment_fallback(self, git_repo, monkeypatch):
        """GITHUB_REPOSITORY provides the context when no remote exists."""
        monkeypatch.setenv("GITHUB_REPOSITORY", "env-org/env-repo")
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        context = detect_repo_context(git_repo)
        assert context is not None
        assert context.owner == "env-org"
        assert context.repo == "env-repo"

    def test_no_context(self, git_repo, no_actions_env):
        """No remote and no environment yields None."""
        assert detect_repo_context(git_repo) is None

    def test_api_url_github_com(self, no_actions_env):
        """github.com maps to the public API endpoint."""
        context = RepoContext("github.com", "org", "repo")
        assert context.api_url == "https://api.github.com"

    def test_api_url_enterprise(self, no_actions_env):
        """GHES hosts map to the conventional /api/v3 path."""
        context = RepoContext("github.example.com", "org", "repo")
        assert context.api_url == "https://github.example.com/api/v3"

    def test_api_url_env_applies_to_matching_host(self, no_actions_env, monkeypatch):
        """GITHUB_API_URL applies when the host matches the server URL."""
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.example.com")
        monkeypatch.setenv("GITHUB_API_URL", "https://github.example.com/custom/api")
        context = RepoContext("github.example.com", "org", "repo")
        assert context.api_url == "https://github.example.com/custom/api"

    def test_api_url_env_ignored_for_other_hosts(self, no_actions_env, monkeypatch):
        """GITHUB_API_URL is ignored for hosts not matching the server.

        A substring match (e.g. hub.com inside https://github.com) must
        not select the environment API URL.
        """
        monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
        monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")
        context = RepoContext("hub.com", "org", "repo")
        assert context.api_url == "https://hub.com/api/v3"


class _FakeGitHub:
    """Minimal stand-in for the dependamerge GitHubAsync client."""

    def __init__(self, pages=None, responses=None):
        """Store canned pages and responses."""
        self._pages = pages or []
        self._responses = responses or {}

    async def get(self, path, params=None):
        """Return the canned response for a path."""
        response = self._responses.get(path)
        if isinstance(response, Exception):
            raise response
        return response

    async def get_paginated(self, path):
        """Yield canned pages."""
        for page in self._pages:
            yield page


class _FakeKeysClient:
    """Minimal async-context stand-in for GitHubKeysClient."""

    fake_github: _FakeGitHub = _FakeGitHub()

    def __init__(self, *args, **kwargs):
        """Accept and ignore client constructor arguments."""

    async def __aenter__(self):
        """Enter the async context."""
        return self

    async def __aexit__(self, *exc_info):
        """Exit the async context."""
        return False

    def _ensure_client(self):
        """Return the fake underlying GitHub client."""
        return self.fake_github


@pytest.fixture
def fake_github(monkeypatch):
    """Patch GitHubKeysClient with a configurable fake GitHub client."""

    def configure(pages=None, responses=None):
        _FakeKeysClient.fake_github = _FakeGitHub(pages, responses)
        monkeypatch.setattr(
            "tag_validate.github_keys.GitHubKeysClient", _FakeKeysClient
        )
        return _FakeKeysClient.fake_github

    return configure


class TestListRepositoryTags:
    """Tests for repository tag enumeration."""

    @pytest.mark.asyncio
    async def test_git_only(self, git_repo, no_actions_env):
        """Tags are enumerated from local git without a context."""
        _git(git_repo, "tag", "v1.0.0")
        _git(git_repo, "tag", "v2.0.0")
        tags, source = await list_repository_tags(git_repo)
        assert tags == ["v1.0.0", "v2.0.0"]
        assert source == "git"

    @pytest.mark.asyncio
    async def test_api_and_git_union(self, git_repo, no_actions_env, fake_github):
        """API and git tag lists are merged."""
        fake_github(pages=[[{"name": "v1.0.0"}, {"name": "v3.0.0"}]])
        _git(git_repo, "tag", "v2.0.0")
        context = RepoContext("github.com", "org", "repo")
        tags, source = await list_repository_tags(git_repo, context)
        assert tags == ["v1.0.0", "v2.0.0", "v3.0.0"]
        assert source == "api+git"

    @pytest.mark.asyncio
    async def test_all_sources_fail(self, tmp_path, no_actions_env):
        """Failure of every source raises RuntimeError."""
        not_a_repo = tmp_path / "empty"
        not_a_repo.mkdir()
        with pytest.raises(RuntimeError, match="enumerate repository tags"):
            await list_repository_tags(not_a_repo)


class TestResolveDefaultBranch:
    """Tests for default branch resolution."""

    @pytest.mark.asyncio
    async def test_via_api(self, git_repo, no_actions_env, fake_github):
        """The API repository object provides the default branch."""
        fake_github(responses={"/repos/org/repo": {"default_branch": "develop"}})
        context = RepoContext("github.com", "org", "repo")
        branch = await resolve_default_branch(git_repo, context)
        assert branch == "develop"

    @pytest.mark.asyncio
    async def test_undetermined(self, git_repo, no_actions_env):
        """No API context and no origin yields None."""
        branch = await resolve_default_branch(git_repo)
        assert branch is None


class TestCheckBranchContainment:
    """Tests for branch containment checks."""

    @pytest.mark.asyncio
    async def test_commit_on_branch(self, git_repo, no_actions_env):
        """A commit on the branch passes the check."""
        sha = _git(git_repo, "rev-parse", "HEAD")
        _git(git_repo, "tag", "v1.0.0")
        info = await check_branch_containment("v1.0.0", sha, "main", git_repo)
        assert info.checked is True
        assert info.contains is True
        assert info.branch == "main"
        assert info.method == "git"

    @pytest.mark.asyncio
    async def test_commit_not_on_branch(self, git_repo, no_actions_env):
        """A commit on an unmerged side branch fails the check."""
        _git(git_repo, "checkout", "-b", "side")
        (git_repo / "side.txt").write_text("side\n")
        _git(git_repo, "add", ".")
        _git(git_repo, "commit", "-m", "Side branch commit")
        sha = _git(git_repo, "rev-parse", "HEAD")
        _git(git_repo, "tag", "v1.0.0")
        _git(git_repo, "checkout", "main")
        info = await check_branch_containment("v1.0.0", sha, "main", git_repo)
        assert info.contains is False
        assert any("not reachable" in e for e in info.errors)

    @pytest.mark.asyncio
    async def test_missing_branch_indeterminate(self, git_repo, no_actions_env):
        """An unknown branch yields an indeterminate (failing) result."""
        sha = _git(git_repo, "rev-parse", "HEAD")
        info = await check_branch_containment("v1.0.0", sha, "no-such-branch", git_repo)
        assert info.contains is None
        assert info.errors

    @pytest.mark.asyncio
    async def test_autodetect_without_source_fails(self, git_repo, no_actions_env):
        """Auto-detect fails closed when no default branch is found."""
        sha = _git(git_repo, "rev-parse", "HEAD")
        info = await check_branch_containment("v1.0.0", sha, "true", git_repo)
        assert info.contains is None
        assert any("auto-detect" in e for e in info.errors)

    @pytest.mark.asyncio
    async def test_api_contained(self, git_repo, no_actions_env, fake_github):
        """The compare API reports containment for behind/identical."""
        sha = "a" * 40
        fake_github(
            responses={f"/repos/org/repo/compare/main...{sha}": {"status": "behind"}}
        )
        context = RepoContext("github.com", "org", "repo")
        info = await check_branch_containment("v1.0.0", sha, "main", git_repo, context)
        assert info.contains is True
        assert info.method == "api"

    @pytest.mark.asyncio
    async def test_api_not_contained(self, git_repo, no_actions_env, fake_github):
        """The compare API reports non-containment for ahead/diverged."""
        sha = "b" * 40
        fake_github(
            responses={f"/repos/org/repo/compare/main...{sha}": {"status": "diverged"}}
        )
        context = RepoContext("github.com", "org", "repo")
        info = await check_branch_containment("v1.0.0", sha, "main", git_repo, context)
        assert info.contains is False
        assert any("not reachable" in e for e in info.errors)

    @pytest.mark.asyncio
    async def test_api_branch_name_url_encoded(
        self, git_repo, no_actions_env, fake_github
    ):
        """Branch names with slashes are URL-encoded in the compare path."""
        sha = "c" * 40
        fake_github(
            responses={
                f"/repos/org/repo/compare/release%2F2.x...{sha}": {
                    "status": "identical"
                }
            }
        )
        context = RepoContext("github.com", "org", "repo")
        info = await check_branch_containment(
            "v2.1.0", sha, "release/2.x", git_repo, context
        )
        assert info.contains is True
        assert info.method == "api"


class TestWorkflowIntegration:
    """Workflow-level tests for the release gating checks."""

    @pytest.mark.asyncio
    async def test_enforce_increment_blocks_lower_tag(self, git_repo, no_actions_env):
        """Validating a lower-value tag fails when enforcement is on."""
        _git(git_repo, "tag", "-a", "v2.0.0", "-m", "Release v2.0.0")
        (git_repo / "second.txt").write_text("two\n")
        _git(git_repo, "add", ".")
        _git(git_repo, "commit", "-m", "Second commit")
        _git(git_repo, "tag", "-a", "v1.0.0", "-m", "Stale release v1.0.0")

        config = ValidationConfig(enforce_increment=True)
        workflow = ValidationWorkflow(config, repo_path=git_repo)
        result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is False
        assert result.increment_check is not None
        assert result.increment_check.incremental is False
        assert result.increment_check.latest_tag == "v2.0.0"

    @pytest.mark.asyncio
    async def test_enforce_increment_allows_higher_tag(self, git_repo, no_actions_env):
        """Validating a higher-value tag passes the increment check."""
        _git(git_repo, "tag", "-a", "v1.0.0", "-m", "Release v1.0.0")
        (git_repo / "second.txt").write_text("two\n")
        _git(git_repo, "add", ".")
        _git(git_repo, "commit", "-m", "Second commit")
        _git(git_repo, "tag", "-a", "v1.1.0", "-m", "Release v1.1.0")

        config = ValidationConfig(enforce_increment=True)
        workflow = ValidationWorkflow(config, repo_path=git_repo)
        result = await workflow.validate_tag("v1.1.0")

        assert result.increment_check is not None
        assert result.increment_check.incremental is True
        assert result.increment_check.latest_tag == "v1.0.0"

    @pytest.mark.asyncio
    async def test_require_branch_blocks_off_branch_tag(self, git_repo, no_actions_env):
        """Validating a tag off the required branch fails."""
        _git(git_repo, "checkout", "-b", "side")
        (git_repo / "side.txt").write_text("side\n")
        _git(git_repo, "add", ".")
        _git(git_repo, "commit", "-m", "Side branch commit")
        _git(git_repo, "tag", "-a", "v1.0.0", "-m", "Off-branch release")
        _git(git_repo, "checkout", "main")

        config = ValidationConfig(require_branch="main")
        workflow = ValidationWorkflow(config, repo_path=git_repo)
        result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is False
        assert result.branch_check is not None
        assert result.branch_check.contains is False

    @pytest.mark.asyncio
    async def test_require_branch_allows_on_branch_tag(self, git_repo, no_actions_env):
        """Validating a tag on the required branch passes the check."""
        _git(git_repo, "tag", "-a", "v1.0.0", "-m", "Release v1.0.0")

        config = ValidationConfig(require_branch="main")
        workflow = ValidationWorkflow(config, repo_path=git_repo)
        result = await workflow.validate_tag("v1.0.0")

        assert result.branch_check is not None
        assert result.branch_check.contains is True
        assert result.branch_check.branch == "main"

    @pytest.mark.asyncio
    async def test_require_branch_fails_closed_on_error(
        self, git_repo, no_actions_env, monkeypatch
    ):
        """An unexpected containment error fails closed, not aborts."""
        _git(git_repo, "tag", "-a", "v1.0.0", "-m", "Release v1.0.0")

        async def boom(*args, **kwargs):
            raise RuntimeError("simulated network failure")

        monkeypatch.setattr(
            "tag_validate.increment_check.check_branch_containment", boom
        )
        config = ValidationConfig(require_branch="main")
        workflow = ValidationWorkflow(config, repo_path=git_repo)
        result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is False
        assert result.branch_check is not None
        assert result.branch_check.checked is True
        assert result.branch_check.contains is None
        assert any("simulated network failure" in e for e in result.branch_check.errors)
