# SPDX-FileCopyrightText: 2026 The Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tests for tag location normalization in the CLI parsing helpers.

``owner/repo/tag`` and ``path/to/repo/tag`` are syntactically identical,
so the presence of a local Git repository is the only discriminator.
These tests pin that behaviour for both outcomes.
"""

from pathlib import Path

import pytest

from tag_validate.cli_parsing import normalize_tag_location


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Run each test from an empty temporary working directory."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _make_repo(root: Path, relative_path: str) -> None:
    """Create a directory that looks like a Git repository."""
    repo = root / relative_path
    repo.mkdir(parents=True)
    (repo / ".git").mkdir()


class TestNormalizeTagLocationLocalPaths:
    """Local repository paths must survive normalization unchanged."""

    def test_nested_relative_path_with_local_repo(self, workdir):
        """A local repo two directories deep is not rewritten as remote."""
        _make_repo(workdir, "path/to/repo")

        assert normalize_tag_location("path/to/repo/v1.0.0") == "path/to/repo/v1.0.0"

    def test_single_slash_path_with_local_repo(self, workdir):
        """A local repo in the current directory is not rewritten."""
        _make_repo(workdir, "repo")

        assert normalize_tag_location("repo/v1.0.0") == "repo/v1.0.0"

    def test_explicit_relative_prefix(self, workdir):
        """A ./ prefix marks a local path regardless of filesystem state."""
        assert normalize_tag_location("./path/to/repo/v1.0.0") == (
            "./path/to/repo/v1.0.0"
        )

    def test_absolute_path(self, workdir):
        """An absolute path marks a local path regardless of state."""
        assert normalize_tag_location("/path/to/repo/v1.0.0") == "/path/to/repo/v1.0.0"

    def test_bare_tag_name(self, workdir):
        """A tag name with no slashes is left alone."""
        assert normalize_tag_location("v1.0.0") == "v1.0.0"


class TestNormalizeTagLocationRemote:
    """Locations with no matching local repository are treated as remote."""

    def test_nested_path_without_local_repo(self, workdir):
        """Absent a local repo, owner/repo/tag becomes owner/repo@tag."""
        assert normalize_tag_location("owner/repo/v1.0.0") == "owner/repo@v1.0.0"

    def test_directory_without_git_is_not_a_repository(self, workdir):
        """A plain directory is not enough; it needs a .git entry."""
        (workdir / "owner" / "repo").mkdir(parents=True)

        assert normalize_tag_location("owner/repo/v1.0.0") == "owner/repo@v1.0.0"

    def test_single_slash_without_local_repo(self, workdir):
        """One slash and no local repo passes through for the workflow."""
        assert normalize_tag_location("repo/v1.0.0") == "repo/v1.0.0"

    def test_existing_at_separator(self, workdir):
        """A location already in remote form is returned unchanged."""
        assert normalize_tag_location("owner/repo@v1.0.0") == "owner/repo@v1.0.0"

    def test_url(self, workdir):
        """URLs are returned unchanged."""
        url = "https://github.com/owner/repo@v1.0.0"

        assert normalize_tag_location(url) == url


class TestNormalizeTagLocationBasePath:
    """Detection honours an explicit base directory.

    ``verify --path`` configures the workflow with a repository path that
    need not be the working directory. Normalization has to consult the
    same directory, or the two disagree about whether a location is local.
    """

    def test_local_repo_found_under_base_path(self, workdir, tmp_path_factory):
        """A repo under the base path is detected from elsewhere."""
        elsewhere = tmp_path_factory.mktemp("elsewhere")
        _make_repo(elsewhere, "nested/repo")

        assert normalize_tag_location("nested/repo/v1.0.0", base_path=elsewhere) == (
            "nested/repo/v1.0.0"
        )

    def test_absent_under_base_path_is_remote(self, workdir, tmp_path_factory):
        """Absent from the base path, the location is still remote."""
        elsewhere = tmp_path_factory.mktemp("elsewhere")

        assert normalize_tag_location("owner/repo/v1.0.0", base_path=elsewhere) == (
            "owner/repo@v1.0.0"
        )

    def test_base_path_not_the_working_directory(self, workdir, tmp_path_factory):
        """A repo in the CWD does not count when a base path is given."""
        _make_repo(workdir, "nested/repo")
        elsewhere = tmp_path_factory.mktemp("elsewhere")

        assert normalize_tag_location("nested/repo/v1.0.0", base_path=elsewhere) == (
            "nested/repo@v1.0.0"
        )

    def test_defaults_to_working_directory(self, workdir):
        """Omitting the base path preserves the previous behaviour."""
        _make_repo(workdir, "nested/repo")

        assert normalize_tag_location("nested/repo/v1.0.0") == "nested/repo/v1.0.0"
