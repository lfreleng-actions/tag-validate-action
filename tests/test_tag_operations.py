# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tag_operations module."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tag_validate.models import RepositoryInfo, TagInfo
from tag_validate.tag_operations import TagLocationError, TagOperations


class TestTagOperations:
    """Test suite for TagOperations class."""

    def test_initialization(self):
        """Test TagOperations initialization."""
        ops = TagOperations()
        assert ops is not None
        assert ops.TAG_LOCATION_PATTERN is not None

    # Tag Location Parsing Tests

    def test_parse_tag_location_basic(self):
        """Test parsing basic tag location."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location("torvalds/linux@v6.0")

        assert owner == "torvalds"
        assert repo == "linux"
        assert tag == "v6.0"

    def test_parse_tag_location_with_https(self):
        """Test parsing tag location with HTTPS URL."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location(
            "https://github.com/torvalds/linux@v6.0"
        )

        assert owner == "torvalds"
        assert repo == "linux"
        assert tag == "v6.0"

    def test_parse_tag_location_with_http(self):
        """Test parsing tag location with HTTP URL."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location(
            "http://github.com/torvalds/linux@v6.0"
        )

        assert owner == "torvalds"
        assert repo == "linux"
        assert tag == "v6.0"

    def test_parse_tag_location_with_git_suffix(self):
        """Test parsing tag location with .git suffix."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location(
            "https://github.com/torvalds/linux.git@v6.0"
        )

        assert owner == "torvalds"
        assert repo == "linux"
        assert tag == "v6.0"

    def test_parse_tag_location_with_dashes(self):
        """Test parsing tag location with dashes in names."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location("my-org/my-repo@v1.2.3")

        assert owner == "my-org"
        assert repo == "my-repo"
        assert tag == "v1.2.3"

    def test_parse_tag_location_with_dots(self):
        """Test parsing tag location with dots in repo name."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location("user/repo.name@v1.0.0")

        assert owner == "user"
        assert repo == "repo.name"
        assert tag == "v1.0.0"

    def test_parse_tag_location_complex_tag(self):
        """Test parsing tag location with complex tag name."""
        ops = TagOperations()
        owner, repo, tag = ops.parse_tag_location("org/repo@v1.2.3-rc.1+build.456")

        assert owner == "org"
        assert repo == "repo"
        assert tag == "v1.2.3-rc.1+build.456"

    def test_parse_tag_location_invalid_no_at(self):
        """Test parsing invalid tag location without @ separator."""
        ops = TagOperations()

        with pytest.raises(TagLocationError) as exc_info:
            ops.parse_tag_location("torvalds/linux")

        assert "Invalid tag location format" in str(exc_info.value)

    def test_parse_tag_location_invalid_no_slash(self):
        """Test parsing invalid tag location without / separator."""
        ops = TagOperations()

        with pytest.raises(TagLocationError) as exc_info:
            ops.parse_tag_location("torvalds@v6.0")

        assert "Invalid tag location format" in str(exc_info.value)

    def test_parse_tag_location_invalid_empty(self):
        """Test parsing empty tag location."""
        ops = TagOperations()

        with pytest.raises(TagLocationError) as exc_info:
            ops.parse_tag_location("")

        assert "Invalid tag location format" in str(exc_info.value)

    # Tagger Info Extraction Tests

    def test_extract_tagger_info_basic(self):
        """Test extracting tagger information from tag object."""
        ops = TagOperations()
        tag_object = """object abc123
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704067200 +0000

Release version 1.0.0"""

        name, email = ops._extract_tagger_info(tag_object)

        assert name == "John Doe"
        assert email == "john@example.com"

    def test_extract_tagger_info_with_middle_name(self):
        """Test extracting tagger info with middle name."""
        ops = TagOperations()
        tag_object = "tagger John Q. Doe <john.doe@example.com> 1234567890 +0000"

        name, email = ops._extract_tagger_info(tag_object)

        assert name == "John Q. Doe"
        assert email == "john.doe@example.com"

    def test_extract_tagger_info_with_special_chars(self):
        """Test extracting tagger info with special characters."""
        ops = TagOperations()
        tag_object = "tagger José García-López <jose@example.es> 1234567890 +0100"

        name, email = ops._extract_tagger_info(tag_object)

        assert name == "José García-López"
        assert email == "jose@example.es"

    def test_extract_tagger_info_no_tagger(self):
        """Test extracting tagger info when not present."""
        ops = TagOperations()
        tag_object = """object abc123
type commit
tag v1.0.0

No tagger line here"""

        name, email = ops._extract_tagger_info(tag_object)

        assert name is None
        assert email is None

    def test_extract_tagger_info_malformed(self):
        """Test extracting tagger info with malformed line."""
        ops = TagOperations()
        tag_object = "tagger InvalidFormat"

        name, email = ops._extract_tagger_info(tag_object)

        assert name is None
        assert email is None

    # Tag Date Extraction Tests

    def test_extract_tag_date_basic(self):
        """Test extracting tag date from tag object."""
        ops = TagOperations()
        tag_object = "tagger John Doe <john@example.com> 1704067200 +0000"

        date = ops._extract_tag_date(tag_object)

        assert date is not None
        assert "2024-01-01" in date
        assert date.endswith("+00:00")

    def test_extract_tag_date_different_timezone(self):
        """Test extracting tag date with different timezone."""
        ops = TagOperations()
        tag_object = "tagger John Doe <john@example.com> 1704067200 -0500"

        date = ops._extract_tag_date(tag_object)

        assert date is not None
        # Should still be in UTC
        assert date.endswith("+00:00")

    def test_extract_tag_date_no_tagger(self):
        """Test extracting tag date when tagger line is missing."""
        ops = TagOperations()
        tag_object = "object abc123\ntype commit"

        date = ops._extract_tag_date(tag_object)

        assert date is None

    # Tag Message Extraction Tests

    def test_extract_tag_message_basic(self):
        """Test extracting tag message from tag object."""
        ops = TagOperations()
        tag_object = """object abc123
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704067200 +0000

Release version 1.0.0
This is a major release."""

        message = ops._extract_tag_message(tag_object)

        assert message is not None
        assert "Release version 1.0.0" in message
        assert "major release" in message

    def test_extract_tag_message_multiline(self):
        """Test extracting multiline tag message."""
        ops = TagOperations()
        tag_object = """object abc123
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704067200 +0000

Release version 1.0.0

Features:
- Feature 1
- Feature 2

Bug fixes:
- Fix 1"""

        message = ops._extract_tag_message(tag_object)

        assert message is not None
        assert "Features:" in message
        assert "Bug fixes:" in message

    def test_extract_tag_message_no_message(self):
        """Test extracting tag message when not present."""
        ops = TagOperations()
        tag_object = """object abc123
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704067200 +0000"""

        message = ops._extract_tag_message(tag_object)

        assert message is None

    def test_extract_tag_message_empty_message(self):
        """Test extracting empty tag message."""
        ops = TagOperations()
        tag_object = """object abc123
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704067200 +0000

"""

        message = ops._extract_tag_message(tag_object)

        # Empty message after stripping
        assert message == "" or message is None

    # Repository Info Builder Tests

    def test_build_repository_info_basic(self):
        """Test building repository info."""
        ops = TagOperations()
        repo_info = ops.build_repository_info("torvalds", "linux")

        assert isinstance(repo_info, RepositoryInfo)
        assert repo_info.owner == "torvalds"
        assert repo_info.name == "linux"
        assert repo_info.clone_url == "https://github.com/torvalds/linux.git"
        assert repo_info.web_url == "https://github.com/torvalds/linux"
        assert repo_info.tag is None

    def test_build_repository_info_with_tag(self):
        """Test building repository info with tag."""
        ops = TagOperations()
        repo_info = ops.build_repository_info("torvalds", "linux", "v6.0")

        assert repo_info.owner == "torvalds"
        assert repo_info.name == "linux"
        assert repo_info.tag == "v6.0"

    # Async Git Operations Tests (with mocking)

    @pytest.mark.asyncio
    async def test_get_tag_object(self):
        """Test getting tag object content."""
        ops = TagOperations()

        mock_result = MagicMock()
        mock_result.stdout = "tag object content"

        with patch(
            "tag_validate.tag_operations.run_git",
            return_value=mock_result,
        ) as mock_run_git:
            result = await ops._get_tag_object("v1.0.0", Path("/repo"))

            assert result == "tag object content"
            mock_run_git.assert_called_once_with(
                ["git", "cat-file", "-p", "v1.0.0"],
                cwd=Path("/repo"),
            )

    @pytest.mark.asyncio
    async def test_get_tag_type_annotated(self):
        """Test getting tag type for annotated tag."""
        ops = TagOperations()

        mock_result = MagicMock()
        mock_result.stdout = "tag\n"

        with patch(
            "tag_validate.tag_operations.run_git",
            return_value=mock_result,
        ):
            result = await ops._get_tag_type("v1.0.0", Path("/repo"))

            assert result == "annotated"

    @pytest.mark.asyncio
    async def test_get_tag_type_lightweight(self):
        """Test getting tag type for lightweight tag."""
        ops = TagOperations()

        mock_result = MagicMock()
        mock_result.stdout = "commit\n"

        with patch(
            "tag_validate.tag_operations.run_git",
            return_value=mock_result,
        ):
            result = await ops._get_tag_type("v1.0.0", Path("/repo"))

            assert result == "lightweight"

    @pytest.mark.asyncio
    async def test_get_commit_sha(self):
        """Test getting commit SHA."""
        ops = TagOperations()

        mock_result = MagicMock()
        mock_result.stdout = "abc123def456\n"

        with patch(
            "tag_validate.tag_operations.run_git",
            return_value=mock_result,
        ) as mock_run_git:
            result = await ops._get_commit_sha("v1.0.0", Path("/repo"))

            assert result == "abc123def456"
            mock_run_git.assert_called_once_with(
                ["git", "rev-list", "-n", "1", "v1.0.0"],
                cwd=Path("/repo"),
            )

    @pytest.mark.asyncio
    async def test_fetch_tag_info_annotated(self):
        """Test fetching tag info for annotated tag."""
        ops = TagOperations()

        tag_object = """object abc123
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704067200 +0000

Release v1.0.0"""

        mock_tag_object = MagicMock()
        mock_tag_object.stdout = tag_object

        mock_tag_type = MagicMock()
        mock_tag_type.stdout = "tag\n"

        mock_commit_sha = MagicMock()
        mock_commit_sha.stdout = "abc123def456\n"

        with patch("tag_validate.tag_operations.run_git") as mock_run_git:
            mock_run_git.side_effect = [mock_tag_object, mock_tag_type, mock_commit_sha]

            result = await ops.fetch_tag_info("v1.0.0", repo_path=Path("/repo"))

            assert isinstance(result, TagInfo)
            assert result.tag_name == "v1.0.0"
            assert result.tag_type == "annotated"
            assert result.tagger_name == "John Doe"
            assert result.tagger_email == "john@example.com"
            assert result.commit_sha == "abc123def456"
            assert result.tag_message == "Release v1.0.0"

    @pytest.mark.asyncio
    async def test_fetch_tag_info_lightweight(self):
        """Test fetching tag info for lightweight tag."""
        ops = TagOperations()

        mock_tag_object = MagicMock()
        mock_tag_object.stdout = "commit object content"

        mock_tag_type = MagicMock()
        mock_tag_type.stdout = "commit\n"

        mock_commit_sha = MagicMock()
        mock_commit_sha.stdout = "xyz789abc123\n"

        with patch("tag_validate.tag_operations.run_git") as mock_run_git:
            mock_run_git.side_effect = [mock_tag_object, mock_tag_type, mock_commit_sha]

            result = await ops.fetch_tag_info("v2.0.0", repo_path=Path("/repo"))

            assert isinstance(result, TagInfo)
            assert result.tag_name == "v2.0.0"
            assert result.tag_type == "lightweight"
            assert result.tagger_name is None
            assert result.tagger_email is None
            assert result.commit_sha == "xyz789abc123"

    @pytest.mark.asyncio
    async def test_fetch_tag_info_with_remote_url(self):
        """Test fetching tag info with remote URL."""
        ops = TagOperations()

        mock_tag_object = MagicMock()
        mock_tag_object.stdout = "commit content"

        mock_tag_type = MagicMock()
        mock_tag_type.stdout = "commit\n"

        mock_commit_sha = MagicMock()
        mock_commit_sha.stdout = "abc123\n"

        with patch("tag_validate.tag_operations.run_git") as mock_run_git:
            mock_run_git.side_effect = [mock_tag_object, mock_tag_type, mock_commit_sha]

            result = await ops.fetch_tag_info(
                "v1.0.0",
                repo_path=Path("/repo"),
                remote_url="https://github.com/org/repo",
            )

            assert result.remote_url == "https://github.com/org/repo"

    @pytest.mark.asyncio
    async def test_get_local_tag_info(self):
        """Test getting local tag info (convenience method)."""
        ops = TagOperations()

        mock_tag_object = MagicMock()
        mock_tag_object.stdout = "commit content"

        mock_tag_type = MagicMock()
        mock_tag_type.stdout = "commit\n"

        mock_commit_sha = MagicMock()
        mock_commit_sha.stdout = "abc123\n"

        with patch("tag_validate.tag_operations.run_git") as mock_run_git:
            mock_run_git.side_effect = [mock_tag_object, mock_tag_type, mock_commit_sha]

            result = await ops.get_local_tag_info(Path("/repo"), "v1.0.0")

            assert isinstance(result, TagInfo)
            assert result.tag_name == "v1.0.0"

    @pytest.mark.asyncio
    async def test_fetch_tag_info_git_error(self):
        """Test fetch_tag_info when git command fails."""
        ops = TagOperations()

        with patch(
            "tag_validate.tag_operations.run_git",
            new=AsyncMock(side_effect=Exception("Git error")),
        ):
            with pytest.raises(TagLocationError) as exc_info:
                await ops.fetch_tag_info("v1.0.0", repo_path=Path("/repo"))

            assert "Failed to fetch tag" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_clone_remote_tag_success(self):
        """Test cloning remote tag successfully."""
        ops = TagOperations()

        mock_temp_dir = Path("/tmp/tag-validate-test")

        # Mock the git operations
        mock_tag_object = MagicMock()
        mock_tag_object.stdout = "commit content"

        mock_tag_type = MagicMock()
        mock_tag_type.stdout = "commit\n"

        mock_commit_sha = MagicMock()
        mock_commit_sha.stdout = "abc123\n"

        with (
            patch(
                "tag_validate.tag_operations.create_secure_tempdir",
                return_value=mock_temp_dir,
            ),
            patch("tag_validate.tag_operations.clone"),
            patch("tag_validate.tag_operations.run_git") as mock_run_git,
            patch.object(ops, "_setup_ssh_allowed_signers", new_callable=AsyncMock),
        ):
            # First call is fetch, next calls are for tag info
            mock_run_git.side_effect = [
                MagicMock(),  # fetch call
                mock_tag_object,
                mock_tag_type,
                mock_commit_sha,
            ]

            temp_dir, tag_info = await ops.clone_remote_tag("torvalds", "linux", "v6.0")

            assert temp_dir == mock_temp_dir
            assert isinstance(tag_info, TagInfo)
            assert tag_info.tag_name == "v6.0"
            assert tag_info.remote_url == "https://github.com/torvalds/linux"

    @pytest.mark.asyncio
    async def test_clone_remote_tag_with_token(self):
        """Test cloning remote tag with authentication token."""
        ops = TagOperations()

        mock_temp_dir = Path("/tmp/tag-validate-test")

        with (
            patch(
                "tag_validate.tag_operations.create_secure_tempdir",
                return_value=mock_temp_dir,
            ),
            patch("tag_validate.tag_operations.clone") as mock_clone,
            patch("tag_validate.tag_operations.run_git") as mock_run_git,
            patch.object(ops, "_setup_ssh_allowed_signers", new_callable=AsyncMock),
        ):
            mock_run_git.side_effect = [
                MagicMock(),  # fetch
                MagicMock(stdout="commit"),  # tag object
                MagicMock(stdout="commit\n"),  # tag type
                MagicMock(stdout="abc123\n"),  # commit sha
            ]

            await ops.clone_remote_tag(
                "torvalds", "linux", "v6.0", token="secret_token"
            )

            # Verify clone was called with token in URL
            mock_clone.assert_called_once()
            call_args = mock_clone.call_args
            assert "x-access-token:secret_token" in call_args.kwargs["url"]

    @pytest.mark.asyncio
    async def test_clone_remote_tag_cleanup_on_error(self):
        """Test that temp directory is cleaned up on clone failure."""
        ops = TagOperations()

        mock_temp_dir = Path("/tmp/tag-validate-test")

        with (
            patch(
                "tag_validate.tag_operations.create_secure_tempdir",
                return_value=mock_temp_dir,
            ),
            patch(
                "tag_validate.tag_operations.clone",
                side_effect=Exception("Clone failed"),
            ),
            patch("tag_validate.tag_operations.secure_rmtree") as mock_rmtree,
        ):
            with pytest.raises(TagLocationError):
                await ops.clone_remote_tag("torvalds", "linux", "v6.0")

            # Verify cleanup was called
            mock_rmtree.assert_called_once_with(mock_temp_dir)
