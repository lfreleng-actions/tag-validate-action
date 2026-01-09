# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tag operations module for tag-validate.

This module provides functionality for fetching, parsing, and working with
Git tags from both local and remote repositories.

Classes:
    TagOperations: Main class for tag-related Git operations
    TagLocationError: Exception for tag location parsing errors

Typical usage:
    ops = TagOperations()
    tag_info = await ops.fetch_tag_info("v1.2.3", repo_path=Path.cwd())
    print(f"Tag: {tag_info.tag_name}, Tagger: {tag_info.tagger_name}")
"""

import logging
import re
from pathlib import Path
from typing import Optional, Tuple

from dependamerge.git_ops import clone, create_secure_tempdir, run_git, secure_rmtree

from .models import RepositoryInfo, TagInfo

logger = logging.getLogger(__name__)


class TagLocationError(Exception):
    """Exception raised when tag location cannot be parsed or accessed."""

    pass


class TagOperations:
    """Handles Git tag operations for local and remote repositories.

    This class provides methods to fetch tag information, clone remote tags,
    parse tag locations, and extract tag metadata from Git objects.

    Attributes:
        TAG_LOCATION_PATTERN: Regex pattern for parsing tag locations
    """

    # Pattern: owner/repo@tag or https://github.com/owner/repo@tag
    TAG_LOCATION_PATTERN = re.compile(
        r"^(?:https?://github\.com/)?"  # Optional GitHub URL
        r"(?P<owner>[a-zA-Z0-9_-]+)"  # Owner/org name
        r"/"
        r"(?P<repo>[a-zA-Z0-9_.-]+?)"  # Repo name
        r"(?:\.git)?"  # Optional .git suffix
        r"@"
        r"(?P<tag>.+)"  # Tag name
        r"$"
    )

    def __init__(self) -> None:
        """Initialize TagOperations."""
        logger.debug("Initialized TagOperations")

    async def fetch_tag_info(
        self,
        tag_name: str,
        repo_path: Optional[Path] = None,
        remote_url: Optional[str] = None,
    ) -> TagInfo:
        """Fetch comprehensive information about a Git tag.

        Args:
            tag_name: Name of the tag to fetch
            repo_path: Path to local repository (default: current directory)
            remote_url: Optional remote repository URL for context

        Returns:
            TagInfo: Comprehensive tag information

        Raises:
            TagLocationError: If tag cannot be found or accessed

        Examples:
            >>> ops = TagOperations()
            >>> info = await ops.fetch_tag_info("v1.2.3")
            >>> print(info.tag_name)
            'v1.2.3'
        """
        if repo_path is None:
            repo_path = Path.cwd()

        logger.debug(f"Fetching tag info for '{tag_name}' in {repo_path}")

        # Get tag object content
        try:
            tag_object = await self._get_tag_object(tag_name, repo_path)
        except Exception as e:
            raise TagLocationError(f"Failed to fetch tag '{tag_name}': {e}") from e

        # Parse tag type
        tag_type = await self._get_tag_type(tag_name, repo_path)

        # Extract tagger information (for annotated tags)
        tagger_name = None
        tagger_email = None
        tag_date = None
        tag_message = None

        if tag_type == "annotated":
            tagger_name, tagger_email = self._extract_tagger_info(tag_object)
            tag_date = self._extract_tag_date(tag_object)
            tag_message = self._extract_tag_message(tag_object)

        # Get commit SHA
        commit_sha = await self._get_commit_sha(tag_name, repo_path)

        # Build TagInfo
        tag_info = TagInfo(
            tag_name=tag_name,
            tag_type=tag_type,
            commit_sha=commit_sha,
            tagger_name=tagger_name,
            tagger_email=tagger_email,
            tag_date=tag_date,
            tag_message=tag_message,
            remote_url=remote_url,
        )

        logger.debug(f"Fetched tag info: {tag_info.tag_name} ({tag_info.tag_type})")
        return tag_info

    async def get_local_tag_info(
        self,
        repo_path: Path,
        tag_name: str,
    ) -> TagInfo:
        """Get information about a tag in a local repository.

        This is a convenience method that wraps fetch_tag_info for local repos.

        Args:
            repo_path: Path to the local Git repository
            tag_name: Name of the tag to inspect

        Returns:
            TagInfo: Tag information

        Raises:
            TagLocationError: If tag cannot be found

        Examples:
            >>> ops = TagOperations()
            >>> info = await ops.get_local_tag_info(Path("/path/to/repo"), "v1.0.0")
        """
        logger.debug(f"Getting local tag info: {tag_name} in {repo_path}")
        return await self.fetch_tag_info(tag_name, repo_path=repo_path)

    async def clone_remote_tag(
        self,
        owner: str,
        repo: str,
        tag: str,
        token: Optional[str] = None,
    ) -> Tuple[Path, TagInfo]:
        """Clone a remote repository and fetch tag information.

        Creates a temporary directory, clones the repository, and fetches
        the specified tag. The caller is responsible for cleanup.

        Args:
            owner: Repository owner (GitHub username or org)
            repo: Repository name
            tag: Tag name to fetch
            token: Optional GitHub token for authentication

        Returns:
            Tuple[Path, TagInfo]: (temp_dir_path, tag_info)

        Raises:
            TagLocationError: If clone or tag fetch fails

        Examples:
            >>> ops = TagOperations()
            >>> temp_dir, info = await ops.clone_remote_tag("torvalds", "linux", "v6.0")
            >>> # Use the tag...
            >>> secure_rmtree(temp_dir)  # Clean up when done
        """
        logger.debug(f"Cloning remote tag: {owner}/{repo}@{tag}")

        # Create secure temp directory
        temp_dir = Path(create_secure_tempdir(prefix="tag-validate-"))
        logger.debug(f"Created temp directory: {temp_dir}")

        try:
            # Build repository URL
            if token:
                repo_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
            else:
                repo_url = f"https://github.com/{owner}/{repo}.git"

            # Clone repository (shallow clone for efficiency)
            logger.debug(f"Cloning {owner}/{repo} to {temp_dir}")
            clone(
                url=repo_url,
                dest=temp_dir,
                depth=1,
                branch=None,  # Clone default branch
            )

            # Fetch the specific tag
            logger.debug(f"Fetching tag {tag}")
            run_git(
                ["git", "fetch", "--depth=1", "origin", f"refs/tags/{tag}:refs/tags/{tag}"],
                cwd=temp_dir,
            )

            # Setup SSH allowed signers with smart fallback
            await self._setup_ssh_allowed_signers(temp_dir)

            # Get tag info
            remote_url = f"https://github.com/{owner}/{repo}"
            tag_info = await self.fetch_tag_info(
                tag_name=tag,
                repo_path=temp_dir,
                remote_url=remote_url,
            )

            logger.debug(f"Successfully cloned and fetched tag {tag}")
            return temp_dir, tag_info

        except Exception as e:
            # Clean up on failure
            logger.error(f"Failed to clone remote tag: {e}")
            secure_rmtree(temp_dir)
            raise TagLocationError(f"Failed to clone {owner}/{repo}@{tag}: {e}") from e

    async def _setup_ssh_allowed_signers(self, repo_path: Path) -> None:
        """Setup SSH allowed signers file with smart fallback.

        Checks multiple locations in priority order:
        1. Already exists in cloned repository (committed file)
        2. Current working directory (.ssh-allowed-signers)
        3. Git config (gpg.ssh.allowedSignersFile)
        4. Home directory (~/.ssh/allowed_signers)
        5. XDG config directory (~/.config/git/allowed_signers)

        Args:
            repo_path: Path to repository where SSH verification will occur
        """
        import shutil

        # Check if file already exists in the cloned repository
        repo_signers = repo_path / ".ssh-allowed-signers"
        if repo_signers.exists():
            logger.debug(f"Using .ssh-allowed-signers from cloned repository")
            run_git(
                ["git", "config", "gpg.ssh.allowedSignersFile", ".ssh-allowed-signers"],
                cwd=repo_path,
            )
            return

        # Try to find allowed signers file in fallback locations
        signers_file = None
        source_description = None

        # 1. Current working directory
        cwd_signers = Path.cwd() / ".ssh-allowed-signers"
        logger.debug(f"Checking for signers file in current directory: {cwd_signers}")
        if cwd_signers.exists():
            signers_file = cwd_signers
            source_description = "current directory"
            logger.debug(f"Found signers file in current directory")

        # 2. Action directory (when running as GitHub Action)
        # Check if GITHUB_ACTION_PATH is set and look there
        if not signers_file:
            import os
            action_path = os.environ.get("GITHUB_ACTION_PATH")
            if action_path:
                action_signers = Path(action_path) / ".ssh-allowed-signers"
                logger.debug(f"Checking for signers file in action directory: {action_signers}")
                if action_signers.exists():
                    signers_file = action_signers
                    source_description = "GitHub Action directory"
                    logger.debug(f"Found signers file in action directory")

        # 3. Git config
        if not signers_file:
            try:
                result = run_git(["git", "config", "--get", "gpg.ssh.allowedSignersFile"])
                if result.stdout.strip():
                    config_path = Path(result.stdout.strip()).expanduser()
                    if config_path.exists():
                        signers_file = config_path
                        source_description = "git config"
            except Exception as exc:
                logger.debug(
                    "Failed to read gpg.ssh.allowedSignersFile from git config; "
                    "continuing with fallback locations: %s",
                    exc,
                )

        # 4. Home directory standard location
        if not signers_file:
            home_signers = Path.home() / ".ssh" / "allowed_signers"
            if home_signers.exists():
                signers_file = home_signers
                source_description = "~/.ssh/allowed_signers"

        # 5. XDG config directory
        if not signers_file:
            xdg_signers = Path.home() / ".config" / "git" / "allowed_signers"
            if xdg_signers.exists():
                signers_file = xdg_signers
                source_description = "~/.config/git/allowed_signers"

        # If we found a signers file, copy it and configure Git
        if signers_file:
            dest_signers = repo_path / ".ssh-allowed-signers"
            logger.debug(f"Copying signers file from {signers_file} to {dest_signers}")
            shutil.copy2(signers_file, dest_signers)
            logger.debug(f"Copied .ssh-allowed-signers from {source_description} to {repo_path}")

            logger.debug(f"Configuring git in {repo_path} to use .ssh-allowed-signers")
            run_git(
                ["git", "config", "gpg.ssh.allowedSignersFile", ".ssh-allowed-signers"],
                cwd=repo_path,
            )
            logger.debug("Configured Git to use .ssh-allowed-signers for SSH verification")
        else:
            logger.warning(f"No .ssh-allowed-signers file found in any fallback location (checked cwd: {Path.cwd()})")

    def parse_tag_location(self, location: str) -> Tuple[str, str, str]:
        """Parse a tag location string into components.

        Supports formats:
        - owner/repo@tag
        - https://github.com/owner/repo@tag
        - https://github.com/owner/repo.git@tag

        Args:
            location: Tag location string

        Returns:
            Tuple[str, str, str]: (owner, repo, tag)

        Raises:
            TagLocationError: If location format is invalid

        Examples:
            >>> ops = TagOperations()
            >>> owner, repo, tag = ops.parse_tag_location("torvalds/linux@v6.0")
            >>> owner, repo, tag
            ('torvalds', 'linux', 'v6.0')
        """
        logger.debug(f"Parsing tag location: {location}")

        match = self.TAG_LOCATION_PATTERN.match(location)
        if not match:
            raise TagLocationError(
                f"Invalid tag location format: '{location}'. "
                f"Expected: owner/repo@tag or https://github.com/owner/repo@tag"
            )

        owner = match.group("owner")
        repo = match.group("repo")
        tag = match.group("tag")

        logger.debug(f"Parsed location: owner={owner}, repo={repo}, tag={tag}")
        return owner, repo, tag

    def _extract_tagger_info(self, tag_object: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract tagger name and email from tag object.

        Parses the 'tagger' line in a Git tag object to extract the
        committer's name and email address.

        Args:
            tag_object: Raw tag object content

        Returns:
            Tuple[Optional[str], Optional[str]]: (tagger_name, tagger_email)

        Examples:
            >>> ops = TagOperations()
            >>> tag_obj = "tagger John Doe <john@example.com> 1234567890 +0000"
            >>> name, email = ops._extract_tagger_info(tag_obj)
            >>> name, email
            ('John Doe', 'john@example.com')
        """
        # Pattern: tagger Name <email@example.com> timestamp timezone
        pattern = re.compile(
            r"^tagger\s+"
            r"(?P<name>.+?)"
            r"\s+<(?P<email>[^>]+)>"
            r"\s+\d+\s+[+-]\d{4}",
            re.MULTILINE,
        )

        match = pattern.search(tag_object)
        if match:
            name = match.group("name").strip()
            email = match.group("email").strip()
            logger.debug(f"Extracted tagger: {name} <{email}>")
            return name, email

        logger.debug("No tagger information found in tag object")
        return None, None

    def _extract_tag_date(self, tag_object: str) -> Optional[str]:
        """Extract tag creation date from tag object.

        Args:
            tag_object: Raw tag object content

        Returns:
            Optional[str]: ISO 8601 timestamp or None

        Examples:
            >>> ops = TagOperations()
            >>> tag_obj = "tagger John <j@ex.com> 1704067200 +0000"
            >>> ops._extract_tag_date(tag_obj)
            '2024-01-01T00:00:00+00:00'
        """
        # Pattern: tagger ... timestamp timezone
        pattern = re.compile(
            r"^tagger\s+.+?\s+<[^>]+>\s+(?P<timestamp>\d+)\s+(?P<timezone>[+-]\d{4})",
            re.MULTILINE,
        )

        match = pattern.search(tag_object)
        if match:
            timestamp = int(match.group("timestamp"))
            # Convert to ISO 8601 format
            from datetime import datetime, timezone as dt_timezone

            dt = datetime.fromtimestamp(timestamp, tz=dt_timezone.utc)
            iso_date = dt.isoformat()
            logger.debug(f"Extracted tag date: {iso_date}")
            return iso_date

        return None

    def _extract_tag_message(self, tag_object: str) -> Optional[str]:
        """Extract tag message from tag object.

        The tag message is everything after the header lines
        (object, type, tag, tagger) and the blank line.

        Args:
            tag_object: Raw tag object content

        Returns:
            Optional[str]: Tag message or None

        Examples:
            >>> ops = TagOperations()
            >>> tag_obj = '''object abc123
            ... type commit
            ... tag v1.0.0
            ... tagger John <j@ex.com> 123 +0000
            ...
            ... Release version 1.0.0'''
            >>> ops._extract_tag_message(tag_obj).strip()
            'Release version 1.0.0'
        """
        # Split on double newline (header/message separator)
        parts = tag_object.split("\n\n", 1)
        if len(parts) > 1:
            message = parts[1].strip()
            logger.debug(f"Extracted tag message ({len(message)} chars)")
            return message

        return None

    async def _get_tag_object(self, tag_name: str, repo_path: Path) -> str:
        """Get the raw tag object content.

        Args:
            tag_name: Name of the tag
            repo_path: Path to the repository

        Returns:
            str: Raw tag object content

        Raises:
            Exception: If git command fails
        """
        logger.debug(f"Getting tag object for {tag_name}")
        result = run_git(
            ["git", "cat-file", "-p", tag_name],
            cwd=repo_path,
        )
        return result.stdout  # type: ignore[no-any-return]

    async def _get_tag_type(self, tag_name: str, repo_path: Path) -> str:
        """Determine if tag is annotated or lightweight.

        Args:
            tag_name: Name of the tag
            repo_path: Path to the repository

        Returns:
            str: "annotated" or "lightweight"
        """
        logger.debug(f"Determining tag type for {tag_name}")

        # Try to get tag object type
        result = run_git(
            ["git", "cat-file", "-t", tag_name],
            cwd=repo_path,
        )

        tag_type_raw = result.stdout.strip()

        if tag_type_raw == "tag":
            return "annotated"
        elif tag_type_raw == "commit":
            return "lightweight"
        else:
            logger.warning(f"Unexpected tag type: {tag_type_raw}")
            return "lightweight"

    async def _get_commit_sha(self, tag_name: str, repo_path: Path) -> str:
        """Get the commit SHA that the tag points to.

        Args:
            tag_name: Name of the tag
            repo_path: Path to the repository

        Returns:
            str: Commit SHA (40 character hex string)

        Raises:
            Exception: If git command fails
        """
        logger.debug(f"Getting commit SHA for tag {tag_name}")
        result = run_git(
            ["git", "rev-list", "-n", "1", tag_name],
            cwd=repo_path,
        )
        commit_sha = result.stdout.strip()
        logger.debug(f"Tag {tag_name} points to commit {commit_sha[:8]}")
        return commit_sha  # type: ignore[no-any-return]

    def build_repository_info(
        self,
        owner: str,
        repo: str,
        tag: Optional[str] = None,
    ) -> RepositoryInfo:
        """Build a RepositoryInfo object from components.

        Args:
            owner: Repository owner
            repo: Repository name
            tag: Optional tag name

        Returns:
            RepositoryInfo: Repository information object

        Examples:
            >>> ops = TagOperations()
            >>> repo_info = ops.build_repository_info("torvalds", "linux", "v6.0")
            >>> repo_info.clone_url
            'https://github.com/torvalds/linux.git'
        """
        clone_url = f"https://github.com/{owner}/{repo}.git"
        web_url = f"https://github.com/{owner}/{repo}"

        return RepositoryInfo(
            owner=owner,
            name=repo,
            clone_url=clone_url,
            web_url=web_url,
            tag=tag,
        )
