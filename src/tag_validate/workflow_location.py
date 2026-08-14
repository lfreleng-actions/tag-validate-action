# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tag location parsing and routing for the validation workflow.

Turns a tag location string into a local or remote validation run,
falling back from local paths to remote repositories where the location
is ambiguous.
"""

import logging
from pathlib import Path

from .models import ValidationResult
from .workflow_clone import WorkflowCloneMixin
from .workflow_types import _TagLocationRequest

logger = logging.getLogger(__name__)


class WorkflowLocationMixin(WorkflowCloneMixin):
    """Tag location routing behaviour for ValidationWorkflow."""

    async def validate_tag_location(
        self,
        tag_location: str,
        github_user: str | None = None,
        github_token: str | None = None,
        require_owners: list[str] | None = None,
    ) -> ValidationResult:
        """Validate a tag from a location string with smart path detection.

        Supports multiple formats with pragmatic fallback behavior:

        Remote formats (requires network access):
        - owner/repo@tag → Fetches from GitHub
        - owner/repo/tag → Converted to owner/repo@tag
        - https://github.com/owner/repo@tag → Direct GitHub URL

        Local formats (filesystem access):
        - ./path/to/repo/tag → Explicit local repository path
        - /absolute/path/to/repo/tag → Absolute local path
        - tag → Tag name in current/specified repository

        Ambiguous formats (tries local first, then remote):
        - path/to/repo/tag → Checks if 'path/to/repo' exists locally
          - If local .git directory found → validates as local
          - Otherwise → tries as remote owner/repo/tag

        Examples:
            # Remote validation
            await workflow.validate_tag_location("torvalds/linux@v6.0")
            await workflow.validate_tag_location("torvalds/linux/v6.0")

            # Local validation
            await workflow.validate_tag_location("./my-repo/v1.0.0")
            await workflow.validate_tag_location("v1.0.0")  # uses current repo

            # Ambiguous (smart detection)
            await workflow.validate_tag_location("test-repo/v1.0.0")
            # Checks if ./test-repo/.git exists, else tries remote

        Args:
            tag_location: Tag location string or tag name
            github_user: GitHub username for key verification
            github_token: GitHub token for API access
            require_owners: List of required GitHub usernames or emails that must own the signing key

        Returns:
            ValidationResult: Complete validation result
        """
        logger.debug(f"Validating tag location: {tag_location}")
        request = _TagLocationRequest(
            github_user=github_user,
            github_token=github_token,
            require_owners=require_owners,
        )

        # Check if it's a remote location or local tag
        from urllib.parse import urlparse

        parsed_host = urlparse(tag_location).hostname or ""
        is_github_host = parsed_host == "github.com" or parsed_host.endswith(
            ".github.com"
        )
        if "@" in tag_location and ("/" in tag_location or is_github_host):
            # Definite remote tag - parse and clone
            return await self._validate_definite_remote(tag_location, request)
        if "/" in tag_location:
            # Ambiguous: local path or remote; try local first
            return await self._validate_ambiguous_tag_location(tag_location, request)
        # No slash or @ - treat as local tag name in current repo
        return await self.validate_tag(
            tag_location, github_user, github_token, require_owners
        )

    async def _validate_definite_remote(
        self,
        tag_location: str,
        request: _TagLocationRequest,
    ) -> ValidationResult:
        """Validate a definite remote tag (owner/repo@tag or GitHub URL).

        Args:
            tag_location: Remote tag location string
            request: Bundled verification options

        Returns:
            ValidationResult: Complete validation result.
        """
        try:
            owner, repo, tag = self.operations.parse_tag_location(tag_location)
            logger.debug(f"Parsed location: {owner}/{repo}@{tag}")
            return await self._clone_and_validate(
                owner,
                repo,
                tag,
                request,
                set_org=True,
            )
        except Exception as e:
            logger.error(f"Failed to validate remote tag: {e}")
            result = self._failed_result(
                tag_location, f"Failed to validate remote tag: {e}"
            )
            # Provide helpful context
            if "parse_tag_location" in str(e):
                result.add_info(
                    "Expected format: 'owner/repo@tag' (e.g., 'torvalds/linux@v6.0')"
                )
            return result

    async def _validate_ambiguous_tag_location(
        self,
        tag_location: str,
        request: _TagLocationRequest,
    ) -> ValidationResult:
        """Validate an ambiguous location, trying local path then remote.

        Args:
            tag_location: Ambiguous tag location (path/to/repo/tag form)
            request: Bundled verification options

        Returns:
            ValidationResult: Complete validation result.
        """
        # Split into potential repo path and tag name
        parts = tag_location.rsplit("/", 1)
        potential_repo_path = parts[0]
        potential_tag = parts[1] if len(parts) > 1 else tag_location

        # Check if it looks like a local path (directory exists)
        local_path = Path(self.repo_path) / potential_repo_path

        if local_path.is_dir() and (local_path / ".git").exists():
            return await self._validate_local_repo_path(
                tag_location,
                local_path,
                potential_repo_path,
                potential_tag,
                request,
            )
        return await self._validate_remote_fallback(tag_location, request)

    async def _validate_remote_fallback(
        self,
        tag_location: str,
        request: _TagLocationRequest,
    ) -> ValidationResult:
        """Validate an ambiguous location as a remote tag (fallback).

        Args:
            tag_location: Original tag location string
            request: Bundled verification options

        Returns:
            ValidationResult: Complete validation result.
        """
        logger.debug(f"Local path not found, treating as remote: {tag_location}")
        # Convert owner/repo/tag to owner/repo@tag if needed
        if tag_location.count("/") >= 2:
            parts = tag_location.rsplit("/", 1)
            normalized_location = f"{parts[0]}@{parts[1]}"
        else:
            normalized_location = tag_location

        try:
            owner, repo, tag = self.operations.parse_tag_location(normalized_location)
            logger.debug(f"Parsed as remote location: {owner}/{repo}@{tag}")
            return await self._clone_and_validate(
                owner,
                repo,
                tag,
                request,
                set_org=False,
            )
        except Exception as e:
            logger.error(f"Failed to validate as remote tag: {e}")
            result = self._failed_result(
                tag_location, f"Failed to validate remote tag: {e}"
            )
            # Add helpful suggestions based on the error
            lower = str(e).lower()
            if "couldn't find remote ref" in lower or "not found" in lower:
                result.add_warning(
                    f"Tag '{tag_location}' not found. "
                    "Please verify the tag exists in the remote repository."
                )
            elif "failed to clone" in lower:
                result.add_warning(
                    "Possible formats: 'owner/repo@tag', "
                    "'./local/repo/tag', or 'tag-name'"
                )
            return result
