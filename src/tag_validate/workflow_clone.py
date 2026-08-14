# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Repository checkout handling for tag-location validation.

Validates a tag inside a temporary clone of a remote repository or
inside a repository discovered on the local filesystem, restoring the
workflow's original repository state afterwards.
"""

import logging
from pathlib import Path

from .models import ValidationResult
from .workflow_context import WorkflowContext
from .workflow_types import _TagLocationRequest

logger = logging.getLogger(__name__)


class WorkflowCloneMixin(WorkflowContext):
    """Checkout handling behaviour for ValidationWorkflow."""

    async def _clone_and_validate(
        self,
        owner: str,
        repo: str,
        tag: str,
        request: _TagLocationRequest,
        *,
        set_org: bool,
    ) -> ValidationResult:
        """Clone a remote tag and validate it in a temporary checkout.

        The repository path, detector, temporary directory, and repo
        context are always restored/cleaned up once validation completes,
        regardless of whether validation succeeds or raises.

        Args:
            owner: Repository owner
            repo: Repository name
            tag: Tag to validate
            request: Bundled verification options
            set_org: Whether to record the GitHub org for Gerrit discovery

        Returns:
            ValidationResult: Result of validating the cloned tag.
        """
        from dependamerge.git_ops import secure_rmtree

        # Resolve the detector through the workflow module so that
        # tag_validate.workflow.SignatureDetector stays the patch seam
        from . import workflow

        temp_dir, _tag_info = await self.operations.clone_remote_tag(
            owner=owner,
            repo=repo,
            tag=tag,
            token=request.github_token,
        )
        # Capture before the try so the finally can always restore it
        original_repo_path = self.repo_path
        try:
            # Update repo path and detector
            self.repo_path = temp_dir
            self.detector = workflow.SignatureDetector(temp_dir)

            if set_org:
                # Store GitHub org for Gerrit auto-discovery
                self._current_github_org = owner
            # Store repo context for increment/branch checks
            self._current_repo_context = (owner, repo)

            # Validate the tag
            return await self.validate_tag(
                tag,
                request.github_user,
                request.github_token,
                request.require_owners,
            )
        finally:
            # Always restore the original repo path/detector so a failed
            # validation does not leave the instance pointing at the
            # now-deleted temporary checkout
            self.repo_path = original_repo_path
            self.detector = workflow.SignatureDetector(original_repo_path)
            # Clean up temporary directory
            secure_rmtree(temp_dir)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            if set_org:
                self._current_github_org = None
            self._current_repo_context = None

    async def _validate_local_repo_path(
        self,
        tag_location: str,
        local_path: Path,
        potential_repo_path: str,
        potential_tag: str,
        request: _TagLocationRequest,
    ) -> ValidationResult:
        """Validate a tag inside a discovered local repository path.

        Args:
            tag_location: Original tag location string
            local_path: Resolved local repository path
            potential_repo_path: Repo path portion of the location
            potential_tag: Tag portion of the location
            request: Bundled verification options

        Returns:
            ValidationResult: Complete validation result.
        """
        # Resolve the detector through the workflow module so that
        # tag_validate.workflow.SignatureDetector stays the patch seam
        from . import workflow

        logger.debug(
            f"Treating as local repo path: {potential_repo_path}/{potential_tag}"
        )
        # Capture before the try so except handlers can restore it
        original_repo_path = self.repo_path
        try:
            # Update repo path and detector temporarily
            self.repo_path = local_path
            self.detector = workflow.SignatureDetector(local_path)
            result = await self.validate_tag(
                potential_tag,
                request.github_user,
                request.github_token,
                request.require_owners,
            )
            # Restore original repo path
            self.repo_path = original_repo_path
            self.detector = workflow.SignatureDetector(original_repo_path)
            return result
        except Exception as e:
            logger.error(f"Failed to validate local tag: {e}")
            # Restore original repo path
            self.repo_path = original_repo_path
            self.detector = workflow.SignatureDetector(original_repo_path)
            result = self._failed_result(
                tag_location, f"Failed to validate local tag: {e}"
            )
            # Add helpful hint about tag format
            if "not a git repository" in str(e).lower():
                result.add_info(
                    f"Repository path '{potential_repo_path}' was found "
                    "but may have issues. Verify that it contains a valid "
                    ".git directory."
                )
            return result
