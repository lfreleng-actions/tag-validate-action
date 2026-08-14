# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Release gate checks for the tag validation workflow.

Groups the increment, branch containment, tag freshness, and
latest-commit gates together with the helper that runs them in order.
"""

import logging
from pathlib import Path

from .models import TagInfo, ValidationResult
from .workflow_context import WorkflowContext

logger = logging.getLogger(__name__)


class WorkflowGatesMixin(WorkflowContext):
    """Release gate behaviour for ValidationWorkflow."""

    async def _run_gate_checks(
        self,
        tag_name: str,
        tag_info: TagInfo,
        result: ValidationResult,
        github_token: str | None,
    ) -> bool:
        """Run increment, branch, age, and latest-commit gates.

        Args:
            tag_name: Name of the tag being validated
            tag_info: Fetched tag information
            result: Validation result to update
            github_token: GitHub API token (optional)

        Returns:
            True to continue validation, False if a gate failed and the
            caller should stop (result already updated).
        """
        # Step 2b: Enforce version increment (if requested)
        if self.config.enforce_increment and not await self._check_increment(
            tag_name, result, github_token
        ):
            result.is_valid = False
            return False

        # Step 2c: Require tag commit on a specific branch (if requested)
        if self.config.require_branch and not await self._check_branch(
            tag_name, tag_info, result, github_token
        ):
            result.is_valid = False
            return False

        # Step 2d: Require the tag to be recently created (if requested)
        if self.config.max_tag_age_minutes is not None and not self._check_tag_age(
            tag_name, tag_info, result
        ):
            result.is_valid = False
            return False

        # Step 2e: Require the tag to be the branch tip (if requested)
        if self.config.require_latest and not await self._check_latest(
            tag_name, tag_info, result, github_token
        ):
            result.is_valid = False
            return False

        return True

    async def _check_increment(
        self,
        tag_name: str,
        result: ValidationResult,
        github_token: str | None = None,
    ) -> bool:
        """Check that the tag increments the repository version.

        Enumerates repository tags (GitHub API and/or local git) and
        requires the tag to compare strictly greater than the highest
        existing comparable tag. Fails closed when tags cannot be
        enumerated or ordering cannot be established.

        Args:
            tag_name: Name of the tag being validated
            result: ValidationResult to update
            github_token: GitHub API token (optional)

        Returns:
            bool: True if the tag is incremental
        """
        from .increment_check import (
            check_increment,
            detect_repo_context,
            list_repository_tags,
        )
        from .models import IncrementCheckInfo

        logger.debug(f"Checking version increment for tag: {tag_name}")

        owner, repo = self._current_repo_context or (None, None)
        context = detect_repo_context(Path(self.repo_path), owner, repo)

        try:
            tags, tag_source = await list_repository_tags(
                Path(self.repo_path), context, github_token
            )
        except Exception as e:
            result.increment_check = IncrementCheckInfo(
                checked=True,
                incremental=None,
                errors=[f"Failed to enumerate repository tags: {e}"],
            )
            result.add_error(
                f"Increment enforcement failed: could not enumerate "
                f"repository tags: {e}"
            )
            return False

        check = check_increment(
            tag_name, tags, validator=self.validator, tag_source=tag_source
        )
        result.increment_check = check

        if check.incremental:
            if check.latest_tag:
                result.add_info(
                    f"Tag increments repository version "
                    f"(previous highest: {check.latest_tag})"
                )
            else:
                result.add_info("Tag is the first version tag in the repository")
            return True

        for error in check.errors:
            result.add_error(error)
        if not check.errors:
            result.add_error(
                f"Tag '{tag_name}' does not increment the repository "
                f"version (latest: {check.latest_tag})"
            )
        return False

    async def _check_branch(
        self,
        tag_name: str,
        tag_info: TagInfo,
        result: ValidationResult,
        github_token: str | None = None,
    ) -> bool:
        """Check that the tag commit is reachable from the required branch.

        Args:
            tag_name: Name of the tag being validated
            tag_info: Tag information (provides the commit SHA)
            result: ValidationResult to update
            github_token: GitHub API token (optional)

        Returns:
            bool: True if the tag commit is on the required branch
        """
        from .increment_check import (
            check_branch_containment,
            detect_repo_context,
        )
        from .models import BranchCheckInfo

        require_branch = self.config.require_branch or ""
        logger.debug(
            f"Checking branch containment for tag {tag_name} (branch: {require_branch})"
        )

        owner, repo = self._current_repo_context or (None, None)
        context = detect_repo_context(Path(self.repo_path), owner, repo)

        try:
            check = await check_branch_containment(
                tag_name=tag_name,
                commit_sha=tag_info.commit_sha,
                branch=require_branch,
                repo_path=Path(self.repo_path),
                context=context,
                token=github_token,
            )
        except Exception as e:
            # Fail closed: an unexpected error (network/IO) must block
            # the release gate rather than abort validation entirely
            result.branch_check = BranchCheckInfo(
                checked=True,
                branch=require_branch or None,
                contains=None,
                errors=[f"Branch containment check failed: {e}"],
            )
            result.add_error(
                f"Branch containment check failed for tag '{tag_name}': {e}"
            )
            return False
        result.branch_check = check

        if check.contains:
            result.add_info(f"Tag commit is reachable from branch '{check.branch}'")
            return True

        for error in check.errors:
            result.add_error(error)
        if not check.errors:
            result.add_error(
                f"Tag '{tag_name}' commit is not reachable from branch '{check.branch}'"
            )
        return False

    def _check_tag_age(
        self,
        tag_name: str,
        tag_info: TagInfo,
        result: ValidationResult,
    ) -> bool:
        """Check that the tag was created within the allowed window.

        Args:
            tag_name: Name of the tag being validated
            tag_info: Tag information (provides type and creation date)
            result: ValidationResult to update

        Returns:
            bool: True if the tag is recent enough
        """
        from .increment_check import check_tag_age
        from .models import TagAgeCheckInfo

        max_age = self.config.max_tag_age_minutes or 0.0
        logger.debug(f"Checking tag age for {tag_name} (window: {max_age:g} minutes)")

        try:
            check = check_tag_age(tag_info, max_age)
        except Exception as e:
            # Fail closed: an unexpected error must block the release
            # gate rather than abort validation entirely
            result.age_check = TagAgeCheckInfo(
                checked=True,
                recent=None,
                tag_date=tag_info.tag_date,
                max_age_minutes=max_age,
                errors=[f"Tag age check failed: {e}"],
            )
            result.add_error(f"Tag age check failed for tag '{tag_name}': {e}")
            return False
        result.age_check = check

        if check.recent:
            result.add_info(f"Tag was created within the last {max_age:g} minute(s)")
            return True

        for error in check.errors:
            result.add_error(error)
        if not check.errors:
            result.add_error(
                f"Tag '{tag_name}' was not created within the last "
                f"{max_age:g} minute(s)"
            )
        return False

    async def _check_latest(
        self,
        tag_name: str,
        tag_info: TagInfo,
        result: ValidationResult,
        github_token: str | None = None,
    ) -> bool:
        """Check that the tag commit is the current tip of the branch.

        The target branch is require_branch when it names a concrete
        branch, otherwise the repository default branch.

        Args:
            tag_name: Name of the tag being validated
            tag_info: Tag information (provides the commit SHA)
            result: ValidationResult to update
            github_token: GitHub API token (optional)

        Returns:
            bool: True if the tag commit is the branch tip
        """
        from .increment_check import (
            check_latest_commit,
            detect_repo_context,
        )
        from .models import LatestCheckInfo

        # Reuse the branch gate's target when it names a concrete
        # branch; 'true' (or unset) auto-detects the default branch
        branch = self.config.require_branch or "true"
        logger.debug(f"Checking tag {tag_name} points to the tip of branch: {branch}")

        owner, repo = self._current_repo_context or (None, None)
        context = detect_repo_context(Path(self.repo_path), owner, repo)

        try:
            check = await check_latest_commit(
                tag_name=tag_name,
                commit_sha=tag_info.commit_sha,
                branch=branch,
                repo_path=Path(self.repo_path),
                context=context,
                token=github_token,
            )
        except Exception as e:
            # Fail closed: an unexpected error (network/IO) must block
            # the release gate rather than abort validation entirely
            result.latest_check = LatestCheckInfo(
                checked=True,
                latest=None,
                # The sentinel 'true' means auto-detect; only a concrete
                # branch name is meaningful in diagnostics
                branch=branch if branch.lower() != "true" else None,
                tag_sha=tag_info.commit_sha,
                errors=[f"Latest-commit check failed: {e}"],
            )
            result.add_error(f"Latest-commit check failed for tag '{tag_name}': {e}")
            return False
        result.latest_check = check

        if check.latest:
            result.add_info(f"Tag commit is the current tip of branch '{check.branch}'")
            return True

        for error in check.errors:
            result.add_error(error)
        if not check.errors:
            result.add_error(
                f"Tag '{tag_name}' commit is not the current tip of "
                f"branch '{check.branch}'"
            )
        return False
