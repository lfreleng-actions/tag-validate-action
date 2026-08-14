# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Shared state contract for the validation workflow mixins.

``ValidationWorkflow`` is assembled from mixins that each live in their
own ``workflow_*`` module. Every mixin derives from ``WorkflowContext``,
which declares the instance state that ``ValidationWorkflow.__init__``
populates, so each module type-checks in isolation.
"""

from pathlib import Path

from .models import ValidationConfig, ValidationResult
from .signature import SignatureDetector
from .tag_operations import TagOperations
from .validation import TagValidator


class WorkflowContext:
    """Instance state shared by every validation workflow mixin.

    Attributes:
        config: ValidationConfig object with validation requirements
        repo_path: Path to the repository currently being validated
        gerrit_username: Gerrit username for HTTP authentication
        gerrit_password: Gerrit HTTP password for authentication
        use_netrc: Whether to use .netrc for credential lookup
        netrc_file: Explicit path to a .netrc file
        validator: TagValidator instance for version validation
        detector: SignatureDetector instance for signature detection
        operations: TagOperations instance for tag operations
    """

    config: ValidationConfig
    repo_path: Path
    gerrit_username: str | None
    gerrit_password: str | None
    use_netrc: bool
    netrc_file: Path | None
    validator: TagValidator
    detector: SignatureDetector
    operations: TagOperations
    _current_github_org: str | None
    _current_repo_context: tuple[str, str] | None

    async def validate_tag(
        self,
        tag_name: str,
        github_user: str | None = None,
        github_token: str | None = None,
        require_owners: list[str] | None = None,
    ) -> ValidationResult:
        """Perform complete tag validation.

        Implemented by ValidationWorkflow; declared here because the
        tag-location mixins delegate back to it.
        """
        raise NotImplementedError

    def _failed_result(self, tag_name: str, error_msg: str) -> ValidationResult:
        """Build a failed ValidationResult with a single error message.

        Args:
            tag_name: Tag name or location that failed validation
            error_msg: Error message to record

        Returns:
            ValidationResult: A result marked invalid with the error added.
        """
        result = ValidationResult(
            tag_name=tag_name,
            is_valid=False,
            config=self.config,
            tag_info=None,
            version_info=None,
            signature_info=None,
        )
        result.add_error(error_msg)
        return result
