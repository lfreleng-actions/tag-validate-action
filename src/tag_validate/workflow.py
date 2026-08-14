# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Verification workflow module for tag-validate.

This module orchestrates the complete tag validation workflow, combining:
- Version validation (SemVer/CalVer)
- Signature detection and verification
- GitHub key verification
- Tag information gathering

The individual validation stages live in the sibling ``workflow_*``
modules and are composed here into a single ValidationWorkflow class.

Classes:
    ValidationWorkflow: Main workflow orchestration class

Typical usage:
    from tag_validate.workflow import ValidationWorkflow
    from tag_validate.models import ValidationConfig

    config = ValidationConfig(
        require_semver=True,
        require_signed=True,
        require_github=True,
    )

    workflow = ValidationWorkflow(config)
    result = await workflow.validate_tag("v1.2.3", github_user="torvalds")

    if result.is_valid:
        print("✅ Tag validation passed!")
    else:
        print(f"❌ Validation failed: {result.errors}")
"""

import logging
from pathlib import Path

from .gerrit_keys import GerritKeysClient
from .github_keys import GitHubKeysClient
from .models import (
    TagInfo,
    ValidationConfig,
    ValidationResult,
)
from .signature import SignatureDetector
from .tag_operations import TagOperations
from .validation import TagValidator
from .workflow_gates import WorkflowGatesMixin
from .workflow_gerrit import WorkflowGerritMixin
from .workflow_github import WorkflowGitHubMixin
from .workflow_location import WorkflowLocationMixin
from .workflow_signature import WorkflowSignatureMixin
from .workflow_summary import WorkflowSummaryMixin
from .workflow_version import WorkflowVersionMixin

# GerritKeysClient, GitHubKeysClient and SignatureDetector are re-exported
# here: they are the collaborators the workflow stages resolve through this
# module, so they can be substituted in one place.
__all__ = [
    "GerritKeysClient",
    "GitHubKeysClient",
    "SignatureDetector",
    "ValidationWorkflow",
]

logger = logging.getLogger(__name__)


class ValidationWorkflow(
    WorkflowGatesMixin,
    WorkflowGerritMixin,
    WorkflowGitHubMixin,
    WorkflowLocationMixin,
    WorkflowSignatureMixin,
    WorkflowSummaryMixin,
    WorkflowVersionMixin,
):
    """Orchestrates the complete tag validation workflow.

    This class combines all validation components to provide a complete
    tag validation workflow, including version validation, signature
    detection, and optional GitHub key verification.

    Attributes:
        config: ValidationConfig object with validation requirements
        validator: TagValidator instance for version validation
        detector: SignatureDetector instance for signature detection
        operations: TagOperations instance for tag operations
    """

    def __init__(
        self,
        config: ValidationConfig,
        repo_path: Path | None = None,
        gerrit_username: str | None = None,
        gerrit_password: str | None = None,
        use_netrc: bool = True,
        netrc_file: Path | str | None = None,
    ):
        """Initialize the validation workflow.

        Args:
            config: Validation configuration
            repo_path: Path to Git repository (default: current directory)
            gerrit_username: Gerrit username for HTTP authentication (optional)
            gerrit_password: Gerrit HTTP password for authentication (optional)
            use_netrc: Whether to use .netrc for credential lookup (default: True)
            netrc_file: Explicit path to .netrc file (optional)

        Security Note:
            Credentials (gerrit_password) are stored in memory only for the duration
            of operations and are never logged or included in error messages.
            The password is masked in string representations to prevent accidental exposure.

        Credential Priority:
            1. Explicit CLI arguments (gerrit_username/gerrit_password)
            2. .netrc file (if use_netrc=True)
            3. Environment variables (GERRIT_USERNAME/GERRIT_PASSWORD)
        """
        self.config = config
        self.repo_path = repo_path or Path.cwd()
        self.gerrit_username = gerrit_username
        self.gerrit_password = gerrit_password
        self.use_netrc = use_netrc
        self.netrc_file = (
            Path(netrc_file) if isinstance(netrc_file, str) else netrc_file
        )

        # Initialize components
        self.validator: TagValidator = TagValidator()
        self.detector: SignatureDetector = SignatureDetector(self.repo_path)
        self.operations: TagOperations = TagOperations()
        self._current_github_org: str | None = None
        # Remote repository context (owner, repo) when validating a
        # remote tag location; used by increment/branch checks
        self._current_repo_context: tuple[str, str] | None = None

        logger.debug(f"Initialized ValidationWorkflow with config: {config}")

    def __repr__(self) -> str:
        """Return string representation with masked credentials.

        Security: Password is never exposed in string representation.
        """
        password_status = "set" if self.gerrit_password else "not set"
        username_display = (
            repr(self.gerrit_username) if self.gerrit_username else "None"
        )
        return (
            f"ValidationWorkflow(config={self.config!r}, "
            f"repo_path={self.repo_path}, "
            f"gerrit_username={username_display}, "
            f"gerrit_password=***{password_status}***)"
        )

    async def _setup_ssh_allowed_signers(self) -> None:
        """Setup SSH allowed signers for the current repository."""
        try:
            logger.debug(
                f"Setting up SSH allowed signers for repository: {self.repo_path}"
            )
            await self.operations._setup_ssh_allowed_signers(self.repo_path)
            # Verify the file was created
            signers_file = self.repo_path / ".ssh-allowed-signers"
            if signers_file.exists():
                logger.debug(f"SSH allowed signers file created at: {signers_file}")
            else:
                logger.warning(f"SSH allowed signers file NOT found at: {signers_file}")
        except Exception as e:
            logger.warning(f"Failed to setup SSH allowed signers: {e}", exc_info=True)

    async def validate_tag(
        self,
        tag_name: str,
        github_user: str | None = None,
        github_token: str | None = None,
        require_owners: list[str] | None = None,
    ) -> ValidationResult:
        """Perform complete tag validation.

        This is the main entry point for the validation workflow. It performs
        all configured validation steps and returns a comprehensive result.

        Args:
            tag_name: Name of the tag to validate
            github_user: GitHub username for key verification (optional)
            github_token: GitHub API token (optional, for rate limiting)

        Returns:
            ValidationResult: Complete validation result with all checks

        Examples:
            >>> config = ValidationConfig(require_semver=True, require_signed=True)
            >>> workflow = ValidationWorkflow(config)
            >>> result = await workflow.validate_tag("v1.2.3")
            >>> if result.is_valid:
            ...     print("Valid tag!")
        """
        logger.debug(f"Starting validation workflow for tag: {tag_name}")

        # Setup SSH allowed signers for local repository
        await self._setup_ssh_allowed_signers()

        # Initialize result
        result = ValidationResult(
            tag_name=tag_name,
            is_valid=True,
            config=self.config,
            tag_info=None,
            version_info=None,
            signature_info=None,
        )

        # Step 1: Fetch tag information
        try:
            tag_info = await self._fetch_tag_info(tag_name)
            result.tag_info = tag_info
            result.add_info(f"Tag type: {tag_info.tag_type}")
        except Exception as e:
            result.is_valid = False
            result.add_error(f"Failed to fetch tag information: {e}")
            logger.error(f"Tag info fetch failed: {e}")
            return result

        # Step 2: Detect and enforce version type
        if not self._run_version_step(result, tag_name):
            return result

        # Steps 2b-2e: Increment, branch, age, and latest gates
        if not await self._run_gate_checks(tag_name, tag_info, result, github_token):
            return result

        # Step 3: Detect and validate signature
        signature_info = await self._run_signature_step(result, tag_name, tag_info)
        if signature_info is None:
            return result

        # Step 4: Verify key on GitHub (if requested and signature exists)
        if self.config.require_github:
            await self._verify_github_key_step(
                result,
                signature_info,
                github_user,
                github_token,
                require_owners,
            )

        # Step 5: Verify key on Gerrit (if requested and signature exists)
        if self.config.require_gerrit:
            await self._verify_gerrit_key_step(result, signature_info, require_owners)

        # Final validation summary
        if result.is_valid:
            logger.debug(f"✅ Tag validation passed: {tag_name}")
        else:
            logger.warning(f"❌ Tag validation failed: {tag_name}")

        return result

    async def _fetch_tag_info(self, tag_name: str) -> TagInfo:
        """Fetch tag information from the repository.

        Args:
            tag_name: Name of the tag

        Returns:
            TagInfo: Tag information

        Raises:
            Exception: If tag fetch fails
        """
        logger.debug(f"Fetching tag info: {tag_name}")
        tag_info = await self.operations.fetch_tag_info(
            tag_name,
            repo_path=self.repo_path,
        )
        logger.debug(
            f"Tag info fetched: {tag_info.tag_type}, commit: {tag_info.commit_sha[:8]}"
        )
        return tag_info
