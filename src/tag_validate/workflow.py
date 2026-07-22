# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Verification workflow module for tag-validate.

This module orchestrates the complete tag validation workflow, combining:
- Version validation (SemVer/CalVer)
- Signature detection and verification
- GitHub key verification
- Tag information gathering

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
import re
from dataclasses import dataclass
from pathlib import Path

from dependamerge.git_ops import redact_text, run_git

from .display_utils import format_server_display, format_user_details
from .gerrit_keys import (
    GerritInvalidCredentialsError,
    GerritKeysClient,
    GerritMissingCredentialsError,
    GerritServerError,
)
from .github_keys import GitHubKeysClient
from .models import (
    KeyVerificationResult,
    SignatureInfo,
    TagInfo,
    ValidationConfig,
    ValidationResult,
    VersionInfo,
)
from .signature import SignatureDetector
from .tag_operations import TagOperations
from .validation import TagValidator

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _TagLocationRequest:
    """Bundled verification options for tag-location validation helpers.

    Groups the user/token/owner parameters that are threaded together
    through the internal tag-location validation helpers.
    """

    github_user: str | None = None
    github_token: str | None = None
    require_owners: list[str] | None = None


class ValidationWorkflow:
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

    def _run_version_step(self, result: ValidationResult, tag_name: str) -> bool:
        """Detect the version type and enforce type requirements.

        Args:
            result: Validation result to update
            tag_name: Name of the tag being validated

        Returns:
            True to continue validation, False if a requirement failed and
            the caller should stop (result already updated).
        """
        if self.config.skip_version_validation:
            # Skip version validation entirely (legacy flag support)
            result.add_info("Version validation skipped (--skip-version-validation)")
            return True

        version_result = self._validate_version(tag_name)
        result.version_info = version_result

        # Only enforce type requirements if explicitly configured
        if (
            self.config.require_semver or self.config.require_calver
        ) and not self._check_version_requirements(version_result):
            result.is_valid = False
            required_types = []
            if self.config.require_semver:
                required_types.append("semver")
            if self.config.require_calver:
                required_types.append("calver")
            result.add_error(
                f"Version type '{version_result.version_type}' does not "
                f"match required type(s): {', '.join(required_types)}"
            )
            return False
        # Otherwise accept any type (including "other")
        return True

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

    async def _run_signature_step(
        self,
        result: ValidationResult,
        tag_name: str,
        tag_info: TagInfo,
    ) -> SignatureInfo | None:
        """Detect and validate the tag signature.

        Args:
            result: Validation result to update
            tag_name: Name of the tag being validated
            tag_info: Fetched tag information

        Returns:
            The detected SignatureInfo when validation should continue, or
            None if the caller should stop (result already updated).
        """
        try:
            signature_info = await self._detect_signature(tag_name, tag_info)
            result.signature_info = signature_info

            if not self._check_signature_requirements(signature_info, result):
                result.is_valid = False
                return None
        except Exception as e:
            result.is_valid = False
            result.add_error(f"Signature detection failed: {e}")
            logger.error(f"Signature detection failed: {e}")
            return None
        return signature_info

    async def _detect_github_user(
        self,
        signature_info: SignatureInfo,
        github_user: str | None,
        github_token: str | None,
    ) -> tuple[str | None, bool]:
        """Resolve the GitHub username, auto-detecting from signer email.

        Args:
            signature_info: Signature information
            github_user: Explicitly provided GitHub username (optional)
            github_token: GitHub API token (optional)

        Returns:
            Tuple of (username or None, whether it was auto-enumerated).
        """
        if github_user or not signature_info.signer_email:
            return github_user, False

        logger.debug(
            f"Attempting to auto-detect GitHub username from email: "
            f"{signature_info.signer_email}"
        )
        try:
            from .github_keys import GitHubKeysClient

            async with GitHubKeysClient(token=github_token) as client:
                detected = await client.lookup_username_by_email(
                    signature_info.signer_email
                )
                if detected:
                    logger.debug(f"Auto-detected GitHub username: {detected}")
                    return detected, True
                logger.warning(
                    f"Could not auto-detect GitHub username from email: "
                    f"{signature_info.signer_email}"
                )
        except Exception as e:
            logger.debug(f"Failed to auto-detect GitHub username: {e}")
        return None, False

    async def _verify_github_key_step(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        github_user: str | None,
        github_token: str | None,
        require_owners: list[str] | None,
    ) -> None:
        """Verify the signing key against GitHub (Step 4).

        Args:
            result: Validation result to update
            signature_info: Signature information
            github_user: GitHub username for key verification (optional)
            github_token: GitHub API token (optional)
            require_owners: Required owners the key must belong to (optional)
        """
        if not (signature_info.type in ["gpg", "ssh"] and signature_info.verified):
            result.add_info("Skipping GitHub key verification (no valid signature)")
            return

        if not github_token:
            result.is_valid = False
            error_msg = (
                "GitHub token is required. Set GITHUB_TOKEN environment "
                "variable or pass --token"
            )
            result.add_error(error_msg)
            logger.error(error_msg)
            return

        detected_user, was_user_enumerated = await self._detect_github_user(
            signature_info, github_user, github_token
        )

        if require_owners:
            await self._verify_github_owners(
                result,
                signature_info,
                detected_user,
                github_token,
                require_owners,
            )
        elif detected_user:
            await self._verify_github_single_user(
                result,
                signature_info,
                detected_user,
                github_token,
                was_user_enumerated,
            )
        else:
            result.is_valid = False
            error_msg = (
                "GitHub key verification requested but no username provided "
                "or detected from tagger email"
            )
            result.add_error(error_msg)
            logger.error(error_msg)

    async def _verify_github_owners(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        detected_user: str | None,
        github_token: str | None,
        require_owners: list[str],
    ) -> None:
        """Verify the signing key against a set of required owners.

        Args:
            result: Validation result to update
            signature_info: Signature information
            detected_user: Detected GitHub username (unused for owners)
            github_token: GitHub API token (optional)
            require_owners: Required owners the key must belong to
        """
        try:
            key_result = await self._require_github_key(
                signature_info,
                detected_user if detected_user else "",
                github_token,
                require_owners,
            )
            result.key_verifications.append(key_result)
            if not key_result.key_registered:
                result.is_valid = False
                result.add_error(
                    f"Signing key not registered to any of the required "
                    f"owners: {', '.join(require_owners)}"
                )
        except Exception as e:
            result.is_valid = False
            result.add_error(f"GitHub key verification failed: {e}")
            logger.error(f"GitHub key verification failed: {e}")

    async def _verify_github_single_user(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        detected_user: str,
        github_token: str | None,
        was_user_enumerated: bool,
    ) -> None:
        """Verify the signing key against a single GitHub user.

        Args:
            result: Validation result to update
            signature_info: Signature information
            detected_user: GitHub username to verify against
            github_token: GitHub API token (optional)
            was_user_enumerated: Whether the username was auto-detected
        """
        try:
            key_result = await self._require_github_key(
                signature_info,
                detected_user,
                github_token,
                None,
            )
            # Set user_enumerated flag if username was auto-detected
            if was_user_enumerated and key_result:
                key_result.user_enumerated = True
            result.key_verifications.append(key_result)
            if not key_result.key_registered:
                result.is_valid = False
                result.add_error(
                    f"Signing key not registered to GitHub user @{detected_user}"
                )
        except Exception as e:
            result.is_valid = False
            result.add_error(f"GitHub key verification failed: {e}")
            logger.error(f"GitHub key verification failed: {e}")

    async def _verify_gerrit_connection(
        self,
        result: ValidationResult,
        gerrit_server: str,
    ) -> None:
        """Verify Gerrit connectivity and authentication.

        Args:
            result: Validation result to update on failure
            gerrit_server: Resolved Gerrit server hostname

        Raises:
            GerritMissingCredentialsError: Credentials required but absent
            GerritInvalidCredentialsError: Credentials provided but invalid
            GerritServerError: Other connection or server errors
        """
        async with GerritKeysClient(
            server=gerrit_server,
            username=self.gerrit_username,
            password=self.gerrit_password,
            use_netrc=self.use_netrc,
            netrc_file=self.netrc_file,
        ) as test_client:
            connection_ok, connection_error = await test_client.verify_connection()
            if connection_ok:
                return
            # Connection/auth failed - mark invalid and raise to skip
            # key verification
            result.is_valid = False
            error_msg = connection_error or "Unknown connection error"
            logger.error(f"Gerrit connection failed: {error_msg}")
            error_lower = error_msg.lower()
            if "credentials required" in error_lower:
                raise GerritMissingCredentialsError(error_msg)
            if (
                "invalid credentials" in error_lower
                or "rejected the provided credentials" in error_lower
            ):
                raise GerritInvalidCredentialsError(error_msg)
            raise GerritServerError(error_msg)

    def _handle_gerrit_server_error(
        self,
        result: ValidationResult,
        error_msg: str,
        gerrit_server: str | None,
    ) -> None:
        """Record result errors for a Gerrit server/connection failure.

        Args:
            result: Validation result to update
            error_msg: Error message from the raised GerritServerError
            gerrit_server: Resolved Gerrit server hostname (may be None)
        """
        lower_msg = error_msg.lower()
        is_endpoint_error = (
            "endpoint not available" in lower_msg or "may not support" in lower_msg
        )
        # When --require-gerrit is specified, verification MUST succeed
        # Any server limitation means the requirement cannot be satisfied
        result.is_valid = False
        result.add_error(
            f"Gerrit key verification required but unavailable: {error_msg}"
        )
        if is_endpoint_error:
            result.add_error(
                f"Gerrit server '{gerrit_server}' does not expose key "
                "management APIs. This server cannot be used for "
                "--require-gerrit verification."
            )

    async def _verify_gerrit_key_step(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        require_owners: list[str] | None,
    ) -> None:
        """Verify the signing key against Gerrit (Step 5).

        Args:
            result: Validation result to update
            signature_info: Signature information
            require_owners: Required owners the key must belong to (optional)
        """
        if not (signature_info.type in ["gpg", "ssh"] and signature_info.verified):
            # When --require-gerrit is specified, a valid signature is REQUIRED
            result.is_valid = False
            result.add_error(
                "Gerrit key verification required but tag has no valid "
                "signature. Tag must be signed with GPG or SSH to verify "
                "key on Gerrit."
            )
            return

        # Determine Gerrit server (bound before the try so except handlers
        # can safely reference it)
        gerrit_server = self.config.gerrit_server
        try:
            github_org = None
            if not gerrit_server:
                # Try to extract GitHub org from current context
                github_org = self._extract_github_org_from_context()
                if github_org:
                    gerrit_server = f"gerrit.{github_org}.org"
                else:
                    raise ValueError(
                        "No Gerrit server specified and could not "
                        "auto-detect from GitHub org"
                    )

            # Verify connection/auth before attempting key verification
            await self._verify_gerrit_connection(result, gerrit_server)

            # Use require_owners if provided, else verify against tagger email
            key_result = await self._require_gerrit_key(
                signature_info, gerrit_server, github_org, require_owners
            )
            result.key_verifications.append(key_result)
            if not key_result.key_registered:
                result.is_valid = False
                if require_owners:
                    result.add_error(
                        f"Signing key not registered to any of the required "
                        f"owners on Gerrit: {', '.join(require_owners)}"
                    )
                else:
                    result.add_error(
                        f"Signing key not registered on Gerrit server "
                        f"{key_result.server}"
                    )

        except GerritMissingCredentialsError as e:
            error_msg = str(e)
            logger.warning(
                f"Gerrit key verification unavailable: Missing credentials - {e}"
            )
            result.is_valid = False
            result.add_error(
                f"Gerrit key verification required but credentials not "
                f"provided: {error_msg}"
            )
            result.add_error(
                "Please provide Gerrit credentials via GERRIT_USERNAME and "
                "GERRIT_PASSWORD environment variables."
            )
        except GerritInvalidCredentialsError as e:
            error_msg = str(e)
            logger.warning(
                f"Gerrit key verification unavailable: Invalid credentials - {e}"
            )
            result.is_valid = False
            result.add_error(
                f"Gerrit key verification required but authentication "
                f"failed: {error_msg}"
            )
            result.add_error(
                "Please verify your Gerrit username and HTTP password are "
                "correct. Note: Use HTTP password from Gerrit Settings > "
                "HTTP Credentials, not your SSO/LDAP password."
            )
        except GerritServerError as e:
            error_msg = str(e)
            logger.warning(f"Gerrit key verification unavailable: {e}")
            self._handle_gerrit_server_error(result, error_msg, gerrit_server)
        except Exception as e:
            result.is_valid = False
            result.add_error(f"Gerrit key verification failed: {e}")
            logger.error(f"Gerrit key verification failed: {e}")

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

    def _validate_version(self, tag_name: str) -> VersionInfo:
        """Validate version format.

        Args:
            tag_name: Tag name to validate

        Returns:
            VersionInfo: Version validation result
        """
        logger.debug(f"Validating version: {tag_name}")

        # Use strict mode if configured
        strict_semver = self.config.require_semver and getattr(
            self.config, "strict_semver", False
        )

        version_result = self.validator.validate_version(
            tag_name,
            allow_prefix=self.config.allow_prefix,
            strict_semver=strict_semver,
        )

        logger.debug(
            f"Version validation: valid={version_result.is_valid}, "
            f"type={version_result.version_type}"
        )

        return version_result

    def _check_version_requirements(self, version_info: VersionInfo) -> bool:
        """Check if version meets configuration requirements.

        Args:
            version_info: Version validation result

        Returns:
            bool: True if requirements are met
        """
        # Check version type requirement
        type_required = self.config.require_semver or self.config.require_calver

        if type_required:
            # Build list of required types
            required_types = []
            if self.config.require_semver:
                required_types.append("semver")
            if self.config.require_calver:
                required_types.append("calver")

            # Handle "both" version type - it satisfies both requirements
            if version_info.version_type == "both":
                # Check if BOTH are required (AND logic)
                if self.config.require_semver and self.config.require_calver:
                    # "both" satisfies the requirement for both
                    pass  # Valid
                else:
                    # Only one is required, "both" still satisfies it (OR logic)
                    pass  # Valid
            else:
                # Single type - check if it matches at least one required type (OR logic)
                if version_info.version_type not in required_types:
                    logger.warning(
                        f"Version type {version_info.version_type} does not match required types: {', '.join(required_types)}"
                    )
                    return False

        # Check development version requirement
        if self.config.reject_development and version_info.is_development:
            logger.warning("Development versions are not allowed")
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

    async def _detect_signature(
        self, tag_name: str, tag_info: TagInfo
    ) -> SignatureInfo:
        """Detect signature on a tag.

        Args:
            tag_name: Name of the tag
            tag_info: Tag information including tagger email

        Returns:
            SignatureInfo: Signature detection result

        Raises:
            Exception: If signature detection fails
        """
        logger.debug(f"Detecting signature: {tag_name}")
        signature_info = await self.detector.detect_signature(tag_name)

        # For SSH signatures, use tagger email as fallback if signer_email is not set
        if (
            signature_info.type == "ssh"
            and not signature_info.signer_email
            and tag_info.tagger_email
        ):
            logger.debug(
                f"Using tagger email as signer email for SSH signature: {tag_info.tagger_email}"
            )
            signature_info = SignatureInfo(
                type=signature_info.type,
                verified=signature_info.verified,
                signer_email=tag_info.tagger_email,
                key_id=signature_info.key_id,
                fingerprint=signature_info.fingerprint,
                signature_data=signature_info.signature_data,
            )

        logger.debug(
            f"Signature detected: type={signature_info.type}, "
            f"verified={signature_info.verified}"
        )

        return signature_info

    def _check_signature_requirements(
        self,
        signature_info: SignatureInfo,
        result: ValidationResult,
    ) -> bool:
        """Check if signature meets requirements.

        Args:
            signature_info: Detected signature information
            result: Validation result to update

        Returns:
            bool: True if requirements are met
        """
        # Check if specific signature types are allowed
        if self.config.allowed_signature_types:
            # Specific signature types were specified - check if current type is allowed
            if signature_info.type not in self.config.allowed_signature_types:
                result.add_error(
                    f"Tag signature type '{signature_info.type}' is not allowed. "
                    f"Allowed types: {', '.join(self.config.allowed_signature_types)}"
                )
                logger.warning(
                    f"Signature type '{signature_info.type}' not in allowed types: "
                    f"{self.config.allowed_signature_types}"
                )
                return False

            # Type is allowed - check for any hard errors
            if signature_info.type == "invalid":
                result.add_error("Tag signature is invalid or corrupted")
                logger.warning(f"Invalid signature: key_id={signature_info.key_id}")
                return False
            elif signature_info.type == "lightweight":
                result.add_error(
                    "Lightweight tags are not allowed when signing requirements are specified"
                )
                logger.warning("Lightweight tag when signature requirements specified")
                return False

        # Check if signature is required (legacy boolean mode)
        elif self.config.require_signed:
            # Signature states rejected when signing is required:
            # - unsigned/lightweight: nothing to verify
            # - gpg-unverifiable: key missing (security risk)
            # - invalid: corrupted or tampered signature
            # Anything else is accepted: verified GPG/SSH, or an SSH
            # signature without an allowed_signers file to verify
            # against. Signature info is already shown in a dedicated
            # section
            rejections = {
                "unsigned": (
                    "Tag must be signed but is unsigned",
                    "Unsigned tag when signature is required",
                ),
                "lightweight": (
                    "Lightweight tags are not allowed when signing is required",
                    "Lightweight tag when signature is required",
                ),
                "gpg-unverifiable": (
                    "Tag has GPG signature but key is not available for verification",
                    f"GPG signature unverifiable: "
                    f"signer={signature_info.signer_email}, "
                    f"key_id={signature_info.key_id}",
                ),
                "invalid": (
                    "Tag signature is invalid or corrupted",
                    f"Invalid signature: key_id={signature_info.key_id}",
                ),
            }
            rejection = rejections.get(signature_info.type)
            if rejection:
                error_message, log_message = rejection
                result.add_error(error_message)
                logger.warning(log_message)
                return False

            if not signature_info.verified:
                # SSH signature without an allowed_signers file to
                # verify against (acceptable when only requiring a
                # signature to be present)
                logger.debug(
                    f"Signature present but not verified: type={signature_info.type}, "
                    f"signer={signature_info.signer_email}, key_id={signature_info.key_id}"
                )

        # Check if unsigned is explicitly required
        elif self.config.require_unsigned:
            if signature_info.type != "unsigned":
                result.add_error("Tag must be unsigned but has a signature")
                logger.warning("Signed tag when unsigned is required")
                return False

        # Ambivalent - accept any signature state
        # Signature info is already shown in dedicated section
        return True

    async def _verify_key_for_username(
        self,
        client: GitHubKeysClient,
        signature_info: SignatureInfo,
        username: str,
    ) -> KeyVerificationResult:
        """Verify the signing key is registered to a specific GitHub user.

        Args:
            client: Open GitHub keys client
            signature_info: Signature information
            username: GitHub username to verify against

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            ValueError: If the signature lacks required data or has an
                unsupported type
        """
        if signature_info.type == "gpg":
            if not signature_info.key_id:
                raise ValueError("GPG key ID not found in signature")
            return await client.verify_gpg_key_registered(
                username=username,
                key_id=signature_info.key_id,
                tagger_email=signature_info.signer_email,
                signer_email=signature_info.signer_email,
            )
        if signature_info.type == "ssh":
            if not signature_info.fingerprint:
                raise ValueError("SSH fingerprint not found in signature")
            return await client.verify_ssh_key_registered(
                username=username,
                public_key_fingerprint=signature_info.fingerprint,
                signer_email=signature_info.signer_email,
            )
        raise ValueError(f"Cannot verify {signature_info.type} signature type")

    async def _match_owner_key(
        self,
        client: GitHubKeysClient,
        signature_info: SignatureInfo,
        owner: str,
    ) -> KeyVerificationResult | None:
        """Check whether the signing key is registered to one owner.

        Args:
            client: Open GitHub keys client
            signature_info: Signature information
            owner: Required owner as a GitHub username or email address

        Returns:
            KeyVerificationResult if the key is registered to this owner,
            otherwise None (owner did not match or verification failed)
        """
        if "@" in owner:
            logger.debug(f"Checking if signer email matches: {owner}")
            if not (
                signature_info.signer_email
                and signature_info.signer_email.lower() == owner.lower()
            ):
                logger.debug(
                    f"Signer email {signature_info.signer_email} does not "
                    f"match required owner {owner}"
                )
                return None
            try:
                username = await client.lookup_username_by_email(owner)
                if username:
                    logger.debug(f"Found GitHub username for email {owner}: {username}")
                    result = await self._verify_key_for_username(
                        client, signature_info, username
                    )
                    if result.key_registered:
                        logger.debug(f"Key verified for owner email: {owner}")
                        return result
            except Exception as e:
                logger.debug(f"Could not verify email {owner}: {e}")
            return None

        logger.debug(f"Verifying key for GitHub username: {owner}")
        try:
            result = await self._verify_key_for_username(client, signature_info, owner)
            if result.key_registered:
                logger.debug(f"Key verified for owner: {owner}")
                return result
        except Exception as e:
            logger.debug(f"Could not verify username {owner}: {e}")
        return None

    async def _require_github_key(
        self,
        signature_info: SignatureInfo,
        github_user: str,
        github_token: str | None = None,
        require_owners: list[str] | None = None,
    ) -> KeyVerificationResult:
        """Verify signing key on GitHub.

        Args:
            signature_info: Signature information
            github_user: GitHub username to verify against
            github_token: GitHub API token (optional)
            require_owners: List of required GitHub usernames or emails that must own the signing key

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            Exception: If verification fails
        """
        # If require_owners is specified, check against all owners
        if require_owners:
            logger.debug(f"Verifying key against required owners: {require_owners}")

            async with GitHubKeysClient(token=github_token) as client:
                for owner in require_owners:
                    match = await self._match_owner_key(client, signature_info, owner)
                    if match is not None:
                        return match

                # If we get here, none of the owners matched
                logger.debug(
                    f"Key not registered to any of the required owners: {require_owners}"
                )
                return KeyVerificationResult(
                    key_registered=False,
                    username=", ".join(require_owners),
                    user_enumerated=False,
                    key_info=None,
                    service="github",
                    server="github.com",
                    user_email=signature_info.signer_email,
                )

        # Original behavior: verify against single github_user
        logger.debug(f"Verifying key on GitHub for user: {github_user}")

        async with GitHubKeysClient(token=github_token) as client:
            result = await self._verify_key_for_username(
                client, signature_info, github_user
            )

        logger.debug(f"Key verification result: registered={result.key_registered}")
        return result

    async def _require_gerrit_key(
        self,
        signature_info: SignatureInfo,
        gerrit_server: str,
        github_org: str | None = None,
        require_owners: list[str] | None = None,
    ) -> KeyVerificationResult:
        """Verify signing key on Gerrit.

        Args:
            signature_info: Signature information
            gerrit_server: Gerrit server hostname or URL
            github_org: GitHub organization name for auto-discovery (optional)
            require_owners: List of required usernames or emails that must own the signing key

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            Exception: If verification fails
        """
        # Determine the tagger email from signature
        tagger_email = signature_info.signer_email
        if not tagger_email:
            raise ValueError("Cannot verify Gerrit key without tagger email")

        logger.debug(f"Verifying key on Gerrit server: {gerrit_server}")

        async with GerritKeysClient(
            server=gerrit_server,
            github_org=github_org,
            username=self.gerrit_username,
            password=self.gerrit_password,
            use_netrc=self.use_netrc,
            netrc_file=self.netrc_file,
        ) as client:
            # Look up account by email
            account = await client.lookup_account_by_email(tagger_email)
            if not account:
                logger.debug(f"No Gerrit account found for email: {tagger_email}")
                return KeyVerificationResult(
                    key_registered=False,
                    username=tagger_email,
                    user_enumerated=True,
                    key_info=None,
                    service="gerrit",
                    server=gerrit_server,
                )

            # If require_owners is specified, check if account matches any owner
            if require_owners:
                logger.debug(
                    f"Verifying account against required owners: {require_owners}"
                )
                account_matches = False

                for owner in require_owners:
                    if "@" in owner:
                        # Owner is an email address
                        if account.email and account.email.lower() == owner.lower():
                            account_matches = True
                            break
                    else:
                        # Owner is a username
                        if (
                            account.username
                            and account.username.lower() == owner.lower()
                        ):
                            account_matches = True
                            break

                if not account_matches:
                    logger.debug(
                        f"Account {account.email} does not match required owners: {require_owners}"
                    )
                    return KeyVerificationResult(
                        key_registered=False,
                        username=", ".join(require_owners),
                        user_enumerated=False,
                        key_info=None,
                        service="gerrit",
                        server=gerrit_server,
                    )

            # Verify the key based on signature type
            if signature_info.type == "gpg":
                if not signature_info.key_id:
                    raise ValueError("GPG key ID not found in signature")

                result = await client.verify_gpg_key_registered(
                    account_id=account.account_id,
                    key_id=signature_info.key_id,
                )

            elif signature_info.type == "ssh":
                if not signature_info.fingerprint:
                    raise ValueError("SSH fingerprint not found in signature")

                result = await client.verify_ssh_key_registered(
                    account_id=account.account_id,
                    fingerprint=signature_info.fingerprint,
                )

            else:
                raise ValueError(f"Cannot verify {signature_info.type} signature type")

            logger.debug(
                f"Gerrit key verification result: registered={result.key_registered}"
            )
            return result

    def _extract_github_org_from_context(self) -> str | None:
        """Extract GitHub organization from current validation context.

        This method attempts to determine the GitHub organization from:
        1. Stored organization from remote repository validation
        2. Git remote URL (parsing github.com URLs)

        Returns:
            GitHub organization name if detected, None otherwise
        """
        # First check if we have a stored GitHub org from remote validation
        if hasattr(self, "_current_github_org") and self._current_github_org:
            logger.debug(
                f"Using stored GitHub org from remote validation: {self._current_github_org}"
            )
            return self._current_github_org

        try:
            # Read the remote URL via the redacting git wrapper so any
            # credential material embedded in the URL can never reach
            # logs or exception messages.
            result = run_git(
                ["git", "remote", "get-url", "origin"],
                cwd=self.repo_path,
                check=False,
                timeout=5,
            )

            if result.returncode == 0:
                remote_url = result.stdout.strip()
                logger.debug(f"Found git remote URL: {redact_text(remote_url)}")

                # Parse GitHub URL patterns
                patterns = [
                    r"github\.com[:/]([^/]+)/",  # https://github.com/owner/ or git@github.com:owner/
                    r"github\.com/([^/]+)",  # https://github.com/owner (no trailing slash)
                ]

                for pattern in patterns:
                    match = re.search(pattern, remote_url)
                    if match:
                        org = match.group(1)
                        logger.debug(f"Extracted GitHub org from remote URL: {org}")
                        return org
            else:
                logger.debug(
                    f"Git remote command failed with return code {result.returncode}"
                )

        except Exception as e:
            # Redact the exception text for defense-in-depth: if the git
            # wrapper ever surfaces a remote URL with embedded credentials
            # (e.g. from a legacy config) in its message, it must not reach
            # the logs verbatim.
            logger.debug(
                f"Could not extract GitHub org from git remote: {redact_text(str(e))}"
            )

        return None

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
            self.detector = SignatureDetector(temp_dir)

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
            self.detector = SignatureDetector(original_repo_path)
            # Clean up temporary directory
            secure_rmtree(temp_dir)
            logger.debug(f"Cleaned up temporary directory: {temp_dir}")
            if set_org:
                self._current_github_org = None
            self._current_repo_context = None

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
        logger.debug(
            f"Treating as local repo path: {potential_repo_path}/{potential_tag}"
        )
        # Capture before the try so except handlers can restore it
        original_repo_path = self.repo_path
        try:
            # Update repo path and detector temporarily
            self.repo_path = local_path
            self.detector = SignatureDetector(local_path)
            result = await self.validate_tag(
                potential_tag,
                request.github_user,
                request.github_token,
                request.require_owners,
            )
            # Restore original repo path
            self.repo_path = original_repo_path
            self.detector = SignatureDetector(original_repo_path)
            return result
        except Exception as e:
            logger.error(f"Failed to validate local tag: {e}")
            # Restore original repo path
            self.repo_path = original_repo_path
            self.detector = SignatureDetector(original_repo_path)
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

    def create_validation_summary(self, result: ValidationResult) -> str:
        """Create a human-readable validation summary.

        Args:
            result: Validation result

        Returns:
            str: Formatted summary text
        """
        lines: list[str] = []

        # Header
        status = "✅" if result.is_valid else "❌"
        lines.append(f"Overall Validation Result {status}")
        lines.append("")

        lines.extend(self._summary_version_lines(result))
        lines.extend(self._summary_signature_lines(result))
        lines.extend(self._summary_increment_lines(result))
        lines.extend(self._summary_branch_lines(result))
        lines.extend(self._summary_age_lines(result))
        lines.extend(self._summary_latest_lines(result))
        lines.extend(self._summary_key_verification_lines(result))

        # Errors - filter out redundant registration errors
        filtered_errors = self._summary_filtered_errors(result)
        if filtered_errors:
            # Add blank line before section if needed
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Errors:")
            lines.extend(f"  • {error}" for error in filtered_errors)

        # Warnings
        if result.warnings:
            # Add blank line before section if needed
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Warnings:")
            lines.extend(f"  • {warning}" for warning in result.warnings)

        # Info messages
        if result.info:
            # Only add blank line if we didn't just add one from a prior section
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Additional Information:")
            lines.extend(f"  • {info}" for info in result.info)

        # Remove trailing empty line if present
        while lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

    def _summary_version_lines(self, result: ValidationResult) -> list[str]:
        """Build the version-info section of the summary."""
        if not result.version_info:
            return []
        v = result.version_info
        lines: list[str] = []

        # Show validation status if version type requirement was specified
        version_status = ""
        if result.config.require_semver or result.config.require_calver:
            required_types = []
            if result.config.require_semver:
                required_types.append("semver")
            if result.config.require_calver:
                required_types.append("calver")
            # "both" type satisfies either requirement
            if v.version_type == "both" or v.version_type in required_types:
                version_status = " ✅"
            else:
                version_status = " ❌"

        lines.append(f"Tag Validation: {result.tag_name}{version_status}")
        lines.append(f"  Type: {v.version_type.upper()}")
        if v.version_type == "semver":
            lines.append(f"  Components: {v.major}.{v.minor}.{v.patch}")
            if v.prerelease:
                lines.append(f"  Prerelease: {v.prerelease}")
        elif v.version_type == "calver":
            lines.append(f"  Date: {v.year}.{v.month}.{v.day or v.micro}")
        if v.is_development:
            lines.append("  Development: Yes")
        lines.append("")
        return lines

    def _summary_signature_lines(self, result: ValidationResult) -> list[str]:
        """Build the signature-info section of the summary."""
        if not result.signature_info:
            return []
        s = result.signature_info
        # Display signature type with friendly names
        type_display = {
            "gpg": "GPG",
            "ssh": "SSH",
            "unsigned": "UNSIGNED",
            "lightweight": "LIGHTWEIGHT",
            "invalid": "INVALID (corrupted/tampered)",
            "gpg-unverifiable": "GPG (key not available)",
        }
        sig_type = type_display.get(s.type, s.type.upper())

        # Show validation status if signature requirement was specified
        signature_status = ""
        if (
            result.config.require_signed
            or result.config.require_unsigned
            or result.config.allowed_signature_types
        ):
            signature_valid = self._check_signature_requirements_status(
                result.signature_info, result.config
            )
            signature_status = " ✅" if signature_valid else " ❌"

        lines: list[str] = [f"Tag Signing{signature_status}"]
        if s.type in ["gpg", "ssh", "gpg-unverifiable", "invalid"]:
            lines.append(f"  Key Type: {sig_type}")
            if s.type == "gpg-unverifiable":
                lines.append("  Status: Key not available for verification")
            elif s.type == "invalid":
                lines.append("  Status: Signature is corrupted or tampered")
            if s.signer_email:
                lines.append(f"  Signer: {s.signer_email}")
            if s.key_id:
                lines.append(f"  Key ID: {s.key_id}")
        lines.append("")
        return lines

    def _summary_increment_lines(self, result: ValidationResult) -> list[str]:
        """Build the version-increment section of the summary."""
        if not (result.increment_check and result.increment_check.checked):
            return []
        ic = result.increment_check
        status_icon = "✅" if ic.incremental else "❌"
        lines: list[str] = [f"Version Increment {status_icon}"]
        if len(ic.latest_tags) > 1:
            # Multi-scheme push: report each scheme's baseline
            for scheme, tag in sorted(ic.latest_tags.items()):
                lines.append(f"  Latest Existing Tag ({scheme}): {tag}")
        elif ic.latest_tag:
            lines.append(f"  Latest Existing Tag: {ic.latest_tag}")
        elif ic.incremental:
            lines.append("  First version tag in repository")
        if ic.scheme:
            lines.append(f"  Comparison Scheme: {ic.scheme}")
        lines.append("")
        return lines

    def _summary_branch_lines(self, result: ValidationResult) -> list[str]:
        """Build the branch-containment section of the summary."""
        if not (result.branch_check and result.branch_check.checked):
            return []
        bc = result.branch_check
        status_icon = "✅" if bc.contains else "❌"
        lines: list[str] = [f"Branch Containment {status_icon}"]
        if bc.branch:
            lines.append(f"  Branch: {bc.branch}")
        if bc.method:
            lines.append(f"  Method: {bc.method}")
        lines.append("")
        return lines

    def _summary_age_lines(self, result: ValidationResult) -> list[str]:
        """Build the tag-freshness section of the summary."""
        if not (result.age_check and result.age_check.checked):
            return []
        ac = result.age_check
        status_icon = "✅" if ac.recent else "❌"
        lines: list[str] = [f"Tag Freshness {status_icon}"]
        if ac.max_age_minutes is not None:
            lines.append(f"  Window: {ac.max_age_minutes:g} minute(s)")
        if ac.age_seconds is not None:
            lines.append(f"  Tag Age: {ac.age_seconds:.0f} seconds")
        lines.append("")
        return lines

    def _summary_latest_lines(self, result: ValidationResult) -> list[str]:
        """Build the latest-commit section of the summary."""
        if not (result.latest_check and result.latest_check.checked):
            return []
        lc = result.latest_check
        status_icon = "✅" if lc.latest else "❌"
        lines: list[str] = [f"Latest Commit {status_icon}"]
        if lc.branch:
            lines.append(f"  Branch: {lc.branch}")
        if lc.branch_sha:
            lines.append(f"  Branch Tip: {lc.branch_sha[:12]}")
        if lc.method:
            lines.append(f"  Method: {lc.method}")
        lines.append("")
        return lines

    def _summary_key_verification_lines(self, result: ValidationResult) -> list[str]:
        """Build the key-verification section of the summary."""
        if not result.key_verifications:
            return []
        lines: list[str] = []
        for k in result.key_verifications:
            # Determine service name and status
            service_name = "Gerrit" if k.service == "gerrit" else "GitHub"
            status_icon = "✅" if k.key_registered else "❌"
            lines.append(f"{service_name} Registered {status_icon}")

            # Show server info using shared utility
            server_line = format_server_display(k.service, k.server)
            if server_line:
                lines.append(server_line)

            lines.append("")
            lines.append(f"{service_name} User:")

            # Build user details using shared utility
            user_lines = format_user_details(
                username=k.username,
                email=k.user_email,
                name=k.user_name,
            )
            lines.extend(user_lines)
            lines.append("")
        return lines

    def _summary_filtered_errors(self, result: ValidationResult) -> list[str]:
        """Return errors with redundant registration errors filtered out.

        Registration errors for a service already shown in the key
        verification section are omitted to avoid duplication.
        """
        if not result.errors:
            return []
        # Collect all services shown in key_verifications section
        services_in_display: set[str] = set()
        if result.key_verifications:
            services_in_display = {k.service for k in result.key_verifications}

        filtered_errors: list[str] = []
        for error in result.errors:
            error_lower = error.lower()
            is_registration_error = "not registered" in error_lower
            # Check which service this error is about
            is_github_error = "github" in error_lower
            is_gerrit_error = "gerrit" in error_lower
            # Only filter if this error is about a service shown above
            should_filter = is_registration_error and (
                (is_github_error and "github" in services_in_display)
                or (is_gerrit_error and "gerrit" in services_in_display)
            )
            if not should_filter:
                filtered_errors.append(error)
        return filtered_errors

    def _check_signature_requirements_status(
        self,
        signature_info: SignatureInfo,
        config: ValidationConfig,
    ) -> bool:
        """Check if signature meets requirements without adding errors.

        This is used for display purposes to show ✅/❌ status.

        Args:
            signature_info: Detected signature information
            config: Validation configuration

        Returns:
            bool: True if signature requirements are met
        """
        # Check if specific signature types are allowed
        if config.allowed_signature_types:
            if signature_info.type not in config.allowed_signature_types:
                return False
            # Type is allowed - check for hard errors
            return signature_info.type not in ["invalid", "lightweight"]

        # Check if signature is required (legacy boolean mode)
        elif config.require_signed:
            return signature_info.type not in [
                "unsigned",
                "lightweight",
                "gpg-unverifiable",
                "invalid",
            ]

        # Check if unsigned is explicitly required
        elif config.require_unsigned:
            return signature_info.type == "unsigned"

        # No signature requirements - always valid
        return True
