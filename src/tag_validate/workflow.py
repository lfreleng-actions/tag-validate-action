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
from pathlib import Path
from typing import Optional

from .display_utils import format_server_display, format_user_details
from .gerrit_keys import GerritKeysClient, GerritServerError
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
        repo_path: Optional[Path] = None,
        gerrit_username: Optional[str] = None,
        gerrit_password: Optional[str] = None,
    ):
        """Initialize the validation workflow.

        Args:
            config: Validation configuration
            repo_path: Path to Git repository (default: current directory)
            gerrit_username: Gerrit username for HTTP authentication (optional)
            gerrit_password: Gerrit HTTP password for authentication (optional)
        """
        self.config = config
        self.repo_path = repo_path or Path.cwd()
        self.gerrit_username = gerrit_username
        self.gerrit_password = gerrit_password

        # Initialize components
        self.validator: TagValidator = TagValidator()
        self.detector: SignatureDetector = SignatureDetector(self.repo_path)
        self.operations: TagOperations = TagOperations()
        self._current_github_org: Optional[str] = None

        logger.debug(f"Initialized ValidationWorkflow with config: {config}")

    async def _setup_ssh_allowed_signers(self) -> None:
        """Setup SSH allowed signers for the current repository."""
        try:
            logger.debug(f"Setting up SSH allowed signers for repository: {self.repo_path}")
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
        github_user: Optional[str] = None,
        github_token: Optional[str] = None,
        require_owners: Optional[list[str]] = None,
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
            key_verification=None,
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

        # Step 2: Detect version type (always runs - nearly zero cost)
        # Type detection is always performed regardless of skip_version_validation
        # This provides valuable information and has negligible performance impact
        if not self.config.skip_version_validation:
            version_result = self._validate_version(tag_name)
            result.version_info = version_result



            # Only enforce type requirements if explicitly configured
            if self.config.require_semver or self.config.require_calver:
                if not self._check_version_requirements(version_result):
                    result.is_valid = False
                    # Add specific error message about version type mismatch
                    required_types = []
                    if self.config.require_semver:
                        required_types.append("semver")
                    if self.config.require_calver:
                        required_types.append("calver")
                    result.add_error(
                        f"Version type '{version_result.version_type}' does not match required type(s): {', '.join(required_types)}"
                    )
                    return result
            # Otherwise accept any type (including "other")
        else:
            # Skip version validation entirely (legacy flag support)
            result.add_info("Version validation skipped (--skip-version-validation)")

        # Step 3: Detect and validate signature
        try:
            signature_info = await self._detect_signature(tag_name)
            result.signature_info = signature_info

            if not self._check_signature_requirements(signature_info, result):
                result.is_valid = False
                return result

        except Exception as e:
            result.is_valid = False
            result.add_error(f"Signature detection failed: {e}")
            logger.error(f"Signature detection failed: {e}")
            return result

        # Step 4: Verify key on GitHub (if requested and signature exists)
        if self.config.require_github:
            if signature_info.type in ["gpg", "ssh"] and signature_info.verified:
                # Check if token is available first
                if not github_token:
                    result.is_valid = False
                    error_msg = "GitHub token is required. Set GITHUB_TOKEN environment variable or pass --token"
                    result.add_error(error_msg)
                    logger.error(error_msg)
                else:
                    # Auto-detect GitHub username from tagger email if not provided
                    detected_user = github_user
                    was_enumerated = False
                    if not detected_user and signature_info.signer_email:
                        logger.debug(f"Attempting to auto-detect GitHub username from email: {signature_info.signer_email}")
                        try:
                            from .github_keys import GitHubKeysClient
                            async with GitHubKeysClient(token=github_token) as client:
                                detected_user = await client.lookup_username_by_email(signature_info.signer_email)
                                if detected_user:
                                    was_enumerated = True
                                    logger.debug(f"Auto-detected GitHub username: {detected_user}")
                                    # User info is already shown in GitHub User section
                                else:
                                    logger.warning(f"Could not auto-detect GitHub username from email: {signature_info.signer_email}")
                        except Exception as e:
                            logger.debug(f"Failed to auto-detect GitHub username: {e}")

                    # Use require_owners if provided, otherwise use detected_user
                    if require_owners:
                        # Verify against required owners
                        try:
                            key_result = await self._require_github_key(
                                signature_info,
                                detected_user if detected_user else "",  # Not used when require_owners is set
                                github_token,
                                require_owners,
                            )
                            result.key_verification = key_result
                            result.key_verifications.append(key_result)

                            if not key_result.key_registered:
                                result.is_valid = False
                                result.add_error(
                                    f"Signing key not registered to any of the required owners: {', '.join(require_owners)}"
                                )
                        except Exception as e:
                            result.is_valid = False
                            result.add_error(f"GitHub key verification failed: {e}")
                            logger.error(f"GitHub key verification failed: {e}")
                    elif detected_user:
                        try:
                            key_result = await self._require_github_key(
                                signature_info,
                                detected_user,
                                github_token,
                                require_owners,
                            )
                            # Set enumerated flag if username was auto-detected
                            if was_enumerated and key_result:
                                key_result.enumerated = True
                            result.key_verification = key_result
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
                    else:
                        result.is_valid = False
                        error_msg = "GitHub key verification requested but no username provided or detected from tagger email"
                        result.add_error(error_msg)
                        logger.error(error_msg)
            else:
                result.add_info("Skipping GitHub key verification (no valid signature)")

        # Step 5: Verify key on Gerrit (if requested and signature exists)
        if self.config.require_gerrit:
            if signature_info.type in ["gpg", "ssh"] and signature_info.verified:
                try:
                    # Determine Gerrit server
                    gerrit_server = self.config.gerrit_server
                    github_org = None

                    if not gerrit_server:
                        # Try to extract GitHub org from current context
                        github_org = self._extract_github_org_from_context()
                        if github_org:
                            gerrit_server = f"gerrit.{github_org}.org"
                        else:
                            raise ValueError("No Gerrit server specified and could not auto-detect from GitHub org")

                    # Verify connection and authentication BEFORE attempting key verification
                    # This provides clear error messages for auth issues
                    async with GerritKeysClient(
                        server=gerrit_server,
                        username=self.gerrit_username,
                        password=self.gerrit_password,
                    ) as test_client:
                        connection_ok, connection_error = await test_client.verify_connection()
                        if not connection_ok:
                            # Connection/auth failed - mark invalid and raise to skip key verification
                            # Error message will be added in the exception handler to avoid duplication
                            result.is_valid = False
                            logger.error(f"Gerrit connection failed: {connection_error}")
                            raise GerritServerError(f"Connection failed: {connection_error}")

                    # Use require_owners if provided, otherwise verify against tagger email
                    key_result = await self._require_gerrit_key(
                        signature_info,
                        gerrit_server,
                        github_org,
                        require_owners,
                    )

                    # Add Gerrit verification to the list
                    if not result.key_verification:
                        result.key_verification = key_result
                    result.key_verifications.append(key_result)

                    if not key_result.key_registered:
                        result.is_valid = False
                        if require_owners:
                            result.add_error(
                                f"Signing key not registered to any of the required owners on Gerrit: {', '.join(require_owners)}"
                            )
                        else:
                            result.add_error(f"Signing key not registered on Gerrit server {key_result.server}")


                except GerritServerError as e:
                    # API access errors - provide helpful message
                    error_msg = str(e)
                    logger.warning(f"Gerrit key verification unavailable: {e}")

                    # Determine error type from message content
                    lower_msg = error_msg.lower()
                    is_auth_error = (
                        "authentication required" in lower_msg or
                        "authentication failed" in lower_msg or
                        "provide valid gerrit credentials" in lower_msg
                    )
                    is_endpoint_error = (
                        "endpoint not available" in lower_msg or
                        "may not support" in lower_msg
                    )

                    # When --require-gerrit is specified, verification MUST succeed
                    # Any server limitation means the requirement cannot be satisfied
                    result.is_valid = False

                    # Add appropriate error message based on the failure type
                    if "Connection failed:" in error_msg:
                        # Connection check failed - provide clear auth/connection error
                        clean_msg = error_msg.replace("Connection failed: ", "")
                        result.add_error(
                            f"Gerrit key verification required but cannot connect to server: {clean_msg}"
                        )
                    elif is_auth_error:
                        # Authentication error - provide specific guidance
                        result.add_error(
                            f"Gerrit key verification required but authentication failed: {error_msg}"
                        )
                        result.add_error(
                            "Please ensure valid Gerrit credentials are provided via GERRIT_USERNAME and GERRIT_PASSWORD."
                        )
                    elif is_endpoint_error:
                        # Endpoint not available
                        result.add_error(
                            f"Gerrit key verification required but unavailable: {error_msg}"
                        )
                        result.add_error(
                            f"Gerrit server '{gerrit_server}' does not expose key management APIs. "
                            "This server cannot be used for --require-gerrit verification."
                        )
                    else:
                        # Other errors
                        result.add_error(
                            f"Gerrit key verification required but unavailable: {error_msg}"
                        )
                except Exception as e:
                    result.is_valid = False
                    result.add_error(f"Gerrit key verification failed: {e}")
                    logger.error(f"Gerrit key verification failed: {e}")
            else:
                # When --require-gerrit is specified, a valid signature is REQUIRED
                result.is_valid = False
                result.add_error(
                    "Gerrit key verification required but tag has no valid signature. "
                    "Tag must be signed with GPG or SSH to verify key on Gerrit."
                )

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
        logger.debug(f"Tag info fetched: {tag_info.tag_type}, commit: {tag_info.commit_sha[:8]}")
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
        strict_semver = (
            self.config.require_semver and
            getattr(self.config, 'strict_semver', False)
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
                    logger.warning(f"Version type {version_info.version_type} does not match required types: {', '.join(required_types)}")
                    return False

        # Check development version requirement
        if self.config.reject_development and version_info.is_development:
            logger.warning("Development versions are not allowed")
            return False

        return True

    async def _detect_signature(self, tag_name: str) -> SignatureInfo:
        """Detect and verify tag signature.

        Args:
            tag_name: Name of the tag

        Returns:
            SignatureInfo: Signature detection result

        Raises:
            Exception: If signature detection fails
        """
        logger.debug(f"Detecting signature: {tag_name}")
        signature_info = await self.detector.detect_signature(tag_name)

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
                result.add_error("Lightweight tags are not allowed when signing requirements are specified")
                logger.warning("Lightweight tag when signature requirements specified")
                return False



        # Check if signature is required (legacy boolean mode)
        elif self.config.require_signed:
            if signature_info.type == "unsigned":
                result.add_error("Tag must be signed but is unsigned")
                logger.warning("Unsigned tag when signature is required")
                return False

            if signature_info.type == "lightweight":
                result.add_error("Lightweight tags are not allowed when signing is required")
                logger.warning("Lightweight tag when signature is required")
                return False

            # Handle signature verification based on type:
            # - gpg-unverifiable: REJECT (security risk - missing key)
            # - invalid: REJECT (corrupted/bad signature)
            # - SSH unverified: ACCEPT (may not have allowed_signers configured)
            # - GPG/SSH verified: ACCEPT
            if signature_info.type == "gpg-unverifiable":
                # GPG signature exists but key not available for verification
                # This is a security risk - reject it
                result.add_error("Tag has GPG signature but key is not available for verification")
                logger.warning(
                    f"GPG signature unverifiable: signer={signature_info.signer_email}, "
                    f"key_id={signature_info.key_id}"
                )
                return False
            elif signature_info.type == "invalid":
                # Corrupted or tampered signature
                result.add_error("Tag signature is invalid or corrupted")
                logger.warning(f"Invalid signature: key_id={signature_info.key_id}")
                return False

            else:
                # SSH or GPG signature present but not verified
                # For SSH, this is acceptable (may not have allowed_signers file)
                # For GPG that's already verified, this shouldn't happen
                # Signature info is already shown in dedicated section
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

    async def _require_github_key(
        self,
        signature_info: SignatureInfo,
        github_user: str,
        github_token: Optional[str] = None,
        require_owners: Optional[list[str]] = None,
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
                    # Check if owner is an email address
                    if "@" in owner:
                        logger.debug(f"Checking if signer email matches: {owner}")
                        # For email, check if it matches the signer's email
                        if signature_info.signer_email and signature_info.signer_email.lower() == owner.lower():
                            # Email matches, now verify the key is registered to a GitHub account with this email
                            # We need to look up the username by email
                            try:
                                username = await client.lookup_username_by_email(owner)
                                if username:
                                    logger.debug(f"Found GitHub username for email {owner}: {username}")
                                    # Now verify the key is registered to this user
                                    if signature_info.type == "gpg":
                                        if not signature_info.key_id:
                                            raise ValueError("GPG key ID not found in signature")
                                        result = await client.verify_gpg_key_registered(
                                            username=username,
                                            key_id=signature_info.key_id,
                                            tagger_email=signature_info.signer_email,
                                            signer_email=signature_info.signer_email,
                                        )
                                    elif signature_info.type == "ssh":
                                        if not signature_info.fingerprint:
                                            raise ValueError("SSH fingerprint not found in signature")
                                        result = await client.verify_ssh_key_registered(
                                            username=username,
                                            public_key_fingerprint=signature_info.fingerprint,
                                            signer_email=signature_info.signer_email,
                                        )
                                    else:
                                        raise ValueError(f"Cannot verify {signature_info.type} signature type")

                                    if result.key_registered:
                                        logger.debug(f"Key verified for owner email: {owner}")
                                        return result
                            except Exception as e:
                                logger.debug(f"Could not verify email {owner}: {e}")
                                continue
                        else:
                            logger.debug(f"Signer email {signature_info.signer_email} does not match required owner {owner}")
                    else:
                        # Owner is a username
                        logger.debug(f"Verifying key for GitHub username: {owner}")
                        try:
                            if signature_info.type == "gpg":
                                if not signature_info.key_id:
                                    raise ValueError("GPG key ID not found in signature")
                                result = await client.verify_gpg_key_registered(
                                    username=owner,
                                    key_id=signature_info.key_id,
                                    tagger_email=signature_info.signer_email,
                                    signer_email=signature_info.signer_email,
                                )
                            elif signature_info.type == "ssh":
                                if not signature_info.fingerprint:
                                    raise ValueError("SSH fingerprint not found in signature")
                                result = await client.verify_ssh_key_registered(
                                    username=owner,
                                    public_key_fingerprint=signature_info.fingerprint,
                                    signer_email=signature_info.signer_email,
                                )
                            else:
                                raise ValueError(f"Cannot verify {signature_info.type} signature type")

                            if result.key_registered:
                                logger.debug(f"Key verified for owner: {owner}")
                                return result
                        except Exception as e:
                            logger.debug(f"Could not verify username {owner}: {e}")
                            continue

                # If we get here, none of the owners matched
                logger.debug(f"Key not registered to any of the required owners: {require_owners}")
                return KeyVerificationResult(
                    key_registered=False,
                    username=", ".join(require_owners),
                    enumerated=False,
                    key_info=None,
                    service="github",
                    server="github.com",
                    user_email=signature_info.signer_email,
                )
        else:
            # Original behavior: verify against single github_user
            logger.debug(f"Verifying key on GitHub for user: {github_user}")

            async with GitHubKeysClient(token=github_token) as client:
                if signature_info.type == "gpg":
                    if not signature_info.key_id:
                        raise ValueError("GPG key ID not found in signature")

                    result = await client.verify_gpg_key_registered(
                        username=github_user,
                        key_id=signature_info.key_id,
                        tagger_email=signature_info.signer_email,
                        signer_email=signature_info.signer_email,
                    )

                elif signature_info.type == "ssh":
                    if not signature_info.fingerprint:
                        raise ValueError("SSH fingerprint not found in signature")

                    result = await client.verify_ssh_key_registered(
                        username=github_user,
                        public_key_fingerprint=signature_info.fingerprint,
                        signer_email=signature_info.signer_email,
                    )

                else:
                    raise ValueError(f"Cannot verify {signature_info.type} signature type")

            logger.debug(f"Key verification result: registered={result.key_registered}")
            return result

    async def _require_gerrit_key(
        self,
        signature_info: SignatureInfo,
        gerrit_server: str,
        github_org: Optional[str] = None,
        require_owners: Optional[list[str]] = None,
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
        ) as client:
            # Look up account by email
            account = await client.lookup_account_by_email(tagger_email)
            if not account:
                logger.debug(f"No Gerrit account found for email: {tagger_email}")
                return KeyVerificationResult(
                    key_registered=False,
                    username=tagger_email,
                    enumerated=True,
                    key_info=None,
                    service="gerrit",
                    server=gerrit_server,
                )

            # If require_owners is specified, check if account matches any owner
            if require_owners:
                logger.debug(f"Verifying account against required owners: {require_owners}")
                account_matches = False

                for owner in require_owners:
                    if "@" in owner:
                        # Owner is an email address
                        if account.email and account.email.lower() == owner.lower():
                            account_matches = True
                            break
                    else:
                        # Owner is a username
                        if account.username and account.username.lower() == owner.lower():
                            account_matches = True
                            break

                if not account_matches:
                    logger.debug(f"Account {account.email} does not match required owners: {require_owners}")
                    return KeyVerificationResult(
                        key_registered=False,
                        username=", ".join(require_owners),
                        enumerated=False,
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

            logger.debug(f"Gerrit key verification result: registered={result.key_registered}")
            return result

    def _extract_github_org_from_context(self) -> Optional[str]:
        """Extract GitHub organization from current validation context.

        This method attempts to determine the GitHub organization from:
        1. Stored organization from remote repository validation
        2. Git remote URL (parsing github.com URLs)

        Returns:
            GitHub organization name if detected, None otherwise
        """
        # First check if we have a stored GitHub org from remote validation
        if hasattr(self, '_current_github_org') and self._current_github_org:
            logger.debug(f"Using stored GitHub org from remote validation: {self._current_github_org}")
            return self._current_github_org

        try:
            # Try to get remote URL from git repository
            import subprocess
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                remote_url = result.stdout.strip()
                logger.debug(f"Found git remote URL: {remote_url}")

                # Parse GitHub URL patterns
                import re
                patterns = [
                    r"github\.com[:/]([^/]+)/",  # https://github.com/owner/ or git@github.com:owner/
                    r"github\.com/([^/]+)",      # https://github.com/owner (no trailing slash)
                ]

                for pattern in patterns:
                    match = re.search(pattern, remote_url)
                    if match:
                        org = match.group(1)
                        logger.debug(f"Extracted GitHub org from remote URL: {org}")
                        return org

        except Exception as e:
            logger.debug(f"Could not extract GitHub org from git remote: {e}")

        return None

    async def validate_tag_location(
        self,
        tag_location: str,
        github_user: Optional[str] = None,
        github_token: Optional[str] = None,
        require_owners: Optional[list[str]] = None,
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

        # Check if it's a remote location or local tag
        if "@" in tag_location and ("/" in tag_location or "github.com" in tag_location):
            # Definite remote tag - parse and clone
            try:
                owner, repo, tag = self.operations.parse_tag_location(tag_location)
                logger.debug(f"Parsed location: {owner}/{repo}@{tag}")

                # Clone the repository
                from dependamerge.git_ops import secure_rmtree
                temp_dir, tag_info = await self.operations.clone_remote_tag(
                    owner=owner,
                    repo=repo,
                    tag=tag,
                    token=github_token,
                )

                try:
                    # Update repo path and detector
                    original_repo_path = self.repo_path
                    self.repo_path = temp_dir
                    self.detector = SignatureDetector(temp_dir)

                    # Store GitHub org for Gerrit auto-discovery
                    self._current_github_org = owner

                    # Validate the tag
                    result = await self.validate_tag(tag, github_user, github_token, require_owners)

                    # Restore original repo path
                    self.repo_path = original_repo_path
                    self.detector = SignatureDetector(original_repo_path)

                    return result

                finally:
                    # Clean up temporary directory
                    secure_rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")
                    # Clear stored org
                    self._current_github_org = None

            except Exception as e:
                logger.error(f"Failed to validate remote tag: {e}")
                result = ValidationResult(
                    tag_name=tag_location,
                    is_valid=False,
                    config=self.config,
                    tag_info=None,
                    version_info=None,
                    signature_info=None,
                    key_verification=None,
                )
                error_msg = f"Failed to validate remote tag: {e}"
                result.add_error(error_msg)

                # Provide helpful context
                if "parse_tag_location" in str(e):
                    result.add_info(
                        "Expected format: 'owner/repo@tag' (e.g., 'torvalds/linux@v6.0')"
                    )
                return result

        elif "/" in tag_location:
            # Ambiguous: could be local path (path/to/repo/tag) or remote (owner/repo/tag)
            # Try local path first (pragmatic fallback)

            # Split into potential repo path and tag name
            parts = tag_location.rsplit("/", 1)
            potential_repo_path = parts[0]
            potential_tag = parts[1] if len(parts) > 1 else tag_location

            # Check if it looks like a local path (directory exists)
            from pathlib import Path
            local_path = Path(self.repo_path) / potential_repo_path

            if local_path.is_dir() and (local_path / ".git").exists():
                # It's a local repository path
                logger.debug(f"Treating as local repo path: {potential_repo_path}/{potential_tag}")

                try:
                    # Update repo path and detector temporarily
                    original_repo_path = self.repo_path
                    self.repo_path = local_path
                    self.detector = SignatureDetector(local_path)

                    # Validate the tag
                    result = await self.validate_tag(potential_tag, github_user, github_token, require_owners)

                    # Restore original repo path
                    self.repo_path = original_repo_path
                    self.detector = SignatureDetector(original_repo_path)

                    return result

                except Exception as e:
                    logger.error(f"Failed to validate local tag: {e}")
                    # Restore original repo path
                    self.repo_path = original_repo_path
                    self.detector = SignatureDetector(original_repo_path)

                    result = ValidationResult(
                        tag_name=tag_location,
                        is_valid=False,
                        config=self.config,
                        tag_info=None,
                        version_info=None,
                        signature_info=None,
                        key_verification=None,
                    )
                    error_msg = f"Failed to validate local tag: {e}"
                    result.add_error(error_msg)

                    # Add helpful hint about tag format
                    if "not a git repository" in str(e).lower():
                        result.add_info(
                            f"Repository path '{potential_repo_path}' was found but may have issues. "
                            "Verify that it contains a valid .git directory."
                        )
                    return result

            else:
                # Not a local path, try as remote (owner/repo/tag or owner/repo@tag)
                logger.debug(f"Local path not found, treating as remote: {tag_location}")

                # Convert owner/repo/tag to owner/repo@tag if needed
                slash_count = tag_location.count("/")
                if slash_count >= 2:
                    # Convert last slash to @
                    parts = tag_location.rsplit("/", 1)
                    normalized_location = f"{parts[0]}@{parts[1]}"
                else:
                    normalized_location = tag_location

                # Try as remote tag
                try:
                    owner, repo, tag = self.operations.parse_tag_location(normalized_location)
                    logger.debug(f"Parsed as remote location: {owner}/{repo}@{tag}")

                    # Clone the repository
                    from dependamerge.git_ops import secure_rmtree
                    temp_dir, tag_info = await self.operations.clone_remote_tag(
                        owner=owner,
                        repo=repo,
                        tag=tag,
                        token=github_token,
                    )

                    try:
                        # Update repo path and detector
                        original_repo_path = self.repo_path
                        self.repo_path = temp_dir
                        self.detector = SignatureDetector(temp_dir)

                        # Validate the tag
                        result = await self.validate_tag(tag, github_user, github_token, require_owners)

                        # Restore original repo path
                        self.repo_path = original_repo_path
                        self.detector = SignatureDetector(original_repo_path)

                        return result

                    finally:
                        # Clean up temporary directory
                        secure_rmtree(temp_dir)
                        logger.debug(f"Cleaned up temporary directory: {temp_dir}")

                except Exception as e:
                    logger.error(f"Failed to validate as remote tag: {e}")
                    result = ValidationResult(
                        tag_name=tag_location,
                        is_valid=False,
                        config=self.config,
                        tag_info=None,
                        version_info=None,
                        signature_info=None,
                        key_verification=None,
                    )
                    error_msg = f"Failed to validate remote tag: {e}"

                    # Add helpful suggestions based on the error
                    if "couldn't find remote ref" in str(e).lower() or "not found" in str(e).lower():
                        result.add_error(error_msg)
                        result.add_warning(
                            f"Tag '{tag_location}' not found. "
                            "Please verify the tag exists in the remote repository."
                        )
                    elif "failed to clone" in str(e).lower():
                        result.add_error(error_msg)
                        result.add_warning(
                            "Possible formats: 'owner/repo@tag', './local/repo/tag', or 'tag-name'"
                        )
                    else:
                        result.add_error(error_msg)
                    return result

        else:
            # No slash or @ - treat as local tag name in current repo
            return await self.validate_tag(tag_location, github_user, github_token, require_owners)

    def create_validation_summary(self, result: ValidationResult) -> str:
        """Create a human-readable validation summary.

        Args:
            result: Validation result

        Returns:
            str: Formatted summary text
        """
        lines = []

        # Header
        status = "✅" if result.is_valid else "❌"
        lines.append(f"Overall Validation Result {status}")
        lines.append("")

        # Version info
        if result.version_info:
            v = result.version_info

            # Show validation status if version type requirement was specified
            version_status = ""
            if result.config.require_semver or result.config.require_calver:
                # Check if version type meets requirements
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
                lines.append(f"  Development: Yes")
            lines.append("")

        # Signature info
        if result.signature_info:
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
            if result.config.require_signed or result.config.require_unsigned or result.config.allowed_signature_types:
                # Check if signature meets requirements
                signature_valid = self._check_signature_requirements_status(result.signature_info, result.config)
                if signature_valid:
                    signature_status = " ✅"
                else:
                    signature_status = " ❌"

            lines.append(f"Tag Signing{signature_status}")

            if s.type in ["gpg", "ssh", "gpg-unverifiable", "invalid"]:
                lines.append(f"  Key Type: {sig_type}")
                if s.type == "gpg-unverifiable":
                    lines.append(f"  Status: Key not available for verification")
                elif s.type == "invalid":
                    lines.append(f"  Status: Signature is corrupted or tampered")
                if s.signer_email:
                    lines.append(f"  Signer: {s.signer_email}")
                if s.key_id:
                    lines.append(f"  Key ID: {s.key_id}")
            lines.append("")

        # Key verification - show all verifications (GitHub and/or Gerrit)
        if result.key_verifications:
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
                    name=k.user_name
                )
                lines.extend(user_lines)
                lines.append("")
        elif result.key_verification:
            # Legacy support for old single key_verification field
            k = result.key_verification

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
                name=k.user_name
            )
            lines.extend(user_lines)

        # Errors - filter out redundant registration errors
        if result.errors:
            # Filter out errors that are redundant with the registration status display
            # Collect all services shown in key_verifications section
            services_in_display = set()
            if result.key_verifications:
                services_in_display = {k.service for k in result.key_verifications}
            elif result.key_verification:
                services_in_display = {result.key_verification.service}

            filtered_errors = []
            for error in result.errors:
                error_lower = error.lower()
                is_registration_error = "not registered" in error_lower

                # Check which service this error is about
                is_github_error = "github" in error_lower
                is_gerrit_error = "gerrit" in error_lower

                # Only filter if this error is about a service shown in key_verifications section
                should_filter = (
                    is_registration_error and
                    ((is_github_error and "github" in services_in_display) or
                     (is_gerrit_error and "gerrit" in services_in_display))
                )

                if not should_filter:
                    filtered_errors.append(error)
            if filtered_errors:
                # Add blank line before section if needed
                if lines and lines[-1] != "":
                    lines.append("")
                lines.append("Errors:")
                for error in filtered_errors:
                    lines.append(f"  • {error}")

        # Warnings
        if result.warnings:
            # Add blank line before section if needed
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Warnings:")
            for warning in result.warnings:
                lines.append(f"  • {warning}")

        # Info messages
        if result.info:
            # Only add blank line if we didn't just add one from signature section
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Additional Information:")
            for info in result.info:
                lines.append(f"  • {info}")

        # Remove trailing empty line if present
        while lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

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
            if signature_info.type in ["invalid", "lightweight"]:
                return False
            return True

        # Check if signature is required (legacy boolean mode)
        elif config.require_signed:
            if signature_info.type in ["unsigned", "lightweight", "gpg-unverifiable", "invalid"]:
                return False
            return True

        # Check if unsigned is explicitly required
        elif config.require_unsigned:
            if signature_info.type != "unsigned":
                return False
            return True

        # No signature requirements - always valid
        return True
