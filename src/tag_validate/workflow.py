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
        verify_github_key=True,
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
    ):
        """Initialize the validation workflow.

        Args:
            config: Validation configuration
            repo_path: Path to Git repository (default: current directory)
        """
        self.config = config
        self.repo_path = repo_path or Path.cwd()

        # Initialize components
        self.validator = TagValidator()
        self.detector = SignatureDetector(self.repo_path)
        self.operations = TagOperations()

        logger.debug(f"Initialized ValidationWorkflow with config: {config}")

    async def validate_tag(
        self,
        tag_name: str,
        github_user: Optional[str] = None,
        github_token: Optional[str] = None,
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
        logger.info(f"Starting validation workflow for tag: {tag_name}")

        # Initialize result
        result = ValidationResult(
            tag_name=tag_name,
            is_valid=True,  # Will be set to False if any check fails
            config=self.config,
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

        # Step 2: Validate version format
        version_result = self._validate_version(tag_name)
        result.version_info = version_result

        if not version_result.is_valid:
            result.is_valid = False
            result.add_error(f"Invalid version format: {tag_name}")
            for error in version_result.errors:
                result.add_error(f"  {error}")
        else:
            result.add_info(f"Version type: {version_result.version_type}")

            # Check version type requirements
            if not self._check_version_requirements(version_result):
                result.is_valid = False
                return result

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
        if self.config.verify_github_key and github_user:
            if signature_info.type in ["gpg", "ssh"] and signature_info.verified:
                try:
                    key_result = await self._verify_github_key(
                        signature_info,
                        github_user,
                        github_token,
                    )
                    result.key_verification = key_result

                    if not key_result.key_registered:
                        result.is_valid = False
                        result.add_error(
                            f"Signing key not registered to GitHub user @{github_user}"
                        )
                    else:
                        result.add_info(
                            f"Signing key verified for GitHub user @{github_user}"
                        )
                except Exception as e:
                    result.add_warning(f"GitHub key verification failed: {e}")
                    logger.warning(f"GitHub key verification failed: {e}")
            else:
                result.add_info("Skipping GitHub key verification (no valid signature)")

        # Final validation summary
        if result.is_valid:
            logger.info(f"✅ Tag validation passed: {tag_name}")
            result.add_info("All validation checks passed")
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
        # Check SemVer requirement
        if self.config.require_semver and version_info.version_type != "semver":
            logger.warning(f"Version type {version_info.version_type} does not match required semver")
            return False

        # Check CalVer requirement
        if self.config.require_calver and version_info.version_type != "calver":
            logger.warning(f"Version type {version_info.version_type} does not match required calver")
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
        """Check if signature meets configuration requirements.

        Args:
            signature_info: Signature detection result
            result: Validation result to update

        Returns:
            bool: True if requirements are met
        """
        # Check if signature is required
        if self.config.require_signed:
            if signature_info.type == "unsigned":
                result.add_error("Tag must be signed but is unsigned")
                logger.warning("Unsigned tag when signature is required")
                return False

            if signature_info.type == "lightweight":
                result.add_error("Lightweight tags are not allowed when signing is required")
                logger.warning("Lightweight tag when signature is required")
                return False

            if not signature_info.verified:
                result.add_error("Tag signature is invalid or unverifiable")
                logger.warning("Invalid/unverifiable signature")
                return False

            result.add_info(f"Tag is signed with {signature_info.type.upper()}")

        # Check if unsigned is explicitly required
        elif self.config.require_unsigned:
            if signature_info.type != "unsigned":
                result.add_error("Tag must be unsigned but has a signature")
                logger.warning("Signed tag when unsigned is required")
                return False
            result.add_info("Tag is unsigned as required")

        else:
            # Ambivalent - accept any signature state
            if signature_info.type == "unsigned":
                result.add_info("Tag is unsigned")
            else:
                status = "verified" if signature_info.verified else "unverifiable"
                result.add_info(f"Tag is {signature_info.type} signed ({status})")

        return True

    async def _verify_github_key(
        self,
        signature_info: SignatureInfo,
        github_user: str,
        github_token: Optional[str] = None,
    ) -> KeyVerificationResult:
        """Verify signing key on GitHub.

        Args:
            signature_info: Signature information
            github_user: GitHub username to verify against
            github_token: GitHub API token (optional)

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            Exception: If verification fails
        """
        logger.debug(f"Verifying key on GitHub for user: {github_user}")

        async with GitHubKeysClient(token=github_token) as client:
            if signature_info.type == "gpg":
                if not signature_info.key_id:
                    raise ValueError("GPG key ID not found in signature")

                result = await client.verify_gpg_key_registered(
                    username=github_user,
                    key_id=signature_info.key_id,
                    tagger_email=signature_info.signer_email,
                )

            elif signature_info.type == "ssh":
                if not signature_info.fingerprint:
                    raise ValueError("SSH fingerprint not found in signature")

                result = await client.verify_ssh_key_registered(
                    username=github_user,
                    public_key_fingerprint=signature_info.fingerprint,
                )

            else:
                raise ValueError(f"Cannot verify {signature_info.type} signature type")

        logger.debug(f"Key verification result: registered={result.key_registered}")
        return result

    async def validate_tag_location(
        self,
        tag_location: str,
        github_user: Optional[str] = None,
        github_token: Optional[str] = None,
    ) -> ValidationResult:
        """Validate a tag from a location string.

        Supports formats:
        - owner/repo@tag
        - https://github.com/owner/repo@tag
        - Local tag name (uses current repo)

        Args:
            tag_location: Tag location string or tag name
            github_user: GitHub username for key verification
            github_token: GitHub token for API access

        Returns:
            ValidationResult: Complete validation result
        """
        logger.info(f"Validating tag location: {tag_location}")

        # Check if it's a remote location or local tag
        if "@" in tag_location and ("/" in tag_location or "github.com" in tag_location):
            # Remote tag - parse and clone
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

                    # Validate the tag
                    result = await self.validate_tag(tag, github_user, github_token)

                    # Restore original repo path
                    self.repo_path = original_repo_path
                    self.detector = SignatureDetector(original_repo_path)

                    return result

                finally:
                    # Clean up temporary directory
                    secure_rmtree(temp_dir)
                    logger.debug(f"Cleaned up temporary directory: {temp_dir}")

            except Exception as e:
                logger.error(f"Failed to validate remote tag: {e}")
                result = ValidationResult(
                    tag_name=tag_location,
                    is_valid=False,
                    config=self.config,
                )
                result.add_error(f"Failed to validate remote tag: {e}")
                return result

        else:
            # Local tag
            return await self.validate_tag(tag_location, github_user, github_token)

    def create_validation_summary(self, result: ValidationResult) -> str:
        """Create a human-readable validation summary.

        Args:
            result: Validation result

        Returns:
            str: Formatted summary text
        """
        lines = []

        # Header
        status = "✅ PASSED" if result.is_valid else "❌ FAILED"
        lines.append(f"Tag Validation: {status}")
        lines.append(f"Tag: {result.tag_name}")
        lines.append("")

        # Version info
        if result.version_info:
            v = result.version_info
            lines.append(f"Version: {v.normalized or v.raw}")
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
            lines.append(f"Signature: {s.type.upper()}")
            if s.type in ["gpg", "ssh"]:
                lines.append(f"  Verified: {'Yes' if s.verified else 'No'}")
                if s.signer_email:
                    lines.append(f"  Signer: {s.signer_email}")
                if s.key_id:
                    lines.append(f"  Key ID: {s.key_id}")
            lines.append("")

        # Key verification
        if result.key_verification:
            k = result.key_verification
            lines.append(f"GitHub Key Verification:")
            lines.append(f"  Registered: {'Yes' if k.key_registered else 'No'}")
            lines.append("")

        # Errors
        if result.errors:
            lines.append("Errors:")
            for error in result.errors:
                lines.append(f"  • {error}")
            lines.append("")

        # Warnings
        if result.warnings:
            lines.append("Warnings:")
            for warning in result.warnings:
                lines.append(f"  • {warning}")
            lines.append("")

        return "\n".join(lines)
