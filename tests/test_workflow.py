# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tests for the workflow module."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from tag_validate.models import (
    KeyVerificationResult,
    SignatureInfo,
    TagInfo,
    ValidationConfig,
    ValidationResult,
    VersionInfo,
)
from tag_validate.workflow import ValidationWorkflow


class TestValidationWorkflow:
    """Test suite for ValidationWorkflow class."""

    def test_initialization_default(self):
        """Test workflow initialization with default settings."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        assert workflow.config == config
        assert workflow.repo_path == Path.cwd()
        assert workflow.validator is not None
        assert workflow.detector is not None
        assert workflow.operations is not None

    def test_initialization_with_repo_path(self, tmp_path):
        """Test workflow initialization with custom repo path."""
        config = ValidationConfig()
        repo_path = tmp_path / "test-repo"
        repo_path.mkdir()
        (repo_path / ".git").mkdir()  # Create .git to make it look like a repo
        workflow = ValidationWorkflow(config, repo_path=repo_path)

        assert workflow.repo_path == repo_path

    @pytest.mark.asyncio
    async def test_validate_tag_success(self):
        """Test successful tag validation."""
        config = ValidationConfig(
            require_semver=True,
            require_signed=True,
        )
        workflow = ValidationWorkflow(config)

        # Mock the internal methods
        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123def456" * 5,
        )

        mock_version_info = VersionInfo(
            raw="v1.2.3",
            normalized="1.2.3",
            is_valid=True,
            version_type="semver",
            major=1,
            minor=2,
            patch=3,
        )

        mock_signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="1234567890ABCDEF",
            signer_email="test@example.com",
        )

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version_info),
            patch.object(
                workflow, "_detect_signature", return_value=mock_signature_info
            ),
        ):
            result = await workflow.validate_tag("v1.2.3")

            assert isinstance(result, ValidationResult)
            assert result.is_valid is True
            assert result.tag_name == "v1.2.3"
            assert result.tag_info == mock_tag_info
            assert result.version_info == mock_version_info
            assert result.signature_info == mock_signature_info

    @pytest.mark.asyncio
    async def test_validate_tag_version_failure(self):
        """Test tag validation with invalid version."""
        config = ValidationConfig(require_semver=True)
        workflow = ValidationWorkflow(config)

        mock_tag_info = TagInfo(
            tag_name="invalid",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        mock_version_info = VersionInfo(
            raw="invalid",
            is_valid=False,
            version_type="other",
            errors=["Invalid version format"],
        )

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version_info),
        ):
            result = await workflow.validate_tag("invalid")

            assert result.is_valid is False
            # Check that version validation failed (errors are now in version_info.errors)
            assert len(result.version_info.errors) > 0
            assert "Invalid version format" in result.version_info.errors[0]

    @pytest.mark.asyncio
    async def test_validate_tag_unsigned_when_signed_required(self):
        """Test validation failure for unsigned tag when signature required."""
        config = ValidationConfig(require_signed=True)
        workflow = ValidationWorkflow(config)

        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        mock_version_info = VersionInfo(
            raw="v1.2.3",
            normalized="1.2.3",
            is_valid=True,
            version_type="semver",
            major=1,
            minor=2,
            patch=3,
        )

        mock_signature_info = SignatureInfo(
            type="unsigned",
            verified=False,
        )

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version_info),
            patch.object(
                workflow, "_detect_signature", return_value=mock_signature_info
            ),
        ):
            result = await workflow.validate_tag("v1.2.3")

            assert result.is_valid is False
            assert any("unsigned" in error.lower() for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_tag_with_github_verification(self):
        """Test tag validation with GitHub key verification."""
        config = ValidationConfig(
            require_signed=True,
            require_github=True,
        )
        workflow = ValidationWorkflow(config)

        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        mock_version_info = VersionInfo(
            raw="v1.2.3",
            normalized="1.2.3",
            is_valid=True,
            version_type="semver",
            major=1,
            minor=2,
            patch=3,
        )

        mock_signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="1234567890ABCDEF",
            signer_email="test@example.com",
        )

        mock_key_result = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version_info),
            patch.object(
                workflow, "_detect_signature", return_value=mock_signature_info
            ),
            patch.object(workflow, "_require_github_key", return_value=mock_key_result),
        ):
            result = await workflow.validate_tag(
                "v1.2.3", github_user="testuser", github_token="test_token"
            )

            assert result.is_valid is True
            assert len(result.key_verifications) == 1
            assert result.key_verifications[0] == mock_key_result

    @pytest.mark.asyncio
    async def test_validate_tag_github_key_not_registered(self):
        """Test validation failure when GitHub key is not registered."""
        config = ValidationConfig(
            require_signed=True,
            require_github=True,
        )
        workflow = ValidationWorkflow(config)

        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        mock_version_info = VersionInfo(
            raw="v1.2.3",
            normalized="1.2.3",
            is_valid=True,
            version_type="semver",
            major=1,
            minor=2,
            patch=3,
        )

        mock_signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="1234567890ABCDEF",
            signer_email="test@example.com",
        )

        mock_key_result = KeyVerificationResult(
            key_registered=False,
            username="testuser",
        )

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version_info),
            patch.object(
                workflow, "_detect_signature", return_value=mock_signature_info
            ),
            patch.object(workflow, "_require_github_key", return_value=mock_key_result),
        ):
            result = await workflow.validate_tag(
                "v1.2.3", github_user="testuser", github_token="test_token"
            )

            assert result.is_valid is False
            assert any("not registered" in error.lower() for error in result.errors)

    def test_check_version_requirements_semver(self):
        """Test version requirement checking for SemVer."""
        config = ValidationConfig(require_semver=True)
        workflow = ValidationWorkflow(config)

        semver_info = VersionInfo(
            raw="v1.2.3",
            is_valid=True,
            version_type="semver",
            major=1,
            minor=2,
            patch=3,
        )

        assert workflow._check_version_requirements(semver_info) is True

        calver_info = VersionInfo(
            raw="2024.01.15",
            is_valid=True,
            version_type="calver",
            year=2024,
            month=1,
            day=15,
        )

        assert workflow._check_version_requirements(calver_info) is False

    def test_check_version_requirements_calver(self):
        """Test version requirement checking for CalVer."""
        config = ValidationConfig(require_calver=True)
        workflow = ValidationWorkflow(config)

        calver_info = VersionInfo(
            raw="2024.01.15",
            is_valid=True,
            version_type="calver",
            year=2024,
            month=1,
            day=15,
        )

        assert workflow._check_version_requirements(calver_info) is True

        semver_info = VersionInfo(
            raw="v1.2.3",
            is_valid=True,
            version_type="semver",
            major=1,
            minor=2,
            patch=3,
        )

        assert workflow._check_version_requirements(semver_info) is False

    def test_check_version_requirements_reject_development(self):
        """Test rejection of development versions."""
        config = ValidationConfig(reject_development=True)
        workflow = ValidationWorkflow(config)

        dev_version = VersionInfo(
            raw="v1.2.3-alpha",
            is_valid=True,
            version_type="semver",
            is_development=True,
            major=1,
            minor=2,
            patch=3,
            prerelease="alpha",
        )

        assert workflow._check_version_requirements(dev_version) is False

        stable_version = VersionInfo(
            raw="v1.2.3",
            is_valid=True,
            version_type="semver",
            is_development=False,
            major=1,
            minor=2,
            patch=3,
        )

        assert workflow._check_version_requirements(stable_version) is True

    def test_check_signature_requirements_signed_required(self):
        """Test signature requirements when signing is required."""
        config = ValidationConfig(require_signed=True)
        workflow = ValidationWorkflow(config)
        result = ValidationResult(tag_name="v1.2.3", config=config)

        # Unsigned tag should fail
        unsigned_sig = SignatureInfo(type="unsigned", verified=False)
        assert workflow._check_signature_requirements(unsigned_sig, result) is False

        # GPG unverifiable should FAIL (security risk - missing key)
        unverifiable_gpg_sig = SignatureInfo(
            type="gpg-unverifiable",
            verified=False,
            key_id="12345",
        )
        result_unverifiable_gpg = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(
                unverifiable_gpg_sig, result_unverifiable_gpg
            )
            is False
        )

        # Invalid signature should FAIL (corrupted/tampered)
        invalid_sig = SignatureInfo(
            type="invalid",
            verified=False,
            key_id="12345",
        )
        result_invalid = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(invalid_sig, result_invalid) is False
        )

        # SSH unverified should PASS (signature present, may not have allowed_signers)
        unverified_ssh_sig = SignatureInfo(
            type="ssh",
            verified=False,
            key_id="SHA256:abc123",
        )
        result_unverified_ssh = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(
                unverified_ssh_sig, result_unverified_ssh
            )
            is True
        )

        # Verified GPG signature should pass
        verified_gpg_sig = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="12345",
        )
        result_verified_gpg = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(
                verified_gpg_sig, result_verified_gpg
            )
            is True
        )

        # Verified SSH signature should pass
        verified_ssh_sig = SignatureInfo(
            type="ssh",
            verified=True,
            key_id="SHA256:abc123",
        )
        result_verified_ssh = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(
                verified_ssh_sig, result_verified_ssh
            )
            is True
        )

    def test_check_signature_requirements_unsigned_required(self):
        """Test signature requirements when unsigned is required."""
        config = ValidationConfig(require_unsigned=True)
        workflow = ValidationWorkflow(config)
        result = ValidationResult(tag_name="v1.2.3", config=config)

        # Unsigned tag should pass
        unsigned_sig = SignatureInfo(type="unsigned", verified=False)
        assert workflow._check_signature_requirements(unsigned_sig, result) is True

        # Signed tag should fail
        signed_sig = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="12345",
        )
        result_signed = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(signed_sig, result_signed) is False
        )

    def test_check_signature_requirements_ambivalent(self):
        """Test signature requirements when ambivalent."""
        config = ValidationConfig()  # No signature requirements
        workflow = ValidationWorkflow(config)

        # Unsigned should pass
        unsigned_sig = SignatureInfo(type="unsigned", verified=False)
        result_unsigned = ValidationResult(tag_name="v1.2.3", config=config)
        assert (
            workflow._check_signature_requirements(unsigned_sig, result_unsigned)
            is True
        )

        # Signed should pass
        signed_sig = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="12345",
        )
        result_signed = ValidationResult(tag_name="v1.2.3", config=config)
        assert workflow._check_signature_requirements(signed_sig, result_signed) is True

    @pytest.mark.asyncio
    async def test_validate_tag_location_local(self):
        """Test validation of local tag location."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        # Mock validate_tag to avoid actual validation
        mock_result = ValidationResult(
            tag_name="v1.2.3",
            is_valid=True,
            config=config,
        )

        with patch.object(
            workflow, "validate_tag", return_value=mock_result
        ) as mock_validate:
            result = await workflow.validate_tag_location("v1.2.3")

            assert result == mock_result
            mock_validate.assert_called_once_with("v1.2.3", None, None, None)

    @pytest.mark.asyncio
    async def test_validate_tag_location_remote(self, tmp_path):
        """Test validation of remote tag location."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        # Create a temporary directory for the test
        test_repo_dir = tmp_path / "test_repo"
        test_repo_dir.mkdir()
        (test_repo_dir / ".git").mkdir()  # Make it look like a git repo

        mock_tag_info = TagInfo(
            tag_name="v1.0.0",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        mock_result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=config,
        )

        with (
            patch.object(
                workflow.operations,
                "parse_tag_location",
                return_value=("torvalds", "linux", "v1.0.0"),
            ),
            patch.object(
                workflow.operations,
                "clone_remote_tag",
                return_value=(test_repo_dir, mock_tag_info),
            ),
            patch.object(workflow, "validate_tag", return_value=mock_result),
            patch("tag_validate.tag_operations.secure_rmtree"),
        ):
            result = await workflow.validate_tag_location("torvalds/linux@v1.0.0")

            assert result.is_valid is True

    def test_create_validation_summary_success(self):
        """Test creation of validation summary for successful validation."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        result = ValidationResult(
            tag_name="v1.2.3",
            is_valid=True,
            config=config,
            version_info=VersionInfo(
                raw="v1.2.3",
                normalized="1.2.3",
                is_valid=True,
                version_type="semver",
                major=1,
                minor=2,
                patch=3,
            ),
            signature_info=SignatureInfo(
                type="gpg",
                verified=True,
                key_id="1234567890ABCDEF",
                signer_email="test@example.com",
            ),
        )
        result.add_info("All validation checks passed")

        summary = workflow.create_validation_summary(result)

        assert "✅" in summary  # Status icon in header
        assert "v1.2.3" in summary
        assert "SEMVER" in summary
        assert "GPG" in summary

    def test_create_validation_summary_failure(self):
        """Test creation of validation summary for failed validation."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        result = ValidationResult(
            tag_name="invalid",
            is_valid=False,
            config=config,
            version_info=VersionInfo(
                raw="invalid",
                is_valid=False,
                version_type="other",
                errors=["Invalid version format"],
            ),
        )
        result.add_error("Invalid version format")

        summary = workflow.create_validation_summary(result)

        assert "❌" in summary  # Status icon in header
        assert "invalid" in summary
        assert "Errors:" in summary

    def test_create_validation_summary_with_warnings(self):
        """Test creation of validation summary with warnings."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        result = ValidationResult(
            tag_name="v1.2.3",
            is_valid=True,
            config=config,
        )
        result.add_warning("This is a warning")

        summary = workflow.create_validation_summary(result)

        assert "Warnings:" in summary
        assert "This is a warning" in summary

    @pytest.mark.asyncio
    async def test_fetch_tag_info_success(self):
        """Test successful tag info fetch."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        with patch.object(
            workflow.operations, "fetch_tag_info", return_value=mock_tag_info
        ) as mock_fetch:
            result = await workflow._fetch_tag_info("v1.2.3")

            assert result == mock_tag_info
            mock_fetch.assert_called_once()

    def test_validate_version(self):
        """Test version validation."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        with patch.object(workflow.validator, "validate_version") as mock_validate:
            mock_validate.return_value = VersionInfo(
                raw="v1.2.3",
                is_valid=True,
                version_type="semver",
            )

            result = workflow._validate_version("v1.2.3")

            assert result.is_valid is True
            mock_validate.assert_called_once()

    @pytest.mark.asyncio
    async def test_detect_signature(self):
        """Test signature detection."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        mock_signature = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="12345",
        )

        # Mock tag info
        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123" * 7,
            tagger_email="test@example.com",
        )

        with patch.object(
            workflow.detector, "detect_signature", return_value=mock_signature
        ) as mock_detect:
            result = await workflow._detect_signature("v1.2.3", mock_tag_info)

            assert result == mock_signature
            mock_detect.assert_called_once_with("v1.2.3")

    @pytest.mark.asyncio
    async def test_require_github_key_gpg(self):
        """Test GitHub GPG key verification."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="1234567890ABCDEF",
            signer_email="test@example.com",
        )

        mock_result = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )

        mock_client = AsyncMock()
        mock_client.verify_gpg_key_registered = AsyncMock(return_value=mock_result)

        with patch("tag_validate.workflow.GitHubKeysClient") as mock_keys_client:
            mock_keys_client.return_value.__aenter__.return_value = mock_client

            result = await workflow._require_github_key(
                signature_info,
                "testuser",
                "token123",
            )

            assert result == mock_result
            mock_client.verify_gpg_key_registered.assert_called_once()

    @pytest.mark.asyncio
    async def test_require_github_key_ssh(self):
        """Test GitHub SSH key verification."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            fingerprint="SHA256:abcdef123456",
        )

        mock_result = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )

        mock_client = AsyncMock()
        mock_client.verify_ssh_key_registered = AsyncMock(return_value=mock_result)

        with patch("tag_validate.workflow.GitHubKeysClient") as mock_keys_client:
            mock_keys_client.return_value.__aenter__.return_value = mock_client

            result = await workflow._require_github_key(
                signature_info,
                "testuser",
                "token123",
            )

            assert result == mock_result
            mock_client.verify_ssh_key_registered.assert_called_once()

    @pytest.mark.asyncio
    async def test_require_github_key_missing_key_id(self):
        """Test GitHub key verification with missing GPG key ID."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            # Missing key_id
        )

        with pytest.raises(ValueError, match="GPG key ID not found"):
            await workflow._require_github_key(signature_info, "testuser", "test_token")

    @pytest.mark.asyncio
    async def test_require_github_key_missing_fingerprint(self):
        """Test GitHub key verification with missing SSH fingerprint."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            # Missing fingerprint
        )

        with pytest.raises(ValueError, match="SSH fingerprint not found"):
            await workflow._require_github_key(signature_info, "testuser", "test_token")

    @pytest.mark.asyncio
    async def test_validate_tag_fetch_error(self):
        """Test validation when tag fetch fails."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        with patch.object(
            workflow, "_fetch_tag_info", side_effect=Exception("Tag not found")
        ):
            result = await workflow.validate_tag("nonexistent")

            assert result.is_valid is False
            assert any("Failed to fetch" in error for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_tag_signature_detection_error(self):
        """Test validation when signature detection fails."""
        config = ValidationConfig()
        workflow = ValidationWorkflow(config)

        mock_tag_info = TagInfo(
            tag_name="v1.2.3",
            tag_type="annotated",
            commit_sha="abc123" * 7,
        )

        mock_version_info = VersionInfo(
            raw="v1.2.3",
            is_valid=True,
            version_type="semver",
        )

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version_info),
            patch.object(
                workflow, "_detect_signature", side_effect=Exception("Git error")
            ),
        ):
            result = await workflow.validate_tag("v1.2.3")

            assert result.is_valid is False
            assert any("Signature detection failed" in error for error in result.errors)
