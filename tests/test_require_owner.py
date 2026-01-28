# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for --require-owner functionality."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app
from tag_validate.models import (
    KeyVerificationResult,
    SignatureInfo,
    ValidationConfig,
    ValidationResult,
    VersionInfo,
)

runner = CliRunner()


@pytest.fixture
def mock_workflow():
    """Mock ValidationWorkflow for testing."""
    with patch("tag_validate.cli.ValidationWorkflow") as mock:
        workflow_instance = MagicMock()
        mock.return_value = workflow_instance
        yield workflow_instance


@pytest.fixture
def mock_github_client():
    """Mock GitHubKeysClient for testing."""
    with patch("tag_validate.workflow.GitHubKeysClient") as mock:
        client_instance = AsyncMock()
        mock.return_value.__aenter__.return_value = client_instance
        mock.return_value.__aexit__.return_value = AsyncMock()
        yield client_instance


class TestRequireOwnerCLI:
    """Test --require-owner CLI option parsing."""

    def test_require_owner_single_username(self, mock_workflow):
        """Test --require-owner with a single GitHub username."""
        # Setup mock
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
        )
        result.version_info = VersionInfo(
            raw="v1.0.0",
            normalized="1.0.0",
            version_type="semver",
            is_valid=True,
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )
        result.signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
        )
        result.key_verifications = [
            KeyVerificationResult(
                key_registered=True,
                username="octocat",
            )
        ]

        mock_workflow.validate_tag_location = AsyncMock(return_value=result)

        # Run command
        cli_result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-owner",
                "octocat",
                "--token",
                "test_token",
                "--json",
            ],
        )

        # Verify
        assert cli_result.exit_code == 0
        mock_workflow.validate_tag_location.assert_called_once()
        call_args = mock_workflow.validate_tag_location.call_args
        assert call_args.kwargs["require_owners"] == ["octocat"]

    def test_require_owner_multiple_usernames_comma(self, mock_workflow):
        """Test --require-owner with multiple usernames (comma-separated)."""
        # Setup mock
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
        )
        result.version_info = VersionInfo(
            raw="v1.0.0",
            normalized="1.0.0",
            version_type="semver",
            is_valid=True,
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )

        mock_workflow.validate_tag_location = AsyncMock(return_value=result)

        # Run command
        cli_result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-owner",
                "octocat,monalisa",
                "--token",
                "test_token",
                "--json",
            ],
        )

        # Verify
        assert cli_result.exit_code == 0
        call_args = mock_workflow.validate_tag_location.call_args
        assert call_args.kwargs["require_owners"] == ["octocat", "monalisa"]

    def test_require_owner_multiple_usernames_space(self, mock_workflow):
        """Test --require-owner with multiple usernames (space-separated)."""
        # Setup mock
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
        )
        result.version_info = VersionInfo(
            raw="v1.0.0",
            normalized="1.0.0",
            version_type="semver",
            is_valid=True,
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )

        mock_workflow.validate_tag_location = AsyncMock(return_value=result)

        # Run command
        cli_result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-owner",
                "octocat monalisa",
                "--token",
                "test_token",
                "--json",
            ],
        )

        # Verify
        assert cli_result.exit_code == 0
        call_args = mock_workflow.validate_tag_location.call_args
        assert call_args.kwargs["require_owners"] == ["octocat", "monalisa"]

    def test_require_owner_email_address(self, mock_workflow):
        """Test --require-owner with an email address."""
        # Setup mock
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
        )
        result.version_info = VersionInfo(
            raw="v1.0.0",
            normalized="1.0.0",
            version_type="semver",
            is_valid=True,
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )

        mock_workflow.validate_tag_location = AsyncMock(return_value=result)

        # Run command
        cli_result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-owner",
                "user@example.com",
                "--token",
                "test_token",
                "--json",
            ],
        )

        # Verify
        assert cli_result.exit_code == 0
        call_args = mock_workflow.validate_tag_location.call_args
        assert call_args.kwargs["require_owners"] == ["user@example.com"]

    def test_require_owner_mixed_usernames_and_emails(self, mock_workflow):
        """Test --require-owner with mixed usernames and email addresses."""
        # Setup mock
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
        )
        result.version_info = VersionInfo(
            raw="v1.0.0",
            normalized="1.0.0",
            version_type="semver",
            is_valid=True,
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )

        mock_workflow.validate_tag_location = AsyncMock(return_value=result)

        # Run command
        cli_result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-owner",
                "octocat,user@example.com,monalisa",
                "--token",
                "test_token",
                "--json",
            ],
        )

        # Verify
        assert cli_result.exit_code == 0
        call_args = mock_workflow.validate_tag_location.call_args
        assert call_args.kwargs["require_owners"] == [
            "octocat",
            "user@example.com",
            "monalisa",
        ]

    def test_require_owner_implies_require_github(self, mock_workflow):
        """Test that --require-owner implies --require-github."""
        # Setup mock
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(require_github=True),
        )
        result.version_info = VersionInfo(
            raw="v1.0.0",
            normalized="1.0.0",
            version_type="semver",
            is_valid=True,
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )

        mock_workflow.validate_tag_location = AsyncMock(return_value=result)

        # Run command without --require-github flag
        cli_result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-owner",
                "octocat",
                "--token",
                "test_token",
                "--json",
            ],
        )

        # Verify that require_github was set to True in the config
        assert cli_result.exit_code == 0
        # Check that ValidationWorkflow was created with require_github=True
        call_args = mock_workflow.validate_tag_location.call_args
        assert call_args.kwargs["require_owners"] == ["octocat"]


class TestRequireOwnerWorkflow:
    """Test require_owner workflow logic."""

    @pytest.mark.asyncio
    async def test_verify_gpg_key_against_username(self, mock_github_client):
        """Test verifying GPG key is registered to a specific username."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
            signer_email="user@example.com",
        )

        # Mock successful verification
        mock_github_client.verify_gpg_key_registered.return_value = (
            KeyVerificationResult(
                key_registered=True,
                username="octocat",
                key_info=None,
            )
        )

        # Test
        result = await workflow._require_github_key(
            signature_info,
            github_user="octocat",
            github_token="test_token",
            require_owners=["octocat"],
        )

        # Verify
        assert result.key_registered is True
        assert result.username == "octocat"
        mock_github_client.verify_gpg_key_registered.assert_called_once_with(
            username="octocat",
            key_id="ABC123",
            tagger_email="user@example.com",
            signer_email="user@example.com",
        )

    @pytest.mark.asyncio
    async def test_verify_ssh_key_against_username(self, mock_github_client):
        """Test verifying SSH key is registered to a specific username."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            fingerprint="SHA256:abc123",
            signer_email="user@example.com",
        )

        # Mock successful verification
        mock_github_client.verify_ssh_key_registered.return_value = (
            KeyVerificationResult(
                key_registered=True,
                username="octocat",
                key_info=None,
            )
        )

        # Test
        result = await workflow._require_github_key(
            signature_info,
            github_user="octocat",
            github_token="test_token",
            require_owners=["octocat"],
        )

        # Verify
        assert result.key_registered is True
        assert result.username == "octocat"
        mock_github_client.verify_ssh_key_registered.assert_called_once_with(
            username="octocat",
            public_key_fingerprint="SHA256:abc123",
            signer_email="user@example.com",
        )

    @pytest.mark.asyncio
    async def test_verify_key_against_multiple_owners_first_matches(
        self, mock_github_client
    ):
        """Test verifying key against multiple owners (first one matches)."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
            signer_email="user@example.com",
        )

        # Mock: first owner matches
        mock_github_client.verify_gpg_key_registered.return_value = (
            KeyVerificationResult(
                key_registered=True,
                username="octocat",
                key_info=None,
            )
        )

        # Test
        result = await workflow._require_github_key(
            signature_info,
            github_user="",
            github_token="test_token",
            require_owners=["octocat", "monalisa"],
        )

        # Verify
        assert result.key_registered is True
        assert result.username == "octocat"
        # Should only call once (stops at first match)
        assert mock_github_client.verify_gpg_key_registered.call_count == 1

    @pytest.mark.asyncio
    async def test_verify_key_against_multiple_owners_second_matches(
        self, mock_github_client
    ):
        """Test verifying key against multiple owners (second one matches)."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
            signer_email="user@example.com",
        )

        # Mock: first owner doesn't match, second does
        mock_github_client.verify_gpg_key_registered.side_effect = [
            KeyVerificationResult(
                key_registered=False, username="octocat", key_info=None
            ),
            KeyVerificationResult(
                key_registered=True, username="monalisa", key_info=None
            ),
        ]

        # Test
        result = await workflow._require_github_key(
            signature_info,
            github_user="",
            github_token="test_token",
            require_owners=["octocat", "monalisa"],
        )

        # Verify
        assert result.key_registered is True
        assert result.username == "monalisa"
        assert mock_github_client.verify_gpg_key_registered.call_count == 2

    @pytest.mark.asyncio
    async def test_verify_key_against_multiple_owners_none_match(
        self, mock_github_client
    ):
        """Test verifying key against multiple owners (none match)."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
            signer_email="user@example.com",
        )

        # Mock: no owners match
        mock_github_client.verify_gpg_key_registered.return_value = (
            KeyVerificationResult(
                key_registered=False,
                username="octocat",
                key_info=None,
            )
        )

        # Test
        result = await workflow._require_github_key(
            signature_info,
            github_user="",
            github_token="test_token",
            require_owners=["octocat", "monalisa"],
        )

        # Verify
        assert result.key_registered is False
        assert result.username == "octocat, monalisa"
        assert mock_github_client.verify_gpg_key_registered.call_count == 2

    @pytest.mark.asyncio
    async def test_verify_key_with_email_address_matching_signer(
        self, mock_github_client
    ):
        """Test verifying key when owner is an email address that matches signer."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
            signer_email="user@example.com",
        )

        # Mock: lookup username by email
        mock_github_client.lookup_username_by_email.return_value = "octocat"
        mock_github_client.verify_gpg_key_registered.return_value = (
            KeyVerificationResult(
                key_registered=True,
                username="octocat",
                key_info=None,
            )
        )

        # Test with email address as owner
        result = await workflow._require_github_key(
            signature_info,
            github_user="",
            github_token="test_token",
            require_owners=["user@example.com"],
        )

        # Verify
        assert result.key_registered is True
        mock_github_client.lookup_username_by_email.assert_called_once_with(
            "user@example.com"
        )
        mock_github_client.verify_gpg_key_registered.assert_called_once()

    @pytest.mark.asyncio
    async def test_verify_key_with_email_address_not_matching_signer(
        self, mock_github_client
    ):
        """Test verifying key when owner email doesn't match signer email."""
        from tag_validate.models import ValidationConfig
        from tag_validate.workflow import ValidationWorkflow

        # Setup
        config = ValidationConfig(require_github=True)
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABC123",
            signer_email="signer@example.com",
        )

        # Test with different email address as owner
        result = await workflow._require_github_key(
            signature_info,
            github_user="",
            github_token="test_token",
            require_owners=["different@example.com"],
        )

        # Verify
        assert result.key_registered is False
        # lookup_username_by_email should not be called because email doesn't match
        mock_github_client.lookup_username_by_email.assert_not_called()
