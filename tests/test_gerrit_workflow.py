# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Gerrit workflow integration.

This module tests the integration of Gerrit key verification
into the ValidationWorkflow class.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from tag_validate.models import (
    GerritAccountInfo,
    KeyVerificationResult,
    SignatureInfo,
    ValidationConfig,
    ValidationResult,
)
from tag_validate.workflow import ValidationWorkflow


class TestGerritWorkflowInit:
    """Test ValidationWorkflow initialization with Gerrit config."""

    def test_workflow_init_with_gerrit_config(self):
        """Test workflow initialization with Gerrit configuration."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        assert workflow.config.require_gerrit is True
        assert workflow.config.gerrit_server == "gerrit.onap.org"

    def test_workflow_init_combined_github_gerrit(self):
        """Test workflow initialization with both GitHub and Gerrit."""
        config = ValidationConfig(
            require_github=True,
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        assert workflow.config.require_github is True
        assert workflow.config.require_gerrit is True
        assert workflow.config.gerrit_server == "gerrit.onap.org"


class TestGerritServerDiscovery:
    """Test GitHub org extraction for Gerrit server discovery."""

    def test_extract_github_org_from_context_stored(self):
        """Test GitHub org extraction from stored context."""
        config = ValidationConfig(require_gerrit=True)
        workflow = ValidationWorkflow(config)

        # Simulate stored GitHub org
        workflow._current_github_org = "onap"

        org = workflow._extract_github_org_from_context()
        assert org == "onap"

    @patch("subprocess.run")
    def test_extract_github_org_from_git_remote_https(self, mock_run):
        """Test GitHub org extraction from HTTPS remote URL."""
        config = ValidationConfig(require_gerrit=True)
        workflow = ValidationWorkflow(config)

        # Mock git remote get-url output
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "https://github.com/onap/policy-engine.git\n"
        mock_run.return_value = mock_result

        org = workflow._extract_github_org_from_context()
        assert org == "onap"

    @patch("subprocess.run")
    def test_extract_github_org_from_git_remote_ssh(self, mock_run):
        """Test GitHub org extraction from SSH remote URL."""
        config = ValidationConfig(require_gerrit=True)
        workflow = ValidationWorkflow(config)

        # Mock git remote get-url output
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "git@github.com:onap/policy-engine.git\n"
        mock_run.return_value = mock_result

        org = workflow._extract_github_org_from_context()
        assert org == "onap"

    @patch("subprocess.run")
    def test_extract_github_org_no_remote(self, mock_run):
        """Test GitHub org extraction when no remote is found."""
        config = ValidationConfig(require_gerrit=True)
        workflow = ValidationWorkflow(config)

        # Mock git command failure
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        org = workflow._extract_github_org_from_context()
        assert org is None


class TestGerritKeyVerification:
    """Test Gerrit key verification in workflow."""

    @pytest.mark.asyncio
    async def test_require_gerrit_key_ssh_success(self):
        """Test successful SSH key verification against Gerrit."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="john@example.com",
            fingerprint="SHA256:abc123def456",
        )

        # Mock Gerrit client
        mock_account = GerritAccountInfo(
            account_id=12345,
            name="John Doe",
            email="john@example.com",
            username="jdoe",
            status="ACTIVE",
        )

        mock_key_result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        with patch("tag_validate.workflow.GerritKeysClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.lookup_account_by_email.return_value = mock_account
            mock_client.verify_ssh_key_registered.return_value = mock_key_result

            result = await workflow._require_gerrit_key(
                signature_info,
                "gerrit.onap.org",
                github_org="onap",
            )

        assert result.key_registered is True
        assert result.service == "gerrit"
        assert result.server == "gerrit.onap.org"

    @pytest.mark.asyncio
    async def test_require_gerrit_key_gpg_success(self):
        """Test successful GPG key verification against Gerrit."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="gpg",
            verified=True,
            signer_email="john@example.com",
            key_id="ABCD1234EFGH5678",
        )

        # Mock Gerrit client
        mock_account = GerritAccountInfo(
            account_id=12345,
            name="John Doe",
            email="john@example.com",
            username="jdoe",
            status="ACTIVE",
        )

        mock_key_result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        with patch("tag_validate.workflow.GerritKeysClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.lookup_account_by_email.return_value = mock_account
            mock_client.verify_gpg_key_registered.return_value = mock_key_result

            result = await workflow._require_gerrit_key(
                signature_info,
                "gerrit.onap.org",
                github_org="onap",
            )

        assert result.key_registered is True
        assert result.service == "gerrit"

    @pytest.mark.asyncio
    async def test_require_gerrit_key_no_account(self):
        """Test Gerrit key verification when account is not found."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="notfound@example.com",
            fingerprint="SHA256:abc123def456",
        )

        with patch("tag_validate.workflow.GerritKeysClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.lookup_account_by_email.return_value = None

            result = await workflow._require_gerrit_key(
                signature_info,
                "gerrit.onap.org",
                github_org="onap",
            )

        assert result.key_registered is False
        assert result.username == "notfound@example.com"
        assert result.enumerated is True
        assert result.service == "gerrit"

    @pytest.mark.asyncio
    async def test_require_gerrit_key_with_owners(self):
        """Test Gerrit key verification with required owners."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="john@example.com",
            fingerprint="SHA256:abc123def456",
        )

        # Mock account that matches owner email
        mock_account = GerritAccountInfo(
            account_id=12345,
            name="John Doe",
            email="john@example.com",
            username="jdoe",
            status="ACTIVE",
        )

        mock_key_result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        with patch("tag_validate.workflow.GerritKeysClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.lookup_account_by_email.return_value = mock_account
            mock_client.verify_ssh_key_registered.return_value = mock_key_result

            result = await workflow._require_gerrit_key(
                signature_info,
                "gerrit.onap.org",
                github_org="onap",
                require_owners=["john@example.com", "maintainer@project.org"],
            )

        assert result.key_registered is True

    @pytest.mark.asyncio
    async def test_require_gerrit_key_owners_no_match(self):
        """Test Gerrit key verification when account doesn't match required owners."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="john@example.com",
            fingerprint="SHA256:abc123def456",
        )

        # Mock account that doesn't match required owners
        mock_account = GerritAccountInfo(
            account_id=12345,
            name="John Doe",
            email="john@example.com",
            username="jdoe",
            status="ACTIVE",
        )

        with patch("tag_validate.workflow.GerritKeysClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.lookup_account_by_email.return_value = mock_account

            result = await workflow._require_gerrit_key(
                signature_info,
                "gerrit.onap.org",
                github_org="onap",
                require_owners=["maintainer@project.org", "lead@project.org"],
            )

        assert result.key_registered is False
        assert result.username == "maintainer@project.org, lead@project.org"

    @pytest.mark.asyncio
    async def test_require_gerrit_key_no_email(self):
        """Test Gerrit key verification without tagger email."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
        )
        workflow = ValidationWorkflow(config)

        signature_info = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email=None,  # No email
            fingerprint="SHA256:abc123def456",
        )

        with pytest.raises(
            ValueError, match="Cannot verify Gerrit key without tagger email"
        ):
            await workflow._require_gerrit_key(
                signature_info,
                "gerrit.onap.org",
                github_org="onap",
            )


class TestGerritWorkflowIntegration:
    """Test complete workflow integration with Gerrit verification."""

    @pytest.mark.asyncio
    async def test_validate_tag_with_gerrit_success(self):
        """Test complete tag validation with successful Gerrit verification."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
            require_signed=True,
            allowed_signature_types=["ssh"],
        )
        workflow = ValidationWorkflow(config)

        # Mock tag info
        mock_tag_info = Mock()
        mock_tag_info.tag_name = "v1.0.0"
        mock_tag_info.tag_type = "annotated"

        # Mock signature detection
        mock_signature = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="john@example.com",
            fingerprint="SHA256:abc123def456",
        )

        # Mock version validation
        mock_version = Mock()
        mock_version.is_valid = True

        # Mock Gerrit verification
        mock_gerrit_result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        # Mock Gerrit client with verify_connection
        mock_gerrit_client = AsyncMock()
        mock_gerrit_client.verify_connection = AsyncMock(return_value=(True, None))
        mock_gerrit_client.__aenter__ = AsyncMock(return_value=mock_gerrit_client)
        mock_gerrit_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version),
            patch.object(workflow, "_detect_signature", return_value=mock_signature),
            patch.object(workflow, "_check_signature_requirements", return_value=True),
            patch.object(
                workflow, "_require_gerrit_key", return_value=mock_gerrit_result
            ),
            patch.object(
                workflow, "_extract_github_org_from_context", return_value="onap"
            ),
            patch(
                "tag_validate.workflow.GerritKeysClient",
                return_value=mock_gerrit_client,
            ),
        ):
            result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is True
        assert result.key_verification is not None
        assert result.key_verification.service == "gerrit"
        assert result.key_verification.key_registered is True

    @pytest.mark.asyncio
    async def test_validate_tag_with_gerrit_failure(self):
        """Test tag validation with Gerrit verification failure."""
        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
            require_signed=True,
        )
        workflow = ValidationWorkflow(config)

        # Mock tag info
        mock_tag_info = Mock()
        mock_tag_info.tag_name = "v1.0.0"
        mock_tag_info.tag_type = "annotated"

        # Mock signature detection
        mock_signature = SignatureInfo(
            type="gpg",
            verified=True,
            signer_email="john@example.com",
            key_id="ABC123",
        )

        # Mock version validation
        mock_version = Mock()
        mock_version.is_valid = True

        # Mock Gerrit verification - key not found
        mock_gerrit_result = KeyVerificationResult(
            key_registered=False,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        # Mock Gerrit client with verify_connection
        mock_gerrit_client = AsyncMock()
        mock_gerrit_client.verify_connection = AsyncMock(return_value=(True, None))
        mock_gerrit_client.__aenter__ = AsyncMock(return_value=mock_gerrit_client)
        mock_gerrit_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version),
            patch.object(workflow, "_detect_signature", return_value=mock_signature),
            patch.object(workflow, "_check_signature_requirements", return_value=True),
            patch.object(
                workflow, "_require_gerrit_key", return_value=mock_gerrit_result
            ),
            patch(
                "tag_validate.workflow.GerritKeysClient",
                return_value=mock_gerrit_client,
            ),
        ):
            result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is False
        assert result.key_verification is not None
        assert result.key_verification.service == "gerrit"
        assert result.key_verification.key_registered is False
        assert any(
            "not registered on Gerrit server" in error for error in result.errors
        )

    @pytest.mark.asyncio
    async def test_validate_tag_combined_github_gerrit(self):
        """Test tag validation with both GitHub and Gerrit verification."""
        config = ValidationConfig(
            require_github=True,
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
            require_signed=True,
            allowed_signature_types=["gpg"],
        )
        workflow = ValidationWorkflow(config)

        # Mock tag info
        mock_tag_info = Mock()
        mock_tag_info.tag_name = "v1.0.0"
        mock_tag_info.tag_type = "annotated"

        # Mock signature detection
        mock_signature = SignatureInfo(
            type="gpg",
            verified=True,
            signer_email="john@example.com",
            key_id="ABCD1234EFGH5678",
        )

        # Mock version validation
        mock_version = Mock()
        mock_version.is_valid = True

        # Mock GitHub verification
        mock_github_result = KeyVerificationResult(
            key_registered=True,
            username="johndoe",
            enumerated=True,
            key_info=None,
            service="github",
            server=None,
        )

        # Mock Gerrit verification
        mock_gerrit_result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        # Mock Gerrit client with verify_connection
        mock_gerrit_client = AsyncMock()
        mock_gerrit_client.verify_connection = AsyncMock(return_value=(True, None))
        mock_gerrit_client.__aenter__ = AsyncMock(return_value=mock_gerrit_client)
        mock_gerrit_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version),
            patch.object(workflow, "_detect_signature", return_value=mock_signature),
            patch.object(workflow, "_check_signature_requirements", return_value=True),
            patch.object(
                workflow, "_require_github_key", return_value=mock_github_result
            ),
            patch.object(
                workflow, "_require_gerrit_key", return_value=mock_gerrit_result
            ),
            patch.object(
                workflow, "_extract_github_org_from_context", return_value="onap"
            ),
            patch("tag_validate.github_keys.GitHubKeysClient") as mock_github_client,
            patch(
                "tag_validate.workflow.GerritKeysClient",
                return_value=mock_gerrit_client,
            ),
        ):
            # Mock the GitHub username lookup
            mock_client = AsyncMock()
            mock_client.lookup_username_by_email = AsyncMock(return_value="johndoe")
            mock_github_client.return_value.__aenter__ = AsyncMock(
                return_value=mock_client
            )
            mock_github_client.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await workflow.validate_tag("v1.0.0", github_token="test_token")

        assert result.is_valid is True
        # Should have both GitHub and Gerrit verifications in the array
        assert len(result.key_verifications) == 2
        # Check GitHub verification
        github_verification = next(
            (v for v in result.key_verifications if v.service == "github"), None
        )
        assert github_verification is not None
        assert github_verification.key_registered is True
        # Check Gerrit verification
        gerrit_verification = next(
            (v for v in result.key_verifications if v.service == "gerrit"), None
        )
        assert gerrit_verification is not None
        assert gerrit_verification.key_registered is True
        assert gerrit_verification.server == "gerrit.onap.org"

    @pytest.mark.asyncio
    async def test_validate_tag_gerrit_server_discovery(self):
        """Test Gerrit server discovery from GitHub org."""
        config = ValidationConfig(
            require_gerrit=True,
            # No gerrit_server specified - should be discovered
            require_signed=True,
        )
        workflow = ValidationWorkflow(config)

        # Mock tag info
        mock_tag_info = Mock()
        mock_tag_info.tag_name = "v1.0.0"
        mock_tag_info.tag_type = "annotated"

        # Mock signature detection
        mock_signature = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="john@example.com",
            fingerprint="SHA256:abc123def456",
        )

        # Mock version validation
        mock_version = Mock()
        mock_version.is_valid = True

        # Mock Gerrit verification
        mock_gerrit_result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        # Mock Gerrit client with verify_connection
        mock_gerrit_client = AsyncMock()
        mock_gerrit_client.verify_connection = AsyncMock(return_value=(True, None))
        mock_gerrit_client.__aenter__ = AsyncMock(return_value=mock_gerrit_client)
        mock_gerrit_client.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version),
            patch.object(workflow, "_detect_signature", return_value=mock_signature),
            patch.object(workflow, "_check_signature_requirements", return_value=True),
            patch.object(
                workflow, "_require_gerrit_key", return_value=mock_gerrit_result
            ),
            patch.object(
                workflow, "_extract_github_org_from_context", return_value="onap"
            ),
            patch(
                "tag_validate.workflow.GerritKeysClient",
                return_value=mock_gerrit_client,
            ),
        ):
            result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is True
        assert result.key_verification is not None
        assert result.key_verification.service == "gerrit"
        # Should have discovered gerrit.onap.org from the GitHub org
        assert result.key_verification.server == "gerrit.onap.org"

    @pytest.mark.asyncio
    async def test_validate_tag_gerrit_no_server_discovery(self):
        """Test tag validation when Gerrit server cannot be discovered."""
        config = ValidationConfig(
            require_gerrit=True,
            # No gerrit_server specified
        )
        workflow = ValidationWorkflow(config)

        # Mock tag info
        mock_tag_info = Mock()
        mock_tag_info.tag_name = "v1.0.0"
        mock_tag_info.tag_type = "annotated"

        # Mock signature detection
        mock_signature = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="john@example.com",
            fingerprint="SHA256:abc123def456",
        )

        # Mock version validation
        mock_version = Mock()
        mock_version.is_valid = True

        with (
            patch.object(workflow, "_fetch_tag_info", return_value=mock_tag_info),
            patch.object(workflow, "_validate_version", return_value=mock_version),
            patch.object(workflow, "_detect_signature", return_value=mock_signature),
            patch.object(workflow, "_check_signature_requirements", return_value=True),
            patch.object(
                workflow, "_extract_github_org_from_context", return_value=None
            ),
        ):
            result = await workflow.validate_tag("v1.0.0")

        assert result.is_valid is False
        assert any("No Gerrit server specified" in error for error in result.errors)

    @pytest.mark.asyncio
    async def test_validate_tag_remote_with_gerrit(self):
        """Test remote tag validation with Gerrit verification."""
        config = ValidationConfig(
            require_gerrit=True,
            require_signed=True,
        )
        workflow = ValidationWorkflow(config)

        # Mock successful validation
        mock_result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=config,
            tag_info=None,
            version_info=None,
            signature_info=None,
            key_verification=KeyVerificationResult(
                key_registered=True,
                username="12345",
                enumerated=False,
                key_info=None,
                service="gerrit",
                server="gerrit.onap.org",
            ),
        )

        with (
            patch.object(
                workflow.operations,
                "parse_tag_location",
                return_value=("onap", "policy-engine", "v1.0.0"),
            ),
            patch.object(
                workflow.operations,
                "clone_remote_tag",
                return_value=("/tmp/test", None),
            ),
            patch.object(workflow, "validate_tag", return_value=mock_result),
            patch("tag_validate.workflow.SignatureDetector"),
            patch("dependamerge.git_ops.secure_rmtree"),
        ):
            result = await workflow.validate_tag_location("onap/policy-engine@v1.0.0")

        assert result.is_valid is True
        assert result.key_verification.service == "gerrit"
        assert result.key_verification.server == "gerrit.onap.org"
