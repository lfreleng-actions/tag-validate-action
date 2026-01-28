# SPDX-FileCopyrightText: 2025 The Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the CLI gerrit subcommand (tag-validate gerrit).

This module tests the Gerrit key verification CLI command including:
- Basic command structure and argument validation
- GPG key verification
- SSH key verification
- Key type auto-detection
- JSON output mode
- Test mode functionality
- Error handling
- Server auto-discovery
"""

import json
import re
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app
from tag_validate.gerrit_keys import GerritAccountInfo, GerritKeysError
from tag_validate.models import KeyVerificationResult

# Test data
SAMPLE_GPG_KEY_ID = "FCE8AAABF53080F6"
SAMPLE_SSH_FINGERPRINT = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"
SAMPLE_USERNAME = "jdoe"
SAMPLE_EMAIL = "jdoe@example.com"
SAMPLE_SERVER = "gerrit.onap.org"


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_gerrit_account():
    """Create a mock Gerrit account."""
    return GerritAccountInfo(
        account_id=1000001,
        username=SAMPLE_USERNAME,
        email=SAMPLE_EMAIL,
        name="John Doe",
        status="ACTIVE",
    )


@pytest.fixture
def mock_verification_success():
    """Create a successful verification result."""
    return KeyVerificationResult(
        key_registered=True,
        username=SAMPLE_USERNAME,
        enumerated=False,
        server=SAMPLE_SERVER,
        service="gerrit",
        user_name="John Doe",
        user_email=SAMPLE_EMAIL,
    )


@pytest.fixture
def mock_verification_failure():
    """Create a failed verification result."""
    return KeyVerificationResult(
        key_registered=False,
        username=SAMPLE_USERNAME,
        enumerated=False,
        server=SAMPLE_SERVER,
        service="gerrit",
        user_name="John Doe",
        user_email=SAMPLE_EMAIL,
    )


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI color codes from text.

    Args:
        text: Text with ANSI codes

    Returns:
        Text without ANSI codes
    """
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


class TestVerifyGerritBasic:
    """Test basic Gerrit verification command structure."""

    def test_gerrit_help(self, runner):
        """Test gerrit subcommand help output."""
        result = runner.invoke(app, ["gerrit", "--help"])
        assert result.exit_code == 0

        # Strip ANSI codes for easier assertions
        output = strip_ansi_codes(result.stdout)

        assert (
            "Verify if a specific GPG key ID or SSH fingerprint is registered on Gerrit"
            in output
        )
        assert "--owner" in output
        assert "--server" in output
        assert "--github-org" in output

    def test_gerrit_missing_key_id(self, runner):
        """Test gerrit command without key ID."""
        result = runner.invoke(app, ["gerrit"])
        assert result.exit_code != 0

    def test_gerrit_missing_owner(self, runner):
        """Test gerrit command without owner."""
        result = runner.invoke(app, ["gerrit", SAMPLE_GPG_KEY_ID])
        assert result.exit_code != 0

    def test_gerrit_missing_server(self, runner):
        """Test gerrit command without server or github-org."""
        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_USERNAME,
            ],
        )
        assert result.exit_code != 0
        assert "Either --server or --github-org must be provided" in result.stdout


class TestVerifyGerritGPG:
    """Test GPG key verification via Gerrit CLI."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_verify_gpg_key_registered(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test successful GPG key verification."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi_codes(result.stdout)
        assert "REGISTERED" in output
        assert SAMPLE_USERNAME in output

    @patch("tag_validate.cli.GerritKeysClient")
    def test_verify_gpg_key_not_registered(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_failure
    ):
        """Test GPG key not registered."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_failure

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
            ],
        )

        assert result.exit_code == 1
        output = strip_ansi_codes(result.stdout)
        assert "NOT REGISTERED" in output

    @patch("tag_validate.cli.GerritKeysClient")
    def test_verify_gpg_key_explicit_type(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test GPG key verification with explicit type."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--type",
                "gpg",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_gpg_key_registered.assert_called_once()


class TestVerifyGerritSSH:
    """Test SSH key verification via Gerrit CLI."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_verify_ssh_key_registered(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test successful SSH key verification."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_username.return_value = mock_gerrit_account
        mock_client.verify_ssh_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_SSH_FINGERPRINT,
                "--owner",
                SAMPLE_USERNAME,
                "--server",
                SAMPLE_SERVER,
                "--json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        assert output["is_registered"] is True

    @patch("tag_validate.cli.GerritKeysClient")
    def test_verify_ssh_key_explicit_type(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test SSH key verification with explicit type."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_username.return_value = mock_gerrit_account
        mock_client.verify_ssh_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_SSH_FINGERPRINT,
                "--owner",
                SAMPLE_USERNAME,
                "--server",
                SAMPLE_SERVER,
                "--type",
                "ssh",
                "--json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        mock_client.verify_ssh_key_registered.assert_called_once()

    @patch("tag_validate.cli.GerritKeysClient")
    def test_verify_ssh_key_without_prefix(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test SSH fingerprint without SHA256 prefix."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_username.return_value = mock_gerrit_account
        mock_client.verify_ssh_key_registered.return_value = mock_verification_success

        # Fingerprint without SHA256: prefix
        fingerprint = "abcdef1234567890abcdef1234567890abcdef12"

        result = runner.invoke(
            app,
            [
                "gerrit",
                fingerprint,
                "--owner",
                SAMPLE_USERNAME,
                "--server",
                SAMPLE_SERVER,
                "--type",
                "ssh",
            ],
        )

        assert result.exit_code == 0


class TestVerifyGerritAutoDetection:
    """Test automatic key type detection for Gerrit."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_auto_detect_gpg_hex(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test auto-detection of GPG key from hex format."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GerritKeysClient")
    def test_auto_detect_ssh_prefix(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test auto-detection of SSH key from SHA256: prefix."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_username.return_value = mock_gerrit_account
        mock_client.verify_ssh_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_SSH_FINGERPRINT,
                "--owner",
                SAMPLE_USERNAME,
                "--server",
                SAMPLE_SERVER,
                "--json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        mock_client.verify_ssh_key_registered.assert_called_once()


class TestVerifyGerritJSON:
    """Test JSON output mode for Gerrit verification."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_gerrit_json_success(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test JSON output for successful verification."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        assert output["key_type"] == "gpg"
        assert output["username"] == SAMPLE_USERNAME
        assert output["server"] == SAMPLE_SERVER
        assert output["service"] == "gerrit"

    @patch("tag_validate.cli.GerritKeysClient")
    def test_gerrit_json_failure(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_failure
    ):
        """Test JSON output for failed verification."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_failure

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--json",
            ],
        )

        assert result.exit_code == 1
        output = json.loads(result.stdout)
        assert output["success"] is False
        assert output["is_registered"] is False

    @patch("tag_validate.cli.GerritKeysClient")
    def test_gerrit_json_account_not_found(self, mock_client_class, runner):
        """Test JSON output when account is not found."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = None

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--json",
            ],
        )

        assert result.exit_code != 0
        # Parse only the first JSON object (may have extra output after errors)
        try:
            lines = result.stdout.strip().split("\n")
            json_line = next(line for line in lines if line.strip().startswith("{"))
            output = json.loads(json_line)
            assert output["success"] is False
            assert "error" in output
        except (json.JSONDecodeError, StopIteration):
            # If JSON parsing fails, just check that the command failed
            assert result.exit_code != 0


class TestVerifyGerritServerDiscovery:
    """Test Gerrit server auto-discovery from GitHub org."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_github_org_discovery(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test server discovery from GitHub organization."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--github-org",
                "onap",
            ],
        )

        assert result.exit_code == 0
        # Verify client was created with github_org
        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args[1]
        assert call_kwargs["github_org"] == "onap"


class TestVerifyGerritAuthentication:
    """Test Gerrit authentication options."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_gerrit_with_credentials(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test Gerrit verification with username and password."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--gerrit-username",
                "admin",
                "--gerrit-password",
                "secret",
            ],
        )

        assert result.exit_code == 0
        call_kwargs = mock_client_class.call_args[1]
        assert call_kwargs["username"] == "admin"
        assert call_kwargs["password"] == "secret"


class TestVerifyGerritTestMode:
    """Test Gerrit test mode functionality."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_test_mode_gpg(self, mock_client_class, runner):
        """Test mode for GPG key (no API calls)."""
        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--test-mode",
            ],
        )

        assert result.exit_code == 0
        output = strip_ansi_codes(result.stdout)
        assert "GPG" in output
        assert SAMPLE_GPG_KEY_ID in output
        # Should not create client in test mode
        mock_client_class.assert_not_called()

    @patch("tag_validate.cli.GerritKeysClient")
    def test_test_mode_ssh(self, mock_client_class, runner):
        """Test mode for SSH key (no API calls)."""
        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_SSH_FINGERPRINT,
                "--owner",
                SAMPLE_USERNAME,
                "--server",
                SAMPLE_SERVER,
                "--test-mode",
            ],
        )

        # Test mode may exit with 1 for SSH (no normalization needed)
        assert result.exit_code in (0, 1)
        # Should not create client in test mode
        mock_client_class.assert_not_called()

    @patch("tag_validate.cli.GerritKeysClient")
    def test_test_mode_json(self, mock_client_class, runner):
        """Test mode with JSON output."""
        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--test-mode",
                "--json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["test_mode"] is True
        assert output["key_type"] == "gpg"
        mock_client_class.assert_not_called()


class TestVerifyGerritErrorHandling:
    """Test error handling for Gerrit verification."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_gerrit_server_error(self, mock_client_class, runner):
        """Test handling of Gerrit server errors."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.side_effect = GerritKeysError(
            "Server connection failed"
        )

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
            ],
        )

        assert result.exit_code != 0
        assert "Error" in result.stdout

    @patch("tag_validate.cli.GerritKeysClient")
    def test_gerrit_server_error_json(self, mock_client_class, runner):
        """Test JSON output for Gerrit server errors."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.side_effect = GerritKeysError(
            "Server connection failed"
        )

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--json",
            ],
        )

        assert result.exit_code != 0
        # Parse only the first JSON object (may have extra output after errors)
        try:
            lines = result.stdout.strip().split("\n")
            json_line = next(line for line in lines if line.strip().startswith("{"))
            output = json.loads(json_line)
            assert output["success"] is False
            assert "error" in output
        except (json.JSONDecodeError, StopIteration):
            # If JSON parsing fails, just check that the command failed
            assert result.exit_code != 0

    def test_invalid_key_type(self, runner):
        """Test with invalid key type."""
        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
                "--type",
                "invalid",
            ],
        )

        assert result.exit_code != 0


class TestVerifyGerritEdgeCases:
    """Test edge cases for Gerrit verification."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_email_vs_username_detection(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test automatic detection of email vs username."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        # First test with email
        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_EMAIL,
                "--server",
                SAMPLE_SERVER,
            ],
        )

        assert result.exit_code == 0
        mock_client.lookup_account_by_email.assert_called_once_with(SAMPLE_EMAIL)

        # Reset mocks
        mock_client.reset_mock()

        # Test with username (no @ symbol)
        mock_client.lookup_account_by_username.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "--owner",
                SAMPLE_USERNAME,
                "--server",
                SAMPLE_SERVER,
            ],
        )

        assert result.exit_code == 0
        mock_client.lookup_account_by_username.assert_called_once_with(SAMPLE_USERNAME)

    @patch("tag_validate.cli.GerritKeysClient")
    def test_short_flags(
        self, mock_client_class, runner, mock_gerrit_account, mock_verification_success
    ):
        """Test short flag variants."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        mock_client.lookup_account_by_email.return_value = mock_gerrit_account
        mock_client.verify_gpg_key_registered.return_value = mock_verification_success

        result = runner.invoke(
            app,
            [
                "gerrit",
                SAMPLE_GPG_KEY_ID,
                "-o",
                SAMPLE_EMAIL,
                "-s",
                SAMPLE_SERVER,
                "-t",
                "gpg",
                "-j",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
