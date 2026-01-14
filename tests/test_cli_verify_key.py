# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the verify-github CLI command.

This module provides comprehensive tests for the `verify-github` sub-command,
which verifies if a GPG key ID or SSH fingerprint is registered on GitHub.

Test Coverage:
--------------
1. **Basic Functionality** (TestVerifyKeyBasic)
   - Help output
   - Missing required arguments
   - Missing GitHub token

2. **GPG Key Verification** (TestVerifyKeyGPG)
   - Registered GPG keys
   - Non-registered GPG keys
   - Explicit type specification
   - Subkey verification with --no-subkeys flag
   - Various GPG key formats (8, 16, 40 character)

3. **SSH Key Verification** (TestVerifyKeySSH)
   - Registered SSH keys
   - SSH fingerprints (SHA256, MD5)
   - Various SSH key types (rsa, ed25519, ecdsa)
   - Explicit type specification

4. **Auto-Detection** (TestVerifyKeyAutoDetection)
   - GPG key auto-detection (8, 16, 40 hex chars)
   - SSH key auto-detection (prefixes, fingerprints)
   - Unknown format handling

5. **JSON Output** (TestVerifyKeyJSON)
   - Success/failure JSON responses
   - Error handling in JSON format
   - Log suppression with JSON output

6. **Environment Variables** (TestVerifyKeyEnvironment)
   - GITHUB_TOKEN environment variable

7. **Edge Cases** (TestVerifyKeyEdgeCases)
   - Invalid key types
   - Exception handling
   - Short flag aliases

8. **Integration Tests** (TestVerifyKeyIntegration)
   - Complete GPG workflow
   - Complete SSH workflow
   - Keys with spaces
   - Mixed-case keys
   - Log suppression verification

Usage:
------
Run all tests:
    pytest tests/test_cli_verify_key.py

Run specific test class:
    pytest tests/test_cli_verify_key.py::TestVerifyKeyGPG

Run with verbose output:
    pytest tests/test_cli_verify_key.py -v
"""

import json
import re
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from tag_validate.cli import app
from tag_validate.models import KeyVerificationResult

runner = CliRunner()


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape codes from text.

    Typer/Rich adds color formatting to CLI output which includes ANSI escape
    sequences (e.g., '\x1b[1;36m--owner\x1b[0m'). These need to be stripped
    to perform accurate string matching in tests, especially in CI environments
    where color output may differ from local development.

    Args:
        text: Text potentially containing ANSI escape codes

    Returns:
        Text with all ANSI codes removed
    """
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return ansi_escape.sub("", text)


class TestVerifyKeyBasic:
    """Test basic verify-github command functionality."""

    def test_verify_key_help(self):
        """Test verify-github help output."""
        result = runner.invoke(app, ["verify-github", "--help"])
        assert result.exit_code == 0

        # Strip ANSI codes for easier assertions
        output = strip_ansi_codes(result.stdout)

        assert "Verify if a specific GPG key ID or SSH fingerprint" in output
        assert "--owner" in output
        assert "--type" in output
        assert "--token" in output
        assert "--json" in output
        assert "--no-subkeys" in output

    def test_verify_key_missing_key_id(self):
        """Test verify-github without key ID argument."""
        result = runner.invoke(app, ["verify-github"])
        assert result.exit_code != 0
        # CliRunner may not capture stderr, check exit code is sufficient

    def test_verify_key_missing_owner(self):
        """Test verify-github without --owner option."""
        result = runner.invoke(app, ["verify-github", "ABCD1234"])
        assert result.exit_code != 0
        # Should complain about missing --owner

    def test_verify_key_missing_token(self):
        """Test verify-github without GitHub token."""
        result = runner.invoke(
            app,
            ["verify-github", "ABCD1234", "--owner", "testuser"],
            env={"GITHUB_TOKEN": ""},  # Ensure no token in environment
        )
        assert result.exit_code == 1
        assert (
            "GitHub token is required" in result.stdout
            or "token" in result.stdout.lower()
        )


class TestVerifyKeyGPG:
    """Test verify-github with GPG keys."""

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_gpg_key_registered(self, mock_client_class):
        """Test verifying a registered GPG key."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234EF5678AB",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "ABCD1234EF5678AB" in result.stdout
        assert "testuser" in result.stdout
        mock_client.verify_gpg_key_registered.assert_called_once_with(
            username="testuser",
            key_id="ABCD1234EF5678AB",
            check_subkeys=True,
        )

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_gpg_key_not_registered(self, mock_client_class):
        """Test verifying a non-registered GPG key."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=False,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "AAAABBBB",  # Valid hex key that won't be found
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 1
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_gpg_key_explicit_type(self, mock_client_class):
        """Test verifying GPG key with explicit --type gpg."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--type",
                "gpg",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_gpg_key_no_subkeys(self, mock_client_class):
        """Test verifying GPG key with --no-subkeys flag."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234EF5678AB",
                "--owner",
                "testuser",
                "--no-subkeys",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_gpg_key_registered.assert_called_once_with(
            username="testuser",
            key_id="ABCD1234EF5678AB",
            check_subkeys=False,  # Should be False due to --no-subkeys
        )

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_gpg_key_various_formats(self, mock_client_class):
        """Test verifying GPG keys in various valid formats."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        # Test different GPG key formats
        key_formats = [
            "ABCD1234",  # 8 chars
            "ABCD1234EF5678AB",  # 16 chars
            "1234567890ABCDEF1234567890ABCDEF12345678",  # 40 chars (full fingerprint)
        ]

        for key_id in key_formats:
            mock_client.verify_gpg_key_registered.reset_mock()
            result = runner.invoke(
                app,
                [
                    "verify-github",
                    key_id,
                    "--owner",
                    "testuser",
                    "--token",
                    "test_token",
                ],
            )
            assert result.exit_code == 0, f"Failed for key format: {key_id}"


class TestVerifyKeySSH:
    """Test verify-github with SSH keys."""

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_ssh_key_registered(self, mock_client_class):
        """Test verifying a registered SSH key."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz"

        result = runner.invoke(
            app,
            [
                "verify-github",
                ssh_key,
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_ssh_key_registered.assert_called_once_with(
            username="testuser",
            public_key_fingerprint=ssh_key,
        )

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_ssh_fingerprint_registered(self, mock_client_class):
        """Test verifying a registered SSH fingerprint."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        ssh_fingerprint = "SHA256:abcdefghijklmnopqrstuvwxyz1234567890ABC"

        result = runner.invoke(
            app,
            [
                "verify-github",
                ssh_fingerprint,
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_ssh_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_ssh_key_explicit_type(self, mock_client_class):
        """Test verifying SSH key with explicit --type ssh."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "some-ambiguous-key",
                "--owner",
                "testuser",
                "--type",
                "ssh",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_ssh_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_ssh_key_various_types(self, mock_client_class):
        """Test verifying various SSH key types."""
        # Setup mock
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        # Test different SSH key types
        ssh_keys = [
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY...",
            "SHA256:abcdefghijklmnopqrstuvwxyz",
            "MD5:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
        ]

        for ssh_key in ssh_keys:
            mock_client.verify_ssh_key_registered.reset_mock()
            result = runner.invoke(
                app,
                [
                    "verify-github",
                    ssh_key,
                    "--owner",
                    "testuser",
                    "--token",
                    "test_token",
                ],
            )
            assert result.exit_code == 0, f"Failed for SSH key type: {ssh_key}"
            mock_client.verify_ssh_key_registered.assert_called_once()


class TestVerifyKeyAutoDetection:
    """Test automatic key type detection."""

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_auto_detect_gpg_hex_8(self, mock_client_class):
        """Test auto-detection of 8-char GPG key ID."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "auto-detected" in result.stdout
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_auto_detect_gpg_hex_16(self, mock_client_class):
        """Test auto-detection of 16-char GPG key ID."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234EF5678AB",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "auto-detected" in result.stdout
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_auto_detect_gpg_hex_40(self, mock_client_class):
        """Test auto-detection of 40-char GPG fingerprint."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "1234567890ABCDEF1234567890ABCDEF12345678",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "auto-detected" in result.stdout
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_auto_detect_ssh_prefix(self, mock_client_class):
        """Test auto-detection of SSH key by prefix."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "auto-detected" in result.stdout
        mock_client.verify_ssh_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_auto_detect_ssh_sha256(self, mock_client_class):
        """Test auto-detection of SSH SHA256 fingerprint."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "SHA256:abcdefghijklmnop",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "auto-detected" in result.stdout
        mock_client.verify_ssh_key_registered.assert_called_once()

    def test_auto_detect_unknown_format(self):
        """Test auto-detection failure for unknown format."""
        result = runner.invoke(
            app,
            [
                "verify-github",
                "not-a-valid-key-123",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 1
        assert "Could not auto-detect key type" in result.stdout


class TestVerifyKeyJSON:
    """Test verify-github with JSON output."""

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_key_json_success(self, mock_client_class):
        """Test JSON output for successful verification."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--token",
                "test_token",
                "--json",
            ],
        )

        assert result.exit_code == 0

        # Parse JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is True
        assert output["key_type"] == "gpg"
        assert output["key_id"] == "ABCD1234"
        assert output["github_user"] == "testuser"
        assert output["is_registered"] is True

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_verify_key_json_failure(self, mock_client_class):
        """Test JSON output for failed verification."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=False,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "NOTFOUND",
                "--owner",
                "testuser",
                "--token",
                "test_token",
                "--json",
            ],
        )

        assert result.exit_code == 1

        # Parse JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is False
        if "is_registered" in output:
            assert output["is_registered"] is False

    def test_verify_key_json_missing_token(self):
        """Test JSON output for missing token error."""
        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--json",
            ],
            env={"GITHUB_TOKEN": ""},
        )

        assert result.exit_code == 1

        # Parse JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is False
        assert "error" in output
        assert "token" in output["error"].lower()

    def test_verify_key_json_invalid_type(self):
        """Test JSON output for invalid key type."""
        result = runner.invoke(
            app,
            [
                "verify-github",
                "somekey",
                "--owner",
                "testuser",
                "--type",
                "invalid",
                "--token",
                "test_token",
                "--json",
            ],
        )

        assert result.exit_code == 1

        # Parse JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is False
        assert "error" in output
        assert "Invalid key type" in output["error"]

    def test_verify_key_json_auto_detect_failure(self):
        """Test JSON output for auto-detection failure."""
        result = runner.invoke(
            app,
            [
                "verify-github",
                "not-a-valid-key",
                "--owner",
                "testuser",
                "--token",
                "test_token",
                "--json",
            ],
        )

        assert result.exit_code == 1

        # Parse JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is False
        assert "error" in output
        assert "auto-detect" in output["error"].lower()


class TestVerifyKeyEnvironment:
    """Test verify-github with environment variables."""

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_token_from_environment(self, mock_client_class):
        """Test reading GitHub token from environment."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            ["verify-github", "ABCD1234", "--owner", "testuser"],
            env={"GITHUB_TOKEN": "env_test_token"},
        )

        assert result.exit_code == 0
        # Verify the client was created (token would be passed internally)
        mock_client_class.assert_called_once()


class TestVerifyKeyEdgeCases:
    """Test edge cases and error handling."""

    def test_invalid_key_type(self):
        """Test with invalid --type value."""
        result = runner.invoke(
            app,
            [
                "verify-github",
                "somekey",
                "--owner",
                "testuser",
                "--type",
                "invalid",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 1
        assert "Invalid key type" in result.stdout

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_exception_handling(self, mock_client_class):
        """Test handling of unexpected exceptions."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.side_effect = Exception(
            "Unexpected error"
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 1
        assert "Error" in result.stdout or "error" in result.stdout.lower()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_exception_handling_json(self, mock_client_class):
        """Test handling of unexpected exceptions with JSON output."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.side_effect = Exception(
            "Unexpected error"
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--token",
                "test_token",
                "--json",
            ],
        )

        assert result.exit_code == 1

        # Parse JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is False
        assert "error" in output
        assert "Unexpected error" in output["error"]

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_short_flags(self, mock_client_class):
        """Test using short flags."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "-o",
                "testuser",
                "-t",
                "gpg",
                "--token",
                "test_token",
                "-j",
            ],
        )

        assert result.exit_code == 0

        # Verify JSON output
        output = json.loads(result.stdout.strip())
        assert output["success"] is True


class TestVerifyKeyIntegration:
    """Integration-style tests combining multiple features."""

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_full_workflow_gpg(self, mock_client_class):
        """Test complete workflow for GPG key verification."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "1234567890ABCDEF",
                "--owner",
                "testuser",
                "--type",
                "auto",
                "--token",
                "test_token",
                "--no-subkeys",
            ],
        )

        assert result.exit_code == 0
        assert "1234567890ABCDEF" in result.stdout
        assert "testuser" in result.stdout
        mock_client.verify_gpg_key_registered.assert_called_once_with(
            username="testuser",
            key_id="1234567890ABCDEF",
            check_subkeys=False,
        )

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_full_workflow_ssh(self, mock_client_class):
        """Test complete workflow for SSH key verification."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_ssh_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefg"

        result = runner.invoke(
            app,
            [
                "verify-github",
                ssh_key,
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        assert "testuser" in result.stdout
        mock_client.verify_ssh_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_gpg_with_spaces(self, mock_client_class):
        """Test GPG key with spaces (common in fingerprint format)."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        # GPG fingerprints are sometimes formatted with spaces
        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD 1234 EF56 78AB",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_mixed_case_keys(self, mock_client_class):
        """Test that key detection works with mixed case."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        # Test mixed case GPG key
        result = runner.invoke(
            app,
            [
                "verify-github",
                "AbCd1234",
                "--owner",
                "testuser",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        mock_client.verify_gpg_key_registered.assert_called_once()

    @patch("tag_validate.cli.GitHubKeysClient")
    def test_json_output_suppresses_logs(self, mock_client_class):
        """Test that JSON output doesn't include log messages."""
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.verify_gpg_key_registered.return_value = KeyVerificationResult(
            key_registered=True,
            username="testuser",
        )
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            app,
            [
                "verify-github",
                "ABCD1234",
                "--owner",
                "testuser",
                "--token",
                "test_token",
                "--json",
            ],
        )

        assert result.exit_code == 0
        # Output should be valid JSON only
        output = json.loads(result.stdout.strip())
        assert "success" in output
        # Should not contain log messages
        assert "Verifying" not in result.stdout
        assert "Key ID" not in result.stdout
