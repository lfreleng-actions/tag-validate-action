# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the verify CLI command.

This module provides comprehensive tests for the `verify` sub-command,
which validates Git tags including version format and signatures.

Test Coverage:
--------------
1. **Empty Tag Location** (TestVerifyEmptyTagLocation)
   - Empty string tag location
   - Whitespace-only tag location
   - JSON output mode with empty tag
   - Non-JSON output mode with empty tag

2. **Tag Location Validation** (TestVerifyTagLocationValidation)
   - Valid local tag names
   - Valid remote tag locations (owner/repo@tag)
   - Invalid formats

3. **Error Handling** (TestVerifyErrorHandling)
   - Missing required arguments
   - Invalid option combinations
   - Graceful error messages

Usage:
------
Run all tests:
    pytest tests/test_cli_verify.py

Run specific test class:
    pytest tests/test_cli_verify.py::TestVerifyEmptyTagLocation

Run with verbose output:
    pytest tests/test_cli_verify.py -v
"""

import json
import re
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app


def strip_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape codes from text.

    Typer/Rich adds color formatting to CLI output which includes ANSI escape
    sequences. These need to be stripped to perform accurate string matching
    in tests, especially in CI environments where color output may differ.

    Args:
        text: Text potentially containing ANSI escape codes

    Returns:
        Text with ANSI codes removed
    """
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def async_return(value):
    """Helper function to create an async return value for mocking."""

    async def _async_return():
        return value

    return _async_return()


runner = CliRunner()


class TestVerifyEmptyTagLocation:
    """Test suite for empty tag_location validation in verify command."""

    def test_empty_string_tag_location_non_json(self):
        """Test that empty string tag location fails with appropriate error message (non-JSON mode)."""
        result = runner.invoke(app, ["verify", ""])

        assert result.exit_code == 1
        assert "Tag location is empty or null" in result.stdout

    def test_empty_string_tag_location_json(self):
        """Test that empty string tag location fails with structured JSON error (JSON mode)."""
        result = runner.invoke(app, ["verify", "", "--json"])

        assert result.exit_code == 1

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert output["tag_name"] == ""
            assert "error" in output
            assert "Tag location is empty or null" in output["error"]
            assert "info" in output
            assert any(
                "tag_location parameter is required" in info for info in output["info"]
            )
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_whitespace_only_tag_location_non_json(self):
        """Test that whitespace-only tag location fails with appropriate error (non-JSON mode)."""
        result = runner.invoke(app, ["verify", "   "])

        assert result.exit_code == 1
        assert "Tag location is empty or null" in result.stdout

    def test_whitespace_only_tag_location_json(self):
        """Test that whitespace-only tag location fails with structured JSON error (JSON mode)."""
        result = runner.invoke(app, ["verify", "   ", "--json"])

        assert result.exit_code == 1

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert output["tag_name"] == ""
            assert "error" in output
            assert "Tag location is empty or null" in output["error"]
            assert "info" in output
            # Check that expected formats are mentioned
            assert any("v1.0.0" in info for info in output["info"])
            assert any("owner/repo@v1.0.0" in info for info in output["info"])
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_tabs_and_newlines_tag_location(self):
        """Test that tag location with only tabs and newlines fails appropriately."""
        result = runner.invoke(app, ["verify", "\t\n\r", "--json"])

        assert result.exit_code == 1

        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestVerifyTagLocationValidation:
    """Test suite for tag_location format validation."""

    def test_valid_simple_tag_name(self):
        """Test that a simple tag name is accepted (may fail validation but not argument parsing)."""
        # This will likely fail because the tag doesn't exist, but it should pass the empty check
        result = runner.invoke(app, ["verify", "v1.0.0", "--json"])

        # The tag won't exist, but we shouldn't get the "empty or null" error
        if result.exit_code == 1:
            assert "Tag location is empty or null" not in result.stdout

    def test_valid_remote_tag_location(self):
        """Test that owner/repo@tag format is accepted."""
        # This will likely fail because we don't have access, but format should be accepted
        result = runner.invoke(app, ["verify", "owner/repo@v1.0.0", "--json"])

        # Should not get the empty tag location error
        if result.exit_code == 1:
            assert "Tag location is empty or null" not in result.stdout

    def test_help_output(self):
        """Test that help message shows expected tag location formats."""
        result = runner.invoke(app, ["verify", "--help"])

        assert result.exit_code == 0

        # Strip ANSI codes for easier assertions
        output = strip_ansi_codes(result.stdout)

        # Help should mention tag_location argument
        assert "tag_location" in output.lower() or "tag-location" in output.lower()


class TestVerifyErrorHandling:
    """Test suite for error handling in verify command."""

    def test_missing_tag_location_argument(self):
        """Test that missing tag_location argument shows appropriate error."""
        result = runner.invoke(app, ["verify"])

        assert result.exit_code != 0
        # Should mention missing argument (case-insensitive check)
        # Error may be in stdout or stderr depending on environment/Typer version
        # Safely try to get stderr (may not be separately captured)
        try:
            stderr_content = result.stderr if hasattr(result, "stderr") else ""
        except (ValueError, AttributeError):
            stderr_content = ""

        output = (result.stdout + stderr_content).lower()
        assert "missing" in output or "required" in output, (
            f"Expected 'missing' or 'required' in output, got stdout: {result.stdout!r}, stderr: {stderr_content!r}"
        )

    def test_json_output_suppresses_rich_formatting(self):
        """Test that JSON mode suppresses rich console output."""
        result = runner.invoke(app, ["verify", "", "--json"])

        # Output should be valid JSON, not rich console formatting
        try:
            output = json.loads(result.stdout)
            assert isinstance(output, dict)
            assert "success" in output
        except json.JSONDecodeError:
            pytest.fail(f"JSON mode should produce valid JSON output: {result.stdout}")

    def test_error_message_includes_examples(self):
        """Test that error message includes helpful format examples."""
        result = runner.invoke(app, ["verify", "", "--json"])

        try:
            output = json.loads(result.stdout)
            info_messages = output.get("info", [])

            # Should include examples of expected formats
            has_local_example = any("v1.0.0" in msg for msg in info_messages)
            has_remote_example = any("owner/repo@" in msg for msg in info_messages)

            assert has_local_example, "Should include local tag example"
            assert has_remote_example, "Should include remote tag example"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestVerifyWithOptions:
    """Test suite for verify command with various options."""

    def test_empty_tag_with_require_type_option(self):
        """Test empty tag location fails even with --require-type option."""
        result = runner.invoke(
            app, ["verify", "", "--require-type", "semver", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_empty_tag_with_require_signed_option(self):
        """Test empty tag location fails even with --require-signed option."""
        result = runner.invoke(
            app, ["verify", "", "--require-signed", "true", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_whitespace_tag_with_multiple_options(self):
        """Test whitespace tag location fails with multiple options combined."""
        result = runner.invoke(
            app,
            [
                "verify",
                "  \t  ",
                "--require-type",
                "semver",
                "--require-signed",
                "true",
                "--require-github",
                "--json",
            ],
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestVerifyOutputConsistency:
    """Test suite to ensure consistent output format between JSON and non-JSON modes."""

    def test_error_message_consistency(self):
        """Test that error message is consistent between JSON and non-JSON modes."""
        # Non-JSON mode
        result_non_json = runner.invoke(app, ["verify", ""])
        output_non_json = result_non_json.stdout

        # JSON mode
        result_json = runner.invoke(app, ["verify", "", "--json"])

        # Both should mention the same core error
        assert "Tag location is empty or null" in output_non_json

        try:
            output_json = json.loads(result_json.stdout)
            assert "Tag location is empty or null" in output_json["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result_json.stdout}")

    def test_exit_codes_consistent(self):
        """Test that exit codes are consistent between JSON and non-JSON modes."""
        result_non_json = runner.invoke(app, ["verify", ""])
        result_json = runner.invoke(app, ["verify", "", "--json"])

        # Both should exit with non-zero code
        assert result_non_json.exit_code == 1
        assert result_json.exit_code == 1


class TestGerritVerification:
    """Test Gerrit verification CLI functionality."""

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_require_gerrit_auto_discovery(self, mock_workflow_class):
        """Test --require-gerrit with auto-discovery."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        # Mock successful validation with Gerrit
        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = True
        mock_result.config.gerrit_server = None
        mock_key_verification = Mock()
        mock_key_verification.service = "gerrit"
        mock_key_verification.server = "gerrit.onap.org"
        mock_key_verification.key_registered = True
        mock_result.key_verifications = [mock_key_verification]
        mock_result.errors = []
        mock_result.warnings = []
        mock_result.info = ["Signing key verified on Gerrit server gerrit.onap.org"]
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "ssh"
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)
        mock_workflow.create_validation_summary.return_value = (
            "Tag Validation: ✅ PASSED\nTag: v1.0.0"
        )

        result = runner.invoke(app, ["verify", "v1.0.0", "--require-gerrit", "true"])

        assert result.exit_code == 0
        # Check that ValidationConfig was created with Gerrit settings
        call_args = mock_workflow_class.call_args[0][0]
        assert call_args.require_gerrit is True
        assert call_args.gerrit_server is None  # Should be None for auto-discovery

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_require_gerrit_explicit_server(self, mock_workflow_class):
        """Test --require-gerrit with explicit server."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = True
        mock_result.config.gerrit_server = "gerrit.onap.org"
        mock_result.errors = []
        mock_result.warnings = []
        mock_result.info = []
        mock_result.key_verifications = []
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "unsigned"
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)
        mock_workflow.create_validation_summary.return_value = (
            "Tag Validation: ✅ PASSED\nTag: v1.0.0"
        )

        result = runner.invoke(
            app, ["verify", "v1.0.0", "--require-gerrit", "gerrit.onap.org"]
        )

        assert result.exit_code == 0
        # Check that ValidationConfig was created with explicit server
        call_args = mock_workflow_class.call_args[0][0]
        assert call_args.require_gerrit is True
        assert call_args.gerrit_server == "gerrit.onap.org"

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_require_gerrit_false(self, mock_workflow_class):
        """Test --require-gerrit false (disabled)."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = False
        mock_result.errors = []
        mock_result.warnings = []
        mock_result.info = []
        mock_result.key_verifications = []
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "unsigned"
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)
        mock_workflow.create_validation_summary.return_value = (
            "Tag Validation: ✅ PASSED\nTag: v1.0.0"
        )

        result = runner.invoke(app, ["verify", "v1.0.0", "--require-gerrit", "false"])

        assert result.exit_code == 0
        # Check that Gerrit is disabled
        call_args = mock_workflow_class.call_args[0][0]
        assert call_args.require_gerrit is False
        assert call_args.gerrit_server is None

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_combined_github_gerrit(self, mock_workflow_class):
        """Test combined GitHub and Gerrit verification."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_github = True
        mock_result.config.require_gerrit = True
        mock_result.config.gerrit_server = "gerrit.onap.org"
        mock_result.errors = []
        mock_result.warnings = []
        mock_result.info = [
            "Signing key verified for GitHub user @johndoe",
            "Signing key verified on Gerrit server gerrit.onap.org",
        ]
        mock_key_verification = Mock()
        mock_key_verification.service = "github"
        mock_key_verification.username = "johndoe"
        mock_key_verification.key_registered = True
        mock_result.key_verifications = [mock_key_verification]
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "gpg"
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)
        mock_workflow.create_validation_summary.return_value = (
            "Tag Validation: ✅ PASSED\nTag: v1.0.0\n\nInfo:\n"
            "  • Signing key verified for GitHub user @johndoe\n"
            "  • Signing key verified on Gerrit server gerrit.onap.org"
        )

        result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-github",
                "--require-gerrit",
                "gerrit.onap.org",
                "--token",
                "test_token",
            ],
        )

        assert result.exit_code == 0
        # Check that both GitHub and Gerrit are enabled
        call_args = mock_workflow_class.call_args[0][0]
        assert call_args.require_github is True
        assert call_args.require_gerrit is True
        assert call_args.gerrit_server == "gerrit.onap.org"

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_gerrit_verification_failure(self, mock_workflow_class):
        """Test Gerrit verification failure."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        mock_result = Mock()
        mock_result.is_valid = False
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = True
        mock_result.config.gerrit_server = "gerrit.onap.org"
        mock_result.errors = [
            "Signing key not registered on Gerrit server gerrit.onap.org"
        ]
        mock_result.warnings = []
        mock_result.info = []
        mock_key_verification = Mock()
        mock_key_verification.service = "gerrit"
        mock_key_verification.server = "gerrit.onap.org"
        mock_key_verification.key_registered = False
        mock_result.key_verifications = [mock_key_verification]
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "ssh"
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)
        mock_workflow.create_validation_summary.return_value = (
            "Tag Validation: ❌ FAILED\nTag: v1.0.0\n\nErrors:\n"
            "  • Signing key not registered on Gerrit server gerrit.onap.org"
        )

        result = runner.invoke(
            app, ["verify", "v1.0.0", "--require-gerrit", "gerrit.onap.org"]
        )

        assert result.exit_code == 1
        assert "Signing key not registered on Gerrit server" in result.stdout

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_gerrit_with_require_owner(self, mock_workflow_class):
        """Test Gerrit verification with required owners."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = True
        mock_result.config.gerrit_server = "gerrit.onap.org"
        mock_result.errors = []
        mock_result.warnings = []
        mock_result.info = [
            "Signing key verified for required owner on Gerrit: maintainer@project.org"
        ]
        mock_key_verification = Mock()
        mock_key_verification.service = "gerrit"
        mock_key_verification.server = "gerrit.onap.org"
        mock_key_verification.key_registered = True
        mock_key_verification.username = "maintainer@project.org"
        mock_result.key_verifications = [mock_key_verification]
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "gpg"
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)
        mock_workflow.create_validation_summary.return_value = (
            "Tag Validation: ✅ PASSED\nTag: v1.0.0\n\nInfo:\n"
            "  • Signing key verified for required owner on Gerrit: maintainer@project.org"
        )

        result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--require-gerrit",
                "gerrit.onap.org",
                "--require-owner",
                "maintainer@project.org",
            ],
        )

        assert result.exit_code == 0
        assert "Signing key verified for required owner on Gerrit" in result.stdout

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_gerrit_json_output(self, mock_workflow_class):
        """Test Gerrit verification with JSON output."""
        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = True
        mock_result.config.gerrit_server = "gerrit.onap.org"
        mock_result.errors = []
        mock_result.warnings = []
        mock_result.info = []

        # Key verification with all required attributes
        mock_key_verification = Mock()
        mock_key_verification.service = "gerrit"
        mock_key_verification.server = "gerrit.onap.org"
        mock_key_verification.key_registered = True
        mock_key_verification.username = "12345"
        mock_key_verification.user_email = "test@example.com"
        mock_key_verification.user_name = "Test User"
        mock_key_verification.user_enumerated = False
        mock_key_verification.key_info = None

        mock_result.key_verifications = [mock_key_verification]

        # Signature info with all required attributes for JSON
        mock_result.signature_info = Mock()
        mock_result.signature_info.type = "ssh"
        mock_result.signature_info.verified = True
        mock_result.signature_info.signer_email = None
        mock_result.signature_info.key_id = "SHA256:abc123"
        mock_result.signature_info.fingerprint = "SHA256:abc123"

        # Version info with all required attributes for JSON
        mock_result.version_info = Mock()
        mock_result.version_info.version_type = "semver"
        mock_result.version_info.is_development = False
        mock_result.version_info.has_prefix = False
        mock_result.version_info.raw = "1.0.0"
        mock_result.version_info.normalized = "1.0.0"
        mock_result.version_info.major = 1
        mock_result.version_info.minor = 0
        mock_result.version_info.patch = 0
        mock_result.version_info.prerelease = None
        mock_result.version_info.build_metadata = None

        mock_workflow.validate_tag_location.return_value = async_return(mock_result)

        result = runner.invoke(
            app, ["verify", "v1.0.0", "--require-gerrit", "gerrit.onap.org", "--json"]
        )

        assert result.exit_code == 0
        output = json.loads(result.stdout)
        assert output["success"] is True
        assert "key_verifications" in output
        assert len(output["key_verifications"]) == 1
        assert output["key_verifications"][0]["service"] == "gerrit"
        assert output["key_verifications"][0]["key_registered"] is True
        assert output["signature_type"] == "ssh"
        assert output["version_type"] == "semver"

    def test_require_gerrit_help(self):
        """Test that --require-gerrit appears in help."""
        # Use a fresh runner to avoid test isolation issues
        from typer.testing import CliRunner

        # Set a wide terminal width to prevent help text truncation
        fresh_runner = CliRunner(env={"COLUMNS": "250"})
        result = fresh_runner.invoke(app, ["verify", "--help"])

        assert result.exit_code == 0

        # Strip ANSI codes for easier assertions
        output = strip_ansi_codes(result.stdout)
        stdout_lower = output.lower()

        # Check for Gerrit-related options
        assert "gerrit" in stdout_lower, "Gerrit should be mentioned in help"

        # Check for the key parts of the help text more robustly
        # The help text might be formatted differently in different contexts
        assert "verify" in stdout_lower and "signing key" in stdout_lower

        # These options might be truncated, so check more flexibly
        if "--require-gerrit" not in result.stdout:
            # If truncated, at least check that gerrit verification is mentioned
            assert "gerrit" in stdout_lower and "verif" in stdout_lower

        # Also check that the actual help text contains the expected phrase
        # Remove all table formatting and normalize
        # Remove box drawing characters and normalize
        cleaned = re.sub(r"[│╰╯╭╮─┌┐└┘├┤┬┴┼]", " ", result.stdout)
        normalized_help = " ".join(cleaned.split())
        assert "verify signing key" in normalized_help.lower()
        assert "registered on gerrit" in normalized_help.lower()
