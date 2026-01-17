# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the validate CLI command.

This module provides comprehensive tests for the `validate` sub-command,
which validates version strings against SemVer and CalVer patterns.

Test Coverage:
--------------
1. **Empty Version String** (TestValidateEmptyVersionString)
   - Empty string version
   - Whitespace-only version
   - JSON output mode with empty version
   - Non-JSON output mode with empty version

2. **Version String Validation** (TestValidateVersionStringValidation)
   - Valid SemVer versions
   - Valid CalVer versions
   - Invalid version formats

3. **Error Handling** (TestValidateErrorHandling)
   - Missing required arguments
   - Invalid option combinations
   - Graceful error messages

4. **Type Requirements** (TestValidateTypeRequirements)
   - Require SemVer type
   - Require CalVer type
   - Type mismatch errors

5. **Output Consistency** (TestValidateOutputConsistency)
   - Consistent error messages between JSON and non-JSON modes
   - Consistent exit codes

Usage:
------
Run all tests:
    pytest tests/test_cli_validate.py

Run specific test class:
    pytest tests/test_cli_validate.py::TestValidateEmptyVersionString

Run with verbose output:
    pytest tests/test_cli_validate.py -v
"""

import json
import re

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app

runner = CliRunner()


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


class TestValidateEmptyVersionString:
    """Test suite for empty version_string validation in validate command."""

    def test_empty_string_version_non_json(self):
        """Test that empty string version fails with appropriate error message (non-JSON mode)."""
        result = runner.invoke(app, ["validate", ""])

        assert result.exit_code == 1
        assert "Version string is empty or null" in result.stdout

    def test_empty_string_version_json(self):
        """Test that empty string version fails with structured JSON error (JSON mode)."""
        result = runner.invoke(app, ["validate", "", "--json"])

        assert result.exit_code == 1

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert output["version"] == ""
            assert "error" in output
            assert "Version string is empty or null" in output["error"]
            assert "info" in output
            assert any(
                "version_string parameter is required" in info
                for info in output["info"]
            )
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_whitespace_only_version_non_json(self):
        """Test that whitespace-only version fails with appropriate error (non-JSON mode)."""
        result = runner.invoke(app, ["validate", "   "])

        assert result.exit_code == 1
        assert "Version string is empty or null" in result.stdout

    def test_whitespace_only_version_json(self):
        """Test that whitespace-only version fails with structured JSON error (JSON mode)."""
        result = runner.invoke(app, ["validate", "   ", "--json"])

        assert result.exit_code == 1

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert output["version"] == ""
            assert "error" in output
            assert "Version string is empty or null" in output["error"]
            assert "info" in output
            # Check that expected formats are mentioned
            assert any("v1.0.0" in info for info in output["info"])
            assert any("2024.01.15" in info for info in output["info"])
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_tabs_and_newlines_version(self):
        """Test that version with only tabs and newlines fails appropriately."""
        result = runner.invoke(app, ["validate", "\t\n\r", "--json"])

        assert result.exit_code == 1

        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Version string is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestValidateVersionStringValidation:
    """Test suite for version_string format validation."""

    def test_valid_semver_version(self):
        """Test that a valid SemVer version is accepted."""
        result = runner.invoke(app, ["validate", "v1.0.0", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "semver"
            assert output["is_valid"] is True
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_valid_calver_version(self):
        """Test that a valid CalVer version is accepted."""
        result = runner.invoke(app, ["validate", "2024.01.15", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "calver"
            assert output["is_valid"] is True
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_invalid_version_format(self):
        """Test that an invalid version format is accepted as 'other' type."""
        result = runner.invoke(app, ["validate", "invalid-version-123", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "other"
            assert output["is_valid"] is True
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_semver_with_prerelease(self):
        """Test SemVer version with prerelease tag."""
        result = runner.invoke(app, ["validate", "v1.0.0-beta.1", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "semver"
            assert output["prerelease"] == "beta.1"
            assert output["development_tag"] is True
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_help_output(self):
        """Test that help message shows expected information."""
        result = runner.invoke(app, ["validate", "--help"])

        assert result.exit_code == 0

        # Strip ANSI codes for easier assertions
        output = strip_ansi_codes(result.stdout)

        # Help should mention version_string argument
        assert (
            "version_string" in output.lower()
            or "version-string" in output.lower()
            or "version string" in output.lower()
        )


class TestValidateErrorHandling:
    """Test suite for error handling in validate command."""

    def test_missing_version_string_argument(self):
        """Test that missing version_string argument shows appropriate error."""
        result = runner.invoke(app, ["validate"])

        assert result.exit_code != 0
        # Should mention missing argument
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
        result = runner.invoke(app, ["validate", "", "--json"])

        # Output should be valid JSON, not rich console formatting
        try:
            output = json.loads(result.stdout)
            assert isinstance(output, dict)
            assert "success" in output
        except json.JSONDecodeError:
            pytest.fail(f"JSON mode should produce valid JSON output: {result.stdout}")

    def test_error_message_includes_examples(self):
        """Test that error message includes helpful format examples."""
        result = runner.invoke(app, ["validate", "", "--json"])

        try:
            output = json.loads(result.stdout)
            info_messages = output.get("info", [])

            # Should include examples of expected formats
            has_semver_example = any("v1.0.0" in msg for msg in info_messages)
            has_calver_example = any("2024.01.15" in msg for msg in info_messages)

            assert has_semver_example, "Should include SemVer example"
            assert has_calver_example, "Should include CalVer example"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestValidateTypeRequirements:
    """Test suite for validate command with type requirements."""

    def test_require_semver_with_semver_version(self):
        """Test that requiring SemVer passes with SemVer version."""
        result = runner.invoke(
            app, ["validate", "v1.0.0", "--require-type", "semver", "--json"]
        )

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "semver"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_require_semver_with_calver_version(self):
        """Test that requiring SemVer fails with CalVer version."""
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "semver", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Version type mismatch" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_require_calver_with_calver_version(self):
        """Test that requiring CalVer passes with CalVer version."""
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "calver", "--json"]
        )

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "calver"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_require_calver_with_semver_version(self):
        """Test that requiring CalVer fails with SemVer version."""
        result = runner.invoke(
            app, ["validate", "v1.0.0", "--require-type", "calver", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Version type mismatch" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_require_type_none_accepts_any_format(self):
        """Test that require-type=none accepts any format including invalid ones."""
        result = runner.invoke(
            app, ["validate", "invalid-123", "--require-type", "none", "--json"]
        )

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "other"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestValidateWithOptions:
    """Test suite for validate command with various options."""

    def test_empty_version_with_require_type_option(self):
        """Test empty version fails even with --require-type option."""
        result = runner.invoke(
            app, ["validate", "", "--require-type", "semver", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Version string is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_whitespace_version_with_multiple_options(self):
        """Test whitespace version fails with multiple options combined."""
        result = runner.invoke(
            app,
            [
                "validate",
                "  \t  ",
                "--require-type",
                "semver",
                "--strict-semver",
                "--json",
            ],
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Version string is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_strict_semver_mode(self):
        """Test strict SemVer mode with prefixed version."""
        result = runner.invoke(app, ["validate", "v1.0.0", "--strict-semver", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_type"] == "other"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_no_prefix_option(self):
        """Test --no-prefix option with prefixed version."""
        result = runner.invoke(app, ["validate", "v1.0.0", "--no-prefix", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["version_prefix"] is True
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestValidateOutputConsistency:
    """Test suite to ensure consistent output format between JSON and non-JSON modes."""

    def test_error_message_consistency(self):
        """Test that error message is consistent between JSON and non-JSON modes."""
        # Non-JSON mode
        result_non_json = runner.invoke(app, ["validate", ""])
        output_non_json = result_non_json.stdout

        # JSON mode
        result_json = runner.invoke(app, ["validate", "", "--json"])

        # Both should mention the same core error
        assert "Version string is empty or null" in output_non_json

        try:
            output_json = json.loads(result_json.stdout)
            assert "Version string is empty or null" in output_json["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result_json.stdout}")

    def test_exit_codes_consistent(self):
        """Test that exit codes are consistent between JSON and non-JSON modes."""
        result_non_json = runner.invoke(app, ["validate", ""])
        result_json = runner.invoke(app, ["validate", "", "--json"])

        # Both should exit with non-zero code
        assert result_non_json.exit_code == 1
        assert result_json.exit_code == 1

    def test_success_exit_codes_consistent(self):
        """Test that success exit codes are consistent between modes."""
        result_non_json = runner.invoke(app, ["validate", "v1.0.0"])
        result_json = runner.invoke(app, ["validate", "v1.0.0", "--json"])

        # Both should exit with zero code on success
        assert result_non_json.exit_code == 0
        assert result_json.exit_code == 0


class TestValidateJSONOutput:
    """Test suite for JSON output format."""

    def test_json_output_contains_required_fields(self):
        """Test that JSON output contains all required fields."""
        result = runner.invoke(app, ["validate", "v1.0.0", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            # Check required fields
            assert "success" in output
            assert "version" in output
            assert "normalized" in output
            assert "version_type" in output
            assert "is_valid" in output
            assert "version_prefix" in output
            assert "development_tag" in output
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_json_output_semver_fields(self):
        """Test that SemVer versions include SemVer-specific fields."""
        result = runner.invoke(app, ["validate", "v1.2.3-beta.1+build.123", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["version_type"] == "semver"
            assert "major" in output
            assert "minor" in output
            assert "patch" in output
            assert "prerelease" in output
            assert "build_metadata" in output
            assert output["major"] == 1
            assert output["minor"] == 2
            assert output["patch"] == 3
            assert output["prerelease"] == "beta.1"
            assert output["build_metadata"] == "build.123"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_json_output_calver_fields(self):
        """Test that CalVer versions include CalVer-specific fields."""
        result = runner.invoke(app, ["validate", "2024.01.15", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["version_type"] == "calver"
            assert "year" in output
            assert "month" in output
            assert "day" in output
            assert output["year"] == 2024
            assert output["month"] == 1
            assert output["day"] == 15
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_json_output_includes_errors_on_failure(self):
        """Test that JSON output handles other type versions correctly."""
        result = runner.invoke(app, ["validate", "invalid-version", "--json"])

        assert result.exit_code == 0
        try:
            output = json.loads(result.stdout)
            assert output["success"] is True
            assert output["is_valid"] is True
            assert output["version_type"] == "other"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")
