# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
GitHub Actions step summary output.

This module provides functionality to write validation results to
GITHUB_STEP_SUMMARY for display in GitHub Actions workflow runs.
"""

import os
from pathlib import Path

from .models import ValidationResult


def is_github_actions() -> bool:
    """
    Check if running in GitHub Actions environment.

    Returns:
        True if GITHUB_STEP_SUMMARY environment variable is set and writable
    """
    github_step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not github_step_summary:
        return False

    # Check if the file is writable
    summary_path = Path(github_step_summary)
    try:
        # Try to open in append mode to verify it's writable
        with summary_path.open("a"):
            pass
        return True
    except (OSError, PermissionError):
        return False


def write_validation_summary(result: ValidationResult, tag_name: str) -> None:
    """
    Write validation result to GitHub Actions step summary.

    This function appends a formatted markdown table to GITHUB_STEP_SUMMARY
    showing the comprehensive validation results.

    Args:
        result: ValidationResult object containing validation details
        tag_name: The tag name that was validated

    Returns:
        None. Silently fails if not in GitHub Actions environment.
    """
    if not is_github_actions():
        return

    github_step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if not github_step_summary:
        return

    summary_path = Path(github_step_summary)

    try:
        # Build markdown content
        markdown_lines = [
            "",
            "## 🏷️ Tag Validation Results",
            "",
        ]

        # Add overall validation status
        if result.is_valid:
            markdown_lines.append("### Overall Validation Result ✅")
        else:
            markdown_lines.append("### Overall Validation Result ❌")

        markdown_lines.append("")
        markdown_lines.append("| Property | Value |")
        markdown_lines.append("|----------|-------|")

        # Tag Name
        markdown_lines.append(f"| **Tag Name** | `{tag_name}` |")

        # Version Information
        if result.version_info:
            version_type = result.version_info.version_type or "unknown"
            markdown_lines.append(f"| **Tag Type** | `{version_type.upper()}` |")

            # Version components based on type
            if result.version_info.normalized:
                if version_type == "semver":
                    components = f"{result.version_info.major}.{result.version_info.minor}.{result.version_info.patch}"
                    if result.version_info.prerelease:
                        components += f"-{result.version_info.prerelease}"
                    if result.version_info.build_metadata:
                        components += f"+{result.version_info.build_metadata}"
                    markdown_lines.append(f"| **Version Components** | `{components}` |")
                elif version_type == "calver":
                    components_parts = []
                    if result.version_info.year:
                        components_parts.append(str(result.version_info.year))
                    if result.version_info.month:
                        components_parts.append(str(result.version_info.month).zfill(2))
                    if result.version_info.day:
                        components_parts.append(str(result.version_info.day).zfill(2))
                    if result.version_info.micro:
                        components_parts.append(str(result.version_info.micro))
                    if components_parts:
                        components = ".".join(components_parts)
                        markdown_lines.append(f"| **Version Components** | `{components}` |")

            markdown_lines.append(f"| **Development Tag** | `{str(result.version_info.is_development).lower()}` |")
            markdown_lines.append(f"| **Version Prefix** | `{str(result.version_info.has_prefix).lower()}` |")

        # Signature Information
        if result.signature_info:
            sig_type = result.signature_info.type or "unsigned"
            markdown_lines.append(f"| **Signature Type** | `{sig_type.upper()}` |")

            if result.signature_info.signer_email:
                markdown_lines.append(f"| **Signer Email** | `{result.signature_info.signer_email}` |")

            if result.signature_info.key_id:
                markdown_lines.append(f"| **Key ID** | `{result.signature_info.key_id}` |")

            if result.signature_info.fingerprint:
                markdown_lines.append(f"| **Fingerprint** | `{result.signature_info.fingerprint}` |")

            markdown_lines.append(f"| **Signature Verified** | `{str(result.signature_info.verified).lower()}` |")

        # Key verifications (GitHub and/or Gerrit from key_verifications list)
        if result.key_verifications:
            for verification in result.key_verifications:
                service_name = verification.service.capitalize()
                markdown_lines.append(f"| **{service_name} Registered** | `{str(verification.key_registered).lower()}` |")

                if verification.server:
                    markdown_lines.append(f"| **{service_name} Server** | `{verification.server}` |")

                if verification.username:
                    markdown_lines.append(f"| **{service_name} Username** | `{verification.username}` |")
                if verification.user_email:
                    markdown_lines.append(f"| **{service_name} Email** | `{verification.user_email}` |")
                if verification.user_name:
                    markdown_lines.append(f"| **{service_name} Name** | `{verification.user_name}` |")

        markdown_lines.append("")

        # Write to summary file
        with summary_path.open("a", encoding="utf-8") as f:
            f.write("\n".join(markdown_lines))

    except (OSError, PermissionError, IOError):
        # Silently fail if we can't write to the summary
        # Don't want to break the validation just because summary fails
        pass
