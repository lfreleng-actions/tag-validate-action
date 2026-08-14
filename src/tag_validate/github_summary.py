# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
GitHub Actions step summary output.

This module provides functionality to write validation results to
GITHUB_STEP_SUMMARY for display in GitHub Actions workflow runs.
"""

import os
from pathlib import Path

from .models import (
    BranchCheckInfo,
    IncrementCheckInfo,
    KeyVerificationResult,
    LatestCheckInfo,
    SignatureInfo,
    TagAgeCheckInfo,
    ValidationResult,
    VersionInfo,
)


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


def _version_component_rows(version_info: VersionInfo, version_type: str) -> list[str]:
    """Build the version component row for a parsed version, if any."""
    if not version_info.normalized:
        return []

    if version_type == "semver":
        components = f"{version_info.major}.{version_info.minor}.{version_info.patch}"
        if version_info.prerelease:
            components += f"-{version_info.prerelease}"
        if version_info.build_metadata:
            components += f"+{version_info.build_metadata}"
        return [f"| **Version Components** | `{components}` |"]

    if version_type == "calver":
        components_parts = []
        if version_info.year:
            components_parts.append(str(version_info.year))
        if version_info.month:
            components_parts.append(str(version_info.month).zfill(2))
        if version_info.day:
            components_parts.append(str(version_info.day).zfill(2))
        if version_info.micro:
            components_parts.append(str(version_info.micro))
        if components_parts:
            components = ".".join(components_parts)
            return [f"| **Version Components** | `{components}` |"]

    return []


def _version_rows(version_info: VersionInfo) -> list[str]:
    """Build the version information rows."""
    version_type = version_info.version_type or "unknown"
    rows = [f"| **Tag Type** | `{version_type.upper()}` |"]
    rows.extend(_version_component_rows(version_info, version_type))
    rows.append(
        f"| **Development Tag** | `{str(version_info.is_development).lower()}` |"
    )
    rows.append(f"| **Version Prefix** | `{str(version_info.has_prefix).lower()}` |")
    return rows


def _signature_rows(signature_info: SignatureInfo) -> list[str]:
    """Build the signature information rows."""
    sig_type = signature_info.type or "unsigned"
    rows = [f"| **Signature Type** | `{sig_type.upper()}` |"]

    if signature_info.signer_email:
        rows.append(f"| **Signer Email** | `{signature_info.signer_email}` |")
    if signature_info.key_id:
        rows.append(f"| **Key ID** | `{signature_info.key_id}` |")
    if signature_info.fingerprint:
        rows.append(f"| **Fingerprint** | `{signature_info.fingerprint}` |")

    rows.append(
        f"| **Signature Verified** | `{str(signature_info.verified).lower()}` |"
    )
    return rows


def _key_verification_rows(
    verifications: list[KeyVerificationResult],
) -> list[str]:
    """Build the key registry verification rows for every checked service."""
    rows: list[str] = []
    for verification in verifications:
        service_name = verification.service.capitalize()
        rows.append(
            f"| **{service_name} Registered** | `{str(verification.key_registered).lower()}` |"
        )
        if verification.server:
            rows.append(f"| **{service_name} Server** | `{verification.server}` |")
        if verification.username:
            rows.append(f"| **{service_name} Username** | `{verification.username}` |")
        if verification.user_email:
            rows.append(f"| **{service_name} Email** | `{verification.user_email}` |")
        if verification.user_name:
            rows.append(f"| **{service_name} Name** | `{verification.user_name}` |")
    return rows


def _increment_rows(increment_check: IncrementCheckInfo) -> list[str]:
    """Build the increment enforcement rows."""
    # Indeterminate (None) fails closed, so report it as false
    incremental = bool(increment_check.incremental)
    rows = [f"| **Incremental** | `{str(incremental).lower()}` |"]

    if len(increment_check.latest_tags) > 1:
        # Multi-scheme push: report each scheme's baseline
        for scheme, tag in sorted(increment_check.latest_tags.items()):
            rows.append(f"| **Latest Existing Tag ({scheme})** | `{tag}` |")
    elif increment_check.latest_tag:
        rows.append(f"| **Latest Existing Tag** | `{increment_check.latest_tag}` |")
    return rows


def _branch_rows(branch_check: BranchCheckInfo) -> list[str]:
    """Build the branch containment rows."""
    # Indeterminate (None) fails closed, so report it as false
    contains = bool(branch_check.contains)
    rows = [f"| **On Required Branch** | `{str(contains).lower()}` |"]
    if branch_check.branch:
        rows.append(f"| **Required Branch** | `{branch_check.branch}` |")
    return rows


def _age_rows(age_check: TagAgeCheckInfo) -> list[str]:
    """Build the tag age (freshness) rows."""
    # Indeterminate (None) fails closed, so report it as false
    recent = bool(age_check.recent)
    rows = [f"| **Recent** | `{str(recent).lower()}` |"]
    if age_check.max_age_minutes is not None:
        rows.append(
            f"| **Freshness Window** | `{age_check.max_age_minutes:g} minute(s)` |"
        )
    return rows


def _latest_rows(latest_check: LatestCheckInfo) -> list[str]:
    """Build the latest commit (branch tip) rows."""
    # Indeterminate (None) fails closed, so report it as false
    latest = bool(latest_check.latest)
    rows = [f"| **Latest Commit** | `{str(latest).lower()}` |"]
    if latest_check.branch:
        rows.append(f"| **Target Branch** | `{latest_check.branch}` |")
    return rows


def build_summary_markdown(result: ValidationResult, tag_name: str) -> list[str]:
    """
    Build the markdown lines describing a validation result.

    Args:
        result: ValidationResult object containing validation details
        tag_name: The tag name that was validated

    Returns:
        List of markdown lines, ready to be joined with newlines.
    """
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

    if result.version_info:
        markdown_lines.extend(_version_rows(result.version_info))
    if result.signature_info:
        markdown_lines.extend(_signature_rows(result.signature_info))
    if result.key_verifications:
        markdown_lines.extend(_key_verification_rows(result.key_verifications))
    if result.increment_check and result.increment_check.checked:
        markdown_lines.extend(_increment_rows(result.increment_check))
    if result.branch_check and result.branch_check.checked:
        markdown_lines.extend(_branch_rows(result.branch_check))
    if result.age_check and result.age_check.checked:
        markdown_lines.extend(_age_rows(result.age_check))
    if result.latest_check and result.latest_check.checked:
        markdown_lines.extend(_latest_rows(result.latest_check))

    markdown_lines.append("")
    return markdown_lines


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
        markdown_lines = build_summary_markdown(result, tag_name)

        # Write to summary file
        with summary_path.open("a", encoding="utf-8") as f:
            f.write("\n".join(markdown_lines))

    except (OSError, PermissionError):
        # Silently fail if we can't write to the summary
        # Don't want to break the validation just because summary fails
        pass
