# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Rich rendering helpers for the tag-validate command-line interface.

This module turns signature, key verification, validation and version
results into the tables and panels printed by the CLI commands.
"""

from typing import Any, Literal, cast

from rich.panel import Panel
from rich.table import Table

from .cli_runtime import console
from .display_utils import format_server_display, format_user_details
from .models import KeyVerificationResult, SignatureInfo
from .workflow import ValidationWorkflow

SIGNATURE_TYPE_DISPLAY = {
    "gpg": "GPG",
    "ssh": "SSH",
    "unsigned": "UNSIGNED",
    "lightweight": "LIGHTWEIGHT",
    "invalid": "INVALID (corrupted/tampered)",
    "gpg-unverifiable": "GPG (key not available)",
}

SIGNATURE_STATUS_DISPLAY = {
    "gpg-unverifiable": "⚠️  Key not available for verification",
    "invalid": "❌ Signature is corrupted or tampered",
    "unsigned": "No signature",
    "lightweight": "No signature",
}


def build_mock_signature(key_id: str, detected_type: str) -> SignatureInfo:
    """Build a placeholder SignatureInfo used to render key lookups.

    The ``github`` and ``gerrit`` commands check key registration only,
    so there is no real signature to display; this synthesises one that
    carries the key identifier the user supplied.

    Args:
        key_id: GPG key ID or SSH fingerprint supplied on the CLI
        detected_type: Resolved key type ("gpg" or "ssh")

    Returns:
        SignatureInfo suitable for display purposes
    """
    return SignatureInfo(
        type=cast(
            Literal[
                "gpg",
                "ssh",
                "unsigned",
                "lightweight",
                "invalid",
                "gpg-unverifiable",
            ],
            detected_type,
        ),
        verified=True,  # We're not verifying a signature, just checking registration
        key_id=key_id if detected_type == "gpg" else None,
        fingerprint=key_id if detected_type == "ssh" else None,
        signer_email=None,
        signature_data=None,
    )


def display_signature_info(signature_info: Any, tag_name: str) -> None:
    """Display signature information in a formatted table."""
    table = Table(title=f"Signature Information for Tag: {tag_name}")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    # Display signature type with friendly names
    sig_type = SIGNATURE_TYPE_DISPLAY.get(
        signature_info.type, signature_info.type.upper()
    )
    table.add_row("Signature Type", sig_type)

    # Display verification status
    status = SIGNATURE_STATUS_DISPLAY.get(signature_info.type)
    if status:
        table.add_row("Status", status)

    if signature_info.signer_email:
        table.add_row("Signer", signature_info.signer_email)

    if signature_info.key_id:
        table.add_row("Key ID", signature_info.key_id)

    if signature_info.fingerprint:
        table.add_row("Fingerprint", signature_info.fingerprint)

    console.print(table)


def _verification_user_section(
    owner: str,
    platform: str,
    account: Any,
    github_user_details: Any,
) -> str:
    """Build the user information block for a key verification panel."""
    # Build user information display using shared utility
    if platform == "Gerrit" and account:
        user_lines = format_user_details(
            username=account.username, email=account.email, name=account.name
        )
    elif platform == "GitHub" and github_user_details:
        user_lines = format_user_details(
            username=github_user_details.get("login"),
            email=github_user_details.get("email"),
            name=github_user_details.get("name"),
        )
    else:
        user_lines = []

    return "\n".join(user_lines) if user_lines else f"  • {platform} User: {owner}"


def _verification_details_section(signature_info: Any) -> str:
    """Build the signature details block for a key verification panel."""
    # Build details section - only show fields that have values
    details_lines = [f"  • Signature Type: {signature_info.type}"]
    if signature_info.key_id:
        details_lines.append(f"  • Key ID: {signature_info.key_id}")
    if signature_info.fingerprint:
        details_lines.append(f"  • Fingerprint: {signature_info.fingerprint}")
    if signature_info.signer_email:
        details_lines.append(f"  • Signer: {signature_info.signer_email}")
    return "\n".join(details_lines)


def display_verification_result(
    verification: KeyVerificationResult,
    signature_info: Any,
    owner: str,
    platform: str = "GitHub",
    account: Any = None,
    github_user_details: Any = None,
) -> None:
    """
    Display key verification result in a formatted panel.

    Args:
        verification: Key verification result from GitHub or Gerrit
        signature_info: Signature information
        owner: Username or email of the key owner
        platform: Platform name ("GitHub" or "Gerrit")
        account: Optional GerritAccountInfo for Gerrit platform
        github_user_details: Optional dict with GitHub user details
    """
    if verification.key_registered:
        panel_style = "green"
        status_icon = "✅"
        status_text = "REGISTERED"
    else:
        panel_style = "red"
        status_icon = "❌"
        status_text = "NOT REGISTERED"

    user_section = _verification_user_section(
        owner, platform, account, github_user_details
    )

    # Build server display using shared utility
    service = "gerrit" if platform == "Gerrit" else "github"
    server_line = format_server_display(service, verification.server)

    # Build content with optional server line
    content_parts = [f"[bold]{status_icon} {status_text}[/bold]"]

    if server_line:
        content_parts.append("")
        content_parts.append(server_line)

    content_parts.extend(
        [
            "",
            "[bold]Details:[/bold]",
            _verification_details_section(signature_info),
            "",
            f"[bold]{platform} User:[/bold]",
            user_section,
        ]
    )

    content = "\n".join(content_parts)

    panel = Panel(
        content.strip(),
        title="Key Verification Result",
        border_style=panel_style,
        padding=(1, 2),
    )
    console.print(panel)


def display_validation_result(result: Any, workflow: ValidationWorkflow) -> None:
    """Display complete validation result in a formatted panel."""
    # Create summary text
    summary = workflow.create_validation_summary(result)

    # Determine panel style
    if result.is_valid:
        panel_style = "green"
        title = f"✅ Tag Validation: {result.tag_name}"
    else:
        panel_style = "red"
        title = f"❌ Tag Validation: {result.tag_name}"

    panel = Panel(
        summary,
        title=title,
        border_style=panel_style,
        padding=(1, 2),
    )
    console.print(panel)


def _add_semver_rows(table: Table, version_info: Any) -> None:
    """Add SemVer component rows to the version information table."""
    table.add_row("Major", str(version_info.major))
    table.add_row("Minor", str(version_info.minor))
    table.add_row("Patch", str(version_info.patch))
    if version_info.prerelease:
        table.add_row("Prerelease", version_info.prerelease)
    if version_info.build_metadata:
        table.add_row("Build Metadata", version_info.build_metadata)


def _add_calver_rows(table: Table, version_info: Any) -> None:
    """Add CalVer component rows to the version information table."""
    table.add_row("Year", str(version_info.year))
    table.add_row("Month", str(version_info.month))
    if version_info.day:
        table.add_row("Day", str(version_info.day))
    if version_info.micro:
        table.add_row("Micro", str(version_info.micro))
    if version_info.modifier:
        table.add_row("Modifier", version_info.modifier)


def display_version_info(version_info: Any, version_string: str) -> None:
    """Display version validation information in a formatted table."""
    if version_info.is_valid:
        title_style = "green"
        title = f"✅ Valid {version_info.version_type.upper()}: {version_string}"
    else:
        title_style = "red"
        title = f"❌ Invalid Version: {version_string}"

    table = Table(title=title, title_style=title_style)
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    table.add_row("Original", version_info.raw)

    if version_info.normalized:
        table.add_row("Normalized", version_info.normalized)

    table.add_row("Version Type", version_info.version_type.upper())
    table.add_row("Valid", "✅ Yes" if version_info.is_valid else "❌ No")
    table.add_row("Has Prefix", "✅ Yes" if version_info.has_prefix else "❌ No")
    table.add_row("Development", "✅ Yes" if version_info.is_development else "❌ No")

    # Add type-specific components
    if version_info.version_type == "semver" and version_info.is_valid:
        _add_semver_rows(table, version_info)
    elif version_info.version_type == "calver" and version_info.is_valid:
        _add_calver_rows(table, version_info)

    console.print(table)

    # Display errors if any
    if version_info.errors:
        console.print("\n[bold red]Errors:[/bold red]")
        for error in version_info.errors:
            console.print(f"  • {error}", style="red")
