# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Option parsing helpers for the tag-validate command-line interface.

This module parses multi-value CLI options, validates the version and
signature type names they carry, and normalizes tag locations supplied
in any of the supported local/remote formats.
"""

from pathlib import Path

import typer

from .cli_runtime import EXIT_INVALID_INPUT, console, logger

VALID_VERSION_TYPES = {"semver", "calver", "both", "none"}
VALID_SIGNATURE_TYPES = {"gpg", "ssh", "gpg-unverifiable", "unsigned"}


def parse_multi_value_option(value: str | None) -> list[str]:
    """Parse comma or space-separated values from an option.

    Args:
        value: Option value string (e.g., "gpg,ssh" or "gpg ssh")

    Returns:
        List of parsed values (lowercased and stripped)

    Examples:
        >>> parse_multi_value_option("gpg,ssh")
        ['gpg', 'ssh']
        >>> parse_multi_value_option("gpg ssh")
        ['gpg', 'ssh']
        >>> parse_multi_value_option(None)
        []
    """
    if not value:
        return []

    # Parse comma or space-separated values
    if "," in value:
        values = [v.strip().lower() for v in value.split(",") if v.strip()]
    else:
        values = [v.lower() for v in value.split() if v]

    return values


def validate_version_types(type_list: list[str]) -> None:
    """Validate version type names.

    Args:
        type_list: List of version type names

    Raises:
        typer.Exit: If invalid types are found
    """
    invalid_types = set(type_list) - VALID_VERSION_TYPES

    if invalid_types:
        console.print(f"[red]Invalid version type(s): {', '.join(invalid_types)}[/red]")
        console.print("Valid types: semver, calver, both, none")
        raise typer.Exit(EXIT_INVALID_INPUT)


def validate_signature_types(sig_list: list[str]) -> None:
    """Validate signature type names and combinations.

    Args:
        sig_list: List of signature type names

    Raises:
        typer.Exit: If invalid types or combinations are found
    """
    invalid_types = set(sig_list) - VALID_SIGNATURE_TYPES

    if invalid_types:
        console.print(
            f"[red]Invalid signature type(s): {', '.join(invalid_types)}[/red]"
        )
        console.print("Valid types: gpg, ssh, gpg-unverifiable, unsigned")
        raise typer.Exit(EXIT_INVALID_INPUT)

    # Check for invalid combinations
    if "unsigned" in sig_list and len(sig_list) > 1:
        console.print("[red]Cannot combine 'unsigned' with other signature types[/red]")
        raise typer.Exit(EXIT_INVALID_INPUT)


def check_version_type_match(version_type: str, required_types: list[str]) -> bool:
    """Check if version type matches required types.

    Handles "both" type which satisfies any semver or calver requirement.
    Handles "none" requirement which accepts any type.
    Handles "both" in requirements which accepts semver OR calver.

    Args:
        version_type: Detected version type (semver, calver, both, other)
        required_types: List of required types

    Returns:
        True if version type matches requirements
    """
    if not required_types:
        return True

    # "none" in requirements means accept any type
    if "none" in required_types:
        return True

    # "both" detected type satisfies any semver or calver requirement
    if version_type == "both":
        return True

    # "both" in requirements means accept semver OR calver (or both)
    if "both" in required_types and version_type in ("semver", "calver", "both"):
        return True

    # Single type must be in the required list
    return version_type in required_types


def _looks_like_local_repository(repo_path: str) -> bool:
    """Return True when ``repo_path`` resolves to a local Git repository."""
    # Try both relative to current dir and absolute
    for base_path in [Path("."), Path.cwd()]:
        test_path = base_path / repo_path
        if test_path.is_dir() and (test_path / ".git").exists():
            return True
    return False


def normalize_tag_location(tag_location: str) -> str:
    """Normalize tag location with smart path detection.

    Handles multiple input formats with pragmatic fallback:
    - owner/repo@tag (remote, already correct)
    - owner/repo/tag (remote if 2+ slashes, otherwise ambiguous)
    - https://github.com/owner/repo@tag (remote URL)
    - ./path/to/repo/tag or /path/to/repo/tag (local path)
    - path/to/repo/tag (ambiguous - check if local path exists, else treat as remote)
    - tag (local tag name)

    The normalization ensures that:
    1. Remote tags use @ separator (owner/repo@tag)
    2. Local paths are preserved for workflow to handle
    3. Ambiguous paths are passed through for smart detection

    Args:
        tag_location: The tag location in various formats

    Returns:
        str: Normalized tag location
    """
    # If already has @, return as-is (remote format)
    if "@" in tag_location:
        return tag_location

    # If it's a URL, return as-is (already validated by regex)
    if tag_location.startswith(("http://", "https://")):
        return tag_location

    # If it explicitly starts with ./ or /, it's definitely a local path
    if tag_location.startswith(("./", "/")):
        return tag_location

    # Count slashes to determine format
    slash_count = tag_location.count("/")

    # If 2+ slashes, likely owner/repo/tag format - convert to owner/repo@tag
    if slash_count >= 2:
        # Split into parts and convert last slash to @
        parts = tag_location.rsplit("/", 1)
        return f"{parts[0]}@{parts[1]}"

    # No slashes - it's a local tag name
    if slash_count != 1:
        return tag_location

    # If 1 slash, it's ambiguous (could be path/to/repo or partial path)
    # Check if it looks like a local path by testing if directory exists
    if _looks_like_local_repository(tag_location.rsplit("/", 1)[0]):
        # It's a local repository path - don't convert
        logger.debug(f"Detected local repository path: {tag_location}")
        return tag_location

    # Not a local path - could be owner/repo format but needs more slashes
    # Let it pass through as-is for workflow to handle
    logger.debug(f"Ambiguous path (no local repo found): {tag_location}")
    return tag_location


TAG_NOT_FOUND_PATTERNS = [
    "not found",
    "does not exist",
    "missing",
    "couldn't find",
    "failed to fetch",
    "failed to clone",
    "no such ref",
    "unknown revision",
    "bad revision",
]


def is_tag_not_found_error(error_message: str) -> bool:
    """Check if an error message indicates a missing tag.

    Args:
        error_message: The error message to check

    Returns:
        bool: True if the error indicates a missing tag
    """
    error_lower = error_message.lower()
    return any(pattern in error_lower for pattern in TAG_NOT_FOUND_PATTERNS)
