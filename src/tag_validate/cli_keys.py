# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Key identifier helpers for the tag-validate command-line interface.

This module normalizes SSH fingerprints, detects whether a key
identifier is a GPG key ID or an SSH fingerprint, and resolves GitHub
owners supplied as email addresses to usernames.
"""

import base64
import binascii
import re

# SSH public key algorithm prefixes recognised for key type detection
SSH_KEY_PREFIXES = [
    "ssh-rsa",
    "ssh-dss",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
]

SHA256_FINGERPRINT_PATTERN = r"^SHA256:([A-Za-z0-9+/]{43}=?|[A-Za-z0-9+/]{44})$"
MD5_FINGERPRINT_PATTERN = r"^MD5:([0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}$"


def _validate_sha256_fingerprint(normalized: str) -> None:
    """Validate a SHA256 SSH fingerprint that failed the strict pattern.

    Args:
        normalized: Fingerprint beginning with the ``SHA256:`` prefix

    Raises:
        ValueError: If the fingerprint is empty, not valid Base64, or does
            not decode to 32 bytes
    """
    # Check if it's just empty hash
    if normalized.upper() == "SHA256:":
        raise ValueError("SHA256 fingerprint cannot be empty")
    # Check if it contains invalid Base64 characters
    hash_part = normalized[7:]  # Remove "SHA256:" prefix
    if not hash_part:
        raise ValueError("SHA256 fingerprint cannot be empty")
    try:
        # Validate Base64 format (SHA256 hash should be 32 bytes = 43-44 chars
        # in base64). Add only the padding the value is missing: an
        # unconditional "==" makes correctly padded input invalid, and
        # rejects over-padded input on some Python versions but not others.
        padding = "=" * (-len(hash_part) % 4)
        decoded = base64.b64decode(hash_part + padding, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            f"SHA256 fingerprint contains invalid Base64 characters: {hash_part}"
        ) from exc

    # Kept outside the try: a length fault is not an encoding fault, and
    # reporting it as one sends the user looking for the wrong problem.
    if len(decoded) != 32:
        raise ValueError(
            f"SHA256 fingerprint has invalid length: expected 32 bytes, got {len(decoded)}"
        )


def _validate_md5_fingerprint(normalized: str) -> None:
    """Validate an MD5 SSH fingerprint that failed the strict pattern.

    Args:
        normalized: Fingerprint beginning with the ``MD5:`` prefix

    Raises:
        ValueError: If the fingerprint is empty or malformed
    """
    # Check if it's just empty hash
    if normalized.upper() == "MD5:":
        raise ValueError("MD5 fingerprint cannot be empty")
    # More detailed validation
    hash_part = normalized[4:]  # Remove "MD5:" prefix
    if not hash_part:
        raise ValueError("MD5 fingerprint cannot be empty")
    # Should be exactly 47 characters: 16 hex pairs separated by colons
    if len(hash_part) != 47:
        raise ValueError(
            f"MD5 fingerprint has invalid length: expected 47 characters, got {len(hash_part)}"
        )
    # Check format with colons
    hex_parts = hash_part.split(":")
    if len(hex_parts) != 16:
        raise ValueError(
            f"MD5 fingerprint should have 16 hex pairs separated by colons, got {len(hex_parts)}"
        )
    # Validate each hex pair
    for i, part in enumerate(hex_parts):
        if len(part) != 2:
            raise ValueError(
                f"MD5 fingerprint hex pair {i + 1} has invalid length: expected 2 characters, got {len(part)}"
            )
        if not re.match(r"^[0-9a-fA-F]{2}$", part):
            raise ValueError(
                f"MD5 fingerprint contains invalid hex characters in pair {i + 1}: {part}"
            )


def normalize_ssh_fingerprint(key_id: str) -> str:
    """Normalize SSH key fingerprint by removing algorithm prefix and validate format.

    Args:
        key_id: SSH key fingerprint that may have algorithm prefix

    Returns:
        Normalized fingerprint (SHA256:... or original if not SSH)

    Raises:
        ValueError: If fingerprint format is invalid
    """
    # Remove common SSH algorithm prefixes
    key_lower = key_id.lower()
    normalized = key_id

    if "sha256:" in key_lower:
        # Extract just the SHA256: part
        sha_index = key_lower.find("sha256:")
        normalized = key_id[sha_index:]

        # Validate SHA256 format: SHA256:base64_string
        if not re.match(SHA256_FINGERPRINT_PATTERN, normalized, re.IGNORECASE):
            _validate_sha256_fingerprint(normalized)

    elif "md5:" in key_lower:
        # Extract just the MD5: part
        md5_index = key_lower.find("md5:")
        normalized = key_id[md5_index:]

        # Validate MD5 format: MD5:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
        if not re.match(MD5_FINGERPRINT_PATTERN, normalized, re.IGNORECASE):
            _validate_md5_fingerprint(normalized)

    return normalized


def detect_key_type(key_id: str) -> str:
    """
    Detect key type (GPG or SSH) from the key string.

    Args:
        key_id: Key ID or fingerprint string

    Returns:
        "gpg", "ssh", or "unknown"
    """
    key_lower = key_id.lower().strip()

    # Check if it starts with SSH key type
    for prefix in SSH_KEY_PREFIXES:
        if key_lower.startswith(prefix):
            return "ssh"

    # Check for SSH fingerprint format (SHA256:... or MD5:...)
    if key_lower.startswith("sha256:") or key_lower.startswith("md5:"):
        return "ssh"

    # Check for SSH fingerprint with algorithm prefix (ECDSA:SHA256:, RSA:SHA256:, etc.)
    if "sha256:" in key_lower or "md5:" in key_lower:
        return "ssh"

    # GPG key patterns - typically hex strings
    # Remove spaces and check if it's a valid hex string
    key_clean = key_id.replace(" ", "").replace(":", "")

    # GPG key IDs are typically 8, 16, or 40 hex characters
    if len(key_clean) in [8, 16, 40] and all(
        c in "0123456789ABCDEFabcdef" for c in key_clean
    ):
        return "gpg"

    # If we can't determine, return unknown
    return "unknown"


async def resolve_owner_to_username(owner: str, github_token: str | None = None) -> str:
    """Resolve owner (email or username) to GitHub username.

    Args:
        owner: GitHub username or email address
        github_token: GitHub API token for email lookup

    Returns:
        GitHub username

    Raises:
        ValueError: If email lookup fails or no token provided for email
    """
    # If it contains @, treat as email and lookup username
    if "@" in owner:
        if not github_token:
            raise ValueError(
                "GitHub token is required for email-to-username lookup. Set GITHUB_TOKEN environment variable or pass --token"
            )

        from .github_keys import GitHubKeysClient

        async with GitHubKeysClient(token=github_token) as client:
            username = await client.lookup_username_by_email(owner)
            if not username:
                raise ValueError(f"Could not find GitHub username for email: {owner}")
            return username
    else:
        # Already a username
        return owner
