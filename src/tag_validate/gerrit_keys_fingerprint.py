# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
SSH fingerprint helpers for Gerrit key verification.

Pure functions for normalizing user-supplied fingerprints and deriving a
SHA256 fingerprint from a registered SSH public key, so both sides of a
comparison end up in the same format.
"""

import base64
import hashlib
import logging

# Prefixes stripped from user-supplied fingerprints before comparison.
_FINGERPRINT_PREFIXES = ("sha256:", "md5:", "ssh-")


def normalize_ssh_fingerprint(fingerprint: str) -> str:
    """
    Normalize SSH fingerprint to consistent format.

    Args:
        fingerprint: Raw SSH fingerprint

    Returns:
        Normalized fingerprint (lowercase, no prefixes)
    """
    # Remove common prefixes and make lowercase
    normalized = fingerprint.lower()
    for prefix in _FINGERPRINT_PREFIXES:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]

    # Remove any colons or spaces
    normalized = normalized.replace(":", "").replace(" ", "")

    return normalized


def calculate_ssh_fingerprint(public_key: str, logger: logging.Logger) -> str:
    """
    Calculate SSH fingerprint from public key.

    Args:
        public_key: SSH public key string
        logger: Logger used to report failures.

    Returns:
        SHA256 fingerprint (base64 encoded without padding)
    """
    try:
        # Split the key into parts
        parts = public_key.strip().split()
        if len(parts) < 2:
            return ""

        # Get the key data (second part)
        key_data = parts[1]

        # Decode base64 key data
        key_bytes = base64.b64decode(key_data)

        # Calculate SHA256 hash
        sha256_hash = hashlib.sha256(key_bytes).digest()

        # Encode as base64 and remove padding
        fingerprint = base64.b64encode(sha256_hash).decode("ascii")
        fingerprint = fingerprint.rstrip("=")

        return fingerprint.lower()

    except Exception as e:
        logger.warning(f"Failed to calculate SSH fingerprint: {e}")
        return ""


__all__ = ["calculate_ssh_fingerprint", "normalize_ssh_fingerprint"]
