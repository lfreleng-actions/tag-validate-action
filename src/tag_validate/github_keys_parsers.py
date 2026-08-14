# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
Parsing helpers for GitHub key API payloads.

Pure functions that turn raw GitHub REST responses into the typed key
models, plus the small utilities for SSH fingerprinting and expiry
checking. Keeping these free of client state makes them independently
testable and keeps the API client focused on transport.
"""

import logging
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from .models import GPGKeyInfo, SSHKeyInfo


def resolve_server_hostname(api_url: str) -> str:
    """Derive the display hostname for a GitHub API base URL.

    Args:
        api_url: Base URL for the GitHub REST API.

    Returns:
        Hostname used to describe the server (e.g. "github.com").
    """
    # Normalize scheme-less inputs (e.g. "api.github.com") so the host is
    # parsed from netloc rather than being treated as a path.
    normalized_url = api_url if "://" in api_url else f"https://{api_url}"
    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    if hostname == "api.github.com":
        return "github.com"

    # Extract host for GitHub Enterprise from netloc so any explicit
    # port is preserved (e.g. ghe.example.com:8443), stripping any
    # userinfo. Remove a leading 'api.' prefix if present
    # (e.g. api.github.example.com -> github.example.com).
    server = parsed.netloc.rsplit("@", 1)[-1]
    if server.startswith("api."):
        server = server[4:]
    return server


def _gpg_key_from_data(data: dict[str, Any], subkeys: list[GPGKeyInfo]) -> GPGKeyInfo:
    """Build a GPGKeyInfo from a raw GitHub GPG key payload."""
    return GPGKeyInfo(
        id=data.get("id", 0),
        key_id=data.get("key_id", ""),
        name=data.get("name"),
        primary_key_id=data.get("primary_key_id"),
        emails=[email["email"] for email in data.get("emails", []) if "email" in email],
        can_sign=data.get("can_sign", False),
        can_encrypt_comms=data.get("can_encrypt_comms", False),
        can_encrypt_storage=data.get("can_encrypt_storage", False),
        can_certify=data.get("can_certify", False),
        created_at=data.get("created_at", ""),
        expires_at=data.get("expires_at"),
        revoked=data.get("revoked", False),
        raw_key=data.get("raw_key"),
        subkeys=subkeys,
    )


def parse_gpg_subkeys(
    key_data: dict[str, Any], logger: logging.Logger
) -> list[GPGKeyInfo]:
    """Parse the subkeys of a GPG key payload, skipping malformed entries."""
    subkeys: list[GPGKeyInfo] = []
    for subkey_data in key_data.get("subkeys", []):
        try:
            # Subkeys don't have subkeys
            subkeys.append(_gpg_key_from_data(subkey_data, []))
        except Exception as e:
            logger.warning(f"Failed to parse GPG subkey data: {e}")
            continue
    return subkeys


def parse_gpg_keys(response: list[Any], logger: logging.Logger) -> list[GPGKeyInfo]:
    """Parse a GitHub GPG keys response, skipping malformed entries."""
    keys: list[GPGKeyInfo] = []
    for key_data in response:
        try:
            # Parse subkeys recursively
            subkeys = parse_gpg_subkeys(key_data, logger)
            keys.append(_gpg_key_from_data(key_data, subkeys))
        except Exception as e:
            logger.warning(f"Failed to parse GPG key data: {e}")
            continue
    return keys


def parse_ssh_keys(response: list[Any], logger: logging.Logger) -> list[SSHKeyInfo]:
    """Parse a GitHub SSH signing keys response, skipping malformed entries."""
    keys: list[SSHKeyInfo] = []
    for key_data in response:
        try:
            keys.append(
                SSHKeyInfo(
                    id=key_data.get("id", 0),
                    key=key_data.get("key", ""),
                    title=key_data.get("title", ""),
                    created_at=key_data.get("created_at", ""),
                )
            )
        except Exception as e:
            logger.warning(f"Failed to parse SSH key data: {e}")
            continue
    return keys


def calculate_ssh_fingerprint(public_key: str, logger: logging.Logger) -> str | None:
    """Calculate SHA256 fingerprint for an SSH public key.

    Args:
        public_key: SSH public key string
        logger: Logger used to report failures.

    Returns:
        Fingerprint in format "SHA256:..." or None if calculation fails
    """
    try:
        # Write the public key to a temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pub", delete=False) as f:
            f.write(public_key.strip())
            temp_file = f.name

        try:
            # Use ssh-keygen to calculate fingerprint
            result = subprocess.run(
                ["ssh-keygen", "-lf", temp_file],
                capture_output=True,
                text=True,
                check=True,
            )

            # Parse output: "256 SHA256:fingerprint comment (TYPE)"
            output = result.stdout.strip()
            parts = output.split()
            for part in parts:
                if part.startswith("SHA256:"):
                    return part

            return None
        finally:
            # Clean up temp file
            os.unlink(temp_file)

    except Exception as e:
        logger.debug(f"Failed to calculate SSH fingerprint: {e}")
        return None


def is_key_expired(expires_at: str | None, logger: logging.Logger) -> bool | None:
    """
    Check if a key is expired based on its expiration timestamp.

    Args:
        expires_at: ISO 8601 expiration timestamp, or None if key doesn't expire.
        logger: Logger used to report parse failures.

    Returns:
        True if expired, False if not expired, None if no expiration date.
    """
    if not expires_at:
        return None

    try:
        expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        now = datetime.now(expiration.tzinfo)
        return now > expiration
    except Exception as e:
        logger.warning(f"Failed to parse expiration date {expires_at}: {e}")
        return None


__all__ = [
    "calculate_ssh_fingerprint",
    "is_key_expired",
    "parse_gpg_keys",
    "parse_gpg_subkeys",
    "parse_ssh_keys",
    "resolve_server_hostname",
]
