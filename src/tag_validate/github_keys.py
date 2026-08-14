# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
GitHub Keys API Client.

This module provides a high-level interface for interacting with GitHub's
user keys APIs (GPG and SSH signing keys). It leverages the GitHubAsync
client from dependamerge for robust API handling with rate limiting and
error recovery.

Key features:
- Fetch user GPG keys from GitHub API
- Fetch user SSH signing keys from GitHub API
- Verify if a specific key is registered to a user
- Get commit verification information from GitHub
- Automatic rate limit handling
- Comprehensive error handling

Supporting code lives in sibling modules:

- :mod:`tag_validate.github_keys_base` - configuration and connection
- :mod:`tag_validate.github_keys_parsers` - response parsing helpers
- :mod:`tag_validate.github_keys_lookup` - user and commit lookups
"""

import logging

from .github_keys_base import GitHubKeysClientBase, GitHubKeysError
from .github_keys_lookup import GitHubUserLookupMixin
from .github_keys_parsers import (
    calculate_ssh_fingerprint,
    is_key_expired,
    parse_gpg_keys,
    parse_ssh_keys,
)
from .models import (
    GitHubVerificationInfo,
    GPGKeyInfo,
    KeyVerificationResult,
    SSHKeyInfo,
)

logger = logging.getLogger(__name__)


class GitHubKeysClient(GitHubUserLookupMixin):
    """
    Client for GitHub user keys APIs.

    This client wraps the dependamerge GitHubAsync client to provide
    tag validation-specific operations for key verification.

    Example:
        >>> async with GitHubKeysClient(token="ghp_xxx") as client:
        ...     keys = await client.get_user_gpg_keys("octocat")
        ...     result = await client.verify_gpg_key_registered(
        ...         "octocat", "3262EFF25BA0D270"
        ...     )
    """

    async def get_user_gpg_keys(self, username: str) -> list[GPGKeyInfo]:
        """
        Get all GPG keys registered to a GitHub user.

        This uses the public API endpoint GET /users/{username}/gpg_keys
        which does not require authentication but respects rate limits.

        Args:
            username: GitHub username to look up keys for.

        Returns:
            List of GPGKeyInfo objects representing the user's registered keys.

        Raises:
            Exception: If the API request fails or user not found.

        Example:
            >>> keys = await client.get_user_gpg_keys("octocat")
            >>> for key in keys:
            ...     print(f"Key ID: {key.key_id}, Can Sign: {key.can_sign}")
        """
        client = self._ensure_client()

        self.logger.debug(f"Fetching GPG keys for user: {username}")

        try:
            response = await client.get(f"/users/{username}/gpg_keys")

            if not isinstance(response, list):
                self.logger.error(
                    f"Unexpected response type for GPG keys: {type(response)}"
                )
                return []

            keys = parse_gpg_keys(response, self.logger)
            self.logger.debug(f"Found {len(keys)} GPG keys for user {username}")
            return keys

        except Exception as e:
            self.logger.error(f"Failed to fetch GPG keys for {username}: {e}")
            raise

    async def get_user_ssh_keys(self, username: str) -> list[SSHKeyInfo]:
        """
        Get all SSH signing keys registered to a GitHub user.

        This uses the public API endpoint GET /users/{username}/ssh_signing_keys
        which does not require authentication but respects rate limits.

        Args:
            username: GitHub username to look up keys for.

        Returns:
            List of SSHKeyInfo objects representing the user's registered SSH keys.

        Raises:
            Exception: If the API request fails or user not found.

        Example:
            >>> keys = await client.get_user_ssh_keys("octocat")
            >>> for key in keys:
            ...     print(f"Title: {key.title}, Created: {key.created_at}")
        """
        client = self._ensure_client()

        self.logger.debug(f"Fetching SSH signing keys for user: {username}")

        try:
            response = await client.get(f"/users/{username}/ssh_signing_keys")

            if not isinstance(response, list):
                self.logger.error(
                    f"Unexpected response type for SSH keys: {type(response)}"
                )
                return []

            keys = parse_ssh_keys(response, self.logger)
            self.logger.debug(f"Found {len(keys)} SSH signing keys for user {username}")
            return keys

        except Exception as e:
            self.logger.error(f"Failed to fetch SSH keys for {username}: {e}")
            raise

    def _build_verification_result(
        self,
        username: str,
        key_info: GPGKeyInfo | SSHKeyInfo | None,
        user_details: dict | None,
        signer_email: str | None,
    ) -> KeyVerificationResult:
        """Assemble a KeyVerificationResult for a (possibly absent) key match."""
        return KeyVerificationResult(
            key_registered=key_info is not None,
            username=username,
            user_enumerated=False,
            key_info=key_info,
            service="github",
            server=self.server,
            user_name=user_details.get("name") if user_details else None,
            user_email=signer_email
            or (user_details.get("email") if user_details else None),
        )

    def _find_gpg_key(
        self,
        user_keys: list[GPGKeyInfo],
        normalized_key_id: str,
        check_subkeys: bool,
    ) -> GPGKeyInfo | None:
        """Find the primary key matching a normalized key ID, if any.

        A subkey match returns its primary key, matching GitHub's own
        presentation of the key that owns the signature.
        """
        for key in user_keys:
            # Check main key
            if key.key_id.replace(" ", "").upper() == normalized_key_id:
                return key

            # Check subkeys if enabled
            if not check_subkeys:
                continue
            for subkey in key.subkeys:
                if subkey.key_id.replace(" ", "").upper() == normalized_key_id:
                    self.logger.debug(
                        f"Found matching subkey {subkey.key_id} under primary key {key.key_id}"
                    )
                    # Return the primary key info, not the subkey
                    return key
        return None

    async def verify_gpg_key_registered(
        self,
        username: str,
        key_id: str,
        tagger_email: str | None = None,
        check_subkeys: bool = True,
        signer_email: str | None = None,
    ) -> KeyVerificationResult:
        """
        Verify if a specific GPG key is registered to a GitHub user.

        This fetches all the user's GPG keys and checks if the provided
        key ID matches any of them. Optionally verifies email matching.

        Args:
            username: GitHub username to check.
            key_id: GPG key ID to verify (e.g., "3262EFF25BA0D270").
            tagger_email: Optional email to verify against key emails.
            check_subkeys: Whether to check subkeys in addition to primary keys (default: True).
            signer_email: Email from the tag signature (used when GitHub API doesn't provide user email).

        Returns:
            KeyVerificationResult with verification details.

        Example:
            >>> result = await client.verify_gpg_key_registered(
            ...     "octocat", "3262EFF25BA0D270", "octocat@github.com"
            ... )
            >>> if result.key_registered:
            ...     print(f"Key belongs to {result.key_owner}")
        """
        self.logger.debug(f"Verifying GPG key {key_id} for user {username}")

        try:
            # Fetch user details
            user_details = await self.get_user_details(username)

            user_keys = await self.get_user_gpg_keys(username)

            # Normalize key_id for comparison (remove spaces, make uppercase)
            normalized_key_id = key_id.replace(" ", "").upper()

            matched = self._find_gpg_key(user_keys, normalized_key_id, check_subkeys)
            if matched is None:
                # Key not found
                self.logger.debug(f"GPG key {key_id} not registered to {username}")

            return self._build_verification_result(
                username=username,
                key_info=matched,
                user_details=user_details,
                signer_email=signer_email,
            )

        except Exception as e:
            self.logger.error(f"Error verifying GPG key: {e}")
            raise

    async def _find_ssh_key(
        self,
        user_keys: list[SSHKeyInfo],
        normalized_fp: str,
        is_fingerprint: bool,
    ) -> SSHKeyInfo | None:
        """Find the SSH key matching a fingerprint or full public key, if any."""
        for key in user_keys:
            if is_fingerprint:
                # Calculate fingerprint of the GitHub key and compare
                key_fingerprint = await self._calculate_ssh_fingerprint(key.key)
                if key_fingerprint and key_fingerprint == normalized_fp:
                    return key
            # Direct key comparison (if full public key provided)
            elif normalized_fp in key.key or key.key in normalized_fp:
                return key
        return None

    async def verify_ssh_key_registered(
        self,
        username: str,
        public_key_fingerprint: str,
        signer_email: str | None = None,
    ) -> KeyVerificationResult:
        """
        Verify if a specific SSH key is registered to a GitHub user.

        This fetches all the user's SSH signing keys and checks if the
        provided key fingerprint or public key matches any of them.

        Args:
            username: GitHub username to check.
            public_key_fingerprint: SSH key fingerprint or public key data to verify.
            signer_email: Email from the tag signature (used when GitHub API doesn't provide user email).

        Returns:
            KeyVerificationResult with verification details.

        Example:
            >>> result = await client.verify_ssh_key_registered(
            ...     "octocat", "SHA256:abcd1234..."
            ... )
            >>> if result.key_registered:
            ...     print(f"SSH key verified for {result.key_owner}")
        """
        self.logger.debug(f"Verifying SSH key for user {username}")

        try:
            # Fetch user details
            user_details = await self.get_user_details(username)

            user_keys = await self.get_user_ssh_keys(username)

            # Normalize fingerprint for comparison
            normalized_fp = public_key_fingerprint.strip()

            # Check if input is a fingerprint (starts with SHA256:) or a public key
            is_fingerprint = normalized_fp.startswith("SHA256:")

            matched = await self._find_ssh_key(user_keys, normalized_fp, is_fingerprint)
            if matched is None:
                # Key not found
                self.logger.debug(
                    f"SSH key with fingerprint {public_key_fingerprint} not registered to {username}"
                )

            return self._build_verification_result(
                username=username,
                key_info=matched,
                user_details=user_details,
                signer_email=signer_email,
            )

        except Exception as e:
            self.logger.error(f"Error verifying SSH key: {e}")
            raise

    async def _calculate_ssh_fingerprint(self, public_key: str) -> str | None:
        """Calculate SHA256 fingerprint for an SSH public key.

        Args:
            public_key: SSH public key string

        Returns:
            Fingerprint in format "SHA256:..." or None if calculation fails
        """
        return calculate_ssh_fingerprint(public_key, self.logger)

    def _is_key_expired(self, expires_at: str | None) -> bool | None:
        """
        Check if a key is expired based on its expiration timestamp.

        Args:
            expires_at: ISO 8601 expiration timestamp, or None if key doesn't expire.

        Returns:
            True if expired, False if not expired, None if no expiration date.
        """
        return is_key_expired(expires_at, self.logger)


__all__ = [
    "GitHubKeysClient",
    "GitHubKeysClientBase",
    "GitHubKeysError",
    "GitHubVerificationInfo",
    "GPGKeyInfo",
    "KeyVerificationResult",
    "SSHKeyInfo",
]
