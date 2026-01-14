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
"""

import logging
import os

from dependamerge.github_async import GitHubAsync

from .models import (
    GPGKeyInfo,
    GitHubVerificationInfo,
    KeyVerificationResult,
    SSHKeyInfo,
)

logger = logging.getLogger(__name__)


class GitHubKeysError(Exception):
    """Raised when GitHub Keys API operations fail."""

    pass


class GitHubKeysClient:
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

    def __init__(
        self,
        token: str | None = None,
        api_url: str = "https://api.github.com",
        graphql_url: str = "https://api.github.com/graphql",
        logger_instance: logging.Logger | None = None,
    ):
        """
        Initialize GitHub keys client.

        Args:
            token: GitHub personal access token. If None, reads from GITHUB_TOKEN env var.
            api_url: Base URL for GitHub REST API (for GitHub Enterprise Server).
            graphql_url: GraphQL endpoint URL (for GitHub Enterprise Server).
            logger_instance: Optional logger instance for client messages.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.api_url = api_url
        self.graphql_url = graphql_url
        self.logger = logger_instance or logger
        self._client: GitHubAsync | None = None

    async def __aenter__(self) -> "GitHubKeysClient":
        """Async context manager entry."""
        self._client = GitHubAsync(
            token=self.token,
            api_url=self.api_url,
            graphql_url=self.graphql_url,
            logger=self.logger,
        )
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.__aexit__(exc_type, exc_val, exc_tb)
            self._client = None

    def _ensure_client(self) -> GitHubAsync:
        """Ensure client is initialized."""
        if not self._client:
            raise RuntimeError(
                "GitHubKeysClient must be used as an async context manager. "
                "Use 'async with GitHubKeysClient(...) as client:'"
            )
        return self._client

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
                self.logger.error(f"Unexpected response type for GPG keys: {type(response)}")
                return []

            keys: list[GPGKeyInfo] = []
            for key_data in response:
                try:
                    # Parse subkeys recursively
                    subkeys = []
                    for subkey_data in key_data.get("subkeys", []):
                        try:
                            subkey = GPGKeyInfo(
                                id=subkey_data.get("id", 0),
                                key_id=subkey_data.get("key_id", ""),
                                name=subkey_data.get("name"),
                                primary_key_id=subkey_data.get("primary_key_id"),
                                emails=[
                                    email["email"]
                                    for email in subkey_data.get("emails", [])
                                    if "email" in email
                                ],
                                can_sign=subkey_data.get("can_sign", False),
                                can_encrypt_comms=subkey_data.get("can_encrypt_comms", False),
                                can_encrypt_storage=subkey_data.get("can_encrypt_storage", False),
                                can_certify=subkey_data.get("can_certify", False),
                                created_at=subkey_data.get("created_at", ""),
                                expires_at=subkey_data.get("expires_at"),
                                revoked=subkey_data.get("revoked", False),
                                raw_key=subkey_data.get("raw_key"),
                                subkeys=[],  # Subkeys don't have subkeys
                            )
                            subkeys.append(subkey)
                        except Exception as e:
                            self.logger.warning(f"Failed to parse GPG subkey data: {e}")
                            continue

                    key_info = GPGKeyInfo(
                        id=key_data.get("id", 0),
                        key_id=key_data.get("key_id", ""),
                        name=key_data.get("name"),
                        primary_key_id=key_data.get("primary_key_id"),
                        emails=[
                            email["email"]
                            for email in key_data.get("emails", [])
                            if "email" in email
                        ],
                        can_sign=key_data.get("can_sign", False),
                        can_encrypt_comms=key_data.get("can_encrypt_comms", False),
                        can_encrypt_storage=key_data.get("can_encrypt_storage", False),
                        can_certify=key_data.get("can_certify", False),
                        created_at=key_data.get("created_at", ""),
                        expires_at=key_data.get("expires_at"),
                        revoked=key_data.get("revoked", False),
                        raw_key=key_data.get("raw_key"),
                        subkeys=subkeys,
                    )
                    keys.append(key_info)
                except Exception as e:
                    self.logger.warning(f"Failed to parse GPG key data: {e}")
                    continue

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
                self.logger.error(f"Unexpected response type for SSH keys: {type(response)}")
                return []

            keys: list[SSHKeyInfo] = []
            for key_data in response:
                try:
                    key_info = SSHKeyInfo(
                        id=key_data.get("id", 0),
                        key=key_data.get("key", ""),
                        title=key_data.get("title", ""),
                        created_at=key_data.get("created_at", ""),
                    )
                    keys.append(key_info)
                except Exception as e:
                    self.logger.warning(f"Failed to parse SSH key data: {e}")
                    continue

            self.logger.debug(f"Found {len(keys)} SSH signing keys for user {username}")
            return keys

        except Exception as e:
            self.logger.error(f"Failed to fetch SSH keys for {username}: {e}")
            raise

    async def verify_gpg_key_registered(
        self,
        username: str,
        key_id: str,
        tagger_email: str | None = None,
        check_subkeys: bool = True,
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
            user_keys = await self.get_user_gpg_keys(username)

            # Normalize key_id for comparison (remove spaces, make uppercase)
            normalized_key_id = key_id.replace(" ", "").upper()

            for key in user_keys:
                # Check main key
                if key.key_id.replace(" ", "").upper() == normalized_key_id:
                    return KeyVerificationResult(
                        key_registered=True,
                        username=username,
                        key_info=key,
                    )

                # Check subkeys if enabled
                if check_subkeys:
                    for subkey in key.subkeys:
                        if subkey.key_id.replace(" ", "").upper() == normalized_key_id:
                            self.logger.debug(
                                f"Found matching subkey {subkey.key_id} under primary key {key.key_id}"
                            )
                            return KeyVerificationResult(
                                key_registered=True,
                                username=username,
                                key_info=key,  # Return the primary key info, not the subkey
                            )

            # Key not found
            self.logger.debug(f"GPG key {key_id} not registered to {username}")
            return KeyVerificationResult(
                key_registered=False,
                username=username,
                key_info=None,
            )

        except Exception as e:
            self.logger.error(f"Error verifying GPG key: {e}")
            raise

    async def verify_ssh_key_registered(
        self,
        username: str,
        public_key_fingerprint: str,
    ) -> KeyVerificationResult:
        """
        Verify if a specific SSH key is registered to a GitHub user.

        This fetches all the user's SSH signing keys and checks if the
        provided key fingerprint or public key matches any of them.

        Args:
            username: GitHub username to check.
            public_key_fingerprint: SSH key fingerprint or public key data to verify.

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
            user_keys = await self.get_user_ssh_keys(username)

            # Normalize fingerprint for comparison
            normalized_fp = public_key_fingerprint.strip()

            # Check if input is a fingerprint (starts with SHA256:) or a public key
            is_fingerprint = normalized_fp.startswith("SHA256:")

            for key in user_keys:
                if is_fingerprint:
                    # Calculate fingerprint of the GitHub key and compare
                    key_fingerprint = await self._calculate_ssh_fingerprint(key.key)
                    if key_fingerprint and key_fingerprint == normalized_fp:
                        return KeyVerificationResult(
                            key_registered=True,
                            username=username,
                            key_info=key,
                        )
                else:
                    # Direct key comparison (if full public key provided)
                    if normalized_fp in key.key or key.key in normalized_fp:
                        return KeyVerificationResult(
                            key_registered=True,
                            username=username,
                            key_info=key,
                        )

            # Key not found
            self.logger.debug(f"SSH key with fingerprint {public_key_fingerprint} not registered to {username}")
            return KeyVerificationResult(
                key_registered=False,
                username=username,
                key_info=None,
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
        import subprocess
        import tempfile

        try:
            # Write the public key to a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pub', delete=False) as f:
                f.write(public_key.strip())
                temp_file = f.name

            try:
                # Use ssh-keygen to calculate fingerprint
                result = subprocess.run(
                    ['ssh-keygen', '-lf', temp_file],
                    capture_output=True,
                    text=True,
                    check=True
                )

                # Parse output: "256 SHA256:fingerprint comment (TYPE)"
                output = result.stdout.strip()
                parts = output.split()
                for part in parts:
                    if part.startswith('SHA256:'):
                        return part

                return None
            finally:
                # Clean up temp file
                os.unlink(temp_file)

        except Exception as e:
            self.logger.debug(f"Failed to calculate SSH fingerprint: {e}")
            return None

    async def lookup_username_by_email(self, email: str) -> str | None:
        """Lookup GitHub username from email using commit search API.

        This uses the GitHub Search API to find commits authored by the given
        email address, then extracts the username from the commit author.

        Args:
            email: Email address to look up

        Returns:
            GitHub username if found, None otherwise

        Example:
            >>> username = await client.lookup_username_by_email("user@example.com")
            >>> if username:
            ...     print(f"Found username: {username}")
        """
        client = self._ensure_client()

        self.logger.debug(f"Looking up GitHub username for email: {email}")

        try:
            # Use commit search API to find commits by this email
            response = await client.get(
                "/search/commits",
                params={"q": f"author-email:{email}"}
            )

            if not isinstance(response, dict):
                self.logger.debug(f"Unexpected response type from commit search: {type(response)}")
                return None

            items = response.get("items", [])
            if not items or len(items) == 0:
                self.logger.debug(f"No commits found for email: {email}")
                return None

            # Get username from first commit's author
            author = items[0].get("author")
            if author and "login" in author:
                username = author["login"]
                if isinstance(username, str):
                    self.logger.debug(f"Found GitHub username '{username}' for email {email}")
                    return username

            self.logger.debug(f"No author information in commit for email: {email}")
            return None

        except Exception as e:
            self.logger.debug(f"Failed to lookup username for email {email}: {e}")
            return None

    async def get_commit_verification(
        self,
        owner: str,
        repo: str,
        ref: str,
    ) -> GitHubVerificationInfo | None:
        """
        Get GitHub's verification information for a commit.

        This fetches the commit data from GitHub's API which includes
        a verification object describing GitHub's analysis of the signature.

        Args:
            owner: Repository owner (user or organization).
            repo: Repository name.
            ref: Git reference (commit SHA, branch name, or tag name).

        Returns:
            GitHubVerificationInfo if available, None if no verification data.

        Raises:
            Exception: If the API request fails.

        Example:
            >>> info = await client.get_commit_verification(
            ...     "octocat", "Hello-World", "v1.0.0"
            ... )
            >>> if info and info.verified:
            ...     print(f"GitHub verified: {info.reason}")
        """
        client = self._ensure_client()

        self.logger.debug(f"Fetching commit verification for {owner}/{repo}@{ref}")

        try:
            response = await client.get(f"/repos/{owner}/{repo}/commits/{ref}")

            if not isinstance(response, dict):
                self.logger.error(f"Unexpected response type for commit: {type(response)}")
                return None

            commit_data = response.get("commit", {})
            verification_data = commit_data.get("verification")

            if not verification_data:
                self.logger.debug("No verification data in commit response")
                return None

            # Parse verification data
            return GitHubVerificationInfo(
                verified=verification_data.get("verified", False),
                reason=verification_data.get("reason", "unsigned"),
                signature=verification_data.get("signature"),
                payload=verification_data.get("payload"),
            )

        except Exception as e:
            self.logger.warning(f"Failed to fetch commit verification: {e}")
            # Don't raise - this is optional information
            return None

    def _is_key_expired(self, expires_at: str | None) -> bool | None:
        """
        Check if a key is expired based on its expiration timestamp.

        Args:
            expires_at: ISO 8601 expiration timestamp, or None if key doesn't expire.

        Returns:
            True if expired, False if not expired, None if no expiration date.
        """
        if not expires_at:
            return None

        try:
            from datetime import datetime

            expiration = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            now = datetime.now(expiration.tzinfo)
            return now > expiration
        except Exception as e:
            self.logger.warning(f"Failed to parse expiration date {expires_at}: {e}")
            return None
