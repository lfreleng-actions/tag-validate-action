# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Gerrit Keys Client for Tag Validation.

This module provides a client for verifying cryptographic keys (GPG and SSH)
against Gerrit Code Review servers. It handles Gerrit server discovery,
account resolution, and key verification using the pygerrit2 library.

The client supports:
- Automatic Gerrit server discovery from GitHub organization names
- Account lookup by email address and username
- SSH key verification against registered keys
- GPG key verification against registered keys
- Fingerprint matching for both SSH and GPG keys
"""

import asyncio
import base64
import hashlib
import logging
import os
from typing import Any, Optional, cast

from pygerrit2 import GerritRestAPI, HTTPBasicAuth, Anonymous
from requests.exceptions import HTTPError

from .models import (
    GerritAccountInfo,
    GerritSSHKeyInfo,
    GerritGPGKeyInfo,
    KeyVerificationResult,
)

logger = logging.getLogger(__name__)


class GerritKeysError(Exception):
    """Base exception for Gerrit keys operations."""

    pass


class GerritServerError(Exception):
    """Raised when Gerrit server communication fails."""

    pass


class GerritKeysClient:
    """
    Client for Gerrit account and keys APIs.

    This client provides tag validation-specific operations for key
    verification against Gerrit Code Review servers. It handles automatic
    server discovery and supports both SSH and GPG key verification.

    Uses pygerrit2 library for reliable Gerrit REST API communication.

    Example:
        >>> async with GerritKeysClient(server="gerrit.onap.org") as client:
        ...     account = await client.lookup_account_by_email(
        ...         "user@example.com"
        ...     )
        ...     result = await client.verify_ssh_key_registered(
        ...         account.account_id, ssh_fingerprint
        ...     )
    """

    def __init__(
        self,
        server: Optional[str] = None,
        github_org: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 30.0,
        logger_instance: Optional[logging.Logger] = None,
    ):
        """
        Initialize Gerrit keys client.

        Args:
            server: Gerrit server hostname or URL. If None, will be
                auto-discovered from github_org.
            github_org: GitHub organization name for server discovery
                (e.g., "onap" -> "gerrit.onap.org").
            username: Gerrit username for HTTP authentication (optional).
            password: Gerrit HTTP password for authentication (optional,
                requires username).
            timeout: Request timeout in seconds.
            logger_instance: Optional logger instance for client messages.

        Raises:
            GerritKeysError: If neither server nor github_org is provided.
        """
        self.logger: logging.Logger = logger_instance or logger
        self.timeout: float = timeout

        # Determine which server we're connecting to
        if server:
            self.server = self._normalize_server_url(server)
        elif github_org:
            self.server = self._discover_server_from_github_org(github_org)
        else:
            raise GerritKeysError(
                "Either server or github_org must be provided"
            )

        # Get credentials from parameters or environment variables
        self.username: Optional[str] = (
            username or os.environ.get("GERRIT_USERNAME")
        )
        self.password: Optional[str] = (
            password or os.environ.get("GERRIT_PASSWORD")
        )

        self._rest: Optional[GerritRestAPI] = None
        self._base_url: str = ""

    async def __aenter__(self) -> "GerritKeysClient":
        """Async context manager entry."""
        # Determine base URL - try common Gerrit path patterns
        base_url = await self._discover_api_base_url()
        self._base_url = base_url

        # Configure authentication
        if self.username and self.password:
            auth = HTTPBasicAuth(self.username, self.password)
            self.logger.debug(
                f"Using HTTP Basic Auth for user: {self.username}"
            )
        else:
            auth = Anonymous()
            self.logger.debug("Using anonymous access (no authentication)")

        # Create pygerrit2 REST API client
        # Note: pygerrit2 automatically adds /a/ prefix when auth is used
        self._rest = GerritRestAPI(url=base_url, auth=auth)

        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        self._rest = None

    def _ensure_client(self) -> GerritRestAPI:
        """Ensure client is initialized."""
        if not self._rest:
            raise RuntimeError(
                "GerritKeysClient must be used as an async context manager. "
                "Use 'async with GerritKeysClient(...) as client:'"
            )
        return self._rest

    def _normalize_server_url(self, server: str) -> str:
        """
        Normalize server URL to just the hostname.

        Args:
            server: Server hostname or URL

        Returns:
            Normalized hostname
        """
        if server.startswith(("http://", "https://")):
            # Extract hostname from URL
            from urllib.parse import urlparse

            parsed = urlparse(server)
            return parsed.netloc
        return server

    def _discover_server_from_github_org(self, github_org: str) -> str:
        """
        Discover Gerrit server from GitHub organization name.

        Uses the pattern: [GITHUB_ORG] -> gerrit.[GITHUB_ORG].org

        Args:
            github_org: GitHub organization name

        Returns:
            Gerrit server hostname
        """
        return f"gerrit.{github_org}.org"

    async def _discover_api_base_url(self) -> str:
        """
        Discover the correct API base URL for the Gerrit server.

        Gerrit instances can be deployed with different path prefixes.
        This method tests common patterns to find the working API endpoint.

        Important: pygerrit2 automatically adds /a to URLs when auth is
        provided. For example:
        - Input: https://gerrit.onap.org/r + auth
        - Result: https://gerrit.onap.org/r/a/ (pygerrit2 adds /a)
        - Input: https://gerrit.onap.org/r + no auth
        - Result: https://gerrit.onap.org/r/ (no change)

        Common patterns:
        - https://host/r/ (most common, works with and without auth)
        - https://host/ (direct)
        - https://host/gerrit/ (OpenDaylight style)

        Returns:
            Working API base URL

        Raises:
            GerritServerError: If no working endpoint is found
        """
        self.logger.debug(
            f"Discovering API base URL for Gerrit server: {self.server}"
        )

        # Test common path patterns
        test_paths = [
            "/r",  # Standard: https://host/r/
            "/infra",  # Linux Foundation style: https://host/infra/
            "",  # Direct: https://host/
            "/gerrit",  # OpenDaylight style: https://host/gerrit/
        ]

        # Test each potential path by trying to access /projects endpoint
        for path in test_paths:
            base_url = f"https://{self.server}{path}"
            self.logger.debug(f"Testing API endpoint: {base_url}")

            try:
                # Create temporary client to test endpoint
                test_auth = Anonymous()
                test_rest = GerritRestAPI(url=base_url, auth=test_auth)

                # Try to list projects (minimal query)
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: test_rest.get("/projects/?d")
                )

                if isinstance(result, dict) and len(result) > 0:
                    self.logger.debug(
                        f"Discovered working API base URL: {base_url}"
                    )
                    return base_url
            except Exception as e:
                self.logger.debug(
                    f"Endpoint {base_url} failed: {e}"
                )
                continue

        # Default to /r/ if nothing works (most common pattern)
        default_url = f"https://{self.server}/r"
        self.logger.debug(
            f"Using default endpoint: {default_url}"
        )
        return default_url

    async def verify_connection(self) -> tuple[bool, Optional[str]]:
        """
        Verify that we can connect to the Gerrit server and authenticate.

        This should be called before attempting key verification operations
        to provide clear error messages about authentication issues.

        Returns:
            Tuple of (success: bool, error_message: Optional[str])
            - (True, None) if connection and auth successful
            - (False, error_msg) if connection or auth failed
        """
        rest = self._ensure_client()

        try:
            # Try to get the server version - this requires authentication
            # and is a lightweight check
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get("/config/server/version")
            )

            if result:
                self.logger.debug(f"Successfully connected to Gerrit server {self.server}")
                return (True, None)
            else:
                return (False, "Unable to retrieve server information")

        except HTTPError as e:
            status_code = getattr(e.response, "status_code", None)

            if status_code == 401:
                return (
                    False,
                    f"Authentication required for Gerrit server '{self.server}'. "
                    f"Please provide credentials via --gerrit-username and --gerrit-password options."
                )
            elif status_code == 403:
                return (
                    False,
                    f"Authentication failed for Gerrit server '{self.server}'. "
                    f"Please verify your Gerrit credentials are correct."
                )
            else:
                return (
                    False,
                    f"HTTP error {status_code} connecting to Gerrit server '{self.server}': {e}"
                )

        except Exception as e:
            self.logger.error(f"Error connecting to Gerrit server: {e}")
            return (
                False,
                f"Failed to connect to Gerrit server '{self.server}': {e}"
            )

    async def get_account_details(
        self, account_id: int
    ) -> Optional[GerritAccountInfo]:
        """
        Get detailed information about a Gerrit account.

        Args:
            account_id: Gerrit account ID

        Returns:
            GerritAccountInfo with full details, None if not found

        Raises:
            GerritServerError: If API request fails
        """
        rest = self._ensure_client()

        try:
            # Get account details with DETAILS option to get all fields
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get(f"/accounts/{account_id}?o=DETAILS")
            )

            if isinstance(result, dict):
                return GerritAccountInfo(
                    account_id=result.get("_account_id", account_id),
                    name=result.get("name"),
                    email=result.get("email"),
                    username=result.get("username"),
                    status=result.get("status", "ACTIVE"),
                )
            return None

        except HTTPError as e:
            status_code = getattr(e.response, "status_code", None)

            if status_code == 401:
                raise GerritServerError(
                    f"Authentication required to access account {account_id}. "
                    f"Please provide valid Gerrit credentials."
                )
            elif status_code == 403:
                raise GerritServerError(
                    f"Authentication failed or insufficient permissions to access account {account_id}."
                )
            elif status_code == 404:
                # 404 for account details just means account not found, return None
                return None
            else:
                self.logger.error(
                    f"HTTP error getting account details for ID {account_id}: {e}"
                )
                raise GerritServerError(
                    f"HTTP error {status_code} getting account details: {e}"
                ) from e

        except Exception as e:
            self.logger.error(
                f"Error getting account details for ID {account_id}: {e}"
            )
            raise GerritServerError(
                f"Failed to get account details: {e}"
            ) from e

    async def lookup_account_by_email(
        self, email: str
    ) -> Optional[GerritAccountInfo]:
        """
        Look up a Gerrit account by email address.

        Args:
            email: Email address to search for

        Returns:
            GerritAccountInfo if found, None otherwise

        Raises:
            GerritServerError: If API request fails
        """
        rest = self._ensure_client()

        try:
            # Use the accounts query API to find account ID
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get(f"/accounts/?q=email:{email}")
            )

            if isinstance(result, list) and len(result) > 0:
                account_id = result[0].get("_account_id", 0)
                # Fetch full account details
                return await self.get_account_details(account_id)
            return None

        except HTTPError as e:
            status_code = getattr(e.response, "status_code", None)

            if status_code == 401:
                raise GerritServerError(
                    f"Authentication required to search for account by email. "
                    f"Please provide valid Gerrit credentials."
                )
            elif status_code == 403:
                raise GerritServerError(
                    f"Authentication failed or insufficient permissions to search accounts."
                )
            else:
                self.logger.error(
                    f"HTTP error looking up account by email {email}: {e}"
                )
                raise GerritServerError(
                    f"HTTP error {status_code} looking up account: {e}"
                ) from e

        except Exception as e:
            self.logger.error(
                f"Error looking up account by email {email}: {e}"
            )
            raise GerritServerError(f"Failed to lookup account: {e}") from e

    async def lookup_account_by_username(
        self, username: str
    ) -> Optional[GerritAccountInfo]:
        """
        Look up a Gerrit account by username.

        Args:
            username: Username to search for

        Returns:
            GerritAccountInfo if found, None otherwise

        Raises:
            GerritServerError: If API request fails
        """
        rest = self._ensure_client()

        try:
            # Use the accounts query API to find account ID
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get(f"/accounts/?q=username:{username}")
            )

            if isinstance(result, list) and len(result) > 0:
                account_id = result[0].get("_account_id", 0)
                # Fetch full account details
                return await self.get_account_details(account_id)
            return None

        except HTTPError as e:
            status_code = getattr(e.response, "status_code", None)

            if status_code == 401:
                raise GerritServerError(
                    f"Authentication required to search for account by username. "
                    f"Please provide valid Gerrit credentials."
                )
            elif status_code == 403:
                raise GerritServerError(
                    f"Authentication failed or insufficient permissions to search accounts."
                )
            else:
                self.logger.error(
                    f"HTTP error looking up account by username {username}: {e}"
                )
                raise GerritServerError(
                    f"HTTP error {status_code} looking up account: {e}"
                ) from e

        except Exception as e:
            self.logger.error(
                f"Error looking up account by username {username}: {e}"
            )
            raise GerritServerError(f"Failed to lookup account: {e}") from e

    async def get_account_ssh_keys(
        self, account_id: int
    ) -> list[GerritSSHKeyInfo]:
        """
        Get all SSH keys registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID

        Returns:
            List of GerritSSHKeyInfo objects

        Raises:
            GerritServerError: If API request fails
        """
        rest = self._ensure_client()

        try:
            # Use pygerrit2 to get SSH keys
            # Note: pygerrit2 automatically adds /a/ when authenticated
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get(f"/accounts/{account_id}/sshkeys")
            )

            if not isinstance(result, list):
                return []

            keys = []
            for key_data in result:
                try:
                    key_info = GerritSSHKeyInfo(
                        seq=key_data.get("seq", 0),
                        ssh_public_key=key_data.get("ssh_public_key", ""),
                        encoded_key=key_data.get("encoded_key", ""),
                        algorithm=key_data.get("algorithm", ""),
                        comment=key_data.get("comment"),
                        valid=key_data.get("valid", False),
                    )
                    keys.append(key_info)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to parse SSH key data: {e}"
                    )
                    continue

            return keys

        except HTTPError as e:
            # Handle HTTP errors with proper status code detection
            status_code = getattr(e.response, "status_code", None)

            if status_code == 401:
                raise GerritServerError(
                    f"Cannot access SSH keys for account {account_id}: "
                    f"Authentication required. Please provide valid Gerrit credentials "
                    f"via --gerrit-username and --gerrit-password options."
                )
            elif status_code == 403:
                raise GerritServerError(
                    f"Cannot access SSH keys for account {account_id}: "
                    f"Authentication failed or insufficient permissions. "
                    f"Please verify your Gerrit credentials."
                )
            elif status_code == 404:
                raise GerritServerError(
                    f"Cannot access SSH keys for account {account_id}: "
                    f"SSH keys endpoint not available on Gerrit server "
                    f"'{self.server}'. This Gerrit instance may not "
                    f"support SSH key management."
                )
            else:
                self.logger.error(
                    f"HTTP error getting SSH keys for account {account_id}: {e}"
                )
                raise GerritServerError(
                    f"HTTP error {status_code} accessing SSH keys: {e}"
                ) from e

        except Exception as e:
            self.logger.error(
                f"Error getting SSH keys for account {account_id}: {e}"
            )
            raise GerritServerError(
                f"Failed to get SSH keys: {e}"
            ) from e

    async def get_account_gpg_keys(
        self, account_id: int
    ) -> list[GerritGPGKeyInfo]:
        """
        Get all GPG keys registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID

        Returns:
            List of GerritGPGKeyInfo objects

        Raises:
            GerritServerError: If API request fails
        """
        rest = self._ensure_client()

        try:
            # Use pygerrit2 to get GPG keys
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get(f"/accounts/{account_id}/gpgkeys")
            )

            if not isinstance(result, dict):
                return []

            keys = []
            for key_id, key_data in result.items():
                try:
                    key_info = GerritGPGKeyInfo(
                        id=key_id,
                        fingerprint=key_data.get("fingerprint", key_id),
                        user_ids=key_data.get("user_ids", []),
                        key=key_data.get("key", ""),
                        status=key_data.get("status", ""),
                        problems=key_data.get("problems", []),
                    )
                    keys.append(key_info)
                except Exception as e:
                    self.logger.warning(
                        f"Failed to parse GPG key data: {e}"
                    )
                    continue

            return keys

        except HTTPError as e:
            # Handle HTTP errors with proper status code detection
            status_code = getattr(e.response, "status_code", None)

            if status_code == 401:
                raise GerritServerError(
                    f"Cannot access GPG keys for account {account_id}: "
                    f"Authentication required. Please provide valid Gerrit credentials "
                    f"via --gerrit-username and --gerrit-password options."
                )
            elif status_code == 403:
                raise GerritServerError(
                    f"Cannot access GPG keys for account {account_id}: "
                    f"Authentication failed or insufficient permissions. "
                    f"Please verify your Gerrit credentials."
                )
            elif status_code == 404:
                raise GerritServerError(
                    f"Cannot access GPG keys for account {account_id}: "
                    f"GPG keys endpoint not available on Gerrit server "
                    f"'{self.server}'. This Gerrit instance may not "
                    f"support GPG key management."
                )
            else:
                self.logger.error(
                    f"HTTP error getting GPG keys for account {account_id}: {e}"
                )
                raise GerritServerError(
                    f"HTTP error {status_code} accessing GPG keys: {e}"
                ) from e

        except Exception as e:
            self.logger.error(
                f"Error getting GPG keys for account {account_id}: {e}"
            )
            raise GerritServerError(
                f"Failed to get GPG keys: {e}"
            ) from e

    async def verify_ssh_key_registered(
        self,
        account_id: int,
        fingerprint: str,
    ) -> KeyVerificationResult:
        """
        Verify if an SSH key fingerprint is registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID
            fingerprint: SSH key fingerprint to verify

        Returns:
            KeyVerificationResult with verification details
        """
        try:
            # Fetch account details
            account = await self.get_account_details(account_id)

            ssh_keys = await self.get_account_ssh_keys(account_id)
            normalized_fingerprint = self._normalize_ssh_fingerprint(
                fingerprint
            )

            for key in ssh_keys:
                if key.valid and key.ssh_public_key:
                    key_fingerprint = await self._calculate_ssh_fingerprint(
                        key.ssh_public_key
                    )
                    if key_fingerprint == normalized_fingerprint:
                        return KeyVerificationResult(
                            key_registered=True,
                            username=account.username if account else str(account_id),
                            enumerated=False,
                            key_info=key,
                            service="gerrit",
                            server=self.server,
                            user_name=account.name if account else None,
                            user_email=account.email if account else None,
                        )

            return KeyVerificationResult(
                key_registered=False,
                username=account.username if account else str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
                user_name=account.name if account else None,
                user_email=account.email if account else None,
            )

        except GerritServerError:
            # Re-raise server errors so they can be handled at workflow
            # level
            raise
        except Exception as e:
            self.logger.error(f"Error verifying SSH key: {e}")
            return KeyVerificationResult(
                key_registered=False,
                username=str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
                user_name=None,
                user_email=None,
            )

    async def verify_gpg_key_registered(
        self,
        account_id: int,
        key_id: str,
    ) -> KeyVerificationResult:
        """
        Verify if a GPG key is registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID
            key_id: GPG key ID to verify

        Returns:
            KeyVerificationResult with verification details
        """
        try:
            # Fetch account details
            account = await self.get_account_details(account_id)

            gpg_keys = await self.get_account_gpg_keys(account_id)
            normalized_key_id = key_id.upper().replace("0X", "")

            for key in gpg_keys:
                # Check if the key ID matches (can be short or long form)
                if key.id.upper().endswith(
                    normalized_key_id
                ) or key.fingerprint.upper().endswith(normalized_key_id):
                    return KeyVerificationResult(
                        key_registered=True,
                        username=account.username if account else str(account_id),
                        enumerated=False,
                        key_info=key,
                        service="gerrit",
                        server=self.server,
                        user_name=account.name if account else None,
                        user_email=account.email if account else None,
                    )
            return KeyVerificationResult(
                key_registered=False,
                username=account.username if account else str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
                user_name=account.name if account else None,
                user_email=account.email if account else None,
            )

        except GerritServerError:
            # Re-raise server errors so they can be handled at workflow
            # level
            raise
        except Exception as e:
            self.logger.error(f"Error verifying GPG key: {e}")
            return KeyVerificationResult(
                key_registered=False,
                username=str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
                user_name=None,
                user_email=None,
            )

    def _normalize_ssh_fingerprint(self, fingerprint: str) -> str:
        """
        Normalize SSH fingerprint to consistent format.

        Args:
            fingerprint: Raw SSH fingerprint

        Returns:
            Normalized fingerprint (lowercase, no prefixes)
        """
        # Remove common prefixes and make lowercase
        normalized = fingerprint.lower()
        for prefix in ["sha256:", "md5:", "ssh-"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]

        # Remove any colons or spaces
        normalized = normalized.replace(":", "").replace(" ", "")

        return normalized

    async def _calculate_ssh_fingerprint(self, public_key: str) -> str:
        """
        Calculate SSH fingerprint from public key.

        Args:
            public_key: SSH public key string

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
            self.logger.warning(
                f"Failed to calculate SSH fingerprint: {e}"
            )
            return ""
