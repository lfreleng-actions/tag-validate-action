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

Supporting code lives in sibling modules:

- :mod:`tag_validate.gerrit_keys_errors` - exception hierarchy
- :mod:`tag_validate.gerrit_keys_base` - configuration and credentials
- :mod:`tag_validate.gerrit_keys_accounts` - account lookups
- :mod:`tag_validate.gerrit_keys_registry` - registered key retrieval
- :mod:`tag_validate.gerrit_keys_fingerprint` - fingerprint helpers
"""

import asyncio
import functools
import logging
from typing import Any

from pygerrit2 import Anonymous, GerritRestAPI, HTTPBasicAuth

from .gerrit_keys_base import GerritKeysClientBase
from .gerrit_keys_errors import (
    GerritAuthError,
    GerritInvalidCredentialsError,
    GerritKeysError,
    GerritMissingCredentialsError,
    GerritServerError,
)
from .gerrit_keys_fingerprint import (
    calculate_ssh_fingerprint,
    normalize_ssh_fingerprint,
)
from .gerrit_keys_registry import GerritKeyRegistryMixin
from .models import (
    GerritAccountInfo,
    GerritGPGKeyInfo,
    GerritSSHKeyInfo,
    KeyVerificationResult,
)
from .netrc import GerritCredentials

logger = logging.getLogger(__name__)


class GerritKeysClient(GerritKeyRegistryMixin):
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

    async def __aenter__(self) -> "GerritKeysClient":
        """Async context manager entry."""
        # Determine base URL - try common Gerrit path patterns
        base_url = await self._discover_api_base_url()
        self._base_url = base_url

        # Configure authentication
        if self.username and self.password:
            auth = HTTPBasicAuth(self.username, self.password)
            self.logger.debug(f"Using HTTP Basic Auth for user: {self.username}")
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
        self.logger.debug(f"Discovering API base URL for Gerrit server: {self.server}")

        # Test common path patterns
        test_paths = [
            "/r",  # Standard: https://host/r/
            "/infra",  # Linux Foundation style: https://host/infra/
            "",  # Direct: https://host/
            "/gerrit",  # OpenDaylight style: https://host/gerrit/
        ]

        # Test each potential path by trying to access /projects endpoint
        for path in test_paths:
            # aislop-ignore-next-line ai-slop/hardcoded-url -- URL built from the configured Gerrit host, not a hardcoded endpoint
            base_url = f"https://{self.server}{path}"
            self.logger.debug(f"Testing API endpoint: {base_url}")

            try:
                # Create temporary client to test endpoint
                test_auth = Anonymous()
                test_rest = GerritRestAPI(url=base_url, auth=test_auth)

                # Try to list projects (minimal query)
                # Use functools.partial to avoid late-binding closure issue (B023)
                # and to provide explicit typing for mypy
                result = await asyncio.get_event_loop().run_in_executor(
                    None, functools.partial(test_rest.get, "/projects/?d")
                )

                if isinstance(result, dict) and len(result) > 0:
                    self.logger.debug(f"Discovered working API base URL: {base_url}")
                    return base_url
            except Exception as e:
                self.logger.debug(f"Endpoint {base_url} failed: {e}")
                continue

        # Default to /r/ if nothing works (most common pattern)
        # aislop-ignore-next-line ai-slop/hardcoded-url -- URL built from the configured Gerrit host, not a hardcoded endpoint
        default_url = f"https://{self.server}/r"
        self.logger.debug(f"Using default endpoint: {default_url}")
        return default_url

    def _verification_result(
        self,
        account: GerritAccountInfo | None,
        account_id: int,
        key_info: GerritSSHKeyInfo | GerritGPGKeyInfo | None,
    ) -> KeyVerificationResult:
        """Assemble a KeyVerificationResult for a (possibly absent) key match."""
        return KeyVerificationResult(
            key_registered=key_info is not None,
            username=(
                (account.username or str(account_id)) if account else str(account_id)
            ),
            user_enumerated=False,
            key_info=key_info,
            service="gerrit",
            server=self.server,
            user_name=account.name if account else None,
            user_email=account.email if account else None,
        )

    def _verification_failure(self, account_id: int) -> KeyVerificationResult:
        """Build the fallback result used when verification raises."""
        return KeyVerificationResult(
            key_registered=False,
            username=str(account_id),
            user_enumerated=False,
            key_info=None,
            service="gerrit",
            server=self.server,
            user_name=None,
            user_email=None,
        )

    async def _find_ssh_key(
        self,
        ssh_keys: list[GerritSSHKeyInfo],
        normalized_fingerprint: str,
    ) -> GerritSSHKeyInfo | None:
        """Find the registered SSH key matching a normalized fingerprint."""
        for key in ssh_keys:
            if not (key.valid and key.ssh_public_key):
                continue
            key_fingerprint = await self._calculate_ssh_fingerprint(key.ssh_public_key)
            if key_fingerprint == normalized_fingerprint:
                return key
        return None

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
            normalized_fingerprint = self._normalize_ssh_fingerprint(fingerprint)

            matched = await self._find_ssh_key(ssh_keys, normalized_fingerprint)
            return self._verification_result(account, account_id, matched)

        except GerritServerError:
            # Re-raise server errors so they can be handled at workflow
            # level
            raise
        except Exception as e:
            self.logger.error(f"Error verifying SSH key: {e}")
            return self._verification_failure(account_id)

    def _find_gpg_key(
        self,
        gpg_keys: list[GerritGPGKeyInfo],
        normalized_key_id: str,
    ) -> GerritGPGKeyInfo | None:
        """Find the registered GPG key matching a normalized key ID."""
        for key in gpg_keys:
            # Check if the key ID matches (can be short or long form)
            if key.id.upper().endswith(
                normalized_key_id
            ) or key.fingerprint.upper().endswith(normalized_key_id):
                return key
        return None

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

            matched = self._find_gpg_key(gpg_keys, normalized_key_id)
            return self._verification_result(account, account_id, matched)

        except GerritServerError:
            # Re-raise server errors so they can be handled at workflow
            # level
            raise
        except Exception as e:
            self.logger.error(f"Error verifying GPG key: {e}")
            return self._verification_failure(account_id)

    def _normalize_ssh_fingerprint(self, fingerprint: str) -> str:
        """
        Normalize SSH fingerprint to consistent format.

        Args:
            fingerprint: Raw SSH fingerprint

        Returns:
            Normalized fingerprint (lowercase, no prefixes)
        """
        return normalize_ssh_fingerprint(fingerprint)

    async def _calculate_ssh_fingerprint(self, public_key: str) -> str:
        """
        Calculate SSH fingerprint from public key.

        Args:
            public_key: SSH public key string

        Returns:
            SHA256 fingerprint (base64 encoded without padding)
        """
        return calculate_ssh_fingerprint(public_key, self.logger)


__all__ = [
    "GerritAuthError",
    "GerritCredentials",
    "GerritInvalidCredentialsError",
    "GerritKeysClient",
    "GerritKeysClientBase",
    "GerritKeysError",
    "GerritMissingCredentialsError",
    "GerritServerError",
]
