# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Retrieval of SSH and GPG keys registered to Gerrit accounts.

Wraps the ``/accounts/{id}/sshkeys`` and ``/accounts/{id}/gpgkeys``
endpoints, translating transport failures into the shared Gerrit error
types and skipping individual entries that fail to parse.
"""

import asyncio
from typing import Any, NoReturn

from requests.exceptions import HTTPError

from .gerrit_keys_accounts import GerritAccountsMixin
from .gerrit_keys_errors import (
    GerritServerError,
    credential_error,
    http_status_of,
)
from .models import GerritGPGKeyInfo, GerritSSHKeyInfo


class GerritKeyRegistryMixin(GerritAccountsMixin):
    """Fetches the SSH and GPG keys registered to a Gerrit account."""

    def _raise_key_access_error(
        self,
        error: HTTPError,
        account_id: int,
        key_kind: str,
    ) -> NoReturn:
        """Translate a key-endpoint HTTP failure into a Gerrit error.

        Args:
            error: The originating HTTP error.
            account_id: Account whose keys were requested.
            key_kind: Either "SSH" or "GPG", used in messages.

        Raises:
            GerritServerError: Always; the specific subclass depends on
                the HTTP status code.
        """
        status_code = http_status_of(error)
        auth_error = credential_error(
            status_code,
            missing=(
                f"Cannot access {key_kind} keys for account {account_id}: "
                f"Credentials required. Please provide Gerrit username and password."
            ),
            invalid=(
                f"Cannot access {key_kind} keys for account {account_id}: "
                f"Invalid credentials or insufficient permissions."
            ),
        )
        if auth_error is not None:
            raise auth_error from None
        if status_code == 404:
            raise GerritServerError(
                f"Cannot access {key_kind} keys for account {account_id}: "
                f"{key_kind} keys endpoint not available on Gerrit server "
                f"'{self.server}'. This Gerrit instance may not "
                f"support {key_kind} key management."
            ) from None

        self.logger.error(
            f"HTTP error getting {key_kind} keys for account {account_id}: {error}"
        )
        raise GerritServerError(
            f"HTTP error {status_code} accessing {key_kind} keys: {error}"
        ) from error

    async def get_account_ssh_keys(self, account_id: int) -> list[GerritSSHKeyInfo]:
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

            return self._parse_ssh_keys(result)

        except HTTPError as e:
            # Handle HTTP errors with proper status code detection
            self._raise_key_access_error(e, account_id, "SSH")

        except Exception as e:
            self.logger.error(f"Error getting SSH keys for account {account_id}: {e}")
            raise GerritServerError(f"Failed to get SSH keys: {e}") from e

    def _parse_ssh_keys(self, result: list[Any]) -> list[GerritSSHKeyInfo]:
        """Parse SSH key payloads, skipping entries that fail validation."""
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
                self.logger.warning(f"Failed to parse SSH key data: {e}")
                continue
        return keys

    async def get_account_gpg_keys(self, account_id: int) -> list[GerritGPGKeyInfo]:
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

            return self._parse_gpg_keys(result)

        except HTTPError as e:
            # Handle HTTP errors with proper status code detection
            self._raise_key_access_error(e, account_id, "GPG")

        except Exception as e:
            self.logger.error(f"Error getting GPG keys for account {account_id}: {e}")
            raise GerritServerError(f"Failed to get GPG keys: {e}") from e

    def _parse_gpg_keys(self, result: dict[str, Any]) -> list[GerritGPGKeyInfo]:
        """Parse GPG key payloads, skipping entries that fail validation."""
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
                self.logger.warning(f"Failed to parse GPG key data: {e}")
                continue
        return keys


__all__ = ["GerritKeyRegistryMixin"]
