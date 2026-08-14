# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Gerrit account lookups and connection verification.

Resolves Gerrit accounts by ID, email, or username, and provides the
pre-flight connectivity check that surfaces authentication problems
before any key verification is attempted.
"""

import asyncio

from requests.exceptions import HTTPError

from .gerrit_keys_base import GerritKeysClientBase
from .gerrit_keys_errors import (
    GerritServerError,
    credential_error,
    http_status_of,
)
from .models import GerritAccountInfo


class GerritAccountsMixin(GerritKeysClientBase):
    """Account resolution and connection checks against a Gerrit server."""

    def _connection_failure(self, status_code: int | None, error: HTTPError) -> str:
        """Describe an HTTP failure encountered while verifying the connection."""
        has_credentials = bool(self.username and self.password)

        if status_code == 401:
            if has_credentials:
                # Credentials were provided but rejected (possibly invalid)
                return (
                    f"Invalid credentials: Gerrit server '{self.server}' rejected the provided credentials. "
                    f"The username or password may be incorrect."
                )
            # No credentials provided
            return (
                f"Credentials required: Gerrit server '{self.server}' requires authentication. "
                f"No username or password provided."
            )
        if status_code == 403:
            return (
                f"Invalid credentials: Authentication failed for Gerrit server '{self.server}'. "
                f"The provided username or password is incorrect."
            )
        return (
            f"HTTP error {status_code} connecting to Gerrit server "
            f"'{self.server}': {error}"
        )

    async def verify_connection(self) -> tuple[bool, str | None]:
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
                self.logger.debug(
                    f"Successfully connected to Gerrit server {self.server}"
                )
                return (True, None)
            else:
                return (False, "Unable to retrieve server information")

        except HTTPError as e:
            return (False, self._connection_failure(http_status_of(e), e))

        except Exception as e:
            self.logger.error(f"Error connecting to Gerrit server: {e}")
            return (False, f"Failed to connect to Gerrit server '{self.server}': {e}")

    async def get_account_details(self, account_id: int) -> GerritAccountInfo | None:
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
            status_code = http_status_of(e)
            auth_error = credential_error(
                status_code,
                missing=(
                    f"Credentials required to access account {account_id}. "
                    f"Please provide Gerrit username and password."
                ),
                invalid=(
                    f"Invalid credentials or insufficient permissions to access account {account_id}."
                ),
            )
            if auth_error is not None:
                raise auth_error from None
            if status_code == 404:
                # 404 for account details just means account not found, return None
                return None

            self.logger.error(
                f"HTTP error getting account details for ID {account_id}: {e}"
            )
            raise GerritServerError(
                f"HTTP error {status_code} getting account details: {e}"
            ) from e

        except Exception as e:
            self.logger.error(f"Error getting account details for ID {account_id}: {e}")
            raise GerritServerError(f"Failed to get account details: {e}") from e

    async def _lookup_account(
        self,
        query: str,
        *,
        criterion: str,
        value: str,
    ) -> GerritAccountInfo | None:
        """Look up an account via the accounts query API.

        Args:
            query: Full query string passed to /accounts/.
            criterion: Human-readable criterion name for error messages.
            value: The searched value, used in log messages.

        Returns:
            GerritAccountInfo if found, None otherwise.
        """
        rest = self._ensure_client()

        try:
            # Use the accounts query API to find account ID
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: rest.get(query)
            )

            if isinstance(result, list) and len(result) > 0:
                account_id = result[0].get("_account_id", 0)
                # Fetch full account details
                return await self.get_account_details(account_id)
            return None

        except HTTPError as e:
            status_code = http_status_of(e)
            auth_error = credential_error(
                status_code,
                missing=(
                    f"Credentials required to search for account by {criterion}. "
                    "Please provide Gerrit username and password."
                ),
                invalid=(
                    "Invalid credentials or insufficient permissions to search accounts."
                ),
            )
            if auth_error is not None:
                raise auth_error from None

            self.logger.error(
                f"HTTP error looking up account by {criterion} {value}: {e}"
            )
            raise GerritServerError(
                f"HTTP error {status_code} looking up account: {e}"
            ) from e

        except Exception as e:
            self.logger.error(f"Error looking up account by {criterion} {value}: {e}")
            raise GerritServerError(f"Failed to lookup account: {e}") from e

    async def lookup_account_by_email(self, email: str) -> GerritAccountInfo | None:
        """
        Look up a Gerrit account by email address.

        Args:
            email: Email address to search for

        Returns:
            GerritAccountInfo if found, None otherwise

        Raises:
            GerritServerError: If API request fails
        """
        return await self._lookup_account(
            f"/accounts/?q=email:{email}", criterion="email", value=email
        )

    async def lookup_account_by_username(
        self, username: str
    ) -> GerritAccountInfo | None:
        """
        Look up a Gerrit account by username.

        Args:
            username: Username to search for

        Returns:
            GerritAccountInfo if found, None otherwise

        Raises:
            GerritServerError: If API request fails
        """
        return await self._lookup_account(
            f"/accounts/?q=username:{username}", criterion="username", value=username
        )


__all__ = ["GerritAccountsMixin"]
