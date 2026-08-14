# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Error types for Gerrit keys operations.

Also provides the shared translation from an HTTP status code to the
matching credential error, so every Gerrit API call reports
authentication problems the same way.
"""

from requests.exceptions import HTTPError


class GerritKeysError(Exception):
    """Base exception for Gerrit keys operations."""

    pass


class GerritServerError(Exception):
    """Raised when Gerrit server communication fails."""

    def __init__(self, message: str, status_code: int | None = None):
        """Initialize with message and optional HTTP status code."""
        super().__init__(message)
        self.status_code = status_code


class GerritAuthError(GerritServerError):
    """Raised when Gerrit authentication fails (401 or 403)."""

    pass


class GerritMissingCredentialsError(GerritAuthError):
    """Raised when credentials are required but not provided (401)."""

    def __init__(self, message: str):
        """Initialize with 401 status code."""
        super().__init__(message, status_code=401)


class GerritInvalidCredentialsError(GerritAuthError):
    """Raised when provided credentials are invalid (403)."""

    def __init__(self, message: str):
        """Initialize with 403 status code."""
        super().__init__(message, status_code=403)


def http_status_of(error: HTTPError) -> int | None:
    """Return the HTTP status code carried by an HTTPError, if any."""
    return getattr(error.response, "status_code", None)


def credential_error(
    status_code: int | None,
    *,
    missing: str,
    invalid: str,
) -> GerritAuthError | None:
    """Map an auth-related status code to the matching credential error.

    Args:
        status_code: HTTP status code from the failed request.
        missing: Message used when credentials were absent (401).
        invalid: Message used when credentials were rejected (403).

    Returns:
        The error to raise, or None if the status is not auth-related.
    """
    if status_code == 401:
        return GerritMissingCredentialsError(missing)
    if status_code == 403:
        return GerritInvalidCredentialsError(invalid)
    return None


__all__ = [
    "GerritAuthError",
    "GerritInvalidCredentialsError",
    "GerritKeysError",
    "GerritMissingCredentialsError",
    "GerritServerError",
    "credential_error",
    "http_status_of",
]
