# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Netrc file parsing for Gerrit authentication credentials.

This module provides functionality to parse .netrc files and retrieve
credentials for authenticating with Gerrit servers. It follows the
standard netrc format as documented at:
https://everything.curl.dev/usingcurl/netrc.html

The module supports:
- Standard netrc tokens: machine, login, password, default
- Quoted strings (curl 7.84.0+) with escape sequences
- Multiple search locations (local directory, home directory)
- Windows compatibility (_netrc fallback)

The implementation is split across sibling modules; this module is the
public entry point and re-exports the full API:

- :mod:`tag_validate.netrc_types` - shared types and token constants
- :mod:`tag_validate.netrc_tokenizer` - lexical analysis
- :mod:`tag_validate.netrc_parser` - grammar-level parsing
- :mod:`tag_validate.netrc_discovery` - file lookup and loading
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from .netrc_discovery import check_netrc_permissions, find_netrc_file, load_netrc
from .netrc_parser import NetrcParser
from .netrc_types import (
    CredentialSource,
    GerritCredentials,
    NetrcCredentials,
    NetrcParseError,
    _normalize_host_for_netrc_lookup,
)

log = logging.getLogger(__name__)


def get_credentials_for_host(
    host: str,
    netrc_file: Path | None = None,
    search_local: bool = True,
    use_netrc: bool = True,
    netrc_optional: bool = True,
) -> NetrcCredentials | None:
    """
    Get credentials for a Gerrit host from .netrc file.

    This is the main entry point for credential lookup. It handles
    the full workflow of finding, parsing, and querying the netrc file.

    Args:
        host: Gerrit server hostname (e.g., 'gerrit.onap.org').
        netrc_file: Explicit path to netrc file (optional).
        search_local: Search current directory for .netrc.
        use_netrc: Whether to use netrc at all (--no-netrc sets False).
        netrc_optional: If True, don't fail if netrc not found.

    Returns:
        NetrcCredentials if found, None otherwise.

    Raises:
        NetrcParseError: If netrc file exists but cannot be parsed.
        FileNotFoundError: If netrc_optional=False and no file found.
    """
    if not use_netrc:
        log.debug("Netrc lookup disabled")
        return None

    # Normalize host - remove scheme, path, and port if present
    normalized_host = _normalize_host_for_netrc_lookup(host)

    # Find the netrc file path first so we can include it in log messages
    netrc_path = find_netrc_file(
        search_local=search_local,
        explicit_path=netrc_file,
    )

    if netrc_path is None:
        if not netrc_optional:
            msg = "No .netrc file found and netrc is required"
            raise FileNotFoundError(msg)
        return None

    netrc = load_netrc(
        path=netrc_path,
        search_local=False,  # Already found the path
    )

    if netrc is None:
        # load_netrc returns None if file couldn't be read
        return None

    credentials = netrc.get_credentials(normalized_host)
    if credentials:
        log.debug(
            "Found netrc credentials for %s (login: %s) in %s",
            normalized_host,
            credentials.login,
            netrc_path,
        )
    else:
        log.warning(
            "No netrc credentials found for %s in %s",
            normalized_host,
            netrc_path,
        )

    return credentials


def _credentials_from_netrc(
    host: str,
    netrc_file: Path | None,
) -> GerritCredentials | None:
    """Resolve credentials from a .netrc file, or None if unavailable."""
    netrc_path = find_netrc_file(
        search_local=True,
        explicit_path=netrc_file,
    )
    if netrc_path is None:
        return None

    netrc = load_netrc(path=netrc_path, search_local=False)
    if netrc is None:
        return None

    # Normalize host for lookup
    normalized_host = _normalize_host_for_netrc_lookup(host)

    netrc_creds = netrc.get_credentials(normalized_host)
    if not netrc_creds:
        log.warning(
            "No netrc credentials found for %s in %s",
            normalized_host,
            netrc_path,
        )
        return None

    log.debug(
        "Using credentials from .netrc for %s (login: %s) in %s",
        normalized_host,
        netrc_creds.login,
        netrc_path,
    )
    return GerritCredentials(
        username=netrc_creds.login,
        password=netrc_creds.password,
        source=CredentialSource.NETRC,
        source_detail=str(netrc_path),
    )


def _credentials_from_env(
    username_var: str,
    password_var: str,
) -> GerritCredentials | None:
    """Resolve credentials from a pair of environment variables."""
    env_user = os.getenv(username_var, "").strip()
    env_pass = os.getenv(password_var, "").strip()
    if not (env_user and env_pass):
        return None

    return GerritCredentials(
        username=env_user,
        password=env_pass,
        source=CredentialSource.ENVIRONMENT,
        # Record only the username variable name; including the password
        # variable name risks it being surfaced in logs via
        # auth_method_display().
        source_detail=username_var,
    )


def resolve_gerrit_credentials(
    host: str,
    *,
    explicit_username: str | None = None,
    explicit_password: str | None = None,
    use_netrc: bool = True,
    netrc_file: Path | None = None,
    env_username_var: str = "GERRIT_USERNAME",
    env_password_var: str = "GERRIT_PASSWORD",
    fallback_env_username_var: str | None = "GERRIT_HTTP_USER",
    fallback_env_password_var: str | None = "GERRIT_HTTP_PASSWORD",
) -> GerritCredentials | None:
    """
    Resolve Gerrit credentials from multiple sources with defined priority.

    This is the canonical function for resolving Gerrit credentials.
    It returns a single GerritCredentials object that contains both
    the credentials and metadata about their source.

    Priority order:
    1. Explicit CLI arguments (explicit_username/explicit_password)
    2. .netrc file (if use_netrc=True)
    3. Primary environment variables (env_username_var/env_password_var)
    4. Fallback environment variables (if provided)

    Args:
        host: Gerrit server hostname for netrc lookup.
        explicit_username: Username from CLI argument (highest priority).
        explicit_password: Password from CLI argument (highest priority).
        use_netrc: Whether to try .netrc for credentials.
        netrc_file: Explicit path to a .netrc file.
        env_username_var: Primary environment variable for username.
        env_password_var: Primary environment variable for password.
        fallback_env_username_var: Fallback environment variable for username.
        fallback_env_password_var: Fallback environment variable for password.

    Returns:
        GerritCredentials with resolved credentials and source info,
        or None if no credentials found.
    """
    # 1. Check explicit CLI arguments first
    if explicit_username and explicit_password:
        log.debug("Using credentials from CLI arguments")
        return GerritCredentials(
            username=explicit_username.strip(),
            password=explicit_password.strip(),
            source=CredentialSource.CLI_ARGUMENT,
            source_detail="--gerrit-username/--gerrit-password",
        )

    # 2. Try .netrc file
    if use_netrc:
        netrc_creds = _credentials_from_netrc(host, netrc_file)
        if netrc_creds is not None:
            return netrc_creds

    # 3. Try primary environment variables
    env_creds = _credentials_from_env(env_username_var, env_password_var)
    if env_creds is not None:
        log.debug(
            "Using credentials from environment variables (username var: %s)",
            env_username_var,
        )
        return env_creds

    # 4. Try fallback environment variables
    if fallback_env_username_var and fallback_env_password_var:
        fallback_creds = _credentials_from_env(
            fallback_env_username_var, fallback_env_password_var
        )
        if fallback_creds is not None:
            log.debug(
                "Using credentials from fallback environment variables "
                "(username var: %s)",
                fallback_env_username_var,
            )
            return fallback_creds

    log.debug("No Gerrit credentials found from any source")
    return None


__all__ = [
    "CredentialSource",
    "GerritCredentials",
    "NetrcCredentials",
    "NetrcParseError",
    "NetrcParser",
    "check_netrc_permissions",
    "find_netrc_file",
    "get_credentials_for_host",
    "load_netrc",
    "resolve_gerrit_credentials",
]
