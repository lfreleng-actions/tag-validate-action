# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Gerrit credential resolution for the tag-validate CLI.

Both the ``gerrit`` and ``verify`` commands fall back to the user's
.netrc file when a username or password was not supplied on the command
line; this module holds that shared lookup.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer

from .cli_runtime import EXIT_MISSING_CREDENTIALS, console, report_error
from .netrc import NetrcParseError, find_netrc_file, load_netrc


@dataclass(frozen=True)
class NetrcLookup:
    """Where and how to look Gerrit credentials up in a .netrc file."""

    host: str
    netrc_file: Path | None
    netrc_optional: bool
    json_output: bool


def resolve_netrc_credentials(
    lookup: NetrcLookup,
    username: str | None,
    password: str | None,
    credentials_lookup: Any,
) -> tuple[str | None, str | None]:
    """Fill in missing Gerrit credentials from the user's .netrc file.

    Args:
        lookup: Host and .netrc settings to resolve credentials with
        username: Username supplied on the command line, if any
        password: Password supplied on the command line, if any
        credentials_lookup: Callable resolving credentials for a host

    Returns:
        The (possibly updated) username and password

    Raises:
        typer.Exit: If .netrc is required but missing
    """
    try:
        netrc_creds = credentials_lookup(
            host=lookup.host,
            netrc_file=lookup.netrc_file,
            use_netrc=True,
            netrc_optional=lookup.netrc_optional,
        )
        if netrc_creds:
            if not username:
                username = netrc_creds.login
            if not password:
                password = netrc_creds.password
            if not lookup.json_output:
                console.print("[dim]🔑 Using credentials from .netrc[/dim]")
    except NetrcParseError as e:
        if not lookup.json_output:
            console.print(f"[yellow]⚠️  Error parsing .netrc file: {e}[/yellow]")
    except FileNotFoundError as exc:
        if not lookup.netrc_optional:
            report_error(
                "No .netrc file found and --netrc-required set",
                json_output=lookup.json_output,
            )
            raise typer.Exit(EXIT_MISSING_CREDENTIALS) from exc

    return username, password


def probe_netrc_for_discovery(
    netrc_file: Path | None, netrc_optional: bool, json_output: bool
) -> None:
    """Validate .netrc availability before the Gerrit server is known.

    With ``--require-gerrit true`` the hostname is only discovered later
    in the workflow, so the file can merely be located and parsed here.

    Raises:
        typer.Exit: If .netrc is required but missing
    """
    try:
        netrc_path = find_netrc_file(
            search_local=True,
            explicit_path=netrc_file,
        )
        if netrc_path is None:
            if not netrc_optional:
                report_error(
                    "No .netrc file found and --netrc-required set",
                    json_output=json_output,
                )
                raise typer.Exit(EXIT_MISSING_CREDENTIALS)
        else:
            # Validate the file is parseable
            load_netrc(path=netrc_path, search_local=False)
            if not json_output:
                console.print(
                    "[dim]🔑 .netrc file found; "
                    "credentials will be resolved after "
                    "Gerrit server discovery[/dim]"
                )
    except NetrcParseError as e:
        if not json_output:
            console.print(f"[yellow]⚠️  Error parsing .netrc file: {e}[/yellow]")
