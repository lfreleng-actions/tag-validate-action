# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Implementation of the ``tag-validate gerrit`` command.

This module resolves Gerrit credentials, looks the account up on the
server, checks whether the supplied key is registered against it, and
renders the outcome as JSON or as a Rich panel.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer

from .cli_credentials import NetrcLookup, resolve_netrc_credentials
from .cli_display import build_mock_signature, display_verification_result
from .cli_key_common import (
    exit_for_registration,
    report_unexpected_verification_error,
    resolve_key_type,
    status_context,
)
from .cli_keys import normalize_ssh_fingerprint
from .cli_runtime import (
    EXIT_INVALID_INPUT,
    console,
    report_error,
    suppress_logging_for_json,
)


@dataclass(frozen=True)
class GerritOptions:
    """Options accepted by the ``gerrit`` command, as supplied."""

    key_id: str
    owner: str
    key_type: str
    server: str | None
    github_org: str | None
    gerrit_username: str | None
    gerrit_password: str | None
    no_netrc: bool
    netrc_file: Path | None
    netrc_optional: bool
    json_output: bool


def _report_ssh_test_result(key_id: str, detected_type: str, json_output: bool) -> None:
    """Report SSH fingerprint normalization for ``--test-mode``."""
    try:
        normalized_fingerprint = normalize_ssh_fingerprint(key_id)
        if json_output:
            console.print_json(
                data={
                    "test_mode": True,
                    "key_type": detected_type,
                    "original_key": key_id,
                    "normalized_key": normalized_fingerprint,
                    "success": True,
                }
            )
        else:
            console.print("[green]✅ SSH key parsing successful[/green]")
            console.print(f"Original: {key_id}")
            console.print(f"Normalized: {normalized_fingerprint}")
    except Exception as e:
        error_msg = f"SSH key parsing failed: {e}"
        if json_output:
            console.print_json(
                data={"test_mode": True, "success": False, "error": error_msg}
            )
        else:
            console.print(f"[red]❌ {error_msg}[/red]")
        raise typer.Exit(1) from e


def _report_gpg_test_result(key_id: str, detected_type: str, json_output: bool) -> None:
    """Report GPG key normalization for ``--test-mode``."""
    if json_output:
        console.print_json(
            data={
                "test_mode": True,
                "key_type": detected_type,
                "original_key": key_id,
                "normalized_key": key_id.upper().replace("0X", ""),
                "success": True,
            }
        )
    else:
        console.print("[green]✅ GPG key parsing successful[/green]")
        console.print(f"Original: {key_id}")
        console.print(f"Normalized: {key_id.upper().replace('0X', '')}")


async def run_gerrit_test_mode(key_id: str, key_type: str, json_output: bool) -> None:
    """Exercise key parsing without contacting a Gerrit server."""
    try:
        # Suppress ALL logs when in test mode
        suppress_logging_for_json()

        detected_type = resolve_key_type(key_id, key_type, json_output)

        if detected_type == "ssh":
            _report_ssh_test_result(key_id, detected_type, json_output)
        else:  # GPG
            _report_gpg_test_result(key_id, detected_type, json_output)

    except typer.Exit:
        raise
    except Exception as e:
        if json_output:
            console.print_json(
                data={"test_mode": True, "success": False, "error": str(e)}
            )
        else:
            console.print(f"[red]❌ Test failed: {e}[/red]")
        raise typer.Exit(1) from e


async def _lookup_gerrit_account(client: Any, owner: str, json_output: bool) -> Any:
    """Look a Gerrit account up by email address or username."""
    try:
        if "@" in owner:
            account = await client.lookup_account_by_email(owner)
        else:
            account = await client.lookup_account_by_username(owner)

        if account is None:
            error_msg = f"Gerrit account not found for '{owner}'"
            report_error(error_msg, json_output=json_output)
            raise typer.Exit(EXIT_INVALID_INPUT)
    except typer.Exit:
        # typer.Exit subclasses RuntimeError; without this guard the
        # "account not found" exit above is caught below and reported a
        # second time, with the exit code interpolated as the message.
        raise
    except Exception as exc:
        if json_output:
            error_msg = f"Failed to find Gerrit account for '{owner}': {exc}"
            console.print_json(data={"success": False, "error": error_msg})
        else:
            error_msg = f"Failed to find Gerrit account for '{owner}'"
            console.print(f"[red]❌ {error_msg}[/red]")
        raise typer.Exit(EXIT_INVALID_INPUT) from exc

    return account


async def _verify_key_on_gerrit(
    client: Any, account: Any, detected_type: str, key_id: str
) -> Any:
    """Check whether the supplied key is registered to a Gerrit account."""
    if detected_type == "gpg":
        return await client.verify_gpg_key_registered(
            account_id=account.account_id,
            key_id=key_id,
        )
    # ssh
    normalized_fingerprint = normalize_ssh_fingerprint(key_id)
    return await client.verify_ssh_key_registered(
        account_id=account.account_id,
        fingerprint=normalized_fingerprint,
    )


def _emit_gerrit_result(
    options: GerritOptions,
    verification: Any,
    account: Any,
    detected_type: str,
) -> None:
    """Render the Gerrit key verification outcome."""
    if options.json_output:
        console.print_json(
            data={
                "success": verification.key_registered,
                "key_type": detected_type,
                "key_id": options.key_id,
                "owner_input": options.owner,
                "username": account.username,
                "email": account.email,
                "name": account.name,
                "server": verification.server,
                "service": "gerrit",
                "is_registered": verification.key_registered,
            }
        )
    else:
        display_verification_result(
            verification,
            build_mock_signature(options.key_id, detected_type),
            options.owner,
            platform="Gerrit",
            account=account,
        )


def _resolve_credentials(
    options: GerritOptions, credentials_lookup: Any
) -> tuple[str | None, str | None]:
    """Resolve credentials: CLI args > netrc > environment."""
    username = options.gerrit_username
    password = options.gerrit_password
    if (username and password) or options.no_netrc:
        return username, password

    effective_host = (
        options.server if options.server else f"gerrit.{options.github_org}.org"
    )
    return resolve_netrc_credentials(
        NetrcLookup(
            host=effective_host,
            netrc_file=options.netrc_file,
            netrc_optional=options.netrc_optional,
            json_output=options.json_output,
        ),
        username,
        password,
        credentials_lookup,
    )


async def run_gerrit_verification(
    options: GerritOptions, *, keys_client_cls: Any, credentials_lookup: Any
) -> None:
    """Verify that a key is registered against a Gerrit account."""
    json_output = options.json_output
    try:
        # Suppress ALL logs when JSON output is requested
        if json_output:
            suppress_logging_for_json()

        # Validate server/github_org parameters
        if not options.server and not options.github_org:
            report_error(
                "Either --server or --github-org must be provided",
                json_output=json_output,
            )
            raise typer.Exit(EXIT_INVALID_INPUT)

        username, password = _resolve_credentials(options, credentials_lookup)
        detected_type = resolve_key_type(options.key_id, options.key_type, json_output)

        # Verify key on Gerrit
        with status_context("[bold green]Verifying key on Gerrit...", json_output):
            async with keys_client_cls(
                server=options.server,
                github_org=options.github_org,
                username=username,
                password=password,
                use_netrc=not options.no_netrc,
                netrc_file=options.netrc_file,
            ) as client:
                account = await _lookup_gerrit_account(
                    client, options.owner, json_output
                )
                verification = await _verify_key_on_gerrit(
                    client, account, detected_type, options.key_id
                )

        _emit_gerrit_result(options, verification, account, detected_type)
        exit_for_registration(verification.key_registered)

    except typer.Exit:
        raise
    except SystemExit:
        raise
    except Exception as e:
        report_unexpected_verification_error(e, json_output)
