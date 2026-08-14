# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Shared behaviour for the ``gerrit`` and ``github`` key commands.

Both commands resolve the key type the same way, report unexpected
failures the same way, and translate a registration result into the
same exit code; that common ground lives here.
"""

import contextlib
from typing import Any

import typer

from .cli_keys import detect_key_type, resolve_owner_to_username
from .cli_runtime import (
    EXIT_INVALID_INPUT,
    EXIT_SUCCESS,
    EXIT_UNEXPECTED_ERROR,
    EXIT_VALIDATION_FAILED,
    console,
    log_unexpected_error,
    report_error,
)


def resolve_key_type(key_id: str, key_type: str, json_output: bool) -> str:
    """Resolve the effective key type, auto-detecting when requested.

    Args:
        key_id: GPG key ID or SSH fingerprint supplied on the CLI
        key_type: Requested type: "gpg", "ssh" or "auto"
        json_output: Whether the command is emitting JSON

    Returns:
        Either "gpg" or "ssh"

    Raises:
        typer.Exit: If the type cannot be detected or is not recognised
    """
    if key_type == "auto":
        detected_type = detect_key_type(key_id)
        if detected_type == "unknown":
            report_error(
                f"Could not auto-detect key type from: {key_id[:50]}... "
                "Please specify --type gpg or --type ssh",
                json_output=json_output,
            )
            raise typer.Exit(1)
        return detected_type

    if key_type not in ["gpg", "ssh"]:
        report_error(
            f"Invalid key type: {key_type}. Must be 'gpg', 'ssh', or 'auto'",
            json_output=json_output,
        )
        raise typer.Exit(1)

    return key_type


def status_context(message: str, json_output: bool) -> Any:
    """Return a Rich status spinner, or a no-op context in JSON mode."""
    if json_output:
        return contextlib.nullcontext()
    return console.status(message)


def exit_for_registration(key_registered: bool) -> None:
    """Translate a key registration result into the command exit code.

    Raises:
        typer.Exit: Always; success or validation failure
    """
    if key_registered:
        raise typer.Exit(EXIT_SUCCESS)
    raise typer.Exit(EXIT_VALIDATION_FAILED)


def report_unexpected_verification_error(error: Exception, json_output: bool) -> None:
    """Report an unhandled key verification failure.

    Raises:
        typer.Exit: Always, with the unexpected-error exit code
    """
    if json_output:
        console.print_json(
            data={
                "success": False,
                "error": str(error),
                "exit_code": EXIT_UNEXPECTED_ERROR,
            }
        )
    else:
        console.print(f"\n[red]❌ Error:[/red] {error}")
        log_unexpected_error("Unexpected error during verification", error)
    raise typer.Exit(EXIT_UNEXPECTED_ERROR) from error


async def resolve_owner_or_exit(
    owner: str, github_token: str | None, json_output: bool
) -> str:
    """Resolve an owner supplied as an email address to a GitHub username.

    Raises:
        typer.Exit: If the email address cannot be resolved
    """
    try:
        return await resolve_owner_to_username(owner, github_token)
    except ValueError as e:
        if json_output:
            console.print_json(
                data={
                    "success": False,
                    "error": str(e),
                    "exit_code": EXIT_INVALID_INPUT,
                }
            )
        else:
            console.print(f"\n[red]❌ Error:[/red] {e}")
        raise typer.Exit(EXIT_INVALID_INPUT) from e
