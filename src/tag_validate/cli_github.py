# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Implementation of the ``tag-validate github`` command.

This module resolves the GitHub owner, checks whether the supplied GPG
key or SSH fingerprint is registered against that account, and renders
the outcome as JSON or as a Rich panel.
"""

import os
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import typer

from .cli_display import build_mock_signature, display_verification_result
from .cli_key_common import (
    exit_for_registration,
    report_unexpected_verification_error,
    resolve_key_type,
    resolve_owner_or_exit,
    status_context,
)
from .cli_keys import normalize_ssh_fingerprint
from .cli_runtime import (
    EXIT_MISSING_TOKEN,
    EXIT_SUCCESS,
    console,
    suppress_logging_for_json,
)


@dataclass(frozen=True)
class GitHubOptions:
    """Options accepted by the ``github`` command, as supplied."""

    key_id: str
    owner: str
    key_type: str
    github_token: str | None
    no_subkeys: bool
    api_url: str
    graphql_url: str
    json_output: bool


def _print_test_mode_summary(
    key_id: str, detected_type: str, key_type: str, owner: str, label: str, value: str
) -> None:
    """Print the human readable ``--test-mode`` summary."""
    console.print("\n[green]✅ Test Mode: Key parsing successful[/green]")
    console.print(
        f"[bold]Key Type:[/bold] {detected_type}"
        + (" (auto-detected)" if key_type == "auto" else "")
    )
    console.print(f"[bold]Original Input:[/bold] {key_id}")
    console.print(f"[bold]{label}:[/bold] {value}")
    console.print(f"[bold]Owner:[/bold] {owner}")
    console.print("\n[dim]No GitHub API calls made in test mode.[/dim]")


def _report_test_mode_result(
    key_id: str, detected_type: str, key_type: str, owner: str, json_output: bool
) -> None:
    """Report key parsing results without contacting the GitHub API."""
    if detected_type == "ssh":
        normalized_fingerprint = normalize_ssh_fingerprint(key_id)
        if json_output:
            console.print_json(
                data={
                    "test_mode": True,
                    "success": True,
                    "key_type": detected_type,
                    "original_input": key_id,
                    "normalized_fingerprint": normalized_fingerprint,
                    "owner": owner,
                }
            )
        else:
            _print_test_mode_summary(
                key_id,
                detected_type,
                key_type,
                owner,
                "Normalized Fingerprint",
                normalized_fingerprint,
            )
    else:  # gpg
        if json_output:
            console.print_json(
                data={
                    "test_mode": True,
                    "success": True,
                    "key_type": detected_type,
                    "original_input": key_id,
                    "normalized_key_id": key_id,
                    "owner": owner,
                }
            )
        else:
            _print_test_mode_summary(
                key_id, detected_type, key_type, owner, "Normalized Key ID", key_id
            )


async def run_github_test_mode(
    key_id: str, key_type: str, owner: str, json_output: bool
) -> None:
    """Exercise key parsing without contacting the GitHub API."""
    # Suppress ALL logs when JSON output is requested
    if json_output:
        suppress_logging_for_json()

    detected_type = resolve_key_type(key_id, key_type, json_output)

    try:
        _report_test_mode_result(key_id, detected_type, key_type, owner, json_output)
        sys.exit(EXIT_SUCCESS)
    except Exception as e:
        error_msg = f"Key parsing/normalization failed: {str(e)}"
        if json_output:
            console.print_json(
                data={
                    "test_mode": True,
                    "success": False,
                    "error": error_msg,
                    "key_type": detected_type,
                    "original_input": key_id,
                }
            )
        else:
            console.print(f"\n[red]❌ Test Mode: {error_msg}[/red]")
        raise typer.Exit(1) from e


def _require_github_token(github_token: str | None, json_output: bool) -> None:
    """Fail when no GitHub token is available from the CLI or environment.

    Raises:
        typer.Exit: If no token can be found
    """
    if github_token or os.getenv("GITHUB_TOKEN"):
        return

    error_msg = (
        "GitHub token is required. Use --token option or set "
        "GITHUB_TOKEN environment variable."
    )
    if json_output:
        console.print_json(
            data={
                "success": False,
                "error": error_msg,
                "exit_code": EXIT_MISSING_TOKEN,
            }
        )
    else:
        console.print(f"\n[red]❌ {error_msg}[/red]")
    raise typer.Exit(EXIT_MISSING_TOKEN)


async def _verify_key_on_github(
    client: Any,
    detected_type: str,
    key_id: str,
    resolved_owner: str,
    no_subkeys: bool,
) -> Any:
    """Check whether the supplied key is registered to a GitHub account."""
    if detected_type == "gpg":
        return await client.verify_gpg_key_registered(
            username=resolved_owner,
            key_id=key_id,
            check_subkeys=not no_subkeys,
        )
    # ssh
    normalized_fingerprint = normalize_ssh_fingerprint(key_id)
    return await client.verify_ssh_key_registered(
        username=resolved_owner,
        public_key_fingerprint=normalized_fingerprint,
    )


def _github_server_hostname(verification: Any, api_url: str) -> str:
    """Determine the server hostname to report for a GitHub verification."""
    # Use verification.server if available, otherwise extract from API URL
    server_hostname = verification.server
    if server_hostname:
        return str(server_hostname)

    parsed_url = urlparse(api_url)
    # Extract just the hostname (e.g., "api.github.com" -> "github.com")
    netloc = parsed_url.netloc if parsed_url.netloc else "github.com"
    # For api.github.com, use github.com; for GHE, keep the hostname
    return "github.com" if netloc == "api.github.com" else netloc.replace("api.", "")


def _emit_github_result(
    options: GitHubOptions,
    verification: Any,
    user_details: Any,
    detected_type: str,
    resolved_owner: str,
) -> None:
    """Render the GitHub key verification outcome."""
    if not options.json_output:
        display_verification_result(
            verification,
            build_mock_signature(options.key_id, detected_type),
            resolved_owner,
            platform="GitHub",
            github_user_details=user_details,
        )
        return

    username = user_details.get("login") if user_details else resolved_owner
    console.print_json(
        data={
            "success": verification.key_registered,
            "key_type": detected_type,
            "key_id": options.key_id,
            "owner_input": options.owner,
            "username": username,
            "email": user_details.get("email") if user_details else None,
            "name": user_details.get("name") if user_details else None,
            "server": _github_server_hostname(verification, options.api_url),
            "service": "github",
            "is_registered": verification.key_registered,
            # Backward-compatible aliases for older JSON consumers
            "github_user": username,
            "key_registered": verification.key_registered,
        }
    )


async def run_github_verification(
    options: GitHubOptions, *, keys_client_cls: Any
) -> None:
    """Verify that a key is registered against a GitHub account."""
    json_output = options.json_output
    try:
        # Suppress ALL logs when JSON output is requested
        if json_output:
            suppress_logging_for_json()

        detected_type = resolve_key_type(options.key_id, options.key_type, json_output)
        _require_github_token(options.github_token, json_output)

        # Resolve owner (email or username) to username first
        resolved_owner = await resolve_owner_or_exit(
            options.owner, options.github_token, json_output
        )

        client_kwargs = {
            "token": options.github_token,
            "api_url": options.api_url,
            "graphql_url": options.graphql_url,
        }

        # Fetch user details
        async with keys_client_cls(**client_kwargs) as client:
            user_details = await client.get_user_details(resolved_owner)

        # Verify key on GitHub
        with status_context("[bold green]Verifying key on GitHub...", json_output):
            async with keys_client_cls(**client_kwargs) as client:
                verification = await _verify_key_on_github(
                    client,
                    detected_type,
                    options.key_id,
                    resolved_owner,
                    options.no_subkeys,
                )

        _emit_github_result(
            options, verification, user_details, detected_type, resolved_owner
        )
        exit_for_registration(verification.key_registered)

    except typer.Exit:
        raise
    except SystemExit:
        raise
    except Exception as e:
        report_unexpected_verification_error(e, json_output)
