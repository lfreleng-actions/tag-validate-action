# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Implementation of the ``tag-validate verify`` command.

This module drives the full validation workflow: it turns the CLI
options into a configuration, runs the workflow against the requested
tag, and reports the outcome to the console, a JSON file and the GitHub
step summary.
"""

from pathlib import Path
from typing import Any

import typer

from .cli_display import display_validation_result
from .cli_key_common import resolve_owner_or_exit, status_context
from .cli_parsing import is_tag_not_found_error, normalize_tag_location
from .cli_runtime import (
    EXIT_UNEXPECTED_ERROR,
    TAG_LOCATION_FORMAT_EXAMPLES,
    TAG_LOCATION_FORMATS,
    console,
    log_unexpected_error,
    suppress_logging_for_json,
)
from .cli_validate import write_json_file
from .cli_verify_config import VerifyOptions, VerifyPlan, build_verify_plan
from .cli_verify_output import (
    build_console_output,
    build_file_output,
    exit_for_result,
    missing_tag_output,
)
from .github_summary import write_validation_summary


def _require_tag_location(tag_location: str, json_output: bool) -> None:
    """Fail when no tag location was supplied.

    Raises:
        typer.Exit: If the tag location is empty or whitespace only
    """
    if tag_location and tag_location.strip():
        return

    error_msg = "Tag location is empty or null"
    info_messages = [
        "tag_location parameter is required but was not provided or is empty",
    ] + TAG_LOCATION_FORMAT_EXAMPLES

    if json_output:
        console.print_json(
            data={
                "success": False,
                "tag_name": "",
                "error": error_msg,
                "info": info_messages,
            }
        )
    else:
        console.print(f"[red]❌ Error:[/red] {error_msg}")
        console.print("\n[yellow]Expected formats:[/yellow]")
        for fmt in TAG_LOCATION_FORMATS.values():
            console.print(f"  • {fmt}")
    raise typer.Exit(1)


def _emit_missing_tag_result(
    tag_name: str, json_output: bool, json_file: Path | None
) -> None:
    """Report a missing tag that ``--permit-missing`` allows through."""
    output = missing_tag_output(tag_name)

    if json_output:
        console.print_json(data=output)
    else:
        console.print("\n[yellow]⚠️  Tag not found, but permit_missing=true[/yellow]")

    # Write JSON to file if requested
    if json_file:
        write_json_file(json_file, output)


async def _run_workflow(
    workflow: Any,
    options: VerifyOptions,
    plan: VerifyPlan,
    normalized_location: str,
    resolved_owner: str | None,
) -> Any:
    """Run the validation workflow, honouring ``--permit-missing``."""
    try:
        with status_context("[bold green]Validating tag...", options.json_output):
            return await workflow.validate_tag_location(
                tag_location=normalized_location,
                github_user=resolved_owner,
                github_token=options.github_token,
                require_owners=(
                    plan.require_owner_list if plan.require_owner_list else None
                ),
            )
    except Exception as e:
        # Handle missing tag with permit_missing flag
        if options.permit_missing and is_tag_not_found_error(str(e)):
            _emit_missing_tag_result(
                normalized_location, options.json_output, options.json_file
            )
            raise typer.Exit(0) from None
        # Re-raise if not a missing tag error or permit_missing is false
        raise


def _emit_verify_results(result: Any, workflow: Any, options: VerifyOptions) -> None:
    """Render the validation result to every requested destination."""
    if options.json_output:
        console.print_json(data=build_console_output(result))
    else:
        display_validation_result(result, workflow)

    # Write JSON to file if requested
    if options.json_file:
        write_json_file(options.json_file, build_file_output(result))

    # Write GitHub step summary if enabled and in GitHub Actions
    if options.github_step_summary and not options.json_output:
        write_validation_summary(result, options.tag_location)


async def run_verify(
    options: VerifyOptions, *, workflow_cls: Any, credentials_lookup: Any
) -> None:
    """Perform the complete tag validation workflow."""
    try:
        # Suppress ALL logs when JSON output is requested
        if options.json_output:
            suppress_logging_for_json()

        _require_tag_location(options.tag_location, options.json_output)

        plan = build_verify_plan(options, credentials_lookup)

        workflow = workflow_cls(
            plan.config,
            repo_path=options.repo_path,
            gerrit_username=plan.gerrit_username,
            gerrit_password=plan.gerrit_password,
            use_netrc=not options.no_netrc,
            netrc_file=options.netrc_file,
        )

        # Resolve owner parameter (email or username) to username if provided
        resolved_owner = None
        if options.owner:
            resolved_owner = await resolve_owner_or_exit(
                options.owner, options.github_token, options.json_output
            )

        # Normalize tag location (handle owner/repo/tag → owner/repo@tag)
        normalized_location = normalize_tag_location(options.tag_location)

        result = await _run_workflow(
            workflow, options, plan, normalized_location, resolved_owner
        )

        # Check if result failed due to missing tag and permit_missing is enabled
        if (
            options.permit_missing
            and not result.is_valid
            and is_tag_not_found_error(" ".join(result.errors))
        ):
            _emit_missing_tag_result(
                normalized_location, options.json_output, options.json_file
            )
            raise typer.Exit(0)

        _emit_verify_results(result, workflow, options)
        exit_for_result(result)

    except typer.Exit:
        # Let typer.Exit pass through without catching
        raise
    except Exception as e:
        if options.json_output:
            console.print_json(
                data={
                    "success": False,
                    "error": str(e),
                    "exit_code": EXIT_UNEXPECTED_ERROR,
                }
            )
        else:
            console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
            log_unexpected_error("Unexpected error during tag verification", e)
        raise typer.Exit(EXIT_UNEXPECTED_ERROR) from e
