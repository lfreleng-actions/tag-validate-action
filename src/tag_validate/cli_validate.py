# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Implementation of the ``tag-validate validate`` command.

This module validates a bare version string against the SemVer and
CalVer patterns and reports the parsed components as JSON or as a Rich
table.
"""

import json as json_module
from pathlib import Path
from typing import Any

import typer

from .cli_display import display_version_info
from .cli_parsing import (
    check_version_type_match,
    parse_multi_value_option,
    validate_version_types,
)
from .cli_runtime import (
    EXIT_VALIDATION_FAILED,
    console,
    log_unexpected_error,
    logger,
    suppress_logging_for_json,
)
from .models import VersionInfo
from .validation import TagValidator

DEVELOPMENT_KEYWORDS = [
    "dev",
    "pre",
    "alpha",
    "beta",
    "rc",
    "snapshot",
    "nightly",
    "canary",
    "preview",
]

EMPTY_VERSION_INFO = [
    "version_string parameter is required but was not provided or is empty",
    "Expected formats: 'v1.0.0' (SemVer), '2024.01.15' (CalVer), or other version strings",
]


def _require_version_string(version_string: str, json_output: bool) -> None:
    """Fail when no version string was supplied.

    Raises:
        typer.Exit: If the version string is empty or whitespace only
    """
    if version_string and version_string.strip():
        return

    error_msg = "Version string is empty or null"
    if json_output:
        console.print_json(
            data={
                "success": False,
                "version": "",
                "error": error_msg,
                "info": EMPTY_VERSION_INFO,
            }
        )
    else:
        console.print(f"\n[red]❌ Error:[/red] {error_msg}")
        console.print("\n[yellow]ℹ️  Info:[/yellow]")
        for info in EMPTY_VERSION_INFO:
            console.print(f"  • {info}")
    raise typer.Exit(1)


def _unvalidated_version_info(version_string: str) -> VersionInfo:
    """Build a permissive result for ``--require-type none`` inputs."""
    return VersionInfo(
        raw=version_string,
        normalized=version_string,
        version_type="other",
        is_valid=True,
        has_prefix=version_string[0:1] in ("v", "V") if version_string else False,
        is_development=any(kw in version_string.lower() for kw in DEVELOPMENT_KEYWORDS),
        # SemVer fields (all None for other type)
        major=None,
        minor=None,
        patch=None,
        prerelease=None,
        build_metadata=None,
        # CalVer fields (all None for unknown type)
        year=None,
        month=None,
        day=None,
        micro=None,
        modifier=None,
        errors=[],
    )


def _validate_version_string(
    version_string: str,
    require_type: str | None,
    allow_prefix: bool,
    strict_semver: bool,
) -> VersionInfo:
    """Validate the version string, honouring ``--require-type none``."""
    validator = TagValidator()
    result = validator.validate_version(
        version_string,
        allow_prefix=allow_prefix,
        strict_semver=strict_semver,
    )

    # Handle require_type=none - accept any format without validation
    if require_type and require_type.lower() == "none" and not result.is_valid:
        # Create a successful result for unknown format
        return _unvalidated_version_info(version_string)

    return result


def _check_required_types(
    result: VersionInfo,
    require_type: str | None,
    version_string: str,
    json_output: bool,
) -> None:
    """Enforce ``--require-type`` against the detected version type.

    Raises:
        typer.Exit: If the detected type is not one of the required types
    """
    if not require_type or not result.is_valid:
        return

    # Parse and validate types
    require_type_list = parse_multi_value_option(require_type)
    validate_version_types(require_type_list)

    # Check if result matches required types
    if check_version_type_match(result.version_type, require_type_list):
        return

    if json_output:
        console.print_json(
            data={
                "success": False,
                "error": f"Version type mismatch: expected {', '.join(require_type_list)}, got {result.version_type}",
                "version": version_string,
                "detected_type": result.version_type,
                "required_types": require_type_list,
            }
        )
    else:
        console.print(
            f"\n[red]❌ Version type mismatch:[/red] "
            f"expected {', '.join(require_type_list)}, got {result.version_type}"
        )
    raise typer.Exit(EXIT_VALIDATION_FAILED)


def _semver_fields(result: VersionInfo) -> dict[str, Any]:
    """Return the SemVer components of a validation result."""
    return {
        "major": result.major,
        "minor": result.minor,
        "patch": result.patch,
        "prerelease": result.prerelease,
        "build_metadata": result.build_metadata,
    }


def _calver_fields(result: VersionInfo) -> dict[str, Any]:
    """Return the CalVer components of a validation result."""
    return {
        "year": result.year,
        "month": result.month,
        "day": result.day,
        "micro": result.micro,
        "modifier": result.modifier,
    }


def _reparsed_calver_fields(result: VersionInfo) -> dict[str, Any]:
    """Return CalVer components obtained by re-parsing a "both" result."""
    validator = TagValidator()
    calver_result = validator.validate_calver(result.normalized or result.raw)
    if not calver_result.is_valid:
        return dict.fromkeys(("year", "month", "day", "micro", "modifier"))
    return _calver_fields(calver_result)


def _build_console_output(result: VersionInfo, version_string: str) -> dict[str, Any]:
    """Build the JSON payload printed to the console."""
    output: dict[str, Any] = {
        "success": result.is_valid,
        "version": version_string,
        "normalized": result.normalized,
        "version_type": result.version_type,
        "is_valid": result.is_valid,
        "development_tag": result.is_development,
        "version_prefix": result.has_prefix,
    }

    # Add type-specific fields
    if result.version_type == "semver":
        output.update(_semver_fields(result))
    elif result.version_type == "calver":
        output.update(_calver_fields(result))
    elif result.version_type == "both":
        # For 'both' type, include SemVer fields from result and CalVer fields by re-parsing
        output.update(_semver_fields(result))
        output.update(_reparsed_calver_fields(result))

    if not result.is_valid:
        output["errors"] = result.errors

    return output


def _build_file_output(result: VersionInfo) -> dict[str, Any]:
    """Build the JSON payload written to ``--json-file``."""
    output: dict[str, Any] = {
        "success": result.is_valid,
        "version": result.raw,
        "detected_type": result.version_type,
        "is_development": result.is_development,
        "has_prefix": result.has_prefix,
        "version_prefix": result.has_prefix,
    }

    # Add type-specific fields
    if result.version_type == "semver":
        output.update(_semver_fields(result))
    elif result.version_type == "calver":
        output.update(_calver_fields(result))

    if not result.is_valid:
        output["errors"] = result.errors

    return output


def write_json_file(json_file: Path, output: dict[str, Any]) -> None:
    """Write a JSON payload to disk, logging (but not raising) failures."""
    try:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        with json_file.open("w", encoding="utf-8") as f:
            json_module.dump(output, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to write JSON to file {json_file}: {e}")


def run_validate(
    *,
    version_string: str,
    require_type: str | None,
    allow_prefix: bool,
    strict_semver: bool,
    json_output: bool,
    json_file: Path | None,
) -> None:
    """Validate a version string against SemVer or CalVer patterns."""
    try:
        # Suppress ALL logs when JSON output is requested
        if json_output:
            suppress_logging_for_json()

        _require_version_string(version_string, json_output)

        result = _validate_version_string(
            version_string, require_type, allow_prefix, strict_semver
        )
        _check_required_types(result, require_type, version_string, json_output)

        # Output results
        if json_output:
            console.print_json(data=_build_console_output(result, version_string))
        else:
            display_version_info(result, version_string)

        # Write JSON to file if requested
        if json_file and not json_output:
            write_json_file(json_file, _build_file_output(result))

        # Exit with appropriate code
        if result.is_valid:
            raise typer.Exit(0)
        else:
            raise typer.Exit(1)

    except typer.Exit:
        raise
    except Exception as e:
        if json_output:
            console.print_json(data={"success": False, "error": str(e)})
        else:
            console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
            log_unexpected_error("Unexpected error during version validation", e)
        raise typer.Exit(1) from e
