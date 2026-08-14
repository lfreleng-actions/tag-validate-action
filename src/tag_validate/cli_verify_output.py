# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
JSON payload construction for the ``tag-validate verify`` command.

The console and ``--json-file`` payloads share most of their structure
but differ in a handful of keys; this module builds both and maps a
validation result onto the command's exit code.
"""

from typing import Any

import typer

from .cli_runtime import (
    EXIT_AUTH_FAILED,
    EXIT_BRANCH_CHECK_FAILED,
    EXIT_MISSING_CREDENTIALS,
    EXIT_MISSING_TOKEN,
    EXIT_NOT_INCREMENTAL,
    EXIT_NOT_LATEST,
    EXIT_SUCCESS,
    EXIT_TAG_NOT_RECENT,
    EXIT_VALIDATION_FAILED,
)


def missing_tag_output(tag_name: str) -> dict[str, Any]:
    """Build the result reported for a missing tag under --permit-missing."""
    return {
        "success": True,
        "tag_name": tag_name,
        "version_type": "other",
        "signature_type": "unsigned",
        "signature_verified": False,
        "key_registered": None,
        "is_development": False,
        "development_tag": False,
        "has_prefix": False,
        "version_prefix": False,
        "errors": [],
        "warnings": ["Tag not found but permit_missing=true"],
        "info": ["Tag was not found"],
    }


def _signature_details(result: Any) -> dict[str, Any]:
    """Build the signature detail block."""
    return {
        "signer_email": result.signature_info.signer_email,
        "key_id": result.signature_info.key_id,
        "fingerprint": result.signature_info.fingerprint,
    }


def _version_details(result: Any) -> dict[str, Any]:
    """Build the version detail block, including type-specific components."""
    details: dict[str, Any] = {
        "raw": result.version_info.raw,
        "normalized": result.version_info.normalized,
    }
    if result.version_info.version_type == "semver":
        details["semver"] = {
            "major": result.version_info.major,
            "minor": result.version_info.minor,
            "patch": result.version_info.patch,
            "prerelease": result.version_info.prerelease,
            "build_metadata": result.version_info.build_metadata,
        }
    elif result.version_info.version_type == "calver":
        details["calver"] = {
            "year": result.version_info.year,
            "month": result.version_info.month,
            "day": result.version_info.day,
            "micro": result.version_info.micro,
        }
    return details


def _add_gating_results(output: dict[str, Any], result: Any) -> None:
    """Add increment/branch/age/latest gating results when checks ran."""
    if result.increment_check and result.increment_check.checked:
        output["incremental"] = result.increment_check.incremental
        output["latest_tag"] = result.increment_check.latest_tag
        output["latest_tags"] = result.increment_check.latest_tags
    if result.branch_check and result.branch_check.checked:
        output["branch"] = result.branch_check.branch
        output["branch_valid"] = result.branch_check.contains
    if result.age_check and result.age_check.checked:
        output["recent"] = result.age_check.recent
        output["tag_age_seconds"] = result.age_check.age_seconds
        output["max_tag_age_minutes"] = result.age_check.max_age_minutes
    if result.latest_check and result.latest_check.checked:
        output["latest"] = result.latest_check.latest
        output["latest_branch"] = result.latest_check.branch
        output["branch_sha"] = result.latest_check.branch_sha


def _common_output(result: Any) -> dict[str, Any]:
    """Build the fields shared by the console and file payloads."""
    return {
        "success": result.is_valid,
        "tag_name": result.tag_name,
        "version_type": (
            result.version_info.version_type if result.version_info else None
        ),
        "signature_type": result.signature_info.type if result.signature_info else None,
        "signature_verified": (
            result.signature_info.verified if result.signature_info else None
        ),
    }


def _tail_output(result: Any) -> dict[str, Any]:
    """Build the trailing fields shared by the console and file payloads."""
    return {
        "development_tag": (
            result.version_info.is_development if result.version_info else False
        ),
        "version_prefix": (
            result.version_info.has_prefix if result.version_info else False
        ),
        "errors": result.errors,
        "warnings": result.warnings,
        "info": result.info,
    }


def build_console_output(result: Any) -> dict[str, Any]:
    """Build the JSON payload printed to the console."""
    output = _common_output(result)
    output.update(_tail_output(result))

    # Add signature details if available
    if result.signature_info:
        output["signature_details"] = _signature_details(result)

    # Add version details if available
    if result.version_info:
        output["version_details"] = _version_details(result)

    # Add key verification details if available
    if result.key_verifications:
        output["key_verifications"] = [
            {
                "service": k.service,
                "key_registered": k.key_registered,
                "server": k.server,
                "username": k.username,
                "user_email": k.user_email,
                "user_name": k.user_name,
            }
            for k in result.key_verifications
        ]

    _add_gating_results(output, result)
    return output


def build_file_output(result: Any) -> dict[str, Any]:
    """Build the JSON payload written to ``--json-file``."""
    output = _common_output(result)
    output["key_registered"] = (
        result.key_verifications[0].key_registered if result.key_verifications else None
    )
    output.update(_tail_output(result))

    # Add signature details if available
    if result.signature_info:
        output["signature_details"] = _signature_details(result)

    # Add version details if available
    if result.version_info:
        output["version_details"] = _version_details(result)

    # Add key verifications (GitHub and/or Gerrit)
    if result.key_verifications:
        output["key_verifications"] = [
            {
                "service": k.service,
                "server": k.server,
                "key_registered": k.key_registered,
                "username": k.username,
                "user_email": k.user_email,
                "user_name": k.user_name,
                "user_enumerated": k.user_enumerated,
            }
            for k in result.key_verifications
        ]

    _add_gating_results(output, result)
    return output


# Structural gate failures, checked before falling back to error text
_GATE_EXIT_CODES = [
    ("increment_check", "incremental", EXIT_NOT_INCREMENTAL),
    ("branch_check", "contains", EXIT_BRANCH_CHECK_FAILED),
    ("age_check", "recent", EXIT_TAG_NOT_RECENT),
    ("latest_check", "latest", EXIT_NOT_LATEST),
]


def _failure_exit_code(result: Any) -> int:
    """Determine the exit code for a failed validation result."""
    # Structural failures first (not string matching)
    for check_name, attribute, exit_code in _GATE_EXIT_CODES:
        check = getattr(result, check_name)
        if check and check.checked and getattr(check, attribute) is not True:
            return exit_code

    # Check for specific error types and return appropriate exit codes
    error_messages = " ".join(result.errors).lower()

    # Check for missing GitHub token
    if "token" in error_messages and "github" in error_messages:
        return EXIT_MISSING_TOKEN
    # Check for missing Gerrit credentials
    if (
        "credentials not provided" in error_messages
        or "credentials required" in error_messages
    ):
        return EXIT_MISSING_CREDENTIALS
    # Check for invalid Gerrit credentials
    if (
        "authentication failed" in error_messages
        or "invalid credentials" in error_messages
    ):
        return EXIT_AUTH_FAILED
    return EXIT_VALIDATION_FAILED


def exit_for_result(result: Any) -> None:
    """Exit with the code that matches the validation result.

    Raises:
        typer.Exit: Always
    """
    if result.is_valid:
        raise typer.Exit(EXIT_SUCCESS)
    raise typer.Exit(_failure_exit_code(result))
