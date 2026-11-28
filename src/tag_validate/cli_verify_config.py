# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Translation of ``tag-validate verify`` options into a ValidationConfig.

The ``verify`` command exposes its requirements as loosely typed strings
so GitHub Actions inputs can be forwarded verbatim; this module parses
them and assembles the typed configuration the workflow needs.
"""

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, NamedTuple, cast

from .cli_credentials import (
    NetrcLookup,
    probe_netrc_for_discovery,
    resolve_netrc_credentials,
)
from .cli_parsing import (
    parse_multi_value_option,
    validate_signature_types,
    validate_version_types,
)
from .cli_runtime import reject_input as _reject_input
from .cli_verify_gpg import GpgTrust, parse_gpg_trust
from .increment_check import DEFAULT_TAG_AGE_MINUTES
from .models import ValidationConfig

FALSE_VALUES = ("false", "no", "0")
TRUE_VALUES = ("true", "yes", "1")


@dataclass(frozen=True)
class VerifyOptions:
    """Every option accepted by the ``verify`` command, as supplied."""

    tag_location: str
    repo_path: Path
    require_type: str | None
    require_signed: str | None
    require_github: bool
    require_gerrit: str | None
    owner: str | None
    require_owner: str | None
    github_token: str | None
    gerrit_username: str | None
    gerrit_password: str | None
    no_netrc: bool
    netrc_file: Path | None
    netrc_optional: bool
    reject_development: bool
    enforce_increment: bool
    require_branch: str | None
    require_recent: str | None
    reference_time: str | None
    reference_source: str | None
    require_latest: bool
    skip_version_validation: bool
    permit_missing: bool
    json_output: bool
    json_file: Path | None
    github_step_summary: bool
    trusted_gpg_keys: Path | None = None
    require_fingerprint: str | None = None
    permit_expired_key: bool = False


@dataclass(frozen=True)
class VerifyPlan:
    """Everything derived from the CLI options before validation runs."""

    config: ValidationConfig
    require_owner_list: list[str]
    gerrit_username: str | None
    gerrit_password: str | None


class DerivedRequirements(NamedTuple):
    """Requirements parsed out of the raw ``verify`` option strings."""

    signatures: "SignatureRequirements"
    gpg_trust: GpgTrust
    version_types: list[str]
    require_github: bool
    require_gerrit: bool
    gerrit_server: str | None
    max_tag_age_minutes: float | None
    reference: "AgeReference"


class AgeReference(NamedTuple):
    """Reference instant for the tag age check, parsed from the CLI."""

    time: datetime | None
    source: Literal["push_event", "supplied"] | None


REFERENCE_SOURCES = ("push_event", "supplied")
_EPOCH_SECONDS = re.compile(r"[0-9]+")


class SignatureRequirements(NamedTuple):
    """Signature expectations parsed from ``--require-signed``."""

    require_signed: bool
    require_unsigned: bool
    allowed_types: list[str] | None


def parse_signature_requirements(require_signed: str | None) -> SignatureRequirements:
    """Parse the multi-value ``--require-signed`` option.

    Supports: gpg, ssh, gpg-unverifiable, unsigned (comma or space-separated)
    """
    if not require_signed:
        return SignatureRequirements(False, False, None)

    # Parse and validate signature types
    require_signed_types = parse_multi_value_option(require_signed)
    validate_signature_types(require_signed_types)

    if "unsigned" in require_signed_types:
        # If unsigned is mixed with other types, store all types
        mixed = len(require_signed_types) > 1
        return SignatureRequirements(
            False, True, require_signed_types if mixed else None
        )

    if require_signed_types:
        # Store specific signature types for validation
        return SignatureRequirements(True, False, require_signed_types)

    return SignatureRequirements(False, False, None)


def parse_version_requirements(
    require_type: str | None, skip_version_validation: bool
) -> list[str]:
    """Parse the multi-value ``--require-type`` option."""
    if not require_type or skip_version_validation:
        return []

    # Parse and validate types
    require_type_list = parse_multi_value_option(require_type)
    validate_version_types(require_type_list)
    # Filter out 'none' - it means no requirement
    return [t for t in require_type_list if t != "none"]


def parse_gerrit_requirement(require_gerrit: str | None) -> tuple[bool, str | None]:
    """Parse ``--require-gerrit`` into an enabled flag and server name."""
    if not require_gerrit:
        return False, None

    if require_gerrit.lower() in TRUE_VALUES:
        # Server will be auto-discovered in the workflow
        return True, None

    if require_gerrit.lower() not in FALSE_VALUES:
        # Treat as server hostname/URL
        return True, require_gerrit

    return False, None


def _parse_instant(value: str) -> datetime | None:
    """Parse ISO 8601 or integer Unix epoch seconds as an aware datetime."""
    try:
        if _EPOCH_SECONDS.fullmatch(value):
            return datetime.fromtimestamp(int(value), UTC)
        parsed = datetime.fromisoformat(value)
    except (ValueError, OverflowError, OSError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_reference_time(
    reference_time: str | None, reference_source: str | None, json_output: bool
) -> AgeReference:
    """Parse ``--reference-time`` and ``--reference-source``.

    Args:
        reference_time: ISO 8601 timestamp or integer Unix epoch seconds
        reference_source: 'push_event', 'supplied', or None ('supplied')
        json_output: Whether the command is emitting JSON

    Returns:
        The reference instant and its source, or (None, None) to
        measure against the clock

    Raises:
        typer.Exit: If either value is invalid, or a source is given
            without a time
    """
    time_value = (reference_time or "").strip()
    source_value = (reference_source or "").strip().lower()

    if source_value and source_value not in REFERENCE_SOURCES:
        raise _reject_input(
            f"Invalid --reference-source value '{reference_source}': "
            f"pass one of {', '.join(REFERENCE_SOURCES)}",
            json_output,
        )
    if not time_value:
        if source_value:
            raise _reject_input(
                "--reference-source requires --reference-time", json_output
            )
        return AgeReference(None, None)

    parsed = _parse_instant(time_value)
    if parsed is None:
        raise _reject_input(
            f"Invalid --reference-time value '{reference_time}': pass "
            "an ISO 8601 timestamp or integer Unix epoch seconds",
            json_output,
        )
    source = cast(Literal["push_event", "supplied"], source_value or "supplied")
    return AgeReference(parsed, source)


def parse_recent_requirement(
    require_recent: str | None, json_output: bool
) -> float | None:
    """Parse ``--require-recent`` into a maximum tag age in minutes.

    Args:
        require_recent: Raw option value: 'true', a number, or a falsey word
        json_output: Whether the command is emitting JSON

    Returns:
        The maximum tag age in minutes, or None when not required

    Raises:
        typer.Exit: If the value is neither 'true' nor a positive number
    """
    require_recent_value = (require_recent or "").strip().lower()
    if not require_recent_value or require_recent_value in FALSE_VALUES:
        return None

    if require_recent_value in ("true", "yes"):
        return DEFAULT_TAG_AGE_MINUTES

    try:
        max_tag_age_minutes: float | None = float(require_recent_value)
    except ValueError:
        max_tag_age_minutes = None

    if (
        max_tag_age_minutes is None
        or not math.isfinite(max_tag_age_minutes)
        or max_tag_age_minutes <= 0
    ):
        raise _reject_input(
            f"Invalid --require-recent value "
            f"'{require_recent}': pass 'true' or a "
            "positive number of minutes",
            json_output,
        )

    return max_tag_age_minutes


def resolve_verify_credentials(
    options: VerifyOptions, credentials_lookup: Any
) -> tuple[str | None, str | None]:
    """Resolve Gerrit credentials: CLI args > netrc > environment.

    This runs before ``--require-gerrit`` is parsed so credentials are
    available whenever Gerrit verification has been requested.
    """
    username = options.gerrit_username
    password = options.gerrit_password
    if not options.require_gerrit or (username and password) or options.no_netrc:
        return username, password

    if options.require_gerrit == "true":
        # Auto-discovery pattern: we don't know the host yet, but we can
        # validate that .netrc exists and is parseable when
        # --netrc-required is set. The actual credential lookup will
        # happen later in GerritKeysClient.
        probe_netrc_for_discovery(
            options.netrc_file, options.netrc_optional, options.json_output
        )
        return username, password

    # Specific server provided
    return resolve_netrc_credentials(
        NetrcLookup(
            host=options.require_gerrit,
            netrc_file=options.netrc_file,
            netrc_optional=options.netrc_optional,
            json_output=options.json_output,
        ),
        username,
        password,
        credentials_lookup,
    )


def _normalize_branch_requirement(require_branch: str | None) -> str | None:
    """Normalize ``--require-branch``, tolerating stray whitespace."""
    # Whitespace-tolerant normalization: workflow inputs may carry stray
    # spaces around a branch name or sentinel value
    require_branch_value = (require_branch or "").strip()
    if require_branch_value and require_branch_value.lower() not in FALSE_VALUES:
        return require_branch_value
    return None


def _build_validation_config(
    options: VerifyOptions, derived: DerivedRequirements
) -> ValidationConfig:
    """Assemble the ValidationConfig described by the CLI options."""
    version_types = derived.version_types
    skip_versions = options.skip_version_validation
    return ValidationConfig(
        require_semver=(
            ("semver" in version_types or "both" in version_types)
            if version_types
            else False
        ),
        require_calver=(
            ("calver" in version_types or "both" in version_types)
            if version_types
            else False
        ),
        require_signed=derived.signatures.require_signed,
        require_unsigned=derived.signatures.require_unsigned,
        allowed_signature_types=(
            derived.signatures.allowed_types if options.require_signed else None
        ),
        trusted_gpg_keys=derived.gpg_trust.trusted_gpg_keys,
        require_fingerprints=derived.gpg_trust.require_fingerprints,
        permit_expired_key=options.permit_expired_key,
        require_github=derived.require_github,
        require_gerrit=derived.require_gerrit,
        gerrit_server=derived.gerrit_server,
        reject_development=options.reject_development if not skip_versions else False,
        skip_version_validation=skip_versions,
        allow_prefix=True,  # Default to allowing version prefixes
        enforce_increment=options.enforce_increment,
        require_branch=_normalize_branch_requirement(options.require_branch),
        max_tag_age_minutes=derived.max_tag_age_minutes,
        tag_age_reference_time=derived.reference.time,
        tag_age_reference_source=derived.reference.source,
        require_latest=options.require_latest,
        config_source="CLI",  # Mark as CLI-originated config
    )


def build_verify_plan(options: VerifyOptions, credentials_lookup: Any) -> VerifyPlan:
    """Parse every requirement option into a ready-to-run plan."""
    signatures = parse_signature_requirements(options.require_signed)
    gpg_trust = parse_gpg_trust(
        options.trusted_gpg_keys, options.require_fingerprint, options.json_output
    )
    version_types = parse_version_requirements(
        options.require_type, options.skip_version_validation
    )
    require_owner_list = parse_multi_value_option(options.require_owner)
    # When require_owner is specified, require_github is implied
    require_github = True if options.require_owner else options.require_github

    gerrit_username, gerrit_password = resolve_verify_credentials(
        options, credentials_lookup
    )
    require_gerrit, gerrit_server = parse_gerrit_requirement(options.require_gerrit)
    max_tag_age_minutes = parse_recent_requirement(
        options.require_recent, options.json_output
    )
    reference = parse_reference_time(
        options.reference_time, options.reference_source, options.json_output
    )

    derived = DerivedRequirements(
        signatures=signatures,
        gpg_trust=gpg_trust,
        version_types=version_types,
        require_github=require_github,
        require_gerrit=require_gerrit,
        gerrit_server=gerrit_server,
        max_tag_age_minutes=max_tag_age_minutes,
        reference=reference,
    )
    return VerifyPlan(
        config=_build_validation_config(options, derived),
        require_owner_list=require_owner_list,
        gerrit_username=gerrit_username,
        gerrit_password=gerrit_password,
    )
