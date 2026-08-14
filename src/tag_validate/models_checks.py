# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Pydantic models for version parsing and release-gating checks.

Covers parsed version strings and the outcome of the increment, branch
containment, tag age, and latest-commit checks.
"""

from typing import Literal

from pydantic import BaseModel, Field


class VersionInfo(BaseModel):
    """Information about version string parsing and validation."""

    raw: str = Field(..., description="Original version string")
    normalized: str | None = Field(
        default=None, description="Normalized version string (without prefix)"
    )
    is_valid: bool = Field(default=False, description="Whether version is valid")
    version_type: Literal["semver", "calver", "both", "other"] = Field(
        default="other", description="Type of version format detected"
    )
    has_prefix: bool = Field(
        default=False, description="Whether version has 'v' or 'V' prefix"
    )
    is_development: bool = Field(
        default=False,
        description="Whether version is a development/pre-release version",
    )

    # SemVer fields
    major: int | None = Field(default=None, description="Major version number (SemVer)")
    minor: int | None = Field(default=None, description="Minor version number (SemVer)")
    patch: int | None = Field(default=None, description="Patch version number (SemVer)")
    prerelease: str | None = Field(
        default=None, description="Pre-release identifier (SemVer)"
    )
    build_metadata: str | None = Field(
        default=None, description="Build metadata (SemVer)"
    )

    # CalVer fields
    year: int | None = Field(default=None, description="Year (CalVer)")
    month: int | None = Field(default=None, description="Month (CalVer)")
    day: int | None = Field(default=None, description="Day (CalVer)")
    micro: int | None = Field(default=None, description="Micro version (CalVer)")
    modifier: str | None = Field(default=None, description="Version modifier (CalVer)")

    # Validation errors
    errors: list[str] = Field(default_factory=list, description="Validation errors")


class IncrementCheckInfo(BaseModel):
    """Result of checking that a tag increments the repository version."""

    checked: bool = Field(
        default=False, description="Whether the increment check was performed"
    )
    incremental: bool | None = Field(
        default=None,
        description=(
            "Whether the tag is strictly greater than every existing "
            "comparable tag (None when not checked or indeterminate)"
        ),
    )
    latest_tag: str | None = Field(
        default=None,
        description=(
            "Baseline tag for reporting: the tag that blocked the push "
            "when the check fails, otherwise the highest existing tag "
            "under the scheme with the most comparable tags"
        ),
    )
    latest_tags: dict[str, str] = Field(
        default_factory=dict,
        description="Highest existing comparable tag per versioning scheme",
    )
    candidate_count: int = Field(
        default=0, description="Number of existing comparable tags considered"
    )
    scheme: str | None = Field(
        default=None,
        description="Versioning scheme(s) used for comparison",
    )
    tag_source: str | None = Field(
        default=None,
        description="Source used to enumerate repository tags (api, git, api+git)",
    )
    errors: list[str] = Field(
        default_factory=list, description="Errors encountered during the check"
    )


class BranchCheckInfo(BaseModel):
    """Result of checking that a tag's commit is reachable from a branch."""

    checked: bool = Field(
        default=False, description="Whether the branch containment check was performed"
    )
    branch: str | None = Field(
        default=None, description="Branch the tag commit was verified against"
    )
    contains: bool | None = Field(
        default=None,
        description=(
            "Whether the tag commit is reachable from the branch "
            "(None when not checked or indeterminate)"
        ),
    )
    method: str | None = Field(
        default=None, description="Method used for the check (api or git)"
    )
    errors: list[str] = Field(
        default_factory=list, description="Errors encountered during the check"
    )


class TagAgeCheckInfo(BaseModel):
    """Result of checking that a tag was created recently."""

    checked: bool = Field(
        default=False, description="Whether the tag age check was performed"
    )
    recent: bool | None = Field(
        default=None,
        description=(
            "Whether the tag was created within the allowed window "
            "(None when not checked or indeterminate)"
        ),
    )
    tag_date: str | None = Field(
        default=None, description="ISO 8601 timestamp when the tag was created"
    )
    age_seconds: float | None = Field(
        default=None, description="Age of the tag at validation time, in seconds"
    )
    max_age_minutes: float | None = Field(
        default=None, description="Maximum permitted tag age, in minutes"
    )
    errors: list[str] = Field(
        default_factory=list, description="Errors encountered during the check"
    )


class LatestCheckInfo(BaseModel):
    """Result of checking that a tag points to the tip of a branch."""

    checked: bool = Field(
        default=False, description="Whether the latest-commit check was performed"
    )
    latest: bool | None = Field(
        default=None,
        description=(
            "Whether the tag commit is the current tip of the branch "
            "(None when not checked or indeterminate)"
        ),
    )
    branch: str | None = Field(
        default=None, description="Branch the tag commit was compared against"
    )
    tag_sha: str | None = Field(
        default=None, description="Commit SHA the tag points to"
    )
    branch_sha: str | None = Field(
        default=None, description="Commit SHA at the tip of the branch"
    )
    method: str | None = Field(
        default=None, description="Method used for the check (api or git)"
    )
    errors: list[str] = Field(
        default_factory=list, description="Errors encountered during the check"
    )


__all__ = [
    "BranchCheckInfo",
    "IncrementCheckInfo",
    "LatestCheckInfo",
    "TagAgeCheckInfo",
    "VersionInfo",
]
