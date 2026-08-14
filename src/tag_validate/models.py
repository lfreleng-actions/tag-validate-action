# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Pydantic models for tag validation.

This module defines type-safe data structures for:
- Tag information and metadata
- Signature information (GPG, SSH)
- GitHub key registry data
- Version validation results
- Complete validation workflow results

Key and check models live in the sibling modules
:mod:`tag_validate.models_keys` and :mod:`tag_validate.models_checks`;
they are re-exported here so ``tag_validate.models`` remains the single
import point for all model types.
"""

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from .models_checks import (
    BranchCheckInfo,
    IncrementCheckInfo,
    LatestCheckInfo,
    TagAgeCheckInfo,
    VersionInfo,
)
from .models_keys import (
    GerritAccountInfo,
    GerritGPGKeyInfo,
    GerritSSHKeyInfo,
    GitHubVerificationInfo,
    GPGKeyInfo,
    KeyVerificationResult,
    SSHKeyInfo,
)


class TagInfo(BaseModel):
    """Information about a Git tag."""

    tag_name: str = Field(..., description="Tag name (e.g., 'v1.2.3')")
    tag_type: Literal["lightweight", "annotated"] = Field(
        ..., description="Type of tag (lightweight or annotated)"
    )
    commit_sha: str = Field(..., description="Commit SHA that the tag points to")
    tagger_name: str | None = Field(
        default=None, description="Name of the person who created the tag"
    )
    tagger_email: str | None = Field(
        default=None, description="Email of the person who created the tag"
    )
    tag_date: str | None = Field(
        default=None, description="ISO 8601 timestamp when tag was created"
    )
    tag_message: str | None = Field(
        default=None, description="Tag message (for annotated tags)"
    )
    remote_url: str | None = Field(
        default=None, description="Remote repository URL if applicable"
    )


class SignatureInfo(BaseModel):
    """Information about a tag's cryptographic signature."""

    type: Literal[
        "gpg", "ssh", "unsigned", "lightweight", "invalid", "gpg-unverifiable"
    ] = Field(..., description="Type of signature or reason for no signature")
    verified: bool = Field(
        default=False, description="Whether the signature was verified locally"
    )
    key_id: str | None = Field(
        default=None, description="GPG key ID (short or long form)"
    )
    fingerprint: str | None = Field(
        default=None, description="Full key fingerprint (GPG or SSH)"
    )
    signer_email: str | None = Field(
        default=None, description="Email address from the signature"
    )
    signature_data: str | None = Field(default=None, description="Raw signature data")


class ValidationConfig(BaseModel):
    """Configuration for tag validation workflow."""

    # Version requirements
    require_semver: bool = Field(
        default=False, description="Require Semantic Versioning"
    )
    require_calver: bool = Field(
        default=False, description="Require Calendar Versioning"
    )
    skip_version_validation: bool = Field(
        default=False, description="Skip version format validation"
    )

    # Signature requirements
    require_signed: bool = Field(default=False, description="Require tag to be signed")
    require_unsigned: bool = Field(
        default=False, description="Require tag to be unsigned"
    )
    allowed_signature_types: list[str] | None = Field(
        default=None,
        description="Specific signature types allowed (gpg, ssh, gpg-unverifiable, unsigned)",
    )

    # GitHub verification
    require_github: bool = Field(
        default=False, description="Verify signing key on GitHub"
    )

    # Gerrit verification
    require_gerrit: bool = Field(
        default=False, description="Verify signing key on Gerrit"
    )
    gerrit_server: str | None = Field(
        default=None, description="Gerrit server hostname or URL"
    )

    # Version filtering
    reject_development: bool = Field(
        default=False, description="Reject development versions"
    )
    allow_prefix: bool = Field(default=True, description="Allow 'v' prefix on versions")

    # Release gating
    enforce_increment: bool = Field(
        default=False,
        description=(
            "Require the tag to be strictly greater than the highest "
            "existing comparable tag in the repository"
        ),
    )
    require_branch: str | None = Field(
        default=None,
        description=(
            "Require the tag commit to be reachable from this branch. "
            "Use 'true' to auto-detect the repository default branch."
        ),
    )
    max_tag_age_minutes: float | None = Field(
        default=None,
        description=(
            "Require the tag to have been created within this many "
            "minutes (None disables the check)"
        ),
    )
    require_latest: bool = Field(
        default=False,
        description=(
            "Require the tag commit to be the current tip of the "
            "target branch (require_branch when set, otherwise the "
            "repository default branch)"
        ),
    )

    # Configuration metadata
    config_source: str | None = Field(
        default=None, description="Source of configuration"
    )


class ValidationResult(BaseModel):
    """Complete validation result for a tag."""

    tag_name: str = Field(..., description="Name of the validated tag")
    is_valid: bool = Field(default=True, description="Overall validation result")

    # Component results
    tag_info: TagInfo | None = Field(default=None, description="Tag metadata")
    version_info: VersionInfo | None = Field(
        default=None, description="Version validation result"
    )
    signature_info: SignatureInfo | None = Field(
        default=None, description="Signature information"
    )
    key_verifications: list[KeyVerificationResult] = Field(
        default_factory=list,
        description="List of key verification results (GitHub and/or Gerrit)",
    )
    increment_check: IncrementCheckInfo | None = Field(
        default=None, description="Tag increment (ordering) check result"
    )
    branch_check: BranchCheckInfo | None = Field(
        default=None, description="Branch containment check result"
    )
    age_check: TagAgeCheckInfo | None = Field(
        default=None, description="Tag age (freshness) check result"
    )
    latest_check: LatestCheckInfo | None = Field(
        default=None, description="Latest-commit (branch tip) check result"
    )

    # Validation configuration used
    config: ValidationConfig = Field(
        ..., description="Configuration used for validation"
    )

    # Messages
    errors: list[str] = Field(default_factory=list, description="Validation errors")
    warnings: list[str] = Field(default_factory=list, description="Validation warnings")
    info: list[str] = Field(default_factory=list, description="Informational messages")

    # Metadata
    validated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="When validation was performed",
    )

    def add_error(self, message: str) -> None:
        """Add an error message and mark validation as failed."""
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        """Add a warning message."""
        self.warnings.append(message)

    def add_info(self, message: str) -> None:
        """Add an informational message."""
        self.info.append(message)


class RepositoryInfo(BaseModel):
    """Information about a repository containing tags."""

    owner: str = Field(..., description="Repository owner (org or user)")
    name: str = Field(..., description="Repository name")
    clone_url: str = Field(..., description="HTTPS clone URL")
    web_url: str | None = Field(default=None, description="Web URL to repository")
    tag: str | None = Field(default=None, description="Specific tag being validated")


__all__ = [
    "BranchCheckInfo",
    "GPGKeyInfo",
    "GerritAccountInfo",
    "GerritGPGKeyInfo",
    "GerritSSHKeyInfo",
    "GitHubVerificationInfo",
    "IncrementCheckInfo",
    "KeyVerificationResult",
    "LatestCheckInfo",
    "RepositoryInfo",
    "SSHKeyInfo",
    "SignatureInfo",
    "TagAgeCheckInfo",
    "TagInfo",
    "ValidationConfig",
    "ValidationResult",
    "VersionInfo",
]
