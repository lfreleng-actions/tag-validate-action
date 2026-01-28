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
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


class TagInfo(BaseModel):
    """Information about a Git tag."""

    tag_name: str = Field(..., description="Tag name (e.g., 'v1.2.3')")
    tag_type: Literal["lightweight", "annotated"] = Field(
        ..., description="Type of tag (lightweight or annotated)"
    )
    commit_sha: str = Field(..., description="Commit SHA that the tag points to")
    tagger_name: Optional[str] = Field(None, description="Name of the person who created the tag")
    tagger_email: Optional[str] = Field(None, description="Email of the person who created the tag")
    tag_date: Optional[str] = Field(None, description="ISO 8601 timestamp when tag was created")
    tag_message: Optional[str] = Field(None, description="Tag message (for annotated tags)")
    remote_url: Optional[str] = Field(None, description="Remote repository URL if applicable")


class SignatureInfo(BaseModel):
    """Information about a tag's cryptographic signature."""

    type: Literal["gpg", "ssh", "unsigned", "lightweight", "invalid", "gpg-unverifiable"] = Field(
        ..., description="Type of signature or reason for no signature"
    )
    verified: bool = Field(False, description="Whether the signature was verified locally")
    key_id: Optional[str] = Field(None, description="GPG key ID (short or long form)")
    fingerprint: Optional[str] = Field(None, description="Full key fingerprint (GPG or SSH)")
    signer_email: Optional[str] = Field(None, description="Email address from the signature")
    signature_data: Optional[str] = Field(None, description="Raw signature data")


class GPGKeyInfo(BaseModel):
    """Information about a GPG key from GitHub's API."""

    id: int = Field(..., description="GitHub's internal ID for this key")
    key_id: str = Field(..., description="GPG key ID (e.g., '3262EFF25BA0D270')")
    name: Optional[str] = Field(None, description="User-provided name/description for the key")
    primary_key_id: Optional[int] = Field(None, description="ID of primary key if this is a subkey")
    emails: list[str] = Field(default_factory=list, description="Email addresses associated with key")
    can_sign: bool = Field(False, description="Whether this key can be used for signing")
    can_encrypt_comms: bool = Field(False, description="Whether key can encrypt communications")
    can_encrypt_storage: bool = Field(False, description="Whether key can encrypt storage")
    can_certify: bool = Field(False, description="Whether key can certify other keys")
    created_at: str = Field(..., description="ISO 8601 timestamp when key was added to GitHub")
    expires_at: Optional[str] = Field(None, description="ISO 8601 timestamp when key expires")
    revoked: bool = Field(False, description="Whether the key has been revoked")
    raw_key: Optional[str] = Field(None, description="Raw PGP public key block")
    subkeys: list["GPGKeyInfo"] = Field(default_factory=list, description="List of subkeys associated with this key")


class SSHKeyInfo(BaseModel):
    """Information about an SSH signing key from GitHub's API."""

    id: int = Field(..., description="GitHub's internal ID for this key")
    key: str = Field(..., description="SSH public key data")
    title: str = Field(..., description="User-provided title/description for the key")
    created_at: str = Field(..., description="ISO 8601 timestamp when key was added to GitHub")


class GerritAccountInfo(BaseModel):
    """Information about a Gerrit account."""

    account_id: int = Field(..., description="Gerrit account ID")
    name: Optional[str] = Field(None, description="Account display name")
    email: Optional[str] = Field(None, description="Primary email address")
    username: Optional[str] = Field(None, description="Username")
    status: str = Field(..., description="Account status")


class GerritSSHKeyInfo(BaseModel):
    """Information about an SSH key from Gerrit's API."""

    seq: int = Field(..., description="Sequence number of the key")
    ssh_public_key: str = Field(..., description="SSH public key data")
    encoded_key: str = Field(..., description="Base64 encoded key")
    algorithm: str = Field(..., description="Key algorithm (e.g., ssh-rsa, ssh-ed25519)")
    comment: Optional[str] = Field(None, description="Key comment")
    valid: bool = Field(..., description="Whether the key is valid")


class GerritGPGKeyInfo(BaseModel):
    """Information about a GPG key from Gerrit's API."""

    id: str = Field(..., description="GPG key ID (short identifier)")
    fingerprint: str = Field(..., description="Full key fingerprint")
    user_ids: list[str] = Field(default_factory=list, description="List of user IDs")
    key: str = Field(..., description="ASCII-armored public key")
    status: str = Field(..., description="Key status")
    problems: list[str] = Field(default_factory=list, description="Any problems with the key")


class GitHubVerificationInfo(BaseModel):
    """GitHub's verification information from the commits API."""

    verified: bool = Field(..., description="Whether GitHub verified the signature")
    reason: str = Field(..., description="GitHub's reason code for verification status")
    signature: Optional[str] = Field(None, description="The signature that was extracted")
    payload: Optional[str] = Field(None, description="The value that was signed")


class KeyVerificationResult(BaseModel):
    """Result of verifying a key against GitHub's or Gerrit's registry."""

    key_registered: bool = Field(
        False, description="Whether the key is registered on the service"
    )
    username: str = Field(..., description="Username checked")
    user_enumerated: bool = Field(
        False, description="Whether the username was auto-detected from email"
    )
    key_info: Optional[GPGKeyInfo | SSHKeyInfo | GerritGPGKeyInfo | GerritSSHKeyInfo] = Field(
        None, description="Full key information from API if found"
    )
    service: str = Field("github", description="Service that was checked (github or gerrit)")
    server: Optional[str] = Field(None, description="Server hostname for Gerrit")
    user_name: Optional[str] = Field(None, description="User's display name")
    user_email: Optional[str] = Field(None, description="User's email address")


class VersionInfo(BaseModel):
    """Information about version string parsing and validation."""

    raw: str = Field(..., description="Original version string")
    normalized: Optional[str] = Field(None, description="Normalized version string (without prefix)")
    is_valid: bool = Field(False, description="Whether version is valid")
    version_type: Literal["semver", "calver", "both", "other"] = Field(
        "other", description="Type of version format detected"
    )
    has_prefix: bool = Field(False, description="Whether version has 'v' or 'V' prefix")
    is_development: bool = Field(
        False, description="Whether version is a development/pre-release version"
    )

    # SemVer fields
    major: Optional[int] = Field(None, description="Major version number (SemVer)")
    minor: Optional[int] = Field(None, description="Minor version number (SemVer)")
    patch: Optional[int] = Field(None, description="Patch version number (SemVer)")
    prerelease: Optional[str] = Field(None, description="Pre-release identifier (SemVer)")
    build_metadata: Optional[str] = Field(None, description="Build metadata (SemVer)")

    # CalVer fields
    year: Optional[int] = Field(None, description="Year (CalVer)")
    month: Optional[int] = Field(None, description="Month (CalVer)")
    day: Optional[int] = Field(None, description="Day (CalVer)")
    micro: Optional[int] = Field(None, description="Micro version (CalVer)")
    modifier: Optional[str] = Field(None, description="Version modifier (CalVer)")

    # Validation errors
    errors: list[str] = Field(default_factory=list, description="Validation errors")


class ValidationConfig(BaseModel):
    """Configuration for tag validation workflow."""

    # Version requirements
    require_semver: bool = Field(False, description="Require Semantic Versioning")
    require_calver: bool = Field(False, description="Require Calendar Versioning")
    skip_version_validation: bool = Field(False, description="Skip version format validation")

    # Signature requirements
    require_signed: bool = Field(False, description="Require tag to be signed")
    require_unsigned: bool = Field(False, description="Require tag to be unsigned")
    allowed_signature_types: Optional[list[str]] = Field(None, description="Specific signature types allowed (gpg, ssh, gpg-unverifiable, unsigned)")

    # GitHub verification
    require_github: bool = Field(False, description="Verify signing key on GitHub")

    # Gerrit verification
    require_gerrit: bool = Field(False, description="Verify signing key on Gerrit")
    gerrit_server: Optional[str] = Field(None, description="Gerrit server hostname or URL")

    # Version filtering
    reject_development: bool = Field(False, description="Reject development versions")
    allow_prefix: bool = Field(True, description="Allow 'v' prefix on versions")

    # Configuration metadata
    config_source: Optional[str] = Field(None, description="Source of configuration")


class ValidationResult(BaseModel):
    """Complete validation result for a tag."""

    tag_name: str = Field(..., description="Name of the validated tag")
    is_valid: bool = Field(True, description="Overall validation result")

    # Component results
    tag_info: Optional[TagInfo] = Field(None, description="Tag metadata")
    version_info: Optional[VersionInfo] = Field(None, description="Version validation result")
    signature_info: Optional[SignatureInfo] = Field(None, description="Signature information")
    key_verifications: list[KeyVerificationResult] = Field(
        default_factory=list, description="List of key verification results (GitHub and/or Gerrit)"
    )

    # Validation configuration used
    config: ValidationConfig = Field(..., description="Configuration used for validation")

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
    web_url: Optional[str] = Field(None, description="Web URL to repository")
    tag: Optional[str] = Field(None, description="Specific tag being validated")
