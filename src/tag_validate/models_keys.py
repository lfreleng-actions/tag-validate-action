# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Pydantic models for signing keys and key registry lookups.

Covers the key material returned by GitHub's and Gerrit's APIs, plus the
result of checking a signing key against one of those registries.
"""

from pydantic import BaseModel, Field


class GPGKeyInfo(BaseModel):
    """Information about a GPG key from GitHub's API."""

    id: int = Field(..., description="GitHub's internal ID for this key")
    key_id: str = Field(..., description="GPG key ID (e.g., '3262EFF25BA0D270')")
    name: str | None = Field(
        default=None, description="User-provided name/description for the key"
    )
    primary_key_id: int | None = Field(
        default=None, description="ID of primary key if this is a subkey"
    )
    emails: list[str] = Field(
        default_factory=list, description="Email addresses associated with key"
    )
    can_sign: bool = Field(
        default=False, description="Whether this key can be used for signing"
    )
    can_encrypt_comms: bool = Field(
        default=False, description="Whether key can encrypt communications"
    )
    can_encrypt_storage: bool = Field(
        default=False, description="Whether key can encrypt storage"
    )
    can_certify: bool = Field(
        default=False, description="Whether key can certify other keys"
    )
    created_at: str = Field(
        ..., description="ISO 8601 timestamp when key was added to GitHub"
    )
    expires_at: str | None = Field(
        default=None, description="ISO 8601 timestamp when key expires"
    )
    revoked: bool = Field(default=False, description="Whether the key has been revoked")
    raw_key: str | None = Field(default=None, description="Raw PGP public key block")
    subkeys: list["GPGKeyInfo"] = Field(
        default_factory=list, description="List of subkeys associated with this key"
    )


class SSHKeyInfo(BaseModel):
    """Information about an SSH signing key from GitHub's API."""

    id: int = Field(..., description="GitHub's internal ID for this key")
    key: str = Field(..., description="SSH public key data")
    title: str = Field(..., description="User-provided title/description for the key")
    created_at: str = Field(
        ..., description="ISO 8601 timestamp when key was added to GitHub"
    )


class GerritAccountInfo(BaseModel):
    """Information about a Gerrit account."""

    account_id: int = Field(..., description="Gerrit account ID")
    name: str | None = Field(default=None, description="Account display name")
    email: str | None = Field(default=None, description="Primary email address")
    username: str | None = Field(default=None, description="Username")
    status: str = Field(..., description="Account status")


class GerritSSHKeyInfo(BaseModel):
    """Information about an SSH key from Gerrit's API."""

    seq: int = Field(..., description="Sequence number of the key")
    ssh_public_key: str = Field(..., description="SSH public key data")
    encoded_key: str = Field(..., description="Base64 encoded key")
    algorithm: str = Field(
        ..., description="Key algorithm (e.g., ssh-rsa, ssh-ed25519)"
    )
    comment: str | None = Field(default=None, description="Key comment")
    valid: bool = Field(..., description="Whether the key is valid")


class GerritGPGKeyInfo(BaseModel):
    """Information about a GPG key from Gerrit's API."""

    id: str = Field(..., description="GPG key ID (short identifier)")
    fingerprint: str = Field(..., description="Full key fingerprint")
    user_ids: list[str] = Field(default_factory=list, description="List of user IDs")
    key: str = Field(..., description="ASCII-armored public key")
    status: str = Field(..., description="Key status")
    problems: list[str] = Field(
        default_factory=list, description="Any problems with the key"
    )


class GitHubVerificationInfo(BaseModel):
    """GitHub's verification information from the commits API."""

    verified: bool = Field(..., description="Whether GitHub verified the signature")
    reason: str = Field(..., description="GitHub's reason code for verification status")
    signature: str | None = Field(
        default=None, description="The signature that was extracted"
    )
    payload: str | None = Field(default=None, description="The value that was signed")


class KeyVerificationResult(BaseModel):
    """Result of verifying a key against GitHub's or Gerrit's registry."""

    key_registered: bool = Field(
        default=False, description="Whether the key is registered on the service"
    )
    username: str = Field(..., description="Username checked")
    user_enumerated: bool = Field(
        default=False, description="Whether the username was auto-detected from email"
    )
    key_info: GPGKeyInfo | SSHKeyInfo | GerritGPGKeyInfo | GerritSSHKeyInfo | None = (
        Field(default=None, description="Full key information from API if found")
    )
    service: str = Field(
        default="github", description="Service that was checked (github or gerrit)"
    )
    server: str | None = Field(default=None, description="Server hostname for Gerrit")
    user_name: str | None = Field(default=None, description="User's display name")
    user_email: str | None = Field(default=None, description="User's email address")


__all__ = [
    "GPGKeyInfo",
    "GerritAccountInfo",
    "GerritGPGKeyInfo",
    "GerritSSHKeyInfo",
    "GitHubVerificationInfo",
    "KeyVerificationResult",
    "SSHKeyInfo",
]
