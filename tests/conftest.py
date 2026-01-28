# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Pytest configuration and shared fixtures for tag-validate tests.

This module provides common fixtures and configuration for all tests.
"""

from unittest.mock import Mock

import pytest

from tag_validate.models import (
    GerritAccountInfo,
    GerritGPGKeyInfo,
    GerritSSHKeyInfo,
    GPGKeyInfo,
    KeyVerificationResult,
    SignatureInfo,
    SSHKeyInfo,
    ValidationConfig,
    VersionInfo,
)


@pytest.fixture
def temp_repo(tmp_path):
    """
    Create a temporary repository directory structure.

    Returns:
        Path: Path to the temporary repository
    """
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    # Create .git directory
    git_dir = repo_path / ".git"
    git_dir.mkdir()

    # Create basic git structure
    (git_dir / "refs" / "tags").mkdir(parents=True)
    (git_dir / "objects").mkdir()

    return repo_path


@pytest.fixture
def sample_gpg_signature():
    """
    Create a sample valid GPG signature.

    Returns:
        SignatureInfo: Sample GPG signature
    """
    return SignatureInfo(
        type="gpg",
        verified=True,
        signer_email="john@example.com",
        key_id="ABCD1234EFGH5678",
        fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
        signature_data="gpg: Good signature from...",
    )


@pytest.fixture
def sample_ssh_signature():
    """
    Create a sample valid SSH signature.

    Returns:
        SignatureInfo: Sample SSH signature
    """
    return SignatureInfo(
        type="ssh",
        verified=True,
        signer_email="jane@example.com",
        key_id="ED25519:SHA256:abc123def456",
        fingerprint="SHA256:abc123def456ghijklmnopqrstuvwxyz",
        signature_data='Good "git" signature...',
    )


@pytest.fixture
def sample_unsigned():
    """
    Create a sample unsigned tag info.

    Returns:
        SignatureInfo: Sample unsigned tag
    """
    return SignatureInfo(
        type="unsigned",
        verified=False,
        signature_data="error: no signature found",
    )


@pytest.fixture
def sample_gpg_key():
    """
    Create a sample GPG key info.

    Returns:
        GPGKeyInfo: Sample GPG key
    """
    return GPGKeyInfo(
        id=12345,
        key_id="ABCD1234EFGH5678",
        raw_key="-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
        emails=["test@example.com", "test2@example.com"],
        can_sign=True,
        can_certify=False,
        can_encrypt_comms=True,
        can_encrypt_storage=False,
        created_at="2023-01-01T00:00:00Z",
        expires_at=None,
    )


@pytest.fixture
def sample_ssh_key():
    """
    Create a sample SSH key info.

    Returns:
        SSHKeyInfo: Sample SSH key
    """
    return SSHKeyInfo(
        id=11111,
        title="Work Laptop",
        key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz",
        created_at="2023-01-15T10:30:00Z",
    )


@pytest.fixture
def sample_semver():
    """
    Create a sample SemVer version info.

    Returns:
        VersionInfo: Sample SemVer
    """
    return VersionInfo(
        raw="v1.2.3",
        normalized="1.2.3",
        is_valid=True,
        version_type="semver",
        has_prefix=True,
        is_development=False,
        major=1,
        minor=2,
        patch=3,
        prerelease=None,
        build_metadata=None,
    )


@pytest.fixture
def sample_calver():
    """
    Create a sample CalVer version info.

    Returns:
        VersionInfo: Sample CalVer
    """
    return VersionInfo(
        raw="2024.01.15",
        normalized="2024.01.15",
        is_valid=True,
        version_type="calver",
        has_prefix=False,
        is_development=False,
        year=2024,
        month=1,
        day=15,
    )


@pytest.fixture
def sample_validation_config():
    """
    Create a sample validation configuration.

    Returns:
        ValidationConfig: Sample configuration
    """
    return ValidationConfig(
        require_signed=True,
        require_semver=True,
        require_github=True,
        reject_development=True,
    )


@pytest.fixture
def sample_gerrit_validation_config():
    """
    Create a sample validation configuration with Gerrit.

    Returns:
        ValidationConfig: Sample Gerrit configuration
    """
    return ValidationConfig(
        require_signed=True,
        require_semver=True,
        require_gerrit=True,
        gerrit_server="gerrit.onap.org",
        reject_development=True,
    )


@pytest.fixture
def sample_key_verification_result():
    """
    Create a sample key verification result.

    Returns:
        KeyVerificationResult: Sample verification result
    """
    return KeyVerificationResult(
        key_registered=True,
        username="testuser",
        service="github",
        user_enumerated=False,
        key_info=None,
    )


@pytest.fixture
def sample_gerrit_account():
    """
    Create a sample Gerrit account info.

    Returns:
        GerritAccountInfo: Sample Gerrit account
    """
    return GerritAccountInfo(
        account_id=12345,
        name="John Doe",
        email="john@example.com",
        username="jdoe",
        status="ACTIVE",
    )


@pytest.fixture
def sample_gerrit_ssh_key():
    """
    Create a sample Gerrit SSH key info.

    Returns:
        GerritSSHKeyInfo: Sample Gerrit SSH key
    """
    return GerritSSHKeyInfo(
        seq=1,
        ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz Test Key",
        encoded_key="AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz",
        algorithm="ssh-ed25519",
        comment="Test Key",
        valid=True,
    )


@pytest.fixture
def sample_gerrit_gpg_key():
    """
    Create a sample Gerrit GPG key info.

    Returns:
        GerritGPGKeyInfo: Sample Gerrit GPG key
    """
    return GerritGPGKeyInfo(
        id="ABCD1234EFGH5678",
        fingerprint="1234567890ABCDEF1234567890ABCDEF12345678",
        user_ids=["John Doe <john@example.com>"],
        key="-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
        status="TRUSTED",
        problems=[],
    )


@pytest.fixture
def sample_gerrit_key_verification_result():
    """
    Create a sample Gerrit key verification result.

    Returns:
        KeyVerificationResult: Sample Gerrit verification result
    """
    return KeyVerificationResult(
        key_registered=True,
        username="12345",
        user_enumerated=False,
        key_info=None,
        service="gerrit",
        server="gerrit.onap.org",
    )


# Git command output fixtures
@pytest.fixture
def git_verify_gpg_output():
    """Sample git verify-tag output for GPG signature."""
    return """gpg: Signature made Mon Jan  1 12:00:00 2024 PST
gpg:                using RSA key ABCD1234EFGH5678
gpg: Good signature from "John Doe <john@example.com>"
[GNUPG:] NEWSIG
[GNUPG:] GOODSIG ABCD1234EFGH5678 John Doe <john@example.com>
[GNUPG:] VALIDSIG 1234567890ABCDEF1234567890ABCDEF12345678 2024-01-01 1704132000
Primary key fingerprint: 1234 5678 90AB CDEF 1234  5678 90AB CDEF 1234 5678
"""


@pytest.fixture
def git_verify_ssh_output():
    """Sample git verify-tag output for SSH signature."""
    return 'Good "git" signature for john@example.com with ED25519 key SHA256:abcdefghijklmnopqrstuvwxyz1234567890ABC\n'


@pytest.fixture
def git_verify_unsigned_output():
    """Sample git verify-tag output for unsigned tag."""
    return "error: no signature found\n"


# GitHub API response fixtures
@pytest.fixture
def github_gpg_keys_response():
    """Sample GitHub API response for GPG keys."""
    return [
        {
            "id": 12345,
            "key_id": "ABCD1234EFGH5678",
            "raw_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
            "emails": [
                {"email": "test@example.com", "verified": True},
                {"email": "test2@example.com", "verified": False},
            ],
            "can_sign": True,
            "can_certify": False,
            "can_encrypt_comms": True,
            "can_encrypt_storage": False,
            "created_at": "2023-01-01T00:00:00Z",
            "expires_at": None,
        }
    ]


@pytest.fixture
def github_ssh_keys_response():
    """Sample GitHub API response for SSH keys."""
    return [
        {
            "id": 11111,
            "title": "Work Laptop",
            "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz",
            "created_at": "2023-01-15T10:30:00Z",
        }
    ]


@pytest.fixture
def github_commit_verification_response():
    """Sample GitHub API response for commit verification."""
    return {
        "sha": "abc123def456",
        "commit": {
            "verification": {
                "verified": True,
                "reason": "valid",
                "signature": "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
                "payload": "tree abc123\nparent def456\n...",
            }
        },
    }


# Gerrit API response fixtures
@pytest.fixture
def gerrit_account_response():
    """Sample Gerrit API response for account lookup."""
    return [
        {
            "_account_id": 12345,
            "name": "John Doe",
            "email": "john@example.com",
            "username": "jdoe",
            "status": "ACTIVE",
        }
    ]


@pytest.fixture
def gerrit_ssh_keys_response():
    """Sample Gerrit API response for SSH keys."""
    return [
        {
            "seq": 1,
            "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz Test Key",
            "encoded_key": "AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz",
            "algorithm": "ssh-ed25519",
            "comment": "Test Key",
            "valid": True,
        },
        {
            "seq": 2,
            "ssh_public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... Old Key",
            "encoded_key": "AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
            "algorithm": "ssh-rsa",
            "comment": "Old Key",
            "valid": False,
        },
    ]


@pytest.fixture
def gerrit_gpg_keys_response():
    """Sample Gerrit API response for GPG keys."""
    return {
        "ABCD1234EFGH5678": {
            "fingerprint": "1234567890ABCDEF1234567890ABCDEF12345678",
            "user_ids": ["John Doe <john@example.com>"],
            "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
            "status": "TRUSTED",
            "problems": [],
        },
        "9876FEDC5432BA10": {
            "fingerprint": "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
            "user_ids": ["John Doe <john@alt.com>", "J. Doe <j.doe@example.com>"],
            "key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
            "status": "EXPIRED",
            "problems": ["Key expired"],
        },
    }


@pytest.fixture
def mock_github_client():
    """Create a mock GitHub client."""
    client = Mock()
    client.get = Mock()
    return client


# Parametrized test data
@pytest.fixture(
    params=[
        ("v1.0.0", True, True, False),  # version, valid, is_semver, is_calver
        ("v2.1.3", True, True, False),
        ("1.0.0", True, True, False),
        ("v1.0.0-alpha", True, True, False),
        ("v1.0.0-beta.1", True, True, False),
        ("v1.0.0+build123", True, True, False),
        ("2024.01.15", True, False, True),
        ("2024.1.1", True, False, True),
    ]
)
def valid_version_strings(request):
    """Parametrized fixture for valid version strings."""
    return request.param


@pytest.fixture(
    params=[
        "invalid",
        "v1.0",
        "1.x.0",
        "abc.def.ghi",
        "",
    ]
)
def invalid_version_strings(request):
    """Parametrized fixture for invalid version strings."""
    return request.param
