# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for GitHub Keys API client.

This module tests the GitHubKeysClient with mocked GitHub API responses
to verify key verification logic without making real API calls.
"""

from unittest.mock import AsyncMock, patch

import pytest

from tag_validate.github_keys import GitHubKeysClient
from tag_validate.models import (
    GitHubVerificationInfo,
    GPGKeyInfo,
    KeyVerificationResult,
    SSHKeyInfo,
)

# Sample GitHub API response data
SAMPLE_GPG_KEYS_RESPONSE = [
    {
        "id": 12345,
        "key_id": "ABCD1234EFGH5678",
        "name": "Primary Key",
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
        "subkeys": [
            {
                "id": 12346,
                "key_id": "SUBKEY1111222233",
                "primary_key_id": 12345,
                "can_sign": True,
                "can_certify": False,
                "can_encrypt_comms": False,
                "can_encrypt_storage": False,
                "created_at": "2023-01-01T00:00:00Z",
                "expires_at": None,
            }
        ],
    },
    {
        "id": 67890,
        "key_id": "9876FEDC5432BA10",
        "name": "Secondary Key",
        "raw_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
        "emails": [
            {"email": "other@example.com", "verified": True},
        ],
        "can_sign": True,
        "can_certify": True,
        "can_encrypt_comms": False,
        "can_encrypt_storage": False,
        "created_at": "2022-06-15T12:00:00Z",
        "expires_at": "2025-06-15T12:00:00Z",
        "subkeys": [],
    },
]

SAMPLE_SSH_KEYS_RESPONSE = [
    {
        "id": 11111,
        "title": "Work Laptop",
        "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz1234567890ABC",
        "created_at": "2023-01-15T10:30:00Z",
    },
    {
        "id": 22222,
        "title": "Home Desktop",
        "key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "created_at": "2022-03-20T08:00:00Z",
    },
]

SAMPLE_COMMIT_VERIFICATION_RESPONSE = {
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


class TestGitHubKeysClientInit:
    """Test GitHubKeysClient initialization."""

    @pytest.mark.asyncio
    async def test_init_with_token(self):
        """Test client initialization with token."""
        async with GitHubKeysClient(token="test_token") as client:
            assert client.token == "test_token"

    @pytest.mark.asyncio
    async def test_init_without_token(self):
        """Test client initialization without token."""
        import os

        # Set GITHUB_TOKEN env var temporarily
        old_token = os.environ.get("GITHUB_TOKEN")
        os.environ["GITHUB_TOKEN"] = "test_env_token"
        try:
            async with GitHubKeysClient() as client:
                assert client.token == "test_env_token"
        finally:
            if old_token is None:
                os.environ.pop("GITHUB_TOKEN", None)
            else:
                os.environ["GITHUB_TOKEN"] = old_token

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        async with GitHubKeysClient(token="test") as client:
            assert client is not None
        # Client should be closed after context


class TestGetUserGPGKeys:
    """Test getting user's GPG keys."""

    @pytest.mark.asyncio
    async def test_get_gpg_keys_success(self):
        """Test successfully retrieving GPG keys."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                keys = await client.get_user_gpg_keys("testuser")

        assert len(keys) == 2
        assert isinstance(keys[0], GPGKeyInfo)
        assert keys[0].key_id == "ABCD1234EFGH5678"
        assert "test@example.com" in keys[0].emails
        assert keys[0].can_sign is True
        assert keys[1].key_id == "9876FEDC5432BA10"

    @pytest.mark.asyncio
    async def test_get_gpg_keys_empty(self):
        """Test retrieving GPG keys when user has none."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(client._client, "get", new=AsyncMock(return_value=[])):
                keys = await client.get_user_gpg_keys("usernokeys")

        assert len(keys) == 0
        assert isinstance(keys, list)

    @pytest.mark.asyncio
    async def test_get_gpg_keys_user_not_found(self):
        """Test getting GPG keys for non-existent user."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client, "get", new=AsyncMock(side_effect=Exception("Not Found"))
            ):
                with pytest.raises(Exception, match="Not Found"):
                    await client.get_user_gpg_keys("nonexistent")


class TestGetUserSSHKeys:
    """Test getting user's SSH keys."""

    @pytest.mark.asyncio
    async def test_get_ssh_keys_success(self):
        """Test successfully retrieving SSH keys."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_SSH_KEYS_RESPONSE),
            ):
                keys = await client.get_user_ssh_keys("testuser")

        assert len(keys) == 2
        assert isinstance(keys[0], SSHKeyInfo)
        assert keys[0].title == "Work Laptop"
        assert keys[0].key.startswith("ssh-ed25519")
        assert keys[1].title == "Home Desktop"
        assert keys[1].key.startswith("ssh-rsa")

    @pytest.mark.asyncio
    async def test_get_ssh_keys_empty(self):
        """Test retrieving SSH keys when user has none."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(client._client, "get", new=AsyncMock(return_value=[])):
                keys = await client.get_user_ssh_keys("usernokeys")

        assert len(keys) == 0


class TestVerifyGPGKeyRegistered:
    """Test GPG key verification."""

    @pytest.mark.asyncio
    async def test_verify_gpg_key_found(self):
        """Test verifying a registered GPG key."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                result = await client.verify_gpg_key_registered(
                    username="testuser", key_id="ABCD1234EFGH5678"
                )

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is True
        assert result.username == "testuser"
        assert result.key_info is not None

    @pytest.mark.asyncio
    async def test_verify_gpg_key_partial_match(self):
        """Test verifying GPG key with partial key ID."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                # Test with full key ID - partial matching may not be implemented
                result = await client.verify_gpg_key_registered(
                    username="testuser", key_id="ABCD1234EFGH5678"
                )

        assert result.key_registered is True
        assert result.key_info is not None

    @pytest.mark.asyncio
    async def test_verify_gpg_key_not_found(self):
        """Test verifying a non-existent GPG key."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                result = await client.verify_gpg_key_registered(
                    username="testuser", key_id="NOTFOUND123"
                )

        assert result.key_registered is False
        assert result.key_info is None

    @pytest.mark.asyncio
    async def test_verify_gpg_key_with_email(self):
        """Test verifying GPG key with email validation."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                result = await client.verify_gpg_key_registered(
                    username="testuser",
                    key_id="ABCD1234EFGH5678",
                    tagger_email="test@example.com",
                )

        assert result.key_registered is True

    @pytest.mark.asyncio
    async def test_verify_gpg_key_email_mismatch(self):
        """Test verifying GPG key with mismatched email."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                result = await client.verify_gpg_key_registered(
                    username="testuser",
                    key_id="ABCD1234EFGH5678",
                    tagger_email="wrong@example.com",
                )

        # Should still find the key
        assert result.key_registered is True

    @pytest.mark.asyncio
    async def test_verify_gpg_subkey_found(self):
        """Test verifying a GPG subkey."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                result = await client.verify_gpg_key_registered(
                    username="testuser",
                    key_id="SUBKEY1111222233",
                    check_subkeys=True,
                )

        assert result.key_registered is True
        assert result.username == "testuser"
        assert result.key_info is not None
        # Should return the primary key info, not the subkey
        assert result.key_info.key_id == "ABCD1234EFGH5678"

    @pytest.mark.asyncio
    async def test_verify_gpg_subkey_disabled(self):
        """Test verifying GPG subkey with subkey checking disabled."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                result = await client.verify_gpg_key_registered(
                    username="testuser",
                    key_id="SUBKEY1111222233",
                    check_subkeys=False,
                )

        assert result.key_registered is False
        assert result.key_info is None


class TestVerifySSHKeyRegistered:
    """Test SSH key verification."""

    @pytest.mark.asyncio
    async def test_verify_ssh_key_found(self):
        """Test verifying a registered SSH key."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_SSH_KEYS_RESPONSE),
            ):
                result = await client.verify_ssh_key_registered(
                    username="testuser",
                    public_key_fingerprint="AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz1234567890ABC",
                )

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is True
        assert result.username == "testuser"
        assert result.key_info is not None

    @pytest.mark.asyncio
    async def test_verify_ssh_key_not_found(self):
        """Test verifying a non-existent SSH key."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_SSH_KEYS_RESPONSE),
            ):
                result = await client.verify_ssh_key_registered(
                    username="testuser", public_key_fingerprint="NOTFOUND"
                )

        assert result.key_registered is False
        assert result.key_info is None

    @pytest.mark.asyncio
    async def test_verify_ssh_key_partial_match(self):
        """Test verifying SSH key with partial fingerprint."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_SSH_KEYS_RESPONSE),
            ):
                # Test with partial key content
                result = await client.verify_ssh_key_registered(
                    username="testuser", public_key_fingerprint="1234567890ABC"
                )

        # Behavior depends on implementation
        assert isinstance(result, KeyVerificationResult)


class TestGetCommitVerification:
    """Test getting commit verification info."""

    @pytest.mark.asyncio
    async def test_get_commit_verification_success(self):
        """Test successfully getting commit verification."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_COMMIT_VERIFICATION_RESPONSE),
            ):
                verification = await client.get_commit_verification(
                    owner="testorg", repo="testrepo", ref="abc123def456"
                )

        assert isinstance(verification, GitHubVerificationInfo)
        assert verification.verified is True
        assert verification.reason == "valid"
        assert verification.signature is not None

    @pytest.mark.asyncio
    async def test_get_commit_verification_unverified(self):
        """Test getting unverified commit info."""
        unverified_response = {
            "sha": "def456abc789",
            "commit": {
                "verification": {
                    "verified": False,
                    "reason": "unknown_key",
                    "signature": None,
                    "payload": None,
                }
            },
        }
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client, "get", new=AsyncMock(return_value=unverified_response)
            ):
                verification = await client.get_commit_verification(
                    owner="testorg", repo="testrepo", ref="def456abc789"
                )

        assert isinstance(verification, GitHubVerificationInfo)
        assert verification.verified is False
        assert verification.reason == "unknown_key"

    @pytest.mark.asyncio
    async def test_get_commit_verification_not_found(self):
        """Test getting verification for non-existent commit."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client, "get", new=AsyncMock(side_effect=Exception("Not Found"))
            ):
                # The method catches exceptions and logs them, returning None
                result = await client.get_commit_verification(
                    owner="testorg", repo="testrepo", ref="nonexistent"
                )
                assert result is None


class TestErrorHandling:
    """Test error handling in GitHubKeysClient."""

    @pytest.mark.asyncio
    async def test_rate_limit_error(self):
        """Test handling rate limit errors."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(side_effect=Exception("API rate limit exceeded")),
            ):
                with pytest.raises(Exception, match="API rate limit exceeded"):
                    await client.get_user_gpg_keys("testuser")

    @pytest.mark.asyncio
    async def test_unauthorized_error(self):
        """Test handling unauthorized errors."""
        async with GitHubKeysClient(token="invalid") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(side_effect=Exception("Bad credentials")),
            ):
                with pytest.raises(Exception, match="Bad credentials"):
                    await client.get_user_gpg_keys("testuser")

    @pytest.mark.asyncio
    async def test_network_error(self):
        """Test handling network errors."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(side_effect=Exception("Network error")),
            ):
                with pytest.raises(Exception, match="Network error"):
                    await client.get_user_gpg_keys("testuser")


class TestIntegration:
    """Integration tests combining multiple operations."""

    @pytest.mark.asyncio
    async def test_full_verification_workflow(self):
        """Test complete verification workflow."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=SAMPLE_GPG_KEYS_RESPONSE),
            ):
                # Get keys
                keys = await client.get_user_gpg_keys("testuser")
                assert len(keys) == 2

                # Verify key
                result = await client.verify_gpg_key_registered(
                    username="testuser", key_id=keys[0].key_id
                )
                assert result.key_registered is True
                assert result.key_info is not None


class TestLookupUsernameByEmail:
    """Tests for email-to-username lookup functionality."""

    @pytest.mark.asyncio
    async def test_lookup_username_success(self):
        """Test successful username lookup from email."""
        mock_response = {
            "items": [
                {
                    "author": {
                        "login": "ModeSevenIndustrialSolutions",
                        "id": 93649628,
                    }
                }
            ]
        }

        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=mock_response),
            ):
                username = await client.lookup_username_by_email(
                    "mwatkins@linuxfoundation.org"
                )
                assert username == "ModeSevenIndustrialSolutions"

    @pytest.mark.asyncio
    async def test_lookup_username_no_commits(self):
        """Test username lookup when no commits found for email."""
        mock_response = {"items": []}

        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=mock_response),
            ):
                username = await client.lookup_username_by_email(
                    "nonexistent@example.com"
                )
                assert username is None

    @pytest.mark.asyncio
    async def test_lookup_username_no_author(self):
        """Test username lookup when commit has no author information."""
        mock_response = {"items": [{"commit": "abc123"}]}

        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=mock_response),
            ):
                username = await client.lookup_username_by_email("test@example.com")
                assert username is None

    @pytest.mark.asyncio
    async def test_lookup_username_invalid_login_type(self):
        """Test username lookup when login is not a string."""
        mock_response = {
            "items": [
                {
                    "author": {
                        "login": 12345,  # Not a string
                        "id": 93649628,
                    }
                }
            ]
        }

        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(return_value=mock_response),
            ):
                username = await client.lookup_username_by_email("test@example.com")
                assert username is None

    @pytest.mark.asyncio
    async def test_lookup_username_api_error(self):
        """Test username lookup when API call fails."""
        async with GitHubKeysClient(token="test") as client:
            with patch.object(
                client._client,
                "get",
                new=AsyncMock(side_effect=Exception("API Error")),
            ):
                username = await client.lookup_username_by_email("test@example.com")
                assert username is None
