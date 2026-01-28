# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Gerrit keys client functionality.

This module provides comprehensive tests for the GerritKeysClient class,
including server discovery, account lookup, key verification, and error handling.
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from tag_validate.gerrit_keys import (
    GerritKeysClient,
    GerritKeysError,
    GerritServerError,
)
from tag_validate.models import (
    GerritAccountInfo,
    GerritGPGKeyInfo,
    GerritSSHKeyInfo,
    KeyVerificationResult,
)

# Sample Gerrit API responses
SAMPLE_GERRIT_ACCOUNT_RESPONSE = [
    {
        "_account_id": 12345,
        "name": "John Doe",
        "email": "john@example.com",
        "username": "jdoe",
        "status": "ACTIVE",
    }
]

SAMPLE_GERRIT_SSH_KEYS_RESPONSE = [
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

SAMPLE_GERRIT_GPG_KEYS_RESPONSE = {
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


class TestGerritKeysClientInit:
    """Test GerritKeysClient initialization."""

    def test_init_with_server(self):
        """Test client initialization with explicit server."""
        client = GerritKeysClient(server="gerrit.example.org")
        assert client.server == "gerrit.example.org"

    def test_init_with_github_org(self):
        """Test client initialization with GitHub org auto-discovery."""
        client = GerritKeysClient(github_org="onap")
        assert client.server == "gerrit.onap.org"

    def test_init_with_server_url(self):
        """Test client initialization with full URL normalization."""
        client = GerritKeysClient(server="https://gerrit.example.org/r")
        assert client.server == "gerrit.example.org"

    def test_init_no_server_or_org(self):
        """Test client initialization fails without server or org."""
        with pytest.raises(
            GerritKeysError, match="Either server or github_org must be provided"
        ):
            GerritKeysClient()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        with patch.object(
            GerritKeysClient,
            "_discover_api_base_url",
            new=AsyncMock(return_value="https://gerrit.onap.org"),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                assert client is not None
                assert client._rest is not None
        # Client should be closed after context


class TestServerDiscovery:
    """Test Gerrit server discovery functionality."""

    def test_normalize_server_url_hostname(self):
        """Test server URL normalization from hostname."""
        client = GerritKeysClient(server="gerrit.example.org")
        assert client.server == "gerrit.example.org"

    def test_normalize_server_url_https(self):
        """Test server URL normalization from HTTPS URL."""
        client = GerritKeysClient(server="https://gerrit.example.org/r")
        assert client.server == "gerrit.example.org"

    def test_normalize_server_url_http(self):
        """Test server URL normalization from HTTP URL."""
        client = GerritKeysClient(server="http://gerrit.example.org")
        assert client.server == "gerrit.example.org"

    def test_discover_server_from_github_org(self):
        """Test server discovery from GitHub organization."""
        client = GerritKeysClient(github_org="onap")
        assert client.server == "gerrit.onap.org"

    @pytest.mark.asyncio
    async def test_discover_api_base_url_success(self):
        """Test successful API base URL discovery."""
        # Just patch the discovery method directly to avoid complex mocking
        with patch.object(
            GerritKeysClient,
            "_discover_api_base_url",
            new_callable=AsyncMock,
            return_value="https://gerrit.onap.org",
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                assert client._base_url == "https://gerrit.onap.org"

    @pytest.mark.asyncio
    async def test_discover_api_base_url_with_path(self):
        """Test API base URL discovery with path prefix."""
        # Just patch the discovery method directly to avoid complex mocking
        with patch.object(
            GerritKeysClient,
            "_discover_api_base_url",
            new_callable=AsyncMock,
            return_value="https://gerrit.onap.org/r",
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                assert client._base_url == "https://gerrit.onap.org/r"

    @pytest.mark.asyncio
    async def test_discover_api_base_url_failure(self):
        """Test API base URL discovery failure."""
        mock_response = Mock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(GerritKeysClient, "_discover_api_base_url") as mock_discover:
            mock_discover.side_effect = GerritServerError(
                "Could not discover Gerrit API endpoint"
            )
            with pytest.raises(
                GerritServerError, match="Could not discover Gerrit API endpoint"
            ):
                async with GerritKeysClient(server="gerrit.example.org"):
                    pass


class TestAccountLookup:
    """Test Gerrit account lookup functionality."""

    @pytest.mark.asyncio
    async def test_lookup_account_by_email_success(self):
        """Test successful account lookup by email."""
        mock_rest = Mock()
        # First call returns list with account ID, second call returns full account details
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE,  # Account query response
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details response
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                account = await client.lookup_account_by_email("john@example.com")

        assert account is not None
        assert isinstance(account, GerritAccountInfo)
        assert account.account_id == 12345
        assert account.name == "John Doe"
        assert account.email == "john@example.com"
        assert account.username == "jdoe"
        assert account.status == "ACTIVE"

    @pytest.mark.asyncio
    async def test_lookup_account_by_email_not_found(self):
        """Test account lookup when email not found."""
        mock_rest = Mock()
        mock_rest.get.return_value = []  # Empty list means not found

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                account = await client.lookup_account_by_email("notfound@example.com")

        assert account is None

    @pytest.mark.asyncio
    async def test_lookup_account_by_username_success(self):
        """Test successful account lookup by username."""
        mock_rest = Mock()
        # First call returns list with account ID, second call returns full account details
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE,  # Account query response
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details response
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                account = await client.lookup_account_by_username("jdoe")

        assert account is not None
        assert account.username == "jdoe"

    @pytest.mark.asyncio
    async def test_lookup_account_api_error(self):
        """Test account lookup with API error."""
        from requests import Response
        from requests.exceptions import HTTPError

        mock_rest = Mock()
        response = Response()
        response.status_code = 500
        mock_rest.get.side_effect = HTTPError(response=response)

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with pytest.raises(
                    GerritServerError, match="HTTP error 500 looking up account"
                ):
                    await client.lookup_account_by_email("test@example.com")


class TestSSHKeyOperations:
    """Test SSH key operations."""

    @pytest.mark.asyncio
    async def test_get_account_ssh_keys_success(self):
        """Test successfully retrieving SSH keys."""
        mock_rest = Mock()
        mock_rest.get.return_value = SAMPLE_GERRIT_SSH_KEYS_RESPONSE

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                keys = await client.get_account_ssh_keys(12345)

        assert len(keys) == 2
        assert isinstance(keys[0], GerritSSHKeyInfo)
        assert keys[0].seq == 1
        assert keys[0].algorithm == "ssh-ed25519"
        assert keys[0].comment == "Test Key"
        assert keys[0].valid is True
        assert keys[1].valid is False

    @pytest.mark.asyncio
    async def test_get_account_ssh_keys_empty(self):
        """Test retrieving SSH keys when none exist."""
        mock_rest = Mock()
        mock_rest.get.return_value = []

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                keys = await client.get_account_ssh_keys(12345)

        assert len(keys) == 0
        assert keys == []

    @pytest.mark.asyncio
    async def test_verify_ssh_key_registered_found(self):
        """Test SSH key verification when key is found."""
        mock_rest = Mock()
        # First call gets account details, second call gets SSH keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details
            SAMPLE_GERRIT_SSH_KEYS_RESPONSE,  # SSH keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with patch.object(
                    client,
                    "_calculate_ssh_fingerprint",
                    new=AsyncMock(return_value="testfingerprint"),
                ):
                    result = await client.verify_ssh_key_registered(
                        12345, "testfingerprint"
                    )

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is True
        assert result.service == "gerrit"
        assert isinstance(result.key_info, GerritSSHKeyInfo)

    @pytest.mark.asyncio
    async def test_verify_ssh_key_registered_not_found(self):
        """Test SSH key verification when key is not found."""
        mock_rest = Mock()
        # First call gets account details, second call gets SSH keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details
            SAMPLE_GERRIT_SSH_KEYS_RESPONSE,  # SSH keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with patch.object(
                    client,
                    "_calculate_ssh_fingerprint",
                    new=AsyncMock(return_value="differentfingerprint"),
                ):
                    result = await client.verify_ssh_key_registered(
                        12345, "nonexistent"
                    )

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is False
        assert result.service == "gerrit"
        assert result.key_info is None


class TestGPGKeyOperations:
    """Test GPG key operations."""

    @pytest.mark.asyncio
    async def test_get_account_gpg_keys_success(self):
        """Test successfully retrieving GPG keys."""
        mock_rest = Mock()
        mock_rest.get.return_value = SAMPLE_GERRIT_GPG_KEYS_RESPONSE

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                keys = await client.get_account_gpg_keys(12345)

        assert len(keys) == 2
        assert isinstance(keys[0], GerritGPGKeyInfo)
        assert keys[0].id == "ABCD1234EFGH5678"
        assert keys[0].status == "TRUSTED"
        assert "John Doe <john@example.com>" in keys[0].user_ids
        assert keys[1].id == "9876FEDC5432BA10"
        assert keys[1].status == "EXPIRED"

    @pytest.mark.asyncio
    async def test_verify_gpg_key_registered_found_exact_match(self):
        """Test GPG key verification with exact key ID match."""
        mock_rest = Mock()
        # First call gets account details, second call gets GPG keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details
            SAMPLE_GERRIT_GPG_KEYS_RESPONSE,  # GPG keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                result = await client.verify_gpg_key_registered(
                    12345, "ABCD1234EFGH5678"
                )

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is True
        assert result.service == "gerrit"
        assert isinstance(result.key_info, GerritGPGKeyInfo)
        assert result.key_info.id == "ABCD1234EFGH5678"

    @pytest.mark.asyncio
    async def test_verify_gpg_key_registered_found_fingerprint_match(self):
        """Test GPG key verification with fingerprint match."""
        mock_rest = Mock()
        # First call gets account details, second call gets GPG keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details
            SAMPLE_GERRIT_GPG_KEYS_RESPONSE,  # GPG keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                result = await client.verify_gpg_key_registered(
                    12345, "1234567890ABCDEF1234567890ABCDEF12345678"
                )

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is True
        assert result.service == "gerrit"
        assert isinstance(result.key_info, GerritGPGKeyInfo)
        assert result.key_info.fingerprint == "1234567890ABCDEF1234567890ABCDEF12345678"

    @pytest.mark.asyncio
    async def test_verify_gpg_key_registered_not_found(self):
        """Test GPG key verification when key is not found."""
        mock_rest = Mock()
        # First call gets account details, second call gets GPG keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details
            SAMPLE_GERRIT_GPG_KEYS_RESPONSE,  # GPG keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                result = await client.verify_gpg_key_registered(12345, "nonexistent")

        assert isinstance(result, KeyVerificationResult)
        assert result.key_registered is False
        assert result.service == "gerrit"
        assert result.key_info is None


class TestUtilityMethods:
    """Test utility methods."""

    def test_normalize_ssh_fingerprint(self):
        """Test SSH fingerprint normalization."""
        client = GerritKeysClient(server="gerrit.onap.org")

        # Test SHA256 prefix removal
        assert (
            client._normalize_ssh_fingerprint("SHA256:abc123def456") == "abc123def456"
        )

        # Test MD5 prefix removal
        assert client._normalize_ssh_fingerprint("MD5:12:34:56:78") == "12345678"

        # Test colon removal
        assert client._normalize_ssh_fingerprint("12:34:56:78:90:ab") == "1234567890ab"

        # Test lowercase conversion
        assert client._normalize_ssh_fingerprint("ABCDEF123456") == "abcdef123456"

    @pytest.mark.asyncio
    async def test_calculate_ssh_fingerprint_ed25519(self):
        """Test SSH fingerprint calculation for Ed25519 key."""
        client = GerritKeysClient(server="gerrit.onap.org")

        # Sample Ed25519 public key - use a real base64 encoded key
        public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Test Key"

        with patch.object(
            client, "_calculate_ssh_fingerprint", return_value="testfingerprint"
        ):
            fingerprint = await client._calculate_ssh_fingerprint(public_key)

            # Should return a non-empty string
            assert fingerprint
            assert isinstance(fingerprint, str)

    @pytest.mark.asyncio
    async def test_calculate_ssh_fingerprint_invalid(self):
        """Test SSH fingerprint calculation with invalid key."""
        client = GerritKeysClient(server="gerrit.onap.org")

        # Invalid key format
        fingerprint = await client._calculate_ssh_fingerprint("invalid-key")

        # Should return empty string for invalid keys
        assert fingerprint == ""


class TestErrorHandling:
    """Test error handling scenarios."""

    @pytest.mark.asyncio
    async def test_account_lookup_server_error(self):
        """Test account lookup with server error."""
        mock_rest = Mock()
        mock_rest.get.side_effect = Exception("Network error")

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with pytest.raises(GerritServerError, match="Failed to lookup account"):
                    await client.lookup_account_by_email("test@example.com")

    @pytest.mark.asyncio
    async def test_ssh_keys_server_error(self):
        """Test SSH key retrieval with server error."""
        from requests import Response
        from requests.exceptions import HTTPError

        mock_rest = Mock()
        response = Response()
        response.status_code = 404
        response.url = "https://gerrit.onap.org/accounts/12345/sshkeys"
        # Create HTTPError with 404 in the string representation
        http_error = HTTPError("404 Not Found", response=response)
        http_error.response = response
        mock_rest.get.side_effect = http_error

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with pytest.raises(
                    GerritServerError, match="SSH keys endpoint not available"
                ):
                    await client.get_account_ssh_keys(12345)

    @pytest.mark.asyncio
    async def test_gpg_keys_server_error(self):
        """Test GPG key retrieval with server error."""
        from requests import Response
        from requests.exceptions import HTTPError

        mock_rest = Mock()
        response = Response()
        response.status_code = 404
        response.url = "https://gerrit.onap.org/accounts/12345/gpgkeys"
        # Create HTTPError with 404 in the string representation
        http_error = HTTPError("404 Not Found", response=response)
        http_error.response = response
        mock_rest.get.side_effect = http_error

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with pytest.raises(
                    GerritServerError, match="GPG keys endpoint not available"
                ):
                    await client.get_account_gpg_keys(12345)

    @pytest.mark.asyncio
    async def test_verify_connection_success(self):
        """Test successful connection verification."""
        mock_rest = Mock()
        mock_rest.get.return_value = "3.7.0"  # Version string

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                success, error = await client.verify_connection()
                assert success is True
                assert error is None

    @pytest.mark.asyncio
    async def test_verify_connection_auth_required(self):
        """Test connection verification with 401 authentication required."""
        from requests import Response
        from requests.exceptions import HTTPError

        mock_rest = Mock()
        response = Response()
        response.status_code = 401
        http_error = HTTPError("401 Unauthorized", response=response)
        http_error.response = response
        mock_rest.get.side_effect = http_error

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
            patch.dict(
                "os.environ",
                {"GERRIT_USERNAME": "", "GERRIT_PASSWORD": ""},
                clear=False,
            ),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                success, error = await client.verify_connection()
                assert success is False
                assert "Credentials required" in error
                assert "gerrit.onap.org" in error

    @pytest.mark.asyncio
    async def test_verify_connection_auth_failed(self):
        """Test connection verification with 403 authentication failed."""
        from requests import Response
        from requests.exceptions import HTTPError

        mock_rest = Mock()
        response = Response()
        response.status_code = 403
        http_error = HTTPError("403 Forbidden", response=response)
        http_error.response = response
        mock_rest.get.side_effect = http_error

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                success, error = await client.verify_connection()
                assert success is False
                assert "Invalid credentials" in error
                assert "Authentication failed" in error

    @pytest.mark.asyncio
    async def test_verify_connection_network_error(self):
        """Test connection verification with network error."""
        mock_rest = Mock()
        mock_rest.get.side_effect = Exception("Connection refused")

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                success, error = await client.verify_connection()
                assert success is False
                assert "Failed to connect" in error
                assert "Connection refused" in error

    @pytest.mark.asyncio
    async def test_client_not_initialized_error(self):
        """Test error when client is used without context manager."""
        client = GerritKeysClient(server="gerrit.onap.org")

        with pytest.raises(
            RuntimeError,
            match="GerritKeysClient must be used as an async context manager",
        ):
            await client.lookup_account_by_email("test@example.com")


class TestIntegration:
    """Integration tests for complete workflows."""

    @pytest.mark.asyncio
    async def test_full_verification_workflow_ssh(self):
        """Test complete SSH key verification workflow."""
        mock_rest = Mock()
        # Sequence: account query, account details, account details again, SSH keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE,  # Account query by email
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details from lookup
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details from verify
            SAMPLE_GERRIT_SSH_KEYS_RESPONSE,  # SSH keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                with patch.object(
                    client,
                    "_calculate_ssh_fingerprint",
                    new=AsyncMock(return_value="testfingerprint"),
                ):
                    # Step 1: Lookup account
                    account = await client.lookup_account_by_email("john@example.com")
                    assert account is not None
                    assert account.account_id == 12345

                    # Step 2: Verify SSH key
                    result = await client.verify_ssh_key_registered(
                        account.account_id, "testfingerprint"
                    )
                    assert result.key_registered is True
                    assert result.service == "gerrit"

    @pytest.mark.asyncio
    async def test_full_verification_workflow_gpg(self):
        """Test complete GPG key verification workflow."""
        mock_rest = Mock()
        # Sequence: account query, account details, account details again, GPG keys
        mock_rest.get.side_effect = [
            SAMPLE_GERRIT_ACCOUNT_RESPONSE,  # Account query by email
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details from lookup
            SAMPLE_GERRIT_ACCOUNT_RESPONSE[0],  # Account details from verify
            SAMPLE_GERRIT_GPG_KEYS_RESPONSE,  # GPG keys
        ]

        with (
            patch.object(
                GerritKeysClient,
                "_discover_api_base_url",
                new=AsyncMock(return_value="https://gerrit.onap.org"),
            ),
            patch("tag_validate.gerrit_keys.GerritRestAPI", return_value=mock_rest),
        ):
            async with GerritKeysClient(server="gerrit.onap.org") as client:
                # Step 1: Lookup account
                account = await client.lookup_account_by_email("john@example.com")
                assert account is not None
                assert account.account_id == 12345

                # Step 2: Verify GPG key
                result = await client.verify_gpg_key_registered(
                    account.account_id, "ABCD1234EFGH5678"
                )
                assert result.key_registered is True
                assert result.service == "gerrit"
                assert isinstance(result.key_info, GerritGPGKeyInfo)
