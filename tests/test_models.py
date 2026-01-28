# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for Pydantic models in tag_validate.models.

This module tests:
- Model validation and serialization
- Enum types
- Optional fields
- Model relationships
"""

from tag_validate.models import (
    GitHubVerificationInfo,
    GPGKeyInfo,
    KeyVerificationResult,
    RepositoryInfo,
    SignatureInfo,
    SSHKeyInfo,
    TagInfo,
    ValidationConfig,
    ValidationResult,
    VersionInfo,
)


class TestSignatureTypes:
    """Test signature type literals."""

    def test_signature_type_values(self):
        """Test valid signature type values."""
        valid_types = [
            "gpg",
            "ssh",
            "unsigned",
            "lightweight",
            "invalid",
            "gpg-unverifiable",
        ]
        for sig_type in valid_types:
            sig = SignatureInfo(
                type=sig_type,
                verified=False,
            )
            assert sig.type == sig_type


class TestSignatureInfo:
    """Test SignatureInfo model."""

    def test_valid_gpg_signature(self):
        """Test creating a valid GPG signature info."""
        sig = SignatureInfo(
            type="gpg",
            verified=True,
            signer_email="john@example.com",
            key_id="ABCD1234EFGH5678",
            fingerprint="1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678",
            signature_data="gpg: Good signature from...",
        )

        assert sig.type == "gpg"
        assert sig.verified is True
        assert sig.signer_email == "john@example.com"
        assert sig.key_id == "ABCD1234EFGH5678"
        assert sig.fingerprint is not None

    def test_valid_ssh_signature(self):
        """Test creating a valid SSH signature info."""
        sig = SignatureInfo(
            type="ssh",
            verified=True,
            signer_email="jane@example.com",
            key_id="SHA256:abc123def456",
            fingerprint="SHA256:abc123def456",
            signature_data="Good ssh signature...",
        )

        assert sig.type == "ssh"
        assert sig.verified is True

    def test_unsigned_tag(self):
        """Test creating info for unsigned tag."""
        sig = SignatureInfo(
            type="unsigned",
            verified=False,
            signature_data="no signature found",
        )

        assert sig.type == "unsigned"
        assert sig.verified is False
        assert sig.signer_email is None

    def test_model_serialization(self):
        """Test model can be serialized to dict."""
        sig = SignatureInfo(
            type="gpg",
            verified=True,
            signer_email="test@example.com",
            key_id="ABC123",
            fingerprint=None,
            signature_data="output",
        )

        data = sig.model_dump()
        assert data["type"] == "gpg"
        assert data["verified"] is True
        assert data["key_id"] == "ABC123"


class TestGPGKeyInfo:
    """Test GPGKeyInfo model."""

    def test_valid_gpg_key(self):
        """Test creating a valid GPG key info."""
        key = GPGKeyInfo(
            id=12345,
            key_id="ABCD1234",
            raw_key="-----BEGIN PGP PUBLIC KEY BLOCK-----...",
            emails=["test@example.com"],
            can_sign=True,
            can_certify=False,
            can_encrypt_comms=True,
            can_encrypt_storage=False,
            created_at="2024-01-01T00:00:00Z",
            expires_at=None,
        )

        assert key.key_id == "ABCD1234"
        assert "test@example.com" in key.emails
        assert key.can_sign is True

    def test_expired_key(self):
        """Test expired key detection."""
        key = GPGKeyInfo(
            id=12346,
            key_id="EXPIRED123",
            raw_key="-----BEGIN PGP PUBLIC KEY BLOCK-----...",
            emails=["old@example.com"],
            can_sign=True,
            can_certify=False,
            can_encrypt_comms=False,
            can_encrypt_storage=False,
            created_at="2019-01-01T00:00:00Z",
            expires_at="2020-01-01T00:00:00Z",
        )

        assert key.expires_at is not None

    def test_multiple_emails(self):
        """Test key with multiple email addresses."""
        key = GPGKeyInfo(
            id=12347,
            key_id="MULTI123",
            raw_key="-----BEGIN PGP PUBLIC KEY BLOCK-----...",
            emails=["primary@example.com", "secondary@example.com", "work@company.com"],
            can_sign=True,
            can_certify=True,
            can_encrypt_comms=True,
            can_encrypt_storage=True,
            created_at="2024-01-01T00:00:00Z",
            expires_at=None,
        )

        assert len(key.emails) == 3
        assert "work@company.com" in key.emails

    def test_gpg_key_with_subkeys(self):
        """Test GPG key with subkeys."""
        subkey = GPGKeyInfo(
            id=12348,
            key_id="SUBKEY1234",
            primary_key_id=12347,
            can_sign=True,
            can_certify=False,
            can_encrypt_comms=False,
            can_encrypt_storage=False,
            created_at="2024-01-01T00:00:00Z",
            expires_at=None,
        )

        key = GPGKeyInfo(
            id=12347,
            key_id="PRIMARY123",
            name="My Signing Key",
            raw_key="-----BEGIN PGP PUBLIC KEY BLOCK-----...",
            emails=["test@example.com"],
            can_sign=True,
            can_certify=True,
            can_encrypt_comms=False,
            can_encrypt_storage=False,
            created_at="2024-01-01T00:00:00Z",
            expires_at=None,
            subkeys=[subkey],
        )

        assert key.key_id == "PRIMARY123"
        assert key.name == "My Signing Key"
        assert len(key.subkeys) == 1
        assert key.subkeys[0].key_id == "SUBKEY1234"
        assert key.subkeys[0].primary_key_id == 12347


class TestSSHKeyInfo:
    """Test SSHKeyInfo model."""

    def test_valid_ssh_key(self):
        """Test creating a valid SSH key info."""
        key = SSHKeyInfo(
            id=54321,
            title="Work Laptop",
            key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
            created_at="2024-01-01T00:00:00Z",
        )

        assert key.title == "Work Laptop"
        assert key.key.startswith("ssh-ed25519")

    def test_ssh_key_serialization(self):
        """Test SSH key can be serialized."""
        key = SSHKeyInfo(
            id=54322,
            title="Test Key",
            key="ssh-rsa AAAAB3NzaC1yc2EA...",
            created_at="2024-01-01T00:00:00Z",
        )

        data = key.model_dump()
        assert data["title"] == "Test Key"
        assert "ssh-rsa" in data["key"]


class TestGitHubVerificationInfo:
    """Test GitHubVerificationInfo model."""

    def test_verified_signature(self):
        """Test verified signature info."""
        info = GitHubVerificationInfo(
            verified=True,
            reason="valid",
            signature="-----BEGIN PGP SIGNATURE-----...",
            payload="commit content...",
        )

        assert info.verified is True
        assert info.reason == "valid"

    def test_unverified_signature(self):
        """Test unverified signature info."""
        info = GitHubVerificationInfo(
            verified=False,
            reason="unknown_key",
            signature=None,
            payload=None,
        )

        assert info.verified is False
        assert info.reason == "unknown_key"


class TestKeyVerificationResult:
    """Test KeyVerificationResult model."""

    def test_registered_key(self):
        """Test result for registered key."""
        result = KeyVerificationResult(
            key_registered=True,
            username="testuser",
            key_info=GPGKeyInfo(
                id=12345,
                key_id="ABCD1234",
                can_sign=True,
                created_at="2024-01-01T00:00:00Z",
            ),
        )

        assert result.key_registered is True
        assert result.username == "testuser"
        assert result.key_info is not None

    def test_unregistered_key(self):
        """Test result for unregistered key."""
        result = KeyVerificationResult(
            key_registered=False,
            username="testuser",
            key_info=None,
        )

        assert result.key_registered is False
        assert result.key_info is None


class TestVersionTypes:
    """Test version type handling."""

    def test_version_type_fields(self):
        """Test version type boolean fields."""
        version = VersionInfo(
            raw="1.0.0",
            normalized="1.0.0",
            is_valid=True,
            version_type="semver",
            has_prefix=True,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
        )
        assert version.version_type == "semver"
        assert version.has_prefix is True


class TestVersionInfo:
    """Test VersionInfo model."""

    def test_valid_semver(self):
        """Test valid SemVer version."""
        version = VersionInfo(
            raw="1.2.3",
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

        assert version.version_type == "semver"
        assert version.major == 1
        assert version.minor == 2
        assert version.patch == 3

    def test_semver_with_prerelease(self):
        """Test SemVer with prerelease tag."""
        version = VersionInfo(
            raw="2.0.0-alpha.1",
            normalized="2.0.0-alpha.1",
            is_valid=True,
            version_type="semver",
            has_prefix=True,
            is_development=True,
            major=2,
            minor=0,
            patch=0,
            prerelease="alpha.1",
            build_metadata=None,
        )

        assert version.prerelease == "alpha.1"
        assert version.is_development is True

    def test_semver_with_build_metadata(self):
        """Test SemVer with build metadata."""
        version = VersionInfo(
            raw="1.0.0+20230101",
            normalized="1.0.0+20230101",
            is_valid=True,
            version_type="semver",
            has_prefix=False,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
            prerelease=None,
            build_metadata="20230101",
        )

        assert version.build_metadata == "20230101"

    def test_calver(self):
        """Test CalVer version."""
        version = VersionInfo(
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

        assert version.version_type == "calver"
        assert version.year == 2024

    def test_development_detection(self):
        """Test development version detection."""
        dev_versions = [
            ("1.0.0-alpha", "alpha"),
            ("1.0.0-beta.1", "beta.1"),
            ("1.0.0-rc.2", "rc.2"),
            ("1.0.0-dev", "dev"),
            ("1.0.0-snapshot", "snapshot"),
        ]

        for raw_version, prerelease in dev_versions:
            version = VersionInfo(
                raw=raw_version,
                normalized=raw_version,
                is_valid=True,
                version_type="semver",
                has_prefix=False,
                is_development=True,
                major=1,
                minor=0,
                patch=0,
                prerelease=prerelease,
                build_metadata=None,
            )
            assert version.is_development is True, f"{raw_version} should be dev"

    def test_stable_version(self):
        """Test stable version detection."""
        version = VersionInfo(
            raw="1.0.0",
            normalized="1.0.0",
            is_valid=True,
            version_type="semver",
            has_prefix=False,
            is_development=False,
            major=1,
            minor=0,
            patch=0,
            prerelease=None,
            build_metadata=None,
        )

        assert version.is_development is False


class TestValidationConfig:
    """Test ValidationConfig model."""

    def test_default_config(self):
        """Test default configuration."""
        config = ValidationConfig()

        assert config.require_signed is False
        assert config.require_unsigned is False
        assert config.require_github is False
        assert config.require_semver is False
        assert config.require_calver is False

    def test_custom_config(self):
        """Test custom configuration."""
        config = ValidationConfig(
            require_signed=True,
            require_semver=True,
            require_github=True,
            reject_development=True,
            allow_prefix=False,
        )

        assert config.require_signed is True
        assert config.require_semver is True
        assert config.require_github is True
        assert config.reject_development is True
        assert config.allow_prefix is False

    def test_config_serialization(self):
        """Test config can be serialized."""
        config = ValidationConfig(
            require_signed=True,
            require_semver=True,
        )

        data = config.model_dump()
        assert data["require_signed"] is True
        assert data["require_semver"] is True


class TestValidationResult:
    """Test ValidationResult model."""

    def test_successful_validation(self):
        """Test successful validation result."""
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
            version_info=VersionInfo(
                raw="1.0.0",
                normalized="1.0.0",
                is_valid=True,
                version_type="semver",
                has_prefix=True,
                is_development=False,
                major=1,
                minor=0,
                patch=0,
                prerelease=None,
                build_metadata=None,
            ),
            signature_info=SignatureInfo(
                type="gpg",
                verified=True,
                signer_email="test@example.com",
                key_id="ABC123",
                fingerprint=None,
                signature_data="Good signature",
            ),
            key_verification=KeyVerificationResult(
                key_registered=True,
                username="testuser",
            ),
            errors=[],
            warnings=[],
        )

        assert result.is_valid is True
        assert result.tag_name == "v1.0.0"
        assert len(result.errors) == 0

    def test_failed_validation(self):
        """Test failed validation result."""
        result = ValidationResult(
            tag_name="invalid-tag",
            is_valid=False,
            config=ValidationConfig(),
            errors=["Invalid version format", "No signature found"],
            warnings=["Tag does not follow convention"],
        )

        assert result.is_valid is False
        assert len(result.errors) == 2
        assert len(result.warnings) == 1

    def test_validation_with_warnings(self):
        """Test validation result with warnings."""
        result = ValidationResult(
            tag_name="v1.0.0-beta",
            is_valid=True,
            config=ValidationConfig(),
            version_info=VersionInfo(
                raw="1.0.0-beta",
                normalized="1.0.0-beta",
                is_valid=True,
                version_type="semver",
                has_prefix=True,
                is_development=True,
                major=1,
                minor=0,
                patch=0,
                prerelease="beta",
                build_metadata=None,
            ),
            warnings=["Development version detected"],
        )

        assert result.is_valid is True
        assert len(result.warnings) == 1
        assert len(result.errors) == 0


class TestTagInfo:
    """Test TagInfo model."""

    def test_basic_tag_info(self):
        """Test basic tag information."""
        tag = TagInfo(
            tag_name="v1.0.0",
            commit_sha="abc123def456",
            tag_type="annotated",
            tagger_name="John Doe",
            tagger_email="john@example.com",
            tag_message="Release version 1.0.0",
        )

        assert tag.tag_name == "v1.0.0"
        assert tag.commit_sha == "abc123def456"
        assert tag.tagger_email == "john@example.com"

    def test_tag_without_tagger(self):
        """Test tag without tagger info (lightweight tag)."""
        tag = TagInfo(
            tag_name="v1.0.0",
            commit_sha="abc123def456",
            tag_type="lightweight",
            tagger_name=None,
            tagger_email=None,
            tag_message=None,
        )

        assert tag.tagger_name is None
        assert tag.tagger_email is None


class TestRepositoryInfo:
    """Test RepositoryInfo model."""

    def test_repository_info(self):
        """Test repository information."""
        repo = RepositoryInfo(
            owner="testorg",
            name="testrepo",
            clone_url="https://github.com/testorg/testrepo.git",
            web_url="https://github.com/testorg/testrepo",
        )

        assert repo.owner == "testorg"
        assert repo.name == "testrepo"
        assert repo.clone_url == "https://github.com/testorg/testrepo.git"

    def test_fork_repository(self):
        """Test fork repository info."""
        repo = RepositoryInfo(
            owner="user",
            name="forked-repo",
            clone_url="https://github.com/user/forked-repo.git",
        )

        assert repo.owner == "user"
        assert repo.name == "forked-repo"


class TestModelIntegration:
    """Test model integration and relationships."""

    def test_complete_validation_result(self):
        """Test creating a complete validation result with all sub-models."""
        result = ValidationResult(
            tag_name="v1.2.3",
            is_valid=True,
            config=ValidationConfig(),
            version_info=VersionInfo(
                raw="1.2.3",
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
            ),
            signature_info=SignatureInfo(
                type="gpg",
                verified=True,
                signer_email="test@example.com",
                key_id="ABCD1234",
                fingerprint="1234567890ABCDEF",
                signature_data="gpg: Good signature",
            ),
            key_verifications=[
                KeyVerificationResult(
                    key_registered=True,
                    username="testuser",
                )
            ],
        )

        # Test serialization of nested models
        data = result.model_dump()
        assert data["is_valid"] is True
        assert data["version_info"]["version_type"] == "semver"
        assert data["signature_info"]["type"] == "gpg"
        assert data["key_verifications"][0]["key_registered"] is True

    def test_json_serialization(self):
        """Test JSON serialization of complex nested models."""
        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=ValidationConfig(),
            version_info=VersionInfo(
                raw="1.0.0",
                normalized="1.0.0",
                is_valid=True,
                version_type="semver",
                has_prefix=True,
                is_development=False,
                major=1,
                minor=0,
                patch=0,
                prerelease=None,
                build_metadata=None,
            ),
        )

        # Should be able to convert to JSON
        json_str = result.model_dump_json()
        assert isinstance(json_str, str)
        assert "v1.0.0" in json_str
        assert "version_type" in json_str
        assert "semver" in json_str


class TestGerritAccountInfo:
    """Test GerritAccountInfo model."""

    def test_valid_gerrit_account(self, sample_gerrit_account):
        """Test valid Gerrit account creation."""
        account = sample_gerrit_account

        assert account.account_id == 12345
        assert account.name == "John Doe"
        assert account.email == "john@example.com"
        assert account.username == "jdoe"
        assert account.status == "ACTIVE"

    def test_gerrit_account_serialization(self, sample_gerrit_account):
        """Test Gerrit account JSON serialization."""
        account = sample_gerrit_account
        json_data = account.model_dump()

        assert json_data["account_id"] == 12345
        assert json_data["name"] == "John Doe"
        assert json_data["email"] == "john@example.com"
        assert json_data["username"] == "jdoe"
        assert json_data["status"] == "ACTIVE"


class TestGerritSSHKeyInfo:
    """Test GerritSSHKeyInfo model."""

    def test_valid_gerrit_ssh_key(self, sample_gerrit_ssh_key):
        """Test valid Gerrit SSH key creation."""
        key = sample_gerrit_ssh_key

        assert key.seq == 1
        assert key.algorithm == "ssh-ed25519"
        assert key.comment == "Test Key"
        assert key.valid is True
        assert "AAAAC3NzaC1lZDI1NTE5" in key.ssh_public_key

    def test_gerrit_ssh_key_serialization(self, sample_gerrit_ssh_key):
        """Test Gerrit SSH key JSON serialization."""
        key = sample_gerrit_ssh_key
        json_data = key.model_dump()

        assert json_data["seq"] == 1
        assert json_data["algorithm"] == "ssh-ed25519"
        assert json_data["valid"] is True


class TestGerritGPGKeyInfo:
    """Test GerritGPGKeyInfo model."""

    def test_valid_gerrit_gpg_key(self, sample_gerrit_gpg_key):
        """Test valid Gerrit GPG key creation."""
        key = sample_gerrit_gpg_key

        assert key.id == "ABCD1234EFGH5678"
        assert key.fingerprint == "1234567890ABCDEF1234567890ABCDEF12345678"
        assert "John Doe <john@example.com>" in key.user_ids
        assert key.status == "TRUSTED"
        assert key.problems == []

    def test_gerrit_gpg_key_serialization(self, sample_gerrit_gpg_key):
        """Test Gerrit GPG key JSON serialization."""
        key = sample_gerrit_gpg_key
        json_data = key.model_dump()

        assert json_data["id"] == "ABCD1234EFGH5678"
        assert json_data["status"] == "TRUSTED"
        assert len(json_data["user_ids"]) == 1


class TestGerritKeyVerificationResult:
    """Test KeyVerificationResult with Gerrit service."""

    def test_gerrit_key_verification_success(
        self, sample_gerrit_key_verification_result
    ):
        """Test successful Gerrit key verification result."""
        result = sample_gerrit_key_verification_result

        assert result.key_registered is True
        assert result.username == "12345"
        assert result.service == "gerrit"
        assert result.server == "gerrit.onap.org"
        assert result.user_enumerated is False

    def test_gerrit_key_verification_failed(self):
        """Test failed Gerrit key verification result."""
        from tag_validate.models import KeyVerificationResult

        result = KeyVerificationResult(
            key_registered=False,
            username="12345",
            user_enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        assert result.key_registered is False
        assert result.service == "gerrit"
        assert result.key_info is None


class TestValidationConfigWithGerrit:
    """Test ValidationConfig with Gerrit fields."""

    def test_gerrit_config_creation(self, sample_gerrit_validation_config):
        """Test ValidationConfig with Gerrit settings."""
        config = sample_gerrit_validation_config

        assert config.require_gerrit is True
        assert config.gerrit_server == "gerrit.onap.org"
        assert config.require_github is False  # Should be False by default

    def test_combined_github_gerrit_config(self):
        """Test ValidationConfig with both GitHub and Gerrit."""
        from tag_validate.models import ValidationConfig

        config = ValidationConfig(
            require_github=True,
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
            require_signed=True,
            allowed_signature_types=["gpg", "ssh"],
        )

        assert config.require_github is True
        assert config.require_gerrit is True
        assert config.gerrit_server == "gerrit.onap.org"
        assert "gpg" in config.allowed_signature_types
        assert "ssh" in config.allowed_signature_types

    def test_gerrit_config_serialization(self, sample_gerrit_validation_config):
        """Test Gerrit config JSON serialization."""
        config = sample_gerrit_validation_config
        json_data = config.model_dump()

        assert json_data["require_gerrit"] is True
        assert json_data["gerrit_server"] == "gerrit.onap.org"
        assert json_data["require_github"] is False


class TestGerritIntegration:
    """Test Gerrit models integration."""

    def test_complete_gerrit_verification_result(self):
        """Test complete verification result with Gerrit key info."""
        from tag_validate.models import (
            GerritSSHKeyInfo,
            KeyVerificationResult,
        )

        ssh_key = GerritSSHKeyInfo(
            seq=1,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz",
            encoded_key="AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz",
            algorithm="ssh-ed25519",
            comment="Test Key",
            valid=True,
        )

        result = KeyVerificationResult(
            key_registered=True,
            username="12345",
            enumerated=True,
            key_info=ssh_key,
            service="gerrit",
            server="gerrit.onap.org",
        )

        assert result.key_registered is True
        assert result.service == "gerrit"
        assert isinstance(result.key_info, GerritSSHKeyInfo)
        assert result.key_info.algorithm == "ssh-ed25519"
        assert result.server == "gerrit.onap.org"

    def test_validation_result_with_gerrit_verification(self):
        """Test ValidationResult with Gerrit key verification."""
        from tag_validate.models import (
            KeyVerificationResult,
            SignatureInfo,
            TagInfo,
            ValidationConfig,
            ValidationResult,
            VersionInfo,
        )

        config = ValidationConfig(
            require_gerrit=True,
            gerrit_server="gerrit.onap.org",
            require_signed=True,
        )

        key_verification = KeyVerificationResult(
            key_registered=True,
            username="12345",
            user_enumerated=False,
            key_info=None,
            service="gerrit",
            server="gerrit.onap.org",
        )

        result = ValidationResult(
            tag_name="v1.0.0",
            is_valid=True,
            config=config,
            tag_info=TagInfo(
                tag_name="v1.0.0",
                tag_type="annotated",
                commit_sha="abc123",
                tagger_name="John Doe",
                tagger_email="john@example.com",
                tag_date="2024-01-01T12:00:00Z",
            ),
            version_info=VersionInfo(
                raw="v1.0.0",
                normalized="1.0.0",
                is_valid=True,
                version_type="semver",
                has_prefix=True,
                is_development=False,
                major=1,
                minor=0,
                patch=0,
            ),
            signature_info=SignatureInfo(
                type="ssh",
                verified=True,
                signer_email="john@example.com",
                fingerprint="SHA256:abc123def456",
            ),
            key_verifications=[key_verification],
        )

        assert result.is_valid is True
        assert result.config.require_gerrit is True
        assert result.key_verifications[0].service == "gerrit"
        assert result.key_verifications[0].key_registered is True
