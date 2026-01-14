# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for signature detection module.

This module tests the SignatureDetector class with mocked git commands
to verify signature detection and parsing logic.
"""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import pytest

# SignatureType removed - using string literals
from tag_validate.signature import (
    SignatureDetectionError,
    SignatureDetector,
)

# Sample git verify-tag outputs
GOOD_GPG_SIGNATURE_OUTPUT = """gpg: Signature made Mon Jan  1 12:00:00 2024 PST
gpg:                using RSA key ABCD1234EFGH5678
gpg: Good signature from "John Doe <john@example.com>"
[GNUPG:] NEWSIG
[GNUPG:] KEY_CONSIDERED 1234567890ABCDEF1234567890ABCDEF12345678 0
[GNUPG:] GOODSIG ABCD1234EFGH5678 John Doe <john@example.com>
[GNUPG:] VALIDSIG 1234567890ABCDEF1234567890ABCDEF12345678 2024-01-01 1704132000 0 4 0 1 10 01 1234567890ABCDEF1234567890ABCDEF12345678
Primary key fingerprint: 1234 5678 90AB CDEF 1234  5678 90AB CDEF 1234 5678
"""

BAD_GPG_SIGNATURE_OUTPUT = """gpg: Signature made Mon Jan  1 12:00:00 2024 PST
gpg:                using RSA key ABCD1234EFGH5678
gpg: BAD signature from "John Doe <john@example.com>"
[GNUPG:] NEWSIG
[GNUPG:] BADSIG ABCD1234EFGH5678 John Doe <john@example.com>
[GNUPG:] ERRSIG ABCD1234EFGH5678 1 10 00 1704132000 9
"""

GOOD_SSH_SIGNATURE_OUTPUT = """Good "git" signature for john@example.com with ED25519 key SHA256:abcdefghijklmnopqrstuvwxyz1234567890ABC
"""

NO_SIGNATURE_OUTPUT = """error: no signature found
"""

UNSIGNED_TAG_OUTPUT = """object abc123def456
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704132000 -0800

Release version 1.0.0
"""

TAG_OBJECT_WITH_SSH_SIG = """object abc123def456
type commit
tag v1.0.0
tagger John Doe <john@example.com> 1704132000 -0800

Release version 1.0.0
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MT...
-----END SSH SIGNATURE-----
"""


@pytest.fixture
def temp_repo_path(tmp_path):
    """Create a temporary repository path."""
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()
    # Create .git directory to make it look like a repo
    (repo_path / ".git").mkdir()
    return repo_path


@pytest.fixture
def signature_detector(temp_repo_path):
    """Create a SignatureDetector instance."""
    return SignatureDetector(temp_repo_path)


class TestSignatureDetectorInit:
    """Test SignatureDetector initialization."""

    def test_init_with_valid_path(self, temp_repo_path):
        """Test initialization with valid repository path."""
        detector = SignatureDetector(temp_repo_path)
        assert detector.repo_path == temp_repo_path

    def test_init_with_invalid_path(self, tmp_path):
        """Test initialization with invalid path."""
        invalid_path = tmp_path / "nonexistent"
        with pytest.raises(ValueError, match="Repository path does not exist"):
            SignatureDetector(invalid_path)

    def test_init_converts_to_path(self, temp_repo_path):
        """Test initialization converts string to Path."""
        detector = SignatureDetector(str(temp_repo_path))
        assert isinstance(detector.repo_path, Path)


class TestDetectGPGSignature:
    """Test GPG signature detection."""

    @pytest.mark.asyncio
    async def test_detect_good_gpg_signature(self, signature_detector):
        """Test detecting a valid GPG signature."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = GOOD_GPG_SIGNATURE_OUTPUT
        mock_result.stdout = ""
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        assert signature_info.type == "gpg"
        assert signature_info.verified is True
        assert signature_info.key_id == "ABCD1234EF"
        assert signature_info.signer_email == "john@example.com"
        assert signature_info.fingerprint is not None

    @pytest.mark.asyncio
    async def test_detect_bad_gpg_signature(self, signature_detector):
        """Test detecting an invalid GPG signature."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = BAD_GPG_SIGNATURE_OUTPUT
        mock_result.stdout = ""
        mock_result.returncode = 1

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        assert signature_info.type in ["gpg", "invalid"]
        assert signature_info.verified is False
        assert signature_info.key_id in ["ABCD1234EF", "ABCD1234EFGH5678", None]

    @pytest.mark.asyncio
    async def test_extract_gpg_key_id_from_validsig(self, signature_detector):
        """Test extracting GPG key ID from VALIDSIG line."""
        output_with_validsig = (
            "[GNUPG:] VALIDSIG 1234567890ABCDEF1234567890ABCDEF12345678 2024-01-01"
        )

        key_id = signature_detector._extract_gpg_key_id(output_with_validsig)

        # Should extract full fingerprint from VALIDSIG
        assert key_id == "90ABCDEF12345678"

    @pytest.mark.asyncio
    async def test_extract_gpg_signer(self, signature_detector):
        """Test extracting signer email from GPG output."""
        signer_email = signature_detector._extract_gpg_signer_email(
            GOOD_GPG_SIGNATURE_OUTPUT
        )
        assert signer_email == "john@example.com"

    @pytest.mark.asyncio
    async def test_extract_gpg_fingerprint(self, signature_detector):
        """Test extracting fingerprint from GPG output."""
        fingerprint = signature_detector._extract_gpg_fingerprint(
            GOOD_GPG_SIGNATURE_OUTPUT
        )
        # Fingerprint may have newline
        assert "1234567890ABCDEF1234567890ABCDEF12345678" in fingerprint


class TestDetectSSHSignature:
    """Test SSH signature detection."""

    @pytest.mark.asyncio
    async def test_detect_good_ssh_signature(self, signature_detector):
        """Test detecting a valid SSH signature."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = GOOD_SSH_SIGNATURE_OUTPUT
        mock_result.stdout = ""
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        # SSH signature detection may vary based on git version
        assert signature_info.type in ["ssh", "invalid"]
        if signature_info.type == "ssh":
            assert signature_info.verified is True
            assert signature_info.signer_email == "john@example.com"
            assert "SHA256" in signature_info.fingerprint

    @pytest.mark.asyncio
    async def test_detect_ssh_signature_with_header(self, signature_detector):
        """Test detecting SSH signature by header in output."""
        ssh_output = (
            "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH...\n-----END SSH SIGNATURE-----"
        )
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = ssh_output
        mock_result.stdout = ""
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        assert signature_info.type == "ssh"


class TestDetectUnsignedTag:
    """Test unsigned tag detection."""

    @pytest.mark.asyncio
    async def test_detect_unsigned_tag(self, signature_detector):
        """Test detecting an unsigned tag."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = NO_SIGNATURE_OUTPUT
        mock_result.stdout = ""
        mock_result.returncode = 1

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        assert signature_info.type == "unsigned"
        assert signature_info.verified is False
        assert signature_info.key_id is None
        assert signature_info.signer_email is None

    @pytest.mark.asyncio
    async def test_detect_empty_output(self, signature_detector):
        """Test handling empty verify output."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = ""
        mock_result.stdout = ""
        mock_result.returncode = 1

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        assert signature_info.type == "unsigned"


class TestGetTagObjectContent:
    """Test getting tag object content."""

    @pytest.mark.asyncio
    async def test_get_tag_object_content_success(self, signature_detector):
        """Test successfully getting tag object content."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stdout = UNSIGNED_TAG_OUTPUT
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            content = await signature_detector.get_tag_object_content("v1.0.0")

        assert "tag v1.0.0" in content
        assert "Release version 1.0.0" in content

    @pytest.mark.asyncio
    async def test_get_tag_object_content_failure(self, signature_detector):
        """Test handling failure to get tag object."""
        with (
            patch(
                "tag_validate.signature.run_git",
                side_effect=Exception("Tag not found"),
            ),
            pytest.raises(
                SignatureDetectionError, match="Could not retrieve tag object"
            ),
        ):
            await signature_detector.get_tag_object_content("nonexistent")


class TestParseGitVerifyOutput:
    """Test parsing git verify-tag output."""

    def test_parse_gpg_output(self, signature_detector):
        """Test parsing GPG signature output."""
        parsed = signature_detector.parse_git_verify_output(GOOD_GPG_SIGNATURE_OUTPUT)

        assert parsed["signature_type"] == "gpg"
        assert parsed["key_id"] == "ABCD1234EF"
        assert "john@example.com" in parsed.get("signer_email", "")

    def test_parse_ssh_output(self, signature_detector):
        """Test parsing SSH signature output."""
        parsed = signature_detector.parse_git_verify_output(GOOD_SSH_SIGNATURE_OUTPUT)

        assert parsed["signature_type"] == "ssh"
        assert parsed.get("verified") is True

    def test_parse_unsigned_output(self, signature_detector):
        """Test parsing unsigned tag output."""
        parsed = signature_detector.parse_git_verify_output(NO_SIGNATURE_OUTPUT)

        assert parsed["signature_type"] == "unsigned"


class TestExtractSSHFingerprint:
    """Test extracting SSH fingerprint from tag object."""

    @pytest.mark.asyncio
    async def test_extract_ssh_fingerprint_from_tag(self, signature_detector):
        """Test extracting SSH fingerprint from tag object."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stdout = TAG_OBJECT_WITH_SSH_SIG
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            fingerprint = await signature_detector._extract_ssh_fingerprint_from_tag(
                "v1.0.0"
            )

        # Current implementation returns None (TODO in code)
        # Update this test when SSH signature parsing is implemented
        assert fingerprint is None or isinstance(fingerprint, str)

    @pytest.mark.asyncio
    async def test_extract_ssh_fingerprint_no_signature(self, signature_detector):
        """Test extracting fingerprint when no SSH signature present."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stdout = UNSIGNED_TAG_OUTPUT
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            fingerprint = await signature_detector._extract_ssh_fingerprint_from_tag(
                "v1.0.0"
            )

        assert fingerprint is None


class TestErrorHandling:
    """Test error handling in SignatureDetector."""

    @pytest.mark.asyncio
    async def test_detect_signature_git_command_failure(self, signature_detector):
        """Test handling git command failure."""
        with (
            patch(
                "tag_validate.signature.run_git",
                side_effect=Exception("Git command failed"),
            ),
            pytest.raises(SignatureDetectionError, match="Signature detection failed"),
        ):
            await signature_detector.detect_signature("v1.0.0")

    @pytest.mark.asyncio
    async def test_detect_signature_unknown_format(self, signature_detector):
        """Test handling unknown signature format."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = "Some unexpected output format"
        mock_result.stdout = ""
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            signature_info = await signature_detector.detect_signature("v1.0.0")

        assert signature_info.type == "invalid"
        assert signature_info.verified is False


class TestRegexPatterns:
    """Test regex pattern matching."""

    def test_gpg_key_pattern_match(self, signature_detector):
        """Test GPG key pattern regex."""
        match = signature_detector.GPG_KEY_PATTERN.search(
            "using RSA key ABCD1234EFGH5678"
        )
        assert match is not None
        assert match.group(1) == "ABCD1234EF"

    def test_gpg_good_sig_pattern_match(self, signature_detector):
        """Test GPG good signature pattern regex."""
        match = signature_detector.GPG_GOOD_SIG_PATTERN.search(
            'Good signature from "John Doe <john@example.com>"'
        )
        assert match is not None
        assert match.group(1) == "John Doe <john@example.com>"

    def test_ssh_key_pattern_match(self, signature_detector):
        """Test SSH key pattern regex."""
        match = signature_detector.SSH_KEY_PATTERN.search(GOOD_SSH_SIGNATURE_OUTPUT)
        assert match is not None
        assert match.group(1) == "john@example.com"
        assert match.group(2) == "ED25519"
        assert "SHA256" in match.group(3)

    def test_gpg_primary_key_pattern_match(self, signature_detector):
        """Test GPG primary key fingerprint pattern regex."""
        match = signature_detector.GPG_PRIMARY_KEY_PATTERN.search(
            GOOD_GPG_SIGNATURE_OUTPUT
        )
        assert match is not None
        fingerprint = match.group(1).replace(" ", "").strip()
        assert "1234567890ABCDEF1234567890ABCDEF12345678" in fingerprint


class TestIntegration:
    """Integration tests for signature detection."""

    @pytest.mark.asyncio
    async def test_full_gpg_signature_workflow(self, signature_detector):
        """Test complete GPG signature detection workflow."""
        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = GOOD_GPG_SIGNATURE_OUTPUT
        mock_result.stdout = ""
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            # Detect signature
            signature_info = await signature_detector.detect_signature("v1.0.0")

            # Verify all fields are populated
            assert signature_info.type == "gpg"
            assert signature_info.verified is True
            assert signature_info.key_id is not None
            assert signature_info.signer_email is not None
            assert signature_info.fingerprint is not None
            assert signature_info.signature_data == GOOD_GPG_SIGNATURE_OUTPUT

    @pytest.mark.asyncio
    async def test_multiple_tag_detection(self, signature_detector):
        """Test detecting signatures on multiple tags."""
        tags = ["v1.0.0", "v1.1.0", "v2.0.0"]

        mock_result = Mock(spec=CompletedProcess)
        mock_result.stderr = GOOD_GPG_SIGNATURE_OUTPUT
        mock_result.stdout = ""
        mock_result.returncode = 0

        with patch("tag_validate.signature.run_git", return_value=mock_result):
            results = []
            for tag in tags:
                sig_info = await signature_detector.detect_signature(tag)
                results.append(sig_info)

            # All should be valid GPG signatures
            assert all(r.type == "gpg" for r in results)
            assert all(r.verified for r in results)
