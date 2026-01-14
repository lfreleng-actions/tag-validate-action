# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for tag validation using real test repositories.

These tests clone real test repositories from GitHub (lfreleng-actions/test-tags-*)
and validate tags using the Python implementation. This ensures the Python code
works correctly with real Git repositories and signatures.

These tests are meant to run in CI or locally with network access.
"""

import os
import shutil
from collections.abc import Generator
from pathlib import Path

import pytest

from tag_validate.signature import SignatureDetector
from tag_validate.tag_operations import TagOperations
from tag_validate.validation import TagValidator

# Test repository information
SEMVER_REPO = "lfreleng-actions/test-tags-semantic"
CALVER_REPO = "lfreleng-actions/test-tags-calver"


def is_ci_without_gpg_keys() -> bool:
    """
    Check if we're running in a CI environment without GPG keys.

    This is common when CI is triggered by pull requests from forks,
    where secrets (including GPG keys) are not available for security reasons.

    Returns:
        True if in CI without keys, False otherwise
    """
    # First, try to detect if the test GPG key is actually available
    # This is the most reliable method
    import subprocess

    try:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "test@tag-validate-action.local"],
            capture_output=True,
            check=False,
            timeout=5,
        )
        # If key is found, GPG keys ARE available
        if result.returncode == 0:
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # GPG command timed out or gpg binary not found - treat as keys unavailable
        # Fall through to check CI environment variables below
        pass

    # Fallback: Check if we're in GitHub Actions
    is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"

    # Check if triggered by a pull request
    is_pull_request = os.getenv("GITHUB_EVENT_NAME") == "pull_request"

    # If in GitHub Actions on a PR, keys are typically not available
    # (this is GitHub's default security behavior for PRs from forks)
    # Return True if both conditions are met
    return is_github_actions and is_pull_request


@pytest.fixture(scope="module")
def semver_repo_path(tmp_path_factory) -> Generator[Path, None, None]:
    """Clone the SemVer test repository.

    This fixture clones the test repository once per test module
    and returns the path to it.
    """
    repo_path = tmp_path_factory.mktemp("semver_repo")

    # Clone the repository
    import subprocess

    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            f"https://github.com/{SEMVER_REPO}.git",
            str(repo_path),
        ],
        check=True,
        capture_output=True,
    )

    # Fetch all tags
    subprocess.run(
        ["git", "fetch", "--tags", "--depth", "1"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    yield repo_path

    # Cleanup
    shutil.rmtree(repo_path, ignore_errors=True)


@pytest.fixture(scope="module")
def calver_repo_path(tmp_path_factory) -> Generator[Path, None, None]:
    """Clone the CalVer test repository.

    This fixture clones the test repository once per test module
    and returns the path to it.
    """
    repo_path = tmp_path_factory.mktemp("calver_repo")

    # Clone the repository
    import subprocess

    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            f"https://github.com/{CALVER_REPO}.git",
            str(repo_path),
        ],
        check=True,
        capture_output=True,
    )

    # Fetch all tags
    subprocess.run(
        ["git", "fetch", "--tags", "--depth", "1"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    yield repo_path

    # Cleanup
    shutil.rmtree(repo_path, ignore_errors=True)


class TestSemVerRepository:
    """Integration tests using the SemVer test repository."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_gpg_signed_tag(self, semver_repo_path: Path):
        """Test detection of GPG-signed tag in SemVer repo."""
        detector = SignatureDetector(semver_repo_path)

        # v0.1.4-gpg-test is a GPG-signed tag
        sig_info = await detector.detect_signature("v0.1.4-gpg-test")

        # GPG signature type depends on key availability
        # - "gpg" when key is in keyring and verified
        # - "gpg-unverifiable" when signature exists but key not available
        if is_ci_without_gpg_keys():
            # In CI without GPG keys (e.g., PR from fork), expect unverifiable
            assert sig_info.type == "gpg-unverifiable"
            assert sig_info.verified is False
            # Key ID should still be extracted even if unverifiable
            assert sig_info.key_id is not None
        else:
            # With GPG keys available, expect verified signature
            assert sig_info.type == "gpg"
            assert sig_info.verified is True
            assert sig_info.key_id is not None
            assert sig_info.signer_email is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_ssh_signed_tag(self, semver_repo_path: Path):
        """Test detection of SSH-signed tag in SemVer repo."""
        detector = SignatureDetector(semver_repo_path)

        # v0.1.3-ssh-signed is an SSH-signed tag
        sig_info = await detector.detect_signature("v0.1.3-ssh-signed")

        assert sig_info.type == "ssh"
        assert sig_info.fingerprint is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_unsigned_tag(self, semver_repo_path: Path):
        """Test detection of unsigned tag in SemVer repo."""
        detector = SignatureDetector(semver_repo_path)

        # v0.1.2-unsigned is an unsigned tag
        sig_info = await detector.detect_signature("v0.1.2-unsigned")

        assert sig_info.type == "unsigned"
        assert sig_info.verified is False

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_tag_info_extraction(self, semver_repo_path: Path):
        """Test extraction of tag information."""
        ops = TagOperations()

        tag_info = await ops.fetch_tag_info(
            "v0.1.4-gpg-test", repo_path=semver_repo_path
        )

        assert tag_info.tag_name == "v0.1.4-gpg-test"
        assert tag_info.commit_sha is not None
        assert len(tag_info.commit_sha) == 40  # Full SHA
        assert tag_info.tag_type in ["annotated", "lightweight"]

    @pytest.mark.integration
    def test_version_validation_semver(self):
        """Test version validation for SemVer tags."""
        validator = TagValidator()

        # Test various SemVer tags from the repo
        test_cases = [
            ("v0.1.4-gpg-test", True, "semver"),
            ("v0.1.3-ssh-signed", True, "semver"),
            ("v0.1.2-unsigned", True, "semver"),
        ]

        for tag, should_be_valid, expected_type in test_cases:
            result = validator.validate_version(tag)
            assert result.is_valid == should_be_valid, f"Tag {tag} validation failed"
            assert result.version_type == expected_type, f"Tag {tag} type mismatch"


class TestCalVerRepository:
    """Integration tests using the CalVer test repository."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_gpg_signed_tag(self, calver_repo_path: Path):
        """Test detection of GPG-signed tag in CalVer repo."""
        detector = SignatureDetector(calver_repo_path)

        # 2025.1.4-gpg-test is a GPG-signed tag
        sig_info = await detector.detect_signature("2025.1.4-gpg-test")

        # GPG signature type depends on key availability
        # - "gpg" when key is in keyring and verified
        # - "gpg-unverifiable" when signature exists but key not available
        if is_ci_without_gpg_keys():
            # In CI without GPG keys (e.g., PR from fork), expect unverifiable
            assert sig_info.type == "gpg-unverifiable"
            assert sig_info.verified is False
            # Key ID should still be extracted even if unverifiable
            assert sig_info.key_id is not None
        else:
            # With GPG keys available, expect verified signature
            assert sig_info.type == "gpg"
            assert sig_info.verified is True
            assert sig_info.key_id is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_ssh_signed_tag(self, calver_repo_path: Path):
        """Test detection of SSH-signed tag in CalVer repo."""
        detector = SignatureDetector(calver_repo_path)

        # 2025.1.3-ssh-signed is an SSH-signed tag
        sig_info = await detector.detect_signature("2025.1.3-ssh-signed")

        assert sig_info.type == "ssh"
        assert sig_info.fingerprint is not None

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_unsigned_tag(self, calver_repo_path: Path):
        """Test detection of unsigned tag in CalVer repo."""
        detector = SignatureDetector(calver_repo_path)

        # 2025.1.2-unsigned is an unsigned tag
        sig_info = await detector.detect_signature("2025.1.2-unsigned")

        assert sig_info.type == "unsigned"
        assert sig_info.verified is False

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_tag_info_extraction(self, calver_repo_path: Path):
        """Test extraction of tag information."""
        ops = TagOperations()

        tag_info = await ops.fetch_tag_info(
            "2025.1.4-gpg-test", repo_path=calver_repo_path
        )

        assert tag_info.tag_name == "2025.1.4-gpg-test"
        assert tag_info.commit_sha is not None
        assert len(tag_info.commit_sha) == 40  # Full SHA
        assert tag_info.tag_type in ["annotated", "lightweight"]

    @pytest.mark.integration
    def test_version_validation_calver(self):
        """Test version validation for CalVer tags."""
        validator = TagValidator()

        # Test various CalVer tags from the repo
        test_cases = [
            ("2025.1.4-gpg-test", True, "calver"),
            ("2025.1.3-ssh-signed", True, "calver"),
            ("2025.1.2-unsigned", True, "calver"),
        ]

        for tag, should_be_valid, expected_type in test_cases:
            # Strip the suffix for validation
            version_part = tag.split("-")[0]
            result = validator.validate_version(version_part)
            assert result.is_valid == should_be_valid, (
                f"Tag {version_part} validation failed"
            )
            assert result.version_type == expected_type, (
                f"Tag {version_part} type mismatch"
            )


class TestRemoteTagCloning:
    """Integration tests for cloning remote tags."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_clone_remote_semver_tag(self, tmp_path: Path):
        """Test cloning a remote SemVer tag."""
        ops = TagOperations()

        # Parse the repository
        owner, repo = SEMVER_REPO.split("/")

        # Clone the tag
        temp_dir, tag_info = await ops.clone_remote_tag(
            owner=owner,
            repo=repo,
            tag="v0.1.4-gpg-test",
        )

        try:
            assert temp_dir.exists()
            assert tag_info.tag_name == "v0.1.4-gpg-test"
            assert tag_info.remote_url == f"https://github.com/{SEMVER_REPO}"
            assert tag_info.commit_sha is not None
        finally:
            # Cleanup
            from dependamerge.git_ops import secure_rmtree

            secure_rmtree(temp_dir)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_clone_remote_calver_tag(self, tmp_path: Path):
        """Test cloning a remote CalVer tag."""
        ops = TagOperations()

        # Parse the repository
        owner, repo = CALVER_REPO.split("/")

        # Clone the tag
        temp_dir, tag_info = await ops.clone_remote_tag(
            owner=owner,
            repo=repo,
            tag="2025.1.4-gpg-test",
        )

        try:
            assert temp_dir.exists()
            assert tag_info.tag_name == "2025.1.4-gpg-test"
            assert tag_info.remote_url == f"https://github.com/{CALVER_REPO}"
            assert tag_info.commit_sha is not None
        finally:
            # Cleanup
            from dependamerge.git_ops import secure_rmtree

            secure_rmtree(temp_dir)


class TestEndToEndWorkflow:
    """End-to-end integration tests combining multiple components."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_validation_workflow_semver(self, semver_repo_path: Path):
        """Test complete validation workflow for SemVer tag."""
        # Step 1: Validate version format
        validator = TagValidator()
        version_result = validator.validate_version("v0.1.4-gpg-test")

        assert version_result.is_valid
        assert version_result.version_type == "semver"
        assert version_result.major == 0
        assert version_result.minor == 1
        assert version_result.patch == 4

        # Step 2: Fetch tag information
        ops = TagOperations()
        tag_info = await ops.fetch_tag_info(
            "v0.1.4-gpg-test", repo_path=semver_repo_path
        )

        assert tag_info.tag_name == "v0.1.4-gpg-test"
        assert tag_info.commit_sha is not None

        # Step 3: Detect signature
        detector = SignatureDetector(semver_repo_path)
        sig_info = await detector.detect_signature("v0.1.4-gpg-test")

        # GPG signature type depends on key availability
        if is_ci_without_gpg_keys():
            # In CI without GPG keys (e.g., PR from fork), expect unverifiable
            assert sig_info.type == "gpg-unverifiable"
            assert sig_info.verified is False
        else:
            # With GPG keys available, expect verified signature
            assert sig_info.type == "gpg"
            assert sig_info.verified is True

        # Workflow complete - all checks passed
        assert True

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_full_validation_workflow_calver(self, calver_repo_path: Path):
        """Test complete validation workflow for CalVer tag."""
        # Step 1: Validate version format
        validator = TagValidator()
        version_result = validator.validate_version("2025.1.4")

        assert version_result.is_valid
        assert version_result.version_type == "calver"
        assert version_result.year == 2025
        assert version_result.month == 1

        # Step 2: Fetch tag information
        ops = TagOperations()
        tag_info = await ops.fetch_tag_info(
            "2025.1.4-gpg-test", repo_path=calver_repo_path
        )

        assert tag_info.tag_name == "2025.1.4-gpg-test"
        assert tag_info.commit_sha is not None

        # Step 3: Detect signature
        detector = SignatureDetector(calver_repo_path)
        sig_info = await detector.detect_signature("2025.1.4-gpg-test")

        # GPG signature type depends on key availability
        if is_ci_without_gpg_keys():
            # In CI without GPG keys (e.g., PR from fork), expect unverifiable
            assert sig_info.type == "gpg-unverifiable"
            assert sig_info.verified is False
        else:
            # With GPG keys available, expect verified signature
            assert sig_info.type == "gpg"
            assert sig_info.verified is True

        # Workflow complete - all checks passed
        assert True

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_validation_workflow_unsigned(self, semver_repo_path: Path):
        """Test validation workflow for unsigned tag (should detect correctly)."""
        # Validate version
        validator = TagValidator()
        version_result = validator.validate_version("v0.1.2-unsigned")
        assert version_result.is_valid

        # Detect signature (should be unsigned)
        detector = SignatureDetector(semver_repo_path)
        sig_info = await detector.detect_signature("v0.1.2-unsigned")

        assert sig_info.type == "unsigned"
        assert sig_info.verified is False

        # Even though unsigned, version is valid
        assert version_result.is_valid is True


# Helper function to run integration tests
def run_integration_tests():
    """Helper function to run integration tests from command line."""
    import sys

    # Run with integration marker
    exit_code = pytest.main(
        [
            __file__,
            "-v",
            "-m",
            "integration",
            "--tb=short",
        ]
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    run_integration_tests()
