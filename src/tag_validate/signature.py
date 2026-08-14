# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Signature detection and parsing for Git tags.

This module provides functionality to detect, parse, and extract information
from GPG and SSH signatures on Git tags. It uses git commands via dependamerge's
git_ops module for secure execution.
"""

import logging
from pathlib import Path

from dependamerge.git_ops import run_git

from .models import SignatureInfo
from .signature_gpg import GpgSignatureMixin
from .signature_ssh import SshSignatureMixin

logger = logging.getLogger(__name__)


class SignatureDetectionError(Exception):
    """Raised when signature detection fails."""

    pass


class SignatureDetector(GpgSignatureMixin, SshSignatureMixin):
    """
    Detects and parses cryptographic signatures on Git tags.

    This class provides methods to:
    - Detect signature type (GPG, SSH, or unsigned)
    - Extract GPG key IDs from verification output
    - Extract SSH public keys from tag objects
    - Parse git verify-tag output
    """

    def __init__(self, repo_path: str | Path):
        """
        Initialize the signature detector.

        Args:
            repo_path: Path to the Git repository (str or Path)
        """
        self.repo_path = Path(repo_path)
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path does not exist: {repo_path}")

    async def detect_signature(self, tag_name: str) -> SignatureInfo:
        """
        Detect and parse the signature on a Git tag.

        This method:
        1. Runs git verify-tag to check signature validity
        2. Determines signature type (GPG, SSH, or none)
        3. Extracts relevant signature details
        4. Returns a structured SignatureInfo object

        Args:
            tag_name: Name of the tag to verify

        Returns:
            SignatureInfo object with signature details

        Raises:
            SignatureDetectionError: If signature detection fails
        """
        logger.debug(f"Detecting signature on tag: {tag_name}")

        try:
            # Run git verify-tag to check signature
            result = run_git(
                ["git", "verify-tag", "--raw", tag_name],
                cwd=self.repo_path,
                check=False,  # Don't raise on non-zero exit (unsigned tags)
            )

            # Git writes signature info to stderr
            verify_output = result.stderr

            # Check if tag has a signature
            if not verify_output or "no signature found" in verify_output.lower():
                logger.debug(f"Tag {tag_name} is unsigned")
                return SignatureInfo(
                    type="unsigned",
                    verified=False,
                )

            # Check for SSH signature configuration error
            if "gpg.ssh.allowedSignersFile needs to be configured" in verify_output:
                logger.debug(
                    "SSH signature detected but allowedSignersFile not configured"
                )
                # Still try to parse SSH signature from tag object
                return await self._parse_ssh_signature(tag_name, verify_output)

            # Detect signature type
            if "BADSIG" in verify_output:
                # Invalid/corrupted GPG signature
                return await self._parse_invalid_gpg_signature(tag_name, verify_output)
            elif "ERRSIG" in verify_output:
                # GPG signature exists but key not available for verification
                return await self._parse_unverifiable_gpg_signature(
                    tag_name, verify_output
                )
            elif (
                "GOODSIG" in verify_output
                or "using RSA key" in verify_output
                or "using DSA key" in verify_output
                or "using ECDSA key" in verify_output
                or "using EdDSA key" in verify_output
            ):
                # Valid GPG signature
                return await self._parse_gpg_signature(tag_name, verify_output)
            elif (
                self.SSH_SIG_HEADER in verify_output
                or "ssh signature" in verify_output.lower()
                or 'Good "git" signature' in verify_output
            ):
                # SSH signature
                return await self._parse_ssh_signature(tag_name, verify_output)
            else:
                # Unknown signature type
                logger.warning(f"Unknown signature type for tag {tag_name}")
                return SignatureInfo(
                    type="invalid",
                    verified=False,
                    signature_data=verify_output,
                )

        except Exception as e:
            logger.error(f"Failed to detect signature on tag {tag_name}: {e}")
            raise SignatureDetectionError(
                f"Signature detection failed for tag {tag_name}: {e}"
            ) from e

    async def get_tag_object_content(self, tag_name: str) -> str:
        """
        Get the raw content of a tag object.

        Args:
            tag_name: Name of the tag

        Returns:
            Raw tag object content

        Raises:
            SignatureDetectionError: If tag object cannot be retrieved
        """
        try:
            result = run_git(
                ["git", "cat-file", "tag", tag_name],
                cwd=self.repo_path,
                check=True,
            )
            return str(result.stdout)

        except Exception as e:
            logger.error(f"Failed to get tag object content: {e}")
            raise SignatureDetectionError(
                f"Could not retrieve tag object for {tag_name}: {e}"
            ) from e

    def parse_git_verify_output(self, output: str) -> dict[str, str | bool]:
        """
        Parse git verify-tag output into a structured dictionary.

        This is a utility method for extracting all available information
        from the verify output.

        Args:
            output: Raw output from git verify-tag

        Returns:
            Dictionary with parsed fields
        """
        parsed: dict[str, str | bool] = {
            "raw_output": output,
            "has_signature": "signature" in output.lower(),
            "is_valid": "GOODSIG" in output
            or "VALIDSIG" in output
            or 'Good "git" signature' in output,
            "signature_type": "unknown",
        }

        if (
            "GOODSIG" in output
            or "using RSA key" in output
            or "using DSA key" in output
            or "using ECDSA key" in output
            or "using EdDSA key" in output
        ):
            parsed["signature_type"] = "gpg"
        elif (
            self.SSH_SIG_HEADER in output
            or "ssh signature" in output.lower()
            or 'Good "git" signature' in output
        ):
            parsed["signature_type"] = "ssh"
        elif "no signature found" in output.lower():
            parsed["signature_type"] = "unsigned"

        # Extract additional fields
        if parsed["signature_type"] == "gpg":
            key_id = self._extract_gpg_key_id(output)
            email = self._extract_gpg_signer_email(output)
            fingerprint = self._extract_gpg_fingerprint(output)
            if key_id:
                parsed["key_id"] = key_id
            if email:
                parsed["signer_email"] = email
            if fingerprint:
                parsed["fingerprint"] = fingerprint
        elif parsed["signature_type"] == "ssh":
            # For SSH signatures, also set verified field
            parsed["verified"] = parsed["is_valid"]

        return parsed
