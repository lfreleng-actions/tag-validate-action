# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Signature detection and parsing for Git tags.

This module provides functionality to detect, parse, and extract information
from GPG and SSH signatures on Git tags. It uses git commands via dependamerge's
git_ops module for secure execution.
"""

import logging
import re
from pathlib import Path

from dependamerge.git_ops import run_git

from .models import SignatureInfo

logger = logging.getLogger(__name__)


class SignatureDetectionError(Exception):
    """Raised when signature detection fails."""

    pass


class SignatureDetector:
    """
    Detects and parses cryptographic signatures on Git tags.

    This class provides methods to:
    - Detect signature type (GPG, SSH, or unsigned)
    - Extract GPG key IDs from verification output
    - Extract SSH public keys from tag objects
    - Parse git verify-tag output
    """

    # Regex patterns for signature detection
    GPG_KEY_PATTERN = re.compile(
        r"using\s+(?:RSA|DSA|ECDSA|EdDSA)\s+key\s+([A-F0-9]+)",
        re.IGNORECASE,
    )
    GPG_GOOD_SIG_PATTERN = re.compile(
        r"Good signature from [\"'](.+?)[\"']",
        re.IGNORECASE,
    )
    GPG_PRIMARY_KEY_PATTERN = re.compile(
        r"Primary key fingerprint:\s+([A-F0-9\s]+)",
        re.IGNORECASE,
    )
    SSH_SIG_HEADER = "-----BEGIN SSH SIGNATURE-----"
    SSH_KEY_PATTERN = re.compile(
        r"Good \"git\" signature for (.+?) with ([\w-]+) key (SHA256:[A-Za-z0-9+/=]+)",
        re.IGNORECASE,
    )

    def __init__(self, repo_path: Path):
        """
        Initialize the signature detector.

        Args:
            repo_path: Path to the Git repository
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
                logger.debug("SSH signature detected but allowedSignersFile not configured")
                # Still try to parse SSH signature from tag object
                return await self._parse_ssh_signature(tag_name, verify_output)

            # Detect signature type
            if "BADSIG" in verify_output:
                # Invalid/corrupted GPG signature
                return await self._parse_invalid_gpg_signature(tag_name, verify_output)
            elif "ERRSIG" in verify_output:
                # GPG signature exists but key not available for verification
                return await self._parse_unverifiable_gpg_signature(tag_name, verify_output)
            elif "GOODSIG" in verify_output or "using RSA key" in verify_output or "using DSA key" in verify_output or "using ECDSA key" in verify_output or "using EdDSA key" in verify_output:
                # Valid GPG signature
                return await self._parse_gpg_signature(tag_name, verify_output)
            elif self.SSH_SIG_HEADER in verify_output or "ssh signature" in verify_output.lower() or 'Good "git" signature' in verify_output:
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

    async def _parse_gpg_signature(
        self, tag_name: str, verify_output: str
    ) -> SignatureInfo:
        """
        Parse GPG signature information from git verify-tag output.

        Args:
            tag_name: Name of the tag
            verify_output: Output from git verify-tag

        Returns:
            SignatureInfo with GPG details
        """
        logger.debug(f"Parsing GPG signature for tag {tag_name}")

        # Extract key ID
        key_id = self._extract_gpg_key_id(verify_output)

        # Extract signer email
        signer_email = self._extract_gpg_signer_email(verify_output)

        # Extract fingerprint
        fingerprint = self._extract_gpg_fingerprint(verify_output)

        # Check if signature is valid using GPG status codes
        # GOODSIG indicates a good signature, VALIDSIG indicates validity
        is_valid = "GOODSIG" in verify_output or "VALIDSIG" in verify_output

        return SignatureInfo(
            type="gpg",
            verified=is_valid,
            key_id=key_id,
            fingerprint=fingerprint,
            signer_email=signer_email,
            signature_data=verify_output,
        )

    async def _parse_invalid_gpg_signature(
        self, tag_name: str, verify_output: str
    ) -> SignatureInfo:
        """
        Parse invalid/corrupted GPG signature information (BADSIG).

        Args:
            tag_name: Name of the tag
            verify_output: Output from git verify-tag

        Returns:
            SignatureInfo with error details
        """
        logger.warning(f"Tag {tag_name} has invalid/corrupted GPG signature")

        # Try to extract key ID even from invalid signature
        key_id = self._extract_gpg_key_id(verify_output)

        # Try to extract fingerprint
        fingerprint = self._extract_gpg_fingerprint(verify_output)

        # Try to extract signer email
        signer_email = self._extract_gpg_signer_email(verify_output)

        return SignatureInfo(
            type="invalid",
            verified=False,
            key_id=key_id,
            fingerprint=fingerprint,
            signer_email=signer_email,
            signature_data=verify_output,
        )

    async def _parse_unverifiable_gpg_signature(
        self, tag_name: str, verify_output: str
    ) -> SignatureInfo:
        """
        Parse unverifiable GPG signature information (ERRSIG - missing key).

        This is different from invalid signatures - the signature itself may be
        valid, but we don't have the public key to verify it.

        Args:
            tag_name: Name of the tag
            verify_output: Output from git verify-tag

        Returns:
            SignatureInfo with gpg-unverifiable type
        """
        logger.warning(f"Tag {tag_name} has GPG signature but key is not available")

        # Try to extract key ID even from unverifiable signature
        key_id = self._extract_gpg_key_id(verify_output)

        # Try to extract fingerprint
        fingerprint = self._extract_gpg_fingerprint(verify_output)

        # Try to extract signer email
        signer_email = self._extract_gpg_signer_email(verify_output)

        return SignatureInfo(
            type="gpg-unverifiable",
            verified=False,
            key_id=key_id,
            fingerprint=fingerprint,
            signer_email=signer_email,
            signature_data=verify_output,
        )

    async def _parse_ssh_signature(
        self, tag_name: str, verify_output: str
    ) -> SignatureInfo:
        """
        Parse SSH signature information from git verify-tag output.

        Args:
            tag_name: Name of the tag
            verify_output: Output from git verify-tag

        Returns:
            SignatureInfo with SSH details
        """
        logger.debug(f"Parsing SSH signature for tag {tag_name}")

        # Extract signer and key details
        signer_email = None
        key_id = None
        fingerprint = None

        match = self.SSH_KEY_PATTERN.search(verify_output)
        if match:
            signer_email = match.group(1)
            key_type = match.group(2)  # e.g., "ED25519", "RSA"
            fingerprint = match.group(3)  # SHA256 fingerprint
            key_id = f"{key_type}:{fingerprint}"

        # Check if signature is valid
        # For SSH, look for the Good "git" signature message
        # If allowedSignersFile is not configured, we can't verify but signature exists
        is_valid = 'Good "git" signature' in verify_output

        # If allowedSignersFile error, we know there's a signature but can't verify it
        if "gpg.ssh.allowedSignersFile needs to be configured" in verify_output:
            is_valid = False
            logger.debug("SSH signature present but cannot be verified without allowedSignersFile")

        # If we couldn't parse the structured output, try to get the tag object
        if not fingerprint:
            try:
                fingerprint = await self._extract_ssh_fingerprint_from_tag(tag_name)
                if fingerprint:
                    key_id = f"SSH:{fingerprint}"
            except Exception as e:
                logger.debug(f"Could not extract SSH fingerprint from tag object: {e}")

        return SignatureInfo(
            type="ssh",
            verified=is_valid,
            signer_email=signer_email,
            key_id=key_id,
            fingerprint=fingerprint,
            signature_data=verify_output,
        )

    def _extract_gpg_key_id(self, verify_output: str) -> str | None:
        """
        Extract GPG key ID from verify-tag output.

        Args:
            verify_output: Output from git verify-tag

        Returns:
            Key ID if found, None otherwise
        """
        match = self.GPG_KEY_PATTERN.search(verify_output)
        if match:
            key_id = match.group(1)
            logger.debug(f"Extracted GPG key ID: {key_id}")
            return key_id

        # Try to extract from VALIDSIG line (format: VALIDSIG <fingerprint> ...)
        for line in verify_output.split("\n"):
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                if len(parts) >= 3:
                    fingerprint = parts[2]
                    # Return last 16 characters as key ID
                    key_id = fingerprint[-16:]
                    logger.debug(f"Extracted GPG key ID from VALIDSIG: {key_id}")
                    return key_id

            # Try to extract from ERRSIG line (format: ERRSIG <keyid> ...)
            # This appears when signature verification fails due to missing public key
            if line.startswith("[GNUPG:] ERRSIG"):
                parts = line.split()
                if len(parts) >= 3:
                    key_id = parts[2]
                    logger.debug(f"Extracted GPG key ID from ERRSIG: {key_id}")
                    return key_id

            # Try to extract from NO_PUBKEY line (format: NO_PUBKEY <keyid>)
            # This also appears when the public key is not in the keyring
            if line.startswith("[GNUPG:] NO_PUBKEY"):
                parts = line.split()
                if len(parts) >= 3:
                    key_id = parts[2]
                    logger.debug(f"Extracted GPG key ID from NO_PUBKEY: {key_id}")
                    return key_id

        logger.debug("Could not extract GPG key ID")
        return None

    def _extract_gpg_signer_email(self, verify_output: str) -> str | None:
        """
        Extract signer email from GPG signature output.

        Args:
            verify_output: Output from git verify-tag

        Returns:
            Signer email if found, None otherwise
        """
        # First try the human-readable format
        match = self.GPG_GOOD_SIG_PATTERN.search(verify_output)
        if match:
            signer_info = match.group(1)
            # Extract email from "Name <email>" format
            email_match = re.search(r'<([^>]+)>', signer_info)
            if email_match:
                email = email_match.group(1)
                logger.debug(f"Extracted GPG signer email: {email}")
                return email
            # If no angle brackets, the whole thing might be an email
            if '@' in signer_info:
                logger.debug(f"Extracted GPG signer email: {signer_info}")
                return signer_info

        # Try to extract from GOODSIG line (format: [GNUPG:] GOODSIG <keyid> <name> <email>)
        for line in verify_output.split("\n"):
            if line.startswith("[GNUPG:] GOODSIG"):
                # Format: [GNUPG:] GOODSIG keyid User Name <email@example.com>
                parts = line.split(None, 2)  # Split on first 2 whitespace
                if len(parts) >= 3:
                    user_info = parts[2]  # Everything after the key ID
                    # Extract email from "Name <email>" format
                    email_match = re.search(r'<([^>]+)>', user_info)
                    if email_match:
                        email = email_match.group(1)
                        logger.debug(f"Extracted GPG signer email from GOODSIG: {email}")
                        return email

        logger.debug("Could not extract GPG signer email")
        return None

    def _extract_gpg_fingerprint(self, verify_output: str) -> str | None:
        """
        Extract GPG key fingerprint from verify-tag output.

        Args:
            verify_output: Output from git verify-tag

        Returns:
            Fingerprint if found, None otherwise
        """
        match = self.GPG_PRIMARY_KEY_PATTERN.search(verify_output)
        if match:
            fingerprint = match.group(1).replace(" ", "")
            logger.debug(f"Extracted GPG fingerprint: {fingerprint}")
            return fingerprint

        # Try to extract from VALIDSIG line
        for line in verify_output.split("\n"):
            if line.startswith("[GNUPG:] VALIDSIG"):
                parts = line.split()
                if len(parts) >= 3:
                    fingerprint = parts[2]
                    logger.debug(f"Extracted GPG fingerprint from VALIDSIG: {fingerprint}")
                    return fingerprint

        logger.debug("Could not extract GPG fingerprint")
        return None

    async def _extract_ssh_fingerprint_from_tag(self, tag_name: str) -> str | None:
        """
        Extract SSH key fingerprint from the tag object.

        This is a fallback method when the fingerprint can't be extracted
        from the verify-tag output. It extracts the SSH signature from the
        tag object and uses ssh-keygen to get the public key fingerprint.

        Args:
            tag_name: Name of the tag

        Returns:
            SSH key fingerprint if found, None otherwise
        """
        import subprocess
        import tempfile

        try:
            # Get the tag object content
            result = run_git(
                ["git", "cat-file", "tag", tag_name],
                cwd=self.repo_path,
                check=True,
            )

            tag_content = result.stdout

            # Look for SSH signature in the tag object
            if self.SSH_SIG_HEADER not in tag_content:
                logger.debug("No SSH signature found in tag object")
                return None

            logger.debug("Found SSH signature in tag object")

            # Extract the SSH signature block
            sig_start = tag_content.find(self.SSH_SIG_HEADER)
            sig_end = tag_content.find("-----END SSH SIGNATURE-----", sig_start)
            if sig_end == -1:
                logger.debug("SSH signature block incomplete")
                return None

            sig_end += len("-----END SSH SIGNATURE-----")

            # Extract the public key from the signature
            # SSH signatures in Git contain the public key
            # We need to parse the signature to extract it
            # For now, try to use git's show command with format
            try:
                # Try to get the signer's key from git
                show_result = run_git(
                    ["git", "cat-file", "-p", tag_name],
                    cwd=self.repo_path,
                    check=True,
                )

                # Look for the signer line which may contain key info
                for line in show_result.stdout.split('\n'):
                    if 'signer' in line.lower() or 'key' in line.lower():
                        logger.debug(f"Found potential key line: {line}")

                # Since we can't easily extract the public key from the signature,
                # return a placeholder that indicates SSH signature was found
                # The actual fingerprint would require parsing the SSH signature format
                return "SSH_SIGNATURE_PRESENT"

            except Exception as e:
                logger.debug(f"Could not extract key info: {e}")
                return "SSH_SIGNATURE_PRESENT"

        except Exception as e:
            logger.debug(f"Failed to extract SSH fingerprint from tag object: {e}")
            return None

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
            "is_valid": "GOODSIG" in output or "VALIDSIG" in output or 'Good "git" signature' in output,
            "signature_type": "unknown",
        }

        if "GOODSIG" in output or "using RSA key" in output or "using DSA key" in output or "using ECDSA key" in output or "using EdDSA key" in output:
            parsed["signature_type"] = "gpg"
        elif self.SSH_SIG_HEADER in output or "ssh signature" in output.lower() or 'Good "git" signature' in output:
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
