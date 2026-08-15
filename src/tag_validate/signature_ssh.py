# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
SSH signature parsing for Git tags.

Reads ``git verify-tag`` output for SSH-signed tags and, when the
fingerprint is absent from that output, falls back to inspecting the tag
object itself.
"""

import base64
import binascii
import hashlib
import logging
import re
import struct
from pathlib import Path

from .models import SignatureInfo

# Bound to the public module's name so log records keep reporting
# `tag_validate.signature` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.signature")

SSH_SIG_FOOTER = "-----END SSH SIGNATURE-----"

# Wire format of an armoured SSH signature, per OpenSSH's PROTOCOL.sshsig:
#
#     byte[6]   MAGIC_PREAMBLE ("SSHSIG")
#     uint32    SIG_VERSION
#     string    publickey
#     string    namespace
#     string    reserved
#     string    hash_algorithm
#     string    signature
#
# Only the leading magic, version and public key are needed here.
_SSHSIG_MAGIC = b"SSHSIG"
_SSHSIG_HEADER_LEN = len(_SSHSIG_MAGIC) + 4  # magic + uint32 version


def _read_ssh_string(blob: bytes, offset: int) -> bytes:
    """Read one length-prefixed string from an SSH wire-format blob.

    Args:
        blob: Decoded signature bytes.
        offset: Byte offset of the 4-byte length prefix.

    Returns:
        The string body.

    Raises:
        ValueError: If the blob is too short for the declared length.
    """
    if offset + 4 > len(blob):
        raise ValueError("truncated SSH signature: no length prefix")
    (length,) = struct.unpack(">I", blob[offset : offset + 4])
    start = offset + 4
    end = start + length
    if end > len(blob):
        raise ValueError(
            f"truncated SSH signature: declared length {length} "
            f"exceeds remaining {len(blob) - start} bytes"
        )
    return blob[start:end]


def fingerprint_from_ssh_signature(armoured: str) -> str | None:
    """Derive the signer's SHA256 fingerprint from an armoured SSH signature.

    Git embeds the signer's public key in the signature itself, so the
    fingerprint can be computed without consulting an allowed-signers
    file or any external key registry. OpenSSH's SHA256 fingerprint is
    the base64-encoded SHA256 digest of the wire-format public key, with
    padding stripped -- the same value ``ssh-keygen -lf`` reports.

    Args:
        armoured: Text containing a ``-----BEGIN SSH SIGNATURE-----``
            block. Surrounding tag content is tolerated.

    Returns:
        Fingerprint as ``"SHA256:..."``, or None when no complete,
        well-formed signature block is present.
    """
    header = SshSignatureMixin.SSH_SIG_HEADER
    start = armoured.find(header)
    if start == -1:
        logger.debug("No SSH signature block found")
        return None

    end = armoured.find(SSH_SIG_FOOTER, start)
    if end == -1:
        logger.debug("SSH signature block incomplete")
        return None

    body = armoured[start + len(header) : end]

    try:
        # The armour wraps base64 at 70 columns; validate=True would
        # reject the newlines, so strip all whitespace first.
        blob = base64.b64decode("".join(body.split()), validate=True)
    except (binascii.Error, ValueError) as e:
        logger.debug(f"SSH signature is not valid base64: {e}")
        return None

    if not blob.startswith(_SSHSIG_MAGIC):
        logger.debug("SSH signature missing the SSHSIG magic preamble")
        return None

    try:
        public_key = _read_ssh_string(blob, _SSHSIG_HEADER_LEN)
    except (ValueError, struct.error) as e:
        logger.debug(f"Could not read public key from SSH signature: {e}")
        return None

    if not public_key:
        logger.debug("SSH signature carries an empty public key")
        return None

    digest = hashlib.sha256(public_key).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


class SshSignatureMixin:
    """SSH signature parsing shared by :class:`SignatureDetector`."""

    # Supplied by SignatureDetector.__init__; declared so the mixin is
    # type-checkable on its own.
    repo_path: Path

    # Markers and patterns for SSH signature detection
    SSH_SIG_HEADER = "-----BEGIN SSH SIGNATURE-----"
    SSH_KEY_PATTERN = re.compile(
        r"Good \"git\" signature for (.+?) with ([\w-]+) key (SHA256:[A-Za-z0-9+/=]+)",
        re.IGNORECASE,
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
            logger.debug(
                "SSH signature present but cannot be verified without allowedSignersFile"
            )

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

    async def _extract_ssh_fingerprint_from_tag(self, tag_name: str) -> str | None:
        """
        Extract the SSH key fingerprint from the tag object.

        This is the fallback used when the fingerprint is absent from
        ``git verify-tag`` output, which happens whenever
        ``gpg.ssh.allowedSignersFile`` is unset: git then prints no
        ``Good "git" signature ... key SHA256:...`` line at all. The
        signature itself still carries the signer's public key, so the
        fingerprint is recoverable from the tag object alone.

        Args:
            tag_name: Name of the tag

        Returns:
            Fingerprint as ``"SHA256:..."``, or None when the tag carries
            no parseable SSH signature. Returning None matters: callers
            treat any truthy value as a real fingerprint and would
            otherwise report a registered key as unregistered.
        """
        # Resolved through the public module so that anything patching
        # `tag_validate.signature.run_git` still intercepts these calls.
        from . import signature

        try:
            result = signature.run_git(
                ["git", "cat-file", "tag", tag_name],
                cwd=self.repo_path,
                check=True,
            )
        except Exception as e:
            logger.debug(f"Failed to read tag object for {tag_name}: {e}")
            return None

        fingerprint = fingerprint_from_ssh_signature(result.stdout)
        if fingerprint:
            logger.debug(f"Derived SSH fingerprint from tag object: {fingerprint}")
        else:
            logger.debug(
                f"Could not derive an SSH fingerprint from tag object {tag_name}"
            )
        return fingerprint
