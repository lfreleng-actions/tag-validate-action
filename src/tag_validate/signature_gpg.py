# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
GPG signature parsing for Git tags.

Turns the output of ``git verify-tag`` into a
:class:`~tag_validate.models.SignatureInfo`, covering the good, invalid,
and unverifiable (missing public key) cases, plus the field extractors
those three share.
"""

import logging
import re
from pathlib import Path
from typing import Any

from .gpg_trust import format_epoch, key_expiry
from .models import SignatureInfo

# Bound to the public module's name so log records keep reporting
# `tag_validate.signature` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.signature")


class GpgSignatureMixin:
    """GPG signature parsing shared by :class:`SignatureDetector`."""

    # Regex patterns for GPG verification output
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

    async def _parse_gpg_output(
        self,
        tag_name: str,
        verify_output: str,
        gnupg_home: Path | None,
        permit_expired_key: bool,
    ) -> SignatureInfo | None:
        """Parse GPG verification output, or return None when not GPG."""
        statuses = self._gpg_status_keywords(verify_output)
        if "BADSIG" in verify_output:
            return await self._parse_invalid_gpg_signature(tag_name, verify_output)
        if "ERRSIG" in verify_output:
            return await self._parse_unverifiable_gpg_signature(tag_name, verify_output)
        if statuses & {"REVKEYSIG", "EXPSIG", "EXPKEYSIG"}:
            return self._parse_gpg_key_state(
                tag_name, verify_output, gnupg_home, permit_expired_key
            )
        if (
            "GOODSIG" in verify_output
            or "using RSA key" in verify_output
            or "using DSA key" in verify_output
            or "using ECDSA key" in verify_output
            or "using EdDSA key" in verify_output
        ):
            return await self._parse_gpg_signature(tag_name, verify_output)
        return None

    @staticmethod
    def _gpg_status_keywords(verify_output: str) -> set[str]:
        """Return the keywords of the ``[GNUPG:]`` status lines."""
        keywords: set[str] = set()
        for line in verify_output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "[GNUPG:]":
                keywords.add(parts[1])
        return keywords

    @staticmethod
    def _validsig_fields(verify_output: str) -> list[str] | None:
        """Return the fields after ``VALIDSIG``, or None when absent."""
        for line in verify_output.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[:2] == ["[GNUPG:]", "VALIDSIG"]:
                return parts[2:]
        return None

    def _extract_gpg_primary_fingerprint(self, verify_output: str) -> str | None:
        """Return the primary key fingerprint, the last VALIDSIG field."""
        fields = self._validsig_fields(verify_output)
        # <fpr> <date> <ts> <expire> <ver> <reserved> <pk> <hash> <class> <primary>
        if fields and len(fields) >= 10:
            return fields[9].upper()
        return None

    def _parse_gpg_key_state(
        self,
        tag_name: str,
        verify_output: str,
        gnupg_home: Path | None,
        permit_expired_key: bool,
    ) -> SignatureInfo:
        """Parse a good signature from a revoked or expired key, or an
        expired signature.

        Only a signature from an expired key, made before that key
        expired, can count as verified, and only with
        ``permit_expired_key``.
        """
        statuses = self._gpg_status_keywords(verify_output)
        primary = self._extract_gpg_primary_fingerprint(verify_output)
        fields = self._validsig_fields(verify_output)
        rejected = SignatureInfo(
            type="invalid",
            verified=False,
            key_id=self._extract_gpg_key_id(verify_output),
            fingerprint=self._extract_gpg_fingerprint(verify_output),
            signer_email=self._extract_gpg_signer_email(verify_output),
            signature_data=verify_output,
            primary_fingerprint=primary,
        )

        update = self._key_state_update(
            tag_name, statuses, primary, fields, gnupg_home, permit_expired_key
        )
        checked: SignatureInfo = rejected.model_copy(update=update)
        return checked

    @staticmethod
    def _key_state_update(
        tag_name: str,
        statuses: set[str],
        primary: str | None,
        fields: list[str] | None,
        gnupg_home: Path | None,
        permit_expired_key: bool,
    ) -> dict[str, Any]:
        """Return the fields that record a key or signature state."""
        if "REVKEYSIG" in statuses or "KEYREVOKED" in statuses:
            logger.warning(f"Tag {tag_name} is signed by a revoked GPG key")
            return {"key_state": "revoked-key"}
        if "EXPSIG" in statuses:
            logger.warning(f"Tag {tag_name} carries an expired GPG signature")
            return {"key_state": "expired-signature"}

        expiry = None
        if primary and fields:
            expiry = key_expiry(gnupg_home, primary, fields[0])
        expiry_text = format_epoch(expiry) if expiry is not None else None
        signed_at = fields[2] if fields and len(fields) >= 3 else ""
        signed_before_expiry = (
            expiry is not None and signed_at.isdigit() and int(signed_at) < expiry
        )
        if not signed_before_expiry:
            logger.warning(f"Tag {tag_name} was signed after its GPG key expired")
            return {"key_state": "signed-after-expiry", "key_expiry": expiry_text}
        if permit_expired_key:
            logger.warning(
                f"Tag {tag_name} is signed by a GPG key that expired on "
                f"{expiry_text}; accepted by permit_expired_key"
            )
            return {
                "type": "gpg",
                "verified": True,
                "key_state": "expired-key",
                "key_expired": True,
                "key_expiry": expiry_text,
            }
        logger.warning(f"Tag {tag_name} is signed by an expired GPG key")
        return {"key_state": "expired-key", "key_expiry": expiry_text}

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
            primary_fingerprint=self._extract_gpg_primary_fingerprint(verify_output),
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
            email_match = re.search(r"<([^>]+)>", signer_info)
            if email_match:
                email = email_match.group(1)
                logger.debug(f"Extracted GPG signer email: {email}")
                return email
            # If no angle brackets, the whole thing might be an email
            if "@" in signer_info:
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
                    email_match = re.search(r"<([^>]+)>", user_info)
                    if email_match:
                        email = email_match.group(1)
                        logger.debug(
                            f"Extracted GPG signer email from GOODSIG: {email}"
                        )
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
                    logger.debug(
                        f"Extracted GPG fingerprint from VALIDSIG: {fingerprint}"
                    )
                    return fingerprint

        logger.debug("Could not extract GPG fingerprint")
        return None
