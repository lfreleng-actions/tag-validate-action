# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Signature detection and enforcement for the validation workflow.

Detects the signature carried by a tag and decides whether it satisfies
the configured signing requirements.
"""

import logging

from .models import SignatureInfo, TagInfo, ValidationResult
from .workflow_context import WorkflowContext

logger = logging.getLogger(__name__)


class WorkflowSignatureMixin(WorkflowContext):
    """Signature detection behaviour for ValidationWorkflow."""

    async def _run_signature_step(
        self,
        result: ValidationResult,
        tag_name: str,
        tag_info: TagInfo,
    ) -> SignatureInfo | None:
        """Detect and validate the tag signature.

        Args:
            result: Validation result to update
            tag_name: Name of the tag being validated
            tag_info: Fetched tag information

        Returns:
            The detected SignatureInfo when validation should continue, or
            None if the caller should stop (result already updated).
        """
        try:
            signature_info = await self._detect_signature(tag_name, tag_info)
            result.signature_info = signature_info

            if not self._check_signature_requirements(signature_info, result):
                result.is_valid = False
                return None
        except Exception as e:
            result.is_valid = False
            result.add_error(f"Signature detection failed: {e}")
            logger.error(f"Signature detection failed: {e}")
            return None
        return signature_info

    async def _detect_signature(
        self, tag_name: str, tag_info: TagInfo
    ) -> SignatureInfo:
        """Detect signature on a tag.

        Args:
            tag_name: Name of the tag
            tag_info: Tag information including tagger email

        Returns:
            SignatureInfo: Signature detection result

        Raises:
            Exception: If signature detection fails
        """
        logger.debug(f"Detecting signature: {tag_name}")
        signature_info = await self.detector.detect_signature(tag_name)

        # For SSH signatures, use tagger email as fallback if signer_email is not set
        if (
            signature_info.type == "ssh"
            and not signature_info.signer_email
            and tag_info.tagger_email
        ):
            logger.debug(
                f"Using tagger email as signer email for SSH signature: {tag_info.tagger_email}"
            )
            signature_info = SignatureInfo(
                type=signature_info.type,
                verified=signature_info.verified,
                signer_email=tag_info.tagger_email,
                key_id=signature_info.key_id,
                fingerprint=signature_info.fingerprint,
                signature_data=signature_info.signature_data,
            )

        logger.debug(
            f"Signature detected: type={signature_info.type}, "
            f"verified={signature_info.verified}"
        )

        return signature_info

    def _check_signature_requirements(
        self,
        signature_info: SignatureInfo,
        result: ValidationResult,
    ) -> bool:
        """Check if signature meets requirements.

        Args:
            signature_info: Detected signature information
            result: Validation result to update

        Returns:
            bool: True if requirements are met
        """
        # Check if specific signature types are allowed
        if self.config.allowed_signature_types:
            # Specific signature types were specified - check if current type is allowed
            if signature_info.type not in self.config.allowed_signature_types:
                result.add_error(
                    f"Tag signature type '{signature_info.type}' is not allowed. "
                    f"Allowed types: {', '.join(self.config.allowed_signature_types)}"
                )
                logger.warning(
                    f"Signature type '{signature_info.type}' not in allowed types: "
                    f"{self.config.allowed_signature_types}"
                )
                return False

            # Type is allowed - check for any hard errors
            if signature_info.type == "invalid":
                result.add_error("Tag signature is invalid or corrupted")
                logger.warning(f"Invalid signature: key_id={signature_info.key_id}")
                return False
            elif signature_info.type == "lightweight":
                result.add_error(
                    "Lightweight tags are not allowed when signing requirements are specified"
                )
                logger.warning("Lightweight tag when signature requirements specified")
                return False

        # Check if signature is required (legacy boolean mode)
        elif self.config.require_signed:
            # Signature states rejected when signing is required:
            # - unsigned/lightweight: nothing to verify
            # - gpg-unverifiable: key missing (security risk)
            # - invalid: corrupted or tampered signature
            # Anything else is accepted: verified GPG/SSH, or an SSH
            # signature without an allowed_signers file to verify
            # against. Signature info is already shown in a dedicated
            # section
            rejections = {
                "unsigned": (
                    "Tag must be signed but is unsigned",
                    "Unsigned tag when signature is required",
                ),
                "lightweight": (
                    "Lightweight tags are not allowed when signing is required",
                    "Lightweight tag when signature is required",
                ),
                "gpg-unverifiable": (
                    "Tag has GPG signature but key is not available for verification",
                    f"GPG signature unverifiable: "
                    f"signer={signature_info.signer_email}, "
                    f"key_id={signature_info.key_id}",
                ),
                "invalid": (
                    "Tag signature is invalid or corrupted",
                    f"Invalid signature: key_id={signature_info.key_id}",
                ),
            }
            rejection = rejections.get(signature_info.type)
            if rejection:
                error_message, log_message = rejection
                result.add_error(error_message)
                logger.warning(log_message)
                return False

            if not signature_info.verified:
                # SSH signature without an allowed_signers file to
                # verify against (acceptable when only requiring a
                # signature to be present)
                logger.debug(
                    f"Signature present but not verified: type={signature_info.type}, "
                    f"signer={signature_info.signer_email}, key_id={signature_info.key_id}"
                )

        # Check if unsigned is explicitly required
        elif self.config.require_unsigned:
            if signature_info.type != "unsigned":
                result.add_error("Tag must be unsigned but has a signature")
                logger.warning("Signed tag when unsigned is required")
                return False

        # Ambivalent - accept any signature state
        # Signature info is already shown in dedicated section
        return True
