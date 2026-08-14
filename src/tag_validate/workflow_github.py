# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""GitHub key verification for the tag validation workflow.

Resolves the GitHub account associated with a signature and checks the
signing key against that account, or against a set of required owners.
"""

import logging

from .github_keys import GitHubKeysClient
from .models import KeyVerificationResult, SignatureInfo, ValidationResult
from .workflow_context import WorkflowContext

logger = logging.getLogger(__name__)


class WorkflowGitHubMixin(WorkflowContext):
    """GitHub key verification behaviour for ValidationWorkflow."""

    async def _detect_github_user(
        self,
        signature_info: SignatureInfo,
        github_user: str | None,
        github_token: str | None,
    ) -> tuple[str | None, bool]:
        """Resolve the GitHub username, auto-detecting from signer email.

        Args:
            signature_info: Signature information
            github_user: Explicitly provided GitHub username (optional)
            github_token: GitHub API token (optional)

        Returns:
            Tuple of (username or None, whether it was auto-enumerated).
        """
        if github_user or not signature_info.signer_email:
            return github_user, False

        logger.debug(
            f"Attempting to auto-detect GitHub username from email: "
            f"{signature_info.signer_email}"
        )
        try:
            from .github_keys import GitHubKeysClient

            async with GitHubKeysClient(token=github_token) as client:
                detected = await client.lookup_username_by_email(
                    signature_info.signer_email
                )
                if detected:
                    logger.debug(f"Auto-detected GitHub username: {detected}")
                    return detected, True
                logger.warning(
                    f"Could not auto-detect GitHub username from email: "
                    f"{signature_info.signer_email}"
                )
        except Exception as e:
            logger.debug(f"Failed to auto-detect GitHub username: {e}")
        return None, False

    async def _verify_github_key_step(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        github_user: str | None,
        github_token: str | None,
        require_owners: list[str] | None,
    ) -> None:
        """Verify the signing key against GitHub (Step 4).

        Args:
            result: Validation result to update
            signature_info: Signature information
            github_user: GitHub username for key verification (optional)
            github_token: GitHub API token (optional)
            require_owners: Required owners the key must belong to (optional)
        """
        if not (signature_info.type in ["gpg", "ssh"] and signature_info.verified):
            result.add_info("Skipping GitHub key verification (no valid signature)")
            return

        if not github_token:
            result.is_valid = False
            error_msg = (
                "GitHub token is required. Set GITHUB_TOKEN environment "
                "variable or pass --token"
            )
            result.add_error(error_msg)
            logger.error(error_msg)
            return

        detected_user, was_user_enumerated = await self._detect_github_user(
            signature_info, github_user, github_token
        )

        if require_owners:
            await self._verify_github_owners(
                result,
                signature_info,
                detected_user,
                github_token,
                require_owners,
            )
        elif detected_user:
            await self._verify_github_single_user(
                result,
                signature_info,
                detected_user,
                github_token,
                was_user_enumerated,
            )
        else:
            result.is_valid = False
            error_msg = (
                "GitHub key verification requested but no username provided "
                "or detected from tagger email"
            )
            result.add_error(error_msg)
            logger.error(error_msg)

    async def _verify_github_owners(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        detected_user: str | None,
        github_token: str | None,
        require_owners: list[str],
    ) -> None:
        """Verify the signing key against a set of required owners.

        Args:
            result: Validation result to update
            signature_info: Signature information
            detected_user: Detected GitHub username (unused for owners)
            github_token: GitHub API token (optional)
            require_owners: Required owners the key must belong to
        """
        try:
            key_result = await self._require_github_key(
                signature_info,
                detected_user if detected_user else "",
                github_token,
                require_owners,
            )
            result.key_verifications.append(key_result)
            if not key_result.key_registered:
                result.is_valid = False
                result.add_error(
                    f"Signing key not registered to any of the required "
                    f"owners: {', '.join(require_owners)}"
                )
        except Exception as e:
            result.is_valid = False
            result.add_error(f"GitHub key verification failed: {e}")
            logger.error(f"GitHub key verification failed: {e}")

    async def _verify_github_single_user(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        detected_user: str,
        github_token: str | None,
        was_user_enumerated: bool,
    ) -> None:
        """Verify the signing key against a single GitHub user.

        Args:
            result: Validation result to update
            signature_info: Signature information
            detected_user: GitHub username to verify against
            github_token: GitHub API token (optional)
            was_user_enumerated: Whether the username was auto-detected
        """
        try:
            key_result = await self._require_github_key(
                signature_info,
                detected_user,
                github_token,
                None,
            )
            # Set user_enumerated flag if username was auto-detected
            if was_user_enumerated and key_result:
                key_result.user_enumerated = True
            result.key_verifications.append(key_result)
            if not key_result.key_registered:
                result.is_valid = False
                result.add_error(
                    f"Signing key not registered to GitHub user @{detected_user}"
                )
        except Exception as e:
            result.is_valid = False
            result.add_error(f"GitHub key verification failed: {e}")
            logger.error(f"GitHub key verification failed: {e}")

    async def _verify_key_for_username(
        self,
        client: GitHubKeysClient,
        signature_info: SignatureInfo,
        username: str,
    ) -> KeyVerificationResult:
        """Verify the signing key is registered to a specific GitHub user.

        Args:
            client: Open GitHub keys client
            signature_info: Signature information
            username: GitHub username to verify against

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            ValueError: If the signature lacks required data or has an
                unsupported type
        """
        if signature_info.type == "gpg":
            if not signature_info.key_id:
                raise ValueError("GPG key ID not found in signature")
            return await client.verify_gpg_key_registered(
                username=username,
                key_id=signature_info.key_id,
                tagger_email=signature_info.signer_email,
                signer_email=signature_info.signer_email,
            )
        if signature_info.type == "ssh":
            if not signature_info.fingerprint:
                raise ValueError("SSH fingerprint not found in signature")
            return await client.verify_ssh_key_registered(
                username=username,
                public_key_fingerprint=signature_info.fingerprint,
                signer_email=signature_info.signer_email,
            )
        raise ValueError(f"Cannot verify {signature_info.type} signature type")

    async def _match_owner_key(
        self,
        client: GitHubKeysClient,
        signature_info: SignatureInfo,
        owner: str,
    ) -> KeyVerificationResult | None:
        """Check whether the signing key is registered to one owner.

        Args:
            client: Open GitHub keys client
            signature_info: Signature information
            owner: Required owner as a GitHub username or email address

        Returns:
            KeyVerificationResult if the key is registered to this owner,
            otherwise None (owner did not match or verification failed)
        """
        if "@" in owner:
            logger.debug(f"Checking if signer email matches: {owner}")
            if not (
                signature_info.signer_email
                and signature_info.signer_email.lower() == owner.lower()
            ):
                logger.debug(
                    f"Signer email {signature_info.signer_email} does not "
                    f"match required owner {owner}"
                )
                return None
            try:
                username = await client.lookup_username_by_email(owner)
                if username:
                    logger.debug(f"Found GitHub username for email {owner}: {username}")
                    result = await self._verify_key_for_username(
                        client, signature_info, username
                    )
                    if result.key_registered:
                        logger.debug(f"Key verified for owner email: {owner}")
                        return result
            except Exception as e:
                logger.debug(f"Could not verify email {owner}: {e}")
            return None

        logger.debug(f"Verifying key for GitHub username: {owner}")
        try:
            result = await self._verify_key_for_username(client, signature_info, owner)
            if result.key_registered:
                logger.debug(f"Key verified for owner: {owner}")
                return result
        except Exception as e:
            logger.debug(f"Could not verify username {owner}: {e}")
        return None

    async def _require_github_key(
        self,
        signature_info: SignatureInfo,
        github_user: str,
        github_token: str | None = None,
        require_owners: list[str] | None = None,
    ) -> KeyVerificationResult:
        """Verify signing key on GitHub.

        Args:
            signature_info: Signature information
            github_user: GitHub username to verify against
            github_token: GitHub API token (optional)
            require_owners: List of required GitHub usernames or emails that must own the signing key

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            Exception: If verification fails
        """
        # Resolve the client through the workflow module so that
        # tag_validate.workflow.GitHubKeysClient stays the patch seam
        from . import workflow

        # If require_owners is specified, check against all owners
        if require_owners:
            logger.debug(f"Verifying key against required owners: {require_owners}")

            async with workflow.GitHubKeysClient(token=github_token) as client:
                for owner in require_owners:
                    match = await self._match_owner_key(client, signature_info, owner)
                    if match is not None:
                        return match

                # If we get here, none of the owners matched
                logger.debug(
                    f"Key not registered to any of the required owners: {require_owners}"
                )
                return KeyVerificationResult(
                    key_registered=False,
                    username=", ".join(require_owners),
                    user_enumerated=False,
                    key_info=None,
                    service="github",
                    server="github.com",
                    user_email=signature_info.signer_email,
                )

        # Original behavior: verify against single github_user
        logger.debug(f"Verifying key on GitHub for user: {github_user}")

        async with workflow.GitHubKeysClient(token=github_token) as client:
            result = await self._verify_key_for_username(
                client, signature_info, github_user
            )

        logger.debug(f"Key verification result: registered={result.key_registered}")
        return result
