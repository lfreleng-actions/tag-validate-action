# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Gerrit key verification for the tag validation workflow.

Looks up the Gerrit account behind a tagger email and checks the signing
key against it, plus the GitHub organisation detection used to derive a
Gerrit server name when one is not configured.
"""

import logging
import re

from dependamerge.git_ops import redact_text, run_git

from .models import KeyVerificationResult, SignatureInfo
from .workflow_context import WorkflowContext

logger = logging.getLogger(__name__)


class WorkflowGerritKeysMixin(WorkflowContext):
    """Gerrit key lookup behaviour for ValidationWorkflow."""

    async def _require_gerrit_key(
        self,
        signature_info: SignatureInfo,
        gerrit_server: str,
        github_org: str | None = None,
        require_owners: list[str] | None = None,
    ) -> KeyVerificationResult:
        """Verify signing key on Gerrit.

        Args:
            signature_info: Signature information
            gerrit_server: Gerrit server hostname or URL
            github_org: GitHub organization name for auto-discovery (optional)
            require_owners: List of required usernames or emails that must own the signing key

        Returns:
            KeyVerificationResult: Key verification result

        Raises:
            Exception: If verification fails
        """
        # Determine the tagger email from signature
        tagger_email = signature_info.signer_email
        if not tagger_email:
            raise ValueError("Cannot verify Gerrit key without tagger email")

        logger.debug(f"Verifying key on Gerrit server: {gerrit_server}")

        # Resolve the client through the workflow module so that
        # tag_validate.workflow.GerritKeysClient stays the patch seam
        from . import workflow

        async with workflow.GerritKeysClient(
            server=gerrit_server,
            github_org=github_org,
            username=self.gerrit_username,
            password=self.gerrit_password,
            use_netrc=self.use_netrc,
            netrc_file=self.netrc_file,
        ) as client:
            # Look up account by email
            account = await client.lookup_account_by_email(tagger_email)
            if not account:
                logger.debug(f"No Gerrit account found for email: {tagger_email}")
                return KeyVerificationResult(
                    key_registered=False,
                    username=tagger_email,
                    user_enumerated=True,
                    key_info=None,
                    service="gerrit",
                    server=gerrit_server,
                )

            # If require_owners is specified, check if account matches any owner
            if require_owners:
                logger.debug(
                    f"Verifying account against required owners: {require_owners}"
                )
                account_matches = False

                for owner in require_owners:
                    if "@" in owner:
                        # Owner is an email address
                        if account.email and account.email.lower() == owner.lower():
                            account_matches = True
                            break
                    else:
                        # Owner is a username
                        if (
                            account.username
                            and account.username.lower() == owner.lower()
                        ):
                            account_matches = True
                            break

                if not account_matches:
                    logger.debug(
                        f"Account {account.email} does not match required owners: {require_owners}"
                    )
                    return KeyVerificationResult(
                        key_registered=False,
                        username=", ".join(require_owners),
                        user_enumerated=False,
                        key_info=None,
                        service="gerrit",
                        server=gerrit_server,
                    )

            # Verify the key based on signature type
            if signature_info.type == "gpg":
                if not signature_info.key_id:
                    raise ValueError("GPG key ID not found in signature")

                result = await client.verify_gpg_key_registered(
                    account_id=account.account_id,
                    key_id=signature_info.key_id,
                )

            elif signature_info.type == "ssh":
                if not signature_info.fingerprint:
                    raise ValueError("SSH fingerprint not found in signature")

                result = await client.verify_ssh_key_registered(
                    account_id=account.account_id,
                    fingerprint=signature_info.fingerprint,
                )

            else:
                raise ValueError(f"Cannot verify {signature_info.type} signature type")

            logger.debug(
                f"Gerrit key verification result: registered={result.key_registered}"
            )
            return result

    def _extract_github_org_from_context(self) -> str | None:
        """Extract GitHub organization from current validation context.

        This method attempts to determine the GitHub organization from:
        1. Stored organization from remote repository validation
        2. Git remote URL (parsing github.com URLs)

        Returns:
            GitHub organization name if detected, None otherwise
        """
        # First check if we have a stored GitHub org from remote validation
        if hasattr(self, "_current_github_org") and self._current_github_org:
            logger.debug(
                f"Using stored GitHub org from remote validation: {self._current_github_org}"
            )
            return self._current_github_org

        try:
            # Read the remote URL via the redacting git wrapper so any
            # credential material embedded in the URL can never reach
            # logs or exception messages.
            result = run_git(
                ["git", "remote", "get-url", "origin"],
                cwd=self.repo_path,
                check=False,
                timeout=5,
            )

            if result.returncode == 0:
                remote_url = result.stdout.strip()
                logger.debug(f"Found git remote URL: {redact_text(remote_url)}")

                # Parse GitHub URL patterns
                patterns = [
                    r"github\.com[:/]([^/]+)/",  # https://github.com/owner/ or git@github.com:owner/
                    r"github\.com/([^/]+)",  # https://github.com/owner (no trailing slash)
                ]

                for pattern in patterns:
                    match = re.search(pattern, remote_url)
                    if match:
                        org = match.group(1)
                        logger.debug(f"Extracted GitHub org from remote URL: {org}")
                        return org
            else:
                logger.debug(
                    f"Git remote command failed with return code {result.returncode}"
                )

        except Exception as e:
            # Redact the exception text for defense-in-depth: if the git
            # wrapper ever surfaces a remote URL with embedded credentials
            # (e.g. from a legacy config) in its message, it must not reach
            # the logs verbatim.
            logger.debug(
                f"Could not extract GitHub org from git remote: {redact_text(str(e))}"
            )

        return None
