# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Gerrit verification step for the tag validation workflow.

Wraps Gerrit connectivity checks, key verification, and the error
handling that turns Gerrit failures into validation errors.
"""

import logging

from .gerrit_keys import (
    GerritInvalidCredentialsError,
    GerritMissingCredentialsError,
    GerritServerError,
)
from .models import SignatureInfo, ValidationResult
from .workflow_gerrit_keys import WorkflowGerritKeysMixin

logger = logging.getLogger(__name__)


class WorkflowGerritMixin(WorkflowGerritKeysMixin):
    """Gerrit verification behaviour for ValidationWorkflow."""

    async def _verify_gerrit_connection(
        self,
        result: ValidationResult,
        gerrit_server: str,
    ) -> None:
        """Verify Gerrit connectivity and authentication.

        Args:
            result: Validation result to update on failure
            gerrit_server: Resolved Gerrit server hostname

        Raises:
            GerritMissingCredentialsError: Credentials required but absent
            GerritInvalidCredentialsError: Credentials provided but invalid
            GerritServerError: Other connection or server errors
        """
        # Resolve the client through the workflow module so that
        # tag_validate.workflow.GerritKeysClient stays the patch seam
        from . import workflow

        async with workflow.GerritKeysClient(
            server=gerrit_server,
            username=self.gerrit_username,
            password=self.gerrit_password,
            use_netrc=self.use_netrc,
            netrc_file=self.netrc_file,
        ) as test_client:
            connection_ok, connection_error = await test_client.verify_connection()
            if connection_ok:
                return
            # Connection/auth failed - mark invalid and raise to skip
            # key verification
            result.is_valid = False
            error_msg = connection_error or "Unknown connection error"
            logger.error(f"Gerrit connection failed: {error_msg}")
            error_lower = error_msg.lower()
            if "credentials required" in error_lower:
                raise GerritMissingCredentialsError(error_msg)
            if (
                "invalid credentials" in error_lower
                or "rejected the provided credentials" in error_lower
            ):
                raise GerritInvalidCredentialsError(error_msg)
            raise GerritServerError(error_msg)

    def _handle_gerrit_server_error(
        self,
        result: ValidationResult,
        error_msg: str,
        gerrit_server: str | None,
    ) -> None:
        """Record result errors for a Gerrit server/connection failure.

        Args:
            result: Validation result to update
            error_msg: Error message from the raised GerritServerError
            gerrit_server: Resolved Gerrit server hostname (may be None)
        """
        lower_msg = error_msg.lower()
        is_endpoint_error = (
            "endpoint not available" in lower_msg or "may not support" in lower_msg
        )
        # When --require-gerrit is specified, verification MUST succeed
        # Any server limitation means the requirement cannot be satisfied
        result.is_valid = False
        result.add_error(
            f"Gerrit key verification required but unavailable: {error_msg}"
        )
        if is_endpoint_error:
            result.add_error(
                f"Gerrit server '{gerrit_server}' does not expose key "
                "management APIs. This server cannot be used for "
                "--require-gerrit verification."
            )

    async def _verify_gerrit_key_step(
        self,
        result: ValidationResult,
        signature_info: SignatureInfo,
        require_owners: list[str] | None,
    ) -> None:
        """Verify the signing key against Gerrit (Step 5).

        Args:
            result: Validation result to update
            signature_info: Signature information
            require_owners: Required owners the key must belong to (optional)
        """
        if not (signature_info.type in ["gpg", "ssh"] and signature_info.verified):
            # When --require-gerrit is specified, a valid signature is REQUIRED
            result.is_valid = False
            result.add_error(
                "Gerrit key verification required but tag has no valid "
                "signature. Tag must be signed with GPG or SSH to verify "
                "key on Gerrit."
            )
            return

        # Determine Gerrit server (bound before the try so except handlers
        # can safely reference it)
        gerrit_server = self.config.gerrit_server
        try:
            github_org = None
            if not gerrit_server:
                # Try to extract GitHub org from current context
                github_org = self._extract_github_org_from_context()
                if github_org:
                    gerrit_server = f"gerrit.{github_org}.org"
                else:
                    raise ValueError(
                        "No Gerrit server specified and could not "
                        "auto-detect from GitHub org"
                    )

            # Verify connection/auth before attempting key verification
            await self._verify_gerrit_connection(result, gerrit_server)

            # Use require_owners if provided, else verify against tagger email
            key_result = await self._require_gerrit_key(
                signature_info, gerrit_server, github_org, require_owners
            )
            result.key_verifications.append(key_result)
            if not key_result.key_registered:
                result.is_valid = False
                if require_owners:
                    result.add_error(
                        f"Signing key not registered to any of the required "
                        f"owners on Gerrit: {', '.join(require_owners)}"
                    )
                else:
                    result.add_error(
                        f"Signing key not registered on Gerrit server "
                        f"{key_result.server}"
                    )

        except GerritMissingCredentialsError as e:
            error_msg = str(e)
            logger.warning(
                f"Gerrit key verification unavailable: Missing credentials - {e}"
            )
            result.is_valid = False
            result.add_error(
                f"Gerrit key verification required but credentials not "
                f"provided: {error_msg}"
            )
            result.add_error(
                "Please provide Gerrit credentials via GERRIT_USERNAME and "
                "GERRIT_PASSWORD environment variables."
            )
        except GerritInvalidCredentialsError as e:
            error_msg = str(e)
            logger.warning(
                f"Gerrit key verification unavailable: Invalid credentials - {e}"
            )
            result.is_valid = False
            result.add_error(
                f"Gerrit key verification required but authentication "
                f"failed: {error_msg}"
            )
            result.add_error(
                "Please verify your Gerrit username and HTTP password are "
                "correct. Note: Use HTTP password from Gerrit Settings > "
                "HTTP Credentials, not your SSO/LDAP password."
            )
        except GerritServerError as e:
            error_msg = str(e)
            logger.warning(f"Gerrit key verification unavailable: {e}")
            self._handle_gerrit_server_error(result, error_msg, gerrit_server)
        except Exception as e:
            result.is_valid = False
            result.add_error(f"Gerrit key verification failed: {e}")
            logger.error(f"Gerrit key verification failed: {e}")
