# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Human-readable validation summaries for the tag validation workflow.

Renders the per-section summary text (version, signature, release gates
and key verification) shown by the CLI.
"""

from .display_utils import format_server_display, format_user_details
from .models import SignatureInfo, ValidationConfig, ValidationResult
from .workflow_context import WorkflowContext


class WorkflowSummaryMixin(WorkflowContext):
    """Summary rendering behaviour for ValidationWorkflow."""

    def create_validation_summary(self, result: ValidationResult) -> str:
        """Create a human-readable validation summary.

        Args:
            result: Validation result

        Returns:
            str: Formatted summary text
        """
        lines: list[str] = []

        # Header
        status = "✅" if result.is_valid else "❌"
        lines.append(f"Overall Validation Result {status}")
        lines.append("")

        lines.extend(self._summary_version_lines(result))
        lines.extend(self._summary_signature_lines(result))
        lines.extend(self._summary_increment_lines(result))
        lines.extend(self._summary_branch_lines(result))
        lines.extend(self._summary_age_lines(result))
        lines.extend(self._summary_latest_lines(result))
        lines.extend(self._summary_key_verification_lines(result))

        # Errors - filter out redundant registration errors
        filtered_errors = self._summary_filtered_errors(result)
        if filtered_errors:
            # Add blank line before section if needed
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Errors:")
            lines.extend(f"  • {error}" for error in filtered_errors)

        # Warnings
        if result.warnings:
            # Add blank line before section if needed
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Warnings:")
            lines.extend(f"  • {warning}" for warning in result.warnings)

        # Info messages
        if result.info:
            # Only add blank line if we didn't just add one from a prior section
            if lines and lines[-1] != "":
                lines.append("")
            lines.append("Additional Information:")
            lines.extend(f"  • {info}" for info in result.info)

        # Remove trailing empty line if present
        while lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

    def _summary_version_lines(self, result: ValidationResult) -> list[str]:
        """Build the version-info section of the summary."""
        if not result.version_info:
            return []
        v = result.version_info
        lines: list[str] = []

        # Show validation status if version type requirement was specified
        version_status = ""
        if result.config.require_semver or result.config.require_calver:
            required_types = []
            if result.config.require_semver:
                required_types.append("semver")
            if result.config.require_calver:
                required_types.append("calver")
            # "both" type satisfies either requirement
            if v.version_type == "both" or v.version_type in required_types:
                version_status = " ✅"
            else:
                version_status = " ❌"

        lines.append(f"Tag Validation: {result.tag_name}{version_status}")
        lines.append(f"  Type: {v.version_type.upper()}")
        if v.version_type == "semver":
            lines.append(f"  Components: {v.major}.{v.minor}.{v.patch}")
            if v.prerelease:
                lines.append(f"  Prerelease: {v.prerelease}")
        elif v.version_type == "calver":
            lines.append(f"  Date: {v.year}.{v.month}.{v.day or v.micro}")
        if v.is_development:
            lines.append("  Development: Yes")
        lines.append("")
        return lines

    def _summary_signature_lines(self, result: ValidationResult) -> list[str]:
        """Build the signature-info section of the summary."""
        if not result.signature_info:
            return []
        s = result.signature_info
        # Display signature type with friendly names
        type_display = {
            "gpg": "GPG",
            "ssh": "SSH",
            "unsigned": "UNSIGNED",
            "lightweight": "LIGHTWEIGHT",
            "invalid": "INVALID (corrupted/tampered)",
            "gpg-unverifiable": "GPG (key not available)",
        }
        sig_type = type_display.get(s.type, s.type.upper())

        # Show validation status if signature requirement was specified
        signature_status = ""
        if (
            result.config.require_signed
            or result.config.require_unsigned
            or result.config.allowed_signature_types
        ):
            signature_valid = self._check_signature_requirements_status(
                result.signature_info, result.config
            )
            signature_status = " ✅" if signature_valid else " ❌"

        lines: list[str] = [f"Tag Signing{signature_status}"]
        if s.type in ["gpg", "ssh", "gpg-unverifiable", "invalid"]:
            lines.append(f"  Key Type: {sig_type}")
            if s.type == "gpg-unverifiable":
                lines.append("  Status: Key not available for verification")
            elif s.type == "invalid":
                lines.append("  Status: Signature is corrupted or tampered")
            if s.signer_email:
                lines.append(f"  Signer: {s.signer_email}")
            if s.key_id:
                lines.append(f"  Key ID: {s.key_id}")
        lines.append("")
        return lines

    def _summary_increment_lines(self, result: ValidationResult) -> list[str]:
        """Build the version-increment section of the summary."""
        if not (result.increment_check and result.increment_check.checked):
            return []
        ic = result.increment_check
        status_icon = "✅" if ic.incremental else "❌"
        lines: list[str] = [f"Version Increment {status_icon}"]
        if len(ic.latest_tags) > 1:
            # Multi-scheme push: report each scheme's baseline
            for scheme, tag in sorted(ic.latest_tags.items()):
                lines.append(f"  Latest Existing Tag ({scheme}): {tag}")
        elif ic.latest_tag:
            lines.append(f"  Latest Existing Tag: {ic.latest_tag}")
        elif ic.incremental:
            lines.append("  First version tag in repository")
        if ic.scheme:
            lines.append(f"  Comparison Scheme: {ic.scheme}")
        lines.append("")
        return lines

    def _summary_branch_lines(self, result: ValidationResult) -> list[str]:
        """Build the branch-containment section of the summary."""
        if not (result.branch_check and result.branch_check.checked):
            return []
        bc = result.branch_check
        status_icon = "✅" if bc.contains else "❌"
        lines: list[str] = [f"Branch Containment {status_icon}"]
        if bc.branch:
            lines.append(f"  Branch: {bc.branch}")
        if bc.method:
            lines.append(f"  Method: {bc.method}")
        lines.append("")
        return lines

    def _summary_age_lines(self, result: ValidationResult) -> list[str]:
        """Build the tag-freshness section of the summary."""
        if not (result.age_check and result.age_check.checked):
            return []
        ac = result.age_check
        status_icon = "✅" if ac.recent else "❌"
        lines: list[str] = [f"Tag Freshness {status_icon}"]
        if ac.max_age_minutes is not None:
            lines.append(f"  Window: {ac.max_age_minutes:g} minute(s)")
        if ac.age_seconds is not None:
            lines.append(f"  Tag Age: {ac.age_seconds:.0f} seconds")
        lines.append("")
        return lines

    def _summary_latest_lines(self, result: ValidationResult) -> list[str]:
        """Build the latest-commit section of the summary."""
        if not (result.latest_check and result.latest_check.checked):
            return []
        lc = result.latest_check
        status_icon = "✅" if lc.latest else "❌"
        lines: list[str] = [f"Latest Commit {status_icon}"]
        if lc.branch:
            lines.append(f"  Branch: {lc.branch}")
        if lc.branch_sha:
            lines.append(f"  Branch Tip: {lc.branch_sha[:12]}")
        if lc.method:
            lines.append(f"  Method: {lc.method}")
        lines.append("")
        return lines

    def _summary_key_verification_lines(self, result: ValidationResult) -> list[str]:
        """Build the key-verification section of the summary."""
        if not result.key_verifications:
            return []
        lines: list[str] = []
        for k in result.key_verifications:
            # Determine service name and status
            service_name = "Gerrit" if k.service == "gerrit" else "GitHub"
            status_icon = "✅" if k.key_registered else "❌"
            lines.append(f"{service_name} Registered {status_icon}")

            # Show server info using shared utility
            server_line = format_server_display(k.service, k.server)
            if server_line:
                lines.append(server_line)

            lines.append("")
            lines.append(f"{service_name} User:")

            # Build user details using shared utility
            user_lines = format_user_details(
                username=k.username,
                email=k.user_email,
                name=k.user_name,
            )
            lines.extend(user_lines)
            lines.append("")
        return lines

    def _summary_filtered_errors(self, result: ValidationResult) -> list[str]:
        """Return errors with redundant registration errors filtered out.

        Registration errors for a service already shown in the key
        verification section are omitted to avoid duplication.
        """
        if not result.errors:
            return []
        # Collect all services shown in key_verifications section
        services_in_display: set[str] = set()
        if result.key_verifications:
            services_in_display = {k.service for k in result.key_verifications}

        filtered_errors: list[str] = []
        for error in result.errors:
            error_lower = error.lower()
            is_registration_error = "not registered" in error_lower
            # Check which service this error is about
            is_github_error = "github" in error_lower
            is_gerrit_error = "gerrit" in error_lower
            # Only filter if this error is about a service shown above
            should_filter = is_registration_error and (
                (is_github_error and "github" in services_in_display)
                or (is_gerrit_error and "gerrit" in services_in_display)
            )
            if not should_filter:
                filtered_errors.append(error)
        return filtered_errors

    def _check_signature_requirements_status(
        self,
        signature_info: SignatureInfo,
        config: ValidationConfig,
    ) -> bool:
        """Check if signature meets requirements without adding errors.

        This is used for display purposes to show ✅/❌ status.

        Args:
            signature_info: Detected signature information
            config: Validation configuration

        Returns:
            bool: True if signature requirements are met
        """
        # Check if specific signature types are allowed
        if config.allowed_signature_types:
            if signature_info.type not in config.allowed_signature_types:
                return False
            # Type is allowed - check for hard errors
            return signature_info.type not in ["invalid", "lightweight"]

        # Check if signature is required (legacy boolean mode)
        elif config.require_signed:
            return signature_info.type not in [
                "unsigned",
                "lightweight",
                "gpg-unverifiable",
                "invalid",
            ]

        # Check if unsigned is explicitly required
        elif config.require_unsigned:
            return signature_info.type == "unsigned"

        # No signature requirements - always valid
        return True
