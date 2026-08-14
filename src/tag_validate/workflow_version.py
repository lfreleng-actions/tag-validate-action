# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Version validation steps for the tag validation workflow.

Provides the version detection step and the configuration checks that
decide whether a detected version type satisfies the requested scheme.
"""

import logging

from .models import ValidationResult, VersionInfo
from .workflow_context import WorkflowContext

logger = logging.getLogger(__name__)


class WorkflowVersionMixin(WorkflowContext):
    """Version validation behaviour for ValidationWorkflow."""

    def _run_version_step(self, result: ValidationResult, tag_name: str) -> bool:
        """Detect the version type and enforce type requirements.

        Args:
            result: Validation result to update
            tag_name: Name of the tag being validated

        Returns:
            True to continue validation, False if a requirement failed and
            the caller should stop (result already updated).
        """
        if self.config.skip_version_validation:
            # Skip version validation entirely (legacy flag support)
            result.add_info("Version validation skipped (--skip-version-validation)")
            return True

        version_result = self._validate_version(tag_name)
        result.version_info = version_result

        # Only enforce type requirements if explicitly configured
        if (
            self.config.require_semver or self.config.require_calver
        ) and not self._check_version_requirements(version_result):
            result.is_valid = False
            required_types = []
            if self.config.require_semver:
                required_types.append("semver")
            if self.config.require_calver:
                required_types.append("calver")
            result.add_error(
                f"Version type '{version_result.version_type}' does not "
                f"match required type(s): {', '.join(required_types)}"
            )
            return False
        # Otherwise accept any type (including "other")
        return True

    def _validate_version(self, tag_name: str) -> VersionInfo:
        """Validate version format.

        Args:
            tag_name: Tag name to validate

        Returns:
            VersionInfo: Version validation result
        """
        logger.debug(f"Validating version: {tag_name}")

        # Use strict mode if configured
        strict_semver = self.config.require_semver and getattr(
            self.config, "strict_semver", False
        )

        version_result = self.validator.validate_version(
            tag_name,
            allow_prefix=self.config.allow_prefix,
            strict_semver=strict_semver,
        )

        logger.debug(
            f"Version validation: valid={version_result.is_valid}, "
            f"type={version_result.version_type}"
        )

        return version_result

    def _check_version_requirements(self, version_info: VersionInfo) -> bool:
        """Check if version meets configuration requirements.

        Args:
            version_info: Version validation result

        Returns:
            bool: True if requirements are met
        """
        # Check version type requirement
        type_required = self.config.require_semver or self.config.require_calver

        if type_required:
            # Build list of required types
            required_types = []
            if self.config.require_semver:
                required_types.append("semver")
            if self.config.require_calver:
                required_types.append("calver")

            # Handle "both" version type - it satisfies both requirements
            if version_info.version_type == "both":
                # Check if BOTH are required (AND logic)
                if self.config.require_semver and self.config.require_calver:
                    # "both" satisfies the requirement for both
                    pass  # Valid
                else:
                    # Only one is required, "both" still satisfies it (OR logic)
                    pass  # Valid
            else:
                # Single type - check if it matches at least one required type (OR logic)
                if version_info.version_type not in required_types:
                    logger.warning(
                        f"Version type {version_info.version_type} does not match required types: {', '.join(required_types)}"
                    )
                    return False

        # Check development version requirement
        if self.config.reject_development and version_info.is_development:
            logger.warning("Development versions are not allowed")
            return False

        return True
