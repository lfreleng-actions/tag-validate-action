# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Version validation module for tag-validate.

This module provides comprehensive version string validation for Git tags,
supporting SemVer, CalVer, and development version detection.

Classes:
    TagValidator: Main validation class for version strings

Typical usage:
    validator = TagValidator()
    result = validator.validate_version("v1.2.3")
    if result.is_valid:
        print(f"Valid {result.version_type}: {result.version}")
"""

import logging

from packaging.version import InvalidVersion, Version

from .models import VersionInfo
from .validation_schemes import VersionSchemeMixin

logger = logging.getLogger(__name__)


class TagValidator(VersionSchemeMixin):
    """Validates version strings in Git tags.

    Supports SemVer, CalVer, and development version detection.
    Handles version prefixes (v prefix) and various development suffixes.

    Attributes:
        SEMVER_PATTERN: Regex pattern for Semantic Versioning
        CALVER_PATTERN: Regex pattern for Calendar Versioning
        DEV_SUFFIXES: List of development version indicators
    """

    def __init__(self) -> None:
        """Initialize the TagValidator."""
        logger.debug("Initialized TagValidator")

    def validate_version(
        self,
        tag: str,
        allow_prefix: bool = True,
        strict_semver: bool = False,
    ) -> VersionInfo:
        """Validate a version string and determine its type.

        This is the main entry point for version validation. It attempts
        to validate the tag as CalVer first if it starts with a year-like
        number (>= 2000), otherwise tries SemVer first, and returns
        comprehensive information about the version.

        Args:
            tag: Version string to validate (e.g., "v1.2.3", "2024.01.15")
            allow_prefix: Whether to allow 'v' prefix (default: True)
            strict_semver: Whether to enforce strict SemVer compliance (default: False)

        Returns:
            VersionInfo: Validation result with version type and components

        Examples:
            >>> validator = TagValidator()
            >>> result = validator.validate_version("v1.2.3")
            >>> result.is_valid
            True
            >>> result.version_type
            'semver'
        """
        logger.debug(f"Validating version: {tag}")

        # Validate against both SemVer and CalVer to detect "both" case
        semver_result = self.validate_semver(tag, allow_prefix, strict_semver)
        calver_result = self.validate_calver(tag, allow_prefix)

        # Check if valid as both
        if semver_result.is_valid and calver_result.is_valid:
            logger.debug(f"Tag '{tag}' validated as both SemVer and CalVer")
            # Return semver result but with type="both"
            result = semver_result
            result.version_type = "both"
            return result

        # Valid as SemVer only
        if semver_result.is_valid:
            logger.debug(f"Tag '{tag}' validated as SemVer: {semver_result.normalized}")
            return semver_result

        # Valid as CalVer only
        if calver_result.is_valid:
            logger.debug(f"Tag '{tag}' validated as CalVer: {calver_result.normalized}")
            return calver_result

        # Other format (doesn't match SemVer or CalVer) - still valid, just different type
        logger.debug(
            f"Tag '{tag}' does not match SemVer or CalVer patterns - type: other"
        )

        # Detect if it has a version prefix
        has_prefix = tag[0:1] in ("v", "V") if tag else False

        # Check if it's a development tag
        is_dev = self.is_development_tag(tag)

        return VersionInfo(
            raw=tag,
            normalized=tag,
            is_valid=True,  # Changed: Accept other types as valid
            version_type="other",  # Changed: Use "other" instead of "unknown"
            has_prefix=has_prefix,
            is_development=is_dev,
            # All version-specific fields are None for "other" type
            major=None,
            minor=None,
            patch=None,
            prerelease=None,
            build_metadata=None,
            year=None,
            month=None,
            day=None,
            micro=None,
            modifier=None,
            errors=[],  # No errors - this is a valid tag, just not semver/calver
        )

    def has_version_prefix(self, tag: str) -> bool:
        """Check if a version string has a 'v' prefix.

        Args:
            tag: Version string to check

        Returns:
            bool: True if tag starts with 'v' or 'V'

        Examples:
            >>> validator = TagValidator()
            >>> validator.has_version_prefix("v1.2.3")
            True
            >>> validator.has_version_prefix("1.2.3")
            False
        """
        has_prefix = tag.startswith("v") or tag.startswith("V")
        logger.debug(f"Tag '{tag}' has prefix: {has_prefix}")
        return has_prefix

    def parse_version_string(
        self,
        tag: str,
        allow_prefix: bool = True,
    ) -> VersionInfo:
        """Parse a version string and extract all components.

        This is an alias for validate_version() for backward compatibility
        and clarity in some contexts.

        Args:
            tag: Version string to parse
            allow_prefix: Whether to allow 'v' prefix

        Returns:
            VersionInfo: Parsed version information

        Examples:
            >>> validator = TagValidator()
            >>> info = validator.parse_version_string("v1.2.3-beta+build.123")
            >>> info.major, info.prerelease, info.build_metadata
            (1, 'beta', 'build.123')
        """
        return self.validate_version(tag, allow_prefix=allow_prefix)

    def strip_prefix(self, tag: str) -> str:
        """Remove 'v' prefix from a version string if present.

        Args:
            tag: Version string that may have a prefix

        Returns:
            str: Version string without 'v' prefix

        Examples:
            >>> validator = TagValidator()
            >>> validator.strip_prefix("v1.2.3")
            '1.2.3'
            >>> validator.strip_prefix("1.2.3")
            '1.2.3'
        """
        if tag.startswith("v") or tag.startswith("V"):
            return tag[1:]
        return tag

    def compare_versions(
        self,
        version1: str,
        version2: str,
    ) -> int | None:
        """Compare two version strings.

        Args:
            version1: First version string
            version2: Second version string

        Returns:
            Optional[int]: -1 if version1 < version2,
                          0 if version1 == version2,
                          1 if version1 > version2,
                          None if versions cannot be compared

        Examples:
            >>> validator = TagValidator()
            >>> validator.compare_versions("v1.2.3", "v1.2.4")
            -1
            >>> validator.compare_versions("v2.0.0", "v1.9.9")
            1
        """
        try:
            # Strip prefixes and parse
            v1_str = self.strip_prefix(version1)
            v2_str = self.strip_prefix(version2)

            v1 = Version(v1_str)
            v2 = Version(v2_str)

            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            else:
                return 0
        except (InvalidVersion, ValueError) as e:
            logger.warning(
                f"Cannot compare versions '{version1}' and '{version2}': {e}"
            )
            return None
