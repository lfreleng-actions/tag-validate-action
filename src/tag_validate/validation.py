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
import re

from packaging.version import InvalidVersion, Version

from .models import VersionInfo

logger = logging.getLogger(__name__)


class TagValidator:
    """Validates version strings in Git tags.

    Supports SemVer, CalVer, and development version detection.
    Handles version prefixes (v prefix) and various development suffixes.

    Attributes:
        SEMVER_PATTERN: Regex pattern for Semantic Versioning
        CALVER_PATTERN: Regex pattern for Calendar Versioning
        DEV_SUFFIXES: List of development version indicators
    """

    # SemVer pattern: v?MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
    SEMVER_PATTERN = re.compile(
        r"^v?"  # Optional 'v' prefix
        r"(?P<major>0|[1-9]\d*)"  # Major version
        r"\."
        r"(?P<minor>0|[1-9]\d*)"  # Minor version
        r"\."
        r"(?P<patch>0|[1-9]\d*)"  # Patch version
        r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
        r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"  # Pre-release
        r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"  # Build metadata
        r"$",
        re.VERBOSE,
    )

    # CalVer pattern: v?YYYY.MM.DD or YYYY.MM.MICRO
    CALVER_PATTERN = re.compile(
        r"^v?"  # Optional 'v' prefix
        r"(?P<year>\d{4})"  # Year (4 digits)
        r"\."
        r"(?P<month>0?[1-9]|1[0-2])"  # Month (1-12, optional leading zero)
        r"\."
        r"(?P<day_or_micro>\d{1,2})"  # Day (1-31) or micro version
        r"(?:\.(?P<micro>\d+))?"  # Optional micro version
        r"(?:-(?P<modifier>[a-zA-Z0-9.-]+))?"  # Optional modifier
        r"$"
    )

    # Development version suffixes
    DEV_SUFFIXES = [
        "alpha",
        "beta",
        "rc",
        "dev",
        "snapshot",
        "pre",
        "preview",
        "test",
        "nightly",
    ]

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
        logger.debug(f"Tag '{tag}' does not match SemVer or CalVer patterns - type: other")

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

    def validate_semver(
        self,
        tag: str,
        allow_prefix: bool = True,
        strict: bool = False,
    ) -> VersionInfo:
        """Validate a Semantic Version string.

        Validates according to SemVer 2.0.0 specification:
        https://semver.org/spec/v2.0.0.html

        Args:
            tag: Version string to validate
            allow_prefix: Whether to allow 'v' prefix
            strict: Whether to enforce strict SemVer (no prefix, exact format)

        Returns:
            VersionInfo: Validation result with parsed components

        Examples:
            >>> validator = TagValidator()
            >>> result = validator.validate_semver("1.2.3")
            >>> result.major, result.minor, result.patch
            (1, 2, 3)
        """
        logger.debug(f"Validating as SemVer: {tag}")

        # Check for prefix
        has_prefix = tag.startswith("v")
        if has_prefix and not allow_prefix:
            return VersionInfo(
                raw=tag,
                is_valid=False,
                version_type="semver",
                errors=["Version prefix 'v' not allowed in strict mode"],
            )

        if strict and has_prefix:
            return VersionInfo(
                raw=tag,
                is_valid=False,
                version_type="semver",
                errors=["Strict SemVer does not allow 'v' prefix"],
            )

        # Match against SemVer pattern
        match = self.SEMVER_PATTERN.match(tag)
        if not match:
            return VersionInfo(
                raw=tag,
                is_valid=False,
                version_type="semver",
                errors=["String does not match SemVer pattern (MAJOR.MINOR.PATCH)"],
            )

        # Extract components
        groups = match.groupdict()
        major = int(groups["major"])
        minor = int(groups["minor"])
        patch = int(groups["patch"])
        prerelease = groups.get("prerelease")
        build_metadata = groups.get("build")

        # Build normalized version string (without prefix)
        version_str = f"{major}.{minor}.{patch}"
        if prerelease:
            version_str += f"-{prerelease}"
        if build_metadata:
            version_str += f"+{build_metadata}"

        # Validate with packaging library (only in strict mode)
        # SemVer 2.0.0 allows hyphens in prerelease identifiers, but PEP 440 doesn't
        # So we only enforce PEP 440 compliance in strict mode
        if strict:
            try:
                Version(version_str)
            except InvalidVersion as e:
                return VersionInfo(
                    raw=tag,
                    is_valid=False,
                    version_type="semver",
                    errors=[f"Invalid version per PEP 440: {e}"],
                )

        # Check if development version
        is_dev = self.is_development_tag(tag)

        # Build result
        result = VersionInfo(
            raw=tag,
            normalized=version_str,
            is_valid=True,
            version_type="semver",
            has_prefix=has_prefix,
            major=major,
            minor=minor,
            patch=patch,
            prerelease=prerelease,
            build_metadata=build_metadata,
            is_development=is_dev,
        )

        logger.debug(f"SemVer validation successful: {result.normalized}")
        return result

    def validate_calver(
        self,
        tag: str,
        allow_prefix: bool = True,
    ) -> VersionInfo:
        """Validate a Calendar Version string.

        Supports common CalVer patterns:
        - YYYY.MM.DD (e.g., 2024.01.15)
        - YYYY.MM.MICRO (e.g., 2024.01.0)

        Args:
            tag: Version string to validate
            allow_prefix: Whether to allow 'v' prefix

        Returns:
            VersionInfo: Validation result with parsed components

        Examples:
            >>> validator = TagValidator()
            >>> result = validator.validate_calver("2024.01.15")
            >>> result.year, result.month
            (2024, 1)
        """
        logger.debug(f"Validating as CalVer: {tag}")

        # Check for prefix
        has_prefix = tag.startswith("v")
        if has_prefix and not allow_prefix:
            return VersionInfo(
                raw=tag,
                is_valid=False,
                version_type="calver",
                errors=["Version prefix 'v' not allowed"],
            )

        # Match against CalVer pattern
        match = self.CALVER_PATTERN.match(tag)
        if not match:
            return VersionInfo(
                raw=tag,
                is_valid=False,
                version_type="calver",
                errors=["String does not match CalVer pattern (YYYY.MM.DD)"],
            )

        # Extract components
        groups = match.groupdict()
        year = int(groups["year"])
        month = int(groups["month"])
        day_or_micro = int(groups["day_or_micro"])
        micro = int(groups["micro"]) if groups.get("micro") else None
        modifier = groups.get("modifier")

        # Validate month
        if not (1 <= month <= 12):
            return VersionInfo(
                raw=tag,
                is_valid=False,
                version_type="calver",
                errors=[f"Invalid month: {month} (must be 1-12)"],
            )

        # Validate day if it looks like a day (1-31)
        if day_or_micro <= 31 and micro is None:
            # Likely YYYY.MM.DD format
            if day_or_micro < 1:
                return VersionInfo(
                    raw=tag,
                    is_valid=False,
                    version_type="calver",
                    errors=[f"Invalid day: {day_or_micro} (must be 1-31)"],
                )
            day = day_or_micro
            version_str = f"{year}.{month}.{day}"
        else:
            # YYYY.MM.MICRO format
            day = None
            version_str = f"{year}.{month}.{day_or_micro}"
            if micro is not None:
                version_str += f".{micro}"

        if modifier:
            version_str += f"-{modifier}"

        # Check if development version
        is_dev = self.is_development_tag(tag)

        # Build result
        result = VersionInfo(
            raw=tag,
            normalized=version_str if not has_prefix else f"v{version_str}",
            is_valid=True,
            version_type="calver",
            has_prefix=has_prefix,
            year=year,
            month=month,
            day=day,
            micro=day_or_micro if day is None else micro,
            modifier=modifier,
            is_development=is_dev,
        )

        logger.debug(f"CalVer validation successful: {result.normalized}")
        return result

    def is_development_tag(self, tag: str) -> bool:
        """Check if a version string indicates a development release.

        Development versions are identified by common suffixes like:
        alpha, beta, rc, dev, snapshot, pre, preview, test, nightly

        Args:
            tag: Version string to check

        Returns:
            bool: True if tag appears to be a development version

        Examples:
            >>> validator = TagValidator()
            >>> validator.is_development_tag("v1.2.3-alpha")
            True
            >>> validator.is_development_tag("v1.2.3")
            False
        """
        tag_lower = tag.lower()
        for suffix in self.DEV_SUFFIXES:
            # Check for suffix in prerelease (e.g., -alpha, -beta.1)
            if f"-{suffix}" in tag_lower or f".{suffix}" in tag_lower:
                logger.debug(f"Tag '{tag}' identified as development version (suffix: {suffix})")
                return True
        return False

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
            logger.warning(f"Cannot compare versions '{version1}' and '{version2}': {e}")
            return None
