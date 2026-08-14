# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""SemVer and CalVer validation for tag-validate.

Holds the two versioning-scheme validators together with the regular
expressions that drive them. :class:`~tag_validate.validation.TagValidator`
inherits from :class:`VersionSchemeMixin`, so the schemes stay reachable
as ``TagValidator.validate_semver`` / ``TagValidator.validate_calver``.
"""

import logging
import re

from packaging.version import InvalidVersion, Version

from .models import VersionInfo

# Bound to the public module's name so log records keep reporting
# `tag_validate.validation` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.validation")


class VersionSchemeMixin:
    """Version-scheme validators shared by :class:`TagValidator`.

    Attributes:
        SEMVER_PATTERN: Regex pattern for Semantic Versioning
        CALVER_PATTERN: Regex pattern for Calendar Versioning
        DEV_SUFFIXES: List of development version indicators
    """

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
        - YYYY.MM.MICRO (e.g., 2024.01.42)
        - YYYY.MM.DD.MICRO (e.g., 2024.01.15.1)

        In three-component versions the third component is treated as
        a day when it is 1-31 and as a micro/patch number when it is
        greater than 31 (0 is rejected as an invalid day). The third
        component is limited to two digits, so micro values above 99
        require the YYYY.MM.DD.MICRO format.

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

        # Validate day/micro component layout
        if micro is not None:
            # Four components: YYYY.MM.DD.MICRO (DD must be a valid day)
            if not (1 <= day_or_micro <= 31):
                return VersionInfo(
                    raw=tag,
                    is_valid=False,
                    version_type="calver",
                    errors=[
                        f"Invalid day: {day_or_micro} (must be 1-31 in "
                        "YYYY.MM.DD.MICRO format)"
                    ],
                )
            day = day_or_micro
            version_str = f"{year}.{month}.{day}.{micro}"
        elif day_or_micro <= 31:
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
                logger.debug(
                    f"Tag '{tag}' identified as development version (suffix: {suffix})"
                )
                return True
        return False
