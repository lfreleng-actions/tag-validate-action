# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""
Tag Validate: GitHub tag validation with cryptographic signature verification.

This package provides tools for validating Git tags against versioning schemes
(SemVer, CalVer) and verifying cryptographic signatures (GPG, SSH) with optional
GitHub key registry verification.

Key features:
- SemVer and CalVer validation
- GPG and SSH signature detection
- GitHub API integration for key verification
- Support for local and remote repositories
- Comprehensive CLI interface

Example usage:
    >>> from tag_validate import TagValidator, ValidationConfig
    >>> config = ValidationConfig(
    ...     require_type="semver",
    ...     require_signed="gpg",
    ...     verify_key_on_github=True
    ... )
    >>> validator = TagValidator(config)
    >>> result = await validator.validate_tag("v1.2.3")
"""

try:
    from tag_validate._version import __version__
except ImportError:
    # Fall back to importlib.metadata if _version.py doesn't exist
    from importlib.metadata import PackageNotFoundError, version
    try:
        __version__ = version("tag-validate")
    except PackageNotFoundError:
        __version__ = "unknown"

__all__ = [
    "__version__",
]
