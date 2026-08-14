# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
Locating, vetting, and loading .netrc files from disk.

Covers the search order across the working directory and home directory
(including the Windows ``_netrc`` fallback) and the permission check that
warns about world-readable credential files.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from .netrc_parser import NetrcParser
from .netrc_types import NetrcParseError

# Bound to the public module's name so log records keep reporting
# `tag_validate.netrc` no matter which sibling module emits them.
log = logging.getLogger(f"{__package__}.netrc")


def find_netrc_file(
    search_local: bool = True,
    explicit_path: Path | None = None,
) -> Path | None:
    """
    Find a .netrc file using standard search order.

    Search order:
    1. Explicit path (if provided)
    2. Local directory .netrc (if search_local=True)
    3. ~/.netrc
    4. ~/_netrc (Windows fallback)

    Args:
        search_local: Whether to search current directory first.
        explicit_path: Explicit path to a netrc file.

    Returns:
        Path to found netrc file, or None if not found.
    """
    if explicit_path is not None:
        if explicit_path.is_file():
            log.debug("Using explicit netrc file: %s", explicit_path)
            return explicit_path
        log.warning("Explicit netrc file not found: %s", explicit_path)
        return None

    candidates: list[Path] = []

    # Local directory
    if search_local:
        candidates.append(Path.cwd() / ".netrc")

    # Home directory
    home = Path.home()
    candidates.append(home / ".netrc")

    # Windows fallback
    if os.name == "nt":
        candidates.append(home / "_netrc")

    for candidate in candidates:
        if candidate.is_file():
            log.debug("Found netrc file: %s", candidate)
            return candidate

    log.debug("No netrc file found in search paths")
    return None


def check_netrc_permissions(path: Path) -> bool:
    """
    Check if netrc file has secure permissions.

    Warns if the file is readable by others (Unix only).

    Args:
        path: Path to the netrc file.

    Returns:
        True if permissions are secure, False otherwise.
    """
    if os.name == "nt":
        # Windows doesn't have the same permission model
        return True

    try:
        mode = path.stat().st_mode
    except OSError as e:
        log.warning("Could not check permissions for %s: %s", path, e)
        return True

    # Check if group or others have read permission
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        log.warning(
            "Netrc file %s has insecure permissions. Consider running: chmod 600 %s",
            path,
            path,
        )
        return False
    return True


def load_netrc(
    path: Path | None = None,
    search_local: bool = True,
) -> NetrcParser | None:
    """
    Load and parse a netrc file.

    Args:
        path: Explicit path to netrc file (optional).
        search_local: Search current directory for .netrc.

    Returns:
        NetrcParser instance, or None if no file found.

    Raises:
        NetrcParseError: If the file exists but cannot be parsed.
    """
    netrc_path = find_netrc_file(
        search_local=search_local,
        explicit_path=path,
    )

    if netrc_path is None:
        return None

    check_netrc_permissions(netrc_path)

    try:
        content = netrc_path.read_text(encoding="utf-8")
    except OSError:
        log.exception("Could not read netrc file %s", netrc_path)
        return None

    try:
        return NetrcParser(content)
    except NetrcParseError:
        log.exception("Could not parse netrc file %s", netrc_path)
        raise


__all__ = [
    "check_netrc_permissions",
    "find_netrc_file",
    "load_netrc",
]
