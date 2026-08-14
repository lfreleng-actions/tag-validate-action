# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Shared value types for the tag validation workflow modules."""

from dataclasses import dataclass


@dataclass(frozen=True)
class _TagLocationRequest:
    """Bundled verification options for tag-location validation helpers.

    Groups the user/token/owner parameters that are threaded together
    through the internal tag-location validation helpers.
    """

    github_user: str | None = None
    github_token: str | None = None
    require_owners: list[str] | None = None
