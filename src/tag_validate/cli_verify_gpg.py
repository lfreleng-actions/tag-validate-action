# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Input checks for the ``verify`` GPG trust options.

``--trusted-gpg-keys`` and ``--require-fingerprint`` are checked here,
before verification starts, so a bad key file or fingerprint fails as
invalid input rather than as a failed tag.
"""

from pathlib import Path
from typing import NamedTuple

from .cli_runtime import reject_input
from .gpg_trust import GpgTrustError, inspect_key_file, parse_fingerprints


class GpgTrust(NamedTuple):
    """Supplied GPG keys and pinned fingerprints, checked before use."""

    trusted_gpg_keys: str | None
    require_fingerprints: list[str] | None


def parse_gpg_trust(
    trusted_gpg_keys: Path | None,
    require_fingerprint: str | None,
    json_output: bool,
) -> GpgTrust:
    """Check ``--trusted-gpg-keys`` and parse ``--require-fingerprint``.

    Raises:
        typer.Exit: If the key file holds no public key or a secret key,
            or a fingerprint is not a full primary key fingerprint
    """
    try:
        if trusted_gpg_keys is not None:
            inspect_key_file(trusted_gpg_keys)
        fingerprints = (
            parse_fingerprints(require_fingerprint)
            if require_fingerprint is not None
            else None
        )
    except GpgTrustError as e:
        raise reject_input(f"Invalid GPG trust option: {e}", json_output) from e
    return GpgTrust(
        str(trusted_gpg_keys) if trusted_gpg_keys else None,
        fingerprints,
    )
