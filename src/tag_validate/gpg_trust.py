# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Supplied GPG keys, pinned fingerprints and key state for tag verification.

Verification against ``--trusted-gpg-keys`` runs in a temporary GnuPG
home holding those keys and nothing else, so the default keyring is
neither read nor changed. This module builds that home, checks the key
file, parses ``--require-fingerprint`` and reads key expiry from GnuPG.
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .models import SignatureInfo

logger = logging.getLogger(__name__)

FINGERPRINT_LENGTH = 40
_HEX = re.compile(r"[0-9A-F]+")
_GPG_TIMEOUT_SECONDS = 60


class GpgTrustError(ValueError):
    """Raised for an unusable trusted key file or fingerprint list."""


def normalize_fingerprint(value: str) -> str:
    """Return a fingerprint in upper case with all whitespace removed."""
    return re.sub(r"\s+", "", value).upper()


def parse_fingerprints(value: str) -> list[str]:
    """Parse a comma or space separated list of primary key fingerprints.

    A fingerprint may be written in groups separated by spaces, as GnuPG
    prints it. Each comma separated part must hold one or more complete
    40-digit fingerprints; short and long key IDs are refused.

    Raises:
        GpgTrustError: If any part is not a whole number of fingerprints,
            or the list is empty
    """
    fingerprints: list[str] = []
    for part in value.split(","):
        compact = normalize_fingerprint(part)
        if not compact:
            continue
        if not _HEX.fullmatch(compact) or len(compact) % FINGERPRINT_LENGTH:
            raise GpgTrustError(
                f"'{part.strip()}' is not a full {FINGERPRINT_LENGTH}-digit "
                "primary key fingerprint (key IDs are not accepted)"
            )
        for start in range(0, len(compact), FINGERPRINT_LENGTH):
            fingerprint = compact[start : start + FINGERPRINT_LENGTH]
            if fingerprint not in fingerprints:
                fingerprints.append(fingerprint)
    if not fingerprints:
        raise GpgTrustError("no fingerprint given")
    return fingerprints


def gpg_executable() -> str:
    """Return the GnuPG executable this module runs, by path when found."""
    return shutil.which("gpg") or "gpg"


def _run_gpg(
    args: list[str], gnupg_home: Path | None
) -> subprocess.CompletedProcess[str]:
    """Run gpg in batch mode against the given home (default when None)."""
    env = dict(os.environ)
    if gnupg_home is not None:
        env["GNUPGHOME"] = str(gnupg_home)
    return subprocess.run(
        [gpg_executable(), "--batch", "--no-tty", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=_GPG_TIMEOUT_SECONDS,
    )


def _remove_home(home: Path) -> None:
    """Stop any GnuPG daemons started for a home, then delete it."""
    try:
        subprocess.run(
            ["gpgconf", "--homedir", str(home), "--kill", "all"],
            capture_output=True,
            check=False,
            timeout=_GPG_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug(f"Could not stop GnuPG daemons for {home}: {e}")
    shutil.rmtree(home, ignore_errors=True)


@contextmanager
def _empty_home() -> Iterator[Path]:
    """Yield a new, private, empty GnuPG home, removed afterwards."""
    home = Path(tempfile.mkdtemp(prefix="tag-validate-gpg-"))
    try:
        yield home
    finally:
        _remove_home(home)


def inspect_key_file(key_file: Path) -> list[str]:
    """Check that a key file holds public keys and no secret key.

    Returns:
        The primary key fingerprints the file holds

    Raises:
        GpgTrustError: If the file cannot be read, holds a secret key,
            or holds no public key
    """
    if not key_file.is_file():
        raise GpgTrustError(f"trusted GPG key file not found: {key_file}")
    with _empty_home() as home:
        listing = _run_gpg(
            [
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                str(key_file),
            ],
            home,
        )
    records = [line.split(":") for line in listing.stdout.splitlines()]
    if any(record[0] in ("sec", "ssb") for record in records):
        raise GpgTrustError("trusted GPG keys must not include a secret key")
    primaries: list[str] = []
    previous = ""
    for record in records:
        if record[0] == "fpr" and previous == "pub" and len(record) > 9:
            primaries.append(record[9].upper())
        previous = record[0]
    if not primaries:
        raise GpgTrustError("trusted GPG keys hold no public key")
    return primaries


@contextmanager
def temporary_keyring(key_file: Path) -> Iterator[Path]:
    """Yield a GnuPG home holding only the keys in ``key_file``.

    Raises:
        GpgTrustError: If the keys cannot be imported
    """
    inspect_key_file(key_file)
    with _empty_home() as home:
        imported = _run_gpg(["--import", str(key_file)], home)
        if imported.returncode != 0:
            raise GpgTrustError(
                f"could not import trusted GPG keys: {imported.stderr.strip()}"
            )
        yield home


def key_expiry(
    gnupg_home: Path | None, primary_fingerprint: str, signing_fingerprint: str
) -> int | None:
    """Return when a signing key stops being valid, as epoch seconds.

    That is the earlier expiry of the primary key and, for a subkey,
    the subkey itself. None when neither expires or the key is unknown.
    """
    listing = _run_gpg(
        ["--with-colons", "--fixed-list-mode", "--list-keys", primary_fingerprint],
        gnupg_home,
    )
    expiries: dict[str, str] = {}
    pending = ""
    for line in listing.stdout.splitlines():
        record = line.split(":")
        if record[0] in ("pub", "sub") and len(record) > 6:
            pending = record[6]
        elif record[0] == "fpr" and len(record) > 9:
            expiries[record[9].upper()] = pending
            pending = ""
    wanted = {primary_fingerprint.upper(), signing_fingerprint.upper()}
    found = [int(expiries[fpr]) for fpr in wanted if expiries.get(fpr, "").isdigit()]
    return min(found) if found else None


def format_epoch(epoch: int) -> str:
    """Format epoch seconds as an ISO 8601 UTC date and time."""
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def describe_key_state(signature_info: SignatureInfo) -> str | None:
    """Name the key or signature state that stops a GPG signature verifying.

    Returns None for a signature without such a state, and for an
    expired key that ``permit_expired_key`` admitted.
    """
    key = signature_info.primary_fingerprint or signature_info.key_id or "unknown"
    expiry = signature_info.key_expiry or "an unknown date"
    if signature_info.key_expired:
        return None
    messages = {
        "revoked-key": f"GPG signing key {key} has been revoked",
        "expired-signature": "GPG signature has expired",
        "expired-key": (
            f"GPG signing key {key} expired on {expiry} (permit_expired_key is not set)"
        ),
        "signed-after-expiry": (
            f"GPG signature was not made before signing key {key} expired on {expiry}"
        ),
    }
    return messages.get(signature_info.key_state or "")
