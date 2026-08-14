# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tag freshness (age) checks.

Confirms that a tag was created recently enough to be treated as a fresh
release rather than a replay of an old one.
"""

import math
from datetime import datetime, timezone

from .models import TagAgeCheckInfo, TagInfo

# Default window (minutes) for the tag age (require_recent) check
DEFAULT_TAG_AGE_MINUTES = 3.0

# Tolerance (seconds) for tag timestamps slightly in the future
# (tagger machine clocks are rarely perfectly synchronized)
CLOCK_SKEW_TOLERANCE_SECONDS = 300


def _format_age(seconds: float) -> str:
    """Format an age in seconds as a human-readable duration.

    Args:
        seconds: Age in seconds

    Returns:
        Human-readable duration (e.g. '2.5 minutes', '3.2 days')
    """
    if seconds < 120:
        return f"{seconds:.0f} seconds"
    if seconds < 7200:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 172800:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def check_tag_age(
    tag_info: TagInfo,
    max_age_minutes: float,
    now: datetime | None = None,
) -> TagAgeCheckInfo:
    """Check that a tag was created within the allowed time window.

    Uses the tag object's tagger timestamp, so the check only works
    for annotated (including signed) tags. Lightweight tags carry no
    creation timestamp and fail closed: falling back to the commit
    date would reject legitimate releases, because release commits
    are usually older than the freshness window.

    Note: tagger timestamps come from the tag creator's clock and are
    not tamper-proof; this gate prevents accidental pushes of stale
    tags rather than deliberate forgery. Combine with require_latest
    for a check that cannot be forged. Timestamps more than a small
    skew tolerance in the future also fail closed, because they
    indicate the timestamp cannot be trusted.

    Args:
        tag_info: Tag metadata (provides tag type and creation date)
        max_age_minutes: Maximum permitted tag age, in minutes
        now: Reference time for age calculation (defaults to UTC now)

    Returns:
        TagAgeCheckInfo with the age check outcome
    """
    info = TagAgeCheckInfo(checked=True, max_age_minutes=max_age_minutes)
    tag_name = tag_info.tag_name

    # Defense in depth: the CLI validates its input, but programmatic
    # callers could pass a non-finite or non-positive window, and NaN
    # comparisons are always False (the gate would fail open)
    if not math.isfinite(max_age_minutes) or max_age_minutes <= 0:
        info.recent = None
        info.errors.append(
            f"Invalid tag age window '{max_age_minutes}': the window "
            "must be a finite positive number of minutes"
        )
        return info

    if tag_info.tag_type != "annotated":
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' is a lightweight tag with no creation "
            "timestamp; tag age cannot be verified. Use an annotated "
            "(or signed) tag, or disable require_recent"
        )
        return info

    if not tag_info.tag_date:
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' is an annotated tag but its creation "
            "timestamp could not be determined; tag age cannot be "
            "verified"
        )
        return info

    try:
        created = datetime.fromisoformat(tag_info.tag_date)
    except ValueError as e:
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' has an unparsable creation timestamp "
            f"'{tag_info.tag_date}': {e}"
        )
        return info
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    reference = now or datetime.now(timezone.utc)
    age_seconds = (reference - created).total_seconds()
    info.tag_date = tag_info.tag_date

    if age_seconds < -CLOCK_SKEW_TOLERANCE_SECONDS:
        # No age reported: an untrusted future timestamp has no
        # meaningful age, and a clamped zero would look fresh
        info.recent = None
        info.errors.append(
            f"Tag '{tag_name}' has a creation timestamp "
            f"{_format_age(-age_seconds)} in the future "
            f"({tag_info.tag_date}); the timestamp cannot be trusted"
        )
        return info

    # Report a non-negative age: tolerated future skew would otherwise
    # surface as a confusing negative age in JSON output and summaries.
    # The signed value is retained for the window comparison below.
    info.age_seconds = max(age_seconds, 0.0)

    if age_seconds > max_age_minutes * 60:
        info.recent = False
        info.errors.append(
            f"Tag '{tag_name}' was created {_format_age(age_seconds)} "
            f"ago ({tag_info.tag_date}), exceeding the require_recent "
            f"window of {max_age_minutes:g} minute(s); stale tags must "
            "be recreated before release"
        )
    else:
        info.recent = True
    return info


__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "DEFAULT_TAG_AGE_MINUTES",
    "check_tag_age",
]
