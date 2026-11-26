# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tag freshness (age) checks.

Confirms that a tag was created recently enough to be treated as a fresh
release rather than a replay of an old one.
"""

import math
from datetime import UTC, datetime

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


def _as_utc(moment: datetime) -> datetime:
    """Treat a naive datetime as UTC."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _stale_message(
    tag_name: str, tag_date: str, age_seconds: float, info: TagAgeCheckInfo
) -> str:
    """Describe a tag older than the window, worded for its reference."""
    age = _format_age(age_seconds)
    if info.reference_source == "push_event":
        lead = (
            f"Tag '{tag_name}' was pushed {age} after it was created "
            f"(created {tag_date}, pushed {info.reference_time})"
        )
    elif info.reference_source == "supplied":
        lead = (
            f"Tag '{tag_name}' was created {age} before the reference "
            f"time {info.reference_time} ({tag_date})"
        )
    else:
        lead = f"Tag '{tag_name}' was created {age} ago ({tag_date})"
    return (
        f"{lead}, exceeding the require_recent window of "
        f"{info.max_age_minutes:g} minute(s); stale tags must be "
        "recreated before release"
    )


def check_tag_age(
    tag_info: TagInfo,
    max_age_minutes: float,
    now: datetime | None = None,
    *,
    reference_source: str = "clock",
    current_time: datetime | None = None,
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
        reference_source: Where ``now`` came from: 'clock', or
            'push_event'/'supplied' for a reference taken from outside
            this process, which must not lie in the future
        current_time: The current time, against which an external
            reference is checked (defaults to UTC now)

    Returns:
        TagAgeCheckInfo with the age check outcome
    """
    reference = _as_utc(now or datetime.now(UTC))
    info = TagAgeCheckInfo(
        checked=True,
        max_age_minutes=max_age_minutes,
        reference_time=reference.isoformat(),
        reference_source=reference_source,
    )
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

    # An external reference after the current time cannot be right, and
    # trusting it would let a stale tag look fresh relative to the clock
    if reference_source != "clock":
        current = _as_utc(current_time or datetime.now(UTC))
        ahead_seconds = (reference - current).total_seconds()
        if ahead_seconds > CLOCK_SKEW_TOLERANCE_SECONDS:
            info.recent = None
            info.errors.append(
                f"Tag age reference time {info.reference_time} "
                f"({reference_source}) is {_format_age(ahead_seconds)} "
                "in the future; the reference cannot be trusted"
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
    created = _as_utc(created)

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
            _stale_message(tag_name, tag_info.tag_date, age_seconds, info)
        )
    else:
        info.recent = True
    return info


__all__ = [
    "CLOCK_SKEW_TOLERANCE_SECONDS",
    "DEFAULT_TAG_AGE_MINUTES",
    "check_tag_age",
]
