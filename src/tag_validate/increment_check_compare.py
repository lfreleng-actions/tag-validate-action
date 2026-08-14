# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Version ordering and increment enforcement.

Implements the SemVer and CalVer comparison rules and the check that a
pushed tag is strictly greater than the highest existing comparable tag.
"""

from itertools import zip_longest

from .models import IncrementCheckInfo, VersionInfo
from .validation import TagValidator


def _semver_identifier_cmp(a: str | None, b: str | None) -> int:
    """Compare two dot-separated pre-release identifiers (SemVer rules).

    Absence of a pre-release identifier sorts HIGHER than presence
    (a release is greater than its pre-releases).

    Args:
        a: First pre-release identifier (or None)
        b: Second pre-release identifier (or None)

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    if a is None and b is None:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1

    for x, y in zip_longest(a.split("."), b.split(".")):
        if x is None:
            # Shorter identifier set has lower precedence
            return -1
        if y is None:
            return 1
        x_numeric, y_numeric = x.isdigit(), y.isdigit()
        if x_numeric and y_numeric:
            if int(x) != int(y):
                return -1 if int(x) < int(y) else 1
        elif x_numeric:
            # Numeric identifiers have lower precedence than alphanumeric
            return -1
        elif y_numeric:
            return 1
        elif x != y:
            return -1 if x < y else 1
    return 0


def compare_semver(a: VersionInfo, b: VersionInfo) -> int:
    """Compare two parsed SemVer versions using SemVer precedence rules.

    Build metadata is ignored, as required by the SemVer specification.

    Args:
        a: First parsed version
        b: Second parsed version

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    tuple_a = (a.major or 0, a.minor or 0, a.patch or 0)
    tuple_b = (b.major or 0, b.minor or 0, b.patch or 0)
    if tuple_a != tuple_b:
        return -1 if tuple_a < tuple_b else 1
    return _semver_identifier_cmp(a.prerelease, b.prerelease)


def compare_calver(a: VersionInfo, b: VersionInfo) -> int:
    """Compare two parsed CalVer versions.

    Compares (year, month, day, micro) numerically, then applies
    pre-release style precedence to any modifier (a version without a
    modifier is greater than the same version with one).

    Args:
        a: First parsed version
        b: Second parsed version

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    tuple_a = (a.year or 0, a.month or 0, a.day or 0, a.micro or 0)
    tuple_b = (b.year or 0, b.month or 0, b.day or 0, b.micro or 0)
    if tuple_a != tuple_b:
        return -1 if tuple_a < tuple_b else 1
    return _semver_identifier_cmp(a.modifier, b.modifier)


def _schemes_for(version: VersionInfo) -> set[str]:
    """Return the set of comparable schemes a version belongs to.

    Args:
        version: Parsed version information

    Returns:
        Subset of {'semver', 'calver'} (empty for 'other' versions)
    """
    if version.version_type == "both":
        return {"semver", "calver"}
    if version.version_type in ("semver", "calver"):
        return {version.version_type}
    return set()


def check_increment(
    tag_name: str,
    existing_tags: list[str],
    validator: TagValidator | None = None,
    tag_source: str | None = None,
) -> IncrementCheckInfo:
    """Check that a tag is strictly greater than existing comparable tags.

    The pushed tag must compare strictly greater than every existing tag
    that parses under a shared versioning scheme (SemVer and/or CalVer).
    The pushed tag itself is excluded from the baseline, so re-pushing
    the current highest tag passes, but pushing any lower or equal value
    fails.

    Fail-closed behaviors:
    - The pushed tag does not parse as SemVer or CalVer: the check fails
      because ordering cannot be established.
    - No same-scheme tags exist but the repository has version tags
      under a different scheme: the check fails to prevent scheme
      switching from bypassing the gate.

    Parsing is deliberately lenient (prefixes allowed, non-strict
    SemVer) and independent of the workflow's format policy: the
    baseline must include every historical version tag even when the
    current policy would reject its format, otherwise a policy change
    (e.g. disallowing 'v' prefixes) would empty the baseline and let a
    stale tag pass as the first version tag. Format policy for the
    pushed tag is enforced separately by version validation.

    Reporting:
    - ``latest_tags`` maps each shared scheme to the highest existing
      tag under that scheme (tags typed 'both' compare under calver and
      semver independently).
    - ``latest_tag`` is a scalar convenience: the baseline that blocked
      the push when the check fails, otherwise the baseline from the
      scheme with the most comparable tags (ties broken by scheme name).

    Args:
        tag_name: The tag being validated
        existing_tags: All tags present in the repository
        validator: TagValidator instance (created when omitted)
        tag_source: Where the tag list came from (for reporting)

    Returns:
        IncrementCheckInfo with the comparison outcome
    """
    validator = validator or TagValidator()
    info = IncrementCheckInfo(checked=True, tag_source=tag_source)

    pushed = validator.validate_version(tag_name)
    pushed_schemes = _schemes_for(pushed)

    if not pushed_schemes:
        info.incremental = False
        info.errors.append(
            f"Tag '{tag_name}' does not parse as SemVer or CalVer; "
            "cannot establish version ordering for enforce_increment"
        )
        return info

    info.scheme = "+".join(sorted(pushed_schemes))

    # Parse all other tags once, tracking any valid version tags that
    # do not share a scheme with the pushed tag
    comparable: dict[str, list[tuple[str, VersionInfo]]] = {
        scheme: [] for scheme in pushed_schemes
    }
    other_scheme_tags: list[str] = []

    for existing in existing_tags:
        if existing == tag_name:
            continue
        parsed = validator.validate_version(existing)
        schemes = _schemes_for(parsed)
        if not schemes:
            continue
        shared = schemes & pushed_schemes
        if shared:
            for scheme in shared:
                # CalVer fields are absent from 'both' results (which
                # carry SemVer fields), so re-parse per scheme
                if scheme == "calver":
                    calver_parsed = validator.validate_calver(existing)
                    comparable[scheme].append((existing, calver_parsed))
                else:
                    semver_parsed = validator.validate_semver(existing)
                    comparable[scheme].append((existing, semver_parsed))
        else:
            other_scheme_tags.append(existing)

    candidate_names = {name for pairs in comparable.values() for name, _ in pairs}
    info.candidate_count = len(candidate_names)

    if not candidate_names:
        if other_scheme_tags:
            info.incremental = False
            info.errors.append(
                f"No existing tags share a versioning scheme with "
                f"'{tag_name}' ({info.scheme}), but the repository has "
                f"{len(other_scheme_tags)} version tag(s) under a "
                "different scheme (e.g. "
                f"'{other_scheme_tags[0]}'); refusing to bypass "
                "increment enforcement"
            )
        else:
            # First version tag in the repository
            info.incremental = True
        return info

    # The pushed tag must be strictly greater than the highest existing
    # tag under every shared scheme
    incremental = True
    blocking_tag: str | None = None

    for scheme, pairs in sorted(comparable.items()):
        if not pairs:
            continue
        compare = compare_semver if scheme == "semver" else compare_calver
        if scheme == "calver":
            pushed_parsed = validator.validate_calver(tag_name)
        else:
            pushed_parsed = validator.validate_semver(tag_name)

        latest_name, latest_parsed = pairs[0]
        for name, parsed in pairs[1:]:
            if compare(parsed, latest_parsed) > 0:
                latest_name, latest_parsed = name, parsed

        info.latest_tags[scheme] = latest_name

        comparison = compare(pushed_parsed, latest_parsed)
        if comparison <= 0:
            incremental = False
            if blocking_tag is None:
                blocking_tag = latest_name
            relation = "equal to" if comparison == 0 else "lower than"
            info.errors.append(
                f"Tag '{tag_name}' is {relation} existing tag "
                f"'{latest_name}' ({scheme} comparison); pushed tags "
                "must increment the repository version"
            )

    info.incremental = incremental
    if blocking_tag is not None:
        info.latest_tag = blocking_tag
    elif info.latest_tags:
        # Multi-scheme ('both') pushes have one baseline per scheme;
        # report the one from the scheme with the most comparable tags
        # (the repository's dominant scheme), ties broken by scheme name
        dominant = min(
            info.latest_tags,
            key=lambda name: (-len(comparable[name]), name),
        )
        info.latest_tag = info.latest_tags[dominant]
    return info


__all__ = [
    "check_increment",
    "compare_calver",
    "compare_semver",
]
