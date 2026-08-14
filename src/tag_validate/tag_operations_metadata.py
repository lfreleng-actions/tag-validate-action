# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Tag location parsing and tag-object metadata extraction.

Covers the two pure-text concerns of :class:`TagOperations`: turning an
``owner/repo@tag`` location string into its parts, and pulling the
tagger, date, and message fields out of a raw Git tag object.
"""

import logging
import re

# Bound to the public module's name so log records keep reporting
# `tag_validate.tag_operations` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.tag_operations")


class TagLocationError(Exception):
    """Exception raised when tag location cannot be parsed or accessed."""

    pass


class TagMetadataMixin:
    """Location parsing and tag-object field extraction.

    Attributes:
        TAG_LOCATION_PATTERN: Regex pattern for parsing tag locations
    """

    # Pattern: owner/repo@tag or https://github.com/owner/repo@tag
    TAG_LOCATION_PATTERN = re.compile(
        r"^(?:https?://github\.com/)?"  # Optional GitHub URL
        r"(?P<owner>[a-zA-Z0-9_-]+)"  # Owner/org name
        r"/"
        r"(?P<repo>[a-zA-Z0-9_.-]+?)"  # Repo name
        r"(?:\.git)?"  # Optional .git suffix
        r"@"
        r"(?P<tag>.+)"  # Tag name
        r"$"
    )

    def parse_tag_location(self, location: str) -> tuple[str, str, str]:
        """Parse a tag location string into components.

        Supports formats:
        - owner/repo@tag
        - https://github.com/owner/repo@tag
        - https://github.com/owner/repo.git@tag

        Args:
            location: Tag location string

        Returns:
            Tuple[str, str, str]: (owner, repo, tag)

        Raises:
            TagLocationError: If location format is invalid

        Examples:
            >>> ops = TagOperations()
            >>> owner, repo, tag = ops.parse_tag_location("torvalds/linux@v6.0")
            >>> owner, repo, tag
            ('torvalds', 'linux', 'v6.0')
        """
        logger.debug(f"Parsing tag location: {location}")

        match = self.TAG_LOCATION_PATTERN.match(location)
        if not match:
            raise TagLocationError(
                f"Invalid tag location format: '{location}'. "
                f"Expected: owner/repo@tag or https://github.com/owner/repo@tag"
            )

        owner = match.group("owner")
        repo = match.group("repo")
        tag = match.group("tag")

        logger.debug(f"Parsed location: owner={owner}, repo={repo}, tag={tag}")
        return owner, repo, tag

    def _extract_tagger_info(self, tag_object: str) -> tuple[str | None, str | None]:
        """Extract tagger name and email from tag object.

        Parses the 'tagger' line in a Git tag object to extract the
        committer's name and email address.

        Args:
            tag_object: Raw tag object content

        Returns:
            Tuple[Optional[str], Optional[str]]: (tagger_name, tagger_email)

        Examples:
            >>> ops = TagOperations()
            >>> tag_obj = "tagger John Doe <john@example.com> 1234567890 +0000"
            >>> name, email = ops._extract_tagger_info(tag_obj)
            >>> name, email
            ('John Doe', 'john@example.com')
        """
        # Pattern: tagger Name <email@example.com> timestamp timezone
        pattern = re.compile(
            r"^tagger\s+"
            r"(?P<name>.+?)"
            r"\s+<(?P<email>[^>]+)>"
            r"\s+\d+\s+[+-]\d{4}",
            re.MULTILINE,
        )

        match = pattern.search(tag_object)
        if match:
            name = match.group("name").strip()
            email = match.group("email").strip()
            logger.debug(f"Extracted tagger: {name} <{email}>")
            return name, email

        logger.debug("No tagger information found in tag object")
        return None, None

    def _extract_tag_date(self, tag_object: str) -> str | None:
        """Extract tag creation date from tag object.

        Args:
            tag_object: Raw tag object content

        Returns:
            Optional[str]: ISO 8601 timestamp or None

        Examples:
            >>> ops = TagOperations()
            >>> tag_obj = "tagger John <j@ex.com> 1704067200 +0000"
            >>> ops._extract_tag_date(tag_obj)
            '2024-01-01T00:00:00+00:00'
        """
        # Pattern: tagger ... timestamp timezone
        pattern = re.compile(
            r"^tagger\s+.+?\s+<[^>]+>\s+(?P<timestamp>\d+)\s+(?P<timezone>[+-]\d{4})",
            re.MULTILINE,
        )

        match = pattern.search(tag_object)
        if match:
            timestamp = int(match.group("timestamp"))
            # Convert to ISO 8601 format
            from datetime import datetime
            from datetime import timezone as dt_timezone

            dt = datetime.fromtimestamp(timestamp, tz=dt_timezone.utc)
            iso_date = dt.isoformat()
            logger.debug(f"Extracted tag date: {iso_date}")
            return iso_date

        return None

    def _extract_tag_message(self, tag_object: str) -> str | None:
        """Extract tag message from tag object.

        The tag message is everything after the header lines
        (object, type, tag, tagger) and the blank line.

        Args:
            tag_object: Raw tag object content

        Returns:
            Optional[str]: Tag message or None

        Examples:
            >>> ops = TagOperations()
            >>> tag_obj = '''object abc123
            ... type commit
            ... tag v1.0.0
            ... tagger John <j@ex.com> 123 +0000
            ...
            ... Release version 1.0.0'''
            >>> ops._extract_tag_message(tag_obj).strip()
            'Release version 1.0.0'
        """
        # Split on double newline (header/message separator)
        parts = tag_object.split("\n\n", 1)
        if len(parts) > 1:
            message = parts[1].strip()
            logger.debug(f"Extracted tag message ({len(message)} chars)")
            return message

        return None
