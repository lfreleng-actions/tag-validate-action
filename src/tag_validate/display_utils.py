# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Display utilities for tag validation output.

This module provides shared display formatting functions to ensure
consistent output across different commands and workflows.
"""

from typing import Optional


def format_user_details(
    username: Optional[str] = None,
    email: Optional[str] = None,
    name: Optional[str] = None,
) -> list[str]:
    """
    Format user details as a list of bullet points.

    Args:
        username: User's username
        email: User's email address
        name: User's display name

    Returns:
        List of formatted strings for user details

    Example:
        >>> lines = format_user_details(
        ...     username="octocat",
        ...     email="octocat@github.com",
        ...     name="The Octocat"
        ... )
        >>> for line in lines:
        ...     print(line)
        • Username: octocat
        • Email: octocat@github.com
        • Name: The Octocat
    """
    lines = []
    if username:
        lines.append(f"  • Username: {username}")
    if email:
        lines.append(f"  • Email: {email}")
    if name:
        lines.append(f"  • Name: {name}")
    return lines


def should_display_server(
    service: str,
    server: Optional[str] = None,
) -> bool:
    """
    Determine if server information should be displayed.

    For Gerrit: Always show server (required)
    For GitHub: Only show if not github.com (i.e., GitHub Enterprise)

    Args:
        service: Service name ("github" or "gerrit")
        server: Server hostname

    Returns:
        True if server should be displayed, False otherwise

    Example:
        >>> should_display_server("gerrit", "gerrit.onap.org")
        True
        >>> should_display_server("github", "github.com")
        False
        >>> should_display_server("github", "github.enterprise.com")
        True
    """
    if not server:
        return False

    if service == "gerrit":
        return True
    elif service == "github":
        return server != "github.com"

    return False


def format_server_display(
    service: str,
    server: Optional[str] = None,
) -> Optional[str]:
    """
    Format server display string if server should be shown.

    Args:
        service: Service name ("github" or "gerrit")
        server: Server hostname

    Returns:
        Formatted server string or None if server should not be displayed

    Example:
        >>> format_server_display("gerrit", "gerrit.onap.org")
        'Gerrit Server: gerrit.onap.org'
        >>> format_server_display("github", "github.com")
        None
        >>> format_server_display("github", "github.enterprise.com")
        'GitHub Server: github.enterprise.com'
    """
    if not should_display_server(service, server):
        return None

    service_name = "Gerrit" if service == "gerrit" else "GitHub"
    return f"{service_name} Server: {server}"
