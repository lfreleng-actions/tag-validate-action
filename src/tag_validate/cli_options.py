# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Typer option definitions for the key-oriented tag-validate commands.

Typer parameter declarations live here so the command functions in
``cli.py`` remain short; each constant is the exact ``typer.Option`` or
``typer.Argument`` object used by the corresponding CLI parameter.
"""

import typer

from . import __version__
from .cli_runtime import console


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        console.print(f"tag-validate version {__version__}")
        raise typer.Exit()


# --- main ---

MAIN_VERSION = typer.Option(
    None,
    "--version",
    "-v",
    help="Show version and exit",
    callback=version_callback,
    is_eager=True,
)

MAIN_VERBOSE = typer.Option(
    False,
    "--verbose",
    "-V",
    help="Enable verbose logging",
)

MAIN_DEBUG = typer.Option(
    False,
    "--debug",
    hidden=True,
)

MAIN_QUIET = typer.Option(
    False,
    "--quiet",
    "-q",
    help="Suppress all output except errors",
)


# --- verify_gerrit ---

GERRIT_KEY_ID = typer.Argument(
    ...,
    help="GPG key ID (e.g., 'FCE8AAABF53080F6') or SSH fingerprint (e.g., 'SHA256:...')",
)

GERRIT_OWNER = typer.Option(
    ...,
    "--owner",
    "-o",
    help="Gerrit username or email address to verify key against",
)

GERRIT_KEY_TYPE = typer.Option(
    "auto",
    "--type",
    "-t",
    help="Key type: 'gpg', 'ssh', or 'auto' (default: auto-detect)",
)

GERRIT_SERVER = typer.Option(
    None,
    "--server",
    "-s",
    # aislop-ignore-next-line ai-slop/hardcoded-url -- example URL in CLI help text
    help="Gerrit server hostname or URL (e.g., 'gerrit.onap.org' or 'https://gerrit.example.com')",
)

GERRIT_GITHUB_ORG = typer.Option(
    None,
    "--github-org",
    "-g",
    help="GitHub organization for server auto-discovery (e.g., 'onap' -> 'gerrit.onap.org')",
)

GERRIT_GERRIT_USERNAME = typer.Option(
    None,
    "--gerrit-username",
    help="Gerrit username for HTTP authentication (priority: CLI > .netrc > GERRIT_USERNAME env var)",
)

GERRIT_GERRIT_PASSWORD = typer.Option(
    None,
    "--gerrit-password",
    help="Gerrit HTTP password for authentication (priority: CLI > .netrc > GERRIT_PASSWORD env var)",
)

GERRIT_NO_NETRC = typer.Option(
    False,
    "--no-netrc",
    help="Disable .netrc credential lookup for Gerrit authentication",
)

GERRIT_NETRC_FILE = typer.Option(
    None,
    "--netrc-file",
    help="Explicit path to .netrc file for Gerrit credentials",
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
)

GERRIT_NETRC_OPTIONAL = typer.Option(
    True,
    "--netrc-optional/--netrc-required",
    help="Whether to fail if .netrc file is not found (default: optional)",
)

GERRIT_JSON_OUTPUT = typer.Option(
    False,
    "--json",
    "-j",
    help="Output results as JSON",
)

GERRIT_TEST_MODE = typer.Option(
    False,
    "--test-mode",
    help="Test key parsing and normalization without making Gerrit API calls",
    hidden=True,
)


# --- verify_github ---

GITHUB_KEY_ID = typer.Argument(
    ...,
    help="GPG key ID (e.g., 'FCE8AAABF53080F6') or SSH fingerprint (e.g., 'SHA256:...')",
)

GITHUB_OWNER = typer.Option(
    ...,
    "--owner",
    "-o",
    help="GitHub username or email address to verify key against",
)

GITHUB_KEY_TYPE = typer.Option(
    "auto",
    "--type",
    "-t",
    help="Key type: 'gpg', 'ssh', or 'auto' (default: auto-detect)",
)

GITHUB_GITHUB_TOKEN = typer.Option(
    None,
    "--token",
    envvar="GITHUB_TOKEN",
    help="GitHub API token (or set GITHUB_TOKEN env var)",
)

GITHUB_JSON_OUTPUT = typer.Option(
    False,
    "--json",
    "-j",
    help="Output results as JSON",
)

GITHUB_NO_SUBKEYS = typer.Option(
    False,
    "--no-subkeys",
    help="Disable GPG subkey verification (only check primary keys)",
)

GITHUB_API_URL = typer.Option(
    "https://api.github.com",
    "--api-url",
    help="GitHub API base URL (for GitHub Enterprise Server)",
)

GITHUB_GRAPHQL_URL = typer.Option(
    "https://api.github.com/graphql",
    "--graphql-url",
    help="GitHub GraphQL endpoint URL (for GitHub Enterprise Server)",
)

GITHUB_TEST_MODE = typer.Option(
    False,
    "--test-mode",
    help="Test key parsing and normalization without making GitHub API calls",
    hidden=True,
)


# --- detect ---

DETECT_TAG_NAME = typer.Argument(..., help="Name of the Git tag to analyze")

DETECT_REPO_PATH = typer.Option(
    ".",
    "--repo-path",
    "-r",
    help="Path to the Git repository",
    exists=True,
    file_okay=False,
    dir_okay=True,
)

DETECT_JSON_OUTPUT = typer.Option(
    False,
    "--json",
    "-j",
    help="Output results as JSON",
)
