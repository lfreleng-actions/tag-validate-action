# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Typer option definitions for the tag-oriented tag-validate commands.

Typer parameter declarations live here so the command functions in
``cli.py`` remain short; each constant is the exact ``typer.Option`` or
``typer.Argument`` object used by the corresponding CLI parameter.
"""

import typer

# --- validate ---

VALIDATE_VERSION_STRING = typer.Argument(
    ..., help="Version string to validate (e.g., v1.2.3, 2024.01.15)"
)

VALIDATE_REQUIRE_TYPE = typer.Option(
    None,
    "--require-type",
    "-t",
    help="Require specific version type: semver, calver (comma or space-separated for multiple)",
)

VALIDATE_ALLOW_PREFIX = typer.Option(
    True,
    "--allow-prefix/--no-prefix",
    help="Allow 'v' prefix on version strings",
)

VALIDATE_STRICT_SEMVER = typer.Option(
    False,
    "--strict-semver",
    help="Enforce strict SemVer compliance (no prefix, exact format)",
)

VALIDATE_JSON_OUTPUT = typer.Option(
    False,
    "--json",
    "-j",
    help="Output results as JSON",
)

VALIDATE_JSON_FILE = typer.Option(
    None,
    "--json-file",
    help="Write JSON output to file while showing rich console output",
)


# --- verify ---

VERIFY_TAG_LOCATION = typer.Argument(
    ..., help="Tag location: tag name, or owner/repo@tag for remote"
)

VERIFY_REPO_PATH = typer.Option(
    ".",
    "--path",
    "-p",
    help="Path to local Git repository (default: current directory)",
    exists=True,
    file_okay=False,
    dir_okay=True,
)

VERIFY_REQUIRE_TYPE = typer.Option(
    None,
    "--require-type",
    "-t",
    help="Require specific version type: semver, calver (comma or space-separated for multiple)",
)

VERIFY_REQUIRE_SIGNED = typer.Option(
    None,
    "--require-signed",
    help="Require tag signature. Values: gpg, ssh, gpg-unverifiable, unsigned (comma or space-separated for multiple). Omit for no requirement.",
)

VERIFY_REQUIRE_GITHUB = typer.Option(
    False,
    "--require-github",
    help="Verify signing key is registered on GitHub",
)

VERIFY_REQUIRE_GERRIT = typer.Option(
    None,
    "--require-gerrit",
    help="Verify signing key is registered on Gerrit. Requires a value: 'true' for auto-discovery from GitHub org (pattern: gerrit.<org>.org), or a specific Gerrit server hostname (e.g. 'gerrit.onap.org'). Example: --require-gerrit gerrit.onap.org",
)

VERIFY_OWNER = typer.Option(
    None,
    "--owner",
    "-o",
    help="GitHub username or email address for key verification (optional, auto-detected from tagger email if not provided)",
)

VERIFY_REQUIRE_OWNER = typer.Option(
    None,
    "--require-owner",
    help="GitHub username(s) or email address(es) that must own the signing key (comma or space-separated for multiple). Implies --require-github.",
)

VERIFY_GITHUB_TOKEN = typer.Option(
    None,
    "--token",
    envvar="GITHUB_TOKEN",
    help="GitHub API token (or set GITHUB_TOKEN env var)",
)

VERIFY_GERRIT_USERNAME = typer.Option(
    None,
    "--gerrit-username",
    help="Gerrit username for HTTP authentication (priority: CLI > .netrc > GERRIT_USERNAME env var)",
)

VERIFY_GERRIT_PASSWORD = typer.Option(
    None,
    "--gerrit-password",
    help="Gerrit HTTP password for authentication (priority: CLI > .netrc > GERRIT_PASSWORD env var)",
)

VERIFY_NO_NETRC = typer.Option(
    False,
    "--no-netrc",
    help="Disable .netrc credential lookup for Gerrit authentication",
)

VERIFY_NETRC_FILE = typer.Option(
    None,
    "--netrc-file",
    help="Explicit path to .netrc file for Gerrit credentials",
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
)

VERIFY_NETRC_OPTIONAL = typer.Option(
    True,
    "--netrc-optional/--netrc-required",
    help="Whether to fail if .netrc file is not found (default: optional)",
)

VERIFY_REJECT_DEVELOPMENT = typer.Option(
    False,
    "--reject-development",
    help="Reject development versions (alpha, beta, rc, etc.)",
)

VERIFY_ENFORCE_INCREMENT = typer.Option(
    False,
    "--enforce-increment",
    help=(
        "Require the tag to be strictly greater than the highest "
        "existing comparable tag in the repository (prevents "
        "re-releasing older versions)"
    ),
)

VERIFY_REQUIRE_BRANCH = typer.Option(
    None,
    "--require-branch",
    help=(
        "Require the tag commit to be reachable from this branch. "
        "Pass a branch name, or 'true' to auto-detect the "
        "repository default branch."
    ),
)

VERIFY_REQUIRE_RECENT = typer.Option(
    None,
    "--require-recent",
    help=(
        "Require the tag to have been created recently. Pass "
        "'true' for the default 3-minute window, or a number of "
        "minutes. Requires an annotated (or signed) tag."
    ),
)

VERIFY_REQUIRE_LATEST = typer.Option(
    False,
    "--require-latest",
    help=(
        "Require the tag commit to be the current tip of the "
        "target branch (--require-branch when set, otherwise the "
        "repository default branch)"
    ),
)

VERIFY_SKIP_VERSION_VALIDATION = typer.Option(
    False,
    "--skip-version-validation",
    help="Skip version format validation (only check signature)",
)

VERIFY_PERMIT_MISSING = typer.Option(
    False,
    "--permit-missing",
    help="Allow missing tags without error (returns success with minimal info)",
)

VERIFY_JSON_OUTPUT = typer.Option(
    False,
    "--json",
    "-j",
    help="Output results as JSON",
)

VERIFY_JSON_FILE = typer.Option(
    None,
    "--json-file",
    help="Write JSON output to file while showing rich console output",
)

VERIFY_GITHUB_STEP_SUMMARY = typer.Option(
    True,
    "--github-step-summary/--no-github-step-summary",
    help="Write validation summary to GITHUB_STEP_SUMMARY (only in GitHub Actions)",
)
