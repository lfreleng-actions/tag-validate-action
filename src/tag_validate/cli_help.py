# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Help text for the tag-validate command-line interface.

Typer renders these strings identically to command docstrings; they
live here so the command declarations in ``cli.py`` stay readable.
"""

# Help text for the ``gerrit`` command.
GERRIT_HELP = """
    Verify if a specific GPG key ID or SSH fingerprint is registered on Gerrit.

    This command directly checks if a key is registered to a Gerrit user
    without needing to extract it from a tag signature.

    The key type is auto-detected by default, but can be explicitly specified
    with --type if needed.

    Either --server or --github-org must be provided, or both can be used
    where --server takes precedence.

    Authentication is optional but required for Gerrit servers that restrict
    public access to user key information.

    Credentials are loaded in this order:
    1. CLI options: --gerrit-username and --gerrit-password
    2. .netrc file (if not disabled with --no-netrc)
    3. Environment variables: GERRIT_USERNAME and GERRIT_PASSWORD

    .netrc search order: ./.netrc, ~/.netrc, ~/_netrc (Windows)
    Use --netrc-file to specify an explicit path.

    The password must be a Gerrit HTTP password generated from
    your account settings, not your SSO/LDAP password.

    Examples:
        # Auto-detect key type (GPG) with explicit server
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server gerrit.onap.org

        # Auto-detect key type (SSH) with GitHub org discovery
        tag-validate gerrit "SHA256:abc123..." --owner user@example.com --github-org onap

        # With authentication (using environment variables)
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server gerrit.onap.org

        # With authentication (using CLI options)
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server gerrit.onap.org           --gerrit-username myuser --gerrit-password myHTTPpassword

        # Explicitly specify type with server URL
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server https://gerrit.example.com --type gpg
    """


# Help text for the ``github`` command.
GITHUB_HELP = """
    Verify if a specific GPG key ID or SSH fingerprint is registered on GitHub.

    This command directly checks if a key is registered to a GitHub user
    without needing to extract it from a tag signature.

    The key type is auto-detected by default, but can be explicitly specified
    with --type if needed.

    Examples:
        # Auto-detect key type (GPG) with username
        tag-validate github FCE8AAABF53080F6 --owner torvalds --token $GITHUB_TOKEN

        # Auto-detect key type (SSH) with email address
        tag-validate github "ssh-ed25519 AAAAC3NzaC1..." --owner user@example.com --token $GITHUB_TOKEN

        # Explicitly specify type with username
        tag-validate github FCE8AAABF53080F6 --owner torvalds --type gpg --token $GITHUB_TOKEN

        # GitHub Enterprise Server
        tag-validate github FCE8AAABF53080F6 --owner torvalds --token $GITHUB_TOKEN --api-url https://github.example.com/api/v3
    """


# Help text for the ``detect`` command.
DETECT_HELP = """
    Detect and display signature information for a Git tag.

    This command analyzes a tag and reports:
    - Signature type (GPG, SSH, or unsigned)
    - Signature validity
    - Key ID and fingerprint
    - Signer information

    Example:
        tag-validate detect v1.0.0
    """


# Help text for the ``validate`` command.
VALIDATE_HELP = """
    Validate a version string against SemVer or CalVer patterns.

    This command validates version strings and reports:
    - Version type (SemVer or CalVer)
    - Validity according to the specification
    - Parsed components (major, minor, patch, etc.)
    - Whether it's a development version

    Examples:
        tag-validate validate v1.2.3
        tag-validate validate 2024.01.15
        tag-validate validate v1.0.0-beta --require-type semver
        tag-validate validate 1.2.3 --strict-semver
    """


# Help text for the ``verify`` command.
VERIFY_HELP = """
    Perform complete tag validation workflow.

    This command performs comprehensive tag validation including:
    - Version format validation (SemVer or CalVer)
    - Signature detection and verification
    - Optional GitHub key verification
    - Development version detection

    Supports both local and remote tags:
    - Local tag in current directory: tag-validate verify-tag v1.2.3
    - Local tag in different repository: tag-validate verify-tag v1.2.3 --path /path/to/repo
    - Remote tag: tag-validate verify-tag owner/repo@v1.2.3

    GitHub Username Auto-Detection:
    When --require-github is used without --owner, the tool will automatically
    detect the GitHub username from the tagger's email address by searching GitHub's
    commit history. This makes validation easier as you don't need to manually
    specify the owner.

    Examples:
        # Validate local tag
        tag-validate verify v1.2.3

        # Require SemVer and signature
        tag-validate verify v1.2.3 --require-type semver --require-signed true

        # Verify GitHub key (auto-detects owner from tagger email)
        tag-validate verify v1.2.3 --require-github --token $GITHUB_TOKEN

        # Validate remote tag with explicit owner (username)
        tag-validate verify torvalds/linux@v6.0           --require-github --owner torvalds --token $GITHUB_TOKEN

        # Validate with email address
        tag-validate verify v1.2.3 --require-github --owner user@example.com --token $GITHUB_TOKEN

        # Require tag signed by specific GitHub user(s)
        tag-validate verify v1.2.3 --require-owner octocat --token $GITHUB_TOKEN

        # Require tag signed by one of multiple owners
        tag-validate verify v1.2.3 --require-owner "octocat,monalisa" --token $GITHUB_TOKEN

        # Require tag signed by specific email address(es)
        tag-validate verify v1.2.3 --require-owner user@example.com --token $GITHUB_TOKEN

        # Mixed usernames and emails
        tag-validate verify v1.2.3 --require-owner "octocat,user@example.com" --token $GITHUB_TOKEN

        # Reject development versions
        tag-validate verify v1.2.3-beta --reject-development

        # Only verify signature and GitHub key (skip version validation)
        tag-validate verify my-tag --skip-version-validation           --require-github --owner user@example.com --token $GITHUB_TOKEN
    """
