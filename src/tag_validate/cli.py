# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Command-line interface for tag-validate.

This module provides a Typer-based CLI for validating Git tags,
verifying cryptographic signatures, and checking key registration on GitHub.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.logging import RichHandler

from . import __version__
from .gerrit_keys import GerritKeysClient
from .github_keys import GitHubKeysClient
from .github_summary import write_validation_summary
from .models import KeyVerificationResult, ValidationConfig
from .signature import SignatureDetector, SignatureDetectionError
from .validation import TagValidator
from .workflow import ValidationWorkflow
from .display_utils import format_user_details, format_server_display

# Exit codes
EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILED = 1
EXIT_MISSING_TOKEN = 2
EXIT_INVALID_INPUT = 3
EXIT_UNEXPECTED_ERROR = 4
EXIT_MISSING_CREDENTIALS = 5  # Required credentials not provided (Gerrit)
EXIT_AUTH_FAILED = 6  # Authentication failed (invalid credentials)


class CustomTyper(typer.Typer):
    """Custom Typer class that shows version in help."""

    def __call__(self, *args, **kwargs):
        # Check if help is being requested
        if "--help" in sys.argv or "-h" in sys.argv:
            console = Console()
            console.print(f"🏷️  tag-validate version {__version__}")
        return super().__call__(*args, **kwargs)


# Initialize Typer app
app = CustomTyper(
    name="tag-validate",
    help="Validate Git tags with signature verification and GitHub key checking",
    add_completion=False,
)


def _process_global_options():
    """Process global options like --verbose and --debug from command line args."""
    import sys
    verbose = False
    debug = False

    # Check for global options and remove them from sys.argv
    new_argv = []
    i = 0
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ['--verbose', '-V']:
            verbose = True
        elif arg == '--debug':
            debug = True
        else:
            new_argv.append(arg)
        i += 1

    # Update sys.argv
    sys.argv[:] = new_argv

    return verbose, debug


def _normalize_ssh_fingerprint(key_id: str) -> str:
    """Normalize SSH key fingerprint by removing algorithm prefix and validate format.

    Args:
        key_id: SSH key fingerprint that may have algorithm prefix

    Returns:
        Normalized fingerprint (SHA256:... or original if not SSH)

    Raises:
        ValueError: If fingerprint format is invalid
    """
    import re
    import base64

    # Remove common SSH algorithm prefixes
    key_lower = key_id.lower()
    normalized = key_id

    if "sha256:" in key_lower:
        # Extract just the SHA256: part
        sha_index = key_lower.find("sha256:")
        normalized = key_id[sha_index:]

        # Validate SHA256 format: SHA256:base64_string
        sha256_pattern = r'^SHA256:([A-Za-z0-9+/]{43}=?|[A-Za-z0-9+/]{44})$'
        if not re.match(sha256_pattern, normalized, re.IGNORECASE):
            # Check if it's just empty hash
            if normalized.upper() == "SHA256:":
                raise ValueError("SHA256 fingerprint cannot be empty")
            # Check if it contains invalid Base64 characters
            hash_part = normalized[7:]  # Remove "SHA256:" prefix
            if not hash_part:
                raise ValueError("SHA256 fingerprint cannot be empty")
            try:
                # Validate Base64 format (SHA256 hash should be 32 bytes = 43-44 chars in base64)
                decoded = base64.b64decode(hash_part + '==', validate=True)  # Add padding for validation
                if len(decoded) != 32:
                    raise ValueError(f"SHA256 fingerprint has invalid length: expected 32 bytes, got {len(decoded)}")
            except Exception:
                raise ValueError(f"SHA256 fingerprint contains invalid Base64 characters: {hash_part}")

    elif "md5:" in key_lower:
        # Extract just the MD5: part
        md5_index = key_lower.find("md5:")
        normalized = key_id[md5_index:]

        # Validate MD5 format: MD5:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
        md5_pattern = r'^MD5:([0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}$'
        if not re.match(md5_pattern, normalized, re.IGNORECASE):
            # Check if it's just empty hash
            if normalized.upper() == "MD5:":
                raise ValueError("MD5 fingerprint cannot be empty")
            # More detailed validation
            hash_part = normalized[4:]  # Remove "MD5:" prefix
            if not hash_part:
                raise ValueError("MD5 fingerprint cannot be empty")
            # Should be exactly 47 characters: 16 hex pairs separated by colons
            if len(hash_part) != 47:
                raise ValueError(f"MD5 fingerprint has invalid length: expected 47 characters, got {len(hash_part)}")
            # Check format with colons
            hex_parts = hash_part.split(':')
            if len(hex_parts) != 16:
                raise ValueError(f"MD5 fingerprint should have 16 hex pairs separated by colons, got {len(hex_parts)}")
            # Validate each hex pair
            for i, part in enumerate(hex_parts):
                if len(part) != 2:
                    raise ValueError(f"MD5 fingerprint hex pair {i+1} has invalid length: expected 2 characters, got {len(part)}")
                if not re.match(r'^[0-9a-fA-F]{2}$', part):
                    raise ValueError(f"MD5 fingerprint contains invalid hex characters in pair {i+1}: {part}")

    return normalized


async def _resolve_owner_to_username(owner: str, github_token: Optional[str] = None) -> str:
    """Resolve owner (email or username) to GitHub username.

    Args:
        owner: GitHub username or email address
        github_token: GitHub API token for email lookup

    Returns:
        GitHub username

    Raises:
        ValueError: If email lookup fails or no token provided for email
    """
    # If it contains @, treat as email and lookup username
    if "@" in owner:
        if not github_token:
            raise ValueError("GitHub token is required for email-to-username lookup. Set GITHUB_TOKEN environment variable or pass --token")

        from .github_keys import GitHubKeysClient
        async with GitHubKeysClient(token=github_token) as client:
            username = await client.lookup_username_by_email(owner)
            if not username:
                raise ValueError(f"Could not find GitHub username for email: {owner}")
            return username
    else:
        # Already a username
        return owner

# Initialize Rich console (will be reconfigured for JSON output if needed)
console = Console()

# Tag location format examples (used in error messages)
TAG_LOCATION_FORMATS = {
    "local": "v1.0.0 (local tag)",
    "remote": "owner/repo@v1.0.0 (remote tag)",
    "path": "./path/to/repo/v1.0.0 (local repository path)",
}

TAG_LOCATION_FORMAT_EXAMPLES = [
    (
        "Expected formats: "
        "'v1.0.0' (local), "
        "'owner/repo@v1.0.0' (remote), "
        "or './path/to/repo/v1.0.0' (local repository path)"
    )
]

# Configure logging (will be suppressed for JSON output)
logging.basicConfig(
    level=logging.WARNING,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
logger = logging.getLogger("tag_validate")

# Process global options after logger is defined
verbose, debug = _process_global_options()
if verbose or debug:
    logging.getLogger().setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)

# Suppress verbose HTTP logs from httpx (used by dependamerge)
logging.getLogger("httpx").setLevel(logging.WARNING)


def parse_multi_value_option(value: Optional[str]) -> list[str]:
    """Parse comma or space-separated values from an option.

    Args:
        value: Option value string (e.g., "gpg,ssh" or "gpg ssh")

    Returns:
        List of parsed values (lowercased and stripped)

    Examples:
        >>> parse_multi_value_option("gpg,ssh")
        ['gpg', 'ssh']
        >>> parse_multi_value_option("gpg ssh")
        ['gpg', 'ssh']
        >>> parse_multi_value_option(None)
        []
    """
    if not value:
        return []

    # Parse comma or space-separated values
    if ',' in value:
        values = [v.strip().lower() for v in value.split(',') if v.strip()]
    else:
        values = [v.lower() for v in value.split() if v]

    return values


def validate_version_types(type_list: list[str]) -> None:
    """Validate version type names.

    Args:
        type_list: List of version type names

    Raises:
        typer.Exit: If invalid types are found
    """
    valid_types = {'semver', 'calver', 'both', 'none'}
    invalid_types = set(type_list) - valid_types

    if invalid_types:
        console.print(f"[red]Invalid version type(s): {', '.join(invalid_types)}[/red]")
        console.print("Valid types: semver, calver, both, none")
        raise typer.Exit(EXIT_INVALID_INPUT)


def validate_signature_types(sig_list: list[str]) -> None:
    """Validate signature type names and combinations.

    Args:
        sig_list: List of signature type names

    Raises:
        typer.Exit: If invalid types or combinations are found
    """
    valid_signature_types = {'gpg', 'ssh', 'gpg-unverifiable', 'unsigned'}
    invalid_types = set(sig_list) - valid_signature_types

    if invalid_types:
        console.print(f"[red]Invalid signature type(s): {', '.join(invalid_types)}[/red]")
        console.print("Valid types: gpg, ssh, gpg-unverifiable, unsigned")
        raise typer.Exit(EXIT_INVALID_INPUT)

    # Check for invalid combinations
    if 'unsigned' in sig_list and len(sig_list) > 1:
        console.print("[red]Cannot combine 'unsigned' with other signature types[/red]")
        raise typer.Exit(EXIT_INVALID_INPUT)


def check_version_type_match(version_type: str, required_types: list[str]) -> bool:
    """Check if version type matches required types.

    Handles "both" type which satisfies any semver or calver requirement.
    Handles "none" requirement which accepts any type.
    Handles "both" in requirements which accepts semver OR calver.

    Args:
        version_type: Detected version type (semver, calver, both, other)
        required_types: List of required types

    Returns:
        True if version type matches requirements
    """
    if not required_types:
        return True

    # "none" in requirements means accept any type
    if "none" in required_types:
        return True

    # "both" detected type satisfies any semver or calver requirement
    if version_type == "both":
        return True

    # "both" in requirements means accept semver OR calver (or both)
    if "both" in required_types and version_type in ("semver", "calver", "both"):
        return True

    # Single type must be in the required list
    return version_type in required_types


def _suppress_logging_for_json():
    """Suppress all logging output for JSON mode."""
    # Disable all logging
    logging.disable(logging.CRITICAL)
    # Also suppress the root logger
    logging.getLogger().setLevel(logging.CRITICAL)
    logging.getLogger("tag_validate").setLevel(logging.CRITICAL)


def _detect_key_type(key_id: str) -> str:
    """
    Detect key type (GPG or SSH) from the key string.

    Args:
        key_id: Key ID or fingerprint string

    Returns:
        "gpg", "ssh", or "unknown"
    """
    key_lower = key_id.lower().strip()

    # SSH key patterns
    ssh_prefixes = [
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ]

    # Check if it starts with SSH key type
    for prefix in ssh_prefixes:
        if key_lower.startswith(prefix):
            return "ssh"

    # Check for SSH fingerprint format (SHA256:... or MD5:...)
    if key_lower.startswith("sha256:") or key_lower.startswith("md5:"):
        return "ssh"

    # Check for SSH fingerprint with algorithm prefix (ECDSA:SHA256:, RSA:SHA256:, etc.)
    if "sha256:" in key_lower or "md5:" in key_lower:
        return "ssh"

    # GPG key patterns - typically hex strings
    # Remove spaces and check if it's a valid hex string
    key_clean = key_id.replace(" ", "").replace(":", "")

    # GPG key IDs are typically 8, 16, or 40 hex characters
    if len(key_clean) in [8, 16, 40] and all(c in "0123456789ABCDEFabcdef" for c in key_clean):
        return "gpg"

    # If we can't determine, return unknown
    return "unknown"


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        console.print(f"tag-validate version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True,
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-V",
        help="Enable verbose logging",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        hidden=True,
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress all output except errors",
    ),
):
    """
    Tag validation tool with cryptographic signature verification.
    """
    # Check if --json flag is present in any command
    # This must be done early to suppress logging before commands execute
    import sys
    if '--json' in sys.argv or '-j' in sys.argv:
        _suppress_logging_for_json()
        return

    if verbose or debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)
        logger.setLevel(logging.ERROR)




@app.command(name="gerrit")
def verify_gerrit(
    key_id: str = typer.Argument(
        ...,
        help="GPG key ID (e.g., 'FCE8AAABF53080F6') or SSH fingerprint (e.g., 'SHA256:...')"
    ),
    owner: str = typer.Option(
        ...,
        "--owner",
        "-o",
        help="Gerrit username or email address to verify key against",
    ),
    key_type: str = typer.Option(
        "auto",
        "--type",
        "-t",
        help="Key type: 'gpg', 'ssh', or 'auto' (default: auto-detect)",
    ),
    server: Optional[str] = typer.Option(
        None,
        "--server",
        "-s",
        help="Gerrit server hostname or URL (e.g., 'gerrit.onap.org' or 'https://gerrit.example.com')",
    ),
    github_org: Optional[str] = typer.Option(
        None,
        "--github-org",
        "-g",
        help="GitHub organization for server auto-discovery (e.g., 'onap' -> 'gerrit.onap.org')",
    ),
    gerrit_username: Optional[str] = typer.Option(
        None,
        "--gerrit-username",
        envvar="GERRIT_USERNAME",
        help="Gerrit username for HTTP authentication (can also use GERRIT_USERNAME env var)",
    ),
    gerrit_password: Optional[str] = typer.Option(
        None,
        "--gerrit-password",
        envvar="GERRIT_PASSWORD",
        help="Gerrit HTTP password for authentication (can also use GERRIT_PASSWORD env var)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON",
    ),
    test_mode: bool = typer.Option(
        False,
        "--test-mode",
        help="Test key parsing and normalization without making Gerrit API calls",
        hidden=True,
    ),
):
    """
    Verify if a specific GPG key ID or SSH fingerprint is registered on Gerrit.

    This command directly checks if a key is registered to a Gerrit user
    without needing to extract it from a tag signature.

    The key type is auto-detected by default, but can be explicitly specified
    with --type if needed.

    Either --server or --github-org must be provided, or both can be used
    where --server takes precedence.

    Authentication is optional but required for Gerrit servers that restrict
    public access to user key information. Use --gerrit-username and
    --gerrit-password, or set GERRIT_USERNAME and GERRIT_PASSWORD environment
    variables. The password must be a Gerrit HTTP password generated from
    your account settings, not your SSO/LDAP password.

    Examples:
        # Auto-detect key type (GPG) with explicit server
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server gerrit.onap.org

        # Auto-detect key type (SSH) with GitHub org discovery
        tag-validate gerrit "SHA256:abc123..." --owner user@example.com --github-org onap

        # With authentication (using environment variables)
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server gerrit.onap.org

        # With authentication (using CLI options)
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server gerrit.onap.org \
          --gerrit-username myuser --gerrit-password myHTTPpassword

        # Explicitly specify type with server URL
        tag-validate gerrit FCE8AAABF53080F6 --owner user@example.com --server https://gerrit.example.com --type gpg
    """

    # Handle test mode first, before any other validations
    if test_mode:
        async def _test_mode():
            try:
                # Suppress ALL logs when in test mode
                _suppress_logging_for_json()

                # Auto-detect or validate key type
                detected_type = key_type
                if key_type == "auto":
                    detected_type = _detect_key_type(key_id)
                    if detected_type == "unknown":
                        error_msg = f"Could not auto-detect key type from: {key_id[:50]}... Please specify --type gpg or --type ssh"
                        if json_output:
                            console.print_json(data={"success": False, "error": error_msg})
                        else:
                            console.print(f"[red]❌ {error_msg}[/red]")
                        raise typer.Exit(1)
                elif key_type not in ["gpg", "ssh"]:
                    error_msg = f"Invalid key type: {key_type}. Must be 'gpg', 'ssh', or 'auto'"
                    if json_output:
                        console.print_json(data={"success": False, "error": error_msg})
                    else:
                        console.print(f"[red]❌ {error_msg}[/red]")
                    raise typer.Exit(1)

                # Test key parsing/normalization
                if detected_type == "ssh":
                    try:
                        normalized_fingerprint = _normalize_ssh_fingerprint(key_id)
                        if json_output:
                            result = {
                                "test_mode": True,
                                "key_type": detected_type,
                                "original_key": key_id,
                                "normalized_key": normalized_fingerprint,
                                "success": True,
                            }
                            console.print_json(data=result)
                        else:
                            console.print(f"[green]✅ SSH key parsing successful[/green]")
                            console.print(f"Original: {key_id}")
                            console.print(f"Normalized: {normalized_fingerprint}")
                    except Exception as e:
                        error_msg = f"SSH key parsing failed: {e}"
                        if json_output:
                            console.print_json(data={"test_mode": True, "success": False, "error": error_msg})
                        else:
                            console.print(f"[red]❌ {error_msg}[/red]")
                        raise typer.Exit(1)
                else:  # GPG
                    if json_output:
                        result = {
                            "test_mode": True,
                            "key_type": detected_type,
                            "original_key": key_id,
                            "normalized_key": key_id.upper().replace("0X", ""),
                            "success": True,
                        }
                        console.print_json(data=result)
                    else:
                        console.print(f"[green]✅ GPG key parsing successful[/green]")
                        console.print(f"Original: {key_id}")
                        console.print(f"Normalized: {key_id.upper().replace('0X', '')}")

            except typer.Exit:
                raise
            except Exception as e:
                if json_output:
                    console.print_json(data={"test_mode": True, "success": False, "error": str(e)})
                else:
                    console.print(f"[red]❌ Test failed: {e}[/red]")
                raise typer.Exit(1)

        # Run test mode and return
        asyncio.run(_test_mode())
        return

    async def _verify():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Validate server/github_org parameters
            if not server and not github_org:
                error_msg = "Either --server or --github-org must be provided"
                if json_output:
                    console.print_json(data={"success": False, "error": error_msg})
                else:
                    console.print(f"[red]❌ {error_msg}[/red]")
                raise typer.Exit(EXIT_INVALID_INPUT)

            # Auto-detect or validate key type
            detected_type = key_type
            if key_type == "auto":
                detected_type = _detect_key_type(key_id)
                if detected_type == "unknown":
                    error_msg = f"Could not auto-detect key type from: {key_id[:50]}... Please specify --type gpg or --type ssh"
                    if json_output:
                        console.print_json(data={"success": False, "error": error_msg})
                    else:
                        console.print(f"[red]❌ {error_msg}[/red]")
                    raise typer.Exit(1)
            elif key_type not in ["gpg", "ssh"]:
                error_msg = f"Invalid key type: {key_type}. Must be 'gpg', 'ssh', or 'auto'"
                if json_output:
                    console.print_json(data={"success": False, "error": error_msg})
                else:
                    console.print(f"[red]❌ {error_msg}[/red]")
                raise typer.Exit(1)

            # Verify key on Gerrit
            account = None
            verification = None

            if json_output:
                async with GerritKeysClient(
                    server=server,
                    github_org=github_org,
                    username=gerrit_username,
                    password=gerrit_password,
                ) as client:
                    # Look up account by email or username
                    try:
                        if "@" in owner:
                            account = await client.lookup_account_by_email(owner)
                        else:
                            account = await client.lookup_account_by_username(owner)

                        if account is None:
                            error_msg = f"Gerrit account not found for '{owner}'"
                            console.print_json(data={"success": False, "error": error_msg})
                            raise typer.Exit(EXIT_INVALID_INPUT)
                    except Exception as e:
                        error_msg = f"Failed to find Gerrit account for '{owner}': {e}"
                        console.print_json(data={"success": False, "error": error_msg})
                        raise typer.Exit(EXIT_INVALID_INPUT)

                    # Verify the key
                    if detected_type == "gpg":
                        verification = await client.verify_gpg_key_registered(
                            account_id=account.account_id,
                            key_id=key_id,
                        )
                    else:  # ssh
                        normalized_fingerprint = _normalize_ssh_fingerprint(key_id)
                        verification = await client.verify_ssh_key_registered(
                            account_id=account.account_id,
                            fingerprint=normalized_fingerprint,
                        )
            else:
                with console.status("[bold green]Verifying key on Gerrit..."):
                    async with GerritKeysClient(
                        server=server,
                        github_org=github_org,
                        username=gerrit_username,
                        password=gerrit_password,
                    ) as client:
                        # Look up account by email or username
                        try:
                            if "@" in owner:
                                account = await client.lookup_account_by_email(owner)
                            else:
                                account = await client.lookup_account_by_username(owner)

                            if account is None:
                                error_msg = f"Gerrit account not found for '{owner}'"
                                console.print(f"[red]❌ {error_msg}[/red]")
                                raise typer.Exit(EXIT_INVALID_INPUT)
                        except Exception:
                            error_msg = f"Failed to find Gerrit account for '{owner}'"
                            console.print(f"[red]❌ {error_msg}[/red]")
                            raise typer.Exit(EXIT_INVALID_INPUT)

                        # Verify the key
                        if detected_type == "gpg":
                            verification = await client.verify_gpg_key_registered(
                                account_id=account.account_id,
                                key_id=key_id,
                            )
                        else:  # ssh
                            normalized_fingerprint = _normalize_ssh_fingerprint(key_id)
                            verification = await client.verify_ssh_key_registered(
                                account_id=account.account_id,
                                fingerprint=normalized_fingerprint,
                            )

            # Display results
            if json_output:
                result = {
                    "success": verification.key_registered,
                    "key_type": detected_type,
                    "key_id": key_id,
                    "owner_input": owner,
                    "username": account.username,
                    "email": account.email,
                    "name": account.name,
                    "server": verification.server,
                    "service": "gerrit",
                    "is_registered": verification.key_registered,
                }
                console.print_json(data=result)
            else:
                # Create a mock SignatureInfo for display purposes
                from .models import SignatureInfo
                from typing import cast, Literal
                mock_signature = SignatureInfo(
                    type=cast(Literal["gpg", "ssh", "unsigned", "lightweight", "invalid", "gpg-unverifiable"], detected_type),
                    verified=True,  # We're not verifying a signature, just checking registration
                    key_id=key_id if detected_type == "gpg" else None,
                    fingerprint=key_id if detected_type == "ssh" else None,
                    signer_email=None,
                    signature_data=None,
                )
                _display_verification_result(
                    verification, mock_signature, owner,
                    platform="Gerrit", account=account
                )

            # Exit with appropriate code
            if verification.key_registered:
                raise typer.Exit(EXIT_SUCCESS)
            else:
                raise typer.Exit(EXIT_VALIDATION_FAILED)

        except typer.Exit:
            raise
        except SystemExit:
            raise
        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e), "exit_code": EXIT_UNEXPECTED_ERROR})
            else:
                console.print(f"\n[red]❌ Error:[/red] {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Unexpected error during verification")
                else:
                    logger.error(f"Unexpected error during verification: {e}")
            raise typer.Exit(EXIT_UNEXPECTED_ERROR)

    # Run async function
    asyncio.run(_verify())


@app.command(name="github")
def verify_github(
    key_id: str = typer.Argument(
        ...,
        help="GPG key ID (e.g., 'FCE8AAABF53080F6') or SSH fingerprint (e.g., 'SHA256:...')"
    ),
    owner: str = typer.Option(
        ...,
        "--owner",
        "-o",
        help="GitHub username or email address to verify key against",
    ),
    key_type: str = typer.Option(
        "auto",
        "--type",
        "-t",
        help="Key type: 'gpg', 'ssh', or 'auto' (default: auto-detect)",
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub API token (or set GITHUB_TOKEN env var)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON",
    ),
    no_subkeys: bool = typer.Option(
        False,
        "--no-subkeys",
        help="Disable GPG subkey verification (only check primary keys)",
    ),
    api_url: str = typer.Option(
        "https://api.github.com",
        "--api-url",
        help="GitHub API base URL (for GitHub Enterprise Server)",
    ),
    graphql_url: str = typer.Option(
        "https://api.github.com/graphql",
        "--graphql-url",
        help="GitHub GraphQL endpoint URL (for GitHub Enterprise Server)",
    ),
    test_mode: bool = typer.Option(
        False,
        "--test-mode",
        help="Test key parsing and normalization without making GitHub API calls",
        hidden=True,
    ),

):
    """
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

    # Handle test mode first, before any other validations
    if test_mode:
        async def _test_mode():
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Auto-detect or validate key type
            detected_type = key_type
            if key_type == "auto":
                detected_type = _detect_key_type(key_id)
                if detected_type == "unknown":
                    error_msg = f"Could not auto-detect key type from: {key_id[:50]}... Please specify --type gpg or --type ssh"
                    if json_output:
                        console.print_json(data={"success": False, "error": error_msg})
                    else:
                        console.print(f"[red]❌ {error_msg}[/red]")
                    raise typer.Exit(1)
            elif key_type not in ["gpg", "ssh"]:
                error_msg = f"Invalid key type: {key_type}. Must be 'gpg', 'ssh', or 'auto'"
                if json_output:
                    console.print_json(data={"success": False, "error": error_msg})
                else:
                    console.print(f"[red]❌ {error_msg}[/red]")
                raise typer.Exit(1)

            try:
                if detected_type == "ssh":
                    normalized_fingerprint = _normalize_ssh_fingerprint(key_id)
                    if json_output:
                        console.print_json(data={
                            "test_mode": True,
                            "success": True,
                            "key_type": detected_type,
                            "original_input": key_id,
                            "normalized_fingerprint": normalized_fingerprint,
                            "owner": owner,
                        })
                    else:
                        console.print(f"\n[green]✅ Test Mode: Key parsing successful[/green]")
                        console.print(f"[bold]Key Type:[/bold] {detected_type}" + (" (auto-detected)" if key_type == "auto" else ""))
                        console.print(f"[bold]Original Input:[/bold] {key_id}")
                        console.print(f"[bold]Normalized Fingerprint:[/bold] {normalized_fingerprint}")
                        console.print(f"[bold]Owner:[/bold] {owner}")
                        console.print(f"\n[dim]No GitHub API calls made in test mode.[/dim]")
                else:  # gpg
                    if json_output:
                        console.print_json(data={
                            "test_mode": True,
                            "success": True,
                            "key_type": detected_type,
                            "original_input": key_id,
                            "normalized_key_id": key_id,
                            "owner": owner,
                        })
                    else:
                        console.print(f"\n[green]✅ Test Mode: Key parsing successful[/green]")
                        console.print(f"[bold]Key Type:[/bold] {detected_type}" + (" (auto-detected)" if key_type == "auto" else ""))
                        console.print(f"[bold]Original Input:[/bold] {key_id}")
                        console.print(f"[bold]Normalized Key ID:[/bold] {key_id}")
                        console.print(f"[bold]Owner:[/bold] {owner}")
                        console.print(f"\n[dim]No GitHub API calls made in test mode.[/dim]")

                import sys
                sys.exit(EXIT_SUCCESS)
            except Exception as e:
                error_msg = f"Key parsing/normalization failed: {str(e)}"
                if json_output:
                    console.print_json(data={
                        "test_mode": True,
                        "success": False,
                        "error": error_msg,
                        "key_type": detected_type,
                        "original_input": key_id,
                    })
                else:
                    console.print(f"\n[red]❌ Test Mode: {error_msg}[/red]")
                raise typer.Exit(1)

        # Run test mode and return
        asyncio.run(_test_mode())
        return

    async def _verify():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Auto-detect or validate key type
            detected_type = key_type
            if key_type == "auto":
                detected_type = _detect_key_type(key_id)
                if detected_type == "unknown":
                    error_msg = f"Could not auto-detect key type from: {key_id[:50]}... Please specify --type gpg or --type ssh"
                    if json_output:
                        console.print_json(data={"success": False, "error": error_msg})
                    else:
                        console.print(f"[red]❌ {error_msg}[/red]")
                    raise typer.Exit(1)
            elif key_type not in ["gpg", "ssh"]:
                error_msg = f"Invalid key type: {key_type}. Must be 'gpg', 'ssh', or 'auto'"
                if json_output:
                    console.print_json(data={"success": False, "error": error_msg})
                else:
                    console.print(f"[red]❌ {error_msg}[/red]")
                raise typer.Exit(1)

            # Validate GitHub token
            import os
            if not github_token and not os.getenv("GITHUB_TOKEN"):
                error_msg = "GitHub token is required. Use --token option or set GITHUB_TOKEN environment variable."
                if json_output:
                    console.print_json(data={"success": False, "error": error_msg, "exit_code": EXIT_MISSING_TOKEN})
                else:
                    console.print(f"\n[red]❌ {error_msg}[/red]")
                raise typer.Exit(EXIT_MISSING_TOKEN)

            # Resolve owner (email or username) to username first
            try:
                resolved_owner = await _resolve_owner_to_username(owner, github_token)
            except ValueError as e:
                if json_output:
                    console.print_json(data={"success": False, "error": str(e), "exit_code": EXIT_INVALID_INPUT})
                else:
                    console.print(f"\n[red]❌ Error:[/red] {e}")
                raise typer.Exit(EXIT_INVALID_INPUT)

            # Fetch user details
            user_details = None
            async with GitHubKeysClient(token=github_token, api_url=api_url, graphql_url=graphql_url) as client:
                user_details = await client.get_user_details(resolved_owner)

            # Verify key on GitHub
            if json_output:
                async with GitHubKeysClient(token=github_token, api_url=api_url, graphql_url=graphql_url) as client:
                    if detected_type == "gpg":
                        verification = await client.verify_gpg_key_registered(
                            username=resolved_owner,
                            key_id=key_id,
                            check_subkeys=not no_subkeys,
                        )
                    else:  # ssh
                        normalized_fingerprint = _normalize_ssh_fingerprint(key_id)
                        verification = await client.verify_ssh_key_registered(
                            username=resolved_owner,
                            public_key_fingerprint=normalized_fingerprint,
                        )
            else:
                with console.status("[bold green]Verifying key on GitHub..."):
                    async with GitHubKeysClient(token=github_token, api_url=api_url, graphql_url=graphql_url) as client:
                        if detected_type == "gpg":
                            verification = await client.verify_gpg_key_registered(
                                username=resolved_owner,
                                key_id=key_id,
                                check_subkeys=not no_subkeys,
                            )
                        else:  # ssh
                            normalized_fingerprint = _normalize_ssh_fingerprint(key_id)
                            verification = await client.verify_ssh_key_registered(
                                username=resolved_owner,
                                public_key_fingerprint=normalized_fingerprint,
                            )

            # Display results
            if json_output:
                # Use verification.server if available, otherwise extract from API URL
                server_hostname = verification.server
                if not server_hostname:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(api_url)
                    # Extract just the hostname (e.g., "api.github.com" -> "github.com")
                    netloc = parsed_url.netloc if parsed_url.netloc else "github.com"
                    # For api.github.com, use github.com; for GHE, keep the hostname
                    server_hostname = "github.com" if netloc == "api.github.com" else netloc.replace("api.", "")

                result = {
                    "success": verification.key_registered,
                    "key_type": detected_type,
                    "key_id": key_id,
                    "owner_input": owner,
                    "username": user_details.get("login") if user_details else resolved_owner,
                    "email": user_details.get("email") if user_details else None,
                    "name": user_details.get("name") if user_details else None,
                    "server": server_hostname,
                    "service": "github",
                    "is_registered": verification.key_registered,
                    # Backward-compatible aliases for older JSON consumers
                    "github_user": user_details.get("login") if user_details else resolved_owner,
                    "key_registered": verification.key_registered,
                }
                console.print_json(data=result)
            else:
                # Create a mock SignatureInfo for display purposes
                from .models import SignatureInfo
                from typing import cast, Literal
                mock_signature = SignatureInfo(
                    type=cast(Literal["gpg", "ssh", "unsigned", "lightweight", "invalid", "gpg-unverifiable"], detected_type),
                    verified=True,  # We're not verifying a signature, just checking registration
                    key_id=key_id if detected_type == "gpg" else None,
                    fingerprint=key_id if detected_type == "ssh" else None,
                    signer_email=None,
                    signature_data=None,
                )
                _display_verification_result(
                    verification, mock_signature, resolved_owner,
                    platform="GitHub", github_user_details=user_details
                )

            # Exit with appropriate code
            if verification.key_registered:
                raise typer.Exit(EXIT_SUCCESS)
            else:
                raise typer.Exit(EXIT_VALIDATION_FAILED)

        except typer.Exit:
            raise
        except SystemExit:
            raise
        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e), "exit_code": EXIT_UNEXPECTED_ERROR})
            else:
                console.print(f"\n[red]❌ Error:[/red] {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Unexpected error during verification")
                else:
                    logger.error(f"Unexpected error during verification: {e}")
            raise typer.Exit(EXIT_UNEXPECTED_ERROR)

    # Run async function
    asyncio.run(_verify())


@app.command()
def detect(
    tag_name: str = typer.Argument(
        ...,
        help="Name of the Git tag to analyze"
    ),
    repo_path: Path = typer.Option(
        ".",
        "--repo-path",
        "-r",
        help="Path to the Git repository",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON",
    ),
):
    """
    Detect and display signature information for a Git tag.

    This command analyzes a tag and reports:
    - Signature type (GPG, SSH, or unsigned)
    - Signature validity
    - Key ID and fingerprint
    - Signer information

    Example:
        tag-validate detect v1.0.0
    """
    async def _detect():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Only show status message when not in JSON mode
            if json_output:
                detector = SignatureDetector(repo_path)
                signature_info = await detector.detect_signature(tag_name)
            else:
                with console.status("[bold green]Detecting signature..."):
                    detector = SignatureDetector(repo_path)
                    signature_info = await detector.detect_signature(tag_name)

            if json_output:
                result = {
                    "tag_name": tag_name,
                    "signature_type": signature_info.type,
                    "is_valid": signature_info.verified,
                    "signer": signature_info.signer_email,
                    "key_id": signature_info.key_id,
                    "fingerprint": signature_info.fingerprint,
                }
                console.print_json(data=result)
            else:
                _display_signature_info(signature_info, tag_name)

            # Exit with success if signature is valid, failure otherwise
            if signature_info.verified or signature_info.type == "unsigned":
                raise typer.Exit(0)
            else:
                raise typer.Exit(1)

        except SignatureDetectionError as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e)})
            else:
                console.print(f"\n[red]❌ Error:[/red] {e}")
            raise typer.Exit(1)
        except typer.Exit:
            raise
        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e)})
            else:
                console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Unexpected error during signature detection")
                else:
                    logger.error(f"Unexpected error during signature detection: {e}")
            raise typer.Exit(1)

    # Run async function
    asyncio.run(_detect())


def _display_signature_info(signature_info, tag_name: str):
    """Display signature information in a formatted table."""
    table = Table(title=f"Signature Information for Tag: {tag_name}")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    # Display signature type with friendly names
    type_display = {
        "gpg": "GPG",
        "ssh": "SSH",
        "unsigned": "UNSIGNED",
        "lightweight": "LIGHTWEIGHT",
        "invalid": "INVALID (corrupted/tampered)",
        "gpg-unverifiable": "GPG (key not available)",
    }
    sig_type = type_display.get(signature_info.type, signature_info.type.upper())
    table.add_row("Signature Type", sig_type)

    # Display verification status
    if signature_info.type == "gpg-unverifiable":
        table.add_row("Status", "⚠️  Key not available for verification")
    elif signature_info.type == "invalid":
        table.add_row("Status", "❌ Signature is corrupted or tampered")
    elif signature_info.type in ["unsigned", "lightweight"]:
        table.add_row("Status", "No signature")

    if signature_info.signer_email:
        table.add_row("Signer", signature_info.signer_email)

    if signature_info.key_id:
        table.add_row("Key ID", signature_info.key_id)

    if signature_info.fingerprint:
        table.add_row("Fingerprint", signature_info.fingerprint)

    console.print(table)


def _display_verification_result(
    verification: KeyVerificationResult,
    signature_info,
    owner: str,
    platform: str = "GitHub",
    account=None,
    github_user_details=None,
):
    """
    Display key verification result in a formatted panel.

    Args:
        verification: Key verification result from GitHub or Gerrit
        signature_info: Signature information
        owner: Username or email of the key owner
        platform: Platform name ("GitHub" or "Gerrit")
        account: Optional GerritAccountInfo for Gerrit platform
        github_user_details: Optional dict with GitHub user details
    """
    if verification.key_registered:
        panel_style = "green"
        status_icon = "✅"
        status_text = "REGISTERED"
    else:
        panel_style = "red"
        status_icon = "❌"
        status_text = "NOT REGISTERED"

    # Build user information display using shared utility
    if platform == "Gerrit" and account:
        user_lines = format_user_details(
            username=account.username,
            email=account.email,
            name=account.name
        )
    elif platform == "GitHub" and github_user_details:
        user_lines = format_user_details(
            username=github_user_details.get("login"),
            email=github_user_details.get("email"),
            name=github_user_details.get("name")
        )
    else:
        user_lines = []

    user_section = "\n".join(user_lines) if user_lines else f"  • {platform} User: {owner}"

    # Build server display using shared utility
    service = "gerrit" if platform == "Gerrit" else "github"
    server_line = format_server_display(service, verification.server)

    # Build details section - only show fields that have values
    details_lines = [f"  • Signature Type: {signature_info.type}"]
    if signature_info.key_id:
        details_lines.append(f"  • Key ID: {signature_info.key_id}")
    if signature_info.fingerprint:
        details_lines.append(f"  • Fingerprint: {signature_info.fingerprint}")
    if signature_info.signer_email:
        details_lines.append(f"  • Signer: {signature_info.signer_email}")
    details_section = "\n".join(details_lines)

    # Build content with optional server line
    content_parts = [f"[bold]{status_icon} {status_text}[/bold]"]

    if server_line:
        content_parts.append("")
        content_parts.append(server_line)

    content_parts.extend([
        "",
        "[bold]Details:[/bold]",
        details_section,
        "",
        f"[bold]{platform} User:[/bold]",
        user_section,
    ])

    content = "\n".join(content_parts)

    panel = Panel(
        content.strip(),
        title="Key Verification Result",
        border_style=panel_style,
        padding=(1, 2),
    )
    console.print(panel)


@app.command()
def validate(
    version_string: str = typer.Argument(
        ...,
        help="Version string to validate (e.g., v1.2.3, 2024.01.15)"
    ),
    require_type: Optional[str] = typer.Option(
        None,
        "--require-type",
        "-t",
        help="Require specific version type: semver, calver (comma or space-separated for multiple)",
    ),
    allow_prefix: bool = typer.Option(
        True,
        "--allow-prefix/--no-prefix",
        help="Allow 'v' prefix on version strings",
    ),
    strict_semver: bool = typer.Option(
        False,
        "--strict-semver",
        help="Enforce strict SemVer compliance (no prefix, exact format)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON",
    ),
    json_file: Optional[Path] = typer.Option(
        None,
        "--json-file",
        help="Write JSON output to file while showing rich console output",
    ),
):
    """
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
    try:
        # Suppress ALL logs when JSON output is requested
        if json_output:
            _suppress_logging_for_json()

        # Validate that version_string is not empty or whitespace
        if not version_string or not version_string.strip():
            error_msg = "Version string is empty or null"
            info_msg = [
                "version_string parameter is required but was not provided or is empty",
                "Expected formats: 'v1.0.0' (SemVer), '2024.01.15' (CalVer), or other version strings"
            ]

            if json_output:
                output = {
                    "success": False,
                    "version": "",
                    "error": error_msg,
                    "info": info_msg,
                }
                console.print_json(data=output)
            else:
                console.print(f"\n[red]❌ Error:[/red] {error_msg}")
                console.print("\n[yellow]ℹ️  Info:[/yellow]")
                for info in info_msg:
                    console.print(f"  • {info}")
            raise typer.Exit(1)

        validator = TagValidator()

        # Handle require_type=none - accept any format without validation
        if require_type and require_type.lower() == "none":
            # Just detect version info without enforcing format
            result = validator.validate_version(
                version_string,
                allow_prefix=allow_prefix,
                strict_semver=strict_semver,
            )
            # Override to always succeed with require_type=none
            if not result.is_valid:
                # Create a successful result for unknown format
                from tag_validate.models import VersionInfo
                result = VersionInfo(
                    raw=version_string,
                    normalized=version_string,
                    version_type="other",
                    is_valid=True,
                    has_prefix=version_string[0:1] in ("v", "V") if version_string else False,
                    is_development=any(kw in version_string.lower() for kw in
                        ["dev", "pre", "alpha", "beta", "rc", "snapshot", "nightly", "canary", "preview"]),
                    # SemVer fields (all None for other type)
                    major=None,
                    minor=None,
                    patch=None,
                    prerelease=None,
                    build_metadata=None,
                    # CalVer fields (all None for unknown type)
                    year=None,
                    month=None,
                    day=None,
                    micro=None,
                    modifier=None,
                    errors=[],
                )
        else:
            # Normal validation
            result = validator.validate_version(
                version_string,
                allow_prefix=allow_prefix,
                strict_semver=strict_semver,
            )

        # Check if specific type is required - multi-value support
        if require_type and result.is_valid:
            # Parse and validate types
            require_type_list = parse_multi_value_option(require_type)
            validate_version_types(require_type_list)

            # Check if result matches required types
            if not check_version_type_match(result.version_type, require_type_list):
                if json_output:
                    output = {
                        "success": False,
                        "error": f"Version type mismatch: expected {', '.join(require_type_list)}, got {result.version_type}",
                        "version": version_string,
                        "detected_type": result.version_type,
                        "required_types": require_type_list,
                    }
                    console.print_json(data=output)
                else:
                    console.print(
                        f"\n[red]❌ Version type mismatch:[/red] "
                        f"expected {', '.join(require_type_list)}, got {result.version_type}"
                    )
                raise typer.Exit(EXIT_VALIDATION_FAILED)

        # Output results
        if json_output:
            output = {
                "success": result.is_valid,
                "version": version_string,
                "normalized": result.normalized,
                "version_type": result.version_type,
                "is_valid": result.is_valid,
                "development_tag": result.is_development,
                "version_prefix": result.has_prefix,
            }

            # Add type-specific fields
            if result.version_type == "semver":
                output.update({
                    "major": result.major,
                    "minor": result.minor,
                    "patch": result.patch,
                    "prerelease": result.prerelease,
                    "build_metadata": result.build_metadata,
                })
            elif result.version_type == "calver":
                output.update({
                    "year": result.year,
                    "month": result.month,
                    "day": result.day,
                    "micro": result.micro,
                    "modifier": result.modifier,
                })
            elif result.version_type == "both":
                # For 'both' type, include SemVer fields from result and CalVer fields by re-parsing
                validator = TagValidator()
                calver_result = validator.validate_calver(result.normalized or result.raw)

                output.update({
                    # SemVer fields from original result
                    "major": result.major,
                    "minor": result.minor,
                    "patch": result.patch,
                    "prerelease": result.prerelease,
                    "build_metadata": result.build_metadata,
                    # CalVer fields from re-parsing as CalVer
                    "year": calver_result.year if calver_result.is_valid else None,
                    "month": calver_result.month if calver_result.is_valid else None,
                    "day": calver_result.day if calver_result.is_valid else None,
                    "micro": calver_result.micro if calver_result.is_valid else None,
                    "modifier": calver_result.modifier if calver_result.is_valid else None,
                })

            if not result.is_valid:
                output["errors"] = result.errors

            console.print_json(data=output)
        else:
            _display_version_info(result, version_string)

        # Write JSON to file if requested
        if json_file and not json_output:
            import json as json_module
            output = {
                "success": result.is_valid,
                "version": result.raw,
                "detected_type": result.version_type,
                "is_development": result.is_development,
                "has_prefix": result.has_prefix,
                "version_prefix": result.has_prefix,
            }

            # Add type-specific fields
            if result.version_type == "semver":
                output.update({
                    "major": result.major,
                    "minor": result.minor,
                    "patch": result.patch,
                    "prerelease": result.prerelease,
                    "build_metadata": result.build_metadata,
                })
            elif result.version_type == "calver":
                output.update({
                    "year": result.year,
                    "month": result.month,
                    "day": result.day,
                    "micro": result.micro,
                    "modifier": result.modifier,
                })

            if not result.is_valid:
                output["errors"] = result.errors

            # Write to file
            try:
                json_file.parent.mkdir(parents=True, exist_ok=True)
                with json_file.open('w', encoding='utf-8') as f:
                    json_module.dump(output, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.error(f"Failed to write JSON to file {json_file}: {e}")

        # Exit with appropriate code
        if result.is_valid:
            raise typer.Exit(0)
        else:
            raise typer.Exit(1)

    except typer.Exit:
        raise
    except Exception as e:
        if json_output:
            console.print_json(data={"success": False, "error": str(e)})
        else:
            console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Unexpected error during version validation")
            else:
                logger.error(f"Unexpected error during version validation: {e}")
        raise typer.Exit(1)


@app.command()
def verify(
    tag_location: str = typer.Argument(
        ...,
        help="Tag location: tag name, or owner/repo@tag for remote"
    ),
    repo_path: Path = typer.Option(
        ".",
        "--path",
        "-p",
        help="Path to local Git repository (default: current directory)",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    require_type: Optional[str] = typer.Option(
        None,
        "--require-type",
        "-t",
        help="Require specific version type: semver, calver (comma or space-separated for multiple)",
    ),
    require_signed: Optional[str] = typer.Option(
        None,
        "--require-signed",
        help="Require tag signature. Values: gpg, ssh, gpg-unverifiable, unsigned (comma or space-separated for multiple). Omit for no requirement.",
    ),
    require_github: bool = typer.Option(
        False,
        "--require-github",
        help="Verify signing key is registered on GitHub",
    ),
    require_gerrit: Optional[str] = typer.Option(
        None,
        "--require-gerrit",
        help="Verify signing key is registered on Gerrit. Requires a value: 'true' for auto-discovery from GitHub org (pattern: gerrit.<org>.org), or a specific Gerrit server hostname (e.g. 'gerrit.onap.org'). Example: --require-gerrit gerrit.onap.org",
    ),
    owner: Optional[str] = typer.Option(
        None,
        "--owner",
        "-o",
        help="GitHub username or email address for key verification (optional, auto-detected from tagger email if not provided)",
    ),
    require_owner: Optional[str] = typer.Option(
        None,
        "--require-owner",
        help="GitHub username(s) or email address(es) that must own the signing key (comma or space-separated for multiple). Implies --require-github.",
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub API token (or set GITHUB_TOKEN env var)",
    ),
    gerrit_username: Optional[str] = typer.Option(
        None,
        "--gerrit-username",
        envvar="GERRIT_USERNAME",
        help="Gerrit username for HTTP authentication (can also use GERRIT_USERNAME env var)",
    ),
    gerrit_password: Optional[str] = typer.Option(
        None,
        "--gerrit-password",
        envvar="GERRIT_PASSWORD",
        help="Gerrit HTTP password for authentication (can also use GERRIT_PASSWORD env var)",
    ),
    reject_development: bool = typer.Option(
        False,
        "--reject-development",
        help="Reject development versions (alpha, beta, rc, etc.)",
    ),
    skip_version_validation: bool = typer.Option(
        False,
        "--skip-version-validation",
        help="Skip version format validation (only check signature)",
    ),
    permit_missing: bool = typer.Option(
        False,
        "--permit-missing",
        help="Allow missing tags without error (returns success with minimal info)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON",
    ),
    json_file: Optional[Path] = typer.Option(
        None,
        "--json-file",
        help="Write JSON output to file while showing rich console output",
    ),
    github_step_summary: bool = typer.Option(
        True,
        "--github-step-summary/--no-github-step-summary",
        help="Write validation summary to GITHUB_STEP_SUMMARY (only in GitHub Actions)",
    ),
):
    """
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
        tag-validate verify torvalds/linux@v6.0 \
          --require-github --owner torvalds --token $GITHUB_TOKEN

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
        tag-validate verify my-tag --skip-version-validation \
          --require-github --owner user@example.com --token $GITHUB_TOKEN
    """
    async def _verify():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Validate tag_location is not empty or null
            if not tag_location or not tag_location.strip():
                error_msg = "Tag location is empty or null"
                info_messages = [
                    "tag_location parameter is required but was not provided or is empty",
                ] + TAG_LOCATION_FORMAT_EXAMPLES

                if json_output:
                    console.print_json(data={
                        "success": False,
                        "tag_name": "",
                        "error": error_msg,
                        "info": info_messages
                    })
                else:
                    console.print(f"[red]❌ Error:[/red] {error_msg}")
                    console.print("\n[yellow]Expected formats:[/yellow]")
                    for fmt in TAG_LOCATION_FORMATS.values():
                        console.print(f"  • {fmt}")
                raise typer.Exit(1)

            # Parse require_signed option - multi-value support
            # Support: gpg, ssh, gpg-unverifiable, unsigned (comma or space-separated)
            config_require_signed = False
            config_require_unsigned = False
            allowed_signature_types = None

            if require_signed:
                # Parse and validate signature types
                require_signed_types = parse_multi_value_option(require_signed)
                validate_signature_types(require_signed_types)

                # Set config flags based on types
                if 'unsigned' in require_signed_types:
                    config_require_unsigned = True
                    # If unsigned is mixed with other types, store all types
                    if len(require_signed_types) > 1:
                        allowed_signature_types = require_signed_types
                    else:
                        allowed_signature_types = None
                elif require_signed_types:
                    # Store specific signature types for validation
                    config_require_signed = True
                    allowed_signature_types = require_signed_types

            # Parse require_type option - multi-value support
            require_type_list = []
            if require_type and not skip_version_validation:
                # Parse and validate types
                require_type_list = parse_multi_value_option(require_type)
                validate_version_types(require_type_list)
                # Filter out 'none' - it means no requirement
                require_type_list = [t for t in require_type_list if t != 'none']

            # Parse require_owner option - multi-value support
            require_owner_list = []
            config_require_github = require_github  # Preserve original parameter value
            if require_owner:
                require_owner_list = parse_multi_value_option(require_owner)
                # When require_owner is specified, require_github is implied
                config_require_github = True

            # Parse require_gerrit option
            config_require_gerrit = False
            gerrit_server = None
            if require_gerrit:
                if require_gerrit.lower() in ("true", "yes", "1"):
                    config_require_gerrit = True
                    # Server will be auto-discovered in the workflow
                elif require_gerrit.lower() not in ("false", "no", "0"):
                    # Treat as server hostname/URL
                    config_require_gerrit = True
                    gerrit_server = require_gerrit

            # Build configuration
            config = ValidationConfig(
                require_semver=("semver" in require_type_list or "both" in require_type_list) if require_type_list else False,
                require_calver=("calver" in require_type_list or "both" in require_type_list) if require_type_list else False,
                require_signed=config_require_signed,
                require_unsigned=config_require_unsigned,
                allowed_signature_types=allowed_signature_types if require_signed else None,
                require_github=config_require_github,
                require_gerrit=config_require_gerrit,
                gerrit_server=gerrit_server,
                reject_development=reject_development if not skip_version_validation else False,
                skip_version_validation=skip_version_validation,
                allow_prefix=True,  # Default to allowing version prefixes
                config_source="CLI",  # Mark as CLI-originated config
            )

            # Create workflow
            workflow = ValidationWorkflow(
                config,
                repo_path=repo_path,
                gerrit_username=gerrit_username,
                gerrit_password=gerrit_password,
            )

            # Resolve owner parameter (email or username) to username if provided
            resolved_owner = None
            if owner:
                try:
                    resolved_owner = await _resolve_owner_to_username(owner, github_token)
                except ValueError as e:
                    if json_output:
                        console.print_json(data={"success": False, "error": str(e), "exit_code": EXIT_INVALID_INPUT})
                    else:
                        console.print(f"\n[red]❌ Error:[/red] {e}")
                    raise typer.Exit(EXIT_INVALID_INPUT)

            # Run validation
            # Normalize tag location format (handle owner/repo/tag → owner/repo@tag)
            normalized_location = _normalize_tag_location(tag_location)

            try:
                if json_output:
                    result = await workflow.validate_tag_location(
                        tag_location=normalized_location,
                        github_user=resolved_owner,
                        github_token=github_token,
                        require_owners=require_owner_list if require_owner_list else None,
                    )
                else:
                    with console.status("[bold green]Validating tag..."):
                        result = await workflow.validate_tag_location(
                            tag_location=normalized_location,
                            github_user=resolved_owner,
                            github_token=github_token,
                            require_owners=require_owner_list if require_owner_list else None,
                        )
            except Exception as e:
                # Handle missing tag with permit_missing flag
                if permit_missing and _is_tag_not_found_error(str(e)):
                    output = {
                        "success": True,
                        "tag_name": normalized_location,
                        "version_type": "other",
                        "signature_type": "unsigned",
                        "signature_verified": False,
                        "key_registered": None,
                        "is_development": False,
                        "development_tag": False,
                        "has_prefix": False,
                        "version_prefix": False,
                        "errors": [],
                        "warnings": ["Tag not found but permit_missing=true"],
                        "info": ["Tag was not found"],
                    }

                    if json_output:
                        console.print_json(data=output)
                    else:
                        console.print("\n[yellow]⚠️  Tag not found, but permit_missing=true[/yellow]")

                    # Write JSON to file if requested
                    if json_file:
                        import json as json_module
                        try:
                            json_file.parent.mkdir(parents=True, exist_ok=True)
                            with json_file.open('w', encoding='utf-8') as f:
                                json_module.dump(output, f, indent=2, ensure_ascii=False)
                        except Exception as file_error:
                            logger.error(f"Failed to write JSON to file {json_file}: {file_error}")

                    raise typer.Exit(0)
                else:
                    # Re-raise if not a missing tag error or permit_missing is false
                    raise

            # Check if result failed due to missing tag and permit_missing is enabled
            if permit_missing and not result.is_valid:
                # Check if the errors indicate a missing tag
                error_text = " ".join(result.errors)
                if _is_tag_not_found_error(error_text):
                    output = {
                        "success": True,
                        "tag_name": normalized_location,
                        "version_type": "other",
                        "signature_type": "unsigned",
                        "signature_verified": False,
                        "key_registered": None,
                        "is_development": False,
                        "development_tag": False,
                        "has_prefix": False,
                        "version_prefix": False,
                        "errors": [],
                        "warnings": ["Tag not found but permit_missing=true"],
                        "info": ["Tag was not found"],
                    }

                    if json_output:
                        console.print_json(data=output)
                    else:
                        console.print("\n[yellow]⚠️  Tag not found, but permit_missing=true[/yellow]")

                    # Write JSON to file if requested
                    if json_file:
                        import json as json_module
                        try:
                            json_file.parent.mkdir(parents=True, exist_ok=True)
                            with json_file.open('w', encoding='utf-8') as f:
                                json_module.dump(output, f, indent=2, ensure_ascii=False)
                        except Exception as file_error:
                            logger.error(f"Failed to write JSON to file {json_file}: {file_error}")

                    raise typer.Exit(0)

            # Output results
            if json_output:
                output = {
                    "success": result.is_valid,
                    "tag_name": result.tag_name,
                    "version_type": result.version_info.version_type if result.version_info else None,
                    "signature_type": result.signature_info.type if result.signature_info else None,
                    "signature_verified": result.signature_info.verified if result.signature_info else None,
                    "development_tag": result.version_info.is_development if result.version_info else False,
                    "version_prefix": result.version_info.has_prefix if result.version_info else False,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "info": result.info,
                }

                # Add signature details if available
                if result.signature_info:
                    output["signature_details"] = {
                        "signer_email": result.signature_info.signer_email,
                        "key_id": result.signature_info.key_id,
                        "fingerprint": result.signature_info.fingerprint,
                    }

                # Add version details if available
                if result.version_info:
                    output["version_details"] = {
                        "raw": result.version_info.raw,
                        "normalized": result.version_info.normalized,
                    }
                    if result.version_info.version_type == "semver":
                        output["version_details"]["semver"] = {
                            "major": result.version_info.major,
                            "minor": result.version_info.minor,
                            "patch": result.version_info.patch,
                            "prerelease": result.version_info.prerelease,
                            "build_metadata": result.version_info.build_metadata,
                        }
                    elif result.version_info.version_type == "calver":
                        output["version_details"]["calver"] = {
                            "year": result.version_info.year,
                            "month": result.version_info.month,
                            "day": result.version_info.day,
                            "micro": result.version_info.micro,
                        }

                # Add key verification details if available
                if result.key_verifications:
                    output["key_verifications"] = []
                    for k in result.key_verifications:
                        verification = {
                            "service": k.service,
                            "key_registered": k.key_registered,
                            "server": k.server,
                            "username": k.username,
                            "user_email": k.user_email,
                            "user_name": k.user_name,
                        }
                        output["key_verifications"].append(verification)

                console.print_json(data=output)
            else:
                _display_validation_result(result, workflow)

            # Write JSON to file if requested
            if json_file:
                import json as json_module
                output = {
                    "success": result.is_valid,
                    "tag_name": result.tag_name,
                    "version_type": result.version_info.version_type if result.version_info else None,
                    "signature_type": result.signature_info.type if result.signature_info else None,
                    "signature_verified": result.signature_info.verified if result.signature_info else None,
                    "key_registered": result.key_verifications[0].key_registered if result.key_verifications else None,
                    "development_tag": result.version_info.is_development if result.version_info else False,
                    "version_prefix": result.version_info.has_prefix if result.version_info else False,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "info": result.info,
                }

                # Add signature details if available
                if result.signature_info:
                    output["signature_details"] = {
                        "signer_email": result.signature_info.signer_email,
                        "key_id": result.signature_info.key_id,
                        "fingerprint": result.signature_info.fingerprint,
                    }

                # Add version details if available
                if result.version_info:
                    output["version_details"] = {
                        "raw": result.version_info.raw,
                        "normalized": result.version_info.normalized,
                    }
                    if result.version_info.version_type == "semver":
                        output["version_details"]["semver"] = {
                            "major": result.version_info.major,
                            "minor": result.version_info.minor,
                            "patch": result.version_info.patch,
                            "prerelease": result.version_info.prerelease,
                            "build_metadata": result.version_info.build_metadata,
                        }
                    elif result.version_info.version_type == "calver":
                        output["version_details"]["calver"] = {
                            "year": result.version_info.year,
                            "month": result.version_info.month,
                            "day": result.version_info.day,
                            "micro": result.version_info.micro,
                        }

                # Add key verifications (GitHub and/or Gerrit)
                if result.key_verifications:
                    output["key_verifications"] = []
                    for k in result.key_verifications:
                        verification = {
                            "service": k.service,
                            "server": k.server,
                            "key_registered": k.key_registered,
                            "username": k.username,
                            "user_email": k.user_email,
                            "user_name": k.user_name,
                            "user_enumerated": k.user_enumerated,
                        }
                        output["key_verifications"].append(verification)

                # Write to file
                try:
                    json_file.parent.mkdir(parents=True, exist_ok=True)
                    with json_file.open('w', encoding='utf-8') as f:
                        json_module.dump(output, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    logger.error(f"Failed to write JSON to file {json_file}: {e}")

            # Write GitHub step summary if enabled and in GitHub Actions
            if github_step_summary and not json_output:
                write_validation_summary(result, tag_location)

            # Exit with appropriate code
            if result.is_valid:
                raise typer.Exit(EXIT_SUCCESS)
            else:
                # Check for specific error types and return appropriate exit codes
                error_messages = " ".join(result.errors).lower()

                # Check for missing GitHub token
                if "token" in error_messages and "github" in error_messages:
                    raise typer.Exit(EXIT_MISSING_TOKEN)
                # Check for missing Gerrit credentials
                elif "credentials not provided" in error_messages or "credentials required" in error_messages:
                    raise typer.Exit(EXIT_MISSING_CREDENTIALS)
                # Check for invalid Gerrit credentials
                elif "authentication failed" in error_messages or "invalid credentials" in error_messages:
                    raise typer.Exit(EXIT_AUTH_FAILED)
                else:
                    raise typer.Exit(EXIT_VALIDATION_FAILED)

        except typer.Exit:
            # Let typer.Exit pass through without catching
            raise
        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e), "exit_code": EXIT_UNEXPECTED_ERROR})
            else:
                console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Unexpected error during tag verification")
                else:
                    logger.error(f"Unexpected error during tag verification: {e}")
            raise typer.Exit(EXIT_UNEXPECTED_ERROR)

    # Run async function
    asyncio.run(_verify())


def _normalize_tag_location(tag_location: str) -> str:
    """Normalize tag location with smart path detection.

    Handles multiple input formats with pragmatic fallback:
    - owner/repo@tag (remote, already correct)
    - owner/repo/tag (remote if 2+ slashes, otherwise ambiguous)
    - https://github.com/owner/repo@tag (remote URL)
    - ./path/to/repo/tag or /path/to/repo/tag (local path)
    - path/to/repo/tag (ambiguous - check if local path exists, else treat as remote)
    - tag (local tag name)

    The normalization ensures that:
    1. Remote tags use @ separator (owner/repo@tag)
    2. Local paths are preserved for workflow to handle
    3. Ambiguous paths are passed through for smart detection

    Args:
        tag_location: The tag location in various formats

    Returns:
        str: Normalized tag location
    """
    from pathlib import Path

    # If already has @, return as-is (remote format)
    if "@" in tag_location:
        return tag_location

    # If it's a URL, return as-is (already validated by regex)
    if tag_location.startswith(("http://", "https://")):
        return tag_location

    # If it explicitly starts with ./ or /, it's definitely a local path
    if tag_location.startswith(("./", "/")):
        return tag_location

    # Count slashes to determine format
    slash_count = tag_location.count("/")

    # If 2+ slashes, likely owner/repo/tag format - convert to owner/repo@tag
    if slash_count >= 2:
        # Split into parts and convert last slash to @
        parts = tag_location.rsplit("/", 1)
        return f"{parts[0]}@{parts[1]}"

    # If 1 slash, it's ambiguous (could be path/to/repo or partial path)
    # Check if it looks like a local path by testing if directory exists
    if slash_count == 1:
        parts = tag_location.rsplit("/", 1)
        potential_repo_path = parts[0]

        # Try both relative to current dir and absolute
        for base_path in [Path("."), Path.cwd()]:
            test_path = base_path / potential_repo_path
            if test_path.is_dir() and (test_path / ".git").exists():
                # It's a local repository path - don't convert
                logger.debug(f"Detected local repository path: {tag_location}")
                return tag_location

        # Not a local path - could be owner/repo format but needs more slashes
        # Let it pass through as-is for workflow to handle
        logger.debug(f"Ambiguous path (no local repo found): {tag_location}")
        return tag_location

    # No slashes - it's a local tag name
    return tag_location


def _is_tag_not_found_error(error_message: str) -> bool:
    """Check if an error message indicates a missing tag.

    Args:
        error_message: The error message to check

    Returns:
        bool: True if the error indicates a missing tag
    """
    error_patterns = [
        "not found",
        "does not exist",
        "missing",
        "couldn't find",
        "failed to fetch",
        "failed to clone",
        "no such ref",
        "unknown revision",
        "bad revision",
    ]
    error_lower = error_message.lower()
    return any(pattern in error_lower for pattern in error_patterns)


def _display_validation_result(result, workflow: ValidationWorkflow):
    """Display complete validation result in a formatted panel."""
    # Create summary text
    summary = workflow.create_validation_summary(result)

    # Determine panel style
    if result.is_valid:
        panel_style = "green"
        title = f"✅ Tag Validation: {result.tag_name}"
    else:
        panel_style = "red"
        title = f"❌ Tag Validation: {result.tag_name}"

    panel = Panel(
        summary,
        title=title,
        border_style=panel_style,
        padding=(1, 2),
    )
    console.print(panel)


def _display_version_info(version_info, version_string: str):
    """Display version validation information in a formatted table."""
    if version_info.is_valid:
        title_style = "green"
        title = f"✅ Valid {version_info.version_type.upper()}: {version_string}"
    else:
        title_style = "red"
        title = f"❌ Invalid Version: {version_string}"

    table = Table(title=title, title_style=title_style)
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    table.add_row("Original", version_info.raw)

    if version_info.normalized:
        table.add_row("Normalized", version_info.normalized)

    table.add_row("Version Type", version_info.version_type.upper())
    table.add_row("Valid", "✅ Yes" if version_info.is_valid else "❌ No")
    table.add_row("Has Prefix", "✅ Yes" if version_info.has_prefix else "❌ No")
    table.add_row("Development", "✅ Yes" if version_info.is_development else "❌ No")

    # Add type-specific components
    if version_info.version_type == "semver" and version_info.is_valid:
        table.add_row("Major", str(version_info.major))
        table.add_row("Minor", str(version_info.minor))
        table.add_row("Patch", str(version_info.patch))
        if version_info.prerelease:
            table.add_row("Prerelease", version_info.prerelease)
        if version_info.build_metadata:
            table.add_row("Build Metadata", version_info.build_metadata)

    elif version_info.version_type == "calver" and version_info.is_valid:
        table.add_row("Year", str(version_info.year))
        table.add_row("Month", str(version_info.month))
        if version_info.day:
            table.add_row("Day", str(version_info.day))
        if version_info.micro:
            table.add_row("Micro", str(version_info.micro))
        if version_info.modifier:
            table.add_row("Modifier", version_info.modifier)

    console.print(table)

    # Display errors if any
    if version_info.errors:
        console.print("\n[bold red]Errors:[/bold red]")
        for error in version_info.errors:
            console.print(f"  • {error}", style="red")


if __name__ == "__main__":
    app()
