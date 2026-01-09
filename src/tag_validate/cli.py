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
from .github_keys import GitHubKeysClient
from .models import KeyVerificationResult, ValidationConfig
from .signature import SignatureDetector, SignatureDetectionError
from .validation import TagValidator
from .workflow import ValidationWorkflow


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

# Initialize Rich console (will be reconfigured for JSON output if needed)
console = Console()

# Configure logging (will be suppressed for JSON output)
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)],
)
logger = logging.getLogger("tag_validate")

# Suppress verbose HTTP logs from httpx (used by dependamerge)
logging.getLogger("httpx").setLevel(logging.WARNING)


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

    if verbose:
        logger.setLevel(logging.DEBUG)
    elif quiet:
        logger.setLevel(logging.ERROR)




@app.command()
def verify_github(
    key_id: str = typer.Argument(
        ...,
        help="GPG key ID (e.g., 'FCE8AAABF53080F6') or SSH fingerprint (e.g., 'SHA256:...')"
    ),
    owner: str = typer.Option(
        ...,
        "--owner",
        "-o",
        help="GitHub username to verify key against",
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
):
    """
    Verify if a specific GPG key ID or SSH fingerprint is registered on GitHub.

    This command directly checks if a key is registered to a GitHub user
    without needing to extract it from a tag signature.

    The key type is auto-detected by default, but can be explicitly specified
    with --type if needed.

    Examples:
        # Auto-detect key type (GPG)
        tag-validate verify-key FCE8AAABF53080F6 --owner torvalds --token $GITHUB_TOKEN

        # Auto-detect key type (SSH)
        tag-validate verify-key "ssh-ed25519 AAAAC3NzaC1..." --owner torvalds --token $GITHUB_TOKEN

        # Explicitly specify type
        tag-validate verify-key FCE8AAABF53080F6 --owner torvalds --type gpg --token $GITHUB_TOKEN
    """
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
                    console.print_json(data={"success": False, "error": error_msg})
                else:
                    console.print(f"\n[red]❌ {error_msg}[/red]")
                raise typer.Exit(1)

            if not json_output:
                console.print(f"\n[bold]Key ID/Fingerprint:[/bold] {key_id}")
                console.print(f"[bold]Key Type:[/bold] {detected_type}" + (" (auto-detected)" if key_type == "auto" else ""))
                console.print(f"[bold]GitHub User:[/bold] @{owner}")

            # Verify key on GitHub
            if json_output:
                async with GitHubKeysClient(token=github_token) as client:
                    if detected_type == "gpg":
                        verification = await client.verify_gpg_key_registered(
                            username=owner,
                            key_id=key_id,
                            check_subkeys=not no_subkeys,
                        )
                    else:  # ssh
                        verification = await client.verify_ssh_key_registered(
                            username=owner,
                            public_key_fingerprint=key_id,
                        )
            else:
                with console.status("[bold green]Verifying key on GitHub..."):
                    async with GitHubKeysClient(token=github_token) as client:
                        if detected_type == "gpg":
                            verification = await client.verify_gpg_key_registered(
                                username=owner,
                                key_id=key_id,
                                check_subkeys=not no_subkeys,
                            )
                        else:  # ssh
                            verification = await client.verify_ssh_key_registered(
                                username=owner,
                                public_key_fingerprint=key_id,
                            )

            # Display results
            if json_output:
                result = {
                    "success": verification.key_registered,
                    "key_type": detected_type,
                    "key_id": key_id,
                    "github_user": owner,
                    "is_registered": verification.key_registered,
                }
                console.print_json(data=result)
            else:
                # Create a mock SignatureInfo for display purposes
                from .models import SignatureInfo
                mock_signature = SignatureInfo(
                    type=detected_type,
                    verified=True,  # We're not verifying a signature, just checking registration
                    key_id=key_id if detected_type == "gpg" else None,
                    fingerprint=key_id if detected_type == "ssh" else None,
                    signer_email=None,
                    signature_data=None,
                )
                _display_verification_result(verification, mock_signature, owner)

            # Exit with appropriate code
            if verification.key_registered:
                raise typer.Exit(0)
            else:
                raise typer.Exit(1)

        except typer.Exit:
            raise
        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e)})
            else:
                console.print(f"\n[red]❌ Error:[/red] {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Unexpected error during verification")
                else:
                    logger.error(f"Unexpected error during verification: {e}")
            raise typer.Exit(1)

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
    else:
        table.add_row("Verified", "✅ Yes" if signature_info.verified else "❌ No")

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
):
    """Display key verification result in a formatted panel."""
    if verification.key_registered:
        panel_style = "green"
        status_icon = "✅"
        status_text = "VERIFIED"
        message = f"The signing key is registered to GitHub user @{owner}"
    else:
        panel_style = "red"
        status_icon = "❌"
        status_text = "NOT VERIFIED"
        message = f"The signing key is NOT registered to GitHub user @{owner}"

    content = f"""
[bold]{status_icon} {status_text}[/bold]

{message}

[bold]Details:[/bold]
  • Signature Type: {signature_info.type}
  • Key ID: {signature_info.key_id or 'N/A'}
  • Fingerprint: {signature_info.fingerprint or 'N/A'}
  • Signer: {signature_info.signer_email or 'N/A'}
  • GitHub User: @{owner}
  • Matched Key: N/A
"""

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
        help="Require specific version type (semver or calver)",
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
                    version_type="unknown",
                    is_valid=True,
                    has_prefix=version_string[0:1] in ("v", "V") if version_string else False,
                    is_development=any(kw in version_string.lower() for kw in
                        ["dev", "pre", "alpha", "beta", "rc", "snapshot", "nightly", "canary", "preview"]),
                    # SemVer fields (all None for unknown type)
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

        # Check if specific type is required (skip if require_type is "none")
        if require_type and require_type.lower() != "none" and result.is_valid:
            if result.version_type != require_type:
                if json_output:
                    output = {
                        "success": False,
                        "error": f"Version type mismatch: expected {require_type}, got {result.version_type}",
                        "version": version_string,
                        "detected_type": result.version_type,
                    }
                    console.print_json(data=output)
                else:
                    console.print(
                        f"\n[red]❌ Version type mismatch:[/red] "
                        f"expected {require_type}, got {result.version_type}"
                    )
                raise typer.Exit(1)

        # Output results
        if json_output:
            output = {
                "success": result.is_valid,
                "version": version_string,
                "normalized": result.normalized,
                "version_type": result.version_type,
                "is_valid": result.is_valid,
                "has_prefix": result.has_prefix,
                "is_development": result.is_development,  # Keep for backwards compatibility
                "development_tag": result.is_development,  # New consistent name
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

            console.print_json(data=output)
        else:
            _display_version_info(result, version_string)

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
        help="Require specific version type (semver or calver)",
    ),
    require_signed: Optional[str] = typer.Option(
        None,
        "--require-signed",
        help="Require tag signature. Values: true (any verified), gpg, ssh, gpg-unverifiable, signed (any including unverified), false (must be unsigned), or omit for no requirement",
    ),
    verify_github_key: bool = typer.Option(
        False,
        "--verify-github-key",
        help="Verify signing key is registered on GitHub",
    ),
    owner: Optional[str] = typer.Option(
        None,
        "--owner",
        "-o",
        help="GitHub username for key verification (optional, auto-detected from tagger email if not provided)",
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--token",
        envvar="GITHUB_TOKEN",
        help="GitHub API token (or set GITHUB_TOKEN env var)",
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
    When --verify-github-key is used without --owner, the tool will automatically
    detect the GitHub username from the tagger's email address by searching GitHub's
    commit history. This makes validation easier as you don't need to manually
    specify the owner.

    Examples:
        # Validate local tag
        tag-validate verify v1.2.3

        # Require SemVer and signature
        tag-validate verify v1.2.3 --require-type semver --require-signed true

        # Verify GitHub key (auto-detects owner from tagger email)
        tag-validate verify v1.2.3 --verify-github-key --token $GITHUB_TOKEN

        # Validate remote tag with explicit owner
        tag-validate verify torvalds/linux@v6.0 \
          --verify-github-key --owner torvalds --token $GITHUB_TOKEN

        # Reject development versions
        tag-validate verify v1.2.3-beta --reject-development

        # Only verify signature and GitHub key (skip version validation)
        tag-validate verify my-tag --skip-version-validation \
          --verify-github-key --owner username --token $GITHUB_TOKEN
    """
    async def _verify():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Parse require_signed option
            # Support: true, false, gpg, ssh, gpg-unverifiable, signed, ambivalent, or None
            config_require_signed = False
            config_require_unsigned = False

            if require_signed:
                require_signed_lower = require_signed.lower()
                if require_signed_lower in ("true", "1", "yes"):
                    config_require_signed = True
                elif require_signed_lower == "false":
                    config_require_unsigned = True
                elif require_signed_lower == "ambivalent":
                    # Don't set either flag - accept any signature state
                    pass
                elif require_signed_lower in ("gpg", "ssh", "gpg-unverifiable", "signed"):
                    # For now, treat these as require_signed=True
                    # Future enhancement: add specific signature type validation
                    config_require_signed = True
                else:
                    console.print(f"[red]Invalid --require-signed value: {require_signed}[/red]")
                    console.print("Valid values: true, false, gpg, ssh, gpg-unverifiable, signed, ambivalent")
                    raise typer.Exit(1)

            # Build configuration
            config = ValidationConfig(
                require_semver=(require_type == "semver") if not skip_version_validation else False,
                require_calver=(require_type == "calver") if not skip_version_validation else False,
                require_signed=config_require_signed,
                require_unsigned=config_require_unsigned,
                verify_github_key=verify_github_key,
                reject_development=reject_development if not skip_version_validation else False,
                skip_version_validation=skip_version_validation,
            )

            # Create workflow
            workflow = ValidationWorkflow(config, repo_path=repo_path)

            # Run validation
            # Normalize tag location format (handle owner/repo/tag → owner/repo@tag)
            normalized_location = _normalize_tag_location(tag_location)

            try:
                if json_output:
                    result = await workflow.validate_tag_location(
                        tag_location=normalized_location,
                        github_user=owner,
                        github_token=github_token,
                    )
                else:
                    with console.status("[bold green]Validating tag..."):
                        result = await workflow.validate_tag_location(
                            tag_location=normalized_location,
                            github_user=owner,
                            github_token=github_token,
                        )
            except Exception as e:
                # Handle missing tag with permit_missing flag
                if permit_missing and _is_tag_not_found_error(str(e)):
                    if json_output:
                        output = {
                            "success": True,
                            "tag_name": normalized_location,
                            "version_type": "unknown",
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
                        console.print_json(data=output)
                    else:
                        console.print("\n[yellow]⚠️  Tag not found, but permit_missing=true[/yellow]")
                    raise typer.Exit(0)
                else:
                    # Re-raise if not a missing tag error or permit_missing is false
                    raise

            # Check if result failed due to missing tag and permit_missing is enabled
            if permit_missing and not result.is_valid:
                # Check if the errors indicate a missing tag
                error_text = " ".join(result.errors)
                if _is_tag_not_found_error(error_text):
                    if json_output:
                        output = {
                            "success": True,
                            "tag_name": normalized_location,
                            "version_type": "unknown",
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
                        console.print_json(data=output)
                    else:
                        console.print("\n[yellow]⚠️  Tag not found, but permit_missing=true[/yellow]")
                    raise typer.Exit(0)

            # Output results
            if json_output:
                output = {
                    "success": result.is_valid,
                    "tag_name": result.tag_name,
                    "version_type": result.version_info.version_type if result.version_info else None,
                    "signature_type": result.signature_info.type if result.signature_info else None,
                    "signature_verified": result.signature_info.verified if result.signature_info else None,
                    "key_registered": result.key_verification.key_registered if result.key_verification else None,
                    "is_development": result.version_info.is_development if result.version_info else False,  # Keep for backwards compatibility
                    "development_tag": result.version_info.is_development if result.version_info else False,  # New consistent name
                    "has_prefix": result.version_info.has_prefix if result.version_info else False,  # Keep for backwards compatibility
                    "version_prefix": result.version_info.has_prefix if result.version_info else False,  # New consistent name
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
                console.print_json(data=output)
            else:
                _display_validation_result(result, workflow)

            # Exit with appropriate code
            if result.is_valid:
                raise typer.Exit(0)
            else:
                raise typer.Exit(1)

        except typer.Exit:
            # Let typer.Exit pass through without catching
            raise
        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e)})
            else:
                console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.exception("Unexpected error during tag verification")
                else:
                    logger.error(f"Unexpected error during tag verification: {e}")
            raise typer.Exit(1)

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
        title = "✅ Tag Validation: PASSED"
    else:
        panel_style = "red"
        title = "❌ Tag Validation: FAILED"

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
