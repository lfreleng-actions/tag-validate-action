# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Command-line interface for tag-validate.

This module provides a Typer-based CLI for validating Git tags,
verifying cryptographic signatures, and checking key registration on GitHub.
"""

import asyncio
import logging
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

# Initialize Typer app
app = typer.Typer(
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


def _suppress_logging_for_json():
    """Suppress all logging output for JSON mode."""
    # Disable all logging
    logging.disable(logging.CRITICAL)
    # Also suppress the root logger
    logging.getLogger().setLevel(logging.CRITICAL)
    logging.getLogger("tag_validate").setLevel(logging.CRITICAL)


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
def verify_key(
    tag_name: str = typer.Argument(
        ...,
        help="Name of the Git tag to verify"
    ),
    repo_path: Path = typer.Option(
        Path.cwd(),
        "--repo-path",
        "-r",
        help="Path to the Git repository",
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    owner: str = typer.Option(
        ...,
        "--owner",
        "-o",
        help="GitHub username to verify key against",
    ),
    github_token: Optional[str] = typer.Option(
        None,
        "--token",
        "-t",
        envvar="GITHUB_TOKEN",
        help="GitHub API token (or set GITHUB_TOKEN env var)",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON",
    ),
):
    """
    Verify if the key used to sign a tag is registered on GitHub.

    This command:
    1. Detects the signature on the specified tag
    2. Extracts the key ID or fingerprint
    3. Queries GitHub to verify if the key is registered to the specified user
    4. Reports the verification result

    Example:
        tag-validate verify-key v1.0.0 --owner torvalds --token $GITHUB_TOKEN
    """
    async def _verify():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Step 1: Detect signature
            if json_output:
                detector = SignatureDetector(repo_path)
                signature_info = await detector.detect_signature(tag_name)
            else:
                with console.status("[bold green]Detecting signature..."):
                    detector = SignatureDetector(repo_path)
                    signature_info = await detector.detect_signature(tag_name)

            if not json_output:
                console.print(f"\n[bold]Tag:[/bold] {tag_name}")
                console.print(f"[bold]Signature Type:[/bold] {signature_info.signature_type.value}")
                console.print(f"[bold]Valid Signature:[/bold] {signature_info.is_valid}")

            # Check if tag is signed
            if signature_info.type == "unsigned":
                if json_output:
                    result = {
                        "success": False,
                        "error": "Tag is not signed",
                        "tag_name": tag_name,
                        "signature_type": signature_info.type,
                    }
                    console.print_json(data=result)
                else:
                    console.print("\n[red]❌ Tag is not signed[/red]")
                raise typer.Exit(1)

            if not signature_info.is_valid:
                if json_output:
                    result = {
                        "success": False,
                        "error": "Signature is invalid",
                        "tag_name": tag_name,
                        "signature_type": signature_info.type,
                        "key_id": signature_info.key_id,
                    }
                    console.print_json(data=result)
                else:
                    console.print("\n[red]❌ Signature is invalid[/red]")
                raise typer.Exit(1)

            # Step 2: Verify key on GitHub
            if json_output:
                async with GitHubKeysClient(token=github_token) as client:
                    if signature_info.type == "gpg":
                        if not signature_info.key_id:
                            raise ValueError("GPG key ID not found in signature")

                        verification = await client.verify_gpg_key_registered(
                            username=owner,
                            key_id=signature_info.key_id,
                        )
                    elif signature_info.type == "ssh":
                        if not signature_info.fingerprint:
                            raise ValueError("SSH key fingerprint not found in signature")

                        verification = await client.verify_ssh_key_registered(
                            username=owner,
                            fingerprint=signature_info.fingerprint,
                        )
                    else:
                        raise ValueError(f"Unsupported signature type: {signature_info.type}")
            else:
                with console.status("[bold green]Verifying key on GitHub..."):
                    async with GitHubKeysClient(token=github_token) as client:
                        if signature_info.type == "gpg":
                            if not signature_info.key_id:
                                raise ValueError("GPG key ID not found in signature")

                            verification = await client.verify_gpg_key_registered(
                                username=owner,
                                key_id=signature_info.key_id,
                            )
                        elif signature_info.type == "ssh":
                            if not signature_info.fingerprint:
                                raise ValueError("SSH key fingerprint not found in signature")

                            verification = await client.verify_ssh_key_registered(
                                username=owner,
                                fingerprint=signature_info.fingerprint,
                            )
                        else:
                            raise ValueError(f"Unsupported signature type: {signature_info.type}")

            # Step 3: Display results
            if json_output:
                result = {
                    "success": verification.key_registered,
                    "tag_name": tag_name,
                    "signature_type": signature_info.type,
                    "key_id": signature_info.key_id,
                    "fingerprint": signature_info.fingerprint,
                    "signer": signature_info.signer,
                    "github_user": owner,
                    "is_registered": verification.key_registered,
                    "matched_key_id": None  # matched_key_id not in model,
                }
                console.print_json(data=result)
            else:
                _display_verification_result(verification, signature_info, owner)

            # Exit with appropriate code
            if verification.key_registered:
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
                logger.exception("Unexpected error during verification")
            raise typer.Exit(1)

    # Run async function
    asyncio.run(_verify())


@app.command()
def detect_signature(
    tag_name: str = typer.Argument(
        ...,
        help="Name of the Git tag to analyze"
    ),
    repo_path: Path = typer.Option(
        Path.cwd(),
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
        tag-validate detect-signature v1.0.0
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
                logger.exception("Unexpected error during signature detection")
            raise typer.Exit(1)

    # Run async function
    asyncio.run(_detect())


def _display_signature_info(signature_info, tag_name: str):
    """Display signature information in a formatted table."""
    table = Table(title=f"Signature Information for Tag: {tag_name}")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")

    table.add_row("Signature Type", signature_info.type)
    table.add_row("Valid", "✅ Yes" if signature_info.verified else "❌ No")

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
def validate_version(
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
        tag-validate validate-version v1.2.3
        tag-validate validate-version 2024.01.15
        tag-validate validate-version v1.0.0-beta --require-type semver
        tag-validate validate-version 1.2.3 --strict-semver
    """
    try:
        # Suppress ALL logs when JSON output is requested
        if json_output:
            _suppress_logging_for_json()

        validator = TagValidator()

        # Validate the version
        result = validator.validate_version(
            version_string,
            allow_prefix=allow_prefix,
            strict_semver=strict_semver,
        )

        # Check if specific type is required
        if require_type and result.is_valid:
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
                "is_development": result.is_development,
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
            logger.exception("Unexpected error during version validation")
        raise typer.Exit(1)


@app.command()
def verify_tag(
    tag_location: str = typer.Argument(
        ...,
        help="Tag location: tag name, or owner/repo@tag for remote"
    ),
    repo_path: Path = typer.Option(
        Path.cwd(),
        "--repo-path",
        "-r",
        help="Path to the Git repository (for local tags)",
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
    require_signed: bool = typer.Option(
        False,
        "--require-signed",
        help="Require tag to be signed",
    ),
    verify_github_key: bool = typer.Option(
        False,
        "--verify-github-key",
        help="Verify signing key is registered on GitHub",
    ),
    github_user: Optional[str] = typer.Option(
        None,
        "--github-user",
        "-u",
        help="GitHub username for key verification",
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

    Supports both local tags and remote tags:
    - Local: tag-validate verify-tag v1.2.3
    - Remote: tag-validate verify-tag owner/repo@v1.2.3

    Examples:
        # Validate local tag
        tag-validate verify-tag v1.2.3

        # Require SemVer and signature
        tag-validate verify-tag v1.2.3 --require-type semver --require-signed

        # Validate remote tag with GitHub key verification
        tag-validate verify-tag torvalds/linux@v6.0 \\
            --verify-github-key --github-user torvalds --token $GITHUB_TOKEN

        # Reject development versions
        tag-validate verify-tag v1.2.3-beta --reject-development
    """
    async def _verify():
        try:
            # Suppress ALL logs when JSON output is requested
            if json_output:
                _suppress_logging_for_json()

            # Build configuration
            config = ValidationConfig(
                require_semver=(require_type == "semver"),
                require_calver=(require_type == "calver"),
                require_signed=require_signed,
                verify_github_key=verify_github_key,
                reject_development=reject_development,
            )

            # Create workflow
            workflow = ValidationWorkflow(config, repo_path=repo_path)

            # Run validation
            if json_output:
                result = await workflow.validate_tag_location(
                    tag_location=tag_location,
                    github_user=github_user,
                    github_token=github_token,
                )
            else:
                with console.status("[bold green]Validating tag..."):
                    result = await workflow.validate_tag_location(
                        tag_location=tag_location,
                        github_user=github_user,
                        github_token=github_token,
                    )

            # Output results
            if json_output:
                output = {
                    "success": result.is_valid,
                    "tag_name": result.tag_name,
                    "version_type": result.version_info.version_type if result.version_info else None,
                    "signature_type": result.signature_info.type if result.signature_info else None,
                    "signature_verified": result.signature_info.verified if result.signature_info else None,
                    "key_registered": result.key_verification.key_registered if result.key_verification else None,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "info": result.info,
                }
                console.print_json(data=output)
            else:
                _display_validation_result(result, workflow)

            # Exit with appropriate code
            if result.is_valid:
                raise typer.Exit(0)
            else:
                raise typer.Exit(1)

        except Exception as e:
            if json_output:
                console.print_json(data={"success": False, "error": str(e)})
            else:
                console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
                logger.exception("Unexpected error during tag verification")
            raise typer.Exit(1)

    # Run async function
    asyncio.run(_verify())


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
