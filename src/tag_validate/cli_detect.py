# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Implementation of the ``tag-validate detect`` command.

This module inspects a Git tag's signature and reports the signature
type, validity and key material as JSON or as a Rich table.
"""

from pathlib import Path

import typer

from .cli_display import display_signature_info
from .cli_key_common import status_context
from .cli_runtime import (
    console,
    log_unexpected_error,
    suppress_logging_for_json,
)
from .signature import SignatureDetectionError, SignatureDetector


async def run_detect(tag_name: str, repo_path: Path, json_output: bool) -> None:
    """Detect and display signature information for a Git tag."""
    try:
        # Suppress ALL logs when JSON output is requested
        if json_output:
            suppress_logging_for_json()

        # Only show status message when not in JSON mode
        with status_context("[bold green]Detecting signature...", json_output):
            detector = SignatureDetector(repo_path)
            signature_info = await detector.detect_signature(tag_name)

        if json_output:
            console.print_json(
                data={
                    "tag_name": tag_name,
                    "signature_type": signature_info.type,
                    "is_valid": signature_info.verified,
                    "signer": signature_info.signer_email,
                    "key_id": signature_info.key_id,
                    "fingerprint": signature_info.fingerprint,
                }
            )
        else:
            display_signature_info(signature_info, tag_name)

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
        raise typer.Exit(1) from e
    except typer.Exit:
        raise
    except Exception as e:
        if json_output:
            console.print_json(data={"success": False, "error": str(e)})
        else:
            console.print(f"\n[red]❌ Unexpected error:[/red] {e}")
            log_unexpected_error("Unexpected error during signature detection", e)
        raise typer.Exit(1) from e
