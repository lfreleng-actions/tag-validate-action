# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Shared runtime state for the tag-validate command-line interface.

This module owns the objects that must be created exactly once for the
CLI process: the Rich console, the logging configuration, and the exit
codes shared by every command implementation.
"""

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

# Exit codes
EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILED = 1
EXIT_MISSING_TOKEN = 2
EXIT_INVALID_INPUT = 3
EXIT_UNEXPECTED_ERROR = 4
EXIT_MISSING_CREDENTIALS = 5  # Required credentials not provided (Gerrit)
EXIT_AUTH_FAILED = 6  # Authentication failed (invalid credentials)
EXIT_NOT_INCREMENTAL = 7  # Tag does not increment the repository version
EXIT_BRANCH_CHECK_FAILED = 8  # Tag commit not reachable from required branch
EXIT_TAG_NOT_RECENT = 9  # Tag not created within the required time window
EXIT_NOT_LATEST = 10  # Tag commit is not the current branch tip

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


def process_global_options():
    """Process global options like --verbose and --debug from command line args."""
    verbose = False
    debug = False

    # Check for global options and remove them from sys.argv
    new_argv = []
    i = 0
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ["--verbose", "-V"]:
            verbose = True
        elif arg == "--debug":
            debug = True
        else:
            new_argv.append(arg)
        i += 1

    # Update sys.argv
    sys.argv[:] = new_argv

    return verbose, debug


def suppress_logging_for_json():
    """Suppress all logging output for JSON mode."""
    # Disable all logging
    logging.disable(logging.CRITICAL)
    # Also suppress the root logger
    logging.getLogger().setLevel(logging.CRITICAL)
    logging.getLogger("tag_validate").setLevel(logging.CRITICAL)


def report_error(error_msg: str, *, json_output: bool, prefix: str = "") -> None:
    """Report an error either as JSON or as a Rich console message.

    Args:
        error_msg: Human readable error message
        json_output: Whether the command is emitting JSON
        prefix: Optional literal prefix for the console message
    """
    if json_output:
        console.print_json(data={"success": False, "error": error_msg})
    else:
        console.print(f"{prefix}[red]❌ {error_msg}[/red]")


def log_unexpected_error(message: str, error: Exception) -> None:
    """Log an unexpected error with a traceback when debug logging is on."""
    if logger.isEnabledFor(logging.DEBUG):
        logger.exception(message)
    else:
        logger.error(f"{message}: {error}")
