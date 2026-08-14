# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Command-line interface for tag-validate.

This module provides a Typer-based CLI for validating Git tags,
verifying cryptographic signatures, and checking key registration on GitHub.

The command surface is declared here; the behaviour behind each command
lives in the sibling ``cli_*`` modules.
"""

import asyncio
import logging
import sys
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .cli_detect import run_detect
from .cli_gerrit import GerritOptions, run_gerrit_test_mode, run_gerrit_verification
from .cli_github import GitHubOptions, run_github_test_mode, run_github_verification
from .cli_help import (
    DETECT_HELP,
    GERRIT_HELP,
    GITHUB_HELP,
    VALIDATE_HELP,
    VERIFY_HELP,
)
from .cli_keys import normalize_ssh_fingerprint as _normalize_ssh_fingerprint
from .cli_options import (
    DETECT_JSON_OUTPUT,
    DETECT_REPO_PATH,
    DETECT_TAG_NAME,
    GERRIT_GERRIT_PASSWORD,
    GERRIT_GERRIT_USERNAME,
    GERRIT_GITHUB_ORG,
    GERRIT_JSON_OUTPUT,
    GERRIT_KEY_ID,
    GERRIT_KEY_TYPE,
    GERRIT_NETRC_FILE,
    GERRIT_NETRC_OPTIONAL,
    GERRIT_NO_NETRC,
    GERRIT_OWNER,
    GERRIT_SERVER,
    GERRIT_TEST_MODE,
    GITHUB_API_URL,
    GITHUB_GITHUB_TOKEN,
    GITHUB_GRAPHQL_URL,
    GITHUB_JSON_OUTPUT,
    GITHUB_KEY_ID,
    GITHUB_KEY_TYPE,
    GITHUB_NO_SUBKEYS,
    GITHUB_OWNER,
    GITHUB_TEST_MODE,
    MAIN_DEBUG,
    MAIN_QUIET,
    MAIN_VERBOSE,
    MAIN_VERSION,
)
from .cli_options_tag import (
    VALIDATE_ALLOW_PREFIX,
    VALIDATE_JSON_FILE,
    VALIDATE_JSON_OUTPUT,
    VALIDATE_REQUIRE_TYPE,
    VALIDATE_STRICT_SEMVER,
    VALIDATE_VERSION_STRING,
    VERIFY_ENFORCE_INCREMENT,
    VERIFY_GERRIT_PASSWORD,
    VERIFY_GERRIT_USERNAME,
    VERIFY_GITHUB_STEP_SUMMARY,
    VERIFY_GITHUB_TOKEN,
    VERIFY_JSON_FILE,
    VERIFY_JSON_OUTPUT,
    VERIFY_NETRC_FILE,
    VERIFY_NETRC_OPTIONAL,
    VERIFY_NO_NETRC,
    VERIFY_OWNER,
    VERIFY_PERMIT_MISSING,
    VERIFY_REJECT_DEVELOPMENT,
    VERIFY_REPO_PATH,
    VERIFY_REQUIRE_BRANCH,
    VERIFY_REQUIRE_GERRIT,
    VERIFY_REQUIRE_GITHUB,
    VERIFY_REQUIRE_LATEST,
    VERIFY_REQUIRE_OWNER,
    VERIFY_REQUIRE_RECENT,
    VERIFY_REQUIRE_SIGNED,
    VERIFY_REQUIRE_TYPE,
    VERIFY_SKIP_VERSION_VALIDATION,
    VERIFY_TAG_LOCATION,
)
from .cli_parsing import (
    check_version_type_match,
    parse_multi_value_option,
    validate_signature_types,
    validate_version_types,
)
from .cli_runtime import (
    console,
    logger,
    process_global_options,
    suppress_logging_for_json,
)
from .cli_validate import run_validate
from .cli_verify import run_verify
from .cli_verify_config import VerifyOptions
from .gerrit_keys import GerritKeysClient
from .github_keys import GitHubKeysClient
from .netrc import get_credentials_for_host
from .workflow import ValidationWorkflow

# Names re-exported for callers (and tests) that reach for them here
__all__ = [
    "GerritKeysClient",
    "GitHubKeysClient",
    "ValidationWorkflow",
    "_normalize_ssh_fingerprint",
    "app",
    "check_version_type_match",
    "console",
    "get_credentials_for_host",
    "parse_multi_value_option",
    "validate_signature_types",
    "validate_version_types",
]


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

# Process global options after logger is defined
verbose, debug = process_global_options()
if verbose or debug:
    logging.getLogger().setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)

# Suppress verbose HTTP logs from httpx (used by dependamerge)
logging.getLogger("httpx").setLevel(logging.WARNING)


@app.callback()
def main(
    ctx: typer.Context,
    version: bool | None = MAIN_VERSION,
    verbose: bool = MAIN_VERBOSE,
    debug: bool = MAIN_DEBUG,
    quiet: bool = MAIN_QUIET,
):
    """
    Tag validation tool with cryptographic signature verification.
    """
    # Check if --json flag is present in any command
    # This must be done early to suppress logging before commands execute
    if "--json" in sys.argv or "-j" in sys.argv:
        suppress_logging_for_json()
        return

    if verbose or debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)
        logger.setLevel(logging.ERROR)


@app.command(name="gerrit", help=GERRIT_HELP)
def verify_gerrit(
    key_id: str = GERRIT_KEY_ID,
    owner: str = GERRIT_OWNER,
    key_type: str = GERRIT_KEY_TYPE,
    server: str | None = GERRIT_SERVER,
    github_org: str | None = GERRIT_GITHUB_ORG,
    gerrit_username: str | None = GERRIT_GERRIT_USERNAME,
    gerrit_password: str | None = GERRIT_GERRIT_PASSWORD,
    no_netrc: bool = GERRIT_NO_NETRC,
    netrc_file: Path | None = GERRIT_NETRC_FILE,
    netrc_optional: bool = GERRIT_NETRC_OPTIONAL,
    json_output: bool = GERRIT_JSON_OUTPUT,
    test_mode: bool = GERRIT_TEST_MODE,
):
    # Handle test mode first, before any other validations
    if test_mode:
        asyncio.run(run_gerrit_test_mode(key_id, key_type, json_output))
        return

    options = GerritOptions(
        key_id=key_id,
        owner=owner,
        key_type=key_type,
        server=server,
        github_org=github_org,
        gerrit_username=gerrit_username,
        gerrit_password=gerrit_password,
        no_netrc=no_netrc,
        netrc_file=netrc_file,
        netrc_optional=netrc_optional,
        json_output=json_output,
    )
    asyncio.run(
        run_gerrit_verification(
            options,
            keys_client_cls=GerritKeysClient,
            credentials_lookup=get_credentials_for_host,
        )
    )


@app.command(name="github", help=GITHUB_HELP)
def verify_github(
    key_id: str = GITHUB_KEY_ID,
    owner: str = GITHUB_OWNER,
    key_type: str = GITHUB_KEY_TYPE,
    github_token: str | None = GITHUB_GITHUB_TOKEN,
    json_output: bool = GITHUB_JSON_OUTPUT,
    no_subkeys: bool = GITHUB_NO_SUBKEYS,
    api_url: str = GITHUB_API_URL,
    graphql_url: str = GITHUB_GRAPHQL_URL,
    test_mode: bool = GITHUB_TEST_MODE,
):
    # Handle test mode first, before any other validations
    if test_mode:
        asyncio.run(run_github_test_mode(key_id, key_type, owner, json_output))
        return

    options = GitHubOptions(
        key_id=key_id,
        owner=owner,
        key_type=key_type,
        github_token=github_token,
        no_subkeys=no_subkeys,
        api_url=api_url,
        graphql_url=graphql_url,
        json_output=json_output,
    )
    asyncio.run(run_github_verification(options, keys_client_cls=GitHubKeysClient))


@app.command(help=DETECT_HELP)
def detect(
    tag_name: str = DETECT_TAG_NAME,
    repo_path: Path = DETECT_REPO_PATH,
    json_output: bool = DETECT_JSON_OUTPUT,
):
    asyncio.run(run_detect(tag_name, repo_path, json_output))


@app.command(help=VALIDATE_HELP)
def validate(
    version_string: str = VALIDATE_VERSION_STRING,
    require_type: str | None = VALIDATE_REQUIRE_TYPE,
    allow_prefix: bool = VALIDATE_ALLOW_PREFIX,
    strict_semver: bool = VALIDATE_STRICT_SEMVER,
    json_output: bool = VALIDATE_JSON_OUTPUT,
    json_file: Path | None = VALIDATE_JSON_FILE,
):
    run_validate(
        version_string=version_string,
        require_type=require_type,
        allow_prefix=allow_prefix,
        strict_semver=strict_semver,
        json_output=json_output,
        json_file=json_file,
    )


@app.command(help=VERIFY_HELP)
def verify(
    tag_location: str = VERIFY_TAG_LOCATION,
    repo_path: Path = VERIFY_REPO_PATH,
    require_type: str | None = VERIFY_REQUIRE_TYPE,
    require_signed: str | None = VERIFY_REQUIRE_SIGNED,
    require_github: bool = VERIFY_REQUIRE_GITHUB,
    require_gerrit: str | None = VERIFY_REQUIRE_GERRIT,
    owner: str | None = VERIFY_OWNER,
    require_owner: str | None = VERIFY_REQUIRE_OWNER,
    github_token: str | None = VERIFY_GITHUB_TOKEN,
    gerrit_username: str | None = VERIFY_GERRIT_USERNAME,
    gerrit_password: str | None = VERIFY_GERRIT_PASSWORD,
    no_netrc: bool = VERIFY_NO_NETRC,
    netrc_file: Path | None = VERIFY_NETRC_FILE,
    netrc_optional: bool = VERIFY_NETRC_OPTIONAL,
    reject_development: bool = VERIFY_REJECT_DEVELOPMENT,
    enforce_increment: bool = VERIFY_ENFORCE_INCREMENT,
    require_branch: str | None = VERIFY_REQUIRE_BRANCH,
    require_recent: str | None = VERIFY_REQUIRE_RECENT,
    require_latest: bool = VERIFY_REQUIRE_LATEST,
    skip_version_validation: bool = VERIFY_SKIP_VERSION_VALIDATION,
    permit_missing: bool = VERIFY_PERMIT_MISSING,
    json_output: bool = VERIFY_JSON_OUTPUT,
    json_file: Path | None = VERIFY_JSON_FILE,
    github_step_summary: bool = VERIFY_GITHUB_STEP_SUMMARY,
):
    options = VerifyOptions(
        tag_location=tag_location,
        repo_path=repo_path,
        require_type=require_type,
        require_signed=require_signed,
        require_github=require_github,
        require_gerrit=require_gerrit,
        owner=owner,
        require_owner=require_owner,
        github_token=github_token,
        gerrit_username=gerrit_username,
        gerrit_password=gerrit_password,
        no_netrc=no_netrc,
        netrc_file=netrc_file,
        netrc_optional=netrc_optional,
        reject_development=reject_development,
        enforce_increment=enforce_increment,
        require_branch=require_branch,
        require_recent=require_recent,
        require_latest=require_latest,
        skip_version_validation=skip_version_validation,
        permit_missing=permit_missing,
        json_output=json_output,
        json_file=json_file,
        github_step_summary=github_step_summary,
    )
    asyncio.run(
        run_verify(
            options,
            workflow_cls=ValidationWorkflow,
            credentials_lookup=get_credentials_for_host,
        )
    )


if __name__ == "__main__":
    app()
