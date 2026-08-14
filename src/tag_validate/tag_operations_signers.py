# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""SSH allowed-signers discovery for tag verification.

Git can only verify an SSH-signed tag when it has an allowed-signers
file. This module locates one from the usual places and installs it into
the repository that verification will run against.
"""

import logging
from pathlib import Path

# Bound to the public module's name so log records keep reporting
# `tag_validate.tag_operations` no matter which sibling module emits them.
logger = logging.getLogger(f"{__package__}.tag_operations")


class SshAllowedSignersMixin:
    """Allowed-signers discovery shared by :class:`TagOperations`."""

    async def _setup_ssh_allowed_signers(self, repo_path: Path) -> None:
        """Setup SSH allowed signers file with smart fallback.

        Checks multiple locations in priority order:
        1. Already exists in cloned repository (committed file)
        2. Current working directory (.ssh-allowed-signers)
        3. Git config (gpg.ssh.allowedSignersFile)
        4. Home directory (~/.ssh/allowed_signers)
        5. XDG config directory (~/.config/git/allowed_signers)

        Args:
            repo_path: Path to repository where SSH verification will occur
        """
        import shutil

        # Resolved through the public module so that anything patching
        # `tag_validate.tag_operations.run_git` still intercepts these calls.
        from . import tag_operations

        # Check if file already exists in the cloned repository
        repo_signers = repo_path / ".ssh-allowed-signers"
        if repo_signers.exists():
            logger.debug("Using .ssh-allowed-signers from cloned repository")
            tag_operations.run_git(
                ["git", "config", "gpg.ssh.allowedSignersFile", ".ssh-allowed-signers"],
                cwd=repo_path,
            )
            return

        # Try to find allowed signers file in fallback locations
        signers_file = None
        source_description = None

        # 1. Current working directory
        cwd_signers = Path.cwd() / ".ssh-allowed-signers"
        logger.debug(f"Checking for signers file in current directory: {cwd_signers}")
        if cwd_signers.exists():
            signers_file = cwd_signers
            source_description = "current directory"
            logger.debug("Found signers file in current directory")

        # 2. Action directory (when running as GitHub Action)
        # Check if GITHUB_ACTION_PATH is set and look there
        if not signers_file:
            import os

            action_path = os.environ.get("GITHUB_ACTION_PATH")
            if action_path:
                action_signers = Path(action_path) / ".ssh-allowed-signers"
                logger.debug(
                    f"Checking for signers file in action directory: {action_signers}"
                )
                if action_signers.exists():
                    signers_file = action_signers
                    source_description = "GitHub Action directory"
                    logger.debug("Found signers file in action directory")

        # 3. Git config
        if not signers_file:
            try:
                result = tag_operations.run_git(
                    ["git", "config", "--get", "gpg.ssh.allowedSignersFile"]
                )
                if result.stdout.strip():
                    config_path = Path(result.stdout.strip()).expanduser()
                    if config_path.exists():
                        signers_file = config_path
                        source_description = "git config"
            except Exception as exc:
                logger.debug(
                    "Failed to read gpg.ssh.allowedSignersFile from git config; "
                    "continuing with fallback locations: %s",
                    exc,
                )

        # 4. Home directory standard location
        if not signers_file:
            home_signers = Path.home() / ".ssh" / "allowed_signers"
            if home_signers.exists():
                signers_file = home_signers
                source_description = "~/.ssh/allowed_signers"

        # 5. XDG config directory
        if not signers_file:
            xdg_signers = Path.home() / ".config" / "git" / "allowed_signers"
            if xdg_signers.exists():
                signers_file = xdg_signers
                source_description = "~/.config/git/allowed_signers"

        # If we found a signers file, copy it and configure Git
        if signers_file:
            dest_signers = repo_path / ".ssh-allowed-signers"
            logger.debug(f"Copying signers file from {signers_file} to {dest_signers}")
            shutil.copy2(signers_file, dest_signers)
            logger.debug(
                f"Copied .ssh-allowed-signers from {source_description} to {repo_path}"
            )

            logger.debug(f"Configuring git in {repo_path} to use .ssh-allowed-signers")
            tag_operations.run_git(
                ["git", "config", "gpg.ssh.allowedSignersFile", ".ssh-allowed-signers"],
                cwd=repo_path,
            )
            logger.debug(
                "Configured Git to use .ssh-allowed-signers for SSH verification"
            )
        else:
            logger.warning(
                f"No .ssh-allowed-signers file found in any fallback location (checked cwd: {Path.cwd()})"
            )
