# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""
GitHub user and commit lookups used during key verification.

Provides the account metadata, email-to-username resolution, and commit
signature verification calls that complement the key registry queries.
"""

from .github_keys_base import GitHubKeysClientBase
from .models import GitHubVerificationInfo


class GitHubUserLookupMixin(GitHubKeysClientBase):
    """User, email, and commit verification lookups against GitHub's API."""

    async def get_user_details(self, username: str) -> dict | None:
        """
        Get detailed user information from GitHub.

        Args:
            username: GitHub username

        Returns:
            Dictionary with user details (login, name, email, etc.)
            or None if user not found

        Raises:
            GitHubKeysError: If API request fails
        """
        client = self._ensure_client()

        try:
            # Get user details from GitHub API
            response = await client.get(f"/users/{username}")

            if not isinstance(response, dict):
                self.logger.debug(
                    f"Unexpected response type for user details: {type(response)}"
                )
                return None

            return {
                "login": response.get("login"),
                "name": response.get("name"),
                "email": response.get("email"),
                "bio": response.get("bio"),
                "company": response.get("company"),
                "location": response.get("location"),
            }

        except Exception as e:
            self.logger.debug(f"Error getting user details for {username}: {e}")
            return None

    async def lookup_username_by_email(self, email: str) -> str | None:
        """Lookup GitHub username from email using commit search API.

        This uses the GitHub Search API to find commits authored by the given
        email address, then extracts the username from the commit author.

        Args:
            email: Email address to look up

        Returns:
            GitHub username if found, None otherwise

        Example:
            >>> username = await client.lookup_username_by_email("user@example.com")
            >>> if username:
            ...     print(f"Found username: {username}")
        """
        client = self._ensure_client()

        self.logger.debug(f"Looking up GitHub username for email: {email}")

        try:
            # Use commit search API to find commits by this email
            response = await client.get(
                "/search/commits", params={"q": f"author-email:{email}"}
            )

            if not isinstance(response, dict):
                self.logger.debug(
                    f"Unexpected response type from commit search: {type(response)}"
                )
                return None

            items = response.get("items", [])
            if not items or len(items) == 0:
                self.logger.debug(f"No commits found for email: {email}")
                return None

            # Get username from first commit's author
            author = items[0].get("author")
            if author and "login" in author:
                username = author["login"]
                if isinstance(username, str):
                    self.logger.debug(
                        f"Found GitHub username '{username}' for email {email}"
                    )
                    return username

            self.logger.debug(f"No author information in commit for email: {email}")
            return None

        except Exception as e:
            self.logger.debug(f"Failed to lookup username for email {email}: {e}")
            return None

    async def get_commit_verification(
        self,
        owner: str,
        repo: str,
        ref: str,
    ) -> GitHubVerificationInfo | None:
        """
        Get GitHub's verification information for a commit.

        This fetches the commit data from GitHub's API which includes
        a verification object describing GitHub's analysis of the signature.

        Args:
            owner: Repository owner (user or organization).
            repo: Repository name.
            ref: Git reference (commit SHA, branch name, or tag name).

        Returns:
            GitHubVerificationInfo if available, None if no verification data.

        Raises:
            Exception: If the API request fails.

        Example:
            >>> info = await client.get_commit_verification(
            ...     "octocat", "Hello-World", "v1.0.0"
            ... )
            >>> if info and info.verified:
            ...     print(f"GitHub verified: {info.reason}")
        """
        client = self._ensure_client()

        self.logger.debug(f"Fetching commit verification for {owner}/{repo}@{ref}")

        try:
            response = await client.get(f"/repos/{owner}/{repo}/commits/{ref}")

            if not isinstance(response, dict):
                self.logger.error(
                    f"Unexpected response type for commit: {type(response)}"
                )
                return None

            commit_data = response.get("commit", {})
            verification_data = commit_data.get("verification")

            if not verification_data:
                self.logger.debug("No verification data in commit response")
                return None

            # Parse verification data
            return GitHubVerificationInfo(
                verified=verification_data.get("verified", False),
                reason=verification_data.get("reason", "unsigned"),
                signature=verification_data.get("signature"),
                payload=verification_data.get("payload"),
            )

        except Exception as e:
            self.logger.warning(f"Failed to fetch commit verification: {e}")
            # Don't raise - this is optional information
            return None


__all__ = ["GitHubUserLookupMixin"]
