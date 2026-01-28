# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for credential security and masking.

This module verifies that sensitive credentials (passwords) are never
exposed in string representations, logging, or error messages.
"""

from tag_validate.gerrit_keys import GerritKeysClient
from tag_validate.models import ValidationConfig
from tag_validate.workflow import ValidationWorkflow


class TestCredentialMasking:
    """Test that credentials are properly masked in various contexts."""

    def test_workflow_repr_no_credentials(self):
        """Test ValidationWorkflow repr with no credentials."""
        from unittest.mock import patch

        # Ensure environment variables are not set to avoid test pollution
        with patch.dict(
            "os.environ", {"GERRIT_USERNAME": "", "GERRIT_PASSWORD": ""}, clear=False
        ):
            workflow = ValidationWorkflow(ValidationConfig())

            repr_str = repr(workflow)

            # Should indicate password is not set
            assert "gerrit_password=***not set***" in repr_str
            assert "gerrit_username=None" in repr_str

            # Should NOT contain actual password value
            assert "None" not in repr_str.split("gerrit_password=")[1].split(")")[0]

    def test_workflow_repr_with_credentials(self):
        """Test ValidationWorkflow repr with credentials set."""
        secret_password = "super_secret_password_123"
        username = "testuser"

        workflow = ValidationWorkflow(
            ValidationConfig(),
            gerrit_username=username,
            gerrit_password=secret_password,
        )

        repr_str = repr(workflow)

        # Password should be masked
        assert "gerrit_password=***set***" in repr_str

        # Username should be visible (not sensitive)
        assert f"gerrit_username='{username}'" in repr_str

        # Password value should NEVER appear in repr
        assert secret_password not in repr_str

    def test_workflow_str_with_credentials(self):
        """Test ValidationWorkflow str() with credentials set."""
        secret_password = "super_secret_password_123"

        workflow = ValidationWorkflow(
            ValidationConfig(),
            gerrit_username="testuser",
            gerrit_password=secret_password,
        )

        # str() should use __repr__ and mask password
        str_repr = str(workflow)
        assert secret_password not in str_repr
        assert "***set***" in str_repr

    def test_gerrit_client_repr_no_credentials(self):
        """Test GerritKeysClient repr with no credentials."""
        from unittest.mock import patch

        # Ensure environment variables are not set to avoid test pollution
        with patch.dict(
            "os.environ", {"GERRIT_USERNAME": "", "GERRIT_PASSWORD": ""}, clear=False
        ):
            client = GerritKeysClient(server="gerrit.example.com")

            repr_str = repr(client)

            # Should indicate password is not set
            assert "password=***not set***" in repr_str
            assert "username=None" in repr_str
            assert "server='gerrit.example.com'" in repr_str

    def test_gerrit_client_repr_with_credentials(self):
        """Test GerritKeysClient repr with credentials set."""
        secret_password = "my_secret_gerrit_password"
        username = "gerrit_user"

        client = GerritKeysClient(
            server="gerrit.example.com",
            username=username,
            password=secret_password,
        )

        repr_str = repr(client)

        # Password should be masked
        assert "password=***set***" in repr_str

        # Username should be visible
        assert f"username='{username}'" in repr_str

        # Password value should NEVER appear in repr
        assert secret_password not in repr_str

    def test_gerrit_client_str_with_credentials(self):
        """Test GerritKeysClient str() with credentials set."""
        secret_password = "another_secret_password"

        client = GerritKeysClient(
            server="gerrit.example.com",
            username="user",
            password=secret_password,
        )

        # str() should use __repr__ and mask password
        str_repr = str(client)
        assert secret_password not in str_repr
        assert "***set***" in str_repr

    def test_gerrit_client_repr_with_env_credentials(self):
        """Test GerritKeysClient repr with credentials from environment."""
        from unittest.mock import patch

        secret_password = "env_secret_password"

        with patch.dict(
            "os.environ",
            {
                "GERRIT_USERNAME": "env_user",
                "GERRIT_PASSWORD": secret_password,
            },
        ):
            # Client should pick up env vars
            client = GerritKeysClient(server="gerrit.example.com")

            repr_str = repr(client)

            # Password should still be masked
            assert "password=***set***" in repr_str
            assert secret_password not in repr_str

    def test_multiple_workflows_with_different_credentials(self):
        """Test that multiple workflows correctly mask their own credentials."""
        password1 = "password_one"
        password2 = "password_two"

        workflow1 = ValidationWorkflow(
            ValidationConfig(),
            gerrit_username="user1",
            gerrit_password=password1,
        )

        workflow2 = ValidationWorkflow(
            ValidationConfig(),
            gerrit_username="user2",
            gerrit_password=password2,
        )

        workflow3 = ValidationWorkflow(ValidationConfig())

        repr1 = repr(workflow1)
        repr2 = repr(workflow2)
        repr3 = repr(workflow3)

        # None should contain actual passwords
        assert password1 not in repr1
        assert password2 not in repr2

        # All should show masked status
        assert "***set***" in repr1
        assert "***set***" in repr2
        assert "***not set***" in repr3

        # Usernames should be visible and correct
        assert "'user1'" in repr1
        assert "'user2'" in repr2
        assert "None" in repr3.split("gerrit_username=")[1].split(",")[0]

    def test_format_string_with_workflow(self):
        """Test that format strings don't expose credentials."""
        secret_password = "format_test_password"

        workflow = ValidationWorkflow(
            ValidationConfig(),
            gerrit_username="format_user",
            gerrit_password=secret_password,
        )

        # Common formatting scenarios
        formatted1 = f"{workflow}"
        formatted2 = f"Workflow: {workflow!r}"
        formatted3 = f"Workflow: {workflow}"

        # None should contain the password
        assert secret_password not in formatted1
        assert secret_password not in formatted2
        assert secret_password not in formatted3

        # All should show masking
        assert "***set***" in formatted1
        assert "***set***" in formatted2
        assert "***set***" in formatted3
