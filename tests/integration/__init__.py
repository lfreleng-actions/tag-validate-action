# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""Integration tests package for tag-validate.

This package contains integration tests that interact with real Git repositories
and external services. These tests are marked with @pytest.mark.integration and
can be run separately from unit tests.

To run only integration tests:
    pytest tests/integration -v -m integration

To skip integration tests:
    pytest tests/ -v -m "not integration"
"""
