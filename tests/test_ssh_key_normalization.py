# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Comprehensive tests for SSH key normalization functionality.

This module provides extensive unit tests for the _normalize_ssh_fingerprint function,
covering all SSH key formats supported by the tag-validate CLI tool. The tests ensure
proper validation, normalization, and error handling for:

- SHA256 fingerprints (standard and algorithm-prefixed)
- MD5 fingerprints (legacy format and algorithm-prefixed)
- Full SSH public keys (Ed25519, RSA, ECDSA)
- GPG keys and unknown formats (passthrough behavior)
- Edge cases and malformed inputs
- Integration with CLI --test-mode behavior

These tests align with the shell script testing in scripts/test_ssh_keys.sh and
provide comprehensive coverage of the key parsing and normalization logic that
prevents invalid inputs from reaching the GitHub API.

Test Categories:
- TestSHA256Fingerprints: Standard SHA256 format validation
- TestMD5Fingerprints: Legacy MD5 format validation
- TestFullPublicKeys: Complete SSH public key handling
- TestNonSSHKeys: GPG keys and unknown format passthrough
- TestEdgeCases: Boundary conditions and complex scenarios
- TestAllShellScriptFormats: Complete shell script coverage
- TestCLIIntegration: Unit test vs CLI behavior verification
"""

import base64

import pytest

from tag_validate.cli import _normalize_ssh_fingerprint


class TestSHA256Fingerprints:
    """Test SHA256 fingerprint normalization and validation."""

    def test_valid_sha256_fingerprints(self):
        """Test that valid SHA256 fingerprints are normalized correctly."""
        test_cases = [
            # Standard SHA256 format
            (
                "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            ),
            (
                "SHA256:lSpWQv6rFamTP2i93lIaLO8s8TZg/t06GsxrjQ5GAXY",
                "SHA256:lSpWQv6rFamTP2i93lIaLO8s8TZg/t06GsxrjQ5GAXY",
            ),
            (
                "SHA256:oitgrhcEWqRZ248fv26IaaN8TT26bXTr6y65ylS/EcI",
                "SHA256:oitgrhcEWqRZ248fv26IaaN8TT26bXTr6y65ylS/EcI",
            ),
            (
                "SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
                "SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
            ),
            (
                "SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
                "SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
            ),
            (
                "SHA256:xzmyjKD2ZBtadsgr2q0Bzu9B5sw4nAFeu69ZMb1MKNA",
                "SHA256:xzmyjKD2ZBtadsgr2q0Bzu9B5sw4nAFeu69ZMb1MKNA",
            ),
            # Known working key
            (
                "SHA256:ZdI8Rev5CBKfs3Uywh3Nta59BfXcqiQ/3tG0pdjY/5Q",
                "SHA256:ZdI8Rev5CBKfs3Uywh3Nta59BfXcqiQ/3tG0pdjY/5Q",
            ),
        ]

        for input_key, expected_output in test_cases:
            result = _normalize_ssh_fingerprint(input_key)
            assert result == expected_output, f"Failed for input: {input_key}"

    def test_algorithm_prefixed_sha256_fingerprints(self):
        """Test that algorithm-prefixed SHA256 fingerprints are normalized correctly."""
        test_cases = [
            # ECDSA prefixed
            (
                "ECDSA:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            ),
            # ED25519 prefixed
            (
                "ED25519:SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
                "SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
            ),
            # RSA prefixed
            (
                "RSA:SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
                "SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
            ),
            # Mixed case algorithm prefixes
            (
                "ecdsa:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            ),
            (
                "ed25519:SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
                "SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
            ),
            (
                "rsa:SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
                "SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
            ),
        ]

        for input_key, expected_output in test_cases:
            result = _normalize_ssh_fingerprint(input_key)
            assert result == expected_output, f"Failed for input: {input_key}"

    def test_invalid_sha256_fingerprints(self):
        """Test that invalid SHA256 fingerprints raise appropriate errors."""
        invalid_cases = [
            # Empty fingerprint
            ("SHA256:", "SHA256 fingerprint cannot be empty"),
            ("ECDSA:SHA256:", "SHA256 fingerprint cannot be empty"),
            ("RSA:SHA256:", "SHA256 fingerprint cannot be empty"),
            # Invalid Base64 characters
            (
                "SHA256:InvalidBase64!",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
            (
                "SHA256:This@Has#Invalid$Chars",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
            (
                "ECDSA:SHA256:Invalid!",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
        ]

        for invalid_input, expected_error_msg in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                _normalize_ssh_fingerprint(invalid_input)
            assert expected_error_msg in str(exc_info.value), (
                f"Failed for input: {invalid_input}"
            )

    def test_wrong_length_sha256_reports_length_not_encoding(self):
        """Test that valid Base64 of the wrong length names the real fault."""
        wrong_length_cases = [
            # Too short
            ("SHA256:TooShort", 6),
            ("SHA256:VeryShort123", 9),
            # Already padded: 16 bytes encoded as "eHh4...eA=="
            (f"SHA256:{base64.b64encode(b'x' * 16).decode()}", 16),
            # Unpadded form of the same value
            (f"SHA256:{base64.b64encode(b'x' * 16).decode().rstrip('=')}", 16),
            # Too long
            ("SHA256:ThisIsTooLongForASHA256FingerprintAndShouldFail12345", 39),
            # 44 unpadded data characters: matched the old fast-path pattern
            # and so escaped validation entirely, despite decoding to 33 bytes
            (f"SHA256:{'A' * 44}", 33),
        ]

        for invalid_input, decoded_length in wrong_length_cases:
            with pytest.raises(ValueError) as exc_info:
                _normalize_ssh_fingerprint(invalid_input)
            message = str(exc_info.value)
            assert (
                f"invalid length: expected 32 bytes, got {decoded_length}" in message
            ), f"Failed for input: {invalid_input}"
            assert "invalid Base64 characters" not in message, (
                f"Encoding blamed for a length fault: {invalid_input}"
            )

    def test_padded_sha256_fingerprint_accepted(self):
        """Test that the 43-character-plus-padding form stays valid."""
        padded = base64.b64encode(b"x" * 32).decode()
        assert padded.endswith("=")

        assert _normalize_ssh_fingerprint(f"SHA256:{padded}") == f"SHA256:{padded}"


class TestMD5Fingerprints:
    """Test MD5 fingerprint normalization and validation."""

    def test_valid_md5_fingerprints(self):
        """Test that valid MD5 fingerprints are normalized correctly."""
        test_cases = [
            # Standard MD5 format
            (
                "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            ),
            (
                "MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
                "MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
            ),
            (
                "MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
                "MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
            ),
            (
                "MD5:e0:69:3e:84:68:47:10:31:2c:75:af:e5:c8:57:7a:13",
                "MD5:e0:69:3e:84:68:47:10:31:2c:75:af:e5:c8:57:7a:13",
            ),
            (
                "MD5:3f:18:4a:59:94:81:34:be:9e:54:92:d1:a1:51:8f:70",
                "MD5:3f:18:4a:59:94:81:34:be:9e:54:92:d1:a1:51:8f:70",
            ),
            (
                "MD5:a1:1e:aa:33:b5:50:2c:16:3d:76:be:4c:03:70:5f:96",
                "MD5:a1:1e:aa:33:b5:50:2c:16:3d:76:be:4c:03:70:5f:96",
            ),
            # Mixed case should work
            (
                "MD5:CF:19:30:D7:F9:0D:04:2E:20:CE:3D:24:77:22:22:E3",
                "MD5:CF:19:30:D7:F9:0D:04:2E:20:CE:3D:24:77:22:22:E3",
            ),
        ]

        for input_key, expected_output in test_cases:
            result = _normalize_ssh_fingerprint(input_key)
            assert result == expected_output, f"Failed for input: {input_key}"

    def test_algorithm_prefixed_md5_fingerprints(self):
        """Test that algorithm-prefixed MD5 fingerprints are normalized correctly."""
        test_cases = [
            # ECDSA prefixed
            (
                "ECDSA:MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            ),
            # ED25519 prefixed
            (
                "ED25519:MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
                "MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
            ),
            # RSA prefixed
            (
                "RSA:MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
                "MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
            ),
            # Mixed case algorithm prefixes
            (
                "ecdsa:MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            ),
            (
                "ed25519:MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
                "MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
            ),
            (
                "rsa:MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
                "MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
            ),
        ]

        for input_key, expected_output in test_cases:
            result = _normalize_ssh_fingerprint(input_key)
            assert result == expected_output, f"Failed for input: {input_key}"

    def test_invalid_md5_fingerprints(self):
        """Test that invalid MD5 fingerprints raise appropriate errors."""
        invalid_cases = [
            # Empty fingerprint
            ("MD5:", "MD5 fingerprint cannot be empty"),
            ("ECDSA:MD5:", "MD5 fingerprint cannot be empty"),
            ("RSA:MD5:", "MD5 fingerprint cannot be empty"),
            # Invalid hex characters
            (
                "MD5:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz",
                "MD5 fingerprint contains invalid hex characters",
            ),
            (
                "MD5:gg:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5 fingerprint contains invalid hex characters",
            ),
            (
                "MD5:cf:xy:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5 fingerprint contains invalid hex characters",
            ),
            # Wrong length (too short)
            (
                "MD5:11:22:33",
                "MD5 fingerprint has invalid length: expected 47 characters, got 8",
            ),
            ("MD5:aa:bb:cc:dd:ee:ff", "MD5 fingerprint has invalid length"),
            # Wrong length (too long)
            (
                "MD5:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11",
                "MD5 fingerprint has invalid length",
            ),
            # Missing colons
            (
                "MD5:1122334455667788990aabbccddeeff00",
                "MD5 fingerprint has invalid length",
            ),
            (
                "MD5:cf1930d7f90d042e20ce3d24772222e3",
                "MD5 fingerprint has invalid length",
            ),
            # Wrong hex pair length (these fail length check before hex validation)
            (
                "MD5:c:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5 fingerprint has invalid length",
            ),
            (
                "MD5:cf:1:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5 fingerprint has invalid length",
            ),
            (
                "MD5:cf:190:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5 fingerprint has invalid length",
            ),
        ]

        for invalid_input, expected_error_msg in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                _normalize_ssh_fingerprint(invalid_input)
            assert expected_error_msg in str(exc_info.value), (
                f"Failed for input: {invalid_input}"
            )


class TestFullPublicKeys:
    """Test that full SSH public keys pass through unchanged."""

    def test_full_public_keys_passthrough(self):
        """Test that full public keys are returned unchanged."""
        test_cases = [
            # Ed25519 key
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmDKuTvCuWLU59NtoBrYAqlzBHuR4MRB5KZonQyvGq test_ed25519",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmDKuTvCuWLU59NtoBrYAqlzBHuR4MRB5KZonQyvGq",
            # RSA key
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNYFI6ZZhgGaRmjg3RpcmgbJ8txCUx8NtW9Zp/vdwJTyrc0q/qqEhYWYjLxwvoFIz4Gsue33ohPjetDFKmIpmMT3bOyYORB+AL5ByYZVuvKwtJw38tTZ112tDGrKAd61JjGfWjGbBW4pZqalUfAxP29GB7B5YyrFbvMpyS4GtBlND/FcakxEtxJKFoIHmGuXk/xvWoEf2B2x7zOm57P5vt0HT60BRRF0zYRYznl//2NcViBzdHIwGqUgO0M34pOKQIfogwEdGU8GW7pTyRssX36j1s5iC+xoq9AIijHrLM+1XtEmENk3u6tn0fGySjYcTx05mR9KhL8nZpT5AWohjz test_rsa_2048",
            # ECDSA key
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKjdGG4+xyV8sGtJgwzfYt+TQ6Xf+HV8LdT0v8s8nP+T5wZhTzh2cT8wt3oV5n6nQXJtNgY2xDk8lG+TwQ/r0A= test_ecdsa",
            # Key without comment
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmDKuTvCuWLU59NtoBrYAqlzBHuR4MRB5KZonQyvGq",
            # Different ECDSA curves
            "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBKjdGG4+xyV8sGtJgwzfYt+TQ6Xf+HV8LdT0v8s8nP+T5wZhTzh2cT8wt3oV5n6nQXJtNgY2xDk8lG+TwQ/r0A",
            "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHKjdGG4+xyV8sGtJgwzfYt+TQ6Xf+HV8LdT0v8s8nP+T5wZhTzh2cT8wt3oV5n6nQXJtNgY2xDk8lG+TwQ/r0A",
        ]

        for public_key in test_cases:
            result = _normalize_ssh_fingerprint(public_key)
            assert result == public_key, f"Public key was modified: {public_key}"


class TestNonSSHKeys:
    """Test that non-SSH keys (GPG keys, etc.) pass through unchanged."""

    def test_gpg_keys_passthrough(self):
        """Test that GPG key IDs pass through unchanged."""
        test_cases = [
            "FCE8AAABF53080F6",
            "1234567890ABCDEF",
            "ABCD1234EFGH5678",
            "A1B2C3D4E5F6",
            "0x1234567890ABCDEF",
            "1A2B3C4D",
        ]

        for gpg_key in test_cases:
            result = _normalize_ssh_fingerprint(gpg_key)
            assert result == gpg_key, f"GPG key was modified: {gpg_key}"

    def test_unknown_formats_passthrough(self):
        """Test that unknown formats pass through unchanged."""
        test_cases = [
            "some-random-string",
            "not-a-key-format",
            "12345",
            "mixed123ABC",
            "user@example.com",
            "",  # Empty string should pass through
            "   ",  # Whitespace should pass through
        ]

        for unknown_format in test_cases:
            result = _normalize_ssh_fingerprint(unknown_format)
            assert result == unknown_format, (
                f"Unknown format was modified: {unknown_format}"
            )


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_case_insensitive_algorithm_detection(self):
        """Test that algorithm detection is case insensitive."""
        test_cases = [
            (
                "ecdsa:sha256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "sha256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            ),
            (
                "ECDSA:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            ),
            (
                "EcDsA:Md5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "Md5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            ),
            (
                "rSa:mD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "mD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            ),
        ]

        for input_key, expected_output in test_cases:
            result = _normalize_ssh_fingerprint(input_key)
            assert result == expected_output, f"Failed for input: {input_key}"

    def test_multiple_algorithm_prefixes(self):
        """Test keys with multiple potential algorithm prefixes in the string."""
        # These should fail validation because they contain invalid characters after normalization
        invalid_cases = [
            (
                "ECDSA:SHA256:RSA:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
            (
                "RSA:MD5:ECDSA:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
                "MD5 fingerprint has invalid length",
            ),
        ]

        for invalid_input, expected_error_msg in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                _normalize_ssh_fingerprint(invalid_input)
            assert expected_error_msg in str(exc_info.value), (
                f"Failed for input: {invalid_input}"
            )

    def test_sha256_and_md5_in_same_string(self):
        """Test strings that contain both SHA256 and MD5 patterns."""
        # These should fail validation because they contain extra content after the fingerprint
        invalid_cases = [
            (
                "PREFIX:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14:MD5:something",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
            (
                "PREFIX:MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3:SHA256:something",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
        ]

        for invalid_input, expected_error_msg in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                _normalize_ssh_fingerprint(invalid_input)
            assert expected_error_msg in str(exc_info.value), (
                f"Failed for input: {invalid_input}"
            )

    def test_whitespace_handling(self):
        """Test that whitespace in keys is handled correctly."""
        # Whitespace in SHA256 should fail validation
        invalid_cases = [
            (
                "SHA256: dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256 fingerprint contains invalid Base64 characters",
            ),
        ]

        # Keys with leading space that DO match SHA256 pattern get normalized
        normalized_cases = [
            (
                " SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
                "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            ),
        ]

        for invalid_input, expected_error_msg in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                _normalize_ssh_fingerprint(invalid_input)
            assert expected_error_msg in str(exc_info.value), (
                f"Failed for input: {invalid_input}"
            )

        for input_key, expected_output in normalized_cases:
            result = _normalize_ssh_fingerprint(input_key)
            assert result == expected_output, f"Failed for input: {input_key}"


# Integration test that covers all formats from our shell script
class TestAllShellScriptFormats:
    """Test all formats covered by our shell test script."""

    def test_all_valid_formats_from_shell_script(self):
        """Test all valid formats that should pass in our shell script."""
        valid_formats = [
            # SHA256 fingerprints (most common format)
            "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            "SHA256:lSpWQv6rFamTP2i93lIaLO8s8TZg/t06GsxrjQ5GAXY",
            "SHA256:oitgrhcEWqRZ248fv26IaaN8TT26bXTr6y65ylS/EcI",
            "SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
            "SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
            "SHA256:xzmyjKD2ZBtadsgr2q0Bzu9B5sw4nAFeu69ZMb1MKNA",
            # Algorithm prefixed fingerprints
            "ECDSA:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            "ED25519:SHA256:+gfWdRetagalcNq4WG0nT1DyN8BeENVmN07pXc7x6wk",
            "RSA:SHA256:Q9U4OcCfadqIPx1neg8yPJqYpoFnVz7f6AElAgYkzwk",
            # MD5 fingerprints (legacy format)
            "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            "MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
            "MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
            # Algorithm prefixed MD5 fingerprints
            "ECDSA:MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            "ED25519:MD5:f9:f3:44:fc:23:d6:97:d1:74:ff:c1:d0:27:c4:83:77",
            "RSA:MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
            # Full public keys
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmDKuTvCuWLU59NtoBrYAqlzBHuR4MRB5KZonQyvGq",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNYFI6ZZhgGaRmjg3RpcmgbJ8txCUx8NtW9Zp/vdwJTyrc0q/qqEhYWYjLxwvoFIz4Gsue33ohPjetDFKmIpmMT3bOyYORB+AL5ByYZVuvKwtJw38tTZ112tDGrKAd61JjGfWjGbBW4pZqalUfAxP29GB7B5YyrFbvMpyS4GtBlND/FcakxEtxJKFoIHmGuXk/xvWoEf2B2x7zOm57P5vt0HT60BRRF0zYRYznl//2NcViBzdHIwGqUgO0M34pOKQIfogwEdGU8GW7pTyRssX36j1s5iC+xoq9AIijHrLM+1XtEmENk3u6tn0fGySjYcTx05mR9KhL8nZpT5AWohjz",
            # Known working key
            "ECDSA:SHA256:ZdI8Rev5CBKfs3Uywh3Nta59BfXcqiQ/3tG0pdjY/5Q",
        ]

        # All of these should normalize successfully without raising exceptions
        for key_format in valid_formats:
            result = _normalize_ssh_fingerprint(key_format)
            # Basic sanity check - result should be non-empty
            assert result, f"Normalization returned empty result for: {key_format}"
            assert isinstance(result, str), (
                f"Normalization returned non-string for: {key_format}"
            )

    def test_all_invalid_formats_from_shell_script(self):
        """Test all invalid formats that should fail in our shell script."""
        invalid_formats = [
            # Empty/malformed SHA256
            "SHA256:",
            "SHA256:InvalidBase64!",
            # Invalid MD5 hex
            "MD5:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz",
            # Note: empty string, whitespace, ssh- prefix only, and invalid-key-format
            # are handled by key type detection, not by this normalization function
        ]

        # All of these should raise ValueError
        for invalid_format in invalid_formats:
            with pytest.raises(ValueError):
                _normalize_ssh_fingerprint(invalid_format)


class TestCLIIntegration:
    """Integration tests to verify unit tests match CLI behavior."""

    def test_unit_tests_match_cli_test_mode(self):
        """Verify that unit test expectations match actual CLI --test-mode behavior."""
        import subprocess

        # Test cases that should succeed in both unit tests and CLI
        success_cases = [
            "SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            "ECDSA:SHA256:dAqSPHAy6OIlcGSjYjMHvw3sy6WQqS63g5uoB5SXA14",
            "MD5:cf:19:30:d7:f9:0d:04:2e:20:ce:3d:24:77:22:22:e3",
            "RSA:MD5:da:21:bd:85:75:74:04:50:c2:8c:af:be:61:de:71:81",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkmDKuTvCuWLU59NtoBrYAqlzBHuR4MRB5KZonQyvGq",
        ]

        # Test cases that should fail in both unit tests and CLI
        failure_cases = [
            "SHA256:",
            "SHA256:InvalidBase64!",
            "MD5:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz:zz",
        ]

        # Get the path to the tag-validate executable
        tag_validate_cmd = "tag-validate"

        for test_key in success_cases:
            # Test unit function
            try:
                _normalize_ssh_fingerprint(test_key)
                unit_success = True
            except ValueError:
                unit_success = False

            # Test CLI command
            try:
                subprocess.run(
                    [
                        tag_validate_cmd,
                        "github",
                        test_key,
                        "-o",
                        "test_user",
                        "--test-mode",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                cli_success = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                cli_success = False
            except FileNotFoundError:
                # Skip CLI test if tag-validate not available
                continue

            assert unit_success == cli_success, (
                f"Mismatch for success case '{test_key}': "
                f"unit_test={'success' if unit_success else 'fail'}, "
                f"cli={'success' if cli_success else 'fail'}"
            )

        for test_key in failure_cases:
            # Test unit function
            try:
                _normalize_ssh_fingerprint(test_key)
                unit_success = True
            except ValueError:
                unit_success = False

            # Test CLI command
            try:
                subprocess.run(
                    [
                        tag_validate_cmd,
                        "github",
                        test_key,
                        "-o",
                        "test_user",
                        "--test-mode",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                cli_success = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                cli_success = False
            except FileNotFoundError:
                # Skip CLI test if tag-validate not available
                continue

            assert unit_success == cli_success, (
                f"Mismatch for failure case '{test_key}': "
                f"unit_test={'success' if unit_success else 'fail'}, "
                f"cli={'success' if cli_success else 'fail'}"
            )
