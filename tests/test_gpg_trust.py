# SPDX-FileCopyrightText: 2026 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for verifying GPG tags against supplied keys and pinned fingerprints.

Each test generates throwaway keys with GnuPG at run time; no key
material lives in the repository.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app
from tag_validate.gpg_trust import (
    GpgTrustError,
    inspect_key_file,
    parse_fingerprints,
)
from tag_validate.models import SignatureInfo, ValidationConfig, ValidationResult
from tag_validate.workflow import ValidationWorkflow

pytestmark = pytest.mark.skipif(
    shutil.which("gpg") is None, reason="GnuPG is not installed"
)

runner = CliRunner()

PAST = "20200101T000000"
SIGNED = "20200601T000000"
LATER = "20210101T000000"
EXIT_INVALID_INPUT = 3


def _gpg(home: Path, *args: str, stdin: str | None = None) -> str:
    """Run gpg against a home and return its stdout."""
    result = subprocess.run(
        [
            "gpg",
            "--batch",
            "--no-tty",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
            *args,
        ],
        input=stdin,
        capture_output=True,
        text=True,
        env={**os.environ, "GNUPGHOME": str(home)},
        check=True,
    )
    return result.stdout


def _git(repo: Path, *args: str, stdin: str | None = None) -> str:
    """Run git in a repository and return its stripped stdout."""
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.org", *args],
        cwd=repo,
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _new_home(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


class Signer:
    """A GnuPG home that generates keys and signs tags."""

    def __init__(self, home: Path, repo: Path) -> None:
        self.home = home
        self.repo = repo

    def new_key(self, email: str, expire: str = "0", at: str = PAST) -> str:
        """Create a signing key and return its primary fingerprint."""
        _gpg(
            self.home,
            "--faked-system-time",
            at,
            "--quick-gen-key",
            f"Test <{email}>",
            "ed25519",
            "sign",
            expire,
        )
        listing = _gpg(self.home, "--with-colons", "--list-keys", email)
        return next(
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
        )

    def add_subkey(self, primary: str) -> str:
        """Add a signing subkey and return its fingerprint."""
        _gpg(
            self.home,
            "--faked-system-time",
            PAST,
            "--quick-add-key",
            primary,
            "ed25519",
            "sign",
            "0",
        )
        listing = _gpg(self.home, "--with-colons", "--list-keys", primary)
        return [
            line.split(":")[9]
            for line in listing.splitlines()
            if line.startswith("fpr:")
        ][-1]

    def export(self, path: Path, *fingerprints: str) -> Path:
        """Write the public keys to an armoured file."""
        path.write_text(_gpg(self.home, "--armor", "--export", *fingerprints))
        return path

    def tag(
        self, name: str, key: str, at: str = SIGNED, sig_expire: str | None = None
    ) -> None:
        """Create a tag signed by ``key`` at a faked time."""
        head = _git(self.repo, "rev-parse", "HEAD")
        body = (
            f"object {head}\ntype commit\ntag {name}\n"
            "tagger Test <test@example.org> 1600000000 +0000\n\nRelease\n"
        )
        expire = ["--default-sig-expire", sig_expire] if sig_expire else []
        signature = _gpg(
            self.home,
            "--faked-system-time",
            at,
            *expire,
            "-u",
            f"{key}!",
            "--armor",
            "--detach-sign",
            stdin=body,
        )
        obj = _git(self.repo, "mktag", stdin=body + signature)
        _git(self.repo, "update-ref", f"refs/tags/{name}", obj)

    def set_expiry(self, primary: str, expire: str, at: str) -> None:
        """Change when a key expires, at a faked time."""
        _gpg(
            self.home, "--faked-system-time", at, "--quick-set-expire", primary, expire
        )

    def revoke(self, primary: str) -> None:
        """Import the key's generated revocation certificate."""
        cert = (self.home / "openpgp-revocs.d" / f"{primary}.rev").read_text()
        _gpg(self.home, "--import", stdin=cert.replace(":-----BEGIN", "-----BEGIN"))


def _kill_agents(home: Path) -> None:
    subprocess.run(
        ["gpgconf", "--homedir", str(home), "--kill", "all"],
        capture_output=True,
        check=False,
    )


@pytest.fixture
def default_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the default GnuPG keyring at an empty home for the test."""
    home = _new_home(tmp_path / "default-gnupg")
    monkeypatch.setenv("GNUPGHOME", str(home))
    yield home
    _kill_agents(home)


@pytest.fixture
def signer(tmp_path: Path, default_home: Path) -> Iterator[Signer]:
    """A repository with one commit, and a separate home holding secret keys."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "Initial")
    home = _new_home(tmp_path / "signer-gnupg")
    yield Signer(home, repo)
    _kill_agents(home)


def _verify(signer: Signer, tag: str, *args: str) -> tuple[int, dict]:
    result = runner.invoke(
        app, ["verify", tag, "--path", str(signer.repo), "--json", *args]
    )
    return result.exit_code, json.loads(result.stdout) if result.stdout else {}


def _keyring_listing(home: Path) -> str:
    return subprocess.run(
        ["gpg", "--batch", "--with-colons", "--list-keys"],
        capture_output=True,
        text=True,
        env={**os.environ, "GNUPGHOME": str(home)},
        check=False,
    ).stdout


class TestParseFingerprints:
    """Parsing of the require_fingerprint list."""

    def test_accepts_grouped_and_listed_fingerprints(self):
        fpr = "89B02864103FDF27E3069BD2BBD9040D7B3B22EB"
        grouped = "89b0 2864 103f df27 e306  9bd2 bbd9 040d 7b3b 22eb"
        other = "9A334AEC4FA6FACB2B7347659C80B891CA0ED56D"
        assert parse_fingerprints(f"{grouped}, {other},{fpr}") == [fpr, other]

    @pytest.mark.parametrize(
        "value", ["", " , ", "BBD9040D7B3B22EB", "0x7B3B22EB", "Z" * 40, "A" * 41]
    )
    def test_refuses_key_ids_and_malformed_values(self, value):
        with pytest.raises(GpgTrustError):
            parse_fingerprints(value)


class TestKeyFileChecks:
    """The trusted key file must hold public keys only."""

    def test_rejects_secret_key(self, signer, tmp_path):
        fpr = signer.new_key("secret@example.org")
        secret = tmp_path / "secret.asc"
        secret.write_text(_gpg(signer.home, "--armor", "--export-secret-keys", fpr))
        with pytest.raises(GpgTrustError, match="secret key"):
            inspect_key_file(secret)

    def test_rejects_file_without_public_key(self, tmp_path):
        empty = tmp_path / "empty.asc"
        empty.write_text("not a key\n")
        with pytest.raises(GpgTrustError, match="no public key"):
            inspect_key_file(empty)

    def test_cli_rejects_bad_inputs(self, signer, tmp_path):
        fpr = signer.new_key("cli@example.org")
        keys = signer.export(tmp_path / "keys.asc", fpr)
        signer.tag("v1.0.0", fpr)
        code, _ = _verify(
            signer, "v1.0.0", "--trusted-gpg-keys", str(tmp_path / "missing.asc")
        )
        assert code == EXIT_INVALID_INPUT
        code, _ = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr[-16:],
        )
        assert code == EXIT_INVALID_INPUT


class TestSuppliedKeys:
    """Verification against supplied keys and a pinned fingerprint."""

    def test_primary_key_signature_matches_pin(self, signer, tmp_path, default_home):
        fpr = signer.new_key("release@example.org")
        keys = signer.export(tmp_path / "keys.asc", fpr)
        signer.tag("v1.0.0", fpr)
        before = _keyring_listing(default_home)

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr.lower(),
        )

        assert code == 0, output
        details = output["signature_details"]
        assert details["primary_fingerprint"] == fpr
        assert details["key_source"] == "supplied"
        assert details["key_expired"] is False
        assert _keyring_listing(default_home) == before

    def test_subkey_signature_matches_primary_pin(self, signer, tmp_path):
        fpr = signer.new_key("sub@example.org")
        subkey = signer.add_subkey(fpr)
        keys = signer.export(tmp_path / "keys.asc", fpr)
        signer.tag("v1.0.0", subkey)

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr,
        )

        assert code == 0, output
        assert output["signature_details"]["primary_fingerprint"] == fpr
        assert output["signature_details"]["fingerprint"] == subkey

    def test_fingerprint_mismatch_fails(self, signer, tmp_path):
        fpr = signer.new_key("release@example.org")
        other = signer.new_key("other@example.org")
        keys = signer.export(tmp_path / "keys.asc", fpr, other)
        signer.tag("v1.0.0", fpr)

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            other,
        )

        assert code == 1
        assert any("does not match any pinned" in e for e in output["errors"])

    def test_key_only_in_default_keyring_is_not_used(
        self, signer, tmp_path, default_home
    ):
        fpr = signer.new_key("release@example.org")
        other = signer.new_key("other@example.org")
        _gpg(
            default_home,
            "--import",
            stdin=_gpg(signer.home, "--armor", "--export", fpr),
        )
        keys = signer.export(tmp_path / "keys.asc", other)
        signer.tag("v1.0.0", fpr)

        code, output = _verify(
            signer, "v1.0.0", "--trusted-gpg-keys", str(keys), "--require-signed", "gpg"
        )

        assert code == 1
        assert output["signature_type"] == "gpg-unverifiable"

    def test_configured_gpg_program_cannot_reach_default_keyring(
        self, signer, tmp_path, default_home
    ):
        fpr = signer.new_key("release@example.org")
        other = signer.new_key("other@example.org")
        _gpg(
            default_home,
            "--import",
            stdin=_gpg(signer.home, "--armor", "--export", fpr),
        )
        keys = signer.export(tmp_path / "keys.asc", other)
        signer.tag("v1.0.0", fpr)
        wrapper = tmp_path / "gpg-wrapper"
        wrapper.write_text(f'#!/bin/sh\nexec gpg --homedir "{default_home}" "$@"\n')
        wrapper.chmod(0o700)
        for setting in ("gpg.program", "gpg.openpgp.program"):
            _git(signer.repo, "config", setting, str(wrapper))

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr,
        )

        assert code == 1
        assert output["signature_type"] == "gpg-unverifiable"

    def test_default_keyring_still_used_without_supplied_keys(
        self, signer, default_home
    ):
        fpr = signer.new_key("release@example.org")
        _gpg(
            default_home,
            "--import",
            stdin=_gpg(signer.home, "--armor", "--export", fpr),
        )
        signer.tag("v1.0.0", fpr)

        code, output = _verify(signer, "v1.0.0", "--require-fingerprint", fpr)

        assert code == 0, output
        assert output["signature_details"]["key_source"] == "keyring"

    def test_unsigned_and_lightweight_tags_fail_pin(self, signer):
        fpr = "89B02864103FDF27E3069BD2BBD9040D7B3B22EB"
        _git(signer.repo, "tag", "light")
        _git(signer.repo, "tag", "-a", "-m", "Unsigned", "unsigned")

        for tag in ("light", "unsigned"):
            code, output = _verify(signer, tag, "--require-fingerprint", fpr)
            assert code == 1, tag
            assert any("pinned key" in e for e in output["errors"]), output


class TestKeyState:
    """Expired and revoked signing keys."""

    def _expired_key_tag(self, signer, tmp_path, sign_at: str) -> tuple[str, Path]:
        fpr = signer.new_key("old@example.org")
        signer.tag("v1.0.0", fpr, at=sign_at)
        signer.set_expiry(fpr, "2020-09-01", at=PAST)
        return fpr, signer.export(tmp_path / "keys.asc", fpr)

    def test_expired_key_fails_by_default(self, signer, tmp_path):
        fpr, keys = self._expired_key_tag(signer, tmp_path, SIGNED)

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr,
        )

        assert code == 1
        assert any("permit_expired_key is not set" in e for e in output["errors"])

    def test_expired_key_passes_when_permitted(self, signer, tmp_path, monkeypatch):
        fpr, keys = self._expired_key_tag(signer, tmp_path, SIGNED)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")

        result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--path",
                str(signer.repo),
                "--json",
                "--trusted-gpg-keys",
                str(keys),
                "--require-fingerprint",
                fpr,
                "--permit-expired-key",
            ],
        )
        output = json.loads(result.stdout)

        assert result.exit_code == 0, output
        assert output["signature_details"]["key_expired"] is True
        assert any("permit_expired_key" in w for w in output["warnings"])
        assert f"::warning::GPG signing key {fpr} expired" in result.stderr

    def test_signature_after_expiry_fails_when_permitted(self, signer, tmp_path):
        fpr, keys = self._expired_key_tag(signer, tmp_path, LATER)

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr,
            "--permit-expired-key",
        )

        assert code == 1
        assert any("not made before" in e for e in output["errors"])

    @pytest.mark.parametrize("permit", [False, True])
    def test_expired_signature_fails(self, signer, tmp_path, permit):
        fpr = signer.new_key("sigexp@example.org")
        signer.tag("v1.0.0", fpr, sig_expire="1d")
        keys = signer.export(tmp_path / "keys.asc", fpr)
        permit_args = ["--permit-expired-key"] if permit else []

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr,
            *permit_args,
        )

        assert code == 1
        assert output["signature_verified"] is False
        assert output["signature_type"] == "invalid"
        assert any("signature has expired" in e for e in output["errors"])

    def test_revoked_key_fails_even_when_permitted(self, signer, tmp_path):
        fpr = signer.new_key("revoked@example.org")
        signer.tag("v1.0.0", fpr)
        signer.revoke(fpr)
        keys = signer.export(tmp_path / "keys.asc", fpr)

        code, output = _verify(
            signer,
            "v1.0.0",
            "--trusted-gpg-keys",
            str(keys),
            "--require-fingerprint",
            fpr,
            "--permit-expired-key",
        )

        assert code == 1
        assert any("revoked" in e for e in output["errors"])


class TestPinFailsClosed:
    """A pin rejects every signature that is not a verified GPG one."""

    @pytest.mark.parametrize(
        ("sig_type", "verified"),
        [("ssh", True), ("gpg", False), ("gpg-unverifiable", False)],
    )
    def test_non_gpg_or_unverified_signature_fails(self, sig_type, verified):
        config = ValidationConfig(
            require_signed=True,
            require_fingerprints=["89B02864103FDF27E3069BD2BBD9040D7B3B22EB"],
        )
        workflow = ValidationWorkflow(config)
        result = ValidationResult(tag_name="v1.0.0", is_valid=True, config=config)
        info = SignatureInfo(
            type=sig_type,
            verified=verified,
            key_id="BBD9040D7B3B22EB",
            primary_fingerprint="89B02864103FDF27E3069BD2BBD9040D7B3B22EB",
        )

        assert workflow._check_signature_requirements(info, result) is False
        assert any("pinned key" in e for e in result.errors)
