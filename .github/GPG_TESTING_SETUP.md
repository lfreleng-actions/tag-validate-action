<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# GPG Testing Setup Guide

This guide explains how to set up GPG key testing in GitHub Actions for the
tag-validate-action.

## Problem

When testing GPG-signed tags without the signing key in the GPG keyring, the
action returns `signing_type=gpg-unverifiable` instead of `signing_type=gpg`.
This is correct behavior, but we need to test both scenarios:

1. **With GPG key available** → `signing_type=gpg` (verified signature)
2. **Without GPG key** → `signing_type=gpg-unverifiable`
   (signature exists but can't verify)

## Solution Overview

We provide two approaches:

### Approach 1: Test Current Behavior (No Setup Required)

The simplest approach is to update tests to expect `gpg-unverifiable` when
testing without keys. This is what the current `testing.yaml` does by default.

**Pros:**

- No secret management needed
- Tests the real-world scenario of missing keys
- Zero setup required

**Cons:**

- Doesn't test actual signature verification
- Can't distinguish between "signature present" and "signature valid"

### Approach 2: Import GPG Keys for Full Verification (Recommended)

Import the GPG key used to sign test tags to enable full signature
verification testing.

**Pros:**

- Tests complete signature verification flow
- Validates that good signatures are detected correctly
- Can test both scenarios (with/without key)

**Cons:**

- Requires storing GPG private key as a secret
- More complex setup

## Setup Instructions for Approach 2

### Step 1: Export the GPG Private Key

On the machine that was used to sign the test tags:

```bash
# List your GPG keys to find the key ID
gpg --list-secret-keys --keyid-format=long

# Export the private key (ASCII armored)
# Replace KEY_ID with your actual key ID (e.g., 3AA5C34371567BD2)
gpg --armor --export-secret-keys KEY_ID > gpg-private-key.asc

# Also export the public key
gpg --armor --export KEY_ID > gpg-public-key.asc
```

### Step 2: Store the Key as a GitHub Secret

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `GPG_PRIVATE_KEY`
5. Value: Paste the entire content of `gpg-private-key.asc`
   (including the `-----BEGIN/END-----` header)
6. Click **Add secret**

**Optional:** Store the key ID as a variable for clarity:

- **Variables** → **New repository variable**
- Name: `GPG_TEST_KEY_ID`
- Value: Your key ID (e.g., `3AA5C34371567BD2`)

### Step 3: Update the Workflow

Add a step to import the GPG key before running signature tests:

```yaml
- name: "Import GPG key for signature verification"
  if: ${{ secrets.GPG_PRIVATE_KEY != '' }}
  shell: bash
  env:
    GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
  run: |
    echo "Importing GPG key..."
    echo "$GPG_PRIVATE_KEY" | gpg --batch --import

    # Set environment variable to indicate key is available
    echo "GPG_KEY_AVAILABLE=true" >> "$GITHUB_ENV"

    # Trust the key (for testing only) - non-interactive method
    KEY_ID=$(gpg --list-secret-keys --keyid-format=long | \
             grep sec | awk '{print $2}' | cut -d'/' -f2)
    echo "Trusting key: $KEY_ID"
    FINGERPRINT=$(gpg --list-keys --fingerprint --with-colons \
                  "$KEY_ID" | grep fpr | head -1 | cut -d: -f10)
    echo "${FINGERPRINT}:6:" | gpg --import-ownertrust

    echo "✓ GPG key imported and trusted"
```

### Step 4: Update Test Assertions

Modify your test assertions to check for different expected values based on
whether the key is available:

```yaml
- name: "Verify GPG signature detection"
  shell: bash
  run: |
    echo "Signing Type: ${{ steps.gpg-test.outputs.signing_type }}"

    if [ "${{ env.GPG_KEY_AVAILABLE }}" = "true" ]; then
      # With key: should verify as 'gpg'
      if [ "${{ steps.gpg-test.outputs.signing_type }}" != "gpg" ]; then
        echo "Error: Expected signing_type=gpg (key available)"
        exit 1
      fi
      echo "✓ GPG signature verified correctly"
    else
      # Without key: should be 'gpg-unverifiable'
      EXPECTED="gpg-unverifiable"
      if [ "${{ steps.gpg-test.outputs.signing_type }}" != "$EXPECTED" ]
      then
        echo "Error: Expected signing_type=$EXPECTED (key unavailable)"
        exit 1
      fi
      echo "✓ GPG signature detected but unverifiable"
    fi
```

## Alternative: Generate Ephemeral Test Keys

For testing the signing flow itself (not existing tags), you can generate a
key in the workflow:

```yaml
- name: "Generate ephemeral GPG key for testing"
  shell: bash
  run: |
    # Generate a test key with no passphrase
    cat > gpg-key-config << EOF
    %no-protection
    Key-Type: RSA
    Key-Length: 2048
    Name-Real: GitHub Actions Test
    Name-Email: test@github-actions.local
    Expire-Date: 0
    %commit
    EOF

    gpg --batch --generate-key gpg-key-config

    # Configure git to use this key
    KEY_ID=$(gpg --list-secret-keys --keyid-format=short | \
             grep sec | awk '{print $2}' | cut -d'/' -f2 | head -1)
    git config --global user.signingkey "$KEY_ID"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true

    echo "Generated key: $KEY_ID"

- name: "Create and sign a test tag"
  shell: bash
  run: |
    git config user.name "Test User"
    git config user.email "test@github-actions.local"
    git tag -s test-tag-1.0.0 -m "Test signed tag"
```

## Security Considerations

### Test Keys Only

**IMPORTANT:** Only use test/demo keys for CI testing. Never commit
production keys to the repository or store them in GitHub Secrets for public
repositories.

### Key Rotation

If your test repositories use real signing keys:

- Rotate them regularly
- Use separate keys for testing vs. production
- Consider using subkeys for testing

### Cleanup

The GPG keyring is ephemeral in GitHub Actions (destroyed after each job),
so imported keys don't persist between runs.

## Testing Both Scenarios

To thoroughly test the action, create two jobs:

```yaml
jobs:
  test-without-key:
    name: "Test GPG Detection (No Key)"
    runs-on: ubuntu-latest
    steps:
      # Don't import key - tests gpg-unverifiable path
      - name: "Test GPG signature detection"
        uses: ./
        id: gpg-test
        with:
          tag_location: test-repo/v1.0.0

      - name: "Verify returns gpg-unverifiable"
        run: |
          EXPECTED="gpg-unverifiable"
          if [ "${{ steps.gpg-test.outputs.signing_type }}" != "$EXPECTED" ]
          then
            echo "Error: Expected gpg-unverifiable without key"
            exit 1
          fi

  test-with-key:
    name: "Test GPG Verification (With Key)"
    runs-on: ubuntu-latest
    steps:
      # Import key - tests full verification path
      - name: "Import GPG key"
        env:
          GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
        run: |
          echo "$GPG_PRIVATE_KEY" | gpg --batch --import

      - name: "Test GPG signature verification"
        uses: ./
        id: gpg-test
        with:
          tag_location: test-repo/v1.0.0

      - name: "Verify returns gpg (verified)"
        run: |
          if [ "${{ steps.gpg-test.outputs.signing_type }}" != "gpg" ]; then
            echo "Error: Expected gpg with valid key"
            exit 1
          fi
```

## Current Implementation

The current `testing.yaml` uses Approach 1 and has been updated to:

- Test without importing GPG keys by default
- Expect `gpg-unverifiable` for GPG-signed tags (correct behavior without keys)
- Conditionally check for `gpg` if `GPG_KEY_AVAILABLE=true` environment
  variable is set

To enable full GPG verification testing, add the secret `GPG_PRIVATE_KEY` to
your repository and uncomment the GPG import step in the workflow.

## Recommended Test Matrix

For comprehensive testing:

<!-- markdownlint-disable MD013 MD060 -->

| Test Case         | GPG Key Available | Expected Result    | Purpose                                |
| ----------------- | ----------------- | ------------------ | -------------------------------------- |
| GPG-signed tag    | ✅ Yes            | `gpg`              | Verify signature validation works      |
| GPG-signed tag | ❌ No | `gpg-unverifiable` | Detect w/o key |
| SSH-signed tag    | N/A               | `ssh`              | Verify SSH signature detection         |
| Unsigned tag      | N/A               | `unsigned`         | Verify unsigned tag detection          |
| Invalid signature | ✅ Yes            | `invalid`          | Verify bad signature detection         |

<!-- markdownlint-enable MD013 MD060 -->

## Troubleshooting

### Key Import Fails

If `gpg --import` fails, check:

- The secret contains the full ASCII armored key (including headers)
- No extra whitespace or line breaks were added
- The key is not encrypted with a passphrase (or provide it)

### Trust Issues

If verification fails with trust warnings:

```bash
# Trust the key automatically (non-interactive method)
FINGERPRINT=$(gpg --list-keys --fingerprint --with-colons \
              KEY_ID | grep fpr | head -1 | cut -d: -f10)
echo "${FINGERPRINT}:6:" | gpg --import-ownertrust
```

### Key Not Found

If git can't find the key:

```bash
# List keys to verify import
gpg --list-keys

# Configure git to use the key
git config --global user.signingkey KEY_ID
```

## References

- [GitHub Actions: Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [GPG Manual](https://www.gnupg.org/documentation/manuals/gnupg/)
- [Git Tag Signing](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
