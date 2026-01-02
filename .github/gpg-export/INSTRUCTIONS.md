# GPG Test Key - Setup Instructions

> **Note for Forks**: If you're using a fork of this repository, replace
> `lfreleng-actions` with your organization/username in all GitHub URLs below.

## What Was Created

Two new GPG-signed test tags have been created and pushed:

1. **test-tags-semantic**: `v0.1.4-gpg-test`
2. **test-tags-calver**: `2025.1.4-gpg-test`

Both are signed with a **non-expiring** test key:

- **Key ID**: `0B951925251E1485`
- **Fingerprint**: `F61F 0C54 8E6F 0270 25A6  2343 0B95 1925 251E 1485`
- **Name**: Tag Validate Action Test Key
- **Email**: <test@tag-validate-action.local>
- **Expires**: Never (0 = no expiration)

## Files in This Directory

- `gpg-public-key.asc` - Public key (for reference)
- `INSTRUCTIONS.md` - This file

## Removed From This Directory

- `gpg-private-key.asc` - Private key for GitHub Secret

The private key is not present in this repository, but is needed to setup
the GPG infrastructure and can be created by the relevant scripts. It will
be discussed below as if it has been created and is present.

## Setup GitHub Secret

### 1. Copy the Private Key

```bash
cat gpg-private-key.asc | pbcopy  # macOS
# or
cat gpg-private-key.asc  # Then manually copy
```

### 2. Add to GitHub Secrets

1. Go to: `https://github.com/YOUR_ORG/tag-validate-action/settings/secrets/actions`
   - Replace `YOUR_ORG` with `lfreleng-actions` or your organization name
2. Click **New repository secret**
3. Name: `GPG_PRIVATE_KEY`
4. Value: Paste the entire contents (including `-----BEGIN/END-----` lines)
5. Click **Add secret**

### 3. Optional: Add Key ID as Variable

1. Go to: `https://github.com/YOUR_ORG/tag-validate-action/settings/variables/actions`
   - Replace `YOUR_ORG` with `lfreleng-actions` or your organization name
2. Click **New repository variable**
3. Name: `GPG_TEST_KEY_ID`
4. Value: `0B951925251E1485`
5. Click **Add variable**

## What's Already Updated

The workflow has already been updated to:

1. ✅ Use the new test tags:
   - `v0.1.4-gpg-test` (semantic)
   - `2025.1.4-gpg-test` (calver)

2. ✅ Import GPG key before signature tests:

   ```yaml
   - name: "Import GPG test key for signature verification"
     if: ${{ secrets.GPG_PRIVATE_KEY != '' }}
     shell: bash
     env:
       GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
     run: |
       echo "Importing GPG test key..."
       # Use temp file to avoid GitHub secret masking corruption of armor headers
       GPG_KEY_FILE=$(mktemp)
       echo "$GPG_PRIVATE_KEY" > "$GPG_KEY_FILE"
       gpg --batch --import "$GPG_KEY_FILE"
       rm -f "$GPG_KEY_FILE"

       # Get the imported key ID for the test key specifically
       KEY_ID=$(gpg --list-secret-keys --keyid-format=long \
                "test@tag-validate-action.local" 2>/dev/null | \
                grep sec | awk '{print $2}' | cut -d'/' -f2 | head -1)

       if [ -z "$KEY_ID" ]; then
         echo "Error: Could not find imported test key"
         exit 1
       fi
       echo "Imported key: $KEY_ID"

       # Trust the key (for testing only) - non-interactive method
       FINGERPRINT=$(gpg --list-keys --fingerprint --with-colons \
                     "$KEY_ID" 2>/dev/null | grep fpr | head -1 | cut -d: -f10)

       if [ -z "$FINGERPRINT" ]; then
         echo "Error: Could not get key fingerprint"
         exit 1
       fi
       echo "Key fingerprint: $FINGERPRINT"

       echo "${FINGERPRINT}:6:" | gpg --import-ownertrust 2>&1

       # Set environment variable
       echo "GPG_KEY_AVAILABLE=true" >> "$GITHUB_ENV"
       echo "✓ GPG test key imported and trusted"
   ```

3. ✅ Test assertions check for correct behavior:
   - With key: expects `signing_type=gpg`
   - Without key: expects `signing_type=gpg-unverifiable`

## How It Works

After adding the secret:

1. **Workflow runs** → Checks if `GPG_PRIVATE_KEY` secret exists
2. **If secret exists**:
   - Imports GPG key
   - Trusts the key
   - Sets `GPG_KEY_AVAILABLE=true`
   - Tests expect `signing_type=gpg` ✅
3. **If secret doesn't exist**:
   - Skips import step
   - Tests expect `signing_type=gpg-unverifiable` ✅

## Verify It Works

After adding the secret, push your branch and check the workflow:

1. Go to: `https://github.com/YOUR_ORG/tag-validate-action/actions`
   - Replace `YOUR_ORG` with `lfreleng-actions` or your organization name
2. Find your workflow run
3. Check "Test Signature Detection" job
4. Verify:
   - ✅ "Import GPG test key" step succeeds
   - ✅ `GPG_KEY_AVAILABLE=true` is set
   - ✅ Signature tests pass with `signing_type=gpg`

## Security Notes

✅ **Test-only key** - Safe to store in GitHub Secrets
✅ **No expiration** - Tests won't break after 1 year
✅ **No passphrase** - Simplified for test environment
✅ **Ephemeral keyring** - GitHub Actions destroys after each job
✅ **Public repository safe** - Secrets are encrypted at rest

## Why No Expiration?

This key is set to never expire (`Expire-Date: 0`) because:

1. **Long-term stability** - Tests won't break in 12 months
2. **Low security risk** - Only used for test tags in public repos
3. **Maintenance-free** - No yearly key rotation required
4. **CI best practice** - Test infrastructure should be stable

## Clean Up

After uploading to GitHub Secrets, delete this directory:

```bash
cd ../..
rm -rf .github/gpg-export/
```

**Important:** Don't commit this directory to git!

## Troubleshooting

### Key Import Fails

Check that the secret contains the full key:

```text
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBG...
...
-----END PGP PRIVATE KEY BLOCK-----
```

### Signature Verification Fails

Verify the key was imported:

```bash
gpg --list-keys "test@tag-validate-action.local"
```

Expected output should show no expiration:

```text
pub   rsa2048/0x0B951925251E1485 2026-01-02 [SCEAR]
```

### Trust Issues

The workflow explicitly trusts the key with trust level 6 (ultimate).
If issues persist, check the trust database:

```bash
gpg --list-keys --with-colons | grep "^uid"
```

Or manually trust a key:

```bash
FINGERPRINT=$(gpg --list-keys --fingerprint --with-colons \
              KEY_ID | grep fpr | head -1 | cut -d: -f10)
echo "${FINGERPRINT}:6:" | gpg --import-ownertrust
```

### Tests Still Fail

If tests expect `gpg` but get `gpg-unverifiable`:

- Verify the secret `GPG_PRIVATE_KEY` exists
- Check the import step runs successfully
- Confirm `GPG_KEY_AVAILABLE=true` is set

If tests expect `gpg-unverifiable` but get `gpg`:

- This means the secret was added (good!)
- Tests are now using full verification
- This is the desired behavior ✅

## Key Management

### Backup

Keep a copy of this key in a secure location (e.g., password manager):

- Key ID: `0B951925251E1485`
- Fingerprint: `F61F 0C54 8E6F 0270 25A6  2343 0B95 1925 251E 1485`

### Rotation (if needed)

If you ever need to rotate this key:

1. Generate a new test key
2. Re-sign the test tags
3. Update the `GPG_PRIVATE_KEY` secret
4. Force-push the new tags

### Revocation

If the key is compromised (unlikely for test key):

```bash
# Import the revocation certificate
gpg --import /Users/mwatkins/.gnupg/openpgp-revocs.d/F61F0C548E6F027025A623430B951925251E1485.rev

# Re-sign test tags with new key
```

## References

- See `.github/GPG_TESTING_SETUP.md` for detailed documentation
- Test repositories (lfreleng-actions):
  - <https://github.com/lfreleng-actions/test-tags-semantic>
  - <https://github.com/lfreleng-actions/test-tags-calver>
- GitHub Secrets: <https://docs.github.com/en/actions/security-guides/encrypted-secrets>
