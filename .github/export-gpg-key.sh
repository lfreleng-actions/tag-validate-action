#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Helper script to export GPG keys for GitHub Actions testing
# This script helps you safely export your GPG key for use in CI testing

set -e

echo "════════════════════════════════════════════════════════════"
echo "  GPG Key Export for GitHub Actions Testing"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "⚠️  WARNING: Only use test keys for CI testing!"
echo "   Never export production keys to GitHub Secrets."
echo ""

# List available GPG keys
echo "Available GPG keys:"
echo "-------------------"
gpg --list-secret-keys --keyid-format=long

echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

# Prompt for key ID
read -r -p "Enter the Key ID to export (e.g., 3AA5C34371567BD2): " KEY_ID

if [ -z "$KEY_ID" ]; then
  echo "Error: No key ID provided"
  exit 1
fi

# Verify key exists
if ! gpg --list-secret-keys "$KEY_ID" &>/dev/null; then
  echo "Error: Key ID '$KEY_ID' not found in keyring"
  exit 1
fi

echo ""
echo "Key details:"
gpg --list-secret-keys --keyid-format=long "$KEY_ID"

echo ""
read -r -p "Is this the correct key? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Aborted."
  exit 0
fi

# Create output directory
OUTPUT_DIR="gpg-export"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "Exporting key..."

# Export private key
gpg --armor --export-secret-keys "$KEY_ID" > "$OUTPUT_DIR/gpg-private-key.asc"
echo "✓ Private key exported to: $OUTPUT_DIR/gpg-private-key.asc"

# Export public key
gpg --armor --export "$KEY_ID" > "$OUTPUT_DIR/gpg-public-key.asc"
echo "✓ Public key exported to: $OUTPUT_DIR/gpg-public-key.asc"

# Create a README with instructions
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# GPG Key Export for GitHub Actions

## Files in this directory:

- `gpg-private-key.asc` - Private key (for GitHub Secret)
- `gpg-public-key.asc` - Public key (reference only)

## Next Steps:

### 1. Add to GitHub Secrets

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `GPG_PRIVATE_KEY`
5. Value: Copy the **entire contents** of `gpg-private-key.asc`
6. Click **Add secret**

### 2. Verify the Secret

The secret should include the full key with headers:

```
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQdGBF...
...
-----END PGP PRIVATE KEY BLOCK-----
```

### 3. Security Reminder

⚠️  **IMPORTANT:**
- Only use test/demo keys for CI
- Never commit these files to git
- Delete this directory after uploading to GitHub
- Rotate keys regularly

### 4. Clean Up

After uploading to GitHub Secrets, delete these files:

```bash
cd ..
rm -rf gpg-export/
```

## Importing the Key in GitHub Actions

Add this step to your workflow before signature verification tests:

```yaml
- name: "Import GPG key for signature verification"
  if: secrets.GPG_PRIVATE_KEY != ''
  shell: bash
  env:
    GPG_PRIVATE_KEY: ${{ secrets.GPG_PRIVATE_KEY }}
  run: |
    echo "Importing GPG key..."
    echo "$GPG_PRIVATE_KEY" | gpg --batch --import

    # Trust the key (for testing)
    KEY_ID=$(gpg --list-secret-keys --keyid-format=long | \
             grep sec | awk '{print $2}' | cut -d'/' -f2)
    echo -e "5\ny\n" | gpg --batch --command-fd 0 \
                            --expert --edit-key "$KEY_ID" trust

    echo "GPG_KEY_AVAILABLE=true" >> "$GITHUB_ENV"
    echo "✓ GPG key imported and trusted"
```

## References

See `.github/GPG_TESTING_SETUP.md` for complete documentation.
EOF

echo "✓ README created: $OUTPUT_DIR/README.md"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Export Complete!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Files exported to: $OUTPUT_DIR/"
echo ""
echo "Next steps:"
echo "1. Review the files in $OUTPUT_DIR/"
echo "2. Add gpg-private-key.asc to GitHub Secrets as GPG_PRIVATE_KEY"
echo "3. Delete the $OUTPUT_DIR/ directory"
echo ""
echo "⚠️  Remember: Only use test keys for CI testing!"
echo ""
