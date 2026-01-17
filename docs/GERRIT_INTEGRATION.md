<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Gerrit Integration Guide

This document describes how to use the new Gerrit key verification
functionality in tag-validate-action.

## Overview

The `require_gerrit` feature allows you to verify that cryptographic signing
keys (SSH or GPG) used to sign Git tags are registered in a Gerrit Code Review
server. This provides enhanced security by ensuring that authorized developers
with registered keys can create valid signed tags.

## Features

- **Automatic Gerrit Server Discovery**: Auto-detects Gerrit server from GitHub
  organization (e.g., `onap` → `gerrit.onap.org`)
- **Manual Server Specification**: Supports custom Gerrit server hostnames or
  URLs
- **SSH Key Verification**: Verifies SSH signing keys against registered SSH
  keys in Gerrit
- **GPG Key Verification**: Verifies GPG signing keys against registered GPG
  keys in Gerrit
- **Account Resolution**: Automatically looks up Gerrit accounts by email
  address
- **Owner Support**: Can verify against required account owners
- **Combined Verification**: Works alongside existing GitHub verification
  (`require_github`)
- **HTTP Authentication**: Supports Gerrit HTTP password authentication for
  servers that require authentication to access user key information

## Authentication

Some Gerrit servers (including `gerrit.onap.org`) require authentication to
access user SSH key and GPG key information. The tool supports HTTP password
authentication for these servers.

### Getting Your Gerrit HTTP Password

1. Log into your Gerrit server via SSO (e.g., Linux Foundation/Google account)
2. Click your profile icon → **Settings**
3. Navigate to **HTTP Credentials** or **HTTP Password**
4. Click **Generate Password** to create a new HTTP password
5. Copy this password (this is NOT your SSO password)

**Important**: The HTTP password is different from your SSO/LDAP login password.
It's a generated token specifically for HTTP API access.

### Using Authentication

#### Environment Variables (Recommended)

Set these environment variables in your shell profile or CI/CD secrets:

```bash
export GERRIT_USERNAME="your-gerrit-username"
export GERRIT_PASSWORD="your-http-password"
```

The tool will automatically use these credentials when needed.

#### GitHub Action Secrets

Store credentials in GitHub Secrets and reference them in your workflow:

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_gerrit: 'gerrit.onap.org'
    gerrit_username: ${{ secrets.GERRIT_USERNAME }}
    gerrit_password: ${{ secrets.GERRIT_PASSWORD }}
    tag_location: ${{ github.ref_name }}
```

#### CLI Options

Pass credentials directly via command-line options:

```bash
tag-validate verify v1.2.3 \
  --require-gerrit gerrit.onap.org \
  --gerrit-username myusername \
  --gerrit-password myHTTPpassword
```

## Usage

### GitHub Action

Add the `require_gerrit` input to your workflow:

#### Auto-Discovery from GitHub Organization

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_gerrit: 'true'  # Auto-discovers gerrit.[org].org
    tag_location: ${{ github.ref_name }}
```

#### Explicit Gerrit Server

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_gerrit: 'gerrit.onap.org'  # Specific server
    tag_location: ${{ github.ref_name }}
```

#### Combined with GitHub Verification

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_github: 'true'
    require_gerrit: 'gerrit.onap.org'
    require_owner: 'user@linuxfoundation.org'  # Must match both systems
    token: ${{ secrets.GITHUB_TOKEN }}
    gerrit_username: ${{ secrets.GERRIT_USERNAME }}
    gerrit_password: ${{ secrets.GERRIT_PASSWORD }}
    tag_location: ${{ github.ref_name }}
```

### Command Line Interface

#### Auto-Discovery Example

```bash
# Auto-discover Gerrit server from remote repository (uses env vars for auth)
tag-validate verify v1.2.3 --require-gerrit true
```

#### Explicit Server Example

```bash
# Use specific Gerrit server (with authentication)
tag-validate verify v1.2.3 \
  --require-gerrit gerrit.onap.org \
  --gerrit-username myusername \
  --gerrit-password myHTTPpassword
```

#### Combined Verification Example

```bash
# Verify against both GitHub and Gerrit (environment variables recommended)
export GERRIT_USERNAME="myusername"
export GERRIT_PASSWORD="myHTTPpassword"

tag-validate verify v1.2.3 \
  --require-github \
  --require-gerrit gerrit.onap.org \
  --require-owner "mwatkins@linuxfoundation.org" \
  --token $GITHUB_TOKEN
```

#### Remote Repository Example

```bash
# Verify remote repository tag with auto-discovery
tag-validate verify onap/policy-engine@v1.2.3 \
  --require-gerrit true
```

## How It Works

### Server Discovery

When `require_gerrit` is set to `true`, the system:

1. **For Remote Repositories**: Extracts the GitHub organization from the
   repository URL (e.g., `onap/policy-engine` → `onap`)
2. **For Local Repositories**: Attempts to extract organization from
   `git remote get-url origin`
3. **Applies Pattern**: Uses pattern `gerrit.[org].org` to construct server URL

### Account Resolution

The system looks up Gerrit accounts using:

1. **Tagger Email**: Extracts email from Git tag signature
2. **Account Query**: Searches Gerrit using `/accounts/?q=email:{email}` API
3. **Account Mapping**: Maps email to Gerrit account ID for key lookup

### Key Verification Process

1. **Extract Key Information**: Gets key ID (GPG) or fingerprint (SSH) from tag
   signature
2. **Fetch Registered Keys**: Retrieves all keys from Gerrit account using:
   - `/accounts/{account-id}/sshkeys` for SSH keys
   - `/accounts/{account-id}/gpgkeys` for GPG keys
3. **Match Keys**: Compares signature key against registered keys
4. **Verify Status**: Ensures keys are valid and not revoked

## Configuration Examples

### Basic Gerrit Verification

```yaml
# Minimal configuration - auto-discovers server
require_gerrit: 'true'
```

### Production Configuration

```yaml
# Complete configuration for production use
require_type: 'semver'
require_signed: 'gpg,ssh'
require_gerrit: 'gerrit.onap.org'
require_owner: 'maintainer@project.org,lead@project.org'
reject_development: true
```

### Multi-Platform Verification

```yaml
# Verify on both GitHub and Gerrit
require_github: 'true'
require_gerrit: 'gerrit.linuxfoundation.org'
require_owner: 'developer@company.com'
token: ${{ secrets.GITHUB_TOKEN }}
```

## Supported Gerrit Servers

The integration has been tested with:

- **ONAP Gerrit**: `gerrit.onap.org` (primary test server)
- **OpenDaylight**: `git.opendaylight.org/gerrit`
- **Eclipse Gerrit**: `git.eclipse.org/r`
- **Linux Foundation**: LF project Gerrit instances

### Server Path Detection

The system automatically detects common Gerrit deployment patterns:

- `https://gerrit.example.org/` (direct)
- `https://gerrit.example.org/r/` (standard)
- `https://gerrit.example.org/gerrit/` (OpenDaylight style)
- `https://gerrit.example.org/a/` (authenticated API)

## Error Handling

### Common Error Scenarios

1. **Server Not Found**:

   ```text
   Error: Could not discover Gerrit API endpoint for gerrit.example.org
   ```

   - Solution: Specify full server URL or check server accessibility

2. **Account Not Found**:

   ```text
   Error: No Gerrit account found for email: user@example.com
   ```

   - Solution: Verify email matches Gerrit account or use `require_owner`

3. **Key Not Registered**:

   ```text
   Error: Signing key not registered on Gerrit server gerrit.example.org
   ```

   - Solution: Register SSH/GPG key in Gerrit account settings

4. **Server Communication Failed**:

   ```text
   Error: Gerrit key verification failed: HTTP 403
   ```

   - Solution: Check server permissions or network connectivity

## Security Considerations

### Key Management

- **SSH Keys**: Must be registered in Gerrit user settings under SSH Keys
- **GPG Keys**: Must be uploaded to Gerrit user settings under GPG Keys
- **Key Validation**: System verifies keys are valid and not expired/revoked

### Network Security

- **HTTPS**: All communication with Gerrit servers uses HTTPS
- **HTTP Basic Authentication**: Uses HTTP Basic Auth when credentials are
  provided
- **Secure Credential Storage**: Credentials should be stored in environment
  variables or secrets management systems
- **Rate Limiting**: Respects Gerrit server rate limits and timeouts

### Access Control

- **Public Key Verification**: Verifies public keys, no private key access
- **Account Privacy**: Accesses public account information
- **Minimal Permissions**: Requires no special privileges on Gerrit server

## Troubleshooting

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# CLI with debug output
tag-validate verify v1.2.3 --require-gerrit gerrit.onap.org --json | jq .

# GitHub Action with debug
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    debug: 'true'
    require_gerrit: 'gerrit.onap.org'
    tag_location: ${{ github.ref_name }}
```

### Manual Testing

Test Gerrit connectivity manually:

```bash
# Test server discovery
curl -s "https://gerrit.onap.org/accounts/?q=email:user@example.com" | head -1

# Test SSH key API (replace account-id)
curl -s "https://gerrit.onap.org/accounts/12345/sshkeys"

# Test GPG key API (replace account-id)
curl -s "https://gerrit.onap.org/accounts/12345/gpgkeys"
```

### Common Solutions

1. **Verify Server URL**: Ensure Gerrit server is accessible via HTTPS
2. **Check Account Email**: Confirm email in tag signature matches Gerrit
   account
3. **Verify Key Registration**: Ensure SSH/GPG keys are properly registered in
   Gerrit
4. **Test Network Access**: Confirm GitHub Actions can reach Gerrit server
5. **Check Authentication**: If server requires auth, verify credentials are
   correct

## Examples with Real Projects

### ONAP Project Example

```yaml
name: Check Release Tag
on:
  push:
    tags: ['v*']

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check Tag
        uses: lfreleng-actions/tag-validate-action@v1
        with:
          require_type: 'semver'
          require_signed: 'gpg'
          require_gerrit: 'true'  # Auto-discovers gerrit.onap.org
          require_owner: 'maintainer@onap.org'
          gerrit_username: ${{ secrets.GERRIT_USERNAME }}
          gerrit_password: ${{ secrets.GERRIT_PASSWORD }}
          reject_development: true
          tag_location: ${{ github.ref_name }}
      ```

### Multi-Maintainer Project

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_gerrit: 'gerrit.linuxfoundation.org'
    require_owner: 'lead@project.org,maintainer1@company.com'
    gerrit_username: ${{ secrets.GERRIT_USERNAME }}
    gerrit_password: ${{ secrets.GERRIT_PASSWORD }}
    tag_location: ${{ github.ref_name }}
```

## Migration from GitHub verification

If you have existing workflows that use GitHub verification:

### Before (GitHub verification)

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_github: 'true'
    require_owner: 'developer@company.com'
    token: ${{ secrets.GITHUB_TOKEN }}
    tag_location: ${{ github.ref_name }}
```

### After (GitHub + Gerrit)

```yaml
- name: Check Tag
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_github: 'true'
    require_gerrit: 'gerrit.company.org'
    require_owner: 'developer@company.com'  # Must exist in both systems
    token: ${{ secrets.GITHUB_TOKEN }}
    gerrit_username: ${{ secrets.GERRIT_USERNAME }}
    gerrit_password: ${{ secrets.GERRIT_PASSWORD }}
    tag_location: ${{ github.ref_name }}
```

## API Reference

### Action Inputs

| Input             | Description     | Default | Examples                  |
| ----------------- | --------------- | ------- | ------------------------- |
| `require_gerrit`  | Gerrit verify   | `false` | `true`, `gerrit.onap.org` |
| `gerrit_username` | Gerrit username | `''`    | `myusername`              |
| `gerrit_password` | Gerrit password | `''`    | `secret-http-password`    |

### CLI Arguments

| Argument            | Description       | Examples                        |
| ------------------- | ----------------- | ------------------------------- |
| `--require-gerrit`  | Enable Gerrit     | `--require-gerrit true`         |
|                     | verification      | `--require-gerrit gerrit.onap`  |
| `--gerrit-username` | Gerrit username   | `--gerrit-username myuser`      |
| `--gerrit-password` | Gerrit HTTP pass  | `--gerrit-password secret`      |

### Output Format

The JSON output includes Gerrit verification results:

```json
{
  "valid": true,
  "key_verification": {
    "key_registered": true,
    "username": "12345",
    "service": "gerrit",
    "server": "gerrit.onap.org",
    "enumerated": true
  }
}
```

## Contributing

To contribute to Gerrit integration:

1. **Test Environment**: Use `gerrit.onap.org` for testing (public access)
2. **Test Account**: Ensure you have SSH/GPG keys registered in test Gerrit
3. **Integration Tests**: Add tests to verify against real Gerrit servers
4. **Documentation**: Update this guide with new features or servers

For issues or feature requests, please open an issue in the repository.
