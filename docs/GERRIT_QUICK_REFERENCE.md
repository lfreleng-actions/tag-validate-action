<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Gerrit Integration Quick Reference

## Overview

The `require_gerrit` feature verifies that cryptographic signing keys (SSH or
GPG) used to sign Git tags are registered in a Gerrit Code Review server.

## Basic Usage

### GitHub Action

```yaml
# Auto-discovery (recommended)
require_gerrit: 'true'

# Explicit server
require_gerrit: 'gerrit.onap.org'

# Combined with GitHub
require_github: 'true'
require_gerrit: 'gerrit.onap.org'
require_owner: 'maintainer@project.org'
token: ${{ secrets.GITHUB_TOKEN }}
```

### CLI

```bash
# Auto-discovery
tag-validate verify v1.2.3 --require-gerrit true

# Explicit server
tag-validate verify v1.2.3 --require-gerrit gerrit.onap.org

# Combined verification
tag-validate verify v1.2.3 \
  --require-github \
  --require-gerrit gerrit.onap.org \
  --require-owner "user@example.com" \
  --token $GITHUB_TOKEN
```

## How It Works

1. **Server Discovery**: `onap/repo` → `gerrit.onap.org`
2. **Account Lookup**: Email from tag signature → Gerrit account ID
3. **Key Verification**: Compare signature key with registered keys
4. **Validation**: Ensure key is valid and not revoked

## Supported Values

| Value     | Description          | Example                        |
| --------- | -------------------- | ------------------------------ |
| `'true'`  | Auto-discover server | `gerrit.[org].org`             |
| `'false'` | Disabled (default)   | -                              |
| Hostname  | Explicit server      | `gerrit.onap.org`              |
| URL       | Full server URL      | `https://gerrit.example.org/r` |

## Common Patterns

### ONAP Projects

```yaml
require_gerrit: 'true'  # → gerrit.onap.org
```

### OpenDaylight Projects

```yaml
require_gerrit: 'git.opendaylight.org/gerrit'
```

### Eclipse Projects

```yaml
require_gerrit: 'git.eclipse.org/r'
```

### Linux Foundation Projects

```yaml
require_gerrit: 'gerrit.linuxfoundation.org'
```

## Error Messages

<!-- markdownlint-disable MD013 -->

| Error                                      | Cause               | Solution             |
| ------------------------------------------ | ------------------- | -------------------- |
| `Could not discover Gerrit API endpoint`   | Server unreachable  | Check server URL     |
| `No Gerrit account found for email`        | Email not in Gerrit | Verify account email |
| `Signing key not registered`               | Key not in Gerrit   | Register SSH/GPG key |
| `Gerrit key verification failed: HTTP 403` | Server permissions  | Check connectivity   |

<!-- markdownlint-enable MD013 -->

## Requirements

- **Signed Tags**: Works with GPG or SSH signed tags
- **Registered Keys**: SSH/GPG keys must be in Gerrit user settings
- **Email Match**: Tag signature email must match Gerrit account
- **Server Access**: Gerrit server must be publicly accessible via HTTPS

## Testing

Use ONAP's public Gerrit for testing:

```bash
# Test account lookup
curl -s "https://gerrit.onap.org/accounts/?q=email:user@example.com"

# Test SSH keys (replace 12345 with account ID)
curl -s "https://gerrit.onap.org/accounts/12345/sshkeys"
```

## Migration

### From GitHub verification

```yaml
# Before
require_github: 'true'

# After
require_github: 'true'
require_gerrit: 'true'
```

### New Projects

```yaml
# Start with Gerrit verification
require_gerrit: 'true'
require_owner: 'maintainer@project.org'
```

## Documentation

- **Full Guide**: [GERRIT_INTEGRATION.md](GERRIT_INTEGRATION.md)
- **Examples**: See `examples/` directory
- **Troubleshooting**: Enable `debug: 'true'` for detailed logs
