<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Tag Validation Action - Quick Reference

## Basic Usage

### Auto-detect from tag push event

```yaml
on:
  push:
    tags: ['*']

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: lfreleng-actions/tag-validate-action@v1
```

### Check string format

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_string: "1.2.3"
```

### Check remote tag

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
```

## Inputs Cheat Sheet

<!-- markdownlint-disable MD013 -->

| Input            | Values                                      | Default      | Description                       |
| ---------------- | ------------------------------------------- | ------------ | --------------------------------- |
| `tag_location`   | `ORG/REPO/TAG`                              | `''`         | Remote tag path                   |
| `tag_string`     | Any string                                  | `''`         | Tag string to check               |
| `require_type`   | `semver`, `calver`, `none`                  | `none`       | Required format                   |
| `require_signed` | `true`, `ssh`, `gpg`, `false`, `ambivalent` | `ambivalent` | Signature rule                    |
| `permit_missing` | `true`, `false`                             | `false`      | Allow missing tags                |
| `token`          | GitHub token                                | `''`         | Token for authenticated API calls |

<!-- markdownlint-enable MD013 -->

## Outputs Cheat Sheet

<!-- markdownlint-disable MD013 -->

| Output            | Values                        | Description             |
| ----------------- | ----------------------------- | ----------------------- |
| `valid`           | `true`, `false`               | Check passed?           |
| `tag_type`        | `semver`, `calver`, `unknown` | Detected version format |
| `signing_type`    | `unsigned`, `ssh`, `gpg`      | Signature type          |
| `development_tag` | `true`, `false`               | Contains dev keywords?  |
| `version_prefix`  | `true`, `false`               | Has v/V prefix?         |
| `tag_name`        | String                        | Tag under inspection    |

<!-- markdownlint-enable MD013 -->

## Common Recipes

### Require SemVer + GPG signature

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver
    require_signed: gpg
```

### Require CalVer + any signature

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: calver
    require_signed: true
```

### Check format (no signature)

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_string: "1.0.0"
    require_type: semver
```

### Detect properties without requirements

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  id: detect
  with:
    permit_missing: true

- run: |
    echo "Type: ${{ steps.detect.outputs.tag_type }}"
    echo "Signed: ${{ steps.detect.outputs.signing_type }}"
    echo "Dev: ${{ steps.detect.outputs.development_tag }}"
```

### Check private repository tag

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/private-repo/v1.0.0"
    require_type: semver
    token: ${{ secrets.GITHUB_TOKEN }}
```

### Increase API rate limits

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

### Conditional logic based on tag type

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  id: tag-check

- name: "Production release"
  if: |
    steps.tag-check.outputs.tag_type == 'semver' &&
    steps.tag-check.outputs.development_tag == 'false'
  run: ./deploy-production.sh

- name: "Development release"
  if: steps.tag-check.outputs.development_tag == 'true'
  run: ./deploy-staging.sh
```

## Check Rules

### Type Checks

```text
require_type: semver + tag_type: semver  = ✅ Pass
require_type: semver + tag_type: calver  = ❌ Fail
require_type: calver + tag_type: calver  = ✅ Pass
require_type: calver + tag_type: semver  = ❌ Fail
require_type: none   + tag_type: any     = ✅ Pass
```

### Signature Checks

```text
require_signed: ambivalent + any signature    = ✅ Pass
require_signed: true       + unsigned         = ❌ Fail
require_signed: true       + ssh/gpg          = ✅ Pass
require_signed: ssh        + ssh              = ✅ Pass
require_signed: ssh        + gpg/unsigned     = ❌ Fail
require_signed: gpg        + gpg              = ✅ Pass
require_signed: gpg        + ssh/unsigned     = ❌ Fail
require_signed: false      + unsigned         = ✅ Pass
require_signed: false      + ssh/gpg          = ❌ Fail
```

## Input Priority

```text
tag_location (highest priority)
    ↓
tag_string
    ↓
Git context (GITHUB_REF)
    ↓
No tag found → check permit_missing
```

## Valid Version Formats

### SemVer Examples

```text
✅ 1.0.0
✅ v2.3.1
✅ 0.1.0-alpha.1
✅ 1.0.0-beta+exp.sha.5114f85
❌ 1.0 (missing patch)
❌ 01.0.0 (leading zero)
```

### CalVer Examples

```text
✅ 2025.01.15
✅ 25.1.0
✅ v2025.1.0-beta
❌ 2025 (missing month)
❌ 2025.13.01 (invalid month)
```

## Development Keywords

Detected as `development_tag: true`:

- `dev`, `pre`, `alpha`, `beta`, `rc`
- `snapshot`, `nightly`, `canary`, `preview`

Examples:

```text
v1.0.0-dev      → development_tag: true
2025.01-BETA.1  → development_tag: true
1.0.0-rc.1      → development_tag: true
v1.0.0          → development_tag: false
```

## Troubleshooting

### "Tag not found" on tag push

```yaml
# ❌ Missing fetch-depth
- uses: actions/checkout@v4
- uses: lfreleng-actions/tag-validate-action@v1

# ✅ Correct
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: lfreleng-actions/tag-validate-action@v1
```

### Signature always "unsigned"

**Causes:**

1. Using `tag_string` (no signature check in string mode)
2. Not in git repository
3. Tag doesn't exist locally

**Solution:** Use tag push event or `tag_location`

### Remote tag rate limiting

```yaml
# Add GitHub token as input
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

## Error Messages

```text
❌ Invalid tag_location format
   → Use ORG/REPO/TAG format

❌ Tag type mismatch
   → require_type doesn't match detected type

❌ Tag was NOT signed
   → require_signed set but tag has no signature

❌ Tag has GPG signature
   → require_signed: ssh but tag is GPG-signed

❌ Remote tag not found
   → Tag doesn't exist at specified location

❌ No tag found
   → Not a tag push event and no inputs provided
```

## Migration from Old Actions

### From tag-validate-semantic-action

```yaml
# Old
- uses: lfreleng-actions/tag-validate-semantic-action@v1
  with:
    string: ${{ github.ref_name }}
    require_signed: gpg

# New
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver
    require_signed: gpg
```

### From tag-validate-calver-action

```yaml
# Old
- uses: lfreleng-actions/tag-validate-calver-action@v1
  with:
    string: ${{ github.ref_name }}
    require_signed: ssh

# New
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: calver
    require_signed: ssh
```

**Output changes:**

- `dev_version` → `development_tag`
- New: `tag_type`, `version_prefix`, `tag_name`

## Complete Example

```yaml
name: Tag Check
on:
  push:
    tags:
      - 'v*'
      - '[0-9]+.*'

jobs:
  check-and-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Check tag"
        id: check
        uses: lfreleng-actions/tag-validate-action@v1
        with:
          require_type: semver
          require_signed: gpg

      - name: "Show outputs"
        run: |
          echo "Valid: ${{ steps.check.outputs.valid }}"
          echo "Type: ${{ steps.check.outputs.tag_type }}"
          echo "Signed: ${{ steps.check.outputs.signing_type }}"
          echo "Dev: ${{ steps.check.outputs.development_tag }}"
          echo "Prefix: ${{ steps.check.outputs.version_prefix }}"
          echo "Tag: ${{ steps.check.outputs.tag_name }}"

      - name: "Production release"
        if: steps.check.outputs.development_tag == 'false'
        run: |
          echo "Deploying production release..."
          ./scripts/release-production.sh

      - name: "Development release"
        if: steps.check.outputs.development_tag == 'true'
        run: |
          echo "Deploying to staging..."
          ./scripts/release-staging.sh
```

## Links

- [Full Documentation](README.md)
- [Implementation Guide](IMPLEMENTATION.md)
- [GitHub Repository](https://github.com/lfreleng-actions/tag-validate-action)
