<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🏷️ Unified Tag Validation Action

A comprehensive GitHub Action for validating tags across versioning schemes
(Semantic Versioning and Calendar Versioning) with cryptographic signature
verification (SSH and GPG).

This action unifies and extends the functionality of
`tag-validate-semantic-action` and `tag-validate-calver-action`.

## Features

- ✅ **Semantic Versioning (SemVer)** validation
- ✅ **Calendar Versioning (CalVer)** validation
- ✅ **SSH signature** detection and verification
- ✅ **GPG signature** detection and verification
- ✅ **Remote tag** validation via GitHub API
- ✅ **Local tag** validation in current repository
- ✅ **String** validation (no signature check)
- ✅ **Development/pre-release** tag detection
- ✅ **Version prefix** (v/V) detection
- ✅ Flexible validation requirements

## Quick Start

### Check Current Repository Tag Push

```yaml
name: "Check Tag"
on:
  push:
    tags:
      - '*'

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Check pushed tag"
        uses: lfreleng-actions/tag-validate-action@v1
        with:
          require_type: semver
          require_signed: true
```

### Check Remote Repository Tag

```yaml
- name: "Check remote tag"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "lfreleng-actions/tag-validate-action/v1.0.0"
    require_type: semver
    require_signed: gpg
```

### Check Tag String

```yaml
- name: "Check version string"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_string: "2025.01.15"
    require_type: calver
```

## Inputs

<!-- markdownlint-disable MD013 -->

| Name           | Required | Default    | Description                                                            |
| -------------- | -------- | ---------- | ---------------------------------------------------------------------- |
| tag_location   | False    | ''         | Path to tag: remote (ORG/REPO/TAG) or local (PATH/TO/REPO/TAG)         |
| tag_string     | False    | ''         | Tag string to check (version format, signature check skipped)          |
| require_type   | False    | none       | Required tag type: `semver`, `calver`, or `none`                       |
| require_signed | False    | ambivalent | Signature rule: `true`, `ssh`, `gpg`, `false`, or `ambivalent`         |
| permit_missing | False    | false      | Allow missing tags without error                                       |
| token          | False    | ''         | GitHub token for authenticated API calls and private repository access |

<!-- markdownlint-enable MD013 -->

### Input Details

#### `tag_location`

Specifies a tag to check. Supports two formats:

1. **Remote repository**: `ORG/REPO/TAG`
2. **Local repository**: `PATH/TO/REPO/TAG`

**Remote Examples:**

- `lfreleng-actions/tag-validate-action/v1.0.0`
- `lfreleng-actions/tag-validate-action/2025.01.15`

**Local Examples:**

- `./my-repo/v1.0.0`
- `test-repos/semantic-tags/v2.1.0`

For remote tags, the action will:

1. Attempt to find the tag with the exact name provided
2. If not found and the tag starts with 'v', try without the 'v' prefix
3. If not found and the tag doesn't start with 'v', try with 'v' prefix added

For local paths, the repository directory must contain a `.git` directory.

#### `tag_string`

Validates a version string without accessing any repository. Signature checking
is **not** performed in this mode.

**Use case:** Check version strings before creating tags.

#### `require_type`

Enforces the versioning scheme the tag must follow.

- `semver` - Tag must match Semantic Versioning format
- `calver` - Tag must match Calendar Versioning format
- `none` - Any format accepted (default)

**Note:** Input is case-insensitive.

#### `require_signed`

Controls cryptographic signature requirements.

- `ambivalent` - No enforcement, signature type reported as output (default)
- `true` - Tag must have a signature (SSH or GPG)
- `ssh` - Tag must be SSH-signed specifically
- `gpg` - Tag must be GPG-signed specifically
- `false` - Tag must have no signature

**Note:** Input is case-insensitive. The action skips signature checking when
using `tag_string` mode.

#### `permit_missing`

When set to `true`, the action will not fail if:

- No tag exists in the workflow context (not a tag push event)
- The `tag_location` specified doesn't exist
- Empty `tag_string` provided

The action will still fail if:

- `tag_location` format is invalid
- Required validation checks fail (type or signature mismatch)

#### `token`

GitHub token for authenticated API requests and private repository access.

**Use cases:**

- Access private repositories via `tag_location`
- Increase API rate limits (60/hour → 5,000/hour)
- Clone repositories requiring authentication

**Example:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/private-repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

**Note:** For workflows in the same repository, `${{ secrets.GITHUB_TOKEN }}`
is automatically available.

## Outputs

<!-- markdownlint-disable MD013 -->

| Name            | Description                                                   |
| --------------- | ------------------------------------------------------------- |
| valid           | Set to `true` if tag passes all validation checks             |
| tag_type        | Detected tag type: `semver`, `calver`, `both`, or `unknown`   |
| signing_type    | Signing method used: `unsigned`, `ssh`, or `gpg`              |
| development_tag | Set to `true` if tag contains pre-release/development strings |
| version_prefix  | Set to `true` if tag has leading v/V character                |
| tag_name        | The tag name under inspection                                 |

<!-- markdownlint-enable MD013 -->

## Tag Detection Priority

The action determines which tag to check in the following order:

1. **`tag_location`** - If provided, validates the specified remote tag
2. **`tag_string`** - If provided (and no tag_location), validates the string
3. **Git context** - If neither above provided, checks if a tag push started
   the workflow

If none of the above sources provide a tag:

- With `permit_missing: true` - Action succeeds with minimal outputs
- With `permit_missing: false` - Action fails with an error

## Usage Examples

### Enforce SemVer with GPG Signatures

```yaml
name: "Strict Tag Validation"
on:
  push:
    tags:
      - 'v*'

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Check tag"
        uses: lfreleng-actions/tag-validate-action@v1
        with:
          require_type: semver
          require_signed: gpg
```

### Check CalVer Tags (Any Signature)

```yaml
- name: "Check CalVer tag"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: calver
    require_signed: true
```

### Check Remote Tag Before Release

```yaml
- name: "Check dependency version"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/my-dependency/v2.1.0"
    require_type: semver
    permit_missing: false
    token: ${{ secrets.GITHUB_TOKEN }}
```

### Check Version String in CI

```yaml
- name: "Check version from package.json"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_string: ${{ steps.get_version.outputs.version }}
    require_type: semver
```

### Detect Development Tags

```yaml
- name: "Check tag and determine if development"
  id: check
  uses: lfreleng-actions/tag-validate-action@v1

- name: "Skip deployment for dev tags"
  if: steps.check.outputs.development_tag == 'true'
  run: echo "Skipping deployment for development tag"
```

### Flexible Validation (No Requirements)

```yaml
- name: "Detect tag properties"
  id: detect
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    permit_missing: true

- name: "Show tag info"
  run: |
    echo "Tag Type: ${{ steps.detect.outputs.tag_type }}"
    echo "Signing: ${{ steps.detect.outputs.signing_type }}"
    echo "Dev Tag: ${{ steps.detect.outputs.development_tag }}"
    echo "Has Prefix: ${{ steps.detect.outputs.version_prefix }}"
```

### Check Private Repository Tag

```yaml
- name: "Check private repository tag"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/private-repo/v2.0.0"
    require_type: semver
    require_signed: gpg
    token: ${{ secrets.PAT_TOKEN }}  # Personal Access Token with repo scope
```

## Implementation Details

### Semantic Versioning (SemVer)

Uses the official regular expression from [semver.org](https://semver.org/):

```regex
^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$
```

**Valid examples:**

- `1.0.0`
- `v2.3.1`
- `0.1.0-alpha.1`
- `1.0.0-beta+exp.sha.5114f85`

### Calendar Versioning (CalVer)

Uses a flexible pattern to support different CalVer schemes:

```regex
^(\d{2}|\d{4})\.(\d{1}|\d{2})((\.|\_|-)[a-zA-Z][a-zA-Z0-9\.\-\_]*)?(\.(\d{1}|\d{2})((\.|\_|-)[a-zA-Z][a-zA-Z0-9\.\-\_]*)?)?$
```

**Valid examples:**

- `2025.01.15`
- `25.1.0`
- `2025.1`
- `v2025.01.15-beta.1`

### Development Tag Detection

Detects common pre-release/development identifiers (case-insensitive):

- `dev`
- `pre`
- `alpha`
- `beta`
- `rc`
- `snapshot`
- `nightly`
- `canary`
- `preview`

**Examples:**

- `v1.0.0-dev` → `development_tag: true`
- `2025.01-beta.1` → `development_tag: true`
- `v1.0.0` → `development_tag: false`

### Signature Detection

The action detects signatures using two methods:

**GPG Signatures:**

- Executes `git verify-tag --raw <tag>`
- Looks for `[GNUPG:]` markers (GOODSIG, VALIDSIG, ERRSIG)

**SSH Signatures:**

- Checks for SSH-specific markers in verification output
- Examines tag object for `-----BEGIN SSH SIGNATURE-----` block

**Limitations:**

- Signature checking requires the tag to exist in a git repository
- The action clones remote tags temporarily for signature verification
- String validation (`tag_string`) cannot check signatures

## Requirements

### Git Version

- Git 2.34 or later required for SSH signing support
- GitHub Actions runners typically have Git 2.39+

### Repository Checkout

For local tag validation (tag push events):

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0  # Required to fetch all tags
```

### GitHub Token

For remote tag validation, the action can use authenticated or anonymous API calls:

**Without token:**

- Rate limit: 60 requests/hour
- Cannot access private repositories

**With token:**

- Rate limit: 5,000 requests/hour
- Can access private repositories (with appropriate permissions)

**Usage:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

## Validation Logic

### Type Validation

| require_type | tag_type | Result |
| ------------ | -------- | ------ |
| `none`       | any      | ✅ Pass |
| `semver`     | `semver` | ✅ Pass |
| `semver`     | `both`   | ✅ Pass |
| `semver`     | `calver` | ❌ Fail |
| `calver`     | `calver` | ✅ Pass |
| `calver`     | `both`   | ✅ Pass |
| `calver`     | `semver` | ❌ Fail |

### Signature Validation

| require_signed | signing_type | Result          |
| -------------- | ------------ | --------------- |
| `ambivalent`   | any          | ✅ Pass (always) |
| `true`         | `unsigned`   | ❌ Fail          |
| `true`         | `ssh`/`gpg`  | ✅ Pass          |
| `ssh`          | `ssh`        | ✅ Pass          |
| `ssh`          | `gpg`        | ❌ Fail          |
| `ssh`          | `unsigned`   | ❌ Fail          |
| `gpg`          | `gpg`        | ✅ Pass          |
| `gpg`          | `ssh`        | ❌ Fail          |
| `gpg`          | `unsigned`   | ❌ Fail          |
| `false`        | `unsigned`   | ✅ Pass          |
| `false`        | `ssh`/`gpg`  | ❌ Fail          |

## Troubleshooting

### "Tag not found" errors

**Solution:** When validating local tags, ensure:

1. You check out the repository with `fetch-depth: 0`
2. The tag exists in the repository
3. The tag name is correct (check for v prefix)

### Signature verification fails

**Possible causes:**

1. Not in a git repository
2. Tag doesn't exist locally
3. Using `tag_string` mode (signatures not checked)

**Solution:** Use tag push events or `tag_location` for signature validation.

### Rate limiting on remote tags

**Solution:** Provide GitHub token for higher rate limits:

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

## Migration from Previous Actions

### From `tag-validate-semantic-action`

```yaml
# Old action
- uses: lfreleng-actions/tag-validate-semantic-action@v1
  with:
    string: ${{ github.ref_name }}
    require_signed: gpg

# New unified action
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver
    require_signed: gpg
```

### From `tag-validate-calver-action`

```yaml
# Old action
- uses: lfreleng-actions/tag-validate-calver-action@v1
  with:
    string: ${{ github.ref_name }}
    exit_on_fail: true

# New unified action
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: calver
```

**Output changes:**

- `dev_version` → `development_tag`
- Added: `tag_type`, `version_prefix`, `tag_name`

## Related Projects

- [tag-validate-semantic-action](https://github.com/lfreleng-actions/tag-validate-semantic-action)
  \- SemVer validation
- [tag-validate-calver-action](https://github.com/lfreleng-actions/tag-validate-calver-action)
  \- CalVer validation

## License

Apache-2.0

## Contributing

Contributions are welcome! Please open an issue or pull request.
