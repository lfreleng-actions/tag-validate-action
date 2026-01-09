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

| Name              | Required | Default    | Description                                                            |
| ----------------- | -------- | ---------- | ---------------------------------------------------------------------- |
| tag_location      | False    | ''         | Path to tag: remote (ORG/REPO/TAG) or local (PATH/TO/REPO/TAG)         |
| tag_string        | False    | ''         | Tag string to check (version format, signature check skipped)          |
| require_type      | False    | none       | Required tag type: `semver`, `calver`, or `none`                       |
| require_signed    | False    | ambivalent | Signature rule: `true`, `ssh`, `gpg`, `false`, or `ambivalent`         |
| permit_missing    | False    | false      | Allow missing tags without error                                       |
| token             | False    | ''         | GitHub token for authenticated API calls and private repository access |
| github_server_url | False    | ''         | GitHub server URL (for GitHub Enterprise Server)                       |
| debug             | False    | false      | Enable debug output including git error messages                       |

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

#### `github_server_url`

GitHub server URL for git operations. Supports GitHub Enterprise Server.

**Default behavior:**

1. Uses the provided `github_server_url` if specified
2. Falls back to `GITHUB_SERVER_URL` environment variable
3. Falls back to `https://github.com`

**Use case:** When validating tags from GitHub Enterprise Server instances.

**Example:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/my-repo/v1.0.0"
    github_server_url: "https://github.enterprise.example.com"
```

#### `debug`

Enable debug output in action logs for troubleshooting.

When enabled, the action will output:

- Internal variable values
- Git command outputs and error messages
- Tag object inspection details
- Signature verification details

**Use case:** Diagnosing validation failures or unexpected behavior.

**Example:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/my-repo/v1.0.0"
    debug: true
```

## Outputs

<!-- markdownlint-disable MD013 -->

| Name            | Description                                                                                    |
| --------------- | ---------------------------------------------------------------------------------------------- |
| valid           | Set to `true` if tag passes all validation checks                                              |
| tag_type        | Detected tag type: `semver`, `calver`, `both`, or `unknown`                                    |
| signing_type    | Signing method used: `unsigned`, `ssh`, `gpg`, `gpg-unverifiable`, `lightweight`, or `invalid` |
| development_tag | Set to `true` if tag contains pre-release/development strings                                  |
| version_prefix  | Set to `true` if tag has leading v/V character                                                 |
| tag_name        | The tag name under inspection                                                                  |

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

### Signature Verification Result Codes

<!-- markdownlint-disable MD013 -->
| Git Verify Result | signing_type      | Description                                                                     |
| ----------------- | ----------------- | ------------------------------------------------------------------------------- |
| 0                 | gpg               | GPG signature verified (GOODSIG or VALIDSIG detected)                           |
| non-zero          | gpg-unverifiable  | GPG signature present but unverifiable (ERRSIG - missing key)                   |
| 0                 | ssh               | SSH signature verified (pattern match in `git verify-tag` output or tag object) |
| non-zero          | invalid           | GPG signature present but verification failed (BADSIG - corrupted or tampered)  |
| non-zero          | lightweight       | Lightweight tag (no tag object; not signable)                                   |
| non-zero          | unsigned          | Annotated tag object present but no GPG/SSH signature markers detected          |
| non-zero          | unsigned          | Tag object unreadable (resolution failure or repository fetch limitation)       |
| non-zero          | unsigned          | Tag reference resolution failed (`rev-parse` returned empty)                    |
<!-- markdownlint-enable MD013 -->

<!-- markdownlint-disable MD013 -->
Notes:

- The action first inspects tag object presence (annotated vs lightweight).
- Git verify result alone does not classify signature state. Output markers (GOODSIG, VALIDSIG, BADSIG, ERRSIG, SSH patterns) determine `signing_type`.
- The "Git Verify Result" column shows internal `git verify-tag` exit codes for reference - `signing_type` is the actual output exposed by the action.
- **ERRSIG vs BADSIG distinction**: ERRSIG (missing key) returns `gpg-unverifiable` to allow consumers to make informed security decisions; BADSIG (failed verification) returns `invalid`.
- A `lightweight` tag is functionally treated as an unsigned tag for policy enforcement, but surfaced distinctly for clarity.
- `invalid` signature states cause failure when `require_signed` is `true`, `gpg`, or `ssh`.

### GitHub API Response Handling

The remote tag existence check uses HTTP status codes (`200` success, others treated as missing). A future enhancement will parse the JSON body to distinguish:

- Permission issues (403) vs true absence (404)
- Redirect or legacy ref patterns
- Error payloads indicating rate limiting
This planned improvement will allow more precise error messaging and potentially differentiated handling (e.g. retry vs fail-fast).
<!-- markdownlint-enable MD013 -->

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

<!-- markdownlint-disable MD060 -->

| require_type | tag_type | Result  |
| ------------ | -------- | ------- |
| `none`       | any      | ✅ Pass |
| `semver`     | `semver` | ✅ Pass |
| `semver`     | `both`   | ✅ Pass |
| `semver`     | `calver` | ❌ Fail |
| `calver`     | `calver` | ✅ Pass |
| `calver`     | `both`   | ✅ Pass |
| `calver`     | `semver` | ❌ Fail |

<!-- markdownlint-enable MD060 -->

### Signature Validation

<!-- markdownlint-disable MD060 -->

| require_signed | signing_type       | Result           |
| -------------- | ------------------ | ---------------- |
| `ambivalent`   | any                | ✅ Pass (always) |
| `true`         | `ssh`/`gpg`        | ✅ Pass          |
| `true`         | `gpg-unverifiable` | ❌ Fail          |
| `true`         | `unsigned`         | ❌ Fail          |
| `true`         | `lightweight`      | ❌ Fail          |
| `true`         | `invalid`          | ❌ Fail          |
| `ssh`          | `ssh`              | ✅ Pass          |
| `ssh`          | `gpg`              | ❌ Fail          |
| `ssh`          | `gpg-unverifiable` | ❌ Fail          |
| `ssh`          | `unsigned`         | ❌ Fail          |
| `ssh`          | `lightweight`      | ❌ Fail          |
| `ssh`          | `invalid`          | ❌ Fail          |
| `gpg`          | `gpg`              | ✅ Pass          |
| `gpg`          | `gpg-unverifiable` | ❌ Fail          |
| `gpg`          | `ssh`              | ❌ Fail          |
| `gpg`          | `unsigned`         | ❌ Fail          |
| `gpg`          | `lightweight`      | ❌ Fail          |
| `gpg`          | `invalid`          | ❌ Fail          |
| `false`        | `unsigned`         | ✅ Pass          |
| `false`        | `lightweight`      | ✅ Pass          |
| `false`        | `ssh`              | ❌ Fail          |
| `false`        | `gpg`              | ❌ Fail          |
| `false`        | `gpg-unverifiable` | ❌ Fail          |
| `false`        | `invalid`          | ❌ Fail          |

<!-- markdownlint-enable MD060 -->

### Security Note: Unverifiable Signatures

**Important:** When `require_signed=true` or `require_signed=gpg`, tags with
`gpg-unverifiable` signatures will **fail** validation. This is a security
feature to prevent tags signed with unknown or untrusted keys from bypassing
signature requirements.

**Why this matters:**

- A `gpg-unverifiable` signature means the key is not in your keyring
- This may mean the key is untrusted or compromised
- For production releases, accept verifiable signatures

**If you need to allow unverifiable signatures:**

- Use `require_signed=ambivalent` (accepts any signature state)
- Or import the GPG key into your keyring for verification

**Example workflow with key import:**

```yaml
- name: Import GPG keys
  run: |
    echo "${{ secrets.GPG_PUBLIC_KEY }}" | gpg --import

- name: Check tag signature
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_signed: gpg
```

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

## Local Testing

You can test the action locally using [Nektos/Act](https://nektosact.com/)
before pushing to GitHub:

```bash
# Setup (one time)
make install-act
make setup-secrets

# Run quick smoke test
make test-quick

# Run specific test suites
make test-basic
make test-local-tags
make test-signatures
make test-python

# Run all tests
make test-all
```

**Benefits:**

- ✅ Fast feedback loop (no waiting for CI)
- ✅ No GitHub Actions minutes consumed
- ✅ Easy debugging with direct container access
- ✅ Test before pushing commits

See [docs/LOCAL_TESTING.md](docs/LOCAL_TESTING.md) for detailed setup and
usage instructions.

## Contributing

Contributions are welcome! Please open an issue or pull request.

Before submitting a PR, please:

1. Test locally with `make test-all`
2. Run pre-commit hooks: `pre-commit run --all-files`
3. Ensure all tests pass
