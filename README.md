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
          require_signed: gpg
```

### Check Local Repository Tag

```yaml
- name: "Check local tag"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: v1.0.0
    require_type: semver
    require_signed: gpg
```

### Check with Gerrit Verification

```yaml
- name: "Check tag with Gerrit verification"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: v1.0.0
    require_type: semver
    require_signed: gpg
    require_gerrit: 'true'  # Auto-discovers gerrit.[org].org
```

### Check with Both GitHub and Gerrit

```yaml
- name: "Check tag with dual verification"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: v1.0.0
    require_github: 'true'
    require_gerrit: 'gerrit.onap.org'
    require_owner: 'maintainer@project.org'
    token: ${{ secrets.GITHUB_TOKEN }}
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

| Name               | Required | Default | Description                                                                                               |
| ------------------ | -------- | ------- | --------------------------------------------------------------------------------------------------------- |
| tag_location       | False    | ''      | Path to tag: remote (ORG/REPO/TAG) or local (PATH/TO/REPO/TAG)                                            |
| tag_string         | False    | ''      | Tag string to check (version format, signature check skipped)                                             |
| require_type       | False    | ''      | Required tag type: `semver`, `calver`, `both`, `none` (comma-separated)                                   |
| require_signed     | False    | ''      | Signature type: `gpg`, `ssh`, `gpg-unverifiable`, `unsigned`                                              |
| require_github     | False    | false   | Requires that signing key is registered to a GitHub account                                               |
| require_gerrit     | False    | false   | Requires that signing key is registered to a Gerrit account (true for auto-discovery, or server hostname) |
| require_owner      | False    | ''      | GitHub/Gerrit username(s)/email(s) that must own signing key                                              |
| reject_development | False    | false   | Reject development/pre-release tags (alpha, beta, rc, dev, etc.)                                          |
| permit_missing     | False    | false   | Allow missing tags without error                                                                          |
| token              | False    | ''      | GitHub token for authenticated API calls and private repo access                                          |
| github_server_url  | False    | ''      | GitHub server URL (for GitHub Enterprise Server)                                                          |
| debug              | False    | false   | Enable debug output including git error messages                                                          |

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

Enforces the versioning scheme the tag must follow. Accepts comma-separated values.

Version type is **always detected and reported** in outputs, regardless of this
setting. This has negligible performance impact (regex matching, no external
calls).

🎯 **Version Types**

| Type     | Meaning             | Example           |
| -------- | ------------------- | ----------------- |
| `semver` | Semantic Versioning | `v1.2.3`          |
| `calver` | Calendar Versioning | `2024.01.15`      |
| `both`   | Valid as both       | `2024.1.0`        |
| `other`  | Custom format       | `release-2024-q1` |

**Examples:**

- `require_type: semver` - Requires SemVer
- `require_type: semver,calver` - Accepts either SemVer or CalVer
- `require_type: both` - Requires tags valid as both SemVer and CalVer
- `require_type: none` or omit - Accepts any format (semver, calver, or custom)

**Important:** When omitted, custom tag formats (type: `other`) are accepted.
This enables signature validation for repositories using custom tagging
schemes.

**Note:** Input is case-insensitive.

#### `require_signed`

Controls cryptographic signature types. Accepts comma-separated values.

🔐 **Signature Types**

<!-- markdownlint-disable MD013 -->

| Type               | Meaning                                | Example Use Case      |
| ------------------ | -------------------------------------- | --------------------- |
| `gpg`              | GPG-signed with verifiable signature   | Production releases   |
| `ssh`              | SSH-signed with verifiable signature   | Development workflows |
| `gpg-unverifiable` | GPG-signed (verification not required) | Legacy signatures     |
| `unsigned`         | Must have no signature                 | Lightweight tags      |
| `lightweight`      | Lightweight tag (output)               | Auto-generated tags   |
| `invalid`          | Invalid signature (output)             | Failed verification   |

<!-- markdownlint-enable MD013 -->

**Examples:**

- `require_signed: gpg` - Requires verified GPG signature
- `require_signed: gpg,ssh` - Accepts either verified GPG or SSH signature
- `require_signed: unsigned` - Requires no signature

**Note:** Input is case-insensitive. The action skips signature checking when
using `tag_string` mode.

#### `require_github`

When set to `true`, requires that the signing key is registered to a GitHub account.
This verifies that the key used to sign the tag is associated with any GitHub user.

**Requires:** A GitHub token must be provided via the `token` input.

**Example:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_signed: gpg
    require_github: true
    token: ${{ secrets.GITHUB_TOKEN }}
```

**GitHub Username Auto-Detection:**

When `require_github` is enabled but no specific username is provided via
`require_owner`, the action will attempt to automatically detect the GitHub
username from the tagger's email address found in the tag signature. If
successful, the username will be displayed with an `[enumerated]` indicator in
the output to show auto-detection rather than explicit specification.

**Note:** Use in combination with `require_owner` to verify the key belongs to
specific GitHub user(s).

#### `require_owner`

Specifies one or more GitHub usernames or email addresses that must own the
signing key.
Accepts comma or space-separated values.

When specified, the action verifies that the key used to sign the tag is
registered to
one of the provided GitHub accounts or email addresses.

**Requires:** A GitHub token must be provided via the `token` input.

**Examples:**

```yaml
# Single owner by username
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_signed: gpg
    require_owner: octocat
    token: ${{ secrets.GITHUB_TOKEN }}
```

```yaml
# Two owners (comma-separated)
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_signed: gpg
    require_owner: octocat,monalisa
    token: ${{ secrets.GITHUB_TOKEN }}
```

```yaml
# Email addresses
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_signed: gpg
    require_owner: octocat@github.com,monalisa@example.com
    token: ${{ secrets.GITHUB_TOKEN }}
```

```yaml
# Mixed usernames and emails
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_signed: gpg
    require_owner: octocat,monalisa@example.com
    token: ${{ secrets.GITHUB_TOKEN }}
```

**Note:** When `require_owner` is specified, `require_github` is implied and
does not need to be set separately.

#### `reject_development`

When set to `true`, the action will reject tags identified as development or
pre-release versions.

Development tags are identified by the presence of keywords in the tag name:

- `alpha`, `beta`, `rc` (release candidate)
- `dev`, `pre`, `preview`
- `snapshot`, `nightly`, `canary`

**Use cases:**

- Prevent accidental releases from development tags
- Enforce production deployments
- Skip CD pipelines for pre-release versions

**Examples:**

```yaml
# Reject development tags in production deployment
- name: "Check production tag"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver
    reject_development: true
```

```yaml
# Allow development tags (default behavior)
- name: "Check any tag"
  uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver
    reject_development: false  # or omit this line
```

**Development tag examples that will be rejected:**

- `v1.0.0-alpha`
- `v2.1.0-beta.1`
- `v3.0.0-rc1`
- `2024.01.15-dev`
- `v1.2.3-snapshot`

**Production tag examples that will pass:**

- `v1.0.0`
- `v2.1.0`
- `2024.01.15`

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

Enable comprehensive debug output in action logs for troubleshooting.

When enabled, the action will output:

- **Bash command tracing**: Shows all shell commands being executed (`set -x`)
- **Python verbose logging**: Enables DEBUG level logging from the Python CLI (`--verbose`)
- Internal variable values
- Git command outputs and error messages
- Tag object inspection details
- Signature verification details
- API calls and responses
- Repository cloning and tag fetching operations

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
| tag_type        | Detected tag type: `semver`, `calver`, `both`, or `other`                                      |
| signing_type    | Signing method used: `unsigned`, `ssh`, `gpg`, `gpg-unverifiable`, `lightweight`, or `invalid` |
| development_tag | Set to `true` if tag contains pre-release/development strings                                  |
| version_prefix  | Set to `true` if tag has leading v/V character                                                 |
| tag_name        | The tag name under inspection                                                                  |

<!-- markdownlint-enable MD013 -->

## Exit Codes

When using the Python CLI (`tag-validate`), the following exit codes are returned:

<!-- markdownlint-disable MD013 -->

| Exit Code | Name                     | Description                                                                  |
| --------- | ------------------------ | ---------------------------------------------------------------------------- |
| 0         | EXIT_SUCCESS             | Validation passed                                                            |
| 1         | EXIT_VALIDATION_FAILED   | Validation failed (type mismatch, signature requirements not met, etc.)      |
| 2         | EXIT_MISSING_TOKEN       | GitHub token required but not provided (when using `--require-github`)       |
| 3         | EXIT_INVALID_INPUT       | Invalid input parameters or malformed arguments                              |
| 4         | EXIT_UNEXPECTED_ERROR    | Unexpected error during execution                                            |
| 5         | EXIT_MISSING_CREDENTIALS | Gerrit credentials required but not provided (when using `--require-gerrit`) |
| 6         | EXIT_AUTH_FAILED         | Gerrit authentication failed (invalid username or password)                  |

<!-- markdownlint-enable MD013 -->

**Notes:**

- Exit code `2` (EXIT_MISSING_TOKEN) is specifically returned when:
  - `--require-github` flag is used but `GITHUB_TOKEN` environment variable is
    not set
  - GitHub API access is required but no authentication token is available

- Exit code `5` (EXIT_MISSING_CREDENTIALS) is returned when:
  - `--require-gerrit` flag is used but Gerrit credentials are not provided
  - Gerrit server requires authentication but `GERRIT_USERNAME` or `GERRIT_PASSWORD`
    environment variables are not set

- Exit code `6` (EXIT_AUTH_FAILED) is returned when:
  - Gerrit credentials are provided but authentication fails
  - Username or HTTP password is incorrect
  - **Note:** Gerrit requires an HTTP password (from Settings > HTTP Credentials),
    not your SSO/LDAP password

- Exit code `1` (EXIT_VALIDATION_FAILED) covers all validation failures
  including:
  - Version type mismatch (e.g., CalVer tag when SemVer required)
  - Signature requirements not met
  - Signing key not registered on GitHub/Gerrit (when `--require-github` or
    `--require-gerrit` is used)
  - Missing username for key verification

**Example handling exit codes in CI:**

```bash
#!/bin/bash

tag-validate verify v1.2.3 --require-github --owner myuser
exit_code=$?

case $exit_code in
  0)
    echo "✅ Validation passed"
    ;;
  1)
    echo "❌ Validation failed"
    exit 1
    ;;
  2)
    echo "❌ GitHub token not provided"
    echo "Set GITHUB_TOKEN environment variable"
    exit 1
    ;;
  5)
    echo "❌ Gerrit credentials not provided"
    echo "Set GERRIT_USERNAME and GERRIT_PASSWORD environment variables"
    exit 1
    ;;
  6)
    echo "❌ Gerrit authentication failed"
    echo "Verify your Gerrit HTTP password (not SSO/LDAP password)"
    exit 1
    ;;
  *)
    echo "❌ Unexpected error (exit code: $exit_code)"
    exit 1
    ;;
esac
```

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
    require_signed: gpg,ssh
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
- `invalid` signature states cause failure when `require_signed` is `gpg` or `ssh`.

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

**Important:** When `require_signed=gpg`, tags with `gpg-unverifiable`
signatures will **fail** validation. This is a security feature to prevent
tags signed with unknown or untrusted keys from bypassing signature requirements.

**Why this matters:**

- A `gpg-unverifiable` signature means the key is not in your keyring
- This may mean the key is untrusted or compromised
- For production releases, accept verifiable signatures

**If you need to allow unverifiable signatures:**

- Omit `require_signed` (accepts any signature state)
- Use `require_signed=gpg-unverifiable` (accepts unverifiable GPG signatures)
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

## Gerrit Integration

This action now supports verifying cryptographic signing keys against Gerrit
Code Review servers. This provides enhanced security by ensuring that
authorized developers with registered keys can create valid signed tags.

For comprehensive documentation on Gerrit integration, including setup
examples, server configuration, and troubleshooting, see:

📖 **[GERRIT_INTEGRATION.md](docs/GERRIT_INTEGRATION.md)**

Key features:

- Auto-discovery of Gerrit servers from GitHub organization names
- SSH and GPG key verification against Gerrit accounts
- Support for required account owners
- Combined GitHub + Gerrit verification
- Works with popular Gerrit instances (ONAP, OpenDaylight, Eclipse, etc.)

## Contributing

Contributions are welcome! Please open an issue or pull request.

Before submitting a PR, please:

1. Test locally with `make test-all`
2. Run pre-commit hooks: `pre-commit run --all-files`
3. Ensure all tests pass
