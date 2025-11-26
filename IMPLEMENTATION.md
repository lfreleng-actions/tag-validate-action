<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Tag Validation Action - Implementation Guide

## Overview

The `tag-validate-action` is a unified GitHub Action that combines and extends
the functionality of `tag-validate-semantic-action` and
`tag-validate-calver-action`. It provides comprehensive tag validation including
version format checking (SemVer/CalVer) and cryptographic signature verification
(SSH/GPG).

## Architecture

### Input Processing Flow

```text
┌─────────────────────────────────────────────────────────────┐
│                     Input Detection                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. tag_location provided?                                  │
│     ├─── YES → Parse ORG/REPO/TAG                           │
│     │         Fetch from GitHub API (with token if provided)│
│     │         Clone repo for signature check (with token)   │
│     │                                                        │
│     └─── NO → 2. tag_string provided?                       │
│              ├─── YES → Use string (no signature check)     │
│              │                                               │
│              └─── NO → 3. Tag push event?                   │
│                       ├─── YES → Use GITHUB_REF_NAME        │
│                       │          Check local repo           │
│                       │                                      │
│                       └─── NO → Check permit_missing        │
│                                  ├─── true → Exit success   │
│                                  └─── false → Exit error    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Validation Pipeline

```text
Tag Source → Version Prefix Check → Format Detection → Type Validation
    ↓              ↓                      ↓                  ↓
    │         (v/V prefix)           (SemVer/CalVer)   (require_type)
    │              │                      │                  │
    ↓              ↓                      ↓                  ↓
Development    Signature           Enforcement        Final
Detection   →  Detection      →   Checks        →    Checks
    ↓              ↓                      ↓                  ↓
(dev/pre/     (SSH/GPG/           (require_signed)      (Outputs)
 alpha/beta)   unsigned)
```

## Key Features

### 1. Multi-Source Tag Resolution

The action supports three distinct tag sources with priority ordering:

#### Priority 1: Remote Tag Location (`tag_location`)

**Format:** `ORG/REPO/TAG`

**Examples:**

- `lfreleng-actions/tag-validate-action/v1.0.0`
- `owner/repository/2025.01.15`

**Process:**

1. Parse location into components (org, repo, tag)
2. Query GitHub API:
   `https://api.github.com/repos/{org}/{repo}/git/refs/tags/{tag}`
   - Uses authenticated request if `token` provided
   - Falls back to anonymous request if no token
3. If not found, try alternate tag name (strip/add 'v' prefix)
4. If found, clone repository temporarily for signature verification
   - Uses token in clone URL for private repositories
5. Extract tag information and check

**Implementation Details:**

```bash
# Parse tag_location
repo_org=$(echo "$tag_location" | cut -d'/' -f1)
repo_name=$(echo "$tag_location" | cut -d'/' -f2)
remote_tag=$(echo "$tag_location" | cut -d'/' -f3-)

# Prepare authentication headers
curl_headers=()
if [ -n "$token" ]; then
  curl_headers=("-H" "Authorization: token $token")
fi

# Check tag exists via API
http_code=$(curl -s -o /dev/null -w "%{http_code}" \
  "${curl_headers[@]}" \
  "https://api.github.com/repos/$repo_org/$repo_name/git/refs/tags/$remote_tag")

# Prepare clone URL with token
clone_url="https://github.com/$repo_org/$repo_name.git"
if [ -n "$token" ]; then
  clone_url="https://x-access-token:$token@github.com/$repo_org/$repo_name.git"
fi

# Clone for signature check
git clone --depth 1 --branch "$tag_to_fetch" "$clone_url" "$temp_dir"
```

### API Calls

GitHub API calls default to unauthenticated requests. To use
authenticated calls:

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

#### Priority 2: Tag String (`tag_string`)

**Format:** Any version string

**Examples:**

- `1.2.3`
- `v2.0.0-beta.1`
- `2025.01.15-dev`

**Process:**

1. Use string directly for validation
2. Check version prefix
3. Detect tag type (SemVer/CalVer)
4. Detect development identifiers
5. **Skip signature checking** (no repository access)

**Use Cases:**

- Check version strings before creating tags
- Pre-flight validation in CI/CD
- Version string format checking

#### Priority 3: Git Context (Tag Push Event)

**Automatic Detection:** When `GITHUB_REF` starts with `refs/tags/`

**Process:**

1. Extract tag name from `GITHUB_REF_NAME`
2. Verify you checked out git repository
3. Perform full validation including signatures
4. Check local repository for tag object

**Trigger Example:**

```yaml
on:
  push:
    tags:
      - 'v*'
      - '[0-9]+.*'
```

### 2. Version Format Detection

#### Semantic Versioning (SemVer)

**Pattern:** Official semver.org regular expression

```regex
^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$
```

**Valid Examples:**

- `1.0.0` - Simple version
- `2.3.1` - Patch update
- `0.1.0-alpha.1` - Pre-release with identifier
- `1.0.0-beta+exp.sha.5114f85` - Pre-release with build metadata
- `1.0.0+20130313144700` - With build metadata

**Invalid Examples:**

- `1.0` - Missing patch version
- `v1.0.0` - Prefix included (stripped before checking)
- `1.0.0.0` - Four version segments
- `01.0.0` - Leading zero in major version

#### Calendar Versioning (CalVer)

**Pattern:** Flexible pattern supporting different CalVer schemes

```regex
^(\d{2}|\d{4})\.(\d{1}|\d{2})((\.|\_|-)[a-zA-Z][a-zA-Z0-9\.\-\_]*)?(\.(\d{1}|\d{2})((\.|\_|-)[a-zA-Z][a-zA-Z0-9\.\-\_]*)?)?$
```

**Valid Examples:**

- `2025.01.15` - YYYY.MM.DD format
- `25.1.0` - YY.M.MICRO format
- `2025.1` - YYYY.M format
- `2025.01.15-beta.1` - With pre-release identifier
- `25.12.3_build123` - With build identifier

**Invalid Examples:**

- `2025` - Missing month component
- `2025.13.01` - Invalid month (>12)
- `25.1` - Ambiguous format (needs at least one more segment)

#### Tags Matching Both Formats

Some tags may match both SemVer and CalVer patterns. For example:

- `2025.1.2` - Valid as both CalVer (YYYY.M.D) and SemVer (MAJOR.MINOR.PATCH)
- `25.1.0` - Valid as both CalVer (YY.M.D) and SemVer (MAJOR.MINOR.PATCH)

When a tag matches both patterns, the `tag_type` output becomes `both`. This allows:

- `require_type: semver` - Tag passes (satisfies SemVer)
- `require_type: calver` - Tag passes (satisfies CalVer)
- `require_type: none` - Tag passes (no constraint)

### 3. Signature Detection

#### GPG Signatures

**Detection Method:**

```bash
# Run git verify-tag with raw output
verify_output=$(git verify-tag --raw "$tag_name" 2>&1 || true)

# Check for GPG markers
if echo "$verify_output" | \
  grep -qE "\[GNUPG:\] (GOODSIG|VALIDSIG|ERRSIG)"; then
  signing_type="gpg"
fi
```

**GPG Markers:**

- `GOODSIG` - Good signature, key in keyring and trusted
- `VALIDSIG` - Valid signature structure
- `ERRSIG` - Signature present but verification failed (key not trusted/available)

**Tag Object Structure:**

```bash
object 1234567890abcdef1234567890abcdef12345678
type commit
tag v1.0.0
tagger Name <email@example.com> 1234567890 +0000

Release v1.0.0
-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEE...
...
-----END PGP SIGNATURE-----
```

#### SSH Signatures

**Detection Method:**

```bash
# Check for SSH-specific markers in verification output
if echo "$verify_output" | grep -qi "Good \"git\" signature.*with.*key"; then
  signing_type="ssh"
fi

# Alternative: Check tag object directly
if git cat-file tag "$tag_name" | grep -q "^-----BEGIN SSH SIGNATURE-----"; then
  signing_type="ssh"
fi
```

**Tag Object Structure:**

```text
object 1234567890abcdef1234567890abcdef12345678
type commit
tag v1.0.0
tagger Name <email@example.com> 1234567890 +0000

Release v1.0.0
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg...
...
-----END SSH SIGNATURE-----
```

**Requirements:**

- Git 2.34+ for SSH signing support
- Tag must exist in a git repository
- Does not require key validation (detects signature presence)

### 4. Development Tag Detection

**Identifiers Detected (Case-Insensitive):**

- `dev` - Development builds
- `pre` - Pre-release versions
- `alpha` - Alpha releases
- `beta` - Beta releases
- `rc` - Release candidates
- `snapshot` - Snapshot builds
- `nightly` - Nightly builds
- `canary` - Canary releases
- `preview` - Preview releases (ex: `v1.0.0-preview`)

**Detection Method:**

```bash
if echo "$clean_tag" | \
  grep -Eqi '(dev|pre|alpha|beta|rc|snapshot|nightly|canary|preview)'; then
  development_tag="true"
fi
```

**Examples:**

- `v1.0.0-dev` → `development_tag: true`
- `2025.01-BETA.1` → `development_tag: true`
- `1.0.0-rc.1` → `development_tag: true`
- `v1.0.0` → `development_tag: false`
- `1.2.3+snapshot` → `development_tag: true`

### 5. Version Prefix Detection

**Supported Prefixes:** `v` or `V`

**Detection:**

```bash
if [[ "$tag_name" == v* ]] || [[ "$tag_name" == V* ]]; then
  version_prefix="true"
fi
```

**Processing:**

- Prefix detected and flagged in output
- Prefix stripped before format validation
- Both lowercase and uppercase supported

**Examples:**

- `v1.0.0` → `version_prefix: true`, validates `1.0.0`
- `V2.0.0` → `version_prefix: true`, validates `2.0.0`
- `1.0.0` → `version_prefix: false`, validates `1.0.0`

## Input Validation

### require_type Validation

**Values:** `semver` | `calver` | `none`

**Processing:**

```bash
require_type=$(echo "${{ inputs.require_type }}" | \
  tr '[:upper:]' '[:lower:]')
```

**Logic:**

```text
┌─────────────────┬──────────────┬──────────┐
│  require_type   │  tag_type    │  Result  │
├─────────────────┼──────────────┼──────────┤
│  none           │  any         │  ✅ Pass │
│  semver         │  semver      │  ✅ Pass │
│  semver         │  both        │  ✅ Pass │
│  semver         │  calver      │  ❌ Fail │
│  semver         │  unknown     │  ❌ Fail │
│  calver         │  calver      │  ✅ Pass │
│  calver         │  both        │  ✅ Pass │
│  calver         │  semver      │  ❌ Fail │
│  calver         │  unknown     │  ❌ Fail │
└─────────────────┴──────────────┴──────────┘
```

### require_signed Validation

**Values:** `ambivalent` | `true` | `ssh` | `gpg` | `false`

**Processing:**

```bash
require_signed=$(echo "${{ inputs.require_signed }}" | \
  tr '[:upper:]' '[:lower:]')
```

**Validation Matrix:**

```text
┌────────────────┬──────────────┬─────────────────────────────────┐
│ require_signed │ signing_type │  Result                         │
├────────────────┼──────────────┼─────────────────────────────────┤
│ ambivalent     │  any         │  ✅ Pass (no enforcement)       │
│ true           │  unsigned    │  ❌ Fail "Tag NOT signed"       │
│ true           │  ssh/gpg     │  ✅ Pass "Tag signed"           │
│ ssh            │  ssh         │  ✅ Pass "SSH signed"           │
│ ssh            │  gpg         │  ❌ Fail "GPG signed"           │
│ ssh            │  unsigned    │  ❌ Fail "NOT signed"           │
│ gpg            │  gpg         │  ✅ Pass "GPG signed"           │
│ gpg            │  ssh         │  ❌ Fail "SSH signed"           │
│ gpg            │  unsigned    │  ❌ Fail "NOT signed"           │
│ false          │  unsigned    │  ✅ Pass "unsigned"             │
│ false          │  ssh/gpg     │  ❌ Fail "signed"               │
└────────────────┴──────────────┴─────────────────────────────────┘
```

### permit_missing Behavior

**Values:** `true` | `false`

**When permit_missing = true:**

- Missing tags (no tag push event, empty inputs) → Success
- Non-existent remote tags → Success
- Empty tag_string → Success
- Invalid tag_location format → Still fails
- Validation failures (type/signature mismatch) → Still fail

**When permit_missing = false (default):**

- Missing tags → Fail
- Non-existent remote tags → Fail
- Empty tag_string → Fail
- Any validation failure → Fail

## Output Generation

### Output Values

The action sets all outputs via `GITHUB_OUTPUT`:

```bash
echo "valid=$valid" >> "$GITHUB_OUTPUT"
echo "tag_type=$tag_type" >> "$GITHUB_OUTPUT"
echo "signing_type=$signing_type" >> "$GITHUB_OUTPUT"
echo "development_tag=$development_tag" >> "$GITHUB_OUTPUT"
echo "version_prefix=$version_prefix" >> "$GITHUB_OUTPUT"
echo "tag_name=$tag_name" >> "$GITHUB_OUTPUT"
```

### Output Summary

The action generates a formatted summary in `GITHUB_STEP_SUMMARY`:

```markdown
## 🏷️ Tag Validation Results

| Property        | Value    |
| --------------- | -------- |
| Tag Name        | `v1.0.0` |
| Tag Type        | `semver` |
| Signing Type    | `gpg`    |
| Development Tag | `false`  |
| Version Prefix  | `true`   |
| Valid           | `true`   |

✅ **Tag validation passed**

## Error Handling

### Error Scenarios

**Invalid tag_location Format**

```text
Error: Invalid tag_location format. Expected ORG/REPO/TAG ❌
Example: lfreleng-actions/tag-validate-action/v0.1.0
```

### Type Mismatch

```text
Error: Tag type mismatch ❌
  Required: semver
  Detected: calver
```

### Signature Rule Not Met

```text
Error: Tag was NOT signed ❌
```

```text
Error: Tag has GPG signature (SSH required) ❌
```

### Missing Tag (permit_missing=false)

```text
Error: No tag found (not a tag push event) ❌
```

```text
Error: Remote tag not found: org/repo/v1.0.0 ❌
```

### Exit Codes

- **0** - Check passed
- **1** - Check failed (any error condition)

## Testing Strategy

### Unit Tests

Located in `.github/workflows/testing.yaml`:

1. **String Validation Tests**
   - SemVer format validation
   - CalVer format validation
   - Version prefix detection
   - Development tag detection
   - Type mismatch scenarios

2. **Local Tag Tests**
   - Tag push event simulation
   - permit_missing behavior
   - Local tag signature detection

3. **Remote Tag Tests**
   - GitHub API integration
   - Tag name variations (with/without v prefix)
   - Non-existent tag handling

4. **Signature Tests**
   - Unsigned tag detection
   - SSH signature detection
   - GPG signature detection
   - Signature rule enforcement

5. **Edge Case Tests**
   - Empty inputs
   - Long version strings
   - Development keywords
   - Case sensitivity
   - Input priority

### Integration Tests

Test against real repositories:

- `lfreleng-actions/test-tags-semantic` - SemVer test tags
- `lfreleng-actions/test-tags-calver` - CalVer test tags

These repositories contain:

- Unsigned tags
- SSH-signed tags
- GPG-signed tags

## Performance Considerations

### Remote Tag Fetching

**Optimization:**

- Shallow clone: `--depth 1`
- Single branch: `--branch <tag>`
- Temporary directory cleanup with trap

**API Rate Limits:**

- Anonymous (no token): 60 requests/hour
- Authenticated (with token): 5,000 requests/hour

**Token Usage:**
Provide a GitHub token via the `token` input to:

- Increase rate limits from 60 to 5,000 requests/hour
- Access private repositories
- Ensure consistent authentication

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

### Caching

No caching implemented by default. For workflows checking tags, consider:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/tag-validate
    key: tag-cache-${{ github.run_id }}
```

## Security Considerations

### Git Repository Cloning

The action clones remote repositories to temporary directories:

```bash
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT
```

### Authentication

GitHub API calls support both authenticated and anonymous access:

**Anonymous (default):**

- No token required
- 60 requests/hour rate limit
- Cannot access private repositories

**Authenticated (recommended):**

- Provide token via `token` input
- 5,000 requests/hour rate limit
- Can access private repositories (with appropriate permissions)

**Example:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/private-repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

**Token Permissions:**

- Public repositories: No special permissions needed
- Private repositories: `repo` scope required
- For workflows in the same repository: `${{ secrets.GITHUB_TOKEN }}`
  automatically has required permissions

### Signature Verification

**Important Notes:**

- Action detects signature **presence**, not validity
- GPG key trust is not verified in CI (key may not be in keyring or have
  trust status)
- SSH signature check does not verify allowed signers
- For strict security, combine with separate key checks

## Migration Guide

### From tag-validate-semantic-action

**Old:**

```yaml
- uses: lfreleng-actions/tag-validate-semantic-action@v1
  with:
    string: ${{ github.ref_name }}
    exit_on_fail: true
    require_signed: gpg
```

**New:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver
    require_signed: gpg
```

**Changes:**

- `string` input removed (auto-detected from context)
- `exit_on_fail` removed (always exits on fail)
- `dev_version` output → `development_tag`
- Added: `tag_type`, `version_prefix`, `tag_name` outputs

### From tag-validate-calver-action

**Old:**

```yaml
- uses: lfreleng-actions/tag-validate-calver-action@v1
  with:
    string: ${{ github.ref_name }}
    require_signed: ssh
```

**New:**

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: calver
    require_signed: ssh
```

**Changes:** Same as above

## Best Practices

### 1. Specify require_type

```yaml
# ✅ Good
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    require_type: semver

# ⚠️ Less safe
- uses: lfreleng-actions/tag-validate-action@v1
```

### 2. Use fetch-depth: 0 for Local Tags

```yaml
# ✅ Good
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: lfreleng-actions/tag-validate-action@v1
```

### 3. Combine with Other Checks

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  id: check

- name: "More checks"
  if: steps.check.outputs.development_tag == 'false'
  run: |
    # Production checks
    ./scripts/check-production-release.sh
```

### 4. Use permit_missing for Optional Checks

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "${{ inputs.dependency }}"
    require_type: semver
    permit_missing: true  # OK if dependency not tagged yet
```

## Troubleshooting

### Issue: "Tag not found" on tag push events

**Solution:**

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0  # Fetch all tags
```

### Issue: Signature always shows "unsigned"

**Causes:**

1. Using `tag_string` mode (no signature check)
2. Not in a git repository
3. Tag doesn't exist locally

**Solution:** Use tag push events or `tag_location` for signature validation

### Issue: Remote tag rate limiting

**Solution:** Provide GitHub token as input:

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "owner/repo/v1.0.0"
    token: ${{ secrets.GITHUB_TOKEN }}
```

### Issue: Cannot access private repository

**Solution:** Provide a token with appropriate permissions:

```yaml
- uses: lfreleng-actions/tag-validate-action@v1
  with:
    tag_location: "my-org/private-repo/v1.0.0"
    token: ${{ secrets.PAT_TOKEN }}  # Personal Access Token with repo scope
```

### Issue: Case-sensitive input not working

**Note:** All inputs (`require_type`, `require_signed`) are automatically lowercased

## Future Enhancements

### Planned Features

1. **Custom regex patterns** - Allow user-defined version patterns
2. **Batch tag checks** - Check tags in single run
3. **Commit signature checking** - Check commit signatures with tag
   signatures
4. **Enhanced remote fetching** - Support for private repositories with token
   authentication
5. **Caching support** - Built-in caching for remote repository clones
6. **Webhook integration** - Check tags before push

### API Stability

The current API is stable for v1.x releases. Breaking changes occur in major
version bumps.

## Conclusion

The `tag-validate-action` provides a comprehensive, flexible solution for tag
checks in GitHub workflows. It combines version format checks with cryptographic
signature verification, supporting input sources and enforcement rules.

For questions, issues, or contributions, please visit the
[GitHub repository](https://github.com/lfreleng-actions/tag-validate-action).
