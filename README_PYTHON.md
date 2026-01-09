<!--
SPDX-FileCopyrightText: 2025 Linux Foundation
SPDX-License-Identifier: Apache-2.0
-->

# tag-validate Python Package

A comprehensive Python tool for validating Git tags with cryptographic signature
verification and GitHub key checking.

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Features

- ✅ **Version Validation** - Support SemVer and CalVer formats
- ✅ **Signature Detection** - Detect GPG and SSH signatures
- ✅ **GitHub Integration** - Verify signing keys on GitHub
- ✅ **Development Tags** - Identify alpha, beta, rc versions
- ✅ **Remote Tags** - Clone and verify remote repository tags
- ✅ **Rich CLI** - Beautiful terminal output with Rich
- ✅ **JSON Output** - Machine-readable output for automation
- ✅ **Type Safe** - Full type hints with Pydantic models
- ✅ **Async** - Efficient async/await operations

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [Programmatic Usage](#programmatic-usage)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Testing](#testing)
- [Development](#development)
- [License](#license)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/lfreleng-actions/tag-validate-action.git
cd tag-validate-action

# Install with development dependencies
pip install -e ".[dev]"

# Or install without dev dependencies
pip install -e .
```

### Requirements

- Python 3.11 or higher
- Git installed and available in PATH
- (Optional) GitHub token for API access (set via `GITHUB_TOKEN` environment
  variable)

### Security Note: GitHub Token Usage

**⚠️ IMPORTANT: Never pass GitHub tokens as command-line arguments in shared
or CI environments!**

GitHub tokens should **always** be provided via the `GITHUB_TOKEN` environment
variable:

```bash
# ✅ SECURE: Set token in environment
export GITHUB_TOKEN="your_token_here"
tag-validate verify v1.2.3 --verify-github-key --owner username

# ❌ INSECURE: Do NOT pass token as CLI argument
# This exposes the token in process listings and shell history!
tag-validate verify v1.2.3 --verify-github-key --owner username --token $GITHUB_TOKEN
```

**Why?** Command-line arguments are visible to:

- Other users on the system via `ps`, `/proc`, or process monitors
- Shell history files (even with `$VARIABLE` expansion)
- Log aggregation tools and process auditing systems

The `--token` flag exists only for single-user development systems where you
control all processes. **Never use it in CI/CD pipelines, shared servers, or
cloud environments.**

## Quick Start

### Verify a Local Tag

```bash
# Basic validation
tag-validate verify v1.2.3

# Require specific version type
tag-validate verify v1.2.3 --require-type semver

# Require tag to be signed
tag-validate verify v1.2.3 --require-signed true
```

### Verify a Remote Tag

```bash
# Verify tag from GitHub repository
tag-validate verify torvalds/linux@v6.0

# With GitHub key verification (token from GITHUB_TOKEN env var)
export GITHUB_TOKEN="your_token_here"
tag-validate verify torvalds/linux@v6.0 \
  --verify-github-key \
  --owner torvalds
```

### Version Format Check

```bash
# Check version format
tag-validate validate v1.2.3

# Check CalVer format
tag-validate validate 2024.01.15 --require-type calver

# Strict SemVer (no 'v' prefix)
tag-validate validate 1.2.3 --strict-semver
```

### Signature Detection

```bash
# Detect signature on a tag
tag-validate detect v1.2.3

# Output as JSON
tag-validate detect v1.2.3 --json
```

## CLI Usage

### Commands

#### `verify` - Complete Tag Validation

Performs comprehensive tag validation including version format, signature
verification, and optional GitHub key checking.

```bash
tag-validate verify <tag-location> [OPTIONS]
```

**Arguments:**

- `tag-location` - Tag name (e.g., `v1.2.3`) or remote location (e.g., `owner/repo@tag`)

**Options:**

- `--require-type semver|calver` - Require specific version type
- `--require-signed` - Require tag to be signed
- `--skip-version-validation` - Skip version format validation (only check signature)
- `--verify-github-key` - Verify signing key on GitHub
- `--owner USER` / `-o` - GitHub username for key verification
- `--token TOKEN` - GitHub API token (**NOT RECOMMENDED**: use `GITHUB_TOKEN`
  env var instead for security)
- `--reject-development` - Reject development versions (alpha, beta, rc)
- `--repo-path PATH` - Path to Git repository (default: current directory)
- `--json` - Output results as JSON

**Examples:**

```bash
# Basic validation
tag-validate verify v1.2.3

# Strict SemVer with signature required
tag-validate verify v1.2.3 --require-type semver --require-signed true

# Remote tag with GitHub verification
tag-validate verify torvalds/linux@v6.0 \
  --require-type semver \
  --verify-github-key \
  --owner torvalds

# Reject development versions
tag-validate verify v1.2.3-beta --reject-development
# ❌ This will fail

# JSON output for automation
tag-validate verify v1.2.3 --json | jq '.success'

# Only verify signature and GitHub key (skip version validation)
# Useful for tags that don't follow SemVer/CalVer
tag-validate verify my-custom-tag --skip-version-validation \
  --require-signed --verify-github-key --owner username
```

#### `validate` - Version Format Check

Check version strings against SemVer or CalVer patterns.

```bash
tag-validate validate <version-string> [OPTIONS]
```

**Options:**

- `--require-type semver|calver` - Require specific version type
- `--allow-prefix / --no-prefix` - Allow/disallow 'v' prefix
- `--strict-semver` - Enforce strict SemVer (no prefix, exact format)
- `--json` - Output results as JSON

**Examples:**

```bash
# Verify SemVer
tag-validate validate v1.2.3

# Verify CalVer
tag-validate validate 2024.01.15

# Strict SemVer (no 'v' prefix)
tag-validate validate 1.2.3 --strict-semver

# Require specific type
tag-validate validate v1.2.3 --require-type semver
```

#### `detect` - Signature Detection

Detects and displays signature information for a Git tag.

```bash
tag-validate detect <tag-name> [OPTIONS]
```

**Options:**

- `--repo-path PATH` - Path to Git repository
- `--json` - Output results as JSON

**Examples:**

```bash
# Detect signature
# Detect signature type
tag-validate detect v1.2.3

# JSON output
tag-validate detect v1.2.3 --json
```

#### `verify-github` - Verify Specific Key on GitHub

Verifies if a specific GPG key ID or SSH fingerprint is registered on GitHub
(without needing a tag). The key type is auto-detected by default.

```bash
tag-validate verify-github <key-id-or-fingerprint> --owner <github-user> [OPTIONS]
```

**Options:**

- `--owner USER` - GitHub username to verify against (required)
- `--type TYPE` - Key type: 'gpg', 'ssh', or 'auto' (default: auto-detect)
- `--token TOKEN` - GitHub API token (**NOT RECOMMENDED**: use `GITHUB_TOKEN`
  env var instead for security)
- `--no-subkeys` - Disable GPG subkey verification (only for GPG keys)
- `--json` - Output results as JSON

**Examples:**

```bash
# Set GITHUB_TOKEN environment variable first for all examples below
export GITHUB_TOKEN="your_token_here"

# Verify a GPG key ID (auto-detected)
tag-validate verify-github FCE8AAABF53080F6 --owner torvalds

# Verify an SSH key (auto-detected)
tag-validate verify-github "ssh-ed25519 AAAAC3NzaC1..." --owner torvalds

# Verify an SSH fingerprint (auto-detected)
tag-validate verify-github "SHA256:abc123..." --owner torvalds

# Explicitly specify type if auto-detection fails
tag-validate verify-github D9141D556C7E379A --owner torvalds --type gpg

# Check GPG primary key only (exclude subkeys)
tag-validate verify-github D9141D556C7E379A --owner torvalds --no-subkeys
```

### Output Formats

#### Console Output (Default)

Beautiful, color-coded output using Rich:

```text
┌─────────────────────────────────────────┐
│ ✅ Tag Validation: PASSED               │
├─────────────────────────────────────────┤
│ Tag: v1.2.3                             │
│                                         │
│ Version: 1.2.3                          │
│   Type: SEMVER                          │
│   Components: 1.2.3                     │
│                                         │
│ Signature: GPG                          │
│   Verified: Yes                         │
│   Signer: user@example.com              │
│   Key ID: 1234567890ABCDEF              │
└─────────────────────────────────────────┘
```

#### JSON Output

Machine-readable JSON for automation:

```json
{
  "success": true,
  "tag_name": "v1.2.3",
  "version_type": "semver",
  "signature_type": "gpg",
  "signature_verified": true,
  "key_registered": true,
  "errors": [],
  "warnings": [],
  "info": [
    "Tag type: annotated",
    "Version type: semver",
    "Tag is signed with GPG",
    "All validation checks passed"
  ]
}
```

## Programmatic Usage

### Complete Validation Workflow

```python
import asyncio
from pathlib import Path
from tag_validate.workflow import ValidationWorkflow
from tag_validate.models import ValidationConfig

async def validate_tag():
    # Configure validation requirements
    config = ValidationConfig(
        require_semver=True,
        require_signed=True,
        verify_github_key=True,
        reject_development=True,
    )

    # Create workflow
    workflow = ValidationWorkflow(config, repo_path=Path.cwd())

    # Run validation
    result = await workflow.validate_tag(
        tag_name="v1.2.3",
        github_user="torvalds",  # Note: API uses github_user internally
        github_token="ghp_...",
    )

    # Check result
    if result.is_valid:
        print("✅ Validation passed!")
    else:
        print("❌ Validation failed!")
        for error in result.errors:
            print(f"  • {error}")

    return result

# Run validation
result = asyncio.run(validate_tag())
```

### Version Validation

```python
from tag_validate.validation import TagValidator

validator = TagValidator()

# Check version format
result = validator.validate_version("v1.2.3")

if result.is_valid:
    print(f"Valid {result.version_type}: {result.normalized}")
    print(f"Components: {result.major}.{result.minor}.{result.patch}")
else:
    print(f"Invalid: {result.errors}")

# Check development version
if validator.is_development_tag("v1.2.3-beta"):
    print("Development version detected")

# Compare versions
comparison = validator.compare_versions("v1.2.3", "v1.2.4")
# Returns: -1 (first < second)
```

### GPG and SSH Signature Detection

```python
import asyncio
from pathlib import Path
from tag_validate.signature import SignatureDetector

async def detect_signature():
    detector = SignatureDetector(Path.cwd())

    sig_info = await detector.detect_signature("v1.2.3")

    print(f"Signature type: {sig_info.type}")
    print(f"Verified: {sig_info.verified}")

    if sig_info.type == "gpg":
        print(f"Key ID: {sig_info.key_id}")
        print(f"Signer: {sig_info.signer_email}")

asyncio.run(detect_signature())
```

### Tag Operations

```python
import asyncio
from pathlib import Path
from tag_validate.tag_operations import TagOperations

async def fetch_tag_info():
    ops = TagOperations()

    # Get local tag info
    tag_info = await ops.fetch_tag_info("v1.2.3", repo_path=Path.cwd())

    print(f"Tag: {tag_info.tag_name}")
    print(f"Type: {tag_info.tag_type}")
    print(f"Commit: {tag_info.commit_sha}")

    # Parse remote tag location
    owner, repo, tag = ops.parse_tag_location("torvalds/linux@v6.0")
    print(f"Owner: {owner}, Repo: {repo}, Tag: {tag}")

asyncio.run(fetch_tag_info())
```

### GitHub Key Verification

```python
import asyncio
from tag_validate.github_keys import GitHubKeysClient

async def verify_key():
    async with GitHubKeysClient(token="ghp_...") as client:
        # Verify GPG key
        result = await client.verify_gpg_key_registered(
            username="torvalds",
            key_id="1234567890ABCDEF",
        )

        if result.key_registered:
            print("✅ Key is registered!")
        else:
            print("❌ Key not found")

asyncio.run(verify_key())
```

## Configuration

### ValidationConfig Options

```python
from tag_validate.models import ValidationConfig

config = ValidationConfig(
    # Version type requirements
    require_semver=True,      # Require Semantic Versioning
    require_calver=False,     # Require Calendar Versioning

    # Signature requirements
    require_signed=True,      # Require tag to be signed
    require_unsigned=False,   # Require tag to be unsigned

    # GitHub verification
    verify_github_key=True,   # Verify key on GitHub

    # Version filtering
    reject_development=True,  # Reject alpha/beta/rc versions

    # Prefix handling
    allow_prefix=True,        # Allow 'v' prefix on versions
)
```

### Environment Variables

- `GITHUB_TOKEN` - GitHub API token for authentication

## Architecture

### Module Overview

```text
src/tag_validate/
├── models.py              # Pydantic data models
├── validation.py          # Version validation (SemVer/CalVer)
├── signature.py           # Signature detection (GPG/SSH)
├── tag_operations.py      # Tag fetching and parsing
├── github_keys.py         # GitHub API integration
├── workflow.py            # Workflow orchestration
└── cli.py                 # Command-line interface
```

### Workflow Steps

1. **Fetch Tag Information** - Retrieve tag metadata from repository
2. **Verify Version** - Check SemVer or CalVer format
3. **Detect Signature** - Identify and verify signature
4. **Verify GitHub Key** - Optional verification on GitHub
5. **Generate Result** - Comprehensive validation result

### Dependencies

- **dependamerge** - GitHub API client infrastructure
- **pydantic** - Data validation and settings management
- **typer** - CLI framework
- **rich** - Beautiful terminal output
- **packaging** - Version parsing and comparison
- **cryptography** - Cryptographic operations
- **python-gnupg** - GPG integration

## Testing

### Run All Tests

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=tag_validate --cov-report=html

# View coverage report
open coverage_html_report/index.html
```

### Run Specific Tests

```bash
# Unit tests
pytest tests/ -m "not integration"

# Integration tests (requires network)
pytest tests/integration -v -m integration

# Specific test file
pytest tests/test_validation.py -v

# Specific test
pytest tests/test_validation.py::TestTagValidator::test_validate_semver_basic -v
```

### Integration Tests

Integration tests use real test repositories:

- `lfreleng-actions/test-tags-semantic` - SemVer tags
- `lfreleng-actions/test-tags-calver` - CalVer tags

See [tests/integration/README.md](tests/integration/README.md) for details.

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/lfreleng-actions/tag-validate-action.git
cd tag-validate-action

# Install with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Code Quality

```bash
# Run pre-commit hooks
pre-commit run --all-files

# Type checking
mypy src/tag_validate

# Linting
ruff check src/tag_validate

# Formatting
black src/tag_validate tests
```

### Project Structure

```text
tag-validate-action/
├── src/tag_validate/       # Source code
├── tests/                  # Test suite
│   ├── integration/        # Integration tests
│   └── test_*.py           # Unit tests
├── docs/                   # Documentation
├── .github/workflows/      # CI/CD workflows
├── pyproject.toml          # Project configuration
└── README.md               # This file
```

## License

Apache-2.0 License - See [LICENSE](LICENSE) for details.

SPDX-License-Identifier: Apache-2.0

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

- **Issues**: [GitHub Issues](https://github.com/lfreleng-actions/tag-validate-action/issues)
- **Discussions**: [GitHub Discussions](https://github.com/lfreleng-actions/tag-validate-action/discussions)
- **Documentation**: [docs/](docs/) directory

## Related Projects

- [dependamerge](https://github.com/lfit/dependamerge) - GitHub API
  infrastructure
- [tag-validate-action](https://github.com/lfreleng-actions/tag-validate-action)
  - GitHub Action wrapper

---

**Maintainer**: Matthew Watkins
**Organization**: The Linux Foundation
**Status**: Production Ready
**Version**: 0.1.0 (Pre-release)
