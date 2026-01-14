<!--
SPDX-FileCopyrightText: 2025 Linux Foundation
SPDX-License-Identifier: Apache-2.0
-->

# Integration Tests for tag-validate

This directory contains integration tests that verify the Python implementation
of `tag-validate` against real Git repositories and external services.

## Overview

Integration tests use real test repositories from the `lfreleng-actions`
organization on GitHub:

- **test-tags-semantic** - Contains SemVer tags with multiple signature types
- **test-tags-calver** - Contains CalVer tags with multiple signature types

These tests ensure the Python implementation works with:

- Real Git repositories
- Real GPG and SSH signatures
- Real tag objects and metadata
- Remote repository cloning

## Test Repositories

### lfreleng-actions/test-tags-semantic

SemVer tags with different signature types:

| Tag                 | Type   | Signature | Purpose                        |
| ------------------- | ------ | --------- | ------------------------------ |
| v0.1.4-gpg-test     | SemVer | GPG       | Valid GPG signature            |
| v0.1.3-ssh-signed   | SemVer | SSH       | Valid SSH signature            |
| v0.1.2-unsigned     | SemVer | None      | Unsigned tag                   |
| v0.1.6-gpg-unknown  | SemVer | GPG       | Unverifiable (key not in ring) |

### lfreleng-actions/test-tags-calver

CalVer tags with different signature types:

| Tag                   | Type   | Signature | Purpose                        |
| --------------------- | ------ | --------- | ------------------------------ |
| 2025.1.4-gpg-test     | CalVer | GPG       | Valid GPG signature            |
| 2025.1.3-ssh-signed   | CalVer | SSH       | Valid SSH signature            |
| 2025.1.2-unsigned     | CalVer | None      | Unsigned tag                   |
| 2025.1.6-gpg-unknown  | CalVer | GPG       | Unverifiable (key not in ring) |

## Running Integration Tests

### Prerequisites

1. **Network Access**: Tests require internet connectivity to clone repositories
2. **Git**: Git must be installed and available in PATH
3. **Python 3.11+**: Tests use modern Python features
4. **Dependencies**: Install with dev extras

```bash
# Install package with dev dependencies
pip install -e ".[dev]"
```

### Run All Integration Tests

```bash
# Run all integration tests
pytest tests/integration -v -m integration

# Run with more detailed output
pytest tests/integration -v -m integration --tb=short

# Run with coverage
pytest tests/integration -v -m integration --cov=tag_validate
```

### Run Specific Test Classes

```bash
# Test SemVer repository
pytest tests/integration/test_real_repositories.py::TestSemVerRepository -v

# Test CalVer repository
pytest tests/integration/test_real_repositories.py::TestCalVerRepository -v

# Test remote cloning
pytest tests/integration/test_real_repositories.py::TestRemoteTagCloning -v

# Test end-to-end workflows
pytest tests/integration/test_real_repositories.py::TestEndToEndWorkflow -v
```

### Run Specific Tests

```bash
# Test GPG signature detection
pytest tests/integration/test_real_repositories.py::TestSemVerRepository::\
test_gpg_signed_tag -v

# Test SSH signature detection
pytest tests/integration/test_real_repositories.py::TestCalVerRepository::\
test_ssh_signed_tag -v

# Test full validation workflow
pytest tests/integration/test_real_repositories.py::TestEndToEndWorkflow::\
test_full_validation_workflow_semver -v
```

### Skip Integration Tests

```bash
# Run all tests EXCEPT integration tests
pytest tests/ -v -m "not integration"
```

## Test Organization

### Test Classes

- **TestSemVerRepository**: Tests against SemVer test repository
  - GPG signature detection
  - SSH signature detection
  - Unsigned tag handling
  - Tag metadata extraction
  - Version validation

- **TestCalVerRepository**: Tests against CalVer test repository
  - GPG signature detection
  - SSH signature detection
  - Unsigned tag handling
  - Tag metadata extraction
  - Version validation

- **TestRemoteTagCloning**: Tests remote repository operations
  - Clone remote tags
  - Authentication with tokens
  - Cleanup and error handling

- **TestEndToEndWorkflow**: Complete integration workflows
  - Version validation → Tag info → Signature detection
  - SemVer and CalVer workflows
  - Unsigned tag workflows

### Fixtures

- **semver_repo_path**: Clones SemVer test repo (module scope)
- **calver_repo_path**: Clones CalVer test repo (module scope)

Fixtures are scoped to the module to avoid repeated cloning.

## CI/CD Integration

These tests are automatically run in CI via `.github/workflows/testing.yaml`:

- **test-python-signature-detection**: Runs signature detection tests
- Tests clone real repositories in CI environment
- Validates against known good tags
- Ensures Python implementation matches bash behavior

### CI Test Jobs

The testing workflow includes:

```yaml
test-python-signature-detection:
  - Checkout test-tags-semantic repo
  - Checkout test-tags-calver repo
  - Install Python package
  - Test GPG signature detection
  - Test SSH signature detection
  - Test unsigned tag detection
```

## Troubleshooting

### Network Issues

If tests fail due to network issues:

```bash
# Check connectivity to GitHub
curl -I https://github.com

# Test repository access
git ls-remote https://github.com/lfreleng-actions/test-tags-semantic.git
```

### Git Authentication

For private repositories, set up authentication:

```bash
# Using GitHub token
export GITHUB_TOKEN="your_token_here"

# Using SSH keys
ssh -T git@github.com
```

### Repository Not Found

If a test repository is not found:

1. Verify repository exists: <https://github.com/lfreleng-actions/test-tags-semantic>
2. Check network connectivity
3. Ensure Git is installed: `git --version`

### Tag Not Found

If a specific tag is not found:

```bash
# List all tags in repository
cd /tmp
git clone --bare https://github.com/lfreleng-actions/test-tags-semantic.git
cd test-tags-semantic.git
git tag -l
```

## Adding New Integration Tests

### 1. Create Test Method

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_new_feature(self, semver_repo_path: Path):
    """Test new feature with real repository."""
    # Test implementation
    pass
```

### 2. Use Existing Fixtures

```python
def test_with_semver(self, semver_repo_path: Path):
    # Use SemVer test repository
    pass

def test_with_calver(self, calver_repo_path: Path):
    # Use CalVer test repository
    pass
```

### 3. Mark as Integration Test

Always mark with `@pytest.mark.integration`:

```python
@pytest.mark.integration
def test_something():
    pass
```

This allows selective running with `-m integration`.

## Performance Considerations

Integration tests are slower than unit tests because they:

- Clone real repositories from GitHub
- Perform real Git operations
- Access network resources

**Typical execution times**:

- Full integration test suite: ~30-60 seconds
- Single test class: ~10-20 seconds
- Individual test: ~2-5 seconds

**Optimization tips**:

- Use module-scoped fixtures to reuse cloned repos
- Run unit tests during development
- Run integration tests before commits
- CI runs all tests automatically

## Best Practices

1. **Always use fixtures** for repository access
2. **Mark tests** with `@pytest.mark.integration`
3. **Clean up resources** in fixtures
4. **Test real scenarios** that match production use
5. **Document expected outcomes** in docstrings
6. **Handle network failures** properly
7. **Use real test data** from actual repositories

## Related Documentation

- [Phase 2 Summary](../../docs/PHASE2_SUMMARY.md) - Phase 2
  implementation details
- [Python Project Status](../../docs/PYTHON_PROJECT_STATUS.md) - Project status
- [Testing Workflow](../../.github/workflows/testing.yaml) - CI configuration

---

**Maintainer**: Matthew Watkins
**Last Updated**: 2025-01-09
**Status**: Active
