<!--
SPDX-FileCopyrightText: 2025 Linux Foundation
SPDX-License-Identifier: Apache-2.0
-->

# Test Suite for tag-validate

This directory contains comprehensive tests for the `tag-validate` package.

## Test Structure

```text
tests/
├── __init__.py              # Test package initialization
├── conftest.py              # Shared fixtures and test configuration
├── test_models.py           # Tests for Pydantic models
├── test_github_keys.py      # Tests for GitHub API client
├── test_signature.py        # Tests for signature detection
├── test_cli_verify_key.py   # Tests for verify-key CLI command
└── fixtures/                # Test data and fixtures
```

## Running Tests

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test File

```bash
pytest tests/test_models.py -v
pytest tests/test_github_keys.py -v
pytest tests/test_signature.py -v
pytest tests/test_cli_verify_key.py -v
```

### Run Tests with Coverage

```bash
pytest tests/ --cov=tag_validate --cov-report=html
```

### Run Tests in Parallel

```bash
pytest tests/ -n auto
```

### Run Fast Tests (skip slow integration tests)

```bash
pytest tests/ -m "not integration"
```

## Test Files

### test_models.py (~638 lines)

Tests all Pydantic models with comprehensive validation:

- `TagInfo` - Tag metadata model
- `SignatureInfo` - Signature details model
- `GPGKeyInfo` - GPG key model
- `SSHKeyInfo` - SSH key model
- `GitHubVerificationInfo` - GitHub verification model
- `KeyVerificationResult` - Key verification result model
- `VersionInfo` - Version parsing model
- `ValidationConfig` - Configuration model
- `ValidationResult` - Complete validation result model
- `RepositoryInfo` - Repository metadata model

**Test Coverage**:

- Model initialization
- Field validation
- Optional fields
- Model serialization/deserialization
- JSON export
- Model relationships
- Edge cases

### test_github_keys.py (~501 lines)

Tests the GitHub API client with mocked responses:

- Client initialization
- Context manager usage
- GPG key fetching
- SSH key fetching
- GPG key verification
- SSH key verification
- Commit verification
- Error handling (404, 429, 401, etc.)
- Rate limiting
- Integration workflows

**Mocking Strategy**:

- Mock HTTP responses from GitHub API
- Sample API response data in fixtures
- Test both success and failure paths

### test_signature.py (~422 lines)

Tests signature detection with mocked git commands:

- SignatureDetector initialization
- GPG signature detection (good and bad)
- SSH signature detection
- Unsigned tag handling
- Key ID extraction
- Fingerprint extraction
- Signer email extraction
- Tag object content retrieval
- Regex pattern matching
- Error handling
- Multi-tag workflows

**Mocking Strategy**:

- Mock `git verify-tag` output
- Mock `git cat-file` output
- Sample git command outputs in fixtures

### test_cli_verify_key.py (~940 lines)

Tests the `verify-key` CLI sub-command with comprehensive coverage:

- Help output and argument parsing
- GPG key verification (registered/not registered)
- SSH key verification (keys and fingerprints)
- Automatic key type detection
- Explicit type specification (--type gpg/ssh)
- Subkey verification (--no-subkeys flag)
- JSON output format (--json)
- Environment variable handling (GITHUB_TOKEN)
- Short flag aliases (-o, -t, -j)
- Error handling and edge cases
- Supported key formats (8/16/40 char hex, SSH prefixes, fingerprints)

**Test Classes**:

- `TestVerifyKeyBasic` - Basic functionality and required arguments
- `TestVerifyKeyGPG` - GPG key verification workflows
- `TestVerifyKeySSH` - SSH key verification workflows
- `TestVerifyKeyAutoDetection` - Key type auto-detection
- `TestVerifyKeyJSON` - JSON output formatting
- `TestVerifyKeyEnvironment` - Environment variable handling
- `TestVerifyKeyEdgeCases` - Error handling and edge cases
- `TestVerifyKeyIntegration` - End-to-end integration tests

**Mocking Strategy**:

- Mock `GitHubKeysClient` with AsyncMock
- Mock API responses for key verification
- Use `typer.testing.CliRunner` for CLI invocation
- Test both success and failure scenarios

### conftest.py (~325 lines)

Shared fixtures and configuration:

- Temporary repository setup
- Sample signature data (GPG, SSH, unsigned)
- Sample key data (GPG, SSH)
- Sample version data (SemVer, CalVer)
- Mock GitHub API responses
- Mock git command outputs
- Parametrized test data

## Test Fixtures

### Repository Fixtures

- `temp_repo` - Creates a temporary Git repository structure
- `temp_repo_path` - Path to temporary repository

### Signature Fixtures

- `sample_gpg_signature` - Valid GPG signature
- `sample_ssh_signature` - Valid SSH signature
- `sample_unsigned` - Unsigned tag info

### Key Fixtures

- `sample_gpg_key` - Sample GPG key info
- `sample_ssh_key` - Sample SSH key info

### Version Fixtures

- `sample_semver` - Sample SemVer version
- `sample_calver` - Sample CalVer version
- `valid_version_strings` - Parametrized valid versions
- `invalid_version_strings` - Parametrized invalid versions

### Git Output Fixtures

- `git_verify_gpg_output` - Sample GPG verify output
- `git_verify_ssh_output` - Sample SSH verify output
- `git_verify_unsigned_output` - Sample unsigned output

### GitHub API Fixtures

- `github_gpg_keys_response` - Sample GPG keys API response
- `github_ssh_keys_response` - Sample SSH keys API response
- `github_commit_verification_response` - Sample verification response

## Writing New Tests

### Test Naming Convention

- Test files: `test_<module>.py`
- Test classes: `Test<FeatureName>`
- Test methods: `test_<specific_behavior>`

### Example Test

```python
import pytest
from tag_validate.models import SignatureInfo

class TestSignatureInfo:
    """Test SignatureInfo model."""

    def test_valid_gpg_signature(self):
        """Test creating a valid GPG signature info."""
        sig = SignatureInfo(
            type="gpg",
            verified=True,
            key_id="ABCD1234",
            fingerprint="1234567890ABCDEF",
            signer_email="test@example.com",
            signature_data="gpg: Good signature...",
        )

        assert sig.type == "gpg"
        assert sig.verified is True
        assert sig.key_id == "ABCD1234"
```

### Async Test Example

```python
import pytest

class TestGitHubKeysClient:
    """Test GitHub API client."""

    @pytest.mark.asyncio
    async def test_get_gpg_keys(self):
        """Test fetching GPG keys."""
        async with GitHubKeysClient(token="test") as client:
            keys = await client.get_user_gpg_keys("testuser")
            assert isinstance(keys, list)
```

### Using Fixtures

```python
class TestSignatureDetector:
    """Test signature detection."""

    @pytest.mark.asyncio
    async def test_detect_signature(
        self,
        signature_detector,  # From conftest.py
        git_verify_gpg_output  # From conftest.py
    ):
        """Test detecting a GPG signature."""
        # Test implementation
```

## Test Markers

### Available Markers

- `@pytest.mark.asyncio` - Async test
- `@pytest.mark.integration` - Integration test (may be slow)
- `@pytest.mark.slow` - Slow test
- `@pytest.mark.parametrize` - Parametrized test

### Using Markers

```python
@pytest.mark.asyncio
async def test_async_function():
    """Test async function."""
    pass

@pytest.mark.integration
def test_real_api():
    """Test with real API."""
    pass

@pytest.mark.parametrize("version,expected", [
    ("v1.0.0", True),
    ("v2.1.3", True),
    ("invalid", False),
])
def test_version_validation(version, expected):
    """Test version validation."""
    pass
```

## Coverage Goals

- **Total**: >80% code coverage
- **Unit Tests**: Test all public APIs
- **Integration Tests**: Test main workflows
- **Edge Cases**: Test error conditions
- **Mocking**: Mock external dependencies

## CI/CD Integration

Tests are run automatically in CI/CD pipelines:

- On every pull request
- On every commit to main branch
- Before releases

## Debugging Tests

### Run with verbose output

```bash
pytest tests/ -vv
```

### Run with print statements

```bash
pytest tests/ -s
```

### Run specific test

```bash
pytest tests/test_models.py::TestSignatureInfo::test_valid_gpg_signature -v
```

### Debug with pdb

```bash
pytest tests/ --pdb
```

### Show test durations

```bash
pytest tests/ --durations=10
```

## Contributing

When adding new features:

1. Write tests first (TDD)
2. Ensure all tests pass
3. Maintain >80% coverage
4. Update this README if adding new test files

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-asyncio documentation](https://pytest-asyncio.readthedocs.io/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [Pydantic testing guide](https://docs.pydantic.dev/latest/concepts/testing/)
