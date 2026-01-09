<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# Local Testing Guide

Test the tag-validate-action locally using
[Nektos/Act](https://nektosact.com/) before pushing to CI.

## Prerequisites

- **Docker Desktop** - Must be running
- **Nektos/Act** - GitHub Actions runner for local testing

## Quick Start

```bash
# 1. Install Act (macOS)
brew install act
# Or use: make install-act

# 2. Setup secrets file
make setup-secrets

# 3. Edit .secrets and add GitHub token
# Get token from: https://github.com/settings/tokens (scope: public_repo)
vim .secrets

# 4. Run tests
make test
```

## Available Commands

```bash
make help              # Show all commands
make test              # Run all tests (~15-20 min)
make test-verbose      # Run with verbose output
make test-dry-run      # Preview what would run
make list-jobs         # List available test jobs
make clean             # Clean up containers
make check-prereqs     # Verify prerequisites
make info              # Show configuration
```

## Configuration

### `.actrc` - Act Configuration

Configures the runner image, secrets file, and container reuse.
No changes needed for typical usage.

### `.secrets` - Local Secrets

Created by `make setup-secrets`. Add your GitHub token:

```text
GITHUB_TOKEN=ghp_your_token_here
```

Optional: Add `GPG_PRIVATE_KEY` for signature verification tests.

### Workflow

Tests run via `.github/workflows/testing-act.yaml` which mirrors
`testing.yaml` but optimized for local Act execution.

## Using Act Directly

```bash
# List jobs
act -l -W .github/workflows/testing-act.yaml

# Run specific job
act workflow_dispatch -W .github/workflows/testing-act.yaml

# Verbose output
act workflow_dispatch -W .github/workflows/testing-act.yaml -v

# Dry run
act workflow_dispatch -W .github/workflows/testing-act.yaml -n
```

## Troubleshooting

### Docker Not Running

Start Docker Desktop:

```bash
open -a Docker  # macOS
```

### Tests Fail

```bash
# Check prerequisites
make check-prereqs

# Run with verbose output
make test-verbose

# Clean and retry
make clean
make test
```

### Rate Limiting

Ensure `GITHUB_TOKEN` is set in `.secrets`. Without it, you're limited
to 60 GitHub API requests/hour. With token: 5,000/hour.

### Disk Space

```bash
# Clean up Docker - remove unused images and containers
docker system prune -a -f

# Or use Make target
make clean
```

## Platform-Specific Notes

**macOS**: Docker socket is auto-detected at `~/.docker/run/docker.sock`

**Linux**: Uses `/var/run/docker.sock`. If permission denied:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Windows**: Use WSL2 with Docker Desktop.

## Development Workflow

```bash
# 1. Make changes
vim action.yaml

# 2. Test locally
make test

# 3. Commit and push
git commit -am "feat: add feature"
git push
```

## Resources

- **Act Docs**: <https://nektosact.com/>
- **Docker**: <https://docs.docker.com/>

Happy testing! 🚀
