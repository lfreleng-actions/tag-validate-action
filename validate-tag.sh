#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

# Tag validation script
set -e

# Initialize variables from inputs
tag_location="$1"
tag_string="$2"
require_type="$3"
require_signed="$4"
permit_missing="$5"
# Token is now read from environment variable for security
# (prevents token exposure in process listings)
token="${VALIDATION_TOKEN:-}"
# github_server_url is pre-resolved by action.yaml with fallback chain:
# inputs.github_server_url || env.GITHUB_SERVER_URL || 'https://github.com'
# Script maintains additional fallback logic for direct usage/testing
github_server_url="$6"
# Ensure github_server_url always has a value (fallback for direct script usage)
if [ -z "$github_server_url" ]; then
  github_server_url="${GITHUB_SERVER_URL:-https://github.com}"
fi
debug="$7"
github_repository="$8"

# Validate github_repository format (should be org/repo)
if [ -n "$github_repository" ]; then
  if ! [[ "$github_repository" =~ ^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$ ]]; then
    echo "Error: Invalid github_repository format: $github_repository" >&2
    echo "Expected format: org/repo" >&2
    exit 1
  fi
fi

# Normalize case for case-insensitive matching
require_type=$(printf '%s' "$require_type" | tr '[:upper:]' '[:lower:]')
require_signed=$(printf '%s' "$require_signed" | tr '[:upper:]' '[:lower:]')
permit_missing=$(printf '%s' "$permit_missing" | tr '[:upper:]' '[:lower:]')
debug=$(printf '%s' "$debug" | tr '[:upper:]' '[:lower:]')

tag_name=""
tag_type="unknown"
signing_type="unsigned"
development_tag="false"
version_prefix="false"
valid="true"
is_remote_tag="false"
orig_dir=""
repo_org=""
repo_name=""
remote_tag=""
local_repo_path=""

# ==================================================================
# Helper Functions
# ==================================================================

# Safe append to GitHub step summary (no-op if file unavailable)
safe_append_summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -w "$GITHUB_STEP_SUMMARY" ]; then
    cat >> "$GITHUB_STEP_SUMMARY"
  fi
}

# Global variable for askpass script path (cleaned up by cleanup_git_askpass)
# This is intentionally global to allow cleanup from error handlers and traps
GIT_VALIDATION_ASKPASS_SCRIPT=""

# Global variable for clone stderr temp file (cleaned up by trap)
# This is intentionally global to allow cleanup from error handlers and traps
CLONE_STDERR_FILE=""

# Setup Git askpass for secure token passing
# Creates a temporary askpass script and sets environment variables
# Note: Sets global GIT_VALIDATION_ASKPASS_SCRIPT for cleanup tracking
setup_git_askpass() {
  local token="$1"

  # Clean up any existing askpass script first
  cleanup_git_askpass

  GIT_VALIDATION_ASKPASS_SCRIPT=$(mktemp) || { echo "Error: Failed to create temporary file" >&2; return 1; }
  chmod 700 "$GIT_VALIDATION_ASKPASS_SCRIPT"
  cat > "$GIT_VALIDATION_ASKPASS_SCRIPT" << 'EOF'
#!/bin/sh
echo "$GIT_TOKEN"
EOF

  export GIT_ASKPASS="$GIT_VALIDATION_ASKPASS_SCRIPT"
  export GIT_TOKEN="$token"
  export GIT_TERMINAL_PROMPT=0
}

# Cleanup Git askpass
# Removes temporary askpass script and unsets environment variables
# Safe to call multiple times (idempotent)
cleanup_git_askpass() {
  if [ -n "${GIT_VALIDATION_ASKPASS_SCRIPT:-}" ]; then
    unset GIT_TOKEN
    unset GIT_ASKPASS
    rm -f "$GIT_VALIDATION_ASKPASS_SCRIPT"
    GIT_VALIDATION_ASKPASS_SCRIPT=""
  fi
}

# Safely write outputs to GITHUB_OUTPUT
# Only writes if GITHUB_OUTPUT is set and writable
safe_write_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ] && [ -w "$GITHUB_OUTPUT" ]; then
    cat >> "$GITHUB_OUTPUT"
  fi
}

# Cleanup clone stderr file
# Removes temporary stderr file and resets the global variable
# Safe to call multiple times (idempotent)
cleanup_clone_stderr() {
  if [ -n "${CLONE_STDERR_FILE:-}" ]; then
    rm -f "$CLONE_STDERR_FILE"
    CLONE_STDERR_FILE=""
  fi
}

# Retry function for network operations
retry_command() {
  local max_attempts=3
  local attempt=1
  local delay=2

  while [ $attempt -le $max_attempts ]; do
    if "$@"; then
      return 0
    fi

    if [ $attempt -lt $max_attempts ]; then
      echo "Attempt $attempt failed, retrying in ${delay}s..." >&2
      sleep $delay
      delay=$((delay * 2))
    fi
    attempt=$((attempt + 1))
  done

  return 1
}

# Validate GitHub naming patterns
validate_github_name() {
  local name="$1"
  local type="$2"

  # GitHub org/repo names: alphanumeric, hyphen, underscore, dot
  # Cannot start with hyphen or dot
  if [[ ! "$name" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]]; then
    echo "Error: Invalid $type name: $name ❌" >&2
    echo "Must start with alphanumeric/underscore and contain only" \
         "alphanumeric, hyphen, underscore, dot" >&2
    return 1
  fi
  return 0
}

# Validate GitHub server URL to prevent command injection
# Returns 0 if URL is valid, 1 otherwise
# SECURITY: Strictly validates server URLs before use in shell commands
validate_server_url() {
  local url="$1"

  # Allow empty URLs (will be handled separately)
  if [ -z "$url" ]; then
    return 1
  fi

  # SECURITY: Only allow HTTPS URLs with strict hostname validation
  # Reject any URLs with shell metacharacters that could enable injection
  # Format: https://hostname[:port]
  # Hostname can contain: alphanumeric, dots, hyphens (no underscores for domains)
  if [[ "$url" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?$ ]]; then
    # Additional check: reject URLs with dangerous characters
    if [[ "$url" =~ [\;\'\"\`\$\(\)\{\}\[\]\<\>\&\|\\] ]]; then
      echo "Error: Server URL contains shell metacharacters" >&2
      return 1
    fi
    return 0
  fi

  echo "Error: Invalid server URL format (must be https://hostname[:port])" >&2
  return 1
}

# SECURITY: Validate github_server_url to prevent command injection
# This must be done before any use in shell commands
if ! validate_server_url "$github_server_url"; then
  echo "Error: Invalid or unsafe github_server_url: $github_server_url" >&2
  echo "Server URL must be in format: https://hostname[:port]" >&2
  exit 1
fi

# Validate Git URL to prevent command injection
# Returns 0 if URL is valid, 1 otherwise
validate_git_url() {
  local url="$1"

  # Allow empty URLs (will be handled separately)
  if [ -z "$url" ]; then
    return 1
  fi

  # SECURITY: Only allow HTTPS and SSH Git URL formats
  # Reject any URLs with shell metacharacters that could enable injection
  # HTTPS: https://host[:port]/path[.git]
  # SSH: git@host:path[.git]
  if [[ "$url" =~ ^https?://[a-zA-Z0-9._-]+(:[0-9]+)?(/[a-zA-Z0-9._/-]+)?(\.git)?$ ]] || \
     [[ "$url" =~ ^git@[a-zA-Z0-9._-]+:[a-zA-Z0-9._/-]+(\.git)?$ ]]; then
    return 0
  fi

  echo "⚠️ URL validation failed: contains invalid characters or format" >&2
  return 1
}

# Extract host from URL (handles both HTTPS and SSH)
extract_host_from_url() {
  local url="$1"

  # SSH format: git@github.com:org/repo.git
  if [[ "$url" =~ ^git@([^:]+): ]] ; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi

  # HTTPS format: https://github.com/org/repo.git
  if [[ "$url" =~ ^https?://([^/:]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi

  return 1
}

# Detect signature type from git verify-tag output and tag content
# Sets the global signing_type variable and prints appropriate message
# Arguments:
#   $1 - verify_output: output from git verify-tag
#   $2 - tag_name: name of the tag to check
#   $3 - debug: debug flag (true/false)
detect_signature_type() {
  local verify_output="$1"
  local tag_name="$2"
  local debug_mode="$3"

  # Check for GPG signature (prioritize bad signatures first)
  # SECURITY: Check BADSIG before GOODSIG/VALIDSIG to prevent
  # invalid signatures from being classified as good.
  # This prevents adversaries from including GOODSIG text in custom fields
  # that might be processed before signature verification.
  # DETECTION: ERRSIG means signature exists but can't verify (missing key)
  # so we classify as 'gpg-unverifiable' to allow informed security decisions
  if printf '%s\n' "$verify_output" | \
     grep -q '\[GNUPG:\] BADSIG'; then
    signing_type="invalid"
    echo "⚠️ Tag has INVALID GPG signature (verification failed)"
    return 0
  elif printf '%s\n' "$verify_output" | \
       grep -q '\[GNUPG:\] GOODSIG'; then
    signing_type="gpg"
    echo "✓ Tag is signed with GPG key (GOOD signature) 🔑"
    return 0
  elif printf '%s\n' "$verify_output" | \
       grep -q '\[GNUPG:\] VALIDSIG'; then
    signing_type="gpg"
    echo "✓ Tag is signed with GPG key (VALID signature) 🔑"
    return 0
  elif printf '%s\n' "$verify_output" | \
       grep -q '\[GNUPG:\] ERRSIG'; then
    # NOTE: Signature exists but cannot be verified (missing key)
    # Use distinct type to allow consumers to make informed security decisions
    signing_type="gpg-unverifiable"
    echo "⚠️ Tag has GPG signature (could not verify - key unavailable) 🔑"
    return 0
  fi

  # Check for SSH signature via verify-tag output (Git 2.34+)
  # NOTE: Git outputs 'Good "git" signature' for SSH signatures (Git 2.34+)
  # The lowercase "git" is the correct pattern, not "SSH"
  # SECURITY: Use specific pattern to avoid false positives from error messages
  if printf '%s\n' "$verify_output" | \
     grep -Eq '^Good "git" signature'; then
    signing_type="ssh"
    echo "✓ Tag is signed with SSH key 🔑"
    return 0
  fi

  # Fallback: Direct inspection of tag object for SSH signature
  if [ "$debug_mode" = "true" ]; then
    echo "DEBUG: Checking git cat-file output for SSH signature:"
  fi

  local tag_content
  tag_content=$(git cat-file tag "$tag_name" 2>/dev/null || echo "")

  if [ -z "$tag_content" ]; then
    echo "⚠️ Could not read tag object content"
    signing_type="unsigned"
    return 0
  fi

  if [ "$debug_mode" = "true" ]; then
    # Only show first and last 5 lines to avoid noise
    echo "$tag_content" | head -5
    echo "... (content truncated for brevity) ..."
    echo "$tag_content" | tail -5
    echo "---"
  fi

  # Robust multiline SSH signature detection
  # Verify both BEGIN and END markers exist to ensure complete signature block
  if printf '%s\n' "$tag_content" | grep -q '^-----BEGIN SSH SIGNATURE-----$' && \
     printf '%s\n' "$tag_content" | grep -q '^-----END SSH SIGNATURE-----$'; then
    signing_type="ssh"
    echo "✓ Tag is signed with SSH key 🔑"
    return 0
  else
    signing_type="unsigned"
    echo "ℹ️ Tag is not signed"
    return 0
  fi
}

# Normalize server URL to base (remove paths)
normalize_server_url() {
  local url="$1"

  # Extract protocol and host only
  if [[ "$url" =~ ^(https?://[^/]+) ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  else
    printf '%s' "$url"
  fi
}

# ==================================================================
# STEP 1: Determine tag source and extract tag name
# ==================================================================

if [ -n "$tag_location" ]; then
  echo "📍 Tag location provided: $tag_location"

  # Determine if this is a local path or remote reference
  # Local paths start with ./ or / or contain a .git directory

  # Extract components using parameter expansion (avoid rev)
  potential_tag="${tag_location##*/}"
  potential_repo_path="${tag_location%/*}"

  # Check if this looks like a local path
  if [[ "$tag_location" == ./* ]] || \
     [[ "$tag_location" == /* ]] || \
     [ -d "$potential_repo_path/.git" ]; then
    echo "🏠 Detected local repository path"

    # Validate that the repository path exists and contains .git
    if [ ! -d "$potential_repo_path/.git" ]; then
      echo "Error: Local path does not contain a Git repository" \
           "(.git directory not found) ❌"
      echo "Path checked: $potential_repo_path"
      exit 1
    fi

    local_repo_path="$potential_repo_path"
    tag_name="$potential_tag"
    is_remote_tag="false"

    echo "  Repository path: $local_repo_path"
    echo "  Tag: $tag_name"

    # Change to the repository directory for git operations
    orig_dir="$(pwd)"
    cd "$local_repo_path" || exit 1
    # Set trap to restore directory on exit (including early exits)
    trap 'cd "$orig_dir" 2>/dev/null || true' EXIT

    # Verify the tag exists
    echo "Checking for tag '$tag_name' in local repository..."
    if ! git tag -l "$tag_name" | grep -q "^${tag_name}$"; then
      echo "Available tags:"
      git tag -l | head -20

      if [ "$permit_missing" = "true" ]; then
        echo "⚠️ Tag not found in local repository," \
             "but permit_missing=true"
        {
          echo "valid=true"
          echo "tag_type=unknown"
          echo "signing_type=unsigned"
          echo "development_tag=false"
          echo "version_prefix=false"
          echo "tag_name=$tag_name"
        } | safe_write_output
        exit 0
      else
        echo "Error: Tag '$tag_name' not found in local repository ❌"
        exit 1
      fi
    fi
    echo "✓ Tag found in local repository"

  else
    # Remote reference format: ORG/REPO/TAG
    echo "🌐 Detected remote repository reference"
    is_remote_tag="true"

    # Parse tag_location: ORG/REPO/TAG
    if [[ ! "$tag_location" =~ ^[^/]+/[^/]+/.+ ]]; then
      echo "Error: Invalid tag_location format ❌"
      echo "Expected formats:"
      echo "  - Remote: ORG/REPO/TAG" \
           "(e.g., lfreleng-actions/tag-validate-action/v0.1.0)"
      echo "  - Local: PATH/TO/REPO/TAG (e.g., ./my-repo/v1.0.0)"
      exit 1
    fi

    # Extract components using parameter expansion
    repo_org="${tag_location%%/*}"
    temp="${tag_location#*/}"
    repo_name="${temp%%/*}"
    remote_tag="${temp#*/}"

    # Validate org and repo names
    validate_github_name "$repo_org" "organization" || exit 1
    validate_github_name "$repo_name" "repository" || exit 1

    echo "  Organization: $repo_org"
    echo "  Repository: $repo_name"
    echo "  Tag: $remote_tag"

    tag_name="$remote_tag"
  fi

elif [ -n "$tag_string" ]; then
  echo "📝 Tag string provided: $tag_string"
  tag_name="$tag_string"

else
  # Check if triggered by tag push event
  if [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
    tag_name="${GITHUB_REF_NAME:-}"
    echo "🏷️ Tag push event detected: $tag_name"

    # Verify we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
      echo "Warning: Not in a git repository, cannot check signatures"
    fi
  else
    # No tag source provided
    if [ "$permit_missing" = "true" ]; then
      echo "ℹ️ No tag found, but permit_missing=true"
      {
        echo "valid=true"
        echo "tag_type=unknown"
        echo "signing_type=unsigned"
        echo "development_tag=false"
        echo "version_prefix=false"
        echo "tag_name="
      } | safe_write_output
      exit 0
    else
      echo "Error: No tag found (not a tag push event," \
           "no tag_location, no tag_string) ❌"
      exit 1
    fi
  fi
fi

# ==================================================================
# STEP 2: Fetch remote tag if needed
# ==================================================================

if [ "$is_remote_tag" = "true" ]; then
  echo ""
  echo "🌐 Fetching remote tag from GitHub..."

  # Try original tag name first
  tag_exists="false"
  tag_to_fetch="$remote_tag"

  # Determine the base API URL and normalize
  # github_server_url is guaranteed to have a value (set earlier with fallback)
  normalized_url=$(normalize_server_url "$github_server_url")
  # Extract hostname and construct API URL for GitHub Enterprise
  if [[ "$normalized_url" != "https://github.com" ]]; then
    api_url="${normalized_url}/api/v3"
  else
    api_url="https://api.github.com"
  fi

  # Prepare curl headers for authenticated requests
  curl_headers=()
  if [ -n "$token" ]; then
    curl_headers=("-H" "Authorization: token $token")
  fi

  # Function to check if tag exists via API
  check_tag_exists() {
    local tag_to_check="$1"
    local http_code
    local curl_status

    if [ ${#curl_headers[@]} -eq 0 ]; then
      http_code=$(retry_command curl -s -o /dev/null -w "%{http_code}" \
        "${api_url}/repos/$repo_org/$repo_name/git/refs/tags/$tag_to_check")
      curl_status=$?
    else
      http_code=$(retry_command curl -s -o /dev/null -w "%{http_code}" \
        "${curl_headers[@]}" \
        "${api_url}/repos/$repo_org/$repo_name/git/refs/tags/$tag_to_check")
      curl_status=$?
    fi

    if [ "$debug" = "true" ]; then
      echo "DEBUG: curl exit status: $curl_status"
      echo "DEBUG: HTTP response code: $http_code"
      echo "DEBUG: API URL: ${api_url}/repos/$repo_org/$repo_name/git/refs/tags/$tag_to_check"
    fi

    # If curl/retry failed, return a known error code
    if [ "$curl_status" -ne 0 ]; then
      echo "000"
    else
      echo "$http_code"
    fi
  }

  # Check if tag exists using GitHub API
  http_code=$(check_tag_exists "$remote_tag")

  if [ "$http_code" = "000" ]; then
    echo "⚠️ Failed to connect to GitHub API after retries"
    if [ "$permit_missing" = "true" ]; then
      echo "ℹ️ permit_missing=true, treating as missing tag"
      tag_exists="false"
    else
      echo "Error: Cannot verify tag existence ❌"
      exit 1
    fi
  elif [ "$http_code" = "200" ]; then
    tag_exists="true"
    echo "✓ Tag found: $remote_tag"
  else
    # Try stripping/adding 'v' prefix
    if [[ "$remote_tag" == v* ]] || [[ "$remote_tag" == V* ]]; then
      # Try without 'v' prefix
      alt_tag="${remote_tag:1}"
      http_code=$(check_tag_exists "$alt_tag")

      if [ "$http_code" = "000" ]; then
        echo "⚠️ Failed to connect to GitHub API after retries"
        if [ "$permit_missing" = "false" ]; then
          echo "Error: Cannot verify tag existence ❌"
          exit 1
        fi
      elif [ "$http_code" = "200" ]; then
        tag_exists="true"
        tag_to_fetch="$alt_tag"
        tag_name="$alt_tag"
        echo "✓ Tag found (without v prefix): $alt_tag"
      fi
    else
      # Try with 'v' prefix
      alt_tag="v$remote_tag"
      http_code=$(check_tag_exists "$alt_tag")

      if [ "$http_code" = "000" ]; then
        echo "⚠️ Failed to connect to GitHub API after retries"
        if [ "$permit_missing" = "false" ]; then
          echo "Error: Cannot verify tag existence ❌"
          exit 1
        fi
      elif [ "$http_code" = "200" ]; then
        tag_exists="true"
        tag_to_fetch="$alt_tag"
        tag_name="$alt_tag"
        echo "✓ Tag found (with v prefix): $alt_tag"
      fi
    fi
  fi

  if [ "$tag_exists" = "false" ]; then
    if [ "$permit_missing" = "true" ]; then
      echo "⚠️ Remote tag not found, but permit_missing=true"
      {
        echo "valid=true"
        echo "tag_type=unknown"
        echo "signing_type=unsigned"
        echo "development_tag=false"
        echo "version_prefix=false"
        echo "tag_name=$remote_tag"
      } | safe_write_output
      exit 0
    else
      echo "Error: Remote tag not found:" \
           "$repo_org/$repo_name/$remote_tag ❌"
      exit 1
    fi
  fi

  # Clone repository with tags
  echo "Cloning repository to check tag signature..."
  temp_dir=""
  # Set trap for cleanup on exit or error (defensive - checks if temp_dir is set)
  # Preserve any existing EXIT trap by appending this cleanup logic
  # Note: Current code structure makes local and remote paths mutually exclusive,
  # but this defensive approach ensures robustness if code structure changes
  existing_exit_trap_cmd=$(trap -p EXIT | sed -n "s/^trap -- '\(.*\)' EXIT$/\1/p")
  if [ -n "$existing_exit_trap_cmd" ]; then
    # Use eval to properly combine traps - existing trap expands now, cleanup variables expand later
    eval "trap '$existing_exit_trap_cmd; cleanup_git_askpass; cleanup_clone_stderr; [ -n \"\$temp_dir\" ] && rm -rf \"\$temp_dir\"; cd \"\$orig_dir\" 2>/dev/null || true' EXIT"
  else
    trap 'cleanup_git_askpass; cleanup_clone_stderr; [ -n "$temp_dir" ] && rm -rf "$temp_dir"; cd "$orig_dir" 2>/dev/null || true' EXIT
  fi
  temp_dir=$(mktemp -d) || { echo "Error: Failed to create temporary directory" >&2; exit 1; }

  # Determine the git server URL and normalize
  # github_server_url is guaranteed to have a value (set earlier with fallback)
  git_server_url=$(normalize_server_url "$github_server_url")

  # Clone with secure token passing if provided
  if [ -n "$token" ]; then
    # Use GIT_ASKPASS for secure token passing (not in argv)
    setup_git_askpass "$token"

    # Capture stderr for debug output if needed
    if [ "$debug" = "true" ]; then
      CLONE_STDERR_FILE=$(mktemp) || { echo "Error: Failed to create temporary file" >&2; exit 1; }
      retry_command git clone --depth 1 --branch "$tag_to_fetch" \
        "${git_server_url}/$repo_org/$repo_name.git" "$temp_dir" \
        2>"$CLONE_STDERR_FILE" 1>/dev/null || {
        echo "Warning: Could not clone repository," \
             "signature check will be skipped"
        echo "DEBUG: git clone error output:"
        cat "$CLONE_STDERR_FILE"
      }
      cleanup_clone_stderr
    else
      retry_command git clone --depth 1 --branch "$tag_to_fetch" \
        "${git_server_url}/$repo_org/$repo_name.git" "$temp_dir" \
        &>/dev/null || {
        echo "Warning: Could not clone repository," \
             "signature check will be skipped"
      }
    fi

    cleanup_git_askpass
  else
    # Capture stderr for debug output if needed
    if [ "$debug" = "true" ]; then
      CLONE_STDERR_FILE=$(mktemp) || { echo "Error: Failed to create temporary file" >&2; exit 1; }
      retry_command git clone --depth 1 --branch "$tag_to_fetch" \
        "${git_server_url}/$repo_org/$repo_name.git" "$temp_dir" \
        2>"$CLONE_STDERR_FILE" 1>/dev/null || {
        echo "Warning: Could not clone repository," \
             "signature check will be skipped"
        echo "DEBUG: git clone error output:"
        cat "$CLONE_STDERR_FILE"
      }
      cleanup_clone_stderr
    else
      retry_command git clone --depth 1 --branch "$tag_to_fetch" \
        "${git_server_url}/$repo_org/$repo_name.git" "$temp_dir" \
        &>/dev/null || {
        echo "Warning: Could not clone repository," \
             "signature check will be skipped"
      }
    fi
  fi

  if [ -d "$temp_dir/.git" ]; then
    temp_orig_dir="$(pwd)"
    cd "$temp_dir" || exit 1
    git fetch --tags 2>/dev/null || true
    cd "$temp_orig_dir" || exit 1
  fi
fi

# ==================================================================
# STEP 3: Check for version prefix
# ==================================================================

# Validate tag_name doesn't contain dangerous characters
# Allow alphanumeric, dots, hyphens, underscores, slashes, plus
# SECURITY: Also check for path traversal patterns
if [[ "$tag_name" =~ [^a-zA-Z0-9._/+-] ]]; then
  echo "Error: Tag name contains invalid characters ❌"
  exit 1
fi

# SECURITY: Prevent path traversal attempts
# Git allows hierarchical tags (e.g., release/v1.0.0) but we need to prevent
# path traversal patterns like ../ or absolute paths
if [[ "$tag_name" == /* ]] || [[ "$tag_name" =~ \.\. ]] || [[ "$tag_name" =~ // ]]; then
  echo "Error: Tag name contains path traversal patterns ❌"
  echo "Tag names cannot start with /, contain .., or have consecutive slashes"
  exit 1
fi

if [[ "$tag_name" == v* ]] || [[ "$tag_name" == V* ]]; then
  version_prefix="true"
  echo "✓ Version prefix detected: ${tag_name:0:1}"
fi

# Strip leading 'v' or 'V' for validation
clean_tag="$tag_name"
if [[ "$tag_name" == v* ]] || [[ "$tag_name" == V* ]]; then
  clean_tag="${tag_name:1}"
fi

# ==================================================================
# STEP 4: Check for development version
# ==================================================================

if printf '%s\n' "$clean_tag" | \
   grep -Eqi '(dev|pre|alpha|beta|rc|snapshot|nightly|canary|preview)'; then
  development_tag="true"
  echo "✓ Development/pre-release tag detected"
fi

# ==================================================================
# STEP 5: Determine tag type (SemVer or CalVer)
# ==================================================================

# SemVer pattern (from official semver.org)
# Using POSIX extended regex instead of PCRE for portability
# Note: Hyphen must be at end of character class for proper POSIX ERE compatibility
# Pattern structure:
#   1. Major.Minor.Patch: ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)
#      - Uses [1-9][0-9]* to forbid leading zeros (per SemVer spec)
#   2. Pre-release (optional): -((0|[1-9][0-9]*|[0-9]*[a-zA-Z][0-9a-zA-Z-]*)(\...)*)?
#   3. Build metadata (optional): \+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*)?
semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'\
'(-((0|[1-9][0-9]*|[0-9]*[a-zA-Z][0-9a-zA-Z-]*)'\
'(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z][0-9a-zA-Z-]*))*))?'\
'(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?$'

# CalVer pattern (flexible, supports common formats)
# POSIX extended regex version
# Note: Uses [0-9] to allow leading zeros (e.g., 2024.01) unlike SemVer
calver_pattern='^([0-9]{2}|[0-9]{4})\.([0-9]{1,2})'\
'((\.|_|-)([a-zA-Z][a-zA-Z0-9._-]*))?'\
'(\.([0-9]{1,2})((\.|_|-)([a-zA-Z][a-zA-Z0-9._-]*))?)?$'

# Check both patterns to determine tag type
matches_semver=false
matches_calver=false

if printf '%s\n' "$clean_tag" | grep -Eq "$semver_pattern"; then
  matches_semver=true
fi

if printf '%s\n' "$clean_tag" | grep -Eq "$calver_pattern"; then
  matches_calver=true
fi

# Determine tag type based on what matched
if [ "$matches_semver" = true ] && [ "$matches_calver" = true ]; then
  tag_type="both"
  echo "✓ Tag matches both Semantic Versioning (SemVer)" \
       "and Calendar Versioning (CalVer)"
elif [ "$matches_calver" = true ]; then
  tag_type="calver"
  echo "✓ Tag matches Calendar Versioning (CalVer)"
elif [ "$matches_semver" = true ]; then
  tag_type="semver"
  echo "✓ Tag matches Semantic Versioning (SemVer)"
else
  tag_type="unknown"
  echo "⚠️ Tag does not match SemVer or CalVer patterns"
fi

# ==================================================================
# STEP 6: Validate required type
# ==================================================================

if [ "$require_type" != "none" ]; then
  # Validate require_type value
  if [ "$require_type" != "semver" ] && [ "$require_type" != "calver" ]; then
    echo "Error: Invalid require_type value: '$require_type' ❌"
    echo "Valid values: none, semver, calver"
    exit 1
  fi

  # Check if tag type matches requirement
  if [ "$tag_type" = "$require_type" ]; then
    echo "✓ Tag type matches requirement: $require_type"
  elif [ "$tag_type" = "both" ] && \
       { [ "$require_type" = "semver" ] || \
         [ "$require_type" = "calver" ]; }; then
    echo "✓ Tag matches both SemVer and CalVer" \
         "(satisfies $require_type requirement)"
  else
    echo "Error: Tag type mismatch ❌"
    echo "  Required: $require_type"
    echo "  Detected: $tag_type"
    valid="false"
    exit 1
  fi
fi

# ==================================================================
# STEP 7: Check tag signature (only if not tag_string)
# ==================================================================

if [ -z "$tag_string" ]; then
  # We can check signatures (either local repo or fetched remote)
  if git rev-parse --git-dir > /dev/null 2>&1; then
    # Check if tag exists in repo
    if git rev-parse "$tag_name" > /dev/null 2>&1; then
      echo ""
      echo "🔐 Checking tag signature..."

      # Check if this is an annotated tag or lightweight tag
      # Use refs/tags/ to get the actual ref object
      tag_ref_sha=$(git rev-parse "refs/tags/$tag_name" 2>/dev/null || \
                    git rev-parse "$tag_name" 2>/dev/null || echo "")

      if [ -n "$tag_ref_sha" ]; then
        tag_object_type=$(git cat-file -t "$tag_ref_sha" 2>/dev/null || \
                         echo "error")

        if [ "$debug" = "true" ]; then
          echo "DEBUG: Tag ref SHA: $tag_ref_sha"
          echo "DEBUG: Tag object type: $tag_object_type"
        fi

        # ============================================================
        # PHASE 1: Ensure we have an annotated tag object
        # ============================================================
        # If we don't have a tag object locally, try to fetch it
        # from remote. This handles cases where actions/checkout
        # only fetches lightweight refs.

        if [ "$tag_object_type" = "error" ]; then
          echo "⚠️ Could not determine tag object type"
          signing_type="unsigned"
        elif [ "$tag_object_type" != "tag" ]; then
          # This is a lightweight tag - cannot be signed
          echo "ℹ️ Lightweight tag detected (no tag object)"
          signing_type="lightweight"

          # Try to fetch the actual annotated tag from remote
          # This can happen when actions/checkout doesn't fetch
          # tag objects
          echo "Attempting to fetch annotated tag from remote..."

          if [ -n "$token" ]; then
            # Secure token passing for fetch operations
            # Dynamically determine the repository URL
            if [ "$is_remote_tag" = "false" ] && \
               [ -n "$local_repo_path" ]; then
              # For local repository validation, get actual remote URL
              remote_url=$(git config --get remote.origin.url \
                          2>/dev/null || echo "")

              # SECURITY: Validate URL before using in git commands
              if [ -z "$remote_url" ]; then
                echo "⚠️ No remote origin configured for local repository"
                setup_git_askpass "$token"
                git fetch --force origin \
                  "refs/tags/$tag_name:refs/tags/$tag_name" \
                  &>/dev/null || true
                cleanup_git_askpass
              elif ! validate_git_url "$remote_url"; then
                echo "⚠️ Invalid remote URL format, skipping fetch"
              else
                # Extract host from remote URL
                remote_host=$(extract_host_from_url "$remote_url")

                if [ -n "$remote_host" ]; then
                  # Use askpass for secure authentication
                  setup_git_askpass "$token"

                  git fetch --force "$remote_url" \
                    "refs/tags/$tag_name:refs/tags/$tag_name" \
                    &>/dev/null || true

                  cleanup_git_askpass
                else
                  echo "⚠️ Could not extract host from remote URL"
                fi
              fi
            else
              # For workflow repository or remote tag validation
              # github_server_url is guaranteed to have a value (set earlier with fallback)
              git_url=$(normalize_server_url "$github_server_url")

              # Use askpass for secure authentication
              setup_git_askpass "$token"

              git fetch --force "${git_url}/${github_repository}.git" \
                "refs/tags/$tag_name:refs/tags/$tag_name" \
                &>/dev/null || true

              cleanup_git_askpass
            fi
          else
            git fetch --force origin \
              "refs/tags/$tag_name:refs/tags/$tag_name" \
              &>/dev/null || true
          fi

          # Re-check the tag object type after fetch
          tag_ref_sha=$(git rev-parse "refs/tags/$tag_name" \
                       2>/dev/null || echo "")
          if [ -n "$tag_ref_sha" ]; then
            tag_object_type=$(git cat-file -t "$tag_ref_sha" \
                             2>/dev/null || echo "error")
            if [ "$debug" = "true" ]; then
              echo "DEBUG: After fetch - Tag ref SHA: $tag_ref_sha"
              echo "DEBUG: After fetch - Tag object type:" \
                   "$tag_object_type"
            fi
          else
            tag_object_type="error"
          fi

          if [ "$tag_object_type" = "error" ]; then
            echo "⚠️ Could not determine tag object type after fetch"
            signing_type="unsigned"
          elif [ "$tag_object_type" != "tag" ]; then
            echo "ℹ️ Confirmed: Lightweight tag" \
                 "(no tag object, cannot be signed)"
            signing_type="lightweight"
          else
            echo "✓ Fetched annotated tag object from remote"
            # Continue to signature verification below
            signing_type="unsigned"  # Will be updated if signature found
          fi
        fi

        # ============================================================
        # PHASE 2: Verify signature of annotated tag
        # ============================================================
        # If we have a tag object (either originally or after fetch),
        # verify its cryptographic signature (GPG or SSH).

        if [ "$tag_object_type" = "tag" ]; then
          echo "✓ Annotated tag detected (has tag object)"

          # Get tag verification output and exit code
          verify_exit_code=0
          verify_output=$(git verify-tag --raw "$tag_name" 2>&1) || \
            verify_exit_code=$?

          # Debug: Show verify output
          if [ "$debug" = "true" ]; then
            echo "DEBUG: git verify-tag exit code: $verify_exit_code"
            echo "DEBUG: git verify-tag output:"
            echo "$verify_output"
            echo "---"
          fi

          # Parse verification result based on exit code and output
          # Exit code 0 = valid signature
          # Exit code != 0 could be: no signature, bad signature, or error

          # Detect signature type using dedicated function
          detect_signature_type "$verify_output" "$tag_name" "$debug"
        fi
      else
        echo "⚠️ Could not resolve tag reference"
        signing_type="unsigned"
      fi
    else
      echo "⚠️ Tag not found in repository, cannot verify signature"
      signing_type="unsigned"
    fi
  else
    echo "⚠️ Not in a git repository, cannot verify signature"
    signing_type="unsigned"
  fi
else
  # tag_string mode - cannot check signatures
  signing_type="unsigned"
  echo "ℹ️ String validation mode - signature check skipped"
fi

# ==================================================================
# STEP 8: Validate signature requirements
# ==================================================================

if [ "$require_signed" != "ambivalent" ]; then
  echo ""
  echo "🔒 Validating signature requirements..."

  case "$require_signed" in
    true)
      if [ "$signing_type" = "unsigned" ] || \
         [ "$signing_type" = "lightweight" ]; then
        echo "Error: Tag was NOT signed ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "invalid" ]; then
        echo "Error: Tag has INVALID signature ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "gpg-unverifiable" ]; then
        echo "Error: Tag has unverifiable GPG signature (key unavailable) ❌"
        echo "Note: Use require_signed=ambivalent to allow unverifiable signatures"
        valid="false"
        exit 1
      else
        echo "✓ Tag was signed ✅"
      fi
      ;;
    ssh)
      if [ "$signing_type" = "gpg" ] || \
         [ "$signing_type" = "gpg-unverifiable" ]; then
        echo "Error: Tag was signed with GPG key (SSH required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "unsigned" ] || \
           [ "$signing_type" = "lightweight" ]; then
        echo "Error: Tag was NOT signed (SSH required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "invalid" ]; then
        echo "Error: Tag has INVALID signature (SSH required) ❌"
        valid="false"
        exit 1
      else
        echo "✓ Tag was signed with SSH key ✅"
      fi
      ;;
    gpg)
      if [ "$signing_type" = "ssh" ]; then
        echo "Error: Tag was signed with SSH key (GPG required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "unsigned" ] || \
           [ "$signing_type" = "lightweight" ]; then
        echo "Error: Tag was NOT signed (GPG required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "invalid" ]; then
        echo "Error: Tag has INVALID signature (GPG required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "gpg-unverifiable" ]; then
        echo "Error: GPG signature cannot be verified (key unavailable) ❌"
        echo "Note: Use require_signed=ambivalent to allow unverifiable signatures"
        valid="false"
        exit 1
      else
        echo "✓ Tag was signed with GPG key ✅"
      fi
      ;;
    false)
      if [ "$signing_type" = "invalid" ]; then
        echo "Error: Tag has INVALID signature" \
             "(unsigned tags required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "gpg" ] || \
           [ "$signing_type" = "gpg-unverifiable" ]; then
        echo "Error: Tag is GPG signed" \
             "(unsigned tags required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "ssh" ]; then
        echo "Error: Tag is SSH signed" \
             "(unsigned tags required) ❌"
        valid="false"
        exit 1
      elif [ "$signing_type" = "unsigned" ] || \
           [ "$signing_type" = "lightweight" ]; then
        echo "✓ Tag is not signed ✅"
      else
        # Catch-all for any unexpected signing_type values
        echo "Error: Unexpected signature state: $signing_type ❌"
        valid="false"
        exit 1
      fi
      ;;
    *)
      echo "Error: Invalid require_signed value: '$require_signed' ❌"
      echo "Valid values: true, ssh, gpg, false, ambivalent"
      exit 1
      ;;
  esac
fi

# ==================================================================
# STEP 9: Output results
# ==================================================================

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "📊 Validation Results"
echo "═══════════════════════════════════════════════════════════"
echo "Tag Name:         $tag_name"
echo "Tag Type:         $tag_type"
echo "Signature:        $signing_type"
echo "Development Tag:  $development_tag"
echo "Version Prefix:   $version_prefix"
echo "Valid:            $valid"
echo "═══════════════════════════════════════════════════════════"

# Set outputs for GitHub Actions
{
  echo "valid=$valid"
  echo "tag_type=$tag_type"
  echo "signing_type=$signing_type"
  echo "development_tag=$development_tag"
  echo "version_prefix=$version_prefix"
  echo "tag_name=$tag_name"
} | safe_write_output

# Write step summary if available
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "## 🏷️ Tag Validation Results"
    echo ""
    echo "| Property | Value |"
    echo "|----------|-------|"
    echo "| Tag Name | \`$tag_name\` |"
    echo "| Tag Type | \`$tag_type\` |"
    echo "| Signature | \`$signing_type\` |"
    echo "| Development Tag | \`$development_tag\` |"
    echo "| Version Prefix | \`$version_prefix\` |"
    echo "| Valid | \`$valid\` |"
    echo ""
    if [ "$valid" = "true" ]; then
      echo "✅ **Tag validation passed**"
    else
      echo "❌ **Tag validation failed**"
    fi
  } | safe_append_summary
fi

echo ""
echo "✅ Tag validation complete"

# Restore original directory if we changed it for local repo operations
# This ensures the script doesn't leave the shell in an unexpected location,
# which is important for sourcing scenarios and general cleanup best practices
if [ -n "${orig_dir:-}" ]; then
  cd "$orig_dir" || true
fi
