#!/bin/bash
# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0
#
# Comprehensive test script for multiple validation types
# Tests all combinations of: semver, github, and gerrit requirements
#
# Requirements:
# - .secrets.github file with GITHUB_TOKEN
# - .secrets.gerrit file with GERRIT_USERNAME and GERRIT_PASSWORD
#
# Optional: Multi-server credential switching
# Define use_onap() and use_lf() functions in .secrets.gerrit to switch
# between different Gerrit server credentials. If not defined, the script
# will use safe defaults that work with a single set of credentials.

set -e

# Test configuration
TEST_TAG="v0.2.1"  # SSH-signed tag for testing

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load secrets
# shellcheck disable=SC1091
if [ -f .secrets.github ]; then
    source .secrets.github
else
    echo -e "${RED}Error: .secrets.github not found${NC}"
    exit 1
fi

# shellcheck disable=SC1091
if [ -f .secrets.gerrit ]; then
    source .secrets.gerrit
else
    echo -e "${RED}Error: .secrets.gerrit not found${NC}"
    exit 1
fi

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test result tracking
declare -a FAILED_TEST_NAMES

# Define safe default credential switching functions
# These can be overridden in .secrets.gerrit if multiple servers are used
if ! type use_onap &> /dev/null; then
    use_onap() {
        echo "Note: use_onap() not defined in .secrets.gerrit - using default credentials"
        return 0
    }
fi

if ! type use_lf &> /dev/null; then
    use_lf() {
        echo "Note: use_lf() not defined in .secrets.gerrit - using default credentials"
        return 0
    }
fi

# Function to print test header
print_test_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Test $((TOTAL_TESTS + 1)): $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to run a test
run_test() {
    local test_name="$1"
    local tag="$2"
    local expected_result="$3"  # "pass" or "fail"
    shift 3
    local cmd_args=("$@")

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_test_header "$test_name"

    echo -e "${YELLOW}Command:${NC} tag-validate verify $tag ${cmd_args[*]}"
    echo -e "${YELLOW}Expected:${NC} $expected_result"
    echo ""

    # Run the command
    if tag-validate verify "$tag" "${cmd_args[@]}"; then
        actual_result="pass"
    else
        actual_result="fail"
    fi

    echo ""

    # Check if result matches expectation
    if [ "$actual_result" == "$expected_result" ]; then
        echo -e "${GREEN}✓ PASS${NC} - Test behaved as expected"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ FAIL${NC} - Expected $expected_result but got $actual_result"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
    fi
}

# Function to print section header
print_section() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║ $1${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════╝${NC}"
}

# Make sure we're in the right directory
cd "$(dirname "$0")"

echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Multiple Validation Types Test Suite${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Testing tag: $TEST_TAG in current repository"
echo "GitHub Token: ${GITHUB_TOKEN:0:10}..."
echo "Gerrit Username: $GERRIT_USERNAME"
echo ""

# ============================================================================
# Test 1: Single validation - SemVer only (should PASS)
# ============================================================================
print_section "Single Validation Tests"

run_test \
    "SemVer validation only - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver

# ============================================================================
# Test 2: Single validation - GitHub only (should PASS if key is registered)
# ============================================================================
run_test \
    "GitHub key verification only - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-github

# ============================================================================
# Test 3: Single validation - Gerrit only with ONAP (should PASS if key is registered)
# ============================================================================
use_onap > /dev/null 2>&1

run_test \
    "Gerrit key verification only (ONAP) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-gerrit gerrit.onap.org

# ============================================================================
# Test 4: Single validation - Gerrit only with LF (should PASS if key is registered)
# ============================================================================
use_lf > /dev/null 2>&1

run_test \
    "Gerrit key verification only (LF) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-gerrit gerrit.linuxfoundation.org

# ============================================================================
# Test 5: Dual validation - SemVer + GitHub (should PASS if both conditions met)
# ============================================================================
print_section "Dual Validation Tests"

run_test \
    "SemVer + GitHub - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-github

# ============================================================================
# Test 6: Dual validation - SemVer + Gerrit (ONAP)
# ============================================================================
use_onap > /dev/null 2>&1

run_test \
    "SemVer + Gerrit (ONAP) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-gerrit gerrit.onap.org

# ============================================================================
# Test 7: Dual validation - SemVer + Gerrit (LF)
# ============================================================================
use_lf > /dev/null 2>&1

run_test \
    "SemVer + Gerrit (LF) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-gerrit gerrit.linuxfoundation.org

# ============================================================================
# Test 8: Dual validation - GitHub + Gerrit (ONAP)
# ============================================================================
use_onap > /dev/null 2>&1

run_test \
    "GitHub + Gerrit (ONAP) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-github \
    --require-gerrit gerrit.onap.org

# ============================================================================
# Test 9: Dual validation - GitHub + Gerrit (LF)
# ============================================================================
use_lf > /dev/null 2>&1

run_test \
    "GitHub + Gerrit (LF) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-github \
    --require-gerrit gerrit.linuxfoundation.org

# ============================================================================
# Test 10: Triple validation - SemVer + GitHub + Gerrit (ONAP)
# ============================================================================
print_section "Triple Validation Tests"

use_onap > /dev/null 2>&1

run_test \
    "SemVer + GitHub + Gerrit (ONAP) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-github \
    --require-gerrit gerrit.onap.org

# ============================================================================
# Test 11: Triple validation - SemVer + GitHub + Gerrit (LF)
# ============================================================================
use_lf > /dev/null 2>&1

run_test \
    "SemVer + GitHub + Gerrit (LF) - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-github \
    --require-gerrit gerrit.linuxfoundation.org

# ============================================================================
# Failure Tests - Invalid SemVer
# ============================================================================
print_section "Failure Tests - Invalid SemVer"

run_test \
    "Invalid SemVer with type requirement - SHOULD FAIL" \
    "invalid-tag" \
    "fail" \
    --require-type semver

run_test \
    "Invalid SemVer + GitHub + Gerrit - SHOULD FAIL" \
    "invalid-tag" \
    "fail" \
    --require-type semver \
    --require-github \
    --require-gerrit gerrit.onap.org

# ============================================================================
# Failure Tests - Invalid GitHub (using non-existent tag)
# ============================================================================
print_section "Failure Tests - Non-existent Tag"

run_test \
    "Non-existent tag with GitHub - SHOULD FAIL" \
    "v99.99.99" \
    "fail" \
    --require-github

run_test \
    "Non-existent tag with all validations - SHOULD FAIL" \
    "v99.99.99" \
    "fail" \
    --require-type semver \
    --require-github \
    --require-gerrit gerrit.onap.org

# ============================================================================
# Edge Case Tests
# ============================================================================
print_section "Edge Case Tests"

# CalVer instead of SemVer (should fail SemVer requirement)
run_test \
    "CalVer tag with SemVer requirement - SHOULD FAIL" \
    "2024.01.15" \
    "fail" \
    --require-type semver

# SemVer tag with CalVer requirement (should fail CalVer requirement)
run_test \
    "SemVer tag with CalVer requirement - SHOULD FAIL" \
    "$TEST_TAG" \
    "fail" \
    --require-type calver

# Both SemVer and CalVer allowed
run_test \
    "SemVer tag with 'both' type requirement - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type both

# Test with both Gerrit servers in sequence
use_onap > /dev/null 2>&1
run_test \
    "All validations with ONAP Gerrit - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-github \
    --require-gerrit gerrit.onap.org

use_lf > /dev/null 2>&1
run_test \
    "All validations with LF Gerrit - SHOULD PASS" \
    "$TEST_TAG" \
    "pass" \
    --require-type semver \
    --require-github \
    --require-gerrit gerrit.linuxfoundation.org

# ============================================================================
# Print Summary
# ============================================================================
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Total Tests:  $TOTAL_TESTS"
echo -e "${GREEN}Passed:       $PASSED_TESTS${NC}"
echo -e "${RED}Failed:       $FAILED_TESTS${NC}"
echo ""

if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed Tests:${NC}"
    for test_name in "${FAILED_TEST_NAMES[@]}"; do
        echo -e "  ${RED}✗${NC} $test_name"
    done
    echo ""
    echo -e "${RED}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  SOME TESTS FAILED${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════════${NC}"
    exit 1
else
    echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"
    exit 0
fi
