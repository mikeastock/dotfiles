#!/usr/bin/env bash
#
# Run all test suites
#
# Usage: ./tests/run-all.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Agents Test Suite${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""

FAILED=0

# Run each test script
for test_script in "$SCRIPT_DIR"/test-*.sh; do
    if [ -x "$test_script" ]; then
        test_name=$(basename "$test_script")
        echo -e "${YELLOW}Running $test_name...${NC}"
        if "$test_script"; then
            echo -e "${GREEN}$test_name passed${NC}"
        else
            echo -e "${RED}$test_name failed${NC}"
            FAILED=1
        fi
        echo ""
    fi
done

if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}All test suites passed!${NC}"
    exit 0
else
    echo -e "${RED}Some test suites failed!${NC}"
    exit 1
fi
