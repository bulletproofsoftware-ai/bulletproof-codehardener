#!/bin/bash
# Code Hardener - Complete Test Suite Runner
# Runs all test categories and generates unified report

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Code Hardener - Complete Test Suite${NC}"
echo -e "${BLUE}  Started: $(date)${NC}"
echo -e "${BLUE}============================================${NC}"

# Create reports directory
mkdir -p "$REPORTS_DIR/$TIMESTAMP"

# Track results
SECURITY_RESULT=0
E2E_RESULT=0
API_RESULT=0
PERF_RESULT=0
A11Y_RESULT=0
VISUAL_RESULT=0

# Check if testing stack is running
echo -e "\n${YELLOW}Checking testing-security-stack status...${NC}"
cd "$TESTING_STACK"
if ! docker-compose ps | grep -q "Up"; then
    echo -e "${RED}Testing stack not running. Starting services...${NC}"
    docker-compose up -d
    sleep 30  # Wait for services to initialize
fi

# 1. Security Tests
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 1: Security Testing${NC}"
echo -e "${BLUE}========================================${NC}"

if "$SCRIPT_DIR/run-security-tests.sh"; then
    echo -e "${GREEN}Security tests: PASSED${NC}"
else
    echo -e "${RED}Security tests: FAILED${NC}"
    SECURITY_RESULT=1
fi

# 2. API Tests
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 2: API Testing${NC}"
echo -e "${BLUE}========================================${NC}"

if "$SCRIPT_DIR/run-api-tests.sh"; then
    echo -e "${GREEN}API tests: PASSED${NC}"
else
    echo -e "${RED}API tests: FAILED${NC}"
    API_RESULT=1
fi

# 3. E2E Tests
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 3: E2E Testing${NC}"
echo -e "${BLUE}========================================${NC}"

if "$SCRIPT_DIR/run-e2e-tests.sh"; then
    echo -e "${GREEN}E2E tests: PASSED${NC}"
else
    echo -e "${RED}E2E tests: FAILED${NC}"
    E2E_RESULT=1
fi

# 4. Performance Tests
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 4: Performance Testing${NC}"
echo -e "${BLUE}========================================${NC}"

if "$SCRIPT_DIR/run-performance-tests.sh"; then
    echo -e "${GREEN}Performance tests: PASSED${NC}"
else
    echo -e "${RED}Performance tests: FAILED${NC}"
    PERF_RESULT=1
fi

# 5. Accessibility Tests
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 5: Accessibility Testing${NC}"
echo -e "${BLUE}========================================${NC}"

if "$SCRIPT_DIR/run-accessibility-tests.sh"; then
    echo -e "${GREEN}Accessibility tests: PASSED${NC}"
else
    echo -e "${RED}Accessibility tests: FAILED${NC}"
    A11Y_RESULT=1
fi

# 6. Visual Regression Tests
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 6: Visual Regression Testing${NC}"
echo -e "${BLUE}========================================${NC}"

if "$SCRIPT_DIR/run-visual-tests.sh"; then
    echo -e "${GREEN}Visual tests: PASSED${NC}"
else
    echo -e "${RED}Visual tests: FAILED${NC}"
    VISUAL_RESULT=1
fi

# Generate Summary Report
echo -e "\n${BLUE}============================================${NC}"
echo -e "${BLUE}  Test Summary Report${NC}"
echo -e "${BLUE}============================================${NC}"

SUMMARY="$REPORTS_DIR/$TIMESTAMP/summary.txt"
{
    echo "Code Hardener Test Suite - Summary Report"
    echo "========================================"
    echo "Timestamp: $(date)"
    echo ""
    echo "Results:"
    echo "--------"
    [ $SECURITY_RESULT -eq 0 ] && echo "Security Tests: PASSED" || echo "Security Tests: FAILED"
    [ $API_RESULT -eq 0 ] && echo "API Tests: PASSED" || echo "API Tests: FAILED"
    [ $E2E_RESULT -eq 0 ] && echo "E2E Tests: PASSED" || echo "E2E Tests: FAILED"
    [ $PERF_RESULT -eq 0 ] && echo "Performance Tests: PASSED" || echo "Performance Tests: FAILED"
    [ $A11Y_RESULT -eq 0 ] && echo "Accessibility Tests: PASSED" || echo "Accessibility Tests: FAILED"
    [ $VISUAL_RESULT -eq 0 ] && echo "Visual Tests: PASSED" || echo "Visual Tests: FAILED"
    echo ""
    echo "Report Location: $REPORTS_DIR/$TIMESTAMP/"
    echo "Allure Dashboard: http://localhost:5252"
} > "$SUMMARY"

cat "$SUMMARY"

# Calculate overall result
TOTAL_FAILURES=$((SECURITY_RESULT + API_RESULT + E2E_RESULT + PERF_RESULT + A11Y_RESULT + VISUAL_RESULT))

if [ $TOTAL_FAILURES -eq 0 ]; then
    echo -e "\n${GREEN}============================================${NC}"
    echo -e "${GREEN}  ALL TESTS PASSED - Ready for deployment${NC}"
    echo -e "${GREEN}============================================${NC}"
    exit 0
else
    echo -e "\n${RED}============================================${NC}"
    echo -e "${RED}  $TOTAL_FAILURES TEST SUITE(S) FAILED${NC}"
    echo -e "${RED}  Deployment blocked${NC}"
    echo -e "${RED}============================================${NC}"
    exit 1
fi
