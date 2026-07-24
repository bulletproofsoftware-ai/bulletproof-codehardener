#!/bin/bash
# Code Hardener - E2E Test Suite
# Runs Playwright end-to-end tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener/e2e"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$REPORTS_DIR"

echo -e "${YELLOW}Running E2E Tests...${NC}"

# Check if any frontend is running
DASHBOARD_UP=false

if curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 | grep -q "200\|301\|302"; then
    DASHBOARD_UP=true
    echo -e "  Dashboard: ${GREEN}Running${NC}"
else
    echo -e "  Dashboard: ${YELLOW}Not running${NC}"
fi

if [ "$DASHBOARD_UP" = false ]; then
    echo -e "${YELLOW}No frontends running - skipping E2E tests${NC}"
    exit 0
fi

# Run Playwright tests
echo -e "\n${YELLOW}Running Playwright E2E tests...${NC}"

FAILURES=0

# Dashboard tests
if [ "$DASHBOARD_UP" = true ]; then
    echo -e "\n${YELLOW}Testing dashboard...${NC}"

    if docker exec playwright npx playwright test \
        --config=/tests/e2e/playwright.config.ts \
        --project=chromium \
        --grep @dashboard \
        --reporter=allure-playwright 2>/dev/null; then
        echo -e "${GREEN}  Dashboard E2E tests passed${NC}"
    else
        echo -e "${RED}  Dashboard E2E tests failed${NC}"
        FAILURES=$((FAILURES + 1))
    fi
fi

# Link crawler test (critical)
echo -e "\n${YELLOW}Running comprehensive link crawler...${NC}"

if docker exec playwright npx playwright test \
    --config=/tests/e2e/playwright.config.ts \
    --project=chromium \
    /tests/e2e/link-crawler.spec.ts \
    --reporter=json 2>/dev/null; then
    echo -e "${GREEN}  Link crawler passed - all links verified${NC}"
else
    echo -e "${RED}  Link crawler failed - broken links detected${NC}"
    FAILURES=$((FAILURES + 1))
fi

# Summary
echo -e "\n${YELLOW}E2E Test Summary:${NC}"
echo -e "  Reports: $REPORTS_DIR/"
echo -e "  Allure: http://localhost:5252"

if [ $FAILURES -gt 0 ]; then
    echo -e "${RED}  $FAILURES E2E test suite(s) failed${NC}"
    exit 1
else
    echo -e "${GREEN}  All E2E tests passed${NC}"
    exit 0
fi
