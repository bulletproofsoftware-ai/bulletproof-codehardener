#!/bin/bash
# Code Hardener - Visual Regression Test Suite
# Runs BackstopJS visual comparison tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener/visual"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$REPORTS_DIR"

echo -e "${YELLOW}Running Visual Regression Tests...${NC}"

# Check if any frontend is running
MARKETING_UP=false
DASHBOARD_UP=false

if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\|301\|302"; then
    MARKETING_UP=true
fi

if curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 | grep -q "200\|301\|302"; then
    DASHBOARD_UP=true
fi

if [ "$MARKETING_UP" = false ] && [ "$DASHBOARD_UP" = false ]; then
    echo -e "${YELLOW}No frontends running - skipping visual tests${NC}"
    exit 0
fi

# Check if reference screenshots exist
REFERENCE_EXISTS=false
if docker exec backstopjs ls /backstop/backstop_data/bitmaps_reference 2>/dev/null | grep -q ".png"; then
    REFERENCE_EXISTS=true
fi

if [ "$REFERENCE_EXISTS" = false ]; then
    echo -e "${YELLOW}No reference screenshots found. Creating baseline...${NC}"

    # Create reference screenshots
    if docker exec backstopjs backstop reference \
        --config=/tests/visual/backstop.config.js 2>/dev/null; then
        echo -e "${GREEN}  Reference screenshots created${NC}"
        echo -e "${YELLOW}  Run tests again to compare against baseline${NC}"
        exit 0
    else
        echo -e "${RED}  Failed to create reference screenshots${NC}"
        exit 1
    fi
fi

# Run visual comparison test
echo -e "\n${YELLOW}Running visual comparison...${NC}"

if docker exec backstopjs backstop test \
    --config=/tests/visual/backstop.config.js 2>/dev/null; then

    echo -e "${GREEN}Visual regression tests passed - no differences detected${NC}"

    # Copy report to reports directory
    docker cp backstopjs:/backstop/backstop_data/html_report "$REPORTS_DIR/html_report_$TIMESTAMP" 2>/dev/null || true

    exit 0
else
    echo -e "${RED}Visual regression tests failed - differences detected${NC}"

    # Copy report for review
    docker cp backstopjs:/backstop/backstop_data/html_report "$REPORTS_DIR/html_report_$TIMESTAMP" 2>/dev/null || true

    echo -e "  Report: $REPORTS_DIR/html_report_$TIMESTAMP/index.html"
    echo -e ""
    echo -e "  To approve changes (if intentional):"
    echo -e "  docker exec backstopjs backstop approve --config=/tests/visual/backstop.config.js"

    exit 1
fi
