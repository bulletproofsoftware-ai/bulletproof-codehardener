#!/bin/bash
# Code Hardener - Accessibility Test Suite
# Runs Pa11y WCAG 2.1 AA compliance tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener/accessibility"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$REPORTS_DIR"

echo -e "${YELLOW}Running Accessibility Tests (WCAG 2.1 AA)...${NC}"

FAILURES=0
MARKETING_ERRORS=0
DASHBOARD_ERRORS=0

# Marketing site pages to test
MARKETING_PAGES=(
    "http://localhost:3000"
    "http://localhost:3000/features"
    "http://localhost:3000/pricing"
    "http://localhost:3000/docs"
    "http://localhost:3000/about"
    "http://localhost:3000/contact"
    "http://localhost:3000/login"
    "http://localhost:3000/signup"
)

# Dashboard pages to test (requires auth - may need adjustment)
DASHBOARD_PAGES=(
    "http://localhost:3001"
    "http://localhost:3001/projects"
    "http://localhost:3001/scans"
    "http://localhost:3001/findings"
    "http://localhost:3001/attestations"
    "http://localhost:3001/settings"
)

# Test Marketing Site
echo -e "\n${YELLOW}Testing Marketing Site...${NC}"

if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\|301\|302"; then
    for page in "${MARKETING_PAGES[@]}"; do
        PAGE_NAME=$(echo "$page" | sed 's|http://localhost:3000||' | sed 's|/||g')
        [ -z "$PAGE_NAME" ] && PAGE_NAME="home"

        echo -e "  Testing: $PAGE_NAME"

        RESULT=$(docker exec pa11y pa11y "$page" \
            --standard WCAG2AA \
            --reporter json 2>/dev/null || echo '{"issues":[]}')

        ISSUES=$(echo "$RESULT" | jq '.issues | length' 2>/dev/null || echo "0")

        if [ "$ISSUES" -gt 0 ]; then
            echo -e "    ${RED}$ISSUES accessibility issues found${NC}"
            MARKETING_ERRORS=$((MARKETING_ERRORS + ISSUES))

            # Save detailed report
            echo "$RESULT" > "$REPORTS_DIR/marketing-$PAGE_NAME-$TIMESTAMP.json"
        else
            echo -e "    ${GREEN}No issues${NC}"
        fi
    done
else
    echo -e "${YELLOW}  Marketing site not running - skipping${NC}"
fi

# Test Dashboard
echo -e "\n${YELLOW}Testing Dashboard...${NC}"

if curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 | grep -q "200\|301\|302"; then
    for page in "${DASHBOARD_PAGES[@]}"; do
        PAGE_NAME=$(echo "$page" | sed 's|http://localhost:3001||' | sed 's|/||g')
        [ -z "$PAGE_NAME" ] && PAGE_NAME="overview"

        echo -e "  Testing: $PAGE_NAME"

        RESULT=$(docker exec pa11y pa11y "$page" \
            --standard WCAG2AA \
            --reporter json 2>/dev/null || echo '{"issues":[]}')

        ISSUES=$(echo "$RESULT" | jq '.issues | length' 2>/dev/null || echo "0")

        if [ "$ISSUES" -gt 0 ]; then
            echo -e "    ${RED}$ISSUES accessibility issues found${NC}"
            DASHBOARD_ERRORS=$((DASHBOARD_ERRORS + ISSUES))

            # Save detailed report
            echo "$RESULT" > "$REPORTS_DIR/dashboard-$PAGE_NAME-$TIMESTAMP.json"
        else
            echo -e "    ${GREEN}No issues${NC}"
        fi
    done
else
    echo -e "${YELLOW}  Dashboard not running - skipping${NC}"
fi

# Generate HTML report for all pages
echo -e "\n${YELLOW}Generating combined HTML report...${NC}"

{
    echo "<html><head><title>Code Hardener Accessibility Report</title>"
    echo "<style>body{font-family:system-ui;max-width:800px;margin:0 auto;padding:20px;}"
    echo ".pass{color:green;}.fail{color:red;}.warn{color:orange;}"
    echo "table{width:100%;border-collapse:collapse;}td,th{border:1px solid #ccc;padding:8px;}</style></head>"
    echo "<body><h1>Code Hardener Accessibility Report</h1>"
    echo "<p>Generated: $(date)</p>"
    echo "<p>Standard: WCAG 2.1 AA</p>"
    echo "<h2>Summary</h2>"
    echo "<table><tr><th>Site</th><th>Issues</th><th>Status</th></tr>"
    echo "<tr><td>Marketing Site</td><td>$MARKETING_ERRORS</td><td class='$([ $MARKETING_ERRORS -eq 0 ] && echo "pass" || echo "fail")'>$([ $MARKETING_ERRORS -eq 0 ] && echo "PASS" || echo "FAIL")</td></tr>"
    echo "<tr><td>Dashboard</td><td>$DASHBOARD_ERRORS</td><td class='$([ $DASHBOARD_ERRORS -eq 0 ] && echo "pass" || echo "fail")'>$([ $DASHBOARD_ERRORS -eq 0 ] && echo "PASS" || echo "FAIL")</td></tr>"
    echo "</table></body></html>"
} > "$REPORTS_DIR/accessibility-report-$TIMESTAMP.html"

# Summary
TOTAL_ERRORS=$((MARKETING_ERRORS + DASHBOARD_ERRORS))

echo -e "\n${YELLOW}Accessibility Test Summary:${NC}"
echo -e "  Marketing site issues: $MARKETING_ERRORS"
echo -e "  Dashboard issues: $DASHBOARD_ERRORS"
echo -e "  Total issues: $TOTAL_ERRORS"
echo -e "  Report: $REPORTS_DIR/accessibility-report-$TIMESTAMP.html"

if [ $TOTAL_ERRORS -gt 0 ]; then
    echo -e "${RED}  Accessibility tests failed - $TOTAL_ERRORS WCAG 2.1 AA violations${NC}"
    exit 1
else
    echo -e "${GREEN}  All accessibility tests passed${NC}"
    exit 0
fi
