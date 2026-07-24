#!/bin/bash
# Code Hardener - API Test Suite
# Runs Newman API tests against backend endpoints

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener/api"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$REPORTS_DIR"

echo -e "${YELLOW}Running API Tests...${NC}"

# Check if API is running
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health | grep -q "200"; then
    echo -e "${YELLOW}API not running at http://localhost:4000 - skipping API tests${NC}"
    exit 0
fi

# Run Newman API tests
echo -e "\n${YELLOW}Running Newman API collection...${NC}"

if docker exec newman newman run \
    /tests/api/codehardener-api.postman_collection.json \
    -e /tests/api/local.postman_environment.json \
    --reporters cli,json,allure \
    --reporter-json-export /results/codehardener-api-$TIMESTAMP.json \
    --reporter-allure-export /app/allure-results 2>/dev/null; then

    echo -e "${GREEN}API tests passed${NC}"
    exit 0
else
    echo -e "${RED}API tests failed${NC}"
    echo -e "  Report: $REPORTS_DIR/codehardener-api-$TIMESTAMP.json"
    exit 1
fi
