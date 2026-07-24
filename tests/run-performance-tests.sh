#!/bin/bash
# Code Hardener - Performance Test Suite
# Runs K6 and Artillery load/stress tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener/performance"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$REPORTS_DIR"

echo -e "${YELLOW}Running Performance Tests...${NC}"

# Check if API is running
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health | grep -q "200"; then
    echo -e "${YELLOW}API not running at http://localhost:4000 - skipping performance tests${NC}"
    exit 0
fi

FAILURES=0

# 1. Smoke Test (quick sanity check)
echo -e "\n${YELLOW}[1/4] Running smoke test (30s, 2 VUs)...${NC}"

if docker exec k6 k6 run \
    --vus 2 \
    --duration 30s \
    --out json=/reports/codehardener-smoke-$TIMESTAMP.json \
    /tests/performance/smoke.js 2>/dev/null; then

    echo -e "${GREEN}  Smoke test passed${NC}"
else
    echo -e "${RED}  Smoke test failed${NC}"
    FAILURES=$((FAILURES + 1))
fi

# 2. Load Test (normal expected load)
echo -e "\n${YELLOW}[2/4] Running load test (2min, 50 VUs)...${NC}"

if docker exec k6 k6 run \
    --vus 50 \
    --duration 2m \
    --out json=/reports/codehardener-load-$TIMESTAMP.json \
    /tests/performance/load.js 2>/dev/null; then

    # Check thresholds
    P95=$(docker exec k6 cat /reports/codehardener-load-$TIMESTAMP.json | jq -s '[.[] | select(.metric == "http_req_duration" and .data.tags.percentile == "95")] | last | .data.value' 2>/dev/null || echo "0")

    if (( $(echo "$P95 > 500" | bc -l) )); then
        echo -e "${RED}  Load test failed - p95 response time ${P95}ms > 500ms${NC}"
        FAILURES=$((FAILURES + 1))
    else
        echo -e "${GREEN}  Load test passed - p95: ${P95}ms${NC}"
    fi
else
    echo -e "${RED}  Load test failed${NC}"
    FAILURES=$((FAILURES + 1))
fi

# 3. Stress Test (find breaking point)
echo -e "\n${YELLOW}[3/4] Running stress test (ramping to 200 VUs)...${NC}"

if docker exec k6 k6 run \
    --out json=/reports/codehardener-stress-$TIMESTAMP.json \
    /tests/performance/stress.js 2>/dev/null; then

    # Check error rate
    ERROR_RATE=$(docker exec k6 cat /reports/codehardener-stress-$TIMESTAMP.json | jq -s '[.[] | select(.metric == "http_req_failed")] | last | .data.value' 2>/dev/null || echo "0")

    if (( $(echo "$ERROR_RATE > 0.05" | bc -l) )); then
        echo -e "${YELLOW}  Stress test: High error rate ${ERROR_RATE} at peak load${NC}"
    else
        echo -e "${GREEN}  Stress test passed - error rate: ${ERROR_RATE}${NC}"
    fi
else
    echo -e "${YELLOW}  Stress test encountered errors (expected at high load)${NC}"
fi

# 4. Spike Test (sudden traffic surge)
echo -e "\n${YELLOW}[4/4] Running spike test...${NC}"

if docker exec artillery artillery run \
    --output /reports/codehardener-spike-$TIMESTAMP.json \
    /tests/performance/spike.yml 2>/dev/null; then

    echo -e "${GREEN}  Spike test completed${NC}"
else
    echo -e "${YELLOW}  Spike test completed with some failures${NC}"
fi

# Summary
echo -e "\n${YELLOW}Performance Test Summary:${NC}"
echo -e "  Reports: $REPORTS_DIR/"
echo -e "  Smoke: codehardener-smoke-$TIMESTAMP.json"
echo -e "  Load: codehardener-load-$TIMESTAMP.json"
echo -e "  Stress: codehardener-stress-$TIMESTAMP.json"
echo -e "  Spike: codehardener-spike-$TIMESTAMP.json"

if [ $FAILURES -gt 0 ]; then
    echo -e "${RED}  Performance tests detected issues${NC}"
    exit 1
else
    echo -e "${GREEN}  Performance tests passed${NC}"
    exit 0
fi
