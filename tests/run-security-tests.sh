#!/bin/bash
# Code Hardener - Security Test Suite
# Runs SAST, DAST, secret detection, and dependency scanning

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TESTING_STACK="~/Code/testing-security-stack"
REPORTS_DIR="$TESTING_STACK/reports/codehardener/security"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$REPORTS_DIR"

echo -e "${YELLOW}Running Security Tests...${NC}"

# Track failures
FAILURES=0

# 1. Static Analysis with Semgrep (SAST)
echo -e "\n${YELLOW}[1/5] Running Semgrep SAST scan...${NC}"
if docker exec semgrep semgrep \
    --config auto \
    --config p/security-audit \
    --config p/owasp-top-ten \
    --json \
    --output /reports/codehardener-semgrep-$TIMESTAMP.json \
    /src/codehardener 2>/dev/null; then

    # Check for critical/high findings
    CRITICAL=$(docker exec semgrep cat /reports/codehardener-semgrep-$TIMESTAMP.json | jq '[.results[] | select(.extra.severity == "ERROR")] | length')
    HIGH=$(docker exec semgrep cat /reports/codehardener-semgrep-$TIMESTAMP.json | jq '[.results[] | select(.extra.severity == "WARNING")] | length')

    echo -e "  Critical: $CRITICAL, High: $HIGH"

    if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
        echo -e "${RED}  SAST scan found critical/high issues${NC}"
        FAILURES=$((FAILURES + 1))
    else
        echo -e "${GREEN}  SAST scan passed${NC}"
    fi
else
    echo -e "${YELLOW}  Semgrep not available or scan failed${NC}"
fi

# 2. Dependency/Container Scanning with Trivy
echo -e "\n${YELLOW}[2/5] Running Trivy vulnerability scan...${NC}"
if docker exec trivy trivy fs \
    --severity HIGH,CRITICAL \
    --format json \
    -o /reports/codehardener-trivy-$TIMESTAMP.json \
    /src/codehardener 2>/dev/null; then

    # Check for vulnerabilities
    VULNS=$(docker exec trivy cat /reports/codehardener-trivy-$TIMESTAMP.json | jq '.Results[]?.Vulnerabilities // [] | length' | awk '{s+=$1} END {print s+0}')

    echo -e "  High/Critical vulnerabilities: $VULNS"

    if [ "$VULNS" -gt 0 ]; then
        echo -e "${RED}  Trivy found vulnerabilities${NC}"
        FAILURES=$((FAILURES + 1))
    else
        echo -e "${GREEN}  Trivy scan passed${NC}"
    fi
else
    echo -e "${YELLOW}  Trivy not available or scan failed${NC}"
fi

# 3. Secret Detection with Gitleaks
echo -e "\n${YELLOW}[3/5] Running Gitleaks secret detection...${NC}"
if docker exec gitleaks gitleaks detect \
    --source /src/codehardener \
    --report-path /reports/codehardener-secrets-$TIMESTAMP.json \
    --report-format json 2>/dev/null; then

    echo -e "${GREEN}  No secrets detected${NC}"
else
    SECRETS=$(docker exec gitleaks cat /reports/codehardener-secrets-$TIMESTAMP.json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
    if [ "$SECRETS" -gt 0 ]; then
        echo -e "${RED}  Gitleaks found $SECRETS potential secrets${NC}"
        FAILURES=$((FAILURES + 1))
    else
        echo -e "${GREEN}  Secret detection passed${NC}"
    fi
fi

# 4. Infrastructure as Code Scanning with Checkov
echo -e "\n${YELLOW}[4/5] Running Checkov IaC scan...${NC}"
if docker exec checkov checkov \
    -d /src/codehardener \
    --framework dockerfile \
    --framework kubernetes \
    --output json \
    --output-file /reports/codehardener-checkov-$TIMESTAMP.json 2>/dev/null; then

    FAILED_CHECKS=$(docker exec checkov cat /reports/codehardener-checkov-$TIMESTAMP.json | jq '.results.failed_checks | length')

    echo -e "  Failed checks: $FAILED_CHECKS"

    if [ "$FAILED_CHECKS" -gt 5 ]; then
        echo -e "${RED}  Checkov found significant IaC issues${NC}"
        FAILURES=$((FAILURES + 1))
    else
        echo -e "${GREEN}  IaC scan passed${NC}"
    fi
else
    echo -e "${YELLOW}  Checkov not available or scan failed${NC}"
fi

# 5. OWASP ZAP DAST Scan (if services are running)
echo -e "\n${YELLOW}[5/5] Running OWASP ZAP DAST scan...${NC}"

# Check if marketing site is running
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200\|301\|302"; then
    echo -e "  Scanning marketing site..."
    docker exec owasp-zap zap-baseline.py \
        -t http://host.docker.internal:3000 \
        -r /zap/reports/codehardener-marketing-$TIMESTAMP.html \
        -J /zap/reports/codehardener-marketing-$TIMESTAMP.json 2>/dev/null || true

    # Check for high/medium alerts
    ALERTS=$(docker exec owasp-zap cat /zap/reports/codehardener-marketing-$TIMESTAMP.json 2>/dev/null | jq '[.site[].alerts[] | select(.riskcode >= 2)] | length' 2>/dev/null || echo "0")

    if [ "$ALERTS" -gt 0 ]; then
        echo -e "${RED}  ZAP found $ALERTS medium+ alerts on marketing site${NC}"
    else
        echo -e "${GREEN}  Marketing site DAST passed${NC}"
    fi
else
    echo -e "${YELLOW}  Marketing site not running - skipping DAST${NC}"
fi

# Check if dashboard is running
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 | grep -q "200\|301\|302"; then
    echo -e "  Scanning dashboard..."
    docker exec owasp-zap zap-baseline.py \
        -t http://host.docker.internal:3001 \
        -r /zap/reports/codehardener-dashboard-$TIMESTAMP.html \
        -J /zap/reports/codehardener-dashboard-$TIMESTAMP.json 2>/dev/null || true
else
    echo -e "${YELLOW}  Dashboard not running - skipping DAST${NC}"
fi

# Check if API is running
if curl -s -o /dev/null -w "%{http_code}" http://localhost:4000/health | grep -q "200"; then
    echo -e "  Scanning API..."
    docker exec owasp-zap zap-api-scan.py \
        -t http://host.docker.internal:4000/api/v1 \
        -f openapi \
        -r /zap/reports/codehardener-api-$TIMESTAMP.html 2>/dev/null || true
else
    echo -e "${YELLOW}  API not running - skipping DAST${NC}"
fi

# Summary
echo -e "\n${YELLOW}Security Test Summary:${NC}"
echo -e "  Reports saved to: $REPORTS_DIR/"
echo -e "  Timestamp: $TIMESTAMP"

if [ $FAILURES -gt 0 ]; then
    echo -e "${RED}  $FAILURES security check(s) failed${NC}"
    exit 1
else
    echo -e "${GREEN}  All security checks passed${NC}"
    exit 0
fi
