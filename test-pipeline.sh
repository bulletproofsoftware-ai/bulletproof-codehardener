#!/bin/bash
# Code Hardener - Full Pipeline Test Script
# Tests the complete scanning workflow from API to results

set -e

API_URL="${API_URL:-http://localhost:4000}"
TEST_USER_ID="${TEST_USER_ID:-test-user-$(date +%s)}"

echo "=========================================="
echo "Code Hardener Pipeline Test"
echo "=========================================="
echo "API URL: $API_URL"
echo "Test User: $TEST_USER_ID"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}✓ $1${NC}"; }
error() { echo -e "${RED}✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}→ $1${NC}"; }

# Test 1: Health check
info "Testing API health..."
HEALTH=$(curl -s "$API_URL/health" || echo "failed")
if echo "$HEALTH" | grep -q "ok\|healthy"; then
    success "API is healthy"
else
    error "API health check failed: $HEALTH"
fi

# Test 2: Create a project
info "Creating test project..."
PROJECT=$(curl -s -X POST "$API_URL/api/v1/projects" \
    -H "Content-Type: application/json" \
    -H "X-User-Id: $TEST_USER_ID" \
    -d '{
        "name": "test-project",
        "repoUrl": "/scan-target"
    }')
PROJECT_ID=$(echo "$PROJECT" | jq -r '.id // .data.id // empty')
if [ -n "$PROJECT_ID" ]; then
    success "Project created: $PROJECT_ID"
else
    info "Project creation response: $PROJECT"
    error "Failed to create project"
fi

# Test 3: Trigger a scan
info "Triggering security scan (quick profile)..."
SCAN=$(curl -s -X POST "$API_URL/api/v1/scans" \
    -H "Content-Type: application/json" \
    -H "X-User-Id: $TEST_USER_ID" \
    -d "{
        \"projectId\": \"$PROJECT_ID\",
        \"profile\": \"quick\"
    }")
SCAN_ID=$(echo "$SCAN" | jq -r '.id // .data.id // .scanId // empty')
if [ -n "$SCAN_ID" ]; then
    success "Scan triggered: $SCAN_ID"
else
    info "Scan response: $SCAN"
    error "Failed to trigger scan"
fi

# Test 4: Poll for scan completion
info "Waiting for scan to complete..."
MAX_ATTEMPTS=60
ATTEMPT=0
while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
    STATUS=$(curl -s "$API_URL/api/v1/scans/$SCAN_ID" \
        -H "X-User-Id: $TEST_USER_ID")
    SCAN_STATUS=$(echo "$STATUS" | jq -r '.status // .data.status // empty')

    case "$SCAN_STATUS" in
        "completed")
            success "Scan completed!"
            break
            ;;
        "failed")
            error "Scan failed: $(echo "$STATUS" | jq -r '.error // .data.error // "unknown"')"
            ;;
        "running"|"pending"|"queued")
            printf "."
            sleep 2
            ;;
        *)
            info "Unknown status: $SCAN_STATUS"
            sleep 2
            ;;
    esac
    ATTEMPT=$((ATTEMPT + 1))
done

if [ "$SCAN_STATUS" != "completed" ]; then
    error "Scan did not complete in time (status: $SCAN_STATUS)"
fi

# Test 5: Get scan results
echo ""
info "Fetching scan results..."
RESULTS=$(curl -s "$API_URL/api/v1/scans/$SCAN_ID" \
    -H "X-User-Id: $TEST_USER_ID")

SCORE=$(echo "$RESULTS" | jq -r '.score // .data.score // 0')
RISK_LEVEL=$(echo "$RESULTS" | jq -r '.riskLevel // .data.riskLevel // .risk_level // "unknown"')
FINDINGS_COUNT=$(echo "$RESULTS" | jq -r '.findingsCount // .data.findingsCount // .findings_count // {}')

echo ""
echo "=========================================="
echo "SCAN RESULTS"
echo "=========================================="
echo "Score: $SCORE / 1000"
echo "Risk Level: $RISK_LEVEL"
echo "Findings: $FINDINGS_COUNT"
echo ""

# Test 6: Get findings
info "Fetching detailed findings..."
FINDINGS=$(curl -s "$API_URL/api/v1/scans/$SCAN_ID/findings?limit=5" \
    -H "X-User-Id: $TEST_USER_ID")
FINDINGS_LIST=$(echo "$FINDINGS" | jq -r '.data // []')
FINDINGS_TOTAL=$(echo "$FINDINGS" | jq -r '.meta.total // 0')

echo "Top findings (showing up to 5):"
echo "$FINDINGS_LIST" | jq -r '.[] | "  - [\(.severity)] \(.title)"' 2>/dev/null || echo "  No findings to display"
echo ""

# Test 7: Check attestation (if available)
info "Checking for attestation (waiting for Sigstore timeout)..."
sleep 12  # Wait for Sigstore signing attempt to timeout
ATTESTATION=$(curl -s "$API_URL/api/v1/scans/$SCAN_ID/attestation" \
    -H "X-User-Id: $TEST_USER_ID" 2>/dev/null || echo "{}")
ATTESTATION_ID=$(echo "$ATTESTATION" | jq -r '.data.id // empty')
if [ -n "$ATTESTATION_ID" ]; then
    SIGNED=$(echo "$ATTESTATION" | jq -r 'if .data.signature then "Yes" else "No" end')
    success "Attestation exists: $ATTESTATION_ID (Signed: $SIGNED)"
else
    info "No attestation found (Sigstore may not be configured)"
fi

# Test 8: MCP endpoint test
info "Testing MCP tool listing..."
MCP_TOOLS=$(curl -s "$API_URL/api/v1/mcp/tools" \
    -H "X-User-Id: $TEST_USER_ID" 2>/dev/null || echo "[]")
TOOL_COUNT=$(echo "$MCP_TOOLS" | jq -r 'length // 0')
if [ "$TOOL_COUNT" -gt 0 ]; then
    success "MCP tools available: $TOOL_COUNT"
else
    info "MCP tools endpoint returned: $MCP_TOOLS"
fi

echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
success "API Health: OK"
success "Project Creation: OK"
success "Scan Execution: OK"
echo "  Score: $SCORE"
echo "  Risk: $RISK_LEVEL"
echo "  Findings: $FINDINGS_TOTAL"
echo ""
echo "All tests passed!"
