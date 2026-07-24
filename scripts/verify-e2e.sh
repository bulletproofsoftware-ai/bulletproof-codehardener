#!/bin/bash
# Code Hardener - End-to-End Verification Script
# Validates the complete stack is working after docker compose up
#
# Usage: ./scripts/verify-e2e.sh
# Assumes: docker compose up -d has been run

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

PASS=0
FAIL=0
WARN=0

API_URL="${API_URL:-http://localhost:4000}"
N8N_URL="${N8N_URL:-http://localhost:5678}"
DD_URL="${DD_URL:-http://localhost:8083}"

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    FAIL=$((FAIL + 1))
}

warn() {
    echo -e "  ${YELLOW}!${NC} $1"
    WARN=$((WARN + 1))
}

wait_for_service() {
    local url=$1
    local name=$2
    local max_retries=${3:-30}
    local interval=${4:-2}

    for i in $(seq 1 $max_retries); do
        if curl -sf "$url" > /dev/null 2>&1; then
            return 0
        fi
        if [ "$i" -eq "$max_retries" ]; then
            return 1
        fi
        sleep $interval
    done
}

echo ""
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Code Hardener - E2E Verification${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""

# ─── Phase 1: Service Health ───
echo -e "${BOLD}Phase 1: Service Health Checks${NC}"
echo "─────────────────────────────"

# Backend API
if wait_for_service "${API_URL}/health" "Backend API" 15 2; then
    pass "Backend API is healthy (${API_URL})"
else
    fail "Backend API not responding at ${API_URL}/health"
fi

# PostgreSQL (via backend health which depends on DB)
if docker exec codehardener-postgres-1 pg_isready -U codehardener > /dev/null 2>&1; then
    pass "PostgreSQL is ready"
else
    fail "PostgreSQL not ready"
fi

# Redis
if docker exec codehardener-redis-1 redis-cli ping 2>/dev/null | grep -q PONG; then
    pass "Redis is ready"
else
    fail "Redis not ready"
fi

# n8n
if wait_for_service "${N8N_URL}/healthz" "n8n" 10 2; then
    pass "n8n is healthy (${N8N_URL})"
else
    warn "n8n not responding (optional service)"
fi

# DefectDojo
if wait_for_service "${DD_URL}/api/v2/" "DefectDojo" 10 2; then
    pass "DefectDojo is healthy (${DD_URL})"
else
    warn "DefectDojo not responding (optional service)"
fi

echo ""

# ─── Phase 2: Database Verification ───
echo -e "${BOLD}Phase 2: Database Verification${NC}"
echo "──────────────────────────────"

# Check databases exist
for db in codehardener defectdojo n8n; do
    if docker exec codehardener-postgres-1 psql -U codehardener -lqt 2>/dev/null | grep -qw "$db"; then
        pass "Database '${db}' exists"
    else
        fail "Database '${db}' missing"
    fi
done

# Check core tables
for table in users projects scans findings policies policy_rules api_keys; do
    if docker exec codehardener-postgres-1 psql -U codehardener -d codehardener -c "\\d ${table}" > /dev/null 2>&1; then
        pass "Table '${table}' exists"
    else
        fail "Table '${table}' missing"
    fi
done

echo ""

# ─── Phase 3: API Endpoints ───
echo -e "${BOLD}Phase 3: API Endpoint Verification${NC}"
echo "───────────────────────────────────"

# Health endpoint
response=$(curl -sf "${API_URL}/health" 2>/dev/null)
if echo "$response" | grep -q "ok\|healthy"; then
    pass "GET /health returns ok"
else
    fail "GET /health unexpected response"
fi

# Auth endpoints exist (should return 4xx, not 404)
for endpoint in "/api/v1/auth/register" "/api/v1/auth/login"; do
    status=$(curl -sf -o /dev/null -w "%{http_code}" -X POST "${API_URL}${endpoint}" -H "Content-Type: application/json" -d '{}' 2>/dev/null)
    if [ "$status" != "404" ] && [ "$status" != "000" ]; then
        pass "POST ${endpoint} is routed (HTTP ${status})"
    else
        fail "POST ${endpoint} returns 404 or no response"
    fi
done

# MCP SSE endpoint
status=$(curl -sf -o /dev/null -w "%{http_code}" "${API_URL}/mcp/sse" -H "X-API-Key: test" --max-time 2 2>/dev/null || true)
if [ -n "$status" ] && [ "$status" != "000" ]; then
    pass "GET /mcp/sse is routed (HTTP ${status})"
else
    warn "GET /mcp/sse not responding (may need auth)"
fi

echo ""

# ─── Phase 4: API Functional Test ───
echo -e "${BOLD}Phase 4: API Functional Test${NC}"
echo "────────────────────────────"

# Register a test user
register_response=$(curl -s -X POST "${API_URL}/api/v1/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"email":"e2e-test@codehardener.local","password":"TestPassword123!","name":"E2E Test"}' 2>/dev/null || echo "")

TOKEN=""
if echo "$register_response" | jq -e '.data.tokens.accessToken' > /dev/null 2>&1; then
    pass "User registration works"
    TOKEN=$(echo "$register_response" | jq -r '.data.tokens.accessToken')
elif echo "$register_response" | grep -q "already exists\|duplicate\|conflict\|already registered"; then
    warn "Test user already exists (previous run)"
    login_response=$(curl -s -X POST "${API_URL}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"email":"e2e-test@codehardener.local","password":"TestPassword123!"}' 2>/dev/null || echo "")
    TOKEN=$(echo "$login_response" | jq -r '.data.tokens.accessToken // empty')
    if [ -n "$TOKEN" ]; then
        pass "User login works"
    else
        fail "User login failed"
    fi
else
    fail "User registration failed: ${register_response:0:200}"
fi

AUTH_HEADER="Authorization: Bearer ${TOKEN}"

# Helper: test an authenticated GET endpoint returns 200
test_endpoint() {
    local method="${1:-GET}"
    local path="$2"
    local label="$3"
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" -X "$method" "${API_URL}${path}" \
        -H "$AUTH_HEADER" -H "Content-Type: application/json" 2>/dev/null || echo "000")
    if [ "$status" = "200" ] || [ "$status" = "201" ]; then
        pass "${label} (HTTP ${status})"
    elif [ "$status" = "000" ]; then
        fail "${label} - no response"
    else
        fail "${label} (HTTP ${status})"
    fi
}

if [ -n "${TOKEN:-}" ]; then
    # Project CRUD
    project_response=$(curl -s -X POST "${API_URL}/api/v1/projects" \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -d '{"name":"e2e-test-project","description":"E2E verification project"}' 2>/dev/null || echo "")

    if echo "$project_response" | jq -e '.data.id' > /dev/null 2>&1; then
        pass "Project creation works"
        PROJECT_ID=$(echo "$project_response" | jq -r '.data.id')
    elif echo "$project_response" | jq -e '.success' > /dev/null 2>&1; then
        pass "Project creation works (already exists)"
        PROJECT_ID=""
    else
        warn "Project creation returned unexpected response"
        PROJECT_ID=""
    fi

    echo ""
    echo -e "${BOLD}Phase 4b: Comprehensive Endpoint Tests${NC}"
    echo "───────────────────────────────────────"

    # Core endpoints
    test_endpoint GET "/api/v1/projects" "GET /projects"
    test_endpoint GET "/api/v1/scans" "GET /scans"
    test_endpoint GET "/api/v1/findings" "GET /findings"
    test_endpoint GET "/api/v1/dashboard/summary" "GET /dashboard/summary"

    # Billing
    test_endpoint GET "/api/v1/billing/plans" "GET /billing/plans (public)"
    test_endpoint GET "/api/v1/billing/subscription" "GET /billing/subscription"
    test_endpoint GET "/api/v1/billing/usage" "GET /billing/usage"
    test_endpoint GET "/api/v1/billing/history" "GET /billing/history"
    test_endpoint GET "/api/v1/billing/payment-methods" "GET /billing/payment-methods"

    # Policies
    test_endpoint GET "/api/v1/policies" "GET /policies"

    # Webhooks
    test_endpoint GET "/api/v1/webhooks" "GET /webhooks"
    test_endpoint GET "/api/v1/webhooks/events" "GET /webhooks/events"

    # Badges
    test_endpoint GET "/api/v1/badges" "GET /badges"

    # Reports
    test_endpoint GET "/api/v1/reports" "GET /reports"

    # Attestations
    test_endpoint GET "/api/v1/attestations" "GET /attestations"

    # Notifications
    test_endpoint GET "/api/v1/notifications" "GET /notifications"
    test_endpoint GET "/api/v1/notifications/preferences" "GET /notifications/preferences"

    # Team
    test_endpoint GET "/api/v1/team/members" "GET /team/members"

    # API Keys
    test_endpoint GET "/api/v1/api-keys" "GET /api-keys"

    # Integrations
    test_endpoint GET "/api/v1/integrations" "GET /integrations"

    # MCP
    test_endpoint GET "/api/v1/mcp/tools" "GET /mcp/tools"

    # Tests
    test_endpoint GET "/api/v1/tests/history" "GET /tests/history"
else
    warn "Skipping authenticated tests (no token)"
fi

echo ""

# ─── Phase 5: n8n Workflows ───
echo -e "${BOLD}Phase 5: n8n Workflow Verification${NC}"
echo "──────────────────────────────────"

if curl -sf "${N8N_URL}/healthz" > /dev/null 2>&1; then
    # Check if workflows were imported
    workflow_count=$(curl -sf -u "admin:codehardener" "${N8N_URL}/api/v1/workflows" 2>/dev/null | grep -o '"id"' | wc -l || echo "0")
    if [ "$workflow_count" -gt 0 ]; then
        pass "n8n has ${workflow_count} workflows imported"
    else
        warn "No n8n workflows found (may need manual import)"
    fi
else
    warn "n8n not available, skipping workflow checks"
fi

echo ""

# ─── Phase 6: Internal API ───
echo -e "${BOLD}Phase 6: Internal API (n8n hooks)${NC}"
echo "──────────────────────────────────"

INTERNAL_KEY="${INTERNAL_API_KEY:-dev-internal-key-change-in-production}"

# Test internal endpoint auth
status=$(curl -sf -o /dev/null -w "%{http_code}" "${API_URL}/internal/projects/test/config" \
    -H "X-Internal-API-Key: ${INTERNAL_KEY}" 2>/dev/null || echo "000")
if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    pass "Internal API is routed (HTTP ${status})"
else
    fail "Internal API not responding"
fi

# Test without auth (should be 401/403)
status=$(curl -sf -o /dev/null -w "%{http_code}" "${API_URL}/internal/projects/test/config" 2>/dev/null || echo "000")
if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    pass "Internal API requires auth (HTTP ${status})"
else
    warn "Internal API auth check returned HTTP ${status}"
fi

echo ""

# ─── Summary ───
echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD}  Verification Summary${NC}"
echo -e "${BOLD}=========================================${NC}"
echo ""
echo -e "  ${GREEN}Passed${NC}: ${PASS}"
echo -e "  ${RED}Failed${NC}: ${FAIL}"
echo -e "  ${YELLOW}Warnings${NC}: ${WARN}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All critical checks passed!${NC}"
    echo ""
    echo "  Services:"
    echo "    Backend API:    ${API_URL}"
    echo "    n8n:            ${N8N_URL}"
    echo "    DefectDojo:     ${DD_URL}"
    echo "    MCP SSE:        ${API_URL}/mcp/sse"
    echo "    MCP stdio:      node backend/dist/mcp-server.js"
    exit 0
else
    echo -e "  ${RED}${BOLD}${FAIL} critical check(s) failed.${NC}"
    echo "  Review the failures above and check docker compose logs."
    exit 1
fi
