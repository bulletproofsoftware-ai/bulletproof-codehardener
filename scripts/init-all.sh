#!/bin/bash
# Code Hardener - Full initialization script
# Runs as the init container entrypoint

set -e

echo "========================================="
echo "Code Hardener - Initialization"
echo "========================================="

# 1. Apply database migrations
echo ""
echo "--- Phase 1: Database Migrations ---"
if [ -d "/app/migrations" ] && ls /app/migrations/*.sql 1> /dev/null 2>&1; then
    for migration in /app/migrations/*.sql; do
        migration_name=$(basename "$migration")
        echo "Applying migration: ${migration_name}..."
        PGPASSWORD="${DB_PASSWORD}" psql \
            -h "${DB_HOST:-postgres}" \
            -U "${DB_USER:-codehardener}" \
            -d "${DB_NAME:-codehardener}" \
            -f "$migration" 2>/dev/null || echo "  Warning: Migration ${migration_name} had issues (may already be applied)"
    done
    echo "Migrations complete"
else
    echo "No migrations found"
fi

# 2. Import n8n workflows (non-blocking)
echo ""
echo "--- Phase 2: n8n Workflow Import ---"
if [ -f "/app/scripts/init-n8n.sh" ]; then
    /bin/sh /app/scripts/init-n8n.sh || echo "n8n init had issues (non-fatal)"
else
    echo "n8n init script not found, skipping"
fi

# 3. Initialize DefectDojo (non-blocking)
echo ""
echo "--- Phase 3: DefectDojo Setup ---"
if [ -f "/app/scripts/init-defectdojo.sh" ]; then
    /bin/sh /app/scripts/init-defectdojo.sh || echo "DefectDojo init had issues (non-fatal)"
else
    echo "DefectDojo init script not found, skipping"
fi

echo ""
echo "========================================="
echo "Code Hardener initialization complete!"
echo ""
echo "Services:"
echo "  Backend API:    http://localhost:${BACKEND_PORT:-4000}"
echo "  Dashboard:      http://localhost:${DASHBOARD_PORT:-3001}"
echo "  n8n:            http://localhost:${N8N_PORT:-5678}"
echo "  DefectDojo:     http://localhost:${DEFECTDOJO_PORT:-8083}"
echo "  MCP SSE:        http://localhost:${BACKEND_PORT:-4000}/mcp/sse"
echo ""
echo "MCP stdio:  node backend/dist/mcp-server.js"
echo "========================================="
