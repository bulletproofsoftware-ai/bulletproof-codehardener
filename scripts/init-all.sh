#!/bin/bash
# Code Hardener - Full initialization script
# Runs as the init container entrypoint

set -e

echo "========================================="
echo "Code Hardener - Initialization"
echo "========================================="

# 1. Apply database migrations
#
# `-v ON_ERROR_STOP=1` is load-bearing, not tidiness. Without it psql keeps
# going after a failed statement and still exits 0, so a migration that errors
# part-way leaves its enclosing BEGIN/COMMIT to roll back and the init container
# prints nothing. That is how `024_saml_replay_protection.sql` came to be absent
# from a running database while the deployment looked healthy: `saml_assertion_replay`
# and `uq_sso_sessions_pending_request` were both missing, and the SAML replay
# gate is a security control. A control that can be absent without anyone
# noticing is not a control.
#
# stderr is no longer sent to /dev/null, and every failure is now reported with
# the word ERROR plus the psql exit code, and repeated in a summary banner.
#
# The exit code of this script is deliberately UNCHANGED. Several pre-existing
# migrations are non-idempotent by construction (015 renames a column, 017 adds
# a constraint with no IF NOT EXISTS) and legitimately fail on a re-run against
# an already-migrated database, so failing the init container on any non-zero
# psql exit would break every restart. Making migrations tracked and replayable
# (a schema_migrations table) is the fix for that and is a separate change.
echo ""
echo "--- Phase 1: Database Migrations ---"
migration_failures=""
if [ -d "/app/migrations" ] && ls /app/migrations/*.sql 1> /dev/null 2>&1; then
    for migration in /app/migrations/*.sql; do
        migration_name=$(basename "$migration")
        echo "Applying migration: ${migration_name}..."
        if PGPASSWORD="${DB_PASSWORD}" psql \
            -v ON_ERROR_STOP=1 \
            -h "${DB_HOST:-postgres}" \
            -U "${DB_USER:-codehardener}" \
            -d "${DB_NAME:-codehardener}" \
            -f "$migration"; then
            echo "  OK: ${migration_name}"
        else
            psql_exit=$?
            echo "  ERROR: migration ${migration_name} FAILED (psql exit ${psql_exit}) - its transaction was ROLLED BACK, so every object it defines is ABSENT" >&2
            migration_failures="${migration_failures} ${migration_name}"
        fi
    done
    if [ -n "${migration_failures}" ]; then
        echo "" >&2
        echo "=========================================" >&2
        echo "ERROR: one or more migrations FAILED:" >&2
        for failed in ${migration_failures}; do
            echo "  - ${failed}" >&2
        done
        echo "Objects defined by those migrations are NOT present." >&2
        echo "Do NOT set SSO_ENABLED=true until 024_saml_replay_protection.sql applies cleanly:" >&2
        echo "  saml_assertion_replay and uq_sso_sessions_pending_request are the SAML replay gate." >&2
        echo "=========================================" >&2
    else
        echo "Migrations complete"
    fi
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
