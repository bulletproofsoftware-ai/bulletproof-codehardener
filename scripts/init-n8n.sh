#!/bin/bash
# Import n8n workflow templates via n8n API
# Called by init-all.sh after n8n is healthy

set -e

N8N_URL="${N8N_URL:-http://n8n:5678}"
N8N_USER="${N8N_USER:-admin}"
N8N_PASSWORD="${N8N_PASSWORD:-codehardener}"
WORKFLOW_DIR="/app/n8n-workflows"
MAX_RETRIES=20
RETRY_INTERVAL=5

echo "Waiting for n8n to be ready..."
for i in $(seq 1 $MAX_RETRIES); do
    if wget -qO- "${N8N_URL}/healthz" > /dev/null 2>&1; then
        echo "n8n is ready"
        break
    fi
    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "n8n not ready after ${MAX_RETRIES} attempts, skipping workflow import"
        exit 0
    fi
    echo "Attempt $i/$MAX_RETRIES - waiting ${RETRY_INTERVAL}s..."
    sleep $RETRY_INTERVAL
done

echo "Importing n8n workflows..."

for workflow_file in "${WORKFLOW_DIR}"/*.json; do
    if [ ! -f "$workflow_file" ]; then
        echo "No workflow files found in ${WORKFLOW_DIR}"
        break
    fi

    workflow_name=$(basename "$workflow_file" .json)
    echo "  Importing: ${workflow_name}..."

    response=$(wget -qO- \
        --header="Content-Type: application/json" \
        --post-file="$workflow_file" \
        --http-user="${N8N_USER}" \
        --http-password="${N8N_PASSWORD}" \
        "${N8N_URL}/api/v1/workflows" 2>&1) || {
        echo "  Warning: Failed to import ${workflow_name} (may already exist)"
        continue
    }

    echo "  Imported: ${workflow_name}"
done

echo "n8n workflow import complete"
echo "Access n8n at: ${N8N_URL}"
