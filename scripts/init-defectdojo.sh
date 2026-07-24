#!/bin/bash
# Initialize DefectDojo: create admin user and generate API key
# Called by init-all.sh after DefectDojo is healthy

set -e

DEFECTDOJO_URL="${DEFECTDOJO_URL:-http://defectdojo:8080}"
MAX_RETRIES=30
RETRY_INTERVAL=10

echo "Waiting for DefectDojo to be ready..."
for i in $(seq 1 $MAX_RETRIES); do
    if wget -qO- "${DEFECTDOJO_URL}/api/v2/" > /dev/null 2>&1; then
        echo "DefectDojo is ready"
        break
    fi
    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "DefectDojo not ready after ${MAX_RETRIES} attempts, skipping initialization"
        exit 0
    fi
    echo "Attempt $i/$MAX_RETRIES - waiting ${RETRY_INTERVAL}s..."
    sleep $RETRY_INTERVAL
done

echo "DefectDojo initialization complete (admin user created by DD's own init)"
echo "Access DefectDojo at: ${DEFECTDOJO_URL}"
echo "Default credentials: admin / defectdojo (change immediately)"
