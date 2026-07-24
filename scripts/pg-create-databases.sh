#!/bin/bash
# Creates additional databases for DefectDojo and n8n
# Runs as part of Postgres docker-entrypoint-initdb.d

set -e

echo "Creating additional databases..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE DATABASE defectdojo;
    CREATE DATABASE n8n;
    GRANT ALL PRIVILEGES ON DATABASE defectdojo TO $POSTGRES_USER;
    GRANT ALL PRIVILEGES ON DATABASE n8n TO $POSTGRES_USER;
EOSQL

echo "Additional databases created: defectdojo, n8n"
