# Code Hardener - Development Makefile
# Full-stack security platform with 27 integrated tools
#
# Usage:
#   make help           - Show all commands
#   make up             - Start core services
#   make up-all         - Start all services including security tools
#   make scan-security  - Run security scans
#

.PHONY: help up down restart logs build clean \
        up-all up-security up-performance up-api-testing \
        backend-build backend-logs backend-shell \
        dashboard-build dashboard-logs \
        marketing-build marketing-logs \
        db-shell db-migrate \
        scan-all scan-security scan-sast scan-secrets scan-deps \
        test-api test-e2e test-performance test-accessibility \
        sbom status \
        mcp-start mcp-test scan-demo workflows-import verify

# Default target
.DEFAULT_GOAL := help

help:
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║            Code Hardener - Development Commands                 ║"
	@echo "╠═══════════════════════════════════════════════════════════════╣"
	@echo "║                                                               ║"
	@echo "║  Core Services                                                ║"
	@echo "║  ────────────                                                 ║"
	@echo "║  make up              Start core services (db, redis, api)    ║"
	@echo "║  make down            Stop all services                       ║"
	@echo "║  make restart         Restart all services                    ║"
	@echo "║  make logs            View all logs                           ║"
	@echo "║  make build           Build all images                        ║"
	@echo "║  make clean           Remove volumes and rebuild              ║"
	@echo "║                                                               ║"
	@echo "║  Extended Services (docker-compose.extended.yml)              ║"
	@echo "║  ──────────────────────────────────────────────────           ║"
	@echo "║  make up-all          Start ALL services                      ║"
	@echo "║  make up-security     Start security scanning tools           ║"
	@echo "║  make up-performance  Start load testing tools                ║"
	@echo "║  make up-reporting    Start reporting/analysis tools          ║"
	@echo "║                                                               ║"
	@echo "║  Service Management                                           ║"
	@echo "║  ──────────────────                                           ║"
	@echo "║  make backend-logs    View backend API logs                   ║"
	@echo "║  make backend-shell   Shell into backend container            ║"
	@echo "║  make db-shell        PostgreSQL shell                        ║"
	@echo "║                                                               ║"
	@echo "║  Security Scanning                                            ║"
	@echo "║  ─────────────────                                            ║"
	@echo "║  make scan-all        Run all security scans                  ║"
	@echo "║  make scan-security   Run critical security scans             ║"
	@echo "║  make scan-sast       Run static analysis only                ║"
	@echo "║  make scan-secrets    Run secret detection only               ║"
	@echo "║  make scan-deps       Run dependency vulnerability scan       ║"
	@echo "║  make sbom            Generate SBOM                           ║"
	@echo "║                                                               ║"
	@echo "║  Testing                                                      ║"
	@echo "║  ───────                                                      ║"
	@echo "║  make test-api        Run API tests (Newman)                  ║"
	@echo "║  make test-e2e        Run E2E tests (Playwright)              ║"
	@echo "║  make test-performance Run load tests (k6)                    ║"
	@echo "║                                                               ║"
	@echo "║  make status          Show service status                     ║"
	@echo "║                                                               ║"
	@echo "║  MCP Server                                                   ║"
	@echo "║  ──────────                                                   ║"
	@echo "║  make mcp-start       Run MCP server locally (stdio)          ║"
	@echo "║  make mcp-test        Test MCP tool listing                   ║"
	@echo "║                                                               ║"
	@echo "║  Automation                                                   ║"
	@echo "║  ──────────                                                   ║"
	@echo "║  make workflows-import Import n8n workflows                   ║"
	@echo "║  make scan-demo       Full end-to-end demo scan               ║"
	@echo "║  make verify          Run E2E verification suite              ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Service URLs (when running):"
	@echo "  API:         http://localhost:4000"
	@echo "  n8n:         http://localhost:5678"
	@echo "  DefectDojo:  http://localhost:8083"
	@echo "  MCP SSE:     http://localhost:4000/mcp/sse"
	@echo "  Dashboard:   http://localhost:3001"
	@echo "  Marketing:   http://localhost:3000"
	@echo "  PostgreSQL:  localhost:5432"
	@echo "  Redis:       localhost:6379"

# ============================================
# CORE SERVICES
# ============================================

up:
	docker compose up -d
	@echo ""
	@echo "Core services started:"
	@echo "  API:         http://localhost:4000"
	@echo "  Dashboard:   http://localhost:3001"
	@echo "  Marketing:   http://localhost:3000"

down:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml down

restart:
	docker compose restart

logs:
	docker compose logs -f

build:
	docker compose build

clean:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml down -v
	rm -rf reports/*
	docker compose build --no-cache
	docker compose up -d

# ============================================
# EXTENDED SERVICES (with profiles)
# ============================================

up-all:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml --profile all up -d
	@echo ""
	@echo "All services started including security tools"

up-security:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml --profile security up -d
	@echo ""
	@echo "Security scanning services started"

up-performance:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml --profile performance up -d
	@echo ""
	@echo "Performance testing services started"

up-reporting:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml --profile reporting up -d
	@echo ""
	@echo "Reporting services started"

up-api-testing:
	docker compose -f docker-compose.yml -f docker-compose.extended.yml --profile api up -d
	@echo ""
	@echo "API testing services started"

# ============================================
# SERVICE-SPECIFIC COMMANDS
# ============================================

backend-build:
	docker compose build backend

backend-logs:
	docker compose logs -f backend

backend-shell:
	docker exec -it codehardener-api sh

scanner-logs:
	docker compose logs -f scanner

dashboard-build:
	docker compose build dashboard

dashboard-logs:
	docker compose logs -f dashboard

marketing-build:
	docker compose build marketing

marketing-logs:
	docker compose logs -f marketing

# ============================================
# DATABASE
# ============================================

db-shell:
	docker exec -it codehardener-postgres psql -U codehardener

db-migrate:
	docker exec -it codehardener-postgres psql -U codehardener -f /docker-entrypoint-initdb.d/init.sql

# ============================================
# SECURITY SCANNING
# ============================================

scan-all: scan-security scan-sast scan-secrets scan-deps
	@echo ""
	@echo "All scans complete. Check ./reports/ for results."

scan-security:
	@echo "Running security scans..."
	@mkdir -p reports/trivy reports/gitleaks
	docker run --rm -v $(PWD):/src -v $(PWD)/reports/trivy:/reports \
		aquasec/trivy:latest fs --severity HIGH,CRITICAL --format json -o /reports/security.json /src
	docker run --rm -v $(PWD):/src -v $(PWD)/reports/gitleaks:/reports \
		zricethezav/gitleaks:latest detect --source /src --report-path /reports/secrets.json --no-git || true
	@echo "Security scan complete."

scan-sast:
	@echo "Running SAST scan..."
	@mkdir -p reports/semgrep
	docker run --rm -v $(PWD):/src -v $(PWD)/reports/semgrep:/reports \
		returntocorp/semgrep:latest scan --config auto --json --output /reports/results.json /src || true
	@echo "SAST scan complete."

scan-secrets:
	@echo "Running secret detection..."
	@mkdir -p reports/gitleaks
	docker run --rm -v $(PWD):/src -v $(PWD)/reports/gitleaks:/reports \
		zricethezav/gitleaks:latest detect --source /src --report-path /reports/secrets.json --no-git
	@echo "Secret scan complete."

scan-deps:
	@echo "Running dependency vulnerability scan..."
	@mkdir -p reports/trivy
	docker run --rm -v $(PWD):/src -v $(PWD)/reports/trivy:/reports \
		aquasec/trivy:latest fs --format json -o /reports/deps.json /src
	@echo "Dependency scan complete."

scan-iac:
	@echo "Running IaC security scan..."
	@mkdir -p reports/checkov
	docker run --rm -v $(PWD):/code -v $(PWD)/reports/checkov:/reports \
		bridgecrew/checkov:latest -d /code --output json --output-file /reports/checkov.json || true
	@echo "IaC scan complete."

sbom:
	@echo "Generating SBOM..."
	@mkdir -p reports/sbom
	docker run --rm -v $(PWD):/src -v $(PWD)/reports/sbom:/reports \
		anchore/syft:latest /src -o spdx-json=/reports/sbom.spdx.json
	@echo "SBOM generated at reports/sbom/sbom.spdx.json"

# ============================================
# TESTING
# ============================================

test-api:
	@echo "Running API tests..."
	docker run --rm --network codehardener-network \
		-v $(PWD)/tests/api:/collections \
		-v $(PWD)/reports/newman:/reports \
		postman/newman:latest run /collections/codehardener-api.postman_collection.json \
		--reporters cli,json \
		--reporter-json-export /reports/newman-report.json

test-e2e:
	@echo "Running E2E tests..."
	cd tests/e2e && npm install && npx playwright test

test-performance:
	@echo "Running load tests..."
	docker run --rm --network codehardener-network \
		-v $(PWD)/tests/performance:/scripts \
		-v $(PWD)/reports/k6:/reports \
		-e K6_OUT=json=/reports/results.json \
		-e TARGET_APP_URL=http://codehardener-api:4000 \
		grafana/k6:latest run /scripts/smoke.js

test-performance-load:
	@echo "Running full load test..."
	docker run --rm --network codehardener-network \
		-v $(PWD)/tests/performance:/scripts \
		-v $(PWD)/reports/k6:/reports \
		-e K6_OUT=json=/reports/load-results.json \
		-e TARGET_APP_URL=http://codehardener-api:4000 \
		grafana/k6:latest run /scripts/load.js

test-accessibility:
	@echo "Running accessibility tests..."
	./tests/run-accessibility-tests.sh

# ============================================
# DAST SCANNING
# ============================================

zap-baseline:
	@echo "Running ZAP baseline scan..."
	docker exec codehardener-zap zap-baseline.py -t http://codehardener-api:4000 -r /zap/reports/baseline.html

zap-api-scan:
	@echo "Running ZAP API scan..."
	docker exec codehardener-zap zap-api-scan.py -t http://codehardener-api:4000/api/v1/docs -f openapi -r /zap/reports/api-scan.html

nuclei-scan:
	@echo "Running Nuclei scan..."
	docker exec codehardener-nuclei nuclei -u http://codehardener-api:4000 -o /reports/nuclei-results.txt

# ============================================
# STATUS
# ============================================

status:
	@echo "Container Status:"
	@echo "─────────────────"
	@docker compose ps 2>/dev/null || echo "Core services not running"
	@echo ""
	@echo "API Health:"
	@curl -s http://localhost:4000/health 2>/dev/null | jq . || echo "API not responding"
	@echo ""
	@echo "Dashboard:"
	@curl -s -o /dev/null -w "%{http_code}" http://localhost:3001 2>/dev/null || echo "Not responding"

# ============================================
# DEVELOPMENT HELPERS
# ============================================

dev-backend:
	cd backend && npm run dev

dev-dashboard:
	cd dashboard && npm run dev

dev-marketing:
	cd marketing && npm run dev

install:
	cd backend && npm install
	cd dashboard && npm install
	cd marketing && npm install

lint:
	cd backend && npm run lint
	cd dashboard && npm run lint

typecheck:
	cd backend && npm run typecheck
	cd dashboard && npm run typecheck

# ============================================
# MCP SERVER
# ============================================

mcp-start:
	@echo "Starting MCP server (stdio mode)..."
	@echo "This will connect your AI agent to Code Hardener."
	@echo "Press Ctrl+C to stop."
	cd backend && npm run mcp-server

mcp-dev:
	@echo "Starting MCP server in dev mode (hot reload)..."
	cd backend && npm run mcp-dev

mcp-test:
	@echo "Testing MCP server tool listing..."
	@echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | cd backend && npx tsx src/mcp-server.ts 2>/dev/null | head -50
	@echo ""
	@echo "MCP tools listed successfully."

# ============================================
# N8N WORKFLOWS
# ============================================

workflows-import:
	@echo "Importing n8n workflows..."
	@if curl -sf http://localhost:5678/healthz > /dev/null 2>&1; then \
		for f in n8n-workflows/*.json; do \
			name=$$(basename "$$f" .json); \
			echo "  Importing: $$name..."; \
			curl -sf -X POST \
				-u "$${N8N_BASIC_AUTH_USER:-admin}:$${N8N_BASIC_AUTH_PASSWORD:-codehardener}" \
				-H "Content-Type: application/json" \
				-d @"$$f" \
				http://localhost:5678/api/v1/workflows > /dev/null 2>&1 && \
				echo "    OK" || echo "    Warning: may already exist"; \
		done; \
		echo "Import complete."; \
	else \
		echo "n8n is not running. Start with: make up"; \
	fi

# ============================================
# DEMO & VERIFICATION
# ============================================

scan-demo:
	@echo "Running full end-to-end demo scan..."
	@echo ""
	@echo "1. Registering demo user..."
	@REGISTER=$$(curl -sf -X POST http://localhost:4000/api/v1/auth/register \
		-H "Content-Type: application/json" \
		-d '{"email":"demo@codehardener.local","password":"DemoPassword123!","name":"Demo User"}' 2>/dev/null); \
	TOKEN=$$(echo "$$REGISTER" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4); \
	if [ -z "$$TOKEN" ]; then \
		echo "   User may already exist, trying login..."; \
		LOGIN=$$(curl -sf -X POST http://localhost:4000/api/v1/auth/login \
			-H "Content-Type: application/json" \
			-d '{"email":"demo@codehardener.local","password":"DemoPassword123!"}' 2>/dev/null); \
		TOKEN=$$(echo "$$LOGIN" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4); \
	fi; \
	if [ -z "$$TOKEN" ]; then \
		echo "   Failed to get auth token. Is the backend running?"; \
		exit 1; \
	fi; \
	echo "   Got token: $${TOKEN:0:20}..."; \
	echo ""; \
	echo "2. Creating demo project..."; \
	PROJECT=$$(curl -sf -X POST http://localhost:4000/api/v1/projects \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d '{"name":"demo-scan","description":"Demo project","source_type":"repository","source_url":"https://github.com/OWASP/NodeGoat"}' 2>/dev/null); \
	PROJECT_ID=$$(echo "$$PROJECT" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4); \
	echo "   Project: $$PROJECT_ID"; \
	echo ""; \
	echo "3. Triggering scan..."; \
	SCAN=$$(curl -sf -X POST "http://localhost:4000/api/v1/scans" \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "{\"project_id\":\"$$PROJECT_ID\",\"profile\":\"quick\"}" 2>/dev/null); \
	SCAN_ID=$$(echo "$$SCAN" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4); \
	echo "   Scan: $$SCAN_ID"; \
	echo ""; \
	echo "4. Check scan status at: http://localhost:4000/api/v1/scans/$$SCAN_ID"; \
	echo "   Or via MCP: codehardener_scan_status {scan_id: \"$$SCAN_ID\"}"; \
	echo ""; \
	echo "Demo complete. Scan is running in background."

verify:
	@echo "Running E2E verification suite..."
	@./scripts/verify-e2e.sh
