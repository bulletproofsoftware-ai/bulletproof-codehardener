# Code Hardener Test Suite

Comprehensive test suite for the Code Hardener security assurance platform.

## Test Categories

| Category | Directory | Tools | Purpose |
|----------|-----------|-------|---------|
| E2E Tests | `e2e/` | Playwright | Full user workflow testing |
| API Tests | `api/` | Newman | API endpoint validation |
| Security Tests | `security/` | Semgrep, Trivy, Gitleaks, OWASP ZAP | Security scanning |
| Performance Tests | `performance/` | K6, Artillery | Load and stress testing |
| Accessibility Tests | `accessibility/` | Pa11y | WCAG 2.1 AA compliance |
| Visual Regression | `visual/` | BackstopJS | UI consistency testing |

## Prerequisites

The testing-security-stack Docker environment must be running:

```bash
cd ~/Code/testing-security-stack
make up
```

## Quick Start

### Run All Tests
```bash
cd ~/Code/codehardener/tests
./run-all-tests.sh
```

### Run Specific Categories
```bash
# Security scans
./run-security-tests.sh

# E2E tests
./run-e2e-tests.sh

# API tests
./run-api-tests.sh

# Performance tests
./run-performance-tests.sh

# Accessibility tests
./run-accessibility-tests.sh

# Visual regression
./run-visual-tests.sh
```

## Test Execution Commands

### Security Testing

```bash
# Static Analysis (SAST) - Semgrep
docker exec semgrep semgrep --config auto --json \
  --output /reports/codehardener-semgrep.json \
  ~/Code/codehardener

# Container/Dependency Scanning - Trivy
docker exec trivy trivy fs --format json \
  -o /reports/codehardener-trivy.json \
  ~/Code/codehardener

# Secret Detection - Gitleaks
docker exec gitleaks gitleaks detect \
  --source ~/Code/codehardener \
  --report-path /reports/codehardener-secrets.json

# Dynamic Analysis (DAST) - OWASP ZAP
# Marketing Site
docker exec owasp-zap zap-baseline.py \
  -t http://localhost:3000 \
  -r /zap/reports/marketing-baseline.html

# Dashboard
docker exec owasp-zap zap-baseline.py \
  -t http://localhost:3001 \
  -r /zap/reports/dashboard-baseline.html

# Backend API
docker exec owasp-zap zap-api-scan.py \
  -t http://localhost:4000/api/v1 \
  -f openapi \
  -r /zap/reports/api-scan.html
```

### E2E Testing

```bash
# Run all E2E tests
docker exec playwright npx playwright test \
  --config=/tests/e2e/playwright.config.ts \
  --reporter=allure-playwright

# Run specific test file
docker exec playwright npx playwright test \
  /tests/e2e/auth.spec.ts

# Run with headed browser (debugging)
docker exec playwright npx playwright test \
  --headed --project=chromium
```

### API Testing

```bash
# Run full API collection
docker exec newman newman run \
  /tests/api/codehardener-api.postman_collection.json \
  -e /tests/api/local.postman_environment.json \
  --reporters cli,json,allure \
  --reporter-json-export /results/api-tests.json

# Run auth tests only
docker exec newman newman run \
  /tests/api/codehardener-api.postman_collection.json \
  --folder "Auth" \
  -e /tests/api/local.postman_environment.json
```

### Performance Testing

```bash
# Smoke test (quick sanity)
docker exec k6 k6 run /tests/performance/smoke.js

# Load test (normal traffic)
docker exec k6 k6 run /tests/performance/load.js

# Stress test (find limits)
docker exec k6 k6 run /tests/performance/stress.js

# Spike test (sudden surge)
docker exec artillery artillery run /tests/performance/spike.yml
```

### Accessibility Testing

```bash
# Marketing site WCAG 2.1 AA
docker exec pa11y pa11y http://localhost:3000 \
  --standard WCAG2AA \
  --reporter json > /reports/marketing-a11y.json

# Dashboard pages
docker exec pa11y pa11y-ci \
  --config /tests/accessibility/.pa11yci.json

# Generate HTML report
docker exec pa11y pa11y http://localhost:3000 \
  --reporter html > /reports/accessibility.html
```

### Visual Regression Testing

```bash
# Create reference screenshots
docker exec backstopjs backstop reference \
  --config=/tests/visual/backstop.config.js

# Run comparison
docker exec backstopjs backstop test \
  --config=/tests/visual/backstop.config.js

# Approve changes (if intentional)
docker exec backstopjs backstop approve \
  --config=/tests/visual/backstop.config.js
```

## Quality Gates

### Security Thresholds

| Severity | Threshold | Action |
|----------|-----------|--------|
| Critical | 0 | Block deployment |
| High | 0 | Block deployment |
| Medium | < 5 | Review required |
| Low | Unlimited | Track in backlog |

### Performance Thresholds

| Metric | Target | Fail |
|--------|--------|------|
| Response Time (p95) | < 200ms | > 500ms |
| Error Rate | 0% | > 1% |
| Throughput | > 500 req/s | < 100 req/s |

### Accessibility Thresholds

| Standard | Target | Fail |
|----------|--------|------|
| WCAG 2.1 AA | 0 errors | Any error |
| WCAG 2.1 AAA | < 5 warnings | > 10 warnings |

## Report Locations

All test reports are generated in:
- `~/Code/testing-security-stack/reports/`
- Allure Dashboard: http://localhost:5252

## CI/CD Integration

See `.github/workflows/test.yml` for GitHub Actions integration.

## Troubleshooting

### Services Not Running
```bash
cd ~/Code/testing-security-stack
docker-compose ps
docker-compose up -d
```

### Test Failures
```bash
# View specific service logs
docker-compose logs -f playwright
docker-compose logs -f newman
```

### Reset Test Data
```bash
# Reset test database
docker exec backend-api npm run db:reset:test
```
