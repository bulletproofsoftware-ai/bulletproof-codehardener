# Code Hardener Implementation Plan

**Created**: 2025-12-26
**Target MVP**: 6 weeks
**Focus**: Working end-to-end with 3-5 core scanners

---

## Current State Summary

| Component | Status | % Complete |
|-----------|--------|------------|
| Database Schema | Done | 100% |
| Marketing Frontend | Done | 95% |
| Dashboard Frontend | Done | 90% |
| Backend API | NOT STARTED | 0% |
| Scanners | NOT STARTED | 0% |
| MCP Server | NOT STARTED | 0% |

---

## Phase 1: Backend Foundation (Days 1-5)

### Objective
Get a working Express API server with authentication and basic routes.

### Tasks

#### Day 1: Project Setup
```bash
mkdir -p backend/src/{config,db,middleware,routes,controllers,services,types,utils}
cd backend
npm init -y
```

- [ ] Create `package.json` with dependencies
- [ ] Create `tsconfig.json`
- [ ] Create `Dockerfile`
- [ ] Create `.env.example`

#### Day 2: Express Server + Health Routes
- [ ] `src/index.ts` - Entry point
- [ ] `src/app.ts` - Express app setup with middleware
- [ ] `src/config/env.ts` - Environment configuration
- [ ] `src/routes/health.routes.ts` - /health and /ready endpoints
- [ ] Test: Server starts on port 4000

#### Day 3: Database Connection
- [ ] `src/db/client.ts` - PostgreSQL connection with pg
- [ ] `src/db/schema.ts` - Drizzle ORM schema (match init.sql)
- [ ] Test: /ready returns 200 when DB connected

#### Day 4: Middleware Layer
- [ ] `src/middleware/errorHandler.ts` - Global error handling
- [ ] `src/middleware/cors.ts` - CORS configuration
- [ ] `src/middleware/rateLimiter.ts` - Rate limiting
- [ ] `src/utils/apiResponse.ts` - Standardized JSON responses

#### Day 5: Docker Integration
- [ ] Update `/docker-compose.yml` to include backend service
- [ ] Create network configuration
- [ ] Test: `docker-compose up` starts all 4 services
- [ ] Verify: Marketing -> Dashboard -> Backend -> Postgres chain works

### Deliverables
- Working Express server on port 4000
- /health and /ready endpoints functional
- Database connection verified
- Docker Compose runs full stack

---

## Phase 2: Authentication System (Days 6-10)

### Objective
Implement JWT-based authentication matching the API client expectations.

### Tasks

#### Day 6: User Service
- [ ] `src/services/auth.service.ts` - Password hashing, JWT generation
- [ ] `src/utils/jwt.ts` - JWT helper functions
- [ ] `src/utils/password.ts` - Bcrypt helpers

#### Day 7: Auth Routes
- [ ] `src/routes/auth.routes.ts`
  - POST /api/v1/auth/register
  - POST /api/v1/auth/login
  - POST /api/v1/auth/refresh
  - POST /api/v1/auth/logout
- [ ] `src/controllers/auth.controller.ts`

#### Day 8: Auth Middleware
- [ ] `src/middleware/auth.ts` - JWT verification
- [ ] Test: Protected routes reject unauthenticated requests
- [ ] Test: Token refresh works

#### Day 9: User Profile Routes
- [ ] GET /api/v1/auth/me
- [ ] PATCH /api/v1/auth/me
- [ ] POST /api/v1/auth/change-password
- [ ] DELETE /api/v1/auth/me

#### Day 10: Testing Auth
- [ ] Unit tests for auth service
- [ ] Integration tests for auth routes
- [ ] Test with dashboard login page

### Deliverables
- Users can register, login, logout
- JWT tokens work with 15m access, 7d refresh
- Dashboard login page functional

---

## Phase 3: Core API Routes (Days 11-18)

### Objective
Implement CRUD routes for all dashboard resources.

### Tasks

#### Days 11-12: Projects API
- [ ] `src/routes/projects.routes.ts`
- [ ] `src/controllers/projects.controller.ts`
- [ ] `src/services/project.service.ts`
- GET /api/v1/projects (list with pagination)
- GET /api/v1/projects/:id
- POST /api/v1/projects
- PATCH /api/v1/projects/:id
- DELETE /api/v1/projects/:id

#### Days 13-14: Scans API
- [ ] `src/routes/scans.routes.ts`
- [ ] `src/controllers/scans.controller.ts`
- [ ] `src/services/scan.service.ts`
- GET /api/v1/scans
- GET /api/v1/scans/:id
- POST /api/v1/scans (create scan - stub for now)
- POST /api/v1/scans/:id/cancel
- GET /api/v1/scans/:id/findings

#### Days 15-16: Findings API
- [ ] `src/routes/findings.routes.ts`
- [ ] `src/controllers/findings.controller.ts`
- [ ] `src/services/finding.service.ts`
- GET /api/v1/findings
- GET /api/v1/findings/:id
- PATCH /api/v1/findings/:id/status
- POST /api/v1/findings/bulk-status

#### Days 17-18: Supporting APIs
- [ ] Attestations routes (CRUD)
- [ ] Policies routes (CRUD)
- [ ] Reports routes (CRUD)
- [ ] API Keys routes (create, list, delete)
- [ ] Dashboard summary endpoint

### Deliverables
- All dashboard pages can fetch/display data
- CRUD operations work for all resources
- Dashboard is fully navigable (with mock scan data)

---

## Phase 4: Scan Queue System (Days 19-23)

### Objective
Implement async scan execution with BullMQ.

### Tasks

#### Day 19: Redis + BullMQ Setup
- [ ] Add Redis to docker-compose.yml
- [ ] `src/services/queue/scan-queue.ts` - Queue setup
- [ ] `src/services/queue/types.ts` - Job types

#### Days 20-21: Base Scanner Architecture
- [ ] `src/services/scanners/base-scanner.ts` - Abstract base class
- [ ] `src/services/scanners/types.ts` - Normalized finding format
- [ ] `src/services/scanners/registry.ts` - Scanner registry

#### Day 22: Scan Worker
- [ ] `src/services/queue/scan-worker.ts` - Job processor
- [ ] Status updates (pending -> running -> completed/failed)
- [ ] Error handling and retries

#### Day 23: Integration
- [ ] POST /api/v1/scans now queues job
- [ ] Real-time status available
- [ ] Test: Scan lifecycle works end-to-end

### Deliverables
- Scans execute asynchronously
- Status updates in real-time
- Foundation for adding scanners

---

## Phase 5: MVP Scanners (Days 24-33)

### Objective
Implement 5 core scanners for complete security coverage.

### Scanner Priority Order

| Scanner | Category | Why MVP |
|---------|----------|---------|
| Trivy | SCA/Container | Most comprehensive, covers deps + containers |
| Gitleaks | Secrets | Critical - secrets in code are #1 issue |
| OpenGrep | SAST | Semgrep alternative, multi-language |
| Checkov | IaC | Terraform/CloudFormation security |
| Nuclei | DAST | Template-based vuln scanning |

### Tasks per Scanner (2 days each)

#### Days 24-25: Trivy Scanner
- [ ] `src/services/scanners/trivy-scanner.ts`
- [ ] Docker execution: `trivy fs --format json`
- [ ] Parse JSON output to normalized findings
- [ ] Unit tests with fixture data

#### Days 26-27: Gitleaks Scanner
- [ ] `src/services/scanners/gitleaks-scanner.ts`
- [ ] Execution: `gitleaks detect --report-format json`
- [ ] Parse findings, map severity
- [ ] Unit tests

#### Days 28-29: OpenGrep Scanner
- [ ] `src/services/scanners/opengrep-scanner.ts`
- [ ] Execution: `opengrep --json`
- [ ] Multi-language support
- [ ] Unit tests

#### Days 30-31: Checkov Scanner
- [ ] `src/services/scanners/checkov-scanner.ts`
- [ ] Execution: `checkov -f --output json`
- [ ] Parse IaC findings
- [ ] Unit tests

#### Days 32-33: Nuclei Scanner
- [ ] `src/services/scanners/nuclei-scanner.ts`
- [ ] Execution: `nuclei -t templates/ -json`
- [ ] Parse vulnerability findings
- [ ] Unit tests

### Deliverables
- 5 working scanners
- Complete scan runs all 5
- Findings appear in dashboard

---

## Phase 6: Assurance Layer (Days 34-38)

### Objective
Unified abstraction with risk scoring and profiles.

### Tasks

#### Day 34: Assurance Engine Core
- [ ] `src/services/assurance/assurance-engine.ts`
- [ ] `src/services/assurance/types.ts`
- [ ] Scan orchestration (run selected scanners)

#### Day 35: Risk Scoring
- [ ] `src/services/assurance/risk-scorer.ts`
- [ ] 0-1000 score calculation
- [ ] Severity weights (critical=200, high=100, medium=50, low=10)
- [ ] Risk levels (excellent, good, moderate, poor, critical)

#### Day 36: Profiles
- [ ] `src/services/assurance/profiles.ts`
- [ ] quick: Gitleaks + Trivy (2 min)
- [ ] standard: + OpenGrep (5 min)
- [ ] comprehensive: All 5 scanners (10 min)
- [ ] security: Gitleaks + OpenGrep + Nuclei
- [ ] compliance: Trivy + Checkov

#### Days 37-38: Integration
- [ ] Scans use profiles
- [ ] Risk score calculated post-scan
- [ ] Badges endpoint returns score
- [ ] Dashboard shows accurate risk level

### Deliverables
- Scans have configurable profiles
- Risk scores calculated accurately
- Badges endpoint works

---

## Phase 7: MCP Server (Days 39-42) - OPTIONAL FOR MVP

### Objective
Claude Code integration via MCP protocol.

### Tasks

#### Day 39: MCP Server Setup
- [ ] `src/services/mcp/mcp-server.ts`
- [ ] `src/services/mcp/cli.ts` (for running standalone)

#### Day 40: Core Tools
- [ ] scan - Run security scan
- [ ] get_scan_status - Check scan progress
- [ ] list_findings - Get findings for scan
- [ ] list_profiles - Available scan profiles

#### Days 41-42: Resources and Testing
- [ ] scan://latest - Current scan resource
- [ ] profiles://list - Available profiles
- [ ] Test with Claude Code

### Deliverables
- MCP server runnable via npx
- 4+ tools functional
- Claude Code can trigger scans

---

## Success Criteria for MVP

### Must Have
- [ ] User can register and login
- [ ] User can create projects
- [ ] User can run scans with 5 scanners
- [ ] Findings appear with severity
- [ ] Risk score calculated (0-1000)
- [ ] Dashboard fully functional

### Should Have
- [ ] Scan profiles (quick/standard/comprehensive)
- [ ] Badge endpoint with score
- [ ] API keys for programmatic access

### Nice to Have
- [ ] MCP server integration
- [ ] Attestation generation
- [ ] Webhook notifications

---

## Resource Requirements

### Development
- 1 full-stack developer: 6 weeks
- Or 2 developers: 3 weeks

### Infrastructure
- PostgreSQL 16 (already spec'd)
- Redis (for BullMQ)
- Docker with security tools

### Security Tools (Binaries/Containers)
- trivy (aquasec/trivy)
- gitleaks (gitleaks/gitleaks)
- opengrep (returntocorp/semgrep fork)
- checkov (bridgecrewio/checkov)
- nuclei (projectdiscovery/nuclei)

---

## Risk Factors

| Risk | Impact | Mitigation |
|------|--------|------------|
| Scanner binary compatibility | High | Use Docker containers for all tools |
| BullMQ complexity | Medium | Start simple, add features later |
| Scope creep (all 27 scanners) | High | Strict MVP focus on 5 scanners |
| Frontend expects different API | Medium | API client already defined - follow it |

---

## Next Steps

1. Correct conductor-state.json to reflect reality
2. Create backend directory structure
3. Implement Phase 1 (Days 1-5)
4. Iterate through remaining phases
