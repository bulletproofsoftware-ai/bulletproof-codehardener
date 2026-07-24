# Code Hardener BRD Appendix: Local Docker MVP Implementation

## Research Agent Enhancement - December 2025

This appendix extends the main PRD-BRD with specific implementation details for the Local Docker MVP deployment.

---

## MVP Scope Definition

### What IS in MVP Scope

| Feature | Description | Priority |
|---------|-------------|----------|
| **Core Scanning** | Trivy, Gitleaks, Bandit integration | P0 |
| **REST API** | All v1 endpoints for scan, findings, attestation | P0 |
| **Authentication** | Email/password, JWT tokens | P0 |
| **Marketing Site** | Homepage, Features, Pricing, Docs, Auth pages | P0 |
| **Dashboard** | Overview, Projects, Scans, Findings, Settings | P0 |
| **Security Score** | 0-1000 calculation algorithm | P0 |
| **Plain-Language** | CVE/CWE translation for top 50 vulnerabilities | P0 |
| **Badges** | SVG badge generation with score | P1 |
| **Basic Attestation** | JSON attestation documents (no Sigstore in MVP) | P1 |

### What is NOT in MVP Scope

| Feature | Reason | Future Phase |
|---------|--------|--------------|
| Sigstore integration | Complex, requires external services | Phase 2 |
| MCP Server | Requires separate npm package | Phase 2 |
| Claude Code Skill | Requires skill publishing | Phase 2 |
| SSO/SAML | Enterprise feature | Phase 3 |
| Self-hosted Helm charts | Enterprise feature | Phase 3 |
| All 27 security tools | Start with core 5 | Phase 2-3 |
| GitHub OAuth | MVP uses email/password only | Phase 2 |
| Team management | Individual users only in MVP | Phase 2 |
| Policy-as-code (OPA) | Advanced feature | Phase 2 |
| Auto-fix generation | Requires AI integration | Phase 2 |

---

## Technology Stack (MVP)

### Container Architecture

```
docker-compose.yml
├── backend-api (Port 4000)
│   ├── Node.js 20 LTS
│   ├── TypeScript 5.x
│   ├── Express.js 4.x
│   ├── PostgreSQL client (pg)
│   ├── JWT authentication (jsonwebtoken)
│   ├── Zod validation
│   └── Security scanners (mounted volumes)
│
├── marketing-site (Port 3000)
│   ├── React 18
│   ├── Vite
│   ├── Tailwind CSS 3.4
│   ├── React Router 6
│   └── Framer Motion (animations)
│
├── dashboard (Port 3001)
│   ├── React 18
│   ├── Vite
│   ├── Tailwind CSS 3.4
│   ├── React Router 6
│   ├── TanStack Query (data fetching)
│   ├── Recharts (visualizations)
│   └── Lucide React (icons)
│
└── postgres (Port 5432)
    ├── PostgreSQL 16
    └── Persistent volume
```

### Security Scanner Integration (MVP)

| Scanner | Version | Purpose | Integration Method |
|---------|---------|---------|-------------------|
| **Trivy** | 0.48+ | Container/SCA/Filesystem | CLI subprocess |
| **Gitleaks** | 8.29+ | Secrets detection | CLI subprocess |
| **Bandit** | 1.7+ | Python SAST | CLI subprocess |
| **ESLint Security** | Latest | JS/TS SAST | Node module |
| **Checkov** | 3.0+ | IaC scanning | CLI subprocess |

### Database Schema (Core Tables)

```sql
-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Projects
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    repository_url VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scans
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending', -- pending, running, completed, failed
    scan_type VARCHAR(50) DEFAULT 'standard', -- quick, standard, comprehensive
    score INTEGER, -- 0-1000
    risk_level VARCHAR(20), -- excellent, good, medium, high, critical
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low, info
    title VARCHAR(500) NOT NULL,
    title_simple VARCHAR(500),
    description TEXT,
    description_simple TEXT,
    cwe VARCHAR(20),
    cve VARCHAR(50),
    file_path VARCHAR(500),
    line_number INTEGER,
    scanner VARCHAR(100),
    fix_available BOOLEAN DEFAULT FALSE,
    fix_description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Attestations
CREATE TABLE attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    content JSONB NOT NULL,
    badge_url VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- API Keys
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    prefix VARCHAR(20) NOT NULL, -- vs_live_ or vs_test_
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_projects_user_id ON projects(user_id);
CREATE INDEX idx_scans_project_id ON scans(project_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
```

---

## API Contract Specification

### Authentication Endpoints

```yaml
POST /api/v1/auth/register:
  request:
    email: string (required)
    password: string (required, min 8 chars)
    name: string (optional)
  response:
    user: { id, email, name }
    token: string (JWT)

POST /api/v1/auth/login:
  request:
    email: string (required)
    password: string (required)
  response:
    user: { id, email, name }
    token: string (JWT)

POST /api/v1/auth/refresh:
  headers:
    Authorization: Bearer <token>
  response:
    token: string (new JWT)

POST /api/v1/auth/forgot-password:
  request:
    email: string
  response:
    message: "Reset email sent"

POST /api/v1/auth/reset-password:
  request:
    token: string
    password: string
  response:
    message: "Password updated"
```

### Project Endpoints

```yaml
GET /api/v1/projects:
  headers:
    Authorization: Bearer <token>
  response:
    projects: [{ id, name, description, repository_url, created_at }]
    total: number

POST /api/v1/projects:
  headers:
    Authorization: Bearer <token>
  request:
    name: string (required)
    description: string (optional)
    repository_url: string (optional)
  response:
    project: { id, name, description, repository_url, created_at }

GET /api/v1/projects/:id:
  response:
    project: { id, name, description, repository_url, created_at }
    stats: { total_scans, last_scan, average_score }

PUT /api/v1/projects/:id:
  request:
    name: string
    description: string
    repository_url: string
  response:
    project: { id, name, description, repository_url, updated_at }

DELETE /api/v1/projects/:id:
  response:
    message: "Project deleted"
```

### Scan Endpoints

```yaml
POST /api/v1/scans:
  headers:
    Authorization: Bearer <token>
  request:
    project_id: uuid (required)
    scan_type: "quick" | "standard" | "comprehensive" (default: standard)
    source: "upload" | "github" | "url"
    file: File (if source=upload)
    github_repo: string (if source=github)
    url: string (if source=url)
  response:
    scan: { id, status: "pending", project_id }

GET /api/v1/scans/:id:
  response:
    scan:
      id: uuid
      project_id: uuid
      status: "pending" | "running" | "completed" | "failed"
      scan_type: string
      score: number (0-1000)
      risk_level: "excellent" | "good" | "medium" | "high" | "critical"
      findings_summary:
        critical: number
        high: number
        medium: number
        low: number
        info: number
      started_at: timestamp
      completed_at: timestamp

GET /api/v1/scans:
  query:
    project_id: uuid (optional)
    status: string (optional)
    limit: number (default 20)
    offset: number (default 0)
  response:
    scans: [...]
    total: number
```

### Finding Endpoints

```yaml
GET /api/v1/findings:
  query:
    scan_id: uuid (optional)
    project_id: uuid (optional)
    severity: string (optional)
    limit: number (default 50)
    offset: number (default 0)
  response:
    findings:
      - id: uuid
        scan_id: uuid
        severity: string
        title: string
        title_simple: string
        description: string
        description_simple: string
        cwe: string
        file_path: string
        line_number: number
        fix_available: boolean
        fix_description: string
    total: number

GET /api/v1/findings/:id:
  response:
    finding: { ... full finding details }
    related_findings: [ ... findings with same CWE ]
```

### Attestation Endpoints

```yaml
POST /api/v1/attestations:
  request:
    scan_id: uuid (required)
  response:
    attestation:
      id: uuid
      scan_id: uuid
      content: { ... attestation JSON }
      badge_url: string
      created_at: timestamp

GET /api/v1/attestations/:id:
  response:
    attestation: { ... }

GET /api/v1/attestations:
  query:
    scan_id: uuid (optional)
    project_id: uuid (optional)
  response:
    attestations: [...]
```

### Badge Endpoints

```yaml
GET /api/v1/badges/:project_id.svg:
  query:
    style: "default" | "flat" | "detailed"
  response:
    Content-Type: image/svg+xml
    body: <svg>...</svg>

GET /api/v1/badges/:scan_id.svg:
  response:
    Content-Type: image/svg+xml
    body: <svg>...</svg>
```

### Health Endpoints

```yaml
GET /health:
  response:
    status: "healthy"
    timestamp: timestamp

GET /ready:
  response:
    status: "ready"
    database: "connected"
    scanners: { trivy: true, gitleaks: true, bandit: true }
```

---

## Security Score Algorithm (MVP)

```typescript
interface ScoreCalculation {
  baseScore: 1000;

  deductions: {
    critical: -200; // per finding, max -600
    high: -50;      // per finding, max -200
    medium: -10;    // per finding, max -100
    low: -2;        // per finding, max -50
    secrets_detected: -100; // flat deduction
    outdated_deps: -25;     // if >1 year old
  };

  bonuses: {
    all_deps_current: +25;
    no_secrets: +25;
  };

  riskLevel: {
    900-1000: 'excellent';
    700-899: 'good';
    500-699: 'medium';
    300-499: 'high';
    0-299: 'critical';
  };
}
```

---

## Plain-Language Translation (MVP - Top 50)

```typescript
const translationMap: Record<string, { title: string; description: string; fix: string }> = {
  'CWE-89': {
    title: 'Database query vulnerability',
    description: 'Your database query takes user input directly. An attacker could manipulate this to steal or delete data.',
    fix: 'Use parameterized queries instead of string concatenation.'
  },
  'CWE-79': {
    title: 'Script injection vulnerability',
    description: 'User input is displayed without sanitization. Attackers could inject malicious scripts.',
    fix: 'Sanitize all user input before displaying it.'
  },
  'CWE-798': {
    title: 'Hardcoded password or API key',
    description: 'A password or API key is visible in your code. Anyone with access can see it.',
    fix: 'Move to environment variables or a secrets manager.'
  },
  // ... 47 more translations
};
```

---

## Docker Compose Configuration

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: codehardener
      POSTGRES_USER: codehardener
      POSTGRES_PASSWORD: ${DB_PASSWORD:-devpassword}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backend/init.sql:/docker-entrypoint-initdb.d/init.sql
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U codehardener"]
      interval: 5s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      NODE_ENV: production
      DATABASE_URL: postgres://codehardener:${DB_PASSWORD:-devpassword}@postgres:5432/codehardener
      JWT_SECRET: ${JWT_SECRET:-devsecret}
      PORT: 4000
    volumes:
      - scan_uploads:/app/uploads
      - ./scanners:/app/scanners:ro
    ports:
      - "4000:4000"
    depends_on:
      postgres:
        condition: service_healthy

  marketing:
    build:
      context: ./marketing
      dockerfile: Dockerfile
    environment:
      VITE_API_URL: http://localhost:4000
    ports:
      - "3000:3000"
    depends_on:
      - backend

  dashboard:
    build:
      context: ./dashboard
      dockerfile: Dockerfile
    environment:
      VITE_API_URL: http://localhost:4000
    ports:
      - "3001:3001"
    depends_on:
      - backend

volumes:
  postgres_data:
  scan_uploads:
```

---

## Directory Structure

```
/codehardener
├── docker-compose.yml
├── .env.example
├── README.md
│
├── /backend
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   ├── init.sql
│   └── /src
│       ├── index.ts
│       ├── /config
│       │   └── database.ts
│       ├── /routes
│       │   ├── auth.ts
│       │   ├── projects.ts
│       │   ├── scans.ts
│       │   ├── findings.ts
│       │   ├── attestations.ts
│       │   └── badges.ts
│       ├── /services
│       │   ├── scanner.ts
│       │   ├── score.ts
│       │   └── translation.ts
│       ├── /middleware
│       │   ├── auth.ts
│       │   └── validation.ts
│       └── /types
│           └── index.ts
│
├── /marketing
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── /src
│       ├── main.tsx
│       ├── App.tsx
│       ├── /pages
│       │   ├── Home.tsx
│       │   ├── Features.tsx
│       │   ├── Pricing.tsx
│       │   ├── Docs.tsx
│       │   ├── Login.tsx
│       │   └── Signup.tsx
│       ├── /components
│       │   ├── Header.tsx
│       │   ├── Footer.tsx
│       │   ├── Hero.tsx
│       │   └── ...
│       └── /styles
│           └── globals.css
│
├── /dashboard
│   ├── Dockerfile
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── /src
│       ├── main.tsx
│       ├── App.tsx
│       ├── /pages
│       │   ├── Overview.tsx
│       │   ├── Projects.tsx
│       │   ├── Scans.tsx
│       │   ├── Findings.tsx
│       │   └── Settings.tsx
│       ├── /components
│       │   ├── Sidebar.tsx
│       │   ├── Header.tsx
│       │   ├── ScoreCard.tsx
│       │   └── ...
│       └── /styles
│           └── globals.css
│
└── /scanners (mounted read-only)
    ├── trivy
    ├── gitleaks
    └── bandit
```

---

## MVP Success Criteria

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| API response time | <500ms p95 | Monitoring |
| Scan completion | <60s for small projects | Timing |
| UI load time | <2s initial | Lighthouse |
| Uptime | 99% local | Manual |
| Zero critical security issues | 0 | Self-scan |
| All pages accessible | 100% | Link crawler |
| WCAG AA compliance | All pages | Pa11y |

---

## Document History

- Created: 2025-12-23
- Author: Research Agent Enhancement
- Status: COMPLETE
