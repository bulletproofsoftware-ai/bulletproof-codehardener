# Code Hardener: Security Assurance Platform for AI-First Developers

## Product Requirements Document / Business Requirements Document

**Version 2.0 — Permissively Licensed Edition**  
**December 2025**

*All 27 integrated tools use Apache 2.0, MIT, BSD, or MPL-2.0 licenses*  
*No AGPL, GPL, or proprietary SaaS restrictions*

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Market Opportunity](#market-opportunity)
3. [Competitive Landscape](#competitive-landscape)
4. [Integrated Tool Stack](#integrated-tool-stack)
5. [The Assurance Layer](#the-assurance-layer) ⭐ *Expanded*
6. [Platform Architecture](#platform-architecture)
7. [Attestation and Supply Chain Security](#attestation-and-supply-chain-security)
8. [Developer Experience](#developer-experience)
9. [Compliance Framework Mappings](#compliance-framework-mappings)
10. [Pricing and Monetization](#pricing-and-monetization)
11. [Implementation Roadmap](#implementation-roadmap)
12. [Risk Register](#risk-register)

---

## Executive Summary

The AI-first development movement—developers building applications through AI prompts without traditional SDLC knowledge—represents a **$3.89 billion market** growing at 32.5% CAGR. With 45% of AI-generated code containing vulnerabilities and 41% of global code now AI-generated, this developer segment lacks purpose-built security infrastructure.

Code Hardener addresses this gap by integrating 27 open-source security and testing tools—all using permissive licenses (Apache 2.0, MIT, BSD, MPL-2.0)—into a unified platform designed for developers who've never heard of OWASP. This version eliminates all licensing risks identified in the initial assessment, replacing AGPL-licensed k6 with Locust, building multi-tool SAST coverage instead of restricted Semgrep rules, and avoiding SonarQube's November 2024 license changes entirely.

### Key Platform Differentiators

- **100% SaaS-safe licensing** — No AGPL, GPL, or proprietary restrictions on any integrated tool
- **Plain-language security findings** — Translates CVEs and CWEs into human-readable explanations
- **Cryptographic attestation** — Sigstore integration provides verifiable security evidence
- **AI coding tool integration** — Native support for Cursor, GitHub Copilot, and Claude Code workflows
- **Accessible pricing** — Free tier for individuals; $19/month Pro tier undercuts competitors by 50%+
- **Zero-configuration Assurance Layer** — One prompt, one API call, or one MCP connection to secure any application

---

## Market Opportunity

### The AI-First Development Security Gap

Traditional security tools assume developers understand CVEs, CWEs, and vulnerability taxonomies. Vibe coders—a term coined by Andrej Karpathy in February 2025—describe their goals in natural language and accept AI-generated code without deep review. Y Combinator reports 25% of Winter 2025 startups have 95% AI-generated codebases.

This creates unprecedented security challenges:

- Developers lack security expertise to evaluate AI-generated code
- Speed-focused development bypasses traditional review guardrails
- No existing tool specifically addresses AI-generated code patterns
- Current solutions price out individual developers ($15,000+ minimums for enterprise tools)

### Market Size and Growth

| Metric | Value |
|--------|-------|
| AI-First Development Market (2024) | $3.89 billion |
| Projected Market (2032) | $37 billion |
| CAGR | 32.5% |
| US Developers Using AI Daily | 92% |
| AI-Generated Code (Global) | 41% of all code |
| AI Code with Vulnerabilities | 29-45% |

### Addressable Market Segments

| Segment | Size | Pain Point | Code Hardener Value |
|---------|------|------------|------------------|
| Solo AI-first developers | 10M+ | No security knowledge | Automated protection |
| AI-first startups | 50K+ | Need SOC 2 fast | Compliance evidence |
| Enterprise AI teams | 5K+ | Governance concerns | Attestation + audit trails |
| Low-code/no-code builders | 5M+ | Zero security tooling | One-click integration |

---

## Competitive Landscape

### Competitor Positioning Matrix

| Competitor | Starting Price | Target Market | AI-First Developer Ready | Key Gap |
|------------|---------------|---------------|------------------|---------|
| **Snyk** | $1,260/dev/yr | Developer-first SMB | ★★★★ | Enterprise pricing scales |
| **Veracode** | $15,000/yr | Enterprise compliance | ★ | Complex setup |
| **GitLab Ultimate** | $99/user/mo | DevSecOps teams | ★★ | Platform lock-in |
| **Socket.dev** | Free for OSS | Supply chain focus | ★★★ | Limited to deps |
| **Semgrep** | $40/contrib/mo | Developer teams | ★★ | Rule license issues |
| **GitHub GHAS** | $49/commit/mo | GitHub-native teams | ★★★ | GitHub lock-in |
| **Checkmarx** | $59,000/yr | Large enterprise | ★ | High cost, complex UX |

### Critical Market Gaps

**No competitor specifically serves AI-assisted development workflows.** The gaps include:

1. **Security for non-technical developers** — Most tools assume security knowledge
2. **AI code security scanning** — Only emerging solutions, not mainstream
3. **Real-time IDE feedback** — Not optimized for Cursor/Copilot/Bolt workflows
4. **Affordable individual pricing** — Free tiers too limited; paid tiers assume team budgets
5. **Low-code/no-code integration** — Zero presence in Replit, Lovable, Bolt.new ecosystems
6. **One-click auto-remediation in all tiers** — Usually locked to enterprise

---

## Integrated Tool Stack

All 27 tools use permissive licenses (Apache 2.0, MIT, BSD, or MPL-2.0). No AGPL, GPL, or proprietary SaaS restrictions exist in this stack.

### Security Scanning Tools

| Tool | License | Category | Purpose |
|------|---------|----------|---------|
| Bandit | Apache 2.0 ✓ | Python SAST | Security vulnerability detection for Python code |
| Gosec | Apache 2.0 ✓ | Go SAST | Security rules and analysis for Go applications |
| ESLint Security | Apache 2.0 ✓ | JS/TS SAST | Security plugins for JavaScript/TypeScript |
| PMD | BSD ✓ | Multi-lang Analysis | Code quality and security for Java, JS, Apex, 16+ langs |
| Opengrep | LGPL-2.1 | Pattern Matching | Custom rule engine for multi-language patterns |
| OWASP ZAP | Apache 2.0 ✓ | DAST | Dynamic web application security testing |
| Trivy | Apache 2.0 ✓ | Container/SCA | Container, filesystem, and dependency scanning |
| Nuclei | MIT ✓ | Vuln Scanner | 8000+ templates for CVEs and misconfigurations |
| Gitleaks CLI | MIT ✓ | Secrets Detection | 100+ detectors for hardcoded secrets |
| detect-secrets | Apache 2.0 ✓ | Secrets Detection | Baseline workflow for enterprise secret management |
| Checkov | Apache 2.0 ✓ | IaC Security | Terraform, Kubernetes, Dockerfile scanning |

### Performance and API Testing

| Tool | License | Category | Purpose |
|------|---------|----------|---------|
| Locust | MIT ✓ | Load Testing | Distributed Python-based load testing (replaces k6) |
| Gatling | Apache 2.0 ✓ | Load Testing | High-performance HTTP, WS, gRPC testing |
| Artillery Core | MPL-2.0 ✓ | Load Testing | Cloud-scale testing (Azure modules excluded) |
| Newman | Apache 2.0 ✓ | API Testing | Postman collection runner for CI/CD |
| WireMock | Apache 2.0 ✓ | API Mocking | HTTP service stubbing and simulation |
| Pact | MIT ✓ | Contract Testing | Consumer-driven contract verification |
| RESTler | MIT ✓ | API Fuzzing | Microsoft's stateful REST API fuzzer |

### Browser, Visual, and Accessibility Testing

| Tool | License | Category | Purpose |
|------|---------|----------|---------|
| Playwright | Apache 2.0 ✓ | E2E Testing | Cross-browser testing for Chromium, Firefox, WebKit |
| BackstopJS | MIT ✓ | Visual Regression | Screenshot comparison for UI changes |
| Pa11y | MIT ✓ | Accessibility | WCAG 2.1 AA and Section 508 validation |

### Supply Chain, Runtime, and Reporting

| Tool | License | Category | Purpose |
|------|---------|----------|---------|
| Syft | Apache 2.0 ✓ | SBOM Generation | SPDX and CycloneDX format generation |
| Grype | Apache 2.0 ✓ | SBOM Scanning | Vulnerability scanning for SBOMs |
| Falco | Apache 2.0 ✓ | Runtime Security | Cloud-native runtime behavior monitoring |
| Toxiproxy | MIT ✓ | Chaos Engineering | Network condition simulation and resilience testing |
| DefectDojo | BSD 3-Clause ✓ | Vuln Management | Finding aggregation and deduplication |
| Allure | Apache 2.0 ✓ | Test Reporting | Rich visualizations and trend tracking |
| Flyway Community | Apache 2.0 ✓ | DB Migrations | Database migration testing and version control |

### Attestation and Policy Infrastructure

| Tool | License | Category | Purpose |
|------|---------|----------|---------|
| Cosign/Sigstore | Apache 2.0 ✓ | Signing | Keyless cryptographic signing of attestations |
| in-toto | Apache 2.0 ✓ | Attestation | Supply chain attestation framework |
| Open Policy Agent | Apache 2.0 ✓ | Policy-as-Code | Quality gates and policy enforcement |

### Tools Excluded (Licensing Risk)

| Original Tool | License Issue | Replacement |
|---------------|---------------|-------------|
| k6 | AGPL-3.0 (source disclosure required) | Locust (MIT) |
| Semgrep Rules | Proprietary license prohibits SaaS | Custom rules + Bandit/Gosec/ESLint |
| SonarQube | SSALv1 (Nov 2024) prohibits competing SaaS | PMD + language linters |
| TruffleHog | AGPL-3.0 | Gitleaks CLI (MIT) |
| Brakeman | Non-commercial license | No Ruby SAST (gap documented) |

---

## The Assurance Layer

The Assurance Layer is the core abstraction that separates complex security infrastructure from end users. It provides a **single interface**—accessible via prompt, MCP server, skill, or REST API—that any developer can use regardless of technical expertise or platform.

### Design Philosophy

> **"Security should feel like a feature, not a checkpoint."**

The Assurance Layer is built on four principles:

1. **Zero Configuration Required** — Works out of the box with sensible defaults
2. **Meet Developers Where They Are** — Integrates with any workflow, any platform
3. **Progressive Disclosure** — Simple by default, powerful when needed
4. **Evidence Over Trust** — Cryptographic proof, not just claims

### What the Assurance Layer Does

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ASSURANCE LAYER                                   │
│                                                                      │
│   INPUT                    PROCESS                    OUTPUT         │
│   ─────                    ───────                    ──────         │
│   • Code repository   →   • 27 security tools   →   • Pass/Fail     │
│   • ZIP file              • Parallel execution       • Risk score    │
│   • GitHub URL            • AI interpretation        • Plain findings│
│   • Prompt description    • Policy evaluation        • Attestation   │
│                                                      • Badge URL     │
│                                                      • Fix guidance  │
└─────────────────────────────────────────────────────────────────────┘
```

The Assurance Layer accepts code in any form and returns:

| Output | Description | Who Uses It |
|--------|-------------|-------------|
| **Pass/Fail Status** | Binary deployment decision | CI/CD pipelines |
| **Risk Score (0-1000)** | Credit score-style metric | Developers, dashboards |
| **Plain-Language Findings** | Human-readable issues | Non-technical developers |
| **Signed Attestation** | Cryptographic proof of scan | Compliance, customers |
| **Verifiable Badge** | Embeddable trust signal | README, marketing |
| **Remediation Guidance** | AI-generated fix suggestions | Anyone fixing issues |

---

### Integration Methods

The Assurance Layer is accessible through **five integration methods**, each designed for different user types and platforms:

#### 1. Natural Language Prompt (Simplest)

For developers using AI coding assistants (Cursor, Claude Code, GitHub Copilot Chat, ChatGPT):

```
User: "Check my code for security issues"

Code Hardener AI: I'll scan your project now.

📊 Security Scan Complete
━━━━━━━━━━━━━━━━━━━━━━━
Score: 720/1000 (Medium Risk)

Found 3 issues:

🔴 Critical: Your database query on line 47 could let 
   attackers read all user data. 
   → Fix: Use parameterized queries instead of string concatenation
   
🟡 Medium: The API key in config.js should be in environment 
   variables, not source code.
   → Fix: Move to .env file and add config.js to .gitignore
   
🟡 Medium: express-session is using default settings which 
   aren't secure for production.
   → Fix: Add secure:true and httpOnly:true to session config

Want me to fix these automatically?
```

**How it works:**
- User invokes via natural language in any AI assistant
- Code Hardener MCP server or skill processes the request
- Results returned in conversational format
- One-click fixes available

**Supported platforms:**
- Cursor (native MCP support)
- Claude Desktop / Claude Code (MCP support)
- VS Code with Continue extension
- Any AI assistant with tool/function calling

---

#### 2. MCP Server (Model Context Protocol)

For AI-native development environments that support MCP:

**Installation (30 seconds):**

```json
// Add to claude_desktop_config.json or cursor settings
{
  "mcpServers": {
    "codehardener": {
      "command": "npx",
      "args": ["-y", "@codehardener/mcp-server"],
      "env": {
        "VIBESHIELD_API_KEY": "your-api-key"
      }
    }
  }
}
```

**Available Tools:**

| Tool | Description | Example |
|------|-------------|---------|
| `scan_project` | Full security scan | "Scan this project for vulnerabilities" |
| `scan_file` | Single file analysis | "Check this file for security issues" |
| `scan_diff` | PR/commit diff scan | "Review security of my changes" |
| `get_score` | Risk score only | "What's my security score?" |
| `get_attestation` | Generate signed proof | "Create a security attestation" |
| `fix_issue` | Auto-remediate finding | "Fix the SQL injection on line 47" |
| `explain_finding` | Plain-language explanation | "Explain this vulnerability simply" |

**MCP Tool Schemas:**

```typescript
// scan_project tool
{
  name: "scan_project",
  description: "Perform comprehensive security scan on project",
  inputSchema: {
    type: "object",
    properties: {
      path: { 
        type: "string", 
        description: "Project path or GitHub URL" 
      },
      scan_type: { 
        type: "string", 
        enum: ["quick", "standard", "comprehensive"],
        default: "standard"
      },
      languages: {
        type: "array",
        items: { type: "string" },
        description: "Override auto-detection"
      }
    },
    required: ["path"]
  }
}

// Response format
{
  status: "completed",
  score: 720,
  risk_level: "medium",
  findings: [
    {
      id: "VS-2024-001",
      severity: "critical",
      title: "SQL Injection vulnerability",
      description_technical: "CWE-89: Improper Neutralization...",
      description_simple: "Your database query could let attackers read all user data",
      location: { file: "api/users.js", line: 47 },
      fix_available: true,
      fix_description: "Use parameterized queries instead of string concatenation"
    }
  ],
  attestation_url: "https://codehardener.dev/att/abc123",
  badge_url: "https://codehardener.dev/badge/abc123.svg"
}
```

---

#### 3. Claude Code Skill

For Claude Code users who want security scanning integrated into their workflow:

**Installation:**

```bash
# Add Code Hardener skill to Claude Code
claude skill add codehardener/security-scan
```

**Usage in Claude Code:**

```bash
# Natural language
claude "scan this project for security issues"

# Direct skill invocation
claude --skill codehardener/security-scan

# Scan and auto-fix
claude "fix all security issues in this project"

# Generate attestation for deployment
claude "create security attestation for production deploy"
```

**Skill Configuration (optional):**

```yaml
# .claude/codehardener.yaml
scan:
  type: comprehensive
  fail_on: critical
  languages: auto
  
policies:
  max_critical: 0
  max_high: 5
  require_attestation: true
  
notifications:
  slack_webhook: ${SLACK_WEBHOOK}
  on: [critical, high]
```

---

#### 4. REST API (Universal)

For any platform, any language, any workflow:

**Authentication:**

```bash
# API key in header
curl -H "Authorization: Bearer vs_live_abc123" \
     https://api.codehardener.dev/v1/scan
```

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/scan` | POST | Submit code for scanning |
| `/v1/scan/{id}` | GET | Get scan results |
| `/v1/scan/{id}/attestation` | GET | Download signed attestation |
| `/v1/score/{repo}` | GET | Quick score check |
| `/v1/badge/{repo}` | GET | SVG badge for README |
| `/v1/fix` | POST | Get AI-generated fixes |

**Submit Scan:**

```bash
# From GitHub URL
curl -X POST https://api.codehardener.dev/v1/scan \
  -H "Authorization: Bearer vs_live_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "github",
    "repo": "username/my-app",
    "branch": "main",
    "scan_type": "standard"
  }'

# From ZIP upload
curl -X POST https://api.codehardener.dev/v1/scan \
  -H "Authorization: Bearer vs_live_abc123" \
  -F "file=@my-project.zip" \
  -F "scan_type=standard"

# Response
{
  "scan_id": "scn_abc123xyz",
  "status": "queued",
  "estimated_time": 45,
  "results_url": "https://api.codehardener.dev/v1/scan/scn_abc123xyz"
}
```

**Get Results:**

```bash
curl https://api.codehardener.dev/v1/scan/scn_abc123xyz \
  -H "Authorization: Bearer vs_live_abc123"

# Response
{
  "scan_id": "scn_abc123xyz",
  "status": "completed",
  "completed_at": "2025-12-23T14:30:00Z",
  "score": 720,
  "risk_level": "medium",
  "summary": {
    "critical": 1,
    "high": 2,
    "medium": 5,
    "low": 12,
    "info": 34
  },
  "findings": [...],
  "attestation": {
    "id": "att_def456",
    "url": "https://codehardener.dev/att/def456",
    "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/abc..."
  },
  "badge": {
    "svg": "https://codehardener.dev/badge/scn_abc123xyz.svg",
    "markdown": "[![Security Score](https://codehardener.dev/badge/scn_abc123xyz.svg)](https://codehardener.dev/report/scn_abc123xyz)"
  }
}
```

---

#### 5. Platform-Native Integrations

Pre-built integrations for low-code/no-code platforms:

##### Replit

```python
# replit.nix - add to your Replit project
{ pkgs }: {
  deps = [
    pkgs.codehardener-cli
  ];
}

# .replit - add security check to run
run = "codehardener scan . && python main.py"
```

Or use the Replit Extension (one-click install):
1. Open Extensions panel
2. Search "Code Hardener"
3. Click Install
4. Security tab appears in sidebar

##### Lovable

```yaml
# lovable.yaml - project configuration
integrations:
  codehardener:
    enabled: true
    scan_on: [push, deploy]
    block_deploy_on: critical
```

Or configure in Lovable dashboard:
1. Project Settings → Integrations
2. Enable Code Hardener
3. Connect GitHub (if not connected)
4. Security scans run automatically

##### Bolt.new

Security scanning is automatic for all Bolt.new projects. Access results:
1. Click "Security" tab in project panel
2. View findings with one-click fixes
3. Generate attestation before sharing

##### v0.dev

```typescript
// Add to your v0 project's package.json scripts
{
  "scripts": {
    "security": "npx @codehardener/cli scan",
    "deploy": "npm run security && npm run build"
  }
}
```

##### GitHub (without GHAS)

```yaml
# .github/workflows/codehardener.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codehardener/action@v1
        with:
          api-key: ${{ secrets.VIBESHIELD_API_KEY }}
          fail-on: critical
```

##### GitLab

```yaml
# .gitlab-ci.yml
security_scan:
  image: codehardener/scanner:latest
  script:
    - codehardener scan . --format gitlab
  artifacts:
    reports:
      sast: codehardener-report.json
```

##### Vercel

```json
// vercel.json
{
  "buildCommand": "npx @codehardener/cli scan --fail-on critical && npm run build"
}
```

##### Netlify

```toml
# netlify.toml
[build]
  command = "npx @codehardener/cli scan --fail-on critical && npm run build"
```

---

### Assurance Layer Features in Detail

#### Feature 1: Intelligent Language Detection

The Assurance Layer automatically detects programming languages and selects appropriate scanners:

```
Detected: Python (67%), JavaScript (28%), Dockerfile (5%)

Scanners activated:
├── Bandit → Python security
├── ESLint Security → JavaScript security
├── Trivy → Dependency vulnerabilities
├── Gitleaks → Secrets detection
├── Checkov → Dockerfile security
└── OWASP ZAP → Web application (if URL provided)
```

No configuration required. Override with:

```json
{
  "languages": ["python", "javascript"],
  "scanners": {
    "enable": ["bandit", "trivy"],
    "disable": ["eslint"]
  }
}
```

#### Feature 2: Plain-Language Finding Translation

Every finding is translated from security jargon to human-readable explanations:

| Technical | Plain Language |
|-----------|----------------|
| CWE-89: SQL Injection | Your database query could let attackers read, modify, or delete any data |
| CWE-79: XSS | User input is displayed without sanitization, letting attackers inject malicious scripts |
| CWE-798: Hardcoded Credentials | Password or API key is visible in your code—anyone with access can see it |
| CWE-918: SSRF | Your app can be tricked into making requests to internal systems |
| CWE-22: Path Traversal | Attackers can access files outside the intended directory |

Example finding output:

```json
{
  "id": "VS-2024-089-001",
  "cwe": "CWE-89",
  "severity": "critical",
  
  "title_technical": "SQL Injection via string concatenation",
  "title_simple": "Database query vulnerability",
  
  "description_technical": "User-controlled input is concatenated directly into SQL query string without parameterization, allowing arbitrary SQL execution.",
  "description_simple": "Your database query on line 47 takes user input and puts it directly into the query. An attacker could type special characters that change the query—letting them read all user data, delete records, or even take over your database.",
  
  "impact_technical": "Confidentiality, Integrity, and Availability impact. CVSS 9.8.",
  "impact_simple": "Someone could steal all your user data, including passwords and personal information.",
  
  "fix_technical": "Use parameterized queries or prepared statements.",
  "fix_simple": "Instead of building the query as a string, use the '?' placeholder and pass the user input separately. Here's exactly what to change:",
  
  "fix_code": {
    "before": "db.query(`SELECT * FROM users WHERE id = ${userId}`)",
    "after": "db.query('SELECT * FROM users WHERE id = ?', [userId])"
  },
  
  "learn_more": "https://codehardener.dev/learn/sql-injection"
}
```

#### Feature 3: One-Click Auto-Fix

For supported finding types, the Assurance Layer can automatically generate and apply fixes:

**Supported Auto-Fix Categories:**

| Category | Fix Type | Confidence |
|----------|----------|------------|
| SQL Injection | Parameterized queries | High |
| XSS | Output encoding | High |
| Hardcoded secrets | Environment variable extraction | High |
| Insecure dependencies | Version upgrade | High |
| Missing security headers | Header injection | High |
| Insecure cookies | Flag addition | High |
| Path traversal | Path sanitization | Medium |
| CORS misconfiguration | Policy correction | Medium |

**Auto-Fix Flow:**

```
User: "Fix the SQL injection issue"

Code Hardener: I'll fix the SQL injection on line 47 of api/users.js.

Changes:
━━━━━━━━

- const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);
+ const result = db.query('SELECT * FROM users WHERE id = ?', [userId]);

This change:
• Uses a parameterized query instead of string concatenation
• The database driver will safely escape the userId value
• Prevents any SQL injection attacks on this query

Apply this fix? [Yes] [No] [Show me more options]
```

#### Feature 4: Risk Score Algorithm

The 0-1000 risk score provides an instant, understandable security assessment:

**Score Calculation:**

```
Base Score = 1000 (perfect)

Deductions:
├── Critical findings: -200 each (max -600)
├── High findings: -50 each (max -200)
├── Medium findings: -10 each (max -100)
├── Low findings: -2 each (max -50)
├── No SBOM: -25
├── Secrets detected: -100
├── Outdated dependencies (>1yr): -25
└── No security headers: -25

Bonuses:
├── All dependencies up to date: +25
├── Security headers present: +25
├── CSP configured: +25
└── HTTPS enforced: +25

Final Score = max(0, min(1000, calculated_score))
```

**Score Interpretation:**

| Score | Risk Level | Badge Color | Deployment Recommendation |
|-------|------------|-------------|---------------------------|
| 900-1000 | Excellent | 🟢 Green | Deploy with confidence |
| 700-899 | Good | 🟢 Green | Deploy, address findings soon |
| 500-699 | Medium | 🟡 Yellow | Review before deploying |
| 300-499 | High | 🟠 Orange | Fix high/critical before deploy |
| 0-299 | Critical | 🔴 Red | Do not deploy |

#### Feature 5: Cryptographic Attestation

Every scan generates a cryptographically signed attestation using Sigstore:

**Attestation Contents:**

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{
    "name": "myapp",
    "digest": {
      "sha256": "a]b2c3d4e5f6..."
    }
  }],
  "predicateType": "https://codehardener.dev/scan/v1",
  "predicate": {
    "scan_id": "scn_abc123xyz",
    "timestamp": "2025-12-23T14:30:00Z",
    "score": 720,
    "risk_level": "medium",
    "findings_summary": {
      "critical": 0,
      "high": 2,
      "medium": 5
    },
    "tools_executed": [
      "bandit@1.7.5",
      "trivy@0.48.0",
      "gitleaks@8.29.0"
    ],
    "policy_passed": true,
    "slsa_level": "L2"
  }
}
```

**Verification:**

```bash
# Anyone can verify the attestation
cosign verify-attestation \
  --type https://codehardener.dev/scan/v1 \
  --certificate-identity-regexp '.*@codehardener.dev' \
  --certificate-oidc-issuer https://accounts.codehardener.dev \
  myapp@sha256:abc123...

# Or use the Code Hardener verifier
npx @codehardener/verify att_def456
```

**What This Proves:**

1. The scan actually happened (timestamp in Rekor transparency log)
2. The results weren't tampered with (cryptographic signature)
3. Code Hardener performed the scan (certificate identity)
4. The specific code version was scanned (subject digest)

#### Feature 6: Embeddable Trust Badges

Display your security score anywhere:

**Markdown (for README):**

```markdown
[![Security Score](https://codehardener.dev/badge/username/repo.svg)](https://codehardener.dev/report/username/repo)
```

**HTML:**

```html
<a href="https://codehardener.dev/report/username/repo">
  <img src="https://codehardener.dev/badge/username/repo.svg" alt="Security Score">
</a>
```

**Badge Variations:**

| Badge | URL Suffix | Use Case |
|-------|------------|----------|
| Score only | `/badge/{repo}.svg` | Minimal |
| Score + grade | `/badge/{repo}.svg?style=grade` | README |
| Full details | `/badge/{repo}.svg?style=detailed` | Documentation |
| Compact | `/badge/{repo}.svg?style=compact` | Tight spaces |

#### Feature 7: Policy-as-Code

Define custom security policies that the Assurance Layer enforces:

**Simple Policy (YAML):**

```yaml
# .codehardener/policy.yaml
name: Production Deployment Policy

gates:
  deploy:
    max_critical: 0
    max_high: 0
    max_medium: 10
    require_attestation: true
    require_sbom: true
    
  staging:
    max_critical: 0
    max_high: 5
    
  development:
    # No restrictions
    
exceptions:
  - finding: "VS-2024-XXX"
    reason: "False positive - input is validated upstream"
    expires: "2025-03-01"
    approved_by: "security@company.com"
```

**Advanced Policy (Rego/OPA):**

```rego
# .codehardener/policy.rego
package codehardener

default allow = false

allow {
    input.findings.critical == 0
    input.findings.high <= max_high
    input.attestation.valid == true
}

max_high = 0 { input.environment == "production" }
max_high = 5 { input.environment == "staging" }
max_high = 999 { input.environment == "development" }

# Require human approval for any high findings in prod
require_approval {
    input.environment == "production"
    input.findings.high > 0
}
```

#### Feature 8: Webhook Notifications

Get notified when scans complete or policies fail:

**Webhook Configuration:**

```json
{
  "webhooks": [
    {
      "url": "https://hooks.slack.com/services/XXX",
      "events": ["scan.completed", "policy.failed"],
      "filter": {
        "min_severity": "high"
      }
    },
    {
      "url": "https://your-app.com/api/security-webhook",
      "events": ["*"],
      "secret": "whsec_abc123"
    }
  ]
}
```

**Webhook Payload:**

```json
{
  "event": "scan.completed",
  "timestamp": "2025-12-23T14:30:00Z",
  "scan": {
    "id": "scn_abc123xyz",
    "repo": "username/repo",
    "branch": "main",
    "commit": "abc123",
    "score": 720,
    "risk_level": "medium",
    "findings": {
      "critical": 0,
      "high": 2,
      "medium": 5
    },
    "policy_passed": true,
    "report_url": "https://codehardener.dev/report/scn_abc123xyz"
  }
}
```

---

### Assurance Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ASSURANCE LAYER                                    │
│                                                                              │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Prompt    │ │    MCP      │ │   Skill     │ │   REST      │           │
│  │  Interface  │ │   Server    │ │  Interface  │ │    API      │           │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘           │
│         │               │               │               │                   │
│         └───────────────┴───────────────┴───────────────┘                   │
│                                    │                                         │
│                         ┌──────────▼──────────┐                             │
│                         │   Request Router    │                             │
│                         │  • Auth validation  │                             │
│                         │  • Rate limiting    │                             │
│                         │  • Request parsing  │                             │
│                         └──────────┬──────────┘                             │
│                                    │                                         │
│                         ┌──────────▼──────────┐                             │
│                         │  Language Detector  │                             │
│                         │  • File analysis    │                             │
│                         │  • Scanner selection│                             │
│                         └──────────┬──────────┘                             │
│                                    │                                         │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         │                          │                          │             │
│  ┌──────▼──────┐           ┌──────▼──────┐           ┌──────▼──────┐       │
│  │   Scanner   │           │   Scanner   │           │   Scanner   │       │
│  │  Executor   │           │  Executor   │           │  Executor   │       │
│  │  (Bandit)   │           │  (Trivy)    │           │  (Gitleaks) │       │
│  └──────┬──────┘           └──────┬──────┘           └──────┬──────┘       │
│         │                          │                          │             │
│         └──────────────────────────┼──────────────────────────┘             │
│                                    │                                         │
│                         ┌──────────▼──────────┐                             │
│                         │  Result Aggregator  │                             │
│                         │  • Deduplication    │                             │
│                         │  • Normalization    │                             │
│                         │  • Score calc       │                             │
│                         └──────────┬──────────┘                             │
│                                    │                                         │
│                         ┌──────────▼──────────┐                             │
│                         │  Finding Translator │                             │
│                         │  • Plain language   │                             │
│                         │  • Fix generation   │                             │
│                         └──────────┬──────────┘                             │
│                                    │                                         │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         │                          │                          │             │
│  ┌──────▼──────┐           ┌──────▼──────┐           ┌──────▼──────┐       │
│  │   Policy    │           │ Attestation │           │   Badge     │       │
│  │  Evaluator  │           │  Generator  │           │  Generator  │       │
│  └─────────────┘           └──────┬──────┘           └─────────────┘       │
│                                    │                                         │
│                         ┌──────────▼──────────┐                             │
│                         │  Sigstore Signing   │                             │
│                         │  • Fulcio certs     │                             │
│                         │  • Rekor logging    │                             │
│                         └──────────┬──────────┘                             │
│                                    │                                         │
│                         ┌──────────▼──────────┐                             │
│                         │  Response Builder   │                             │
│                         │  • Format for client│                             │
│                         │  • Webhook dispatch │                             │
│                         └─────────────────────┘                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Implementation Guide for Platform Developers

For teams building integrations with the Assurance Layer:

#### SDK Installation

```bash
# Node.js
npm install @codehardener/sdk

# Python
pip install codehardener

# Go
go get github.com/codehardener/sdk-go

# CLI (any platform)
curl -fsSL https://codehardener.dev/install.sh | sh
```

#### Quick Start (Node.js)

```javascript
import { Code Hardener } from '@codehardener/sdk';

const vs = new Code Hardener({ apiKey: process.env.VIBESHIELD_API_KEY });

// Scan a GitHub repo
const scan = await vs.scan({
  source: 'github',
  repo: 'username/my-app'
});

console.log(`Score: ${scan.score}`);
console.log(`Risk: ${scan.riskLevel}`);
console.log(`Critical issues: ${scan.findings.critical}`);

// Get plain-language findings
for (const finding of scan.findings.items) {
  console.log(`- ${finding.titleSimple}`);
  console.log(`  ${finding.descriptionSimple}`);
}

// Generate attestation
const attestation = await vs.attest(scan.id);
console.log(`Attestation: ${attestation.url}`);
```

#### Quick Start (Python)

```python
from codehardener import Code Hardener
import os

vs = Code Hardener(api_key=os.environ['VIBESHIELD_API_KEY'])

# Scan local directory
scan = vs.scan(path='./my-project')

print(f"Score: {scan.score}")
print(f"Risk: {scan.risk_level}")

# Get findings with plain language
for finding in scan.findings:
    print(f"- {finding.title_simple}")
    print(f"  Fix: {finding.fix_simple}")

# Auto-fix critical issues
if scan.findings.critical > 0:
    fixes = vs.fix(scan.id, severity='critical')
    for fix in fixes:
        print(f"Fixed: {fix.file}:{fix.line}")
```

#### Building an MCP Server Integration

For platforms wanting to add Code Hardener as an MCP tool:

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { Code Hardener } from "@codehardener/sdk";

const server = new Server({
  name: "codehardener",
  version: "1.0.0"
}, {
  capabilities: { tools: {} }
});

const vs = new Code Hardener({ apiKey: process.env.VIBESHIELD_API_KEY });

server.setRequestHandler("tools/list", async () => ({
  tools: [
    {
      name: "scan_project",
      description: "Scan project for security vulnerabilities",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "Project path" }
        },
        required: ["path"]
      }
    }
  ]
}));

server.setRequestHandler("tools/call", async (request) => {
  if (request.params.name === "scan_project") {
    const scan = await vs.scan({ path: request.params.arguments.path });
    return {
      content: [{
        type: "text",
        text: formatScanResults(scan)
      }]
    };
  }
});

function formatScanResults(scan) {
  return `
Security Scan Complete
━━━━━━━━━━━━━━━━━━━━━
Score: ${scan.score}/1000 (${scan.riskLevel})

${scan.findings.items.map(f => 
  `${severityEmoji(f.severity)} ${f.titleSimple}\n   ${f.descriptionSimple}`
).join('\n\n')}

Attestation: ${scan.attestation?.url || 'Not generated'}
  `.trim();
}
```

---

## Platform Architecture

### Three-Tier Assurance Model

The platform separates infrastructure from end users through a three-tier architecture:

#### Consumer Tier (Evidence & Attestation)

End users and their customers receive:
- Cryptographically signed attestation reports
- Security scorecards  
- Compliance badges
- SBOM artifacts

No infrastructure knowledge required—just verifiable evidence of security testing.

#### Orchestration Tier (Pipeline & Policy)

- Quality gates enforce pass/fail thresholds via OPA policy-as-code
- Sigstore signs all attestations
- DefectDojo and Allure aggregate evidence
- API boundary exposes only scan submission and results—never infrastructure access

#### Execution Tier (Isolated Scanning)

All 27 security tools run in isolated containers with gVisor sandboxing:
- Ephemeral containers per scan
- Read-only filesystems
- Network isolation
- Automatic cleanup

### Container Isolation Strategy

| Scan Type | Risk Level | Isolation Method | Startup | Use Case |
|-----------|------------|------------------|---------|----------|
| Quick (secrets, lint) | Low | Docker + seccomp | 50ms | Fast feedback |
| Code analysis (SAST) | Medium | gVisor sandbox | 100ms | Default |
| Dynamic (DAST) | High | Firecracker MicroVM | 150ms | Network scans |
| Untrusted execution | Critical | Kata Containers | 300ms | Customer code |

### Deployment Models

| Model | Best For | Delivery Method |
|-------|----------|-----------------|
| SaaS Multi-tenant | SMBs, startups, individuals | Fully hosted service |
| On-Premises | Enterprises, regulated industries | Helm chart, K8s operator |
| Hybrid | Large enterprises with data sensitivity | Local agents + cloud dashboard |
| Docker Compose | Evaluation, small teams | Single-host deployment |

---

## Attestation and Supply Chain Security

### SLSA Implementation

| Level | Requirements | Code Hardener Implementation |
|-------|--------------|---------------------------|
| L1 | Provenance exists showing how artifact was built | Auto-generate provenance for every scan |
| L2 | Provenance digitally signed; builds on hosted platform | Sigstore integration for keyless signing |
| L3 | Isolated build environment; secrets inaccessible | gVisor sandbox isolation for all scans |

### Sigstore Integration Flow

1. Customer triggers scan via CI/CD integration or API
2. Code Hardener generates scan attestation in in-toto Statement v1 format
3. Fulcio issues short-lived certificate via OIDC identity
4. Cosign signs attestation with ephemeral key
5. Signature recorded in Rekor transparency log (immutable)
6. Customer receives verifiable badge with Rekor entry link

### NIST SSDF Alignment

| SSDF Practice | Description | Platform Feature |
|---------------|-------------|------------------|
| PO.3 | Implement supporting toolchains | 27 integrated security tools |
| PS.1 | Protect code from unauthorized access | Gitleaks + detect-secrets |
| PS.2 | Provide secure build environments | Isolated scan containers |
| PW.5 | Verify secure coding practices | Multi-language SAST |
| PW.7-9 | Review, test, and fix vulnerabilities | Comprehensive scanning + remediation |
| RV.1 | Identify and confirm vulnerabilities | CVE detection with Trivy, Nuclei, Grype |

---

## Developer Experience

### UX Design Principles

1. **Make security invisible** — Background scanning surfaces results only when actionable
2. **Translate to human language** — "This query could let attackers read all user emails" vs "SQL Injection (CWE-89)"
3. **Prioritize ruthlessly** — Show only critical issues first; hide low-priority behind "Show more"
4. **Progressive disclosure** — Summary → Details → Raw data (drill-down on demand)

### Security Score Model

| Score Range | Visual | Label | Recommended Action |
|-------------|--------|-------|-------------------|
| 900-1000 | 🟢 | Excellent | Deploy with confidence |
| 700-899 | 🟢 | Good | Deploy, address findings soon |
| 500-699 | 🟡 | Medium | Review before deploying |
| 300-499 | 🟠 | High Risk | Fix high/critical before deploy |
| 0-299 | 🔴 | Critical | Do not deploy |

### AI Coding Tool Integrations

| Tool | Type | Integration Pattern |
|------|------|---------------------|
| Cursor | AI-native IDE | Real-time inline warnings, chat-based review |
| GitHub Copilot | IDE extension | Pre-suggestion security filtering |
| Claude Code | CLI agent | Piped review: `git diff \| codehardener review` |
| v0.dev / Bolt.new | Full-stack builders | Pre-deploy security gates |
| Windsurf / Codeium | AI assistants | Inline security hints |

### Onboarding Target: Time-to-First-Value Under 2 Minutes

| Step | Duration | Experience |
|------|----------|------------|
| 1. Connect | 30 seconds | One-click GitHub OAuth |
| 2. First scan | 60 seconds | Progress: "Scanning 47 files..." |
| 3. First value | 30 seconds | Show single most important finding with one-click fix |
| 4. Optional tour | Self-paced | Contextual suggestions |

---

## Compliance Framework Mappings

### SOC 2 Trust Service Criteria

| Control | Category | Evidence from Code Hardener |
|---------|----------|--------------------------|
| CC3.1 | Risk Assessment | Vulnerability risk scores, threat assessments |
| CC4.1 | Monitoring | Continuous scan dashboards, trend reports |
| CC5.1 | Control Activities | Security tool configs, automated remediation |
| CC6.1 | Logical Access | Authentication scanning, credential checks |
| CC7.2 | Vulnerability Monitoring | SAST/DAST findings, severity trends |
| CC8.1 | Change Management | Pre-deployment gate results, code review logs |
| CC9.1 | Risk Mitigation | Remediation tracking, closure rates |

### ISO 27001:2022 Annex A

| Control | Title | Platform Feature |
|---------|-------|------------------|
| A.8.8 | Technical Vulnerability Management | SAST/DAST findings, patch recommendations |
| A.8.26 | Application Security Requirements | Secure coding verification |
| A.8.28 | Secure Coding | Multi-language code analysis |
| A.8.29 | Security Testing | Comprehensive test results |

### GDPR Considerations

| Requirement | Implementation |
|-------------|----------------|
| Data Minimization (Art. 5) | Scan only necessary code; don't persist raw source |
| Right to Erasure (Art. 17) | Auto-delete scan results on request |
| Processing Records (Art. 30) | Maintain audit trail of all processing |
| Cross-Border Transfers | EU data residency option; SCCs for transfers |

### FedRAMP Path

Recommended approach: **FedRAMP LI-SaaS** (Low Impact SaaS)
- 37+ controls (subset of full Low baseline)
- Faster authorization than full FedRAMP
- Suitable for security tools not handling sensitive federal data
- Timeline: 12-18 months; Cost: $500K-$1M

---

## Pricing and Monetization

### Tier Structure

| Tier | Price | Target | Key Features |
|------|-------|--------|--------------|
| **Free** | $0 | Solo AI-first developers | 3 private projects, 200 scans/mo, basic SAST+SCA+secrets, IDE integration |
| **Pro** | $19/month | Freelancers, hobbyists | 10 projects, unlimited scans, all languages, fix recommendations |
| **Team** | $39/dev/month | Small teams (2-25) | Unlimited projects, team dashboard, SSO, Slack, custom policies |
| **Enterprise** | Custom | 25+ developers | Self-hosted, FedRAMP, SLA support, data residency |

### Competitive Price Comparison

| Metric | Code Hardener | Snyk | Semgrep | GitHub GHAS |
|--------|------------|------|---------|-------------|
| Free tier projects | 3 private | 1 | 10 contributors | 0 |
| Individual developer | $19/mo | $25+/mo | $40/mo | $49/mo |
| Team (10 devs, annual) | $3,900 | $12,600 | $4,800 | $5,880 |
| Enterprise minimum | ~$30K | $50K+ | Custom | Volume |

### Revenue Projections

| Year | Focus | ARR Target |
|------|-------|------------|
| 1-2 | PLG foundation, free user acquisition | $500K - $2M |
| 3-4 | Layer enterprise sales on PLG | $5M - $15M |
| 5+ | Enterprise majority, multi-product | $30M+ |

### Key Metrics Targets

| Metric | Target | Industry Benchmark |
|--------|--------|-------------------|
| Net Revenue Retention | 110-130% | 120% (best-in-class) |
| Free-to-paid conversion | 5-8% | 3.3% (cybersecurity avg) |
| Expansion revenue | 30-40% | 25-35% (typical SaaS) |

---

## Implementation Roadmap

### Phase 1: Foundation (Months 1-6)

**Core Platform:**
1. Kubernetes-based scan orchestration with KEDA autoscaling
2. gVisor sandbox isolation for all scan operations
3. PostgreSQL with row-level security for multi-tenancy
4. Basic web dashboard and REST API

**Initial Tool Integrations (permissive licenses only):**
- Trivy (container/filesystem) — Apache 2.0
- Gitleaks CLI (secrets) — MIT
- OWASP ZAP (DAST) — Apache 2.0
- Nuclei (vulnerability scanning) — MIT
- Checkov (IaC) — Apache 2.0
- Syft + Grype (SBOM) — Apache 2.0
- Bandit + Gosec + ESLint security (SAST) — Apache 2.0/MIT

**Assurance Layer v1:**
- REST API with all core endpoints
- MCP server for Claude/Cursor
- Plain-language finding translation
- Basic security score

**Developer Experience:**
- GitHub OAuth integration
- VS Code extension
- Security score dashboard

### Phase 2: Expansion (Months 7-12)

**Additional Tools:**
- Locust (load testing) — MIT
- Playwright (E2E) — Apache 2.0
- OPA (policy) — Apache 2.0
- PMD (Java/multi-lang) — BSD
- DefectDojo integration — BSD

**Assurance Layer v2:**
- Claude Code skill
- Auto-fix for top 10 vulnerability types
- Policy-as-code (YAML + Rego)
- Webhook notifications

**Attestation Layer:**
- Sigstore integration (Cosign, Fulcio, Rekor)
- SLSA L2 provenance
- in-toto attestation format
- Verifiable badges

**Platform Integrations:**
- Replit extension
- Lovable integration
- Bolt.new native support
- Vercel/Netlify build plugins

### Phase 3: Enterprise (Months 13-18)

**Enterprise Features:**
- SSO/SAML integration
- Self-hosted deployment (Helm chart)
- Comprehensive audit logging
- Data residency options (US, EU)
- Custom integrations API

**Compliance:**
- SOC 2 Type I certification
- ISO 27001 gap analysis
- FedRAMP LI-SaaS preparation

**Assurance Layer v3:**
- AI-assisted vulnerability triage
- Automated remediation PRs
- SBOM management dashboard
- Compliance report generation

### Phase 4: Scale (Months 19-24)

**Platform Maturity:**
- SOC 2 Type II certification
- FedRAMP LI-SaaS authorization
- Kubernetes operator for on-premises
- Multi-region deployment (NA, EU, APAC)

**Product Expansion:**
- API security testing suite
- Runtime security monitoring (Falco)
- Developer security training (gamified)
- Marketplace for custom rules

---

## Risk Register

### Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Scanner container escape | Low | Critical | gVisor/Firecracker isolation; security audits; bug bounty |
| Cross-tenant data leakage | Low | Critical | Namespace isolation; row-level security; pen testing |
| Tool update breaks compatibility | Medium | Medium | Version pinning; canary rollouts; automated rollback |
| Multi-tool SAST integration complexity | Medium | Medium | Unified output normalization; phased rollout |

### Business Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Snyk moves downmarket | Medium | High | Establish position early; differentiate on UX |
| Cursor/Replit build native security | Medium | High | Deep integration partnerships; attestation value |
| Low free-to-paid conversion | Medium | Medium | A/B test triggers; optimize onboarding |
| Enterprise sales cycle too long | Medium | Medium | PLG foundation provides base revenue |

### Compliance Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| GDPR data residency violation | Low | High | EU deployment option; data classification; DPAs |
| SOC 2 audit failure | Low | High | Early auditor engagement; continuous compliance |
| FedRAMP authorization delay | Medium | Medium | Start with LI-SaaS; use authorized infrastructure |

### Licensing Risks — ELIMINATED

All licensing risks from v1.0 have been eliminated:
- k6 (AGPL) → Locust (MIT)
- Semgrep rules → Custom rules + permissive SAST tools
- SonarQube (SSALv1) → PMD + language linters
- TruffleHog (AGPL) → Gitleaks CLI (MIT)
- Artillery Azure → Core only (MPL-2.0)

**Zero high-risk tools remain in the stack.**

---

## Key Success Factors

1. **First-mover advantage in AI-first developer security** — No competitor targets AI-assisted development with accessible pricing

2. **Plain-language UX removes security jargon barriers** — Translates CVEs and CWEs into human-readable explanations

3. **Verifiable attestations provide compliance evidence** — Sigstore creates cryptographically signed proof

4. **100% permissive licensing enables flexible deployment** — SaaS, on-premises, and hybrid without legal complexity

5. **Accessible pricing captures developers before enterprise procurement** — Free tier and $19/mo Pro undercut competitors by 50%+

6. **AI coding tool integrations meet developers where they work** — Native support for Cursor, Copilot, Claude Code

7. **Assurance Layer abstracts all complexity** — One prompt, one API call, or one MCP connection to secure any application

---

## Conclusion

Code Hardener addresses a critical gap in the security tools market: purpose-built protection for AI-first developers who lack traditional security expertise. By combining 27 permissively-licensed open-source tools into a single platform with developer-friendly UX, cryptographic attestation, and accessible pricing, the platform can capture the rapidly growing AI-first development market before established competitors adapt.

The **Assurance Layer** is the core innovation—a single abstraction that makes enterprise-grade security accessible through natural language prompts, MCP servers, skills, or REST APIs. Non-technical developers on any platform—from Cursor to Replit to Lovable—can secure their applications without understanding CVEs, CWEs, or security tooling.

The 24-month roadmap delivers an MVP within 6 months, enterprise features by month 18, and compliance certifications by month 24—positioning Code Hardener as the default security layer for AI-assisted development.

---

*Document Version: 2.0*  
*Last Updated: December 2025*  
*Classification: Confidential*
