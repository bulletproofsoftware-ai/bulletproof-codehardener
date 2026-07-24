# Code Hardener Prompt System - Business Requirements Document

**Document Version:** 1.0
**Date:** January 11, 2026
**Status:** Draft
**Author:** Code Hardener Development Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Business Objectives](#2-business-objectives)
3. [Scope](#3-scope)
4. [Stakeholders](#4-stakeholders)
5. [System Overview](#5-system-overview)
6. [Functional Requirements](#6-functional-requirements)
   - 6.1 [Prompt Parser Service](#61-prompt-parser-service)
   - 6.2 [Test Case Generator](#62-test-case-generator)
   - 6.3 [GitHub Integration](#63-github-integration)
7. [Non-Functional Requirements](#7-non-functional-requirements)
8. [Data Requirements](#8-data-requirements)
9. [Integration Requirements](#9-integration-requirements)
10. [User Interface Requirements](#10-user-interface-requirements)
11. [Security Requirements](#11-security-requirements)
12. [Compliance Requirements](#12-compliance-requirements)
13. [Acceptance Criteria](#13-acceptance-criteria)
14. [Appendices](#14-appendices)

---

## 1. Executive Summary

### 1.1 Purpose

This Business Requirements Document (BRD) defines the requirements for building the **Code Hardener Prompt System**, a critical component that enables AI coding agents to generate, parse, and execute security test prompts against codebases. The system bridges the gap between natural language security requirements and automated security tool execution.

### 1.2 Problem Statement

Modern AI-first developers using coding assistants (Claude Code, Cursor, GitHub Copilot) generate code rapidly but lack:
- Expertise to write comprehensive security test cases
- Knowledge of which security tools apply to specific vulnerabilities
- Time to manually configure and run 27+ security scanning tools
- Ability to interpret technical security findings (CVE/CWE jargon)

### 1.3 Proposed Solution

The Code Hardener Prompt System provides three core capabilities:

1. **Prompt Parser Service**: Reads natural language security test prompts from `.md` files, maps them to appropriate security tools, executes scans, and returns results in a consistent format.

2. **Test Case Generator**: Analyzes source code and Business Requirements Documents (BRDs) to automatically generate comprehensive security test case prompts.

3. **GitHub Integration**: OAuth-based repository connection enabling direct scanning of GitHub repositories, branch selection, and commit-level security tracking.

### 1.4 Business Value

| Metric | Current State | Target State |
|--------|---------------|--------------|
| Time to security scan | 2-4 hours manual | < 5 minutes automated |
| Security tool expertise required | Expert level | None (AI-assisted) |
| Test case coverage | Ad-hoc, incomplete | Systematic, BRD-aligned |
| Repository integration | Manual file upload | One-click OAuth |

---

## 2. Business Objectives

### 2.1 Primary Objectives

| ID | Objective | Success Metric | Target |
|----|-----------|----------------|--------|
| BO-1 | Enable natural language security testing | Users can write security tests in plain English | 100% prompt-to-tool mapping accuracy |
| BO-2 | Automate test case generation | Generate test cases from code + BRD | ≥80% relevant test coverage |
| BO-3 | Streamline repository connection | One-click GitHub OAuth | < 30 seconds to connect |
| BO-4 | Reduce security expertise barrier | Non-security experts can run comprehensive scans | Zero security knowledge required |
| BO-5 | Accelerate development velocity | Security testing integrated into AI workflow | < 2 minute scan turnaround |

### 2.2 Secondary Objectives

- Establish Code Hardener as the standard security layer for AI coding assistants
- Enable marketplace integrations (Cursor, Replit, Bolt.new, Lovable)
- Build foundation for enterprise GitHub/GitLab organization scanning
- Create training data for future prompt understanding improvements

### 2.3 Key Performance Indicators (KPIs)

| KPI | Definition | Target | Measurement Frequency |
|-----|------------|--------|----------------------|
| Prompt Parse Success Rate | % of prompts successfully mapped to tools | ≥95% | Daily |
| Test Case Relevance Score | User rating of generated test cases | ≥4.2/5.0 | Per generation |
| GitHub Connection Success | % of OAuth flows completed successfully | ≥98% | Daily |
| Time to First Scan | Duration from repo connect to scan results | < 3 minutes | Per scan |
| Tool Mapping Accuracy | % of correct tool selections for prompts | ≥90% | Weekly audit |

---

## 3. Scope

### 3.1 In Scope

#### Phase 1: Core Prompt System (This BRD)

| Component | Features |
|-----------|----------|
| **Prompt Parser Service** | - Parse `.md` files containing security test prompts<br>- Natural language understanding (NLU) for security intent<br>- Tool mapping engine (prompt → scanner)<br>- Execution orchestration<br>- Result normalization and formatting |
| **Test Case Generator** | - Code analysis for vulnerability surface detection<br>- BRD parsing and requirement extraction<br>- Security test case prompt generation<br>- OWASP/CWE-aligned test coverage<br>- Export to `.md` format |
| **GitHub Integration** | - OAuth 2.0 authentication flow<br>- Repository listing and selection<br>- Branch enumeration<br>- File tree browsing<br>- Commit SHA tracking<br>- Webhook for push-triggered scans |

#### Phase 2: Extended Integrations (Future BRD)

- GitLab OAuth integration
- Bitbucket integration
- Azure DevOps integration
- Local filesystem scanning improvements
- IDE plugins (VS Code, JetBrains)

### 3.2 Out of Scope

| Item | Reason | Future Consideration |
|------|--------|---------------------|
| Self-hosted GitHub Enterprise | Requires VPN/network configuration | Phase 3 |
| GitLab integration | Separate OAuth implementation | Phase 2 |
| Real-time collaborative editing | Not core to security scanning | Not planned |
| Custom scanner development | Use existing 27 tools | Phase 4 |
| Mobile application | Desktop/web focus | Not planned |

### 3.3 Assumptions

| ID | Assumption | Impact if Invalid |
|----|------------|-------------------|
| A-1 | Users have GitHub accounts | Cannot connect repositories |
| A-2 | Prompts are written in English | NLU accuracy decreases |
| A-3 | BRDs follow standard formats (Markdown, Word, PDF) | Parser may fail |
| A-4 | Network connectivity to GitHub API | OAuth flow fails |
| A-5 | AI coding agents output `.md` files | Manual file creation required |

### 3.4 Constraints

| ID | Constraint | Mitigation |
|----|------------|------------|
| C-1 | GitHub API rate limits (5000 req/hr authenticated) | Implement caching, batch requests |
| C-2 | Scanner execution time varies (1s - 30min) | Async queue with progress updates |
| C-3 | Large repositories (>1GB) | Shallow clone, incremental scanning |
| C-4 | Free tier resource limits | Queue prioritization, scan throttling |
| C-5 | OAuth token expiration | Refresh token rotation |

---

## 4. Stakeholders

### 4.1 Stakeholder Matrix

| Stakeholder | Role | Interest | Influence | Engagement Level |
|-------------|------|----------|-----------|------------------|
| AI-First Developers | Primary Users | High | High | Collaborate |
| Security Teams | Secondary Users | High | Medium | Consult |
| DevOps Engineers | Integration Users | Medium | Medium | Inform |
| Product Owner | Decision Maker | High | High | Manage Closely |
| Engineering Team | Implementers | High | High | Collaborate |
| Compliance Officers | Validators | Medium | Medium | Consult |

### 4.2 User Personas

#### Persona 1: Alex - The AI-First Developer

| Attribute | Description |
|-----------|-------------|
| **Role** | Full-stack developer at a startup |
| **Experience** | 3 years coding, 0 years security |
| **Tools** | Claude Code, Cursor, VS Code |
| **Pain Points** | - Doesn't know which security tools to use<br>- Can't interpret CVE/CWE findings<br>- Security slows down shipping |
| **Goals** | - Ship secure code fast<br>- Pass security audits<br>- Learn security through AI assistance |
| **Prompt System Usage** | Writes natural language prompts like "Check this API for SQL injection" |

#### Persona 2: Sam - The Security-Conscious Lead

| Attribute | Description |
|-----------|-------------|
| **Role** | Tech lead at a mid-size company |
| **Experience** | 8 years coding, 2 years security |
| **Tools** | GitHub, Jenkins, SonarQube |
| **Pain Points** | - Team doesn't write security tests<br>- Manual security reviews bottleneck PRs<br>- Need consistent security coverage |
| **Goals** | - Automate security gate in CI/CD<br>- Generate security tests from requirements<br>- Track security posture over time |
| **Prompt System Usage** | Uses Test Case Generator to create security requirements from BRDs |

#### Persona 3: Jordan - The Compliance Manager

| Attribute | Description |
|-----------|-------------|
| **Role** | Compliance officer at enterprise |
| **Experience** | 5 years compliance, limited technical |
| **Tools** | GRC platforms, audit tools |
| **Pain Points** | - Can't verify security claims<br>- Audit evidence is scattered<br>- Developers don't understand compliance |
| **Goals** | - Automated compliance evidence<br>- Traceable security testing<br>- Audit-ready reports |
| **Prompt System Usage** | Reviews generated test cases for compliance alignment |

---

## 5. System Overview

### 5.1 Architecture Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI HARDENER PROMPT SYSTEM                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │   AI Agent   │    │   Developer  │    │   GitHub     │                  │
│  │  (Claude,    │    │  (Dashboard) │    │   Webhook    │                  │
│  │   Cursor)    │    │              │    │              │                  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                  │
│         │                   │                   │                          │
│         ▼                   ▼                   ▼                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         API GATEWAY                                  │   │
│  │              POST /prompts/parse                                     │   │
│  │              POST /prompts/generate                                  │   │
│  │              GET/POST /github/*                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│         │                   │                   │                          │
│         ▼                   ▼                   ▼                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    │
│  │   PROMPT    │    │  TEST CASE  │    │   GITHUB    │                    │
│  │   PARSER    │    │  GENERATOR  │    │ INTEGRATION │                    │
│  │   SERVICE   │    │   SERVICE   │    │   SERVICE   │                    │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘                    │
│         │                   │                   │                          │
│         └─────────┬─────────┴─────────┬─────────┘                          │
│                   ▼                   ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      TOOL MAPPING ENGINE                             │   │
│  │                                                                      │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │   Intent    │  │   Entity    │  │   Scanner   │                  │   │
│  │  │  Classifier │──│  Extractor  │──│   Mapper    │                  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                   │                                                        │
│                   ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      SCAN EXECUTION PIPELINE                         │   │
│  │                      (Existing 27 Tools)                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                   │                                                        │
│                   ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      RESULT NORMALIZER                               │   │
│  │              (Plain Language Translation)                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Component Descriptions

| Component | Purpose | Key Technologies |
|-----------|---------|------------------|
| **Prompt Parser Service** | Interprets natural language security prompts and maps to tools | NLU, keyword extraction, fuzzy matching |
| **Test Case Generator** | Creates security test prompts from code + BRD analysis | AST parsing, requirement extraction, LLM |
| **GitHub Integration** | OAuth flow, repository access, webhook handling | OAuth 2.0, GitHub REST API, webhooks |
| **Tool Mapping Engine** | Converts parsed intents to scanner configurations | Rule engine, ML classifier (future) |
| **Scan Execution Pipeline** | Orchestrates scanner execution (existing) | BullMQ, Docker, gVisor |
| **Result Normalizer** | Translates findings to plain language (existing) | CWE/OWASP mappings |

### 5.3 Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW DIAGRAM                              │
└─────────────────────────────────────────────────────────────────────────────┘

FLOW 1: Prompt Parse & Execute
─────────────────────────────
User/Agent                    System                         Tools
    │                            │                              │
    │  1. Upload .md file        │                              │
    │  ─────────────────────────>│                              │
    │                            │                              │
    │                            │  2. Parse prompts            │
    │                            │  ──────────────┐             │
    │                            │                │             │
    │                            │  <─────────────┘             │
    │                            │                              │
    │                            │  3. Map to scanners          │
    │                            │  ──────────────┐             │
    │                            │                │             │
    │                            │  <─────────────┘             │
    │                            │                              │
    │                            │  4. Execute scans            │
    │                            │  ───────────────────────────>│
    │                            │                              │
    │                            │  5. Collect results          │
    │                            │  <───────────────────────────│
    │                            │                              │
    │                            │  6. Normalize & translate    │
    │                            │  ──────────────┐             │
    │                            │                │             │
    │                            │  <─────────────┘             │
    │                            │                              │
    │  7. Return results         │                              │
    │  <─────────────────────────│                              │
    │                            │                              │


FLOW 2: Test Case Generation
────────────────────────────
User                          System                         Analysis
    │                            │                              │
    │  1. Provide code + BRD     │                              │
    │  ─────────────────────────>│                              │
    │                            │                              │
    │                            │  2. Analyze code             │
    │                            │  ───────────────────────────>│
    │                            │                              │
    │                            │  3. Code vulnerabilities     │
    │                            │  <───────────────────────────│
    │                            │                              │
    │                            │  4. Parse BRD                │
    │                            │  ───────────────────────────>│
    │                            │                              │
    │                            │  5. Security requirements    │
    │                            │  <───────────────────────────│
    │                            │                              │
    │                            │  6. Generate test cases      │
    │                            │  ──────────────┐             │
    │                            │                │             │
    │                            │  <─────────────┘             │
    │                            │                              │
    │  7. Return .md prompts     │                              │
    │  <─────────────────────────│                              │
    │                            │                              │


FLOW 3: GitHub OAuth & Scan
───────────────────────────
User                          System                         GitHub
    │                            │                              │
    │  1. Click "Connect GitHub" │                              │
    │  ─────────────────────────>│                              │
    │                            │                              │
    │                            │  2. Redirect to GitHub       │
    │                            │  ───────────────────────────>│
    │                            │                              │
    │  3. Authorize app          │                              │
    │  ──────────────────────────────────────────────────────>│
    │                            │                              │
    │                            │  4. Callback with code       │
    │                            │  <───────────────────────────│
    │                            │                              │
    │                            │  5. Exchange for token       │
    │                            │  ───────────────────────────>│
    │                            │                              │
    │                            │  6. Access token             │
    │                            │  <───────────────────────────│
    │                            │                              │
    │                            │  7. Fetch repositories       │
    │                            │  ───────────────────────────>│
    │                            │                              │
    │                            │  8. Repository list          │
    │                            │  <───────────────────────────│
    │                            │                              │
    │  9. Display repos          │                              │
    │  <─────────────────────────│                              │
    │                            │                              │
    │  10. Select repo           │                              │
    │  ─────────────────────────>│                              │
    │                            │                              │
    │                            │  11. Clone & scan            │
    │                            │  ───────────────────────────>│
    │                            │                              │
```

---

## 6. Functional Requirements

### 6.1 Prompt Parser Service

#### 6.1.1 Overview

The Prompt Parser Service reads natural language security test prompts from Markdown files, understands the security intent, maps to appropriate scanning tools, orchestrates execution, and returns normalized results.

#### 6.1.2 Prompt File Format

**Supported Input Formats:**

| Format | Extension | Description |
|--------|-----------|-------------|
| Markdown | `.md` | Primary format, supports structured prompts |
| Plain Text | `.txt` | Simple list of prompts |
| JSON | `.json` | Structured prompt array |
| YAML | `.yaml`, `.yml` | Structured prompt definitions |

**Markdown Prompt File Schema:**

```markdown
# Security Test Prompts

## Metadata
- **Project**: [Project Name]
- **Version**: [Version]
- **Generated By**: [Agent Name]
- **Date**: [ISO 8601 Date]

## Test Prompts

### Authentication Tests
- [ ] Check for SQL injection in login form
- [ ] Verify password hashing uses bcrypt or argon2
- [ ] Test for brute force protection on authentication endpoints

### API Security Tests
- [ ] Scan all REST endpoints for injection vulnerabilities
- [ ] Verify JWT tokens are properly validated
- [ ] Check for sensitive data exposure in API responses

### Dependency Tests
- [ ] Scan dependencies for known CVEs
- [ ] Check for outdated packages with security patches
- [ ] Verify no malicious packages in dependency tree

### Infrastructure Tests
- [ ] Validate Dockerfile for security best practices
- [ ] Check Kubernetes manifests for misconfigurations
- [ ] Scan Terraform files for security issues
```

#### 6.1.3 Functional Requirements Table

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| PPS-001 | Parse Markdown prompt files | Must Have | System extracts all prompt items from valid `.md` files |
| PPS-002 | Parse plain text prompt files | Should Have | System extracts prompts from `.txt` files (one per line) |
| PPS-003 | Parse JSON prompt arrays | Should Have | System accepts `{"prompts": ["...", "..."]}` format |
| PPS-004 | Parse YAML prompt definitions | Could Have | System accepts YAML structured prompts |
| PPS-005 | Extract prompt metadata | Must Have | System captures project, version, date, author from files |
| PPS-006 | Handle nested prompt structures | Must Have | System parses hierarchical prompt sections |
| PPS-007 | Support checkbox syntax | Should Have | System recognizes `- [ ]` and `- [x]` markers |
| PPS-008 | Ignore non-prompt content | Must Have | System skips comments, explanations, headers |
| PPS-009 | Validate prompt file format | Must Have | System returns clear errors for malformed files |
| PPS-010 | Support file upload via API | Must Have | POST endpoint accepts multipart file upload |
| PPS-011 | Support file path reference | Must Have | API accepts local/remote file path |
| PPS-012 | Support inline prompt text | Must Have | API accepts prompts directly in request body |

#### 6.1.4 Natural Language Understanding (NLU)

**Intent Classification:**

| Intent Category | Example Prompts | Mapped Tools |
|-----------------|-----------------|--------------|
| `sql_injection` | "Check for SQL injection", "Test database queries for injection" | opengrep, bandit, eslint-security |
| `xss` | "Scan for XSS vulnerabilities", "Check for cross-site scripting" | opengrep, eslint-security, nuclei |
| `authentication` | "Verify authentication security", "Check login security" | opengrep, bandit, zap |
| `secrets` | "Find hardcoded secrets", "Check for exposed credentials" | gitleaks, detect-secrets |
| `dependencies` | "Scan dependencies for CVEs", "Check for vulnerable packages" | trivy, grype |
| `container` | "Scan Docker image", "Check container security" | trivy, grype |
| `iac` | "Check Terraform security", "Scan Kubernetes manifests" | checkov |
| `api_security` | "Test API endpoints", "Check REST API security" | zap, nuclei, restler |
| `code_quality` | "Check code for security issues", "Static analysis" | opengrep, pmd, eslint-security |
| `compliance` | "Check OWASP compliance", "Verify security standards" | checkov, opa |
| `performance` | "Load test the API", "Check for DoS vulnerabilities" | locust, artillery, k6 |
| `accessibility` | "Check accessibility", "Test WCAG compliance" | pa11y |

**Entity Extraction:**

| Entity Type | Examples | Purpose |
|-------------|----------|---------|
| `language` | Python, JavaScript, Go, Java | Select language-specific scanners |
| `framework` | React, Django, Express, Spring | Apply framework-specific rules |
| `file_path` | `src/auth/`, `*.py`, `controllers/` | Scope scan to specific paths |
| `severity` | critical, high, medium, low | Filter result severity |
| `cwe_id` | CWE-89, CWE-79, CWE-22 | Target specific vulnerability classes |
| `owasp` | A01, A02, A03 | Target OWASP Top 10 categories |
| `tool_name` | trivy, gitleaks, zap | Explicit tool selection |

#### 6.1.5 NLU Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| NLU-001 | Classify security intent from prompt | Must Have | ≥90% accuracy on test dataset |
| NLU-002 | Extract target language entities | Must Have | Correctly identifies programming languages |
| NLU-003 | Extract file path entities | Should Have | Parses glob patterns and paths |
| NLU-004 | Extract severity filters | Should Have | Maps "critical only", "high and above" |
| NLU-005 | Handle ambiguous prompts | Must Have | Returns multiple possible interpretations |
| NLU-006 | Support synonyms and variations | Must Have | "SQL injection" = "SQLi" = "database injection" |
| NLU-007 | Handle negation | Should Have | "Don't check for XSS" excludes XSS scanners |
| NLU-008 | Extract explicit tool references | Must Have | "Use trivy to scan" maps to trivy |
| NLU-009 | Support compound prompts | Should Have | "Check for SQL injection and XSS" maps to multiple |
| NLU-010 | Provide confidence scores | Must Have | Each mapping includes confidence 0.0-1.0 |

#### 6.1.6 Tool Mapping Engine

**Mapping Rules:**

```yaml
# Tool Mapping Configuration
mappings:
  sql_injection:
    primary:
      - tool: opengrep
        rules: ["sql-injection", "sqli"]
        confidence: 0.95
      - tool: bandit
        rules: ["B608", "B309"]
        languages: [python]
        confidence: 0.90
    secondary:
      - tool: eslint-security
        rules: ["detect-sql-injection"]
        languages: [javascript, typescript]
        confidence: 0.85

  xss:
    primary:
      - tool: opengrep
        rules: ["xss", "cross-site-scripting"]
        confidence: 0.95
      - tool: eslint-security
        rules: ["detect-unsafe-dom", "no-danger"]
        languages: [javascript, typescript]
        confidence: 0.90
    secondary:
      - tool: nuclei
        templates: ["xss"]
        requires: [target_url]
        confidence: 0.80

  secrets:
    primary:
      - tool: gitleaks
        confidence: 0.98
      - tool: detect-secrets
        confidence: 0.95

  dependencies:
    primary:
      - tool: trivy
        mode: "fs"
        confidence: 0.95
      - tool: grype
        confidence: 0.90

  container:
    primary:
      - tool: trivy
        mode: "image"
        requires: [image_name]
        confidence: 0.95
      - tool: grype
        mode: "image"
        requires: [image_name]
        confidence: 0.90

  iac:
    primary:
      - tool: checkov
        confidence: 0.95
    secondary:
      - tool: trivy
        mode: "config"
        confidence: 0.85
```

#### 6.1.7 Tool Mapping Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| TM-001 | Map intents to primary tools | Must Have | Each intent has ≥1 primary tool mapping |
| TM-002 | Support secondary/fallback tools | Should Have | Secondary tools used when primary unavailable |
| TM-003 | Filter by language compatibility | Must Have | Python prompts don't trigger Go-only scanners |
| TM-004 | Respect explicit tool selection | Must Have | "Use trivy" overrides automatic mapping |
| TM-005 | Handle missing required inputs | Must Have | Return error if tool needs unavailable input |
| TM-006 | Combine tools for compound prompts | Must Have | "SQL injection and XSS" runs multiple scanners |
| TM-007 | Apply confidence thresholds | Should Have | Only run tools with confidence ≥ configurable threshold |
| TM-008 | Support custom mapping rules | Could Have | Users can add project-specific mappings |
| TM-009 | Log mapping decisions | Must Have | Audit trail of why each tool was selected |
| TM-010 | Provide mapping explanation | Should Have | API returns human-readable mapping rationale |

#### 6.1.8 Execution Orchestration

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| EO-001 | Queue scan jobs asynchronously | Must Have | Jobs added to BullMQ queue |
| EO-002 | Track job progress | Must Have | Real-time status updates (pending, running, done) |
| EO-003 | Support parallel tool execution | Should Have | Independent scanners run concurrently |
| EO-004 | Handle tool failures gracefully | Must Have | Failed tool doesn't abort entire scan |
| EO-005 | Respect tool dependencies | Should Have | Run prerequisite scans first |
| EO-006 | Apply timeout limits | Must Have | Individual tool timeout (configurable, default 5min) |
| EO-007 | Support scan cancellation | Should Have | User can cancel in-progress scans |
| EO-008 | Aggregate results from multiple tools | Must Have | Combined results with source attribution |
| EO-009 | Deduplicate findings | Should Have | Same finding from multiple tools appears once |
| EO-010 | Apply severity mapping | Must Have | Normalize severity across tools |

#### 6.1.9 Result Formatting

**Output Schema:**

```json
{
  "scanId": "uuid",
  "status": "completed",
  "promptFile": "security-tests.md",
  "prompts": [
    {
      "id": "prompt-1",
      "text": "Check for SQL injection in login form",
      "intent": "sql_injection",
      "confidence": 0.95,
      "mappedTools": ["opengrep", "bandit"],
      "status": "completed"
    }
  ],
  "summary": {
    "totalPrompts": 10,
    "completedPrompts": 10,
    "totalFindings": 23,
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 6,
    "riskScore": 720,
    "riskLevel": "high"
  },
  "findings": [
    {
      "id": "finding-1",
      "promptId": "prompt-1",
      "tool": "opengrep",
      "ruleId": "python.sqlalchemy.security.sqlalchemy-execute-raw-query",
      "severity": "high",
      "title": "SQL Injection Vulnerability",
      "description": "Raw SQL query execution detected without parameterization",
      "plainLanguage": "Your code builds a database query by directly inserting user input. An attacker could manipulate this to access or delete data they shouldn't.",
      "file": "src/auth/login.py",
      "line": 45,
      "column": 12,
      "codeSnippet": "cursor.execute(f\"SELECT * FROM users WHERE email = '{email}'\")",
      "cweId": "CWE-89",
      "owaspCategory": "A03:2021-Injection",
      "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE email = ?', (email,))",
      "references": [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/Top10/A03_2021-Injection/"
      ]
    }
  ],
  "attestation": {
    "id": "attestation-uuid",
    "signature": "base64...",
    "certificate": "base64...",
    "rekorLogId": "rekor-uuid"
  },
  "duration": 45000,
  "completedAt": "2026-01-11T15:30:00Z"
}
```

#### 6.1.10 Result Formatting Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| RF-001 | Return JSON response | Must Have | Valid JSON with documented schema |
| RF-002 | Include prompt-to-finding mapping | Must Have | Each finding links to triggering prompt |
| RF-003 | Provide plain language descriptions | Must Have | All findings have non-technical explanation |
| RF-004 | Include remediation guidance | Should Have | Actionable fix suggestions |
| RF-005 | Calculate aggregate risk score | Must Have | 0-1000 score with severity breakdown |
| RF-006 | Support multiple output formats | Should Have | JSON, SARIF, Markdown, HTML |
| RF-007 | Include CWE/OWASP mappings | Must Have | Standard vulnerability classifications |
| RF-008 | Provide code snippets | Should Have | Relevant code context for findings |
| RF-009 | Include attestation data | Should Have | Sigstore attestation for audit trail |
| RF-010 | Support streaming results | Could Have | Real-time results as tools complete |

---

### 6.2 Test Case Generator

#### 6.2.1 Overview

The Test Case Generator analyzes source code and Business Requirements Documents (BRDs) to automatically generate comprehensive security test case prompts. This enables proactive security testing aligned with business requirements.

#### 6.2.2 Input Formats

**Code Input:**

| Input Type | Description | Example |
|------------|-------------|---------|
| GitHub Repository | OAuth-connected repository | `github.com/user/repo` |
| Local Directory | File path on server | `/projects/myapp/src` |
| Uploaded Archive | ZIP/TAR file | `project.zip` |
| Single File | Individual source file | `auth.py` |

**BRD Input:**

| Format | Extension | Parser |
|--------|-----------|--------|
| Markdown | `.md` | Native |
| Microsoft Word | `.docx` | mammoth.js |
| PDF | `.pdf` | pdf-parse |
| Plain Text | `.txt` | Native |
| Confluence | URL | Confluence API |
| Notion | URL | Notion API |
| Google Docs | URL | Google Docs API |

#### 6.2.3 Code Analysis

**Analysis Capabilities:**

| Analysis Type | Purpose | Output |
|---------------|---------|--------|
| Language Detection | Identify programming languages | `{python: 60%, javascript: 30%, go: 10%}` |
| Framework Detection | Identify frameworks/libraries | `[django, react, express]` |
| Entry Point Detection | Find API endpoints, routes | `[POST /login, GET /users/:id]` |
| Authentication Detection | Identify auth mechanisms | `[jwt, session, oauth]` |
| Data Flow Analysis | Track user input flows | `[input → db, input → response]` |
| Sensitive Data Detection | Find PII, secrets handling | `[email, password, ssn]` |
| Dependency Analysis | List third-party packages | `[requests, sqlalchemy, jwt]` |
| Infrastructure Detection | Find IaC files | `[Dockerfile, k8s/, terraform/]` |

#### 6.2.4 Code Analysis Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| CA-001 | Detect programming languages | Must Have | Accurately identify languages in codebase |
| CA-002 | Identify web frameworks | Must Have | Detect Django, Express, Spring, etc. |
| CA-003 | Extract API endpoints | Must Have | Find REST routes, GraphQL schemas |
| CA-004 | Detect authentication patterns | Should Have | Identify auth mechanisms |
| CA-005 | Trace data flows | Should Have | Map user input to database/output |
| CA-006 | Identify sensitive data handling | Must Have | Find PII, credential usage |
| CA-007 | Parse dependency manifests | Must Have | Read package.json, requirements.txt, go.mod |
| CA-008 | Detect infrastructure files | Should Have | Find Dockerfile, K8s, Terraform |
| CA-009 | Generate code summary | Must Have | High-level codebase overview |
| CA-010 | Handle large codebases | Must Have | Process repos up to 1GB |

#### 6.2.5 BRD Parsing

**Extraction Targets:**

| Element | Description | Example |
|---------|-------------|---------|
| Functional Requirements | What the system should do | "Users can log in with email/password" |
| Security Requirements | Explicit security needs | "All data must be encrypted at rest" |
| Compliance Requirements | Regulatory needs | "System must be HIPAA compliant" |
| Data Handling | Data types and sensitivity | "System processes payment card data" |
| User Roles | Access control requirements | "Admin users can delete accounts" |
| Integration Points | External system connections | "Integrates with Stripe API" |
| Performance Requirements | Throughput/latency needs | "API must handle 1000 req/sec" |

#### 6.2.6 BRD Parsing Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| BP-001 | Parse Markdown BRDs | Must Have | Extract requirements from `.md` files |
| BP-002 | Parse Word documents | Should Have | Extract from `.docx` files |
| BP-003 | Parse PDF documents | Should Have | Extract text from PDFs |
| BP-004 | Extract functional requirements | Must Have | Identify feature descriptions |
| BP-005 | Extract security requirements | Must Have | Find explicit security needs |
| BP-006 | Extract compliance requirements | Should Have | Identify regulatory references |
| BP-007 | Identify data sensitivity | Must Have | Detect PII, PCI, PHI references |
| BP-008 | Extract user roles | Should Have | Find access control requirements |
| BP-009 | Handle structured formats | Should Have | Parse tables, lists, sections |
| BP-010 | Support BRD templates | Could Have | Pre-defined parsing for common formats |

#### 6.2.7 Test Case Generation

**Generation Strategy:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        TEST CASE GENERATION PIPELINE                        │
└─────────────────────────────────────────────────────────────────────────────┘

     ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
     │     Code     │         │     BRD      │         │   Security   │
     │   Analysis   │         │   Parsing    │         │  Knowledge   │
     └──────┬───────┘         └──────┬───────┘         └──────┬───────┘
            │                        │                        │
            │   ┌────────────────────┴────────────────────┐   │
            │   │         CORRELATION ENGINE              │   │
            │   │                                         │   │
            │   │  Code Features ←→ BRD Requirements      │   │
            └──>│  Entry Points ←→ User Stories           │<──┘
                │  Data Flows ←→ Data Requirements        │
                │  Auth Patterns ←→ Access Control        │
                │                                         │
                └────────────────────┬────────────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │       TEST CASE TEMPLATES     │
                     │                               │
                     │  • OWASP Top 10 Coverage     │
                     │  • CWE Top 25 Coverage       │
                     │  • Compliance Checklists     │
                     │  • Framework-Specific Tests  │
                     │  • Custom Business Logic     │
                     │                               │
                     └───────────────────────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │    GENERATED TEST PROMPTS     │
                     │                               │
                     │  Prioritized by:             │
                     │  • Risk level                │
                     │  • BRD alignment             │
                     │  • Code coverage             │
                     │  • Compliance requirements   │
                     │                               │
                     └───────────────────────────────┘
```

**Test Case Categories:**

| Category | Trigger | Example Prompts Generated |
|----------|---------|---------------------------|
| **Injection** | SQL/NoSQL usage detected | "Test login endpoint for SQL injection via email parameter" |
| **Authentication** | Auth code detected | "Verify password hashing uses secure algorithm (bcrypt/argon2)" |
| **Session** | Session handling detected | "Check session tokens for predictability and secure attributes" |
| **Access Control** | Role/permission code found | "Test admin endpoints are inaccessible to regular users" |
| **Cryptography** | Crypto functions used | "Verify encryption uses AES-256 or stronger" |
| **Data Exposure** | PII handling detected | "Check API responses don't leak sensitive user data" |
| **Dependencies** | Package manifests exist | "Scan all dependencies for known CVEs (critical/high)" |
| **Containers** | Dockerfile exists | "Check Dockerfile for security best practices" |
| **IaC** | Terraform/K8s files exist | "Scan infrastructure code for misconfigurations" |
| **API** | REST/GraphQL endpoints | "Test all endpoints for authentication bypass" |
| **Compliance** | HIPAA/PCI reference in BRD | "Verify data encryption meets HIPAA requirements" |

#### 6.2.8 Test Generation Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| TG-001 | Generate OWASP Top 10 tests | Must Have | Cover all 10 categories where applicable |
| TG-002 | Generate CWE Top 25 tests | Should Have | Cover relevant CWE categories |
| TG-003 | Align tests with BRD requirements | Must Have | Each BRD requirement has security tests |
| TG-004 | Generate endpoint-specific tests | Must Have | Tests target discovered API endpoints |
| TG-005 | Include authentication tests | Must Have | Auth mechanisms have specific tests |
| TG-006 | Include authorization tests | Must Have | Access control has specific tests |
| TG-007 | Generate dependency tests | Must Have | Include SCA test prompts |
| TG-008 | Generate infrastructure tests | Should Have | IaC files have specific tests |
| TG-009 | Prioritize tests by risk | Must Have | High-risk areas tested first |
| TG-010 | Avoid duplicate/redundant tests | Should Have | No repetitive test cases |
| TG-011 | Include compliance tests | Should Have | Regulatory requirements covered |
| TG-012 | Generate performance tests | Could Have | Load/stress test prompts |

#### 6.2.9 Output Format

**Generated Test Prompts File:**

```markdown
# Security Test Prompts

## Metadata
- **Project**: MyApp
- **Repository**: github.com/user/myapp
- **Generated**: 2026-01-11T15:30:00Z
- **Generator**: Code Hardener Test Case Generator v1.0
- **Code Analysis**: Python (Django), JavaScript (React)
- **BRD Analyzed**: requirements/PRD.md

## Coverage Summary
| Category | Tests | Risk Level |
|----------|-------|------------|
| Injection | 8 | Critical |
| Authentication | 12 | High |
| Access Control | 6 | High |
| Data Exposure | 5 | Medium |
| Dependencies | 3 | Medium |
| Infrastructure | 4 | Medium |
| **Total** | **38** | |

## Critical Priority Tests

### Injection Tests (OWASP A03)
*Based on: SQLAlchemy usage in `src/models/`, user input handling in `src/api/`*

- [ ] Test `/api/login` endpoint for SQL injection via `email` parameter
- [ ] Test `/api/users/search` for SQL injection via `query` parameter
- [ ] Verify all database queries use parameterized statements
- [ ] Check for NoSQL injection in MongoDB queries (`src/services/analytics.py`)

### Authentication Tests (OWASP A07)
*Based on: JWT implementation in `src/auth/`, BRD Section 3.2 "User Authentication"*

- [ ] Verify password hashing uses bcrypt with cost factor ≥12
- [ ] Test for authentication bypass on protected endpoints
- [ ] Check JWT tokens include appropriate expiration (≤1 hour per BRD)
- [ ] Verify refresh token rotation is implemented
- [ ] Test for brute force protection on `/api/login`
- [ ] Check password reset flow for account enumeration

## High Priority Tests

### Access Control Tests (OWASP A01)
*Based on: Role definitions in `src/models/user.py`, BRD Section 4.1 "User Roles"*

- [ ] Verify admin endpoints (`/api/admin/*`) reject non-admin users
- [ ] Test horizontal privilege escalation (user A accessing user B data)
- [ ] Check IDOR vulnerabilities on `/api/users/:id` endpoint
- [ ] Verify API key permissions match documented scopes

### Data Exposure Tests (OWASP A02)
*Based on: PII handling in `src/services/`, BRD Section 5.0 "Data Privacy"*

- [ ] Check API responses don't include sensitive fields (password hash, SSN)
- [ ] Verify error messages don't leak system information
- [ ] Test for sensitive data in URL parameters
- [ ] Check logging doesn't capture sensitive data

## Medium Priority Tests

### Dependency Tests (OWASP A06)
*Based on: `requirements.txt`, `package.json`*

- [ ] Scan Python dependencies for known CVEs (critical/high)
- [ ] Scan JavaScript dependencies for known CVEs (critical/high)
- [ ] Check for outdated packages with available security patches

### Infrastructure Tests (OWASP A05)
*Based on: `Dockerfile`, `kubernetes/`, `terraform/`*

- [ ] Verify Dockerfile doesn't run as root
- [ ] Check Kubernetes manifests for security contexts
- [ ] Scan Terraform configurations for misconfigurations
- [ ] Verify secrets aren't hardcoded in infrastructure files

## Compliance Tests
*Based on: BRD Section 6.0 "Compliance Requirements" (SOC 2)*

- [ ] Verify audit logging is enabled for all sensitive operations
- [ ] Check data encryption at rest is implemented
- [ ] Verify TLS 1.2+ is enforced for all connections
- [ ] Test session timeout matches policy (30 minutes per BRD)

---

## Execution Instructions

To execute these tests with Code Hardener:

1. **Via API:**
```bash
curl -X POST https://api.codehardener.com/v1/prompts/parse \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@security-tests.md" \
  -F "projectId=your-project-id"
```

2. **Via Dashboard:**
   - Navigate to Project → Security Tests
   - Upload this file or paste contents
   - Click "Execute Tests"

3. **Via Claude Code:**
```
@codehardener scan with prompts from security-tests.md
```
```

---

### 6.3 GitHub Integration

#### 6.3.1 Overview

GitHub Integration enables users to connect their GitHub accounts via OAuth 2.0, browse and select repositories, and run security scans directly on their codebase without manual file uploads.

#### 6.3.2 OAuth 2.0 Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           GITHUB OAUTH 2.0 FLOW                             │
└─────────────────────────────────────────────────────────────────────────────┘

  User                    Code Hardener                    GitHub
    │                          │                            │
    │  1. Click "Connect       │                            │
    │     GitHub"              │                            │
    │  ───────────────────────>│                            │
    │                          │                            │
    │                          │  2. Generate state token   │
    │                          │     Store in session       │
    │                          │                            │
    │  3. Redirect to GitHub   │                            │
    │     OAuth authorize URL  │                            │
    │  <───────────────────────│                            │
    │                          │                            │
    │  4. User sees GitHub     │                            │
    │     authorization page   │                            │
    │  ──────────────────────────────────────────────────>│
    │                          │                            │
    │  5. User authorizes      │                            │
    │     Code Hardener app      │                            │
    │  ──────────────────────────────────────────────────>│
    │                          │                            │
    │                          │  6. GitHub redirects       │
    │                          │     with code + state      │
    │  <───────────────────────────────────────────────────│
    │                          │                            │
    │  7. Callback to          │                            │
    │     Code Hardener          │                            │
    │  ───────────────────────>│                            │
    │                          │                            │
    │                          │  8. Verify state token     │
    │                          │                            │
    │                          │  9. Exchange code for      │
    │                          │     access token           │
    │                          │  ────────────────────────>│
    │                          │                            │
    │                          │  10. Return access +       │
    │                          │      refresh tokens        │
    │                          │  <────────────────────────│
    │                          │                            │
    │                          │  11. Store encrypted       │
    │                          │      tokens in database    │
    │                          │                            │
    │                          │  12. Fetch user profile    │
    │                          │  ────────────────────────>│
    │                          │                            │
    │                          │  13. Return profile        │
    │                          │  <────────────────────────│
    │                          │                            │
    │  14. Redirect to         │                            │
    │      dashboard with      │                            │
    │      success             │                            │
    │  <───────────────────────│                            │
    │                          │                            │
```

#### 6.3.3 OAuth Configuration

**GitHub App Settings:**

| Setting | Value |
|---------|-------|
| App Name | Code Hardener |
| Homepage URL | https://codehardener.com |
| Callback URL | https://api.codehardener.com/v1/github/callback |
| Webhook URL | https://api.codehardener.com/v1/github/webhook |
| Webhook Secret | [Securely generated] |

**Required Scopes:**

| Scope | Purpose | Required |
|-------|---------|----------|
| `repo` | Full access to private/public repositories | Yes |
| `read:user` | Read user profile information | Yes |
| `user:email` | Access user email addresses | Yes |
| `read:org` | List organizations (for org repos) | Optional |
| `admin:repo_hook` | Manage repository webhooks | Optional |

#### 6.3.4 OAuth Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| GH-001 | Implement OAuth 2.0 authorization flow | Must Have | Users can authorize Code Hardener |
| GH-002 | Generate cryptographic state token | Must Have | CSRF protection via state parameter |
| GH-003 | Exchange code for access token | Must Have | Receive and store access token |
| GH-004 | Store tokens encrypted | Must Have | AES-256 encryption at rest |
| GH-005 | Implement refresh token rotation | Must Have | Auto-refresh expired tokens |
| GH-006 | Handle OAuth errors gracefully | Must Have | Clear error messages for users |
| GH-007 | Support token revocation | Should Have | Users can disconnect GitHub |
| GH-008 | Validate callback origin | Must Have | Only accept callbacks from GitHub |
| GH-009 | Implement rate limit handling | Must Have | Respect GitHub API limits |
| GH-010 | Log OAuth events for audit | Must Have | Track connections/disconnections |

#### 6.3.5 Repository Operations

**Supported Operations:**

| Operation | Endpoint | Description |
|-----------|----------|-------------|
| List User Repos | `GET /user/repos` | Fetch authenticated user's repositories |
| List Org Repos | `GET /orgs/{org}/repos` | Fetch organization repositories |
| Get Repository | `GET /repos/{owner}/{repo}` | Fetch repository details |
| List Branches | `GET /repos/{owner}/{repo}/branches` | Fetch repository branches |
| Get Branch | `GET /repos/{owner}/{repo}/branches/{branch}` | Fetch branch details |
| Get Commit | `GET /repos/{owner}/{repo}/commits/{sha}` | Fetch commit details |
| Download Archive | `GET /repos/{owner}/{repo}/zipball/{ref}` | Download repository archive |
| Get Contents | `GET /repos/{owner}/{repo}/contents/{path}` | Fetch file/directory contents |
| Get Tree | `GET /repos/{owner}/{repo}/git/trees/{sha}` | Fetch repository tree |

#### 6.3.6 Repository Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| GH-011 | List user's repositories | Must Have | Display all accessible repos |
| GH-012 | List organization repositories | Should Have | Display org repos if authorized |
| GH-013 | Filter repositories | Should Have | Search/filter by name, language |
| GH-014 | Sort repositories | Should Have | Sort by name, updated, stars |
| GH-015 | Paginate repository list | Must Have | Handle users with many repos |
| GH-016 | Show repository metadata | Must Have | Name, description, language, visibility |
| GH-017 | List branches for repository | Must Have | Show all branches for selection |
| GH-018 | Default to main/master branch | Should Have | Auto-select default branch |
| GH-019 | Show last commit info | Should Have | Display latest commit SHA/message |
| GH-020 | Clone repository for scanning | Must Have | Download and extract repo code |

#### 6.3.7 Webhook Integration

**Supported Webhook Events:**

| Event | Trigger | Action |
|-------|---------|--------|
| `push` | Code pushed to branch | Queue security scan |
| `pull_request` | PR opened/updated | Queue PR security scan |
| `pull_request_review` | PR review submitted | Update scan status |
| `create` | Branch/tag created | Index new branch |
| `delete` | Branch/tag deleted | Remove from index |

**Webhook Payload Processing:**

```json
{
  "event": "push",
  "repository": {
    "id": 123456,
    "full_name": "user/repo",
    "default_branch": "main"
  },
  "ref": "refs/heads/main",
  "before": "abc123",
  "after": "def456",
  "commits": [
    {
      "id": "def456",
      "message": "Add new feature",
      "author": { "name": "User", "email": "user@example.com" }
    }
  ],
  "pusher": { "name": "user", "email": "user@example.com" }
}
```

#### 6.3.8 Webhook Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| GH-021 | Receive push webhooks | Should Have | Process push events |
| GH-022 | Receive PR webhooks | Should Have | Process pull request events |
| GH-023 | Validate webhook signatures | Must Have | Verify HMAC-SHA256 signature |
| GH-024 | Queue scans on push | Should Have | Auto-scan on code push |
| GH-025 | Queue scans on PR | Should Have | Auto-scan on PR open/update |
| GH-026 | Post scan results to PR | Could Have | Comment with findings on PR |
| GH-027 | Update commit status | Could Have | Set commit status (pass/fail) |
| GH-028 | Handle webhook retries | Must Have | Idempotent webhook processing |
| GH-029 | Rate limit webhook processing | Should Have | Prevent webhook flood attacks |
| GH-030 | Log webhook events | Must Have | Audit trail of all webhooks |

#### 6.3.9 Repository Scanning

**Scan Flow:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REPOSITORY SCAN FLOW                                │
└─────────────────────────────────────────────────────────────────────────────┘

  Dashboard                 API                    Scanner              GitHub
      │                      │                        │                    │
      │  1. Select repo +    │                        │                    │
      │     branch           │                        │                    │
      │  ───────────────────>│                        │                    │
      │                      │                        │                    │
      │                      │  2. Create scan job    │                    │
      │                      │                        │                    │
      │                      │  3. Download repo      │                    │
      │                      │  ─────────────────────────────────────────>│
      │                      │                        │                    │
      │                      │  4. Receive archive    │                    │
      │                      │  <─────────────────────────────────────────│
      │                      │                        │                    │
      │                      │  5. Extract to         │                    │
      │                      │     scan volume        │                    │
      │                      │  ─────────────────────>│                    │
      │                      │                        │                    │
      │                      │                        │  6. Run scanners   │
      │                      │                        │  ────────┐         │
      │                      │                        │          │         │
      │                      │                        │  <───────┘         │
      │                      │                        │                    │
      │                      │  7. Return findings    │                    │
      │                      │  <─────────────────────│                    │
      │                      │                        │                    │
      │  8. Display results  │                        │                    │
      │  <───────────────────│                        │                    │
      │                      │                        │                    │
```

#### 6.3.10 Scanning Requirements

| ID | Requirement | Priority | Acceptance Criteria |
|----|-------------|----------|---------------------|
| GH-031 | Clone repository for scan | Must Have | Download repo code |
| GH-032 | Support branch selection | Must Have | Scan specific branch |
| GH-033 | Support commit SHA selection | Should Have | Scan specific commit |
| GH-034 | Handle large repositories | Must Have | Support repos up to 1GB |
| GH-035 | Shallow clone option | Should Have | Reduce download time/size |
| GH-036 | Clean up after scan | Must Have | Remove cloned code after scan |
| GH-037 | Cache repository metadata | Should Have | Reduce API calls |
| GH-038 | Track scan history per repo | Must Have | Show past scans for repo |
| GH-039 | Compare scans across commits | Could Have | Show finding diff between commits |
| GH-040 | Support monorepo scanning | Could Have | Scan subdirectories of repo |

---

## 7. Non-Functional Requirements

### 7.1 Performance Requirements

| ID | Requirement | Target | Measurement |
|----|-------------|--------|-------------|
| NFR-001 | Prompt parsing latency | < 500ms for files ≤100KB | 95th percentile |
| NFR-002 | Tool mapping latency | < 100ms per prompt | 95th percentile |
| NFR-003 | Scan queue time | < 30 seconds | Average wait time |
| NFR-004 | Individual tool timeout | Configurable, default 5 minutes | Max execution time |
| NFR-005 | Total scan timeout | Configurable, default 30 minutes | Max scan duration |
| NFR-006 | API response time | < 200ms for non-scan endpoints | 95th percentile |
| NFR-007 | Dashboard page load | < 2 seconds | Time to interactive |
| NFR-008 | GitHub OAuth flow | < 5 seconds total | End-to-end |
| NFR-009 | Repository list fetch | < 3 seconds for 100 repos | API response time |
| NFR-010 | Repository clone time | < 60 seconds for repos ≤100MB | Download + extract |

### 7.2 Scalability Requirements

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NFR-011 | Concurrent scans | 100 per cluster | With KEDA autoscaling |
| NFR-012 | Prompt files per scan | 10 files | Aggregate results |
| NFR-013 | Prompts per file | 500 prompts | Parse all |
| NFR-014 | Findings per scan | 10,000 findings | Store and display |
| NFR-015 | Connected GitHub accounts | Unlimited | Per user |
| NFR-016 | Repositories per account | 1,000 listed | Paginated |
| NFR-017 | Webhook events per hour | 10,000 | Per organization |
| NFR-018 | Test case generation | 500 test cases | Per generation |

### 7.3 Reliability Requirements

| ID | Requirement | Target | Notes |
|----|-------------|--------|-------|
| NFR-019 | Service availability | 99.9% | Monthly uptime |
| NFR-020 | Scan completion rate | 99% | Successful completion |
| NFR-021 | Data durability | 99.999% | No data loss |
| NFR-022 | Backup frequency | Every 6 hours | Database backups |
| NFR-023 | Recovery time objective | < 1 hour | Disaster recovery |
| NFR-024 | Recovery point objective | < 6 hours | Maximum data loss |
| NFR-025 | GitHub API fallback | Graceful degradation | On GitHub outage |

### 7.4 Usability Requirements

| ID | Requirement | Description |
|----|-------------|-------------|
| NFR-026 | Zero configuration | Default settings work for 80% of use cases |
| NFR-027 | Plain language results | All findings understandable by non-security experts |
| NFR-028 | One-click GitHub connect | Single button to initiate OAuth |
| NFR-029 | Progress visibility | Real-time scan progress updates |
| NFR-030 | Error messages | Clear, actionable error descriptions |
| NFR-031 | Mobile responsive | Dashboard works on tablet/mobile |
| NFR-032 | Keyboard navigation | Full keyboard accessibility |
| NFR-033 | Documentation | Comprehensive help docs and examples |

---

## 8. Data Requirements

### 8.1 Data Models

#### Prompt File Record

```sql
CREATE TABLE prompt_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id),
  user_id UUID NOT NULL REFERENCES users(id),
  filename VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  format VARCHAR(20) NOT NULL, -- 'markdown', 'json', 'yaml', 'text'
  metadata JSONB,
  prompt_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### Parsed Prompt Record

```sql
CREATE TABLE parsed_prompts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  prompt_file_id UUID NOT NULL REFERENCES prompt_files(id),
  scan_id UUID REFERENCES scans(id),
  sequence_number INTEGER NOT NULL,
  raw_text TEXT NOT NULL,
  intent VARCHAR(50), -- 'sql_injection', 'xss', 'secrets', etc.
  intent_confidence DECIMAL(3,2),
  entities JSONB, -- extracted entities
  mapped_tools TEXT[], -- array of tool names
  mapping_rationale TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### GitHub Connection Record

```sql
CREATE TABLE github_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  github_user_id BIGINT NOT NULL,
  github_username VARCHAR(255) NOT NULL,
  github_email VARCHAR(255),
  github_avatar_url TEXT,
  access_token_encrypted BYTEA NOT NULL,
  refresh_token_encrypted BYTEA,
  token_expires_at TIMESTAMPTZ,
  scopes TEXT[],
  connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  UNIQUE(user_id, github_user_id)
);
```

#### GitHub Repository Record

```sql
CREATE TABLE github_repositories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  github_connection_id UUID NOT NULL REFERENCES github_connections(id),
  project_id UUID REFERENCES projects(id),
  github_repo_id BIGINT NOT NULL,
  owner VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  full_name VARCHAR(512) NOT NULL,
  description TEXT,
  default_branch VARCHAR(255) NOT NULL DEFAULT 'main',
  is_private BOOLEAN NOT NULL DEFAULT false,
  language VARCHAR(100),
  topics TEXT[],
  last_synced_at TIMESTAMPTZ,
  webhook_id BIGINT,
  webhook_secret_encrypted BYTEA,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(github_connection_id, github_repo_id)
);
```

#### Generated Test Case Record

```sql
CREATE TABLE generated_test_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id),
  user_id UUID NOT NULL REFERENCES users(id),
  source_type VARCHAR(20) NOT NULL, -- 'code', 'brd', 'both'
  code_source TEXT, -- repository URL or file path
  brd_source TEXT, -- BRD file path or URL
  code_analysis JSONB, -- analysis results
  brd_analysis JSONB, -- parsed requirements
  generated_prompts TEXT NOT NULL, -- markdown content
  prompt_count INTEGER NOT NULL,
  categories JSONB, -- breakdown by category
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 8.2 Data Retention

| Data Type | Retention Period | Reason |
|-----------|------------------|--------|
| Scan results | 1 year | Audit trail |
| Prompt files | 90 days | Space management |
| GitHub tokens | Until revoked | Required for access |
| Generated test cases | 90 days | Space management |
| Webhook logs | 30 days | Debugging |
| Audit logs | 7 years | Compliance |

### 8.3 Data Privacy

| Data Element | Sensitivity | Protection |
|--------------|-------------|------------|
| GitHub access tokens | Critical | AES-256 encryption |
| Repository code | High | Deleted after scan |
| User email | Medium | PII protection |
| Scan findings | Medium | Project-level access control |
| Prompt content | Low | Standard encryption |

---

## 9. Integration Requirements

### 9.1 External System Integrations

| System | Integration Type | Purpose |
|--------|------------------|---------|
| GitHub | OAuth 2.0 + REST API | Repository access |
| GitLab | OAuth 2.0 + REST API | Future: Repository access |
| Sigstore | API | Attestation signing |
| Rekor | API | Transparency log |
| Slack | Webhook | Notifications |
| Discord | Webhook | Notifications |
| Jira | API | Issue creation |
| Linear | API | Issue creation |

### 9.2 Internal System Integrations

| System | Integration | Purpose |
|--------|-------------|---------|
| Scan Queue (BullMQ) | Direct | Job orchestration |
| Scanner Containers | Docker API | Tool execution |
| PostgreSQL | Drizzle ORM | Data persistence |
| Redis | ioredis | Caching, sessions |
| MCP Server | Existing | Claude Code integration |

### 9.3 API Contracts

#### POST /api/v1/prompts/parse

**Request:**
```json
{
  "projectId": "uuid",
  "file": "<multipart file upload>",
  // OR
  "filePath": "/path/to/prompts.md",
  // OR
  "content": "# Prompts\n- Check for SQL injection\n- Scan dependencies",
  "options": {
    "confidenceThreshold": 0.7,
    "outputFormat": "json",
    "executeImmediately": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "promptFileId": "uuid",
    "scanId": "uuid",
    "parsedPrompts": [...],
    "summary": {...}
  }
}
```

#### POST /api/v1/prompts/generate

**Request:**
```json
{
  "projectId": "uuid",
  "codeSource": {
    "type": "github",
    "repository": "user/repo",
    "branch": "main"
  },
  "brdSource": {
    "type": "upload",
    "file": "<multipart file>"
  },
  "options": {
    "categories": ["injection", "authentication", "dependencies"],
    "maxPrompts": 100,
    "prioritySort": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "generationId": "uuid",
    "promptContent": "# Security Test Prompts\n...",
    "promptCount": 38,
    "categories": {...},
    "codeAnalysis": {...},
    "brdAnalysis": {...}
  }
}
```

#### GET /api/v1/github/connect

**Response:** Redirect to GitHub OAuth authorization URL

#### GET /api/v1/github/callback

**Query Parameters:**
- `code`: Authorization code from GitHub
- `state`: CSRF state token

**Response:** Redirect to dashboard with success/error

#### GET /api/v1/github/repositories

**Response:**
```json
{
  "success": true,
  "data": {
    "repositories": [
      {
        "id": "uuid",
        "githubId": 123456,
        "owner": "user",
        "name": "repo",
        "fullName": "user/repo",
        "description": "...",
        "defaultBranch": "main",
        "isPrivate": false,
        "language": "Python",
        "topics": ["security", "api"]
      }
    ],
    "pagination": {
      "page": 1,
      "perPage": 30,
      "total": 45,
      "hasMore": true
    }
  }
}
```

#### POST /api/v1/github/repositories/{repoId}/scan

**Request:**
```json
{
  "branch": "main",
  "commitSha": "abc123",
  "profile": "standard",
  "promptFile": "security-tests.md"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "scanId": "uuid",
    "status": "queued"
  }
}
```

---

## 10. User Interface Requirements

### 10.1 Dashboard Pages

#### Prompt Upload Page

| Element | Description | Interaction |
|---------|-------------|-------------|
| File Dropzone | Drag-and-drop area for prompt files | Accepts .md, .txt, .json, .yaml |
| Text Input | Manual prompt entry area | Multi-line textarea |
| Parse Button | Initiate parsing | Shows progress spinner |
| Prompt Preview | Parsed prompts display | Checkbox list format |
| Tool Mapping View | Show mapped tools per prompt | Expandable details |
| Execute Button | Run scans for parsed prompts | Requires confirmation |

#### Test Generator Page

| Element | Description | Interaction |
|---------|-------------|-------------|
| Code Source Selector | Choose repo/upload/path | Radio buttons |
| Repository Picker | Select connected GitHub repo | Dropdown with search |
| Branch Selector | Choose branch to analyze | Dropdown |
| BRD Upload | Upload BRD document | File dropzone |
| Category Filters | Select test categories | Multi-select checkboxes |
| Generate Button | Start generation | Shows progress |
| Results Preview | Generated prompts display | Markdown preview |
| Download Button | Export prompts as .md | Triggers download |
| Execute Button | Run generated prompts | Links to scan |

#### GitHub Connection Page

| Element | Description | Interaction |
|---------|-------------|-------------|
| Connect Button | Initiate GitHub OAuth | Opens popup/redirect |
| Connected Account | Show connected GitHub user | Avatar, username, email |
| Repository List | Show accessible repositories | Sortable, filterable table |
| Repository Card | Individual repo details | Name, language, visibility badge |
| Branch Dropdown | Select branch per repo | Shows default first |
| Scan Button | Quick scan repository | Opens scan config modal |
| Disconnect Button | Revoke GitHub connection | Requires confirmation |
| Webhook Status | Show webhook configuration | Enable/disable toggle |

### 10.2 UI Mockups

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Code Hardener                                    [User Avatar] ▼  [Logout]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                                            │
│  │ Dashboard   │   SECURITY TEST PROMPTS                                   │
│  ├─────────────┤   ─────────────────────                                   │
│  │ Projects    │                                                            │
│  ├─────────────┤   ┌─────────────────────────────────────────────────────┐  │
│  │ ★ Prompts  │   │                                                     │  │
│  │   Upload    │   │   📄 Drop your prompt file here                    │  │
│  │   Generate  │   │      or click to browse                            │  │
│  ├─────────────┤   │                                                     │  │
│  │ GitHub      │   │   Supported: .md, .txt, .json, .yaml               │  │
│  │   Repos     │   │                                                     │  │
│  │   Settings  │   └─────────────────────────────────────────────────────┘  │
│  ├─────────────┤                                                            │
│  │ Scans       │   ── OR enter prompts directly ──                         │
│  ├─────────────┤                                                            │
│  │ Settings    │   ┌─────────────────────────────────────────────────────┐  │
│  └─────────────┘   │ - Check for SQL injection in login                 │  │
│                    │ - Scan dependencies for CVEs                        │  │
│                    │ - Verify authentication security                    │  │
│                    │ - Check for hardcoded secrets                       │  │
│                    │                                                     │  │
│                    └─────────────────────────────────────────────────────┘  │
│                                                                             │
│                    [Parse Prompts]                                         │
│                                                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  PARSED PROMPTS (4)                                        [Execute All]   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐
│  │ ☑ Check for SQL injection in login                                     │
│  │   Intent: sql_injection (95% confidence)                               │
│  │   Tools: opengrep, bandit                                              │
│  │   ▼ View mapping rationale                                             │
│  ├─────────────────────────────────────────────────────────────────────────┤
│  │ ☑ Scan dependencies for CVEs                                           │
│  │   Intent: dependencies (98% confidence)                                │
│  │   Tools: trivy, grype                                                  │
│  │   ▼ View mapping rationale                                             │
│  ├─────────────────────────────────────────────────────────────────────────┤
│  │ ☑ Verify authentication security                                       │
│  │   Intent: authentication (88% confidence)                              │
│  │   Tools: opengrep, bandit, eslint-security                            │
│  │   ▼ View mapping rationale                                             │
│  ├─────────────────────────────────────────────────────────────────────────┤
│  │ ☑ Check for hardcoded secrets                                          │
│  │   Intent: secrets (99% confidence)                                     │
│  │   Tools: gitleaks, detect-secrets                                      │
│  │   ▼ View mapping rationale                                             │
│  └─────────────────────────────────────────────────────────────────────────┘
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Code Hardener                                    [User Avatar] ▼  [Logout]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                                            │
│  │ Dashboard   │   CONNECT GITHUB                                          │
│  ├─────────────┤   ──────────────────                                       │
│  │ Projects    │                                                            │
│  ├─────────────┤   ┌───────────────────────────────────────────────────┐   │
│  │ Prompts     │   │                                                   │   │
│  ├─────────────┤   │   🔗  Connect your GitHub account to:            │   │
│  │ ★ GitHub   │   │                                                   │   │
│  │   Repos     │   │   ✓ Scan repositories directly                   │   │
│  │   Settings  │   │   ✓ Auto-scan on push (webhooks)                 │   │
│  ├─────────────┤   │   ✓ Track security across commits                │   │
│  │ Scans       │   │   ✓ Comment on pull requests                     │   │
│  ├─────────────┤   │                                                   │   │
│  │ Settings    │   │   [🐙 Connect with GitHub]                       │   │
│  └─────────────┘   │                                                   │   │
│                    │   We request: repo, read:user, user:email        │   │
│                    │                                                   │   │
│                    └───────────────────────────────────────────────────┘   │
│                                                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│  ✅ CONNECTED: @octocat                                   [Disconnect]     │
│                                                                             │
│  YOUR REPOSITORIES                          🔍 Search    [↑↓ Sort by]     │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐
│  │ 📁 octocat/hello-world                              🔓 Public          │
│  │    Hello World repository for testing                                  │
│  │    JavaScript • main • Updated 2 days ago                              │
│  │    [Select Branch ▼]  [Scan Now]                                       │
│  ├─────────────────────────────────────────────────────────────────────────┤
│  │ 📁 octocat/my-api                                   🔒 Private         │
│  │    REST API for my application                                         │
│  │    Python • main • Updated 5 hours ago                                 │
│  │    [Select Branch ▼]  [Scan Now]                                       │
│  ├─────────────────────────────────────────────────────────────────────────┤
│  │ 📁 octocat/infrastructure                           🔒 Private         │
│  │    Terraform and Kubernetes configs                                    │
│  │    HCL • main • Updated 1 week ago                                     │
│  │    [Select Branch ▼]  [Scan Now]                                       │
│  └─────────────────────────────────────────────────────────────────────────┘
│                                                                             │
│  Showing 3 of 45 repositories                          [Load More]         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Security Requirements

### 11.1 Authentication & Authorization

| ID | Requirement | Implementation |
|----|-------------|----------------|
| SEC-001 | OAuth tokens encrypted at rest | AES-256-GCM with per-user keys |
| SEC-002 | Token refresh before expiry | Background job 5 min before expiry |
| SEC-003 | Scope validation on API calls | Verify token has required scopes |
| SEC-004 | GitHub connection per user | No cross-user token access |
| SEC-005 | Webhook signature validation | HMAC-SHA256 verification |
| SEC-006 | State parameter for CSRF | Cryptographic random, single-use |
| SEC-007 | Token revocation on disconnect | Immediate GitHub token revocation |

### 11.2 Data Protection

| ID | Requirement | Implementation |
|----|-------------|----------------|
| SEC-008 | Repository code isolation | Per-scan isolated containers |
| SEC-009 | Code deletion after scan | Automatic cleanup, verified |
| SEC-010 | Prompt content validation | Sanitize before storage |
| SEC-011 | No code logging | Exclude code from application logs |
| SEC-012 | Encryption in transit | TLS 1.2+ for all connections |
| SEC-013 | Database encryption | PostgreSQL TDE |

### 11.3 Input Validation

| ID | Requirement | Implementation |
|----|-------------|----------------|
| SEC-014 | Prompt file size limit | 10MB maximum |
| SEC-015 | Prompt content sanitization | Strip executable content |
| SEC-016 | Path traversal prevention | Validate file paths |
| SEC-017 | Repository URL validation | Whitelist GitHub domains |
| SEC-018 | Branch name validation | Alphanumeric + limited special chars |
| SEC-019 | Webhook payload validation | Schema validation |

### 11.4 Rate Limiting

| ID | Requirement | Limit |
|----|-------------|-------|
| SEC-020 | OAuth flow rate limit | 10 per minute per IP |
| SEC-021 | Prompt parse rate limit | 100 per hour per user |
| SEC-022 | Test generation rate limit | 20 per hour per user |
| SEC-023 | Repository list rate limit | 60 per minute per user |
| SEC-024 | Webhook rate limit | 1000 per hour per repository |

---

## 12. Compliance Requirements

### 12.1 Regulatory Compliance

| Requirement | Standard | Implementation |
|-------------|----------|----------------|
| Audit logging | SOC 2 | Log all OAuth events, scans, data access |
| Access control | SOC 2 | RBAC, least privilege |
| Encryption | SOC 2, ISO 27001 | AES-256 at rest, TLS in transit |
| Data retention | GDPR | Configurable retention, deletion on request |
| Right to erasure | GDPR | User data export and deletion |
| Vendor security | SOC 2 | GitHub's SOC 2 compliance |

### 12.2 Audit Requirements

| Event | Logged Data | Retention |
|-------|-------------|-----------|
| GitHub OAuth connect | User ID, GitHub ID, timestamp, scopes | 7 years |
| GitHub OAuth disconnect | User ID, GitHub ID, timestamp, reason | 7 years |
| Repository scan initiated | User ID, repo, branch, commit, timestamp | 7 years |
| Prompt file uploaded | User ID, filename, size, timestamp | 7 years |
| Test cases generated | User ID, sources, prompt count, timestamp | 7 years |
| Webhook received | Repo, event type, timestamp | 1 year |

---

## 13. Acceptance Criteria

### 13.1 Prompt Parser Service

| Scenario | Given | When | Then |
|----------|-------|------|------|
| Parse Markdown file | Valid .md file with 10 prompts | User uploads file | All 10 prompts parsed with intents |
| Handle malformed file | Invalid file format | User uploads file | Clear error message returned |
| Map prompts to tools | Parsed prompts with intents | System maps tools | Each prompt has ≥1 mapped tool |
| Execute scans | Mapped prompts | User clicks execute | Scan job created, results returned |
| Handle unknown intent | Prompt with unclear intent | System parses | Low confidence score, multiple options |

### 13.2 Test Case Generator

| Scenario | Given | When | Then |
|----------|-------|------|------|
| Generate from code | GitHub repository selected | User generates | Test prompts for detected languages/frameworks |
| Generate from BRD | BRD document uploaded | User generates | Test prompts aligned with requirements |
| Generate from both | Code + BRD provided | User generates | Comprehensive prompts covering both |
| Export prompts | Generated prompts | User downloads | Valid .md file downloaded |
| Execute generated | Generated prompts | User executes | Scans run, results displayed |

### 13.3 GitHub Integration

| Scenario | Given | When | Then |
|----------|-------|------|------|
| OAuth connect | User not connected | User clicks connect | Redirect to GitHub, then back with connection |
| List repositories | User connected | User views repo page | All accessible repos displayed |
| Scan repository | Repository selected | User clicks scan | Code cloned, scanned, results shown |
| Webhook scan | Push webhook received | Code pushed to repo | Auto-scan triggered |
| Disconnect | User connected | User clicks disconnect | Token revoked, connection removed |

---

## 14. Appendices

### Appendix A: Tool Mapping Reference

| Security Concern | Primary Tools | Secondary Tools | Languages/Contexts |
|------------------|---------------|-----------------|-------------------|
| SQL Injection | opengrep, bandit | eslint-security | Python, JS, Java |
| XSS | opengrep, eslint-security | nuclei | JS, HTML |
| CSRF | opengrep | zap | All web frameworks |
| Authentication Bypass | opengrep, bandit | zap | All |
| Insecure Deserialization | opengrep | bandit | Python, Java |
| Secrets Exposure | gitleaks, detect-secrets | - | All |
| Vulnerable Dependencies | trivy, grype | - | All |
| Container Security | trivy | grype | Docker |
| IaC Misconfig | checkov | trivy | Terraform, K8s |
| API Security | zap, nuclei | restler | REST, GraphQL |
| SSRF | opengrep | nuclei | All |
| Path Traversal | opengrep | bandit | All |
| Command Injection | opengrep, bandit | - | Python, JS, Shell |
| XXE | opengrep | - | Java, PHP |
| Broken Access Control | opengrep | zap | All |

### Appendix B: Intent Classification Keywords

```yaml
sql_injection:
  keywords:
    - sql injection
    - sqli
    - database injection
    - query injection
    - parameterized query
    - prepared statement
  patterns:
    - "check.*sql.*injection"
    - "test.*database.*security"
    - "verify.*parameterized"

xss:
  keywords:
    - xss
    - cross-site scripting
    - script injection
    - html injection
    - dom-based
    - reflected
    - stored xss
  patterns:
    - "check.*xss"
    - "test.*cross.*site"
    - "verify.*output.*encoding"

secrets:
  keywords:
    - secrets
    - credentials
    - api keys
    - passwords
    - tokens
    - hardcoded
    - exposed
  patterns:
    - "find.*secrets"
    - "check.*hardcoded"
    - "scan.*credentials"

dependencies:
  keywords:
    - dependencies
    - packages
    - libraries
    - cve
    - vulnerabilities
    - outdated
    - sca
  patterns:
    - "scan.*dependencies"
    - "check.*packages"
    - "find.*cve"

authentication:
  keywords:
    - authentication
    - login
    - password
    - session
    - jwt
    - oauth
    - mfa
    - 2fa
  patterns:
    - "test.*authentication"
    - "verify.*login"
    - "check.*password.*security"

authorization:
  keywords:
    - authorization
    - access control
    - permissions
    - rbac
    - acl
    - privilege
    - idor
  patterns:
    - "test.*authorization"
    - "check.*access.*control"
    - "verify.*permissions"
```

### Appendix C: GitHub API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login/oauth/authorize` | GET | Start OAuth flow |
| `/login/oauth/access_token` | POST | Exchange code for token |
| `/user` | GET | Get authenticated user |
| `/user/repos` | GET | List user repositories |
| `/orgs/{org}/repos` | GET | List org repositories |
| `/repos/{owner}/{repo}` | GET | Get repository details |
| `/repos/{owner}/{repo}/branches` | GET | List branches |
| `/repos/{owner}/{repo}/branches/{branch}` | GET | Get branch details |
| `/repos/{owner}/{repo}/commits/{sha}` | GET | Get commit details |
| `/repos/{owner}/{repo}/zipball/{ref}` | GET | Download repository |
| `/repos/{owner}/{repo}/contents/{path}` | GET | Get file contents |
| `/repos/{owner}/{repo}/hooks` | POST | Create webhook |
| `/repos/{owner}/{repo}/hooks/{id}` | DELETE | Delete webhook |

### Appendix D: Error Codes

| Code | Message | Resolution |
|------|---------|------------|
| PROMPT_PARSE_001 | Invalid file format | Use .md, .txt, .json, or .yaml |
| PROMPT_PARSE_002 | File too large | Maximum 10MB |
| PROMPT_PARSE_003 | No prompts found | Add prompt items to file |
| PROMPT_MAP_001 | Unknown intent | Rephrase prompt or specify tool |
| PROMPT_MAP_002 | No tools available | Check tool availability |
| GEN_001 | Code analysis failed | Verify repository access |
| GEN_002 | BRD parse failed | Check BRD file format |
| GEN_003 | Generation timeout | Reduce scope or retry |
| GH_AUTH_001 | OAuth state mismatch | Restart OAuth flow |
| GH_AUTH_002 | Token exchange failed | Retry or contact support |
| GH_AUTH_003 | Insufficient scopes | Re-authorize with required scopes |
| GH_REPO_001 | Repository not found | Check permissions |
| GH_REPO_002 | Branch not found | Verify branch name |
| GH_REPO_003 | Clone failed | Check repository size |
| GH_WEBHOOK_001 | Signature invalid | Check webhook secret |
| GH_WEBHOOK_002 | Event not supported | Only push/PR supported |

### Appendix E: Glossary

| Term | Definition |
|------|------------|
| BRD | Business Requirements Document |
| CWE | Common Weakness Enumeration |
| DAST | Dynamic Application Security Testing |
| IaC | Infrastructure as Code |
| Intent | The security concern expressed in a prompt |
| MCP | Model Context Protocol |
| NLU | Natural Language Understanding |
| OAuth | Open Authorization protocol |
| OWASP | Open Web Application Security Project |
| Prompt | Natural language security test instruction |
| SARIF | Static Analysis Results Interchange Format |
| SAST | Static Application Security Testing |
| SCA | Software Composition Analysis |
| SBOM | Software Bill of Materials |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-11 | Code Hardener Team | Initial draft |

---

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Product Owner | | | |
| Engineering Lead | | | |
| Security Lead | | | |
| QA Lead | | | |
