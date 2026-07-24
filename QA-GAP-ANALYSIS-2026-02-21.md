# Code Hardener: Comprehensive QA Gap Analysis

**Date**: 2026-02-21
**QA Agent**: qa (Opus 4.6)
**Scope**: PRD-BRD v2.0 vs. actual implementation in backend/, dashboard/, postgres/, docker-compose.yml
**BRD-tracker.json claims**: 35/35 requirements "completed" (100%)

---

## EXECUTIVE SUMMARY

**BRD-tracker.json is misleading.** It tracks 35 requirements covering scanner integrations, the MCP server, risk scoring, and the assurance engine. Those 35 requirements ARE largely implemented and functional. However, the BRD-tracker covers only a fraction of what the PRD-BRD document actually specifies. The PRD-BRD describes an entire product platform with 5 integration methods, 4 pricing tiers with enforcement, compliance frameworks, container isolation, Kubernetes orchestration, SDK distribution, platform-native integrations, and more. The majority of those features have NO requirements in the tracker and NO implementation.

**Verdict: NOT READY FOR RELEASE**

### Completion Summary

| Category | PRD Scope | Implemented | Gap |
|----------|-----------|-------------|-----|
| Scanner Integrations (27 in PRD) | 27 tools | 30+ scanners (exceeds PRD) | EXCEEDS -- see notes |
| Integration Method 1: NLU/Prompt | Full NLU pipeline | Partial (prompt parser exists) | PARTIAL |
| Integration Method 2: MCP Server | Full MCP w/ 7 tools per PRD | 11+ tools, SSE transport | IMPLEMENTED |
| Integration Method 3: Claude Code Skill | Publishable skill package | Not packaged | NOT IMPLEMENTED |
| Integration Method 4: REST API | 6 endpoints per PRD | 20+ route files | IMPLEMENTED (exceeds PRD) |
| Integration Method 5: Platform Integrations | Replit, Lovable, Bolt, GitHub Actions, etc. | GitHub only | MOSTLY MISSING |
| Pricing/Billing Enforcement | Tier limits enforced at scan time | Plans defined, Stripe integrated, NO enforcement at scan time | CRITICAL GAP |
| Attestation/Sigstore | Full Sigstore + Rekor + in-toto | Implemented with Ed25519 local fallback | IMPLEMENTED |
| Risk Score (0-1000) | Deduction-based algorithm | Implemented (different formula) | IMPLEMENTED |
| Badges | SVG badge generation | Full implementation | IMPLEMENTED |
| Plain-Language Translation | CWE/OWASP translation | Pattern-based translator | IMPLEMENTED |
| Policy-as-Code (YAML + Rego) | OPA + YAML policies | OPA scanner + policies controller | PARTIAL |
| Webhook Notifications | Configurable webhooks | Webhook controller + queue | IMPLEMENTED |
| Container Isolation | gVisor/Firecracker per PRD | Docker only (no gVisor/Firecracker) | NOT IMPLEMENTED |
| Kubernetes/KEDA | K8s orchestration + autoscaling | Docker Compose only | NOT IMPLEMENTED |
| Row-Level Security | PostgreSQL RLS for multi-tenancy | NOT implemented -- app-level WHERE clauses | NOT IMPLEMENTED |
| SSO/SAML | Enterprise SSO | Not implemented | NOT IMPLEMENTED |
| SDK Distribution | npm/pip/go packages | Not published | NOT IMPLEMENTED |
| GitHub Actions/GitLab CI | CI/CD marketplace actions | Not built | NOT IMPLEMENTED |
| Auto-Fix / Remediation | One-click auto-fix | Remediation suggestions exist, no auto-apply | PARTIAL |
| Dashboard | Full security dashboard | 30+ pages implemented | IMPLEMENTED |
| Database Schema | Complete schema | 20+ tables, migrations | IMPLEMENTED |
| GitHub OAuth | OAuth integration | Full with SSRF protection | IMPLEMENTED |
| Compliance Reports | SOC 2/ISO 27001 evidence | Not implemented | NOT IMPLEMENTED |

---

## DETAILED GAP ANALYSIS

### 1. SCANNER COVERAGE GAPS

**PRD specifies 27 tools. Implementation has 30+ scanners (exceeds PRD).**

| PRD Tool | License | Scanner File Exists | Status |
|----------|---------|---------------------|--------|
| Bandit | Apache 2.0 | bandit.ts | IMPLEMENTED |
| Gosec | Apache 2.0 | gosec.ts | IMPLEMENTED |
| ESLint Security | Apache 2.0 | eslint-security.ts | IMPLEMENTED |
| PMD | BSD | pmd.ts | IMPLEMENTED |
| Opengrep | LGPL-2.1 | opengrep.ts | IMPLEMENTED |
| OWASP ZAP | Apache 2.0 | zap.ts | IMPLEMENTED |
| Trivy | Apache 2.0 | trivy.ts | IMPLEMENTED |
| Nuclei | MIT | nuclei.ts | IMPLEMENTED |
| Gitleaks CLI | MIT | gitleaks.ts | IMPLEMENTED |
| detect-secrets | Apache 2.0 | detect-secrets.ts | IMPLEMENTED |
| Checkov | Apache 2.0 | checkov.ts | IMPLEMENTED |
| Locust | MIT | locust.ts | IMPLEMENTED |
| **Gatling** | **Apache 2.0** | **NO FILE** | **NOT IMPLEMENTED** |
| Artillery Core | MPL-2.0 | artillery.ts | IMPLEMENTED |
| Newman | Apache 2.0 | newman.ts | IMPLEMENTED |
| **WireMock** | **Apache 2.0** | **NO FILE** | **NOT IMPLEMENTED** |
| Pact | MIT | pact.ts | IMPLEMENTED |
| RESTler | MIT | restler.ts | IMPLEMENTED |
| Playwright | Apache 2.0 | playwright.ts | IMPLEMENTED |
| BackstopJS | MIT | backstopjs.ts (backstop.ts) | IMPLEMENTED |
| Pa11y | MIT | pa11y.ts | IMPLEMENTED |
| Syft | Apache 2.0 | syft.ts | IMPLEMENTED |
| Grype | Apache 2.0 | grype.ts | IMPLEMENTED |
| Falco | Apache 2.0 | Not in scanner dir | NOT IN PIPELINE |
| Toxiproxy | MIT | Not in scanner dir | NOT IN PIPELINE |
| DefectDojo | BSD 3-Clause | Via services/defectdojo/ | IMPLEMENTED (separate service) |
| Allure | Apache 2.0 | allure.ts | IMPLEMENTED |
| Flyway Community | Apache 2.0 | Not in scanner dir | NOT IN PIPELINE |
| Cosign/Sigstore | Apache 2.0 | cosign.ts | IMPLEMENTED |
| in-toto | Apache 2.0 | in-toto.ts | IMPLEMENTED |
| Open Policy Agent | Apache 2.0 | opa.ts | IMPLEMENTED |

**Extra tools not in PRD but implemented**: k6.ts, garak.ts, pip-audit.ts, dockle.ts, conftest.ts

**Key Scanner Gaps**:
- **Gatling**: Referenced in NLU patterns and tools controller but NO scanner implementation exists
- **WireMock**: Listed in BRD-tracker as REQ-022 "completed" but NO scanner file exists anywhere in the codebase
- **Falco**: BRD-tracker REQ-033 claims "completed" but no scanner file in /services/scanners/. Only in scanner-registry.ts metadata.
- **Toxiproxy**: BRD-tracker REQ-034 claims "completed" but no scanner file exists
- **Flyway**: BRD-tracker REQ-028 claims "completed" but no scanner file in the scanners directory

**BRD-tracker Integrity Issue**: REQ-022 (WireMock), REQ-028 (Flyway), REQ-033 (Falco), REQ-034 (Toxiproxy) all claim "completed" status with artifact paths that DO NOT MATCH actual file names. The tracker lists `/backend/src/services/scanners/wiremock-scanner.ts` but the actual directory has NO wiremock file at all. This is a data integrity problem in the tracker itself.

---

### 2. INTEGRATION METHODS (5 specified in PRD)

#### Method 1: Natural Language Prompt -- PARTIAL

**PRD Spec**: Users invoke via natural language in any AI assistant. Code Hardener processes the request.

**Implementation**:
- `/backend/src/services/prompt-parser/` exists with NLU (intent classifier, entity extractor, synonym mapping)
- `/backend/src/routes/prompts.routes.ts` and `/backend/src/controllers/prompts.controller.ts` exist
- Classifies intents like "scan", "check", "review" etc.

**Gap**: The prompt parser translates natural language to tool invocations but does NOT connect to any AI assistant (Cursor, Copilot, ChatGPT). It is a local NLU service, not a hosted AI integration. The conversational response format shown in the PRD (with icons, formatted findings, "Want me to fix these automatically?") is not implemented.

#### Method 2: MCP Server -- IMPLEMENTED

**PRD Spec**: MCP server with 7 tools (scan_project, scan_file, scan_diff, get_score, get_attestation, fix_issue, explain_finding)

**Implementation**:
- `/backend/src/services/mcp/server.ts` -- 11 MCP tools (scan, status, findings, fix, score, attestation, sbom, compare, dismiss, history, report) plus high-level tools
- `/backend/src/services/mcp/sse-transport.ts` -- SSE transport for remote connections
- `/backend/src/services/mcp/tools/` -- Additional orchestrated tools

**Gap**: Tool names differ from PRD (codehardener_scan vs scan_project, etc.) but functionality is covered. `scan_file` and `scan_diff` from the PRD are NOT directly implemented as individual tools.

#### Method 3: Claude Code Skill -- NOT IMPLEMENTED

**PRD Spec**: `claude skill add codehardener/security-scan`, `.claude/codehardener.yaml` configuration

**Implementation**: No skill package exists. No package published to any registry. No `.claude/codehardener.yaml` configuration support.

**Gap**: Complete. This is a P1 gap for Phase 2 of the PRD roadmap.

#### Method 4: REST API -- IMPLEMENTED (Exceeds PRD)

**PRD Spec**: 6 endpoints: `/v1/scan`, `/v1/scan/{id}`, `/v1/scan/{id}/attestation`, `/v1/score/{repo}`, `/v1/badge/{repo}`, `/v1/fix`

**Implementation**: 20+ route files covering scans, findings, attestations, badges, policies, webhooks, billing, teams, notifications, integrations, reports, tools, projects, api-keys, prompts, test-generator, github.

**Gap**: URL structure differs (e.g., `/api/v1/scans` not `/v1/scan`). Badge endpoint is `/api/v1/badges/public/{token}` not `/v1/badge/{repo}`. The PRD shows `https://api.codehardener.dev/v1/scan` which implies a production deployment that does not exist.

#### Method 5: Platform-Native Integrations -- MOSTLY MISSING

**PRD Spec**: Pre-built integrations for Replit, Lovable, Bolt.new, v0.dev, GitHub Actions, GitLab CI, Vercel, Netlify

**Implementation**:
- GitHub OAuth integration: IMPLEMENTED (full OAuth flow, webhook processing, repository service)
- All other platform integrations: NOT IMPLEMENTED

**Gap**:
- No Replit extension
- No Lovable integration
- No Bolt.new native support
- No v0.dev integration
- No GitHub Action (codehardener/action@v1)
- No GitLab CI template
- No Vercel build plugin
- No Netlify build plugin
- No CLI tool (`@codehardener/cli`)

---

### 3. PRICING/BILLING TIER ENFORCEMENT -- CRITICAL GAP

**PRD Spec**: 4 tiers (Free: 3 projects/200 scans, Pro: 10 projects/unlimited, Team: 50 projects/unlimited/SSO, Enterprise: unlimited/self-hosted)

**Implementation**:
- Plan definitions exist in `billing.controller.ts` with correct limits
- Stripe integration is implemented (checkout, portal, webhooks, subscription management)
- Usage tracking exists (project count, scan count per month)
- Dashboard billing page exists

**CRITICAL GAP**: **Tier limits are NOT enforced at scan/project creation time.**

Evidence:
- `scans.controller.ts` has NO references to `plan_id`, `tier`, `subscription`, or any limit checking
- No middleware checks subscription tier before allowing scan creation
- No middleware checks project count against tier limit before allowing project creation
- A Free user could create unlimited projects and unlimited scans because the billing controller only REPORTS usage -- it does not BLOCK actions

This is a critical business risk. Without enforcement, the Free tier is effectively unlimited.

---

### 4. COMPLIANCE/SECURITY FEATURES

#### Container Isolation -- NOT IMPLEMENTED

**PRD Spec**: gVisor sandbox for SAST, Firecracker MicroVM for DAST, Kata Containers for untrusted code, seccomp for quick scans

**Implementation**: All scanners run in a single Docker container (`Dockerfile.scanner`). No gVisor, Firecracker, or Kata Containers. No per-scan isolation. No ephemeral containers per scan.

**Gap**: The container isolation strategy described in the PRD (table with 4 risk levels) is entirely absent. All scans share one persistent container.

#### Row-Level Security -- NOT IMPLEMENTED

**PRD Spec**: PostgreSQL with row-level security for multi-tenancy

**Implementation**: No RLS policies defined in init.sql or migrations. Multi-tenancy is enforced purely at the application level via `WHERE user_id = $1` clauses in queries.

**Gap**: This is adequate for a single-tenant dev environment but does not meet the PRD's multi-tenancy security requirement.

#### Kubernetes/KEDA -- NOT IMPLEMENTED

**PRD Spec**: Kubernetes-based scan orchestration with KEDA autoscaling

**Implementation**: Docker Compose only. No Kubernetes manifests, Helm charts, or KEDA configuration exist anywhere in the project.

**Gap**: Complete. This is Phase 1 infrastructure per the PRD.

#### SSO/SAML -- NOT IMPLEMENTED

**PRD Spec**: Team tier includes SSO/SAML integration

**Implementation**: Authentication is email/password + JWT + GitHub OAuth only. No SAML, no OIDC federation, no SSO provider integration.

**Gap**: Required for Team/Enterprise tiers.

#### SOC 2 / ISO 27001 / FedRAMP -- NOT IMPLEMENTED

**PRD Spec**: SOC 2 Type I/II, ISO 27001 gap analysis, FedRAMP LI-SaaS

**Implementation**:
- Audit log table exists in the database schema
- Some compliance mappings documented in the PRD
- No automated compliance report generation
- No compliance evidence collection
- No continuous compliance monitoring

**Gap**: Compliance is documentation-only at this point. No tooling supports compliance evidence gathering.

#### GDPR -- NOT IMPLEMENTED

**PRD Spec**: Data minimization, right to erasure, processing records, EU data residency

**Implementation**: No GDPR-specific features (data export, data deletion on request, processing logs, data residency configuration).

---

### 5. ASSURANCE LAYER FEATURES

#### Feature 1: Intelligent Language Detection -- PARTIAL

**Implementation**: The scan pipeline selects scanners based on profile (quick, standard, comprehensive, etc.) but does NOT auto-detect programming languages to select appropriate scanners. The user must choose a profile or specify scanners explicitly.

**Gap**: The auto-detection of "Python (67%), JavaScript (28%), Dockerfile (5%)" shown in the PRD is not implemented.

#### Feature 2: Plain-Language Translation -- IMPLEMENTED

**Implementation**: `/backend/src/services/translator/plain-language.ts` provides pattern-based CWE/OWASP translation. MCP tools include translate_finding.

#### Feature 3: One-Click Auto-Fix -- PARTIAL

**Implementation**: `/backend/src/services/scanners/remediation.ts` exists. Fix descriptions are stored in findings. MCP `codehardener_fix` returns fix suggestions.

**Gap**: The PRD shows an interactive "Apply this fix? [Yes] [No]" flow that modifies code. The implementation only returns fix descriptions -- it does not apply code changes.

#### Feature 4: Risk Score Algorithm -- IMPLEMENTED (Different Formula)

**PRD Formula**:
- Base 1000, deduct 200/critical, 50/high, 10/medium, 2/low
- Bonuses for up-to-date deps, security headers, etc.

**Implementation**: Uses a logarithmic scoring algorithm (per risk-score.ts). The formula differs from the PRD but achieves the same 0-1000 range with the same risk level thresholds.

**Gap**: Minor. Bonuses for "deps up to date", "security headers present", "CSP configured", "HTTPS enforced" are NOT implemented. Only deductions exist.

#### Feature 5: Cryptographic Attestation -- IMPLEMENTED

**Implementation**: Full attestation pipeline with in-toto format, Ed25519 local signing, Sigstore/cosign support (when configured), Rekor transparency log recording.

#### Feature 6: Embeddable Trust Badges -- IMPLEMENTED

**Implementation**: Full SVG badge generation with multiple types (security-score, scan-status, findings-count, last-scan) and styles (flat, flat-square, for-the-badge).

#### Feature 7: Policy-as-Code -- PARTIAL

**Implementation**: OPA scanner exists. Policies controller exists with YAML policy storage. Policy evaluator service exists.

**Gap**: Full Rego policy evaluation via OPA is available through the scanner, but the PRD's `.codehardener/policy.yaml` configuration file support (read from repository) is not implemented. Policy evaluation is database-driven, not file-driven.

#### Feature 8: Webhook Notifications -- IMPLEMENTED

**Implementation**: Full webhook management (CRUD), delivery tracking, webhook queue, signature verification.

---

### 6. SDK / CLI DISTRIBUTION -- NOT IMPLEMENTED

**PRD Spec**:
- `npm install @codehardener/sdk`
- `pip install codehardener`
- `go get github.com/codehardener/sdk-go`
- `curl -fsSL https://codehardener.dev/install.sh | sh`

**Implementation**: None. No SDK packages exist. No CLI tool exists. No install script exists.

---

### 7. ARCHITECTURAL DEVIATIONS

| PRD Architecture | Actual Implementation | Severity |
|------------------|----------------------|----------|
| Three-tier architecture (Consumer/Orchestration/Execution) | Two-tier (Backend API + Scanner Worker) | Medium |
| gVisor sandbox per scan | Single shared Docker container | High |
| Kubernetes + KEDA | Docker Compose only | High |
| PostgreSQL RLS | Application-level WHERE clauses | Medium |
| Ephemeral scan containers | Persistent scanner container | High |
| Read-only filesystems for scans | Writable /scan-target | Medium |
| Network isolation per scan | Shared Docker network | High |
| Firecracker MicroVMs for DAST | Same container as SAST | High |
| Multi-region deployment | Single host | Low (expected for MVP) |
| Helm chart for on-premises | Not created | Low (Phase 3 per PRD) |

---

### 8. BRD-TRACKER INTEGRITY ISSUES

The BRD-tracker.json has several data integrity problems:

1. **REQ-022 (WireMock)**: Claims "completed" with artifact `/backend/src/services/scanners/wiremock-scanner.ts`. **This file does not exist.** No wiremock scanner file exists anywhere.

2. **REQ-028 (Flyway)**: Claims "completed" with artifact `/backend/src/services/scanners/flyway-scanner.ts`. **This file does not exist.** No flyway scanner file exists.

3. **REQ-033 (Falco)**: Claims "completed" with artifact `/backend/src/services/scanners/falco-scanner.ts`. **This file does not exist.**

4. **REQ-034 (Toxiproxy)**: Claims "completed" with artifact `/backend/src/services/scanners/toxiproxy-scanner.ts`. **This file does not exist.**

5. **REQ-035 (DefectDojo)**: Claims "completed" with artifact `/backend/src/services/scanners/defectdojo-scanner.ts`. **This file does not exist.** DefectDojo integration exists at `/backend/src/services/defectdojo/` as a separate service (client, import, product-sync), not as a scanner.

6. **REQ-036 (Allure)**: Claims artifact `/backend/src/services/scanners/allure-scanner.ts`. Actual file is `/backend/src/services/scanners/allure.ts` (no "-scanner" suffix).

7. **Tool count mismatch**: BRD-tracker claims 30 tools. PRD specifies 27. Implementation has 33 scanner files (including k6, garak, pip-audit, dockle, conftest which are extras). The k6 scanner EXISTS despite the PRD explicitly stating k6 was EXCLUDED due to AGPL licensing.

---

### 9. SECURITY CONCERNS

1. **k6 (AGPL-3.0) is included**: The PRD explicitly excludes k6 due to AGPL licensing risk. Yet `k6.ts` exists as a scanner and is included in the `performance` profile. This is a licensing compliance violation per the PRD's own requirements.

2. **Default dev secrets in docker-compose.yml**: `JWT_SECRET: dev-secret-change-in-production`, `N8N_API_KEY` hardcoded, `DD_SECRET_KEY: defectdojo-secret-key-change-in-production`. These are dev-only defaults but could ship to production if not changed.

3. **No tier enforcement**: As noted above, a Free user faces no actual limits. This is both a business and security risk (resource exhaustion).

4. **Shared scanner container**: All users' code is scanned in the same persistent container at `/scan-target`. There is no isolation between scans. A malicious repository could leave artifacts that affect subsequent scans.

---

## REQUIREMENTS NOT IN BRD-TRACKER (PRD-BRD FEATURES WITH NO TRACKING)

The BRD-tracker tracks 35 requirements. The following PRD features have NO corresponding requirement:

| PRD Feature | PRD Section | BRD-tracker Req | Status |
|-------------|-------------|-----------------|--------|
| Intelligent language auto-detection | Assurance Layer Feature 1 | NONE | Not implemented |
| One-click auto-fix (code modification) | Assurance Layer Feature 3 | NONE | Partial (suggestions only) |
| Risk score bonuses | Assurance Layer Feature 4 | NONE | Not implemented |
| Claude Code Skill package | Integration Method 3 | NONE | Not implemented |
| Replit extension | Integration Method 5 | NONE | Not implemented |
| Lovable integration | Integration Method 5 | NONE | Not implemented |
| Bolt.new native support | Integration Method 5 | NONE | Not implemented |
| v0.dev integration | Integration Method 5 | NONE | Not implemented |
| GitHub Action (marketplace) | Integration Method 5 | NONE | Not implemented |
| GitLab CI template | Integration Method 5 | NONE | Not implemented |
| Vercel build plugin | Integration Method 5 | NONE | Not implemented |
| Netlify build plugin | Integration Method 5 | NONE | Not implemented |
| CLI tool (@codehardener/cli) | SDK Installation | NONE | Not implemented |
| Node.js SDK | SDK Installation | NONE | Not implemented |
| Python SDK | SDK Installation | NONE | Not implemented |
| Go SDK | SDK Installation | NONE | Not implemented |
| Tier limit enforcement | Pricing Tiers | NONE | Not implemented |
| gVisor container isolation | Container Isolation | NONE | Not implemented |
| Firecracker MicroVM | Container Isolation | NONE | Not implemented |
| Kubernetes + KEDA | Platform Architecture | NONE | Not implemented |
| PostgreSQL RLS | Platform Architecture | NONE | Not implemented |
| SSO/SAML | Enterprise Features | NONE | Not implemented |
| SOC 2 compliance evidence | Compliance | NONE | Not implemented |
| ISO 27001 compliance tooling | Compliance | NONE | Not implemented |
| FedRAMP preparation | Compliance | NONE | Not implemented |
| GDPR data erasure | Compliance | NONE | Not implemented |
| EU data residency | Compliance | NONE | Not implemented |
| Helm chart (on-premises) | Deployment | NONE | Not implemented |
| GitHub OAuth one-click onboarding | Developer Experience | REQ-017 (partial) | Implemented |
| VS Code extension | Developer Experience | NONE | Not implemented |
| Gatling scanner | Performance Testing | NONE | Not implemented |
| WireMock scanner | API Testing | REQ-022 (FALSE) | Not implemented |
| Falco scanner | Runtime Security | REQ-033 (FALSE) | Not implemented |
| Toxiproxy scanner | Chaos Engineering | REQ-034 (FALSE) | Not implemented |
| Flyway scanner | Database | REQ-028 (FALSE) | Not implemented |

---

## PRIORITY CLASSIFICATION

### P0 - Critical (Must fix before any release)

1. **Tier limit enforcement**: Free users have no limits. Business-critical.
2. **k6 AGPL removal**: Licensing violation per PRD's own requirements.
3. **BRD-tracker false completions**: REQ-022, REQ-028, REQ-033, REQ-034 claim files that do not exist.

### P1 - High (Required for MVP)

4. **Intelligent language detection**: Core Assurance Layer feature not implemented.
5. **Scan isolation**: Shared container is a security risk for multi-tenant.
6. **Missing WireMock, Falco, Toxiproxy, Flyway scanners**: Tracker claims complete but files missing.
7. **scan_file and scan_diff MCP tools**: PRD specifies these but they are not implemented.

### P2 - Medium (Required for Phase 2 per PRD roadmap)

8. **Claude Code Skill package**: Phase 2 deliverable.
9. **Platform integrations (Replit, Lovable, etc.)**: Phase 2 deliverable.
10. **CLI tool distribution**: Phase 2 deliverable.
11. **SDK packages (npm, pip, go)**: Phase 2 deliverable.
12. **Auto-fix code modification**: Phase 2 deliverable.
13. **Risk score bonuses**: Minor gap in scoring algorithm.
14. **GitHub Action marketplace listing**: Phase 2 deliverable.

### P3 - Low (Phase 3 / Enterprise)

15. **SSO/SAML**: Enterprise feature.
16. **Kubernetes/KEDA**: Enterprise infrastructure.
17. **gVisor/Firecracker**: Enterprise isolation.
18. **PostgreSQL RLS**: Enterprise multi-tenancy.
19. **SOC 2 / ISO 27001 / FedRAMP**: Enterprise compliance.
20. **GDPR features**: Enterprise compliance.
21. **Helm chart**: Enterprise deployment.
22. **VS Code extension**: Developer experience.
23. **Multi-region deployment**: Enterprise scale.

---

## WHAT IS WORKING WELL

Despite the gaps above, the core platform is substantially built:

1. **30+ scanner implementations** with real command execution (not mocks)
2. **Full scan pipeline** with profile-based scanner selection, timeout handling, concurrent execution
3. **MCP server** with 11+ tools and SSE transport for remote connections
4. **Comprehensive REST API** with 20+ route modules
5. **Attestation system** with in-toto format, Ed25519 signing, Sigstore support
6. **Risk scoring** with logarithmic algorithm
7. **Plain-language translation** for CWE/OWASP findings
8. **Dashboard** with 30+ pages (projects, scans, findings, attestations, policies, reports, settings, billing, team)
9. **Billing infrastructure** with Stripe (checkout, portal, webhooks, subscription lifecycle)
10. **GitHub integration** with OAuth, repository access, webhook processing, SSRF protection
11. **Policy engine** with evaluator service
12. **Webhook system** with delivery tracking and signature verification
13. **Test generator** with BRD parsing and code analysis
14. **Database schema** with 20+ tables, migrations, proper indexing
15. **Docker Compose** orchestration with backend, scanner, n8n, postgres, redis, dashboard

---

## QA VERDICT

**STATUS: NOT READY FOR RELEASE**

**Justification**:
- 3 P0 critical gaps (tier enforcement, AGPL violation, tracker integrity)
- 4 P1 high gaps (missing scanners falsely claimed as complete, no scan isolation)
- BRD-tracker shows 100% but is inaccurate -- at least 5 requirements reference nonexistent files
- 25+ PRD features have no tracking at all

**Required Actions Before Any Release**:
1. Fix BRD-tracker.json to reflect actual state (mark REQ-022, REQ-028, REQ-033, REQ-034 as NOT complete)
2. Implement tier enforcement middleware
3. Remove k6 scanner or document the licensing decision explicitly
4. Implement missing scanners (WireMock, Falco, Toxiproxy, Flyway, Gatling) or remove from tracker

**Required Actions Before Production Release**:
5. All P1 items resolved
6. Container isolation for multi-tenant scanning
7. Language auto-detection for scanner selection
8. BRD-tracker expanded to cover all PRD features

---

*QA Gap Analysis performed by qa agent (Opus 4.6) on 2026-02-21*
*This document compares the PRD-BRD v2.0 specification against the actual codebase at commit 40026cb7*
