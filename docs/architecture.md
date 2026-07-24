# Architecture

## System Overview

Code Hardener is a security assurance platform for AI-first developers. It provides automated security scanning, vulnerability management, finding enrichment, cryptographic attestation, and compliance reporting through a unified API, MCP protocol, and web dashboard.

The platform integrates 62 unique security tools (64 SCANNER_MAP entries including 2 aliases) into a single "Assurance Layer" that requires zero configuration -- it auto-detects languages, selects appropriate scanners, enriches findings with code analysis, and produces a quality score (0-1000).

## Service Architecture

| Service | Role | Internal Port | Default External Port |
|---------|------|---------------|----------------------|
| `postgres` | PostgreSQL 16 -- single instance, 3 databases | 5432 | 5432 |
| `redis` | BullMQ job queue + cache (Redis 7) | 6379 | 6379 |
| `backend` | Express API server + MCP SSE endpoint | 4000 | 4000 |
| `scanner` | BullMQ worker -- executes scan pipeline with 62 tools installed | - | - |
| `dashboard` | Next.js 14 web UI (App Router) | 3000 | 3001 |
| `n8n` | Workflow automation (scan orchestration, webhooks) | 5678 | 5678 |
| `defectdojo` | Vulnerability management UI (optional, profile-gated) | 8080 | 8083 |
| `init` | One-shot container: runs migrations, imports n8n workflows | - | - |

All services communicate over a shared `codehardener` Docker bridge network. The scanner container has no exposed ports -- it connects to PostgreSQL and Redis directly and processes jobs from the BullMQ queue.

**Key architectural split**: The backend queues scan jobs via `addScanJob()`. The scanner container runs the actual pipeline via `runScanPipeline()`. Rebuilding `backend` alone does NOT update pipeline logic -- you must rebuild `scanner`.

## Databases

Single PostgreSQL 16 instance hosts three databases:

| Database | Owner | Purpose |
|----------|-------|---------|
| `codehardener` | Application | 35 tables -- core application data |
| `defectdojo` | DefectDojo | Managed by DefectDojo migrations |
| `n8n` | n8n | Managed by n8n |

### Core Tables (codehardener database)

| Table | Purpose |
|-------|---------|
| `users` | User accounts |
| `oauth_accounts` | OAuth provider links (GitHub, GitLab) |
| `projects` | Scan targets with DAST context (target_url, container_image, etc.) |
| `scans` | Scan executions with scores, profiles, code analysis summaries |
| `findings` | Security findings with enrichment data (exploitability, reachability, dataflow) |
| `finding_suppressions` | Project-level auto-suppression rules |
| `attestations` | Cryptographic scan attestations (Sigstore/Ed25519) |
| `api_keys` | API authentication keys |
| `policies` | Security policy definitions |
| `policy_rules` | Ordered rules within policies |
| `webhooks` | Webhook configurations |
| `webhook_deliveries` | Webhook delivery logs |
| `reports` | Generated compliance reports |
| `badges` | Embeddable quality score badges |
| `integrations` | Third-party integration configs |
| `teams` | Team organizations |
| `team_members` | Team membership |
| `team_invites` | Pending team invitations |
| `notifications` | User notifications |
| `notification_preferences` | Per-user notification settings |
| `subscriptions` | Billing subscriptions |
| `invoices` | Billing invoices |
| `payment_methods` | Stored payment methods |
| `audit_log` | Security audit trail |
| `refresh_tokens` | JWT refresh tokens |
| `code_analysis_results` | Cached CA module output |
| `brd_analysis_results` | BRD analysis output |
| `generated_test_cases` | Test generator output |
| `github_connections` | GitHub app connections |
| `github_oauth_states` | OAuth CSRF state tokens |
| `github_repositories` | Synced GitHub repositories |
| `github_webhook_events` | GitHub webhook event log |
| `registry_credentials` | Encrypted container registry credentials |
| `oauth_audit_log` | OAuth operation audit trail |
| `schema_migrations` | Migration tracking |

**Migrations**: `postgres/migrations/` contains migrations 002-018 (007 consolidated earlier migrations). `init.sql` represents the final schema state.

**Conventions**: All string columns use TEXT (not VARCHAR) for findings/scan data. No Drizzle ORM schema -- raw SQL via tagged templates. Mixed `db.execute(sql\`...\`)` and `pool.query()` patterns.

## Scan Pipeline

The scan pipeline runs inside the scanner container. The full execution flow:

```
prepareScanTarget        Clone/pull repository into /scan-target
        |
collectFileInventory     Count and categorize all files (audit evidence)
        |
runCodeAnalysis          CA-001 languages, CA-002 frameworks, CA-003 endpoints,
        |                CA-004 auth patterns, CA-005 dataflows
        |
detectProjectContext     Auto-detect OpenAPI specs, Postman collections, Pact contracts,
        |                Dockerfiles, CI configs
        |
checkTargetHealth        Verify targetUrl is reachable (for DAST scanners)
        |
augmentScannersWithContext  Add DAST/API scanners based on detected context
        |
runScanners              Execute scanners in parallel batches (default: 5 concurrent)
        |                └─ llm-threatmodel (if deep/full profile + opt-in)
        |                └─ llm-vuln-scan (if deep/full profile + opt-in)
        |
enrichFindings           Reachability + dataflow + exploitability enrichment
        |                └─ llm-triage: N-vote verify, dedupe, FP exclusion, recalibration (if deep/full + opt-in)
        |
insertFindings           Store findings with deduplication (3-layer)
        |
applySuppressions        Framework-aware + project-level suppression rules
        |
calculateQualityScore    Compute raw + adjusted scores with bonuses
        |
createAttestation        Sign with Sigstore (Cosign/Fulcio/Rekor) or Ed25519 fallback
        |
llm-patch                Generate candidate patch suggestions (if deep/full + opt-in)
        |
LLM verification         Claude Haiku exploit verification (Premium, non-fatal)
        |
importToDefectDojo       Push results to DefectDojo (if enabled, non-fatal)
```

### n8n Delegation

When `N8N_ENABLED=true`, the worker first attempts to delegate the scan to n8n via webhook. If n8n is unavailable, it falls back to the local pipeline. n8n communicates back via `/internal/*` routes authenticated with `X-Internal-API-Key`.

### LLM Assurance Layer (defending-code-reference-harness integration)

Four-stage static analysis using Claude, available in `deep` and `full` scan profiles when `ANTHROPIC_API_KEY` is set AND the project has `llm_analysis_enabled=true` (default false; protects source code privacy):

**Stages:**

1. **llm-threatmodel** (`runScanners` phase): Generates or refreshes a persistent per-project threat model (THREAT_MODEL.md, 8-section harness contract). Staleness detected via file inventory hash. Context-seeded from code-analysis results (CA-001 through CA-005). Emits info-level findings for unmitigated critical/high threats. Zero API calls on stale check (reuses cached model).

2. **llm-vuln-scan** (`runScanners` phase): Threat-model-scoped static review. Extracts focus areas from threat model (capped at `LLM_SCAN_MAX_FOCUS_AREAS`, default 8), fans out Sonnet agent-loop calls per focus area (concurrency 3), parses `<finding>` XML output. Light deduplication on file:line+category. Confidence-pass second-opinion scoring via Haiku (skippable). Falls back to quick recon mode if threat model unavailable.

3. **llm-triage** (`enrichFindings` phase): N-vote verification (default 3 independent Haiku votes per finding, majority verdict). Cross-scanner deduplication (collapses Semgrep + llm-vuln-scan on the same sink; richer finding retained). Test-file FP exclusion via content patterns. Threat-model recalibration (findings on unmitigated surfaces rank up; deprioritized surfaces rank down). Triaged findings bypass the single-shot `llm-verifier` call.

4. **llm-patch** (after `createAttestation` phase): Generates candidate patch diffs for verified/confirmed findings (Sonnet agent loop, `LLM_PATCH_MAX_FINDINGS` default 5). Stored as `proposed` patches in `candidate_patches` table; never auto-applied. Includes rationale and validation notes (build/exploit-path-closed/tests/bypass checklist). Exposed via `GET /api/v1/findings/:id/patches`.

**Security & Cost Controls:**

- **Gating**: All stages require both `ANTHROPIC_API_KEY` env var AND project-level `llm_analysis_enabled` boolean (source code transmitted to Anthropic API only when both are true).
- **Path confinement**: llm-agent.ts tools (`read_file`, `list_files`, `grep`) are path-confined to scan target directory; symlink/`..` escape attempts rejected; realpath validation.
- **Secret redaction**: Tool output (all three tools) passes regex redactor for AWS keys, private-key blocks, bearer/API tokens before inclusion in prompts.
- **Untrusted framing**: Scan-target content delimited in prompts as untrusted data; system instructions in separate `system` parameter; no instruction-following in user blocks.
- **Markdown injection safety**: LLM-sourced fields in reports (threat model, patch metadata, validation notes) escape via `escapeMarkdownField()` helper; patch diffs render in fenced blocks with embedded-fence neutralization.
- **Token budget**: Per-scan aggregate `LLM_SCAN_MAX_TOTAL_TOKENS` (default 2000000) shared across all stages; exhaustion → remaining stages skip with `skipReason: 'llm_budget_exhausted'`. The threat-model stage is reserved a bounded slice via `LLM_THREATMODEL_MAX_TOKENS` (default 150000) so it cannot drain the shared pool and starve later stages; an incomplete threat-model run persists nothing and skips with `llm_threatmodel_incomplete` rather than caching narration.
- **Patches never auto-applied**: Patch `status` (`proposed`/`accepted`/`rejected`) is metadata only; no code path exists to apply patches server-side.

**Configuration environment variables** (all optional, safe defaults):
- `LLM_SCAN_MODEL` (Sonnet for vuln-scan + patches)
- `LLM_THREATMODEL_MODEL` (Haiku for threat model)
- `LLM_SCAN_MAX_FOCUS_AREAS`, `LLM_SCAN_MAX_TOKENS_PER_AREA`, `LLM_SCAN_CONFIDENCE_PASS` (confidence scoring)
- `LLM_TRIAGE_MAX_FINDINGS`, `LLM_TRIAGE_VOTES` (voting)
- `LLM_PATCH_MAX_FINDINGS` (patch generation)
- `LLM_SCAN_MAX_TOTAL_TOKENS` (aggregate circuit-breaker, default 2000000)
- `LLM_THREATMODEL_MAX_TOKENS` (per-stage reservation for threat-model generation, default 150000)

**Database tables** (migration 023):
- `threat_models`: Per-project persistent threat models (id, project_id, content, threats_json parsed from section 4, source_inventory_hash for staleness, model_used, timestamps).
- `candidate_patches`: Proposed fixes (id, finding_id, scan_id, patch_diff, rationale, validation_notes, model_used, status: proposed|accepted|rejected, created_at).

**Premium/Enterprise feature**: Positioned as part of Code Hardener's Premium and Enterprise tiers (requires `ANTHROPIC_API_KEY`).

## Scanners

### Scanner Registry

62 unique scanners registered in `SCANNER_MAP` (64 entries with 2 aliases: `semgrep` -> `opengrep`, `eslint` -> `eslint-security`).

| Category | Scanners | Count |
|----------|----------|-------|
| **SAST** | Opengrep, Bandit (Python), Gosec (Go), ESLint Security (JS/TS), PMD (multi-language) | 5 |
| **DAST** | Nuclei, OWASP ZAP | 2 |
| **SCA / Container** | Trivy, Grype, Dockle | 3 |
| **Secrets** | Gitleaks | 1 |
| **IaC** | Checkov | 1 |
| **Load Testing** | Locust, Artillery, Gatling | 3 |
| **API Testing** | Newman, Pact, RESTler, WireMock, Schemathesis, Keploy | 6 |
| **Browser / Visual** | Playwright, BackstopJS, Pa11y | 3 |
| **Supply Chain** | Syft (SBOM), in-toto, Cosign | 3 |
| **Mutation Testing** | Stryker (JS/TS), mutmut (Python), pitest (Java) | 3 |
| **Test Runners** | Jest (JS/TS), pytest (Python) | 2 |
| **AI Code Quality** | DeepEval, package-validator (hallucinated packages) | 2 |
| **Threat Modeling** | STRIDE threat model analyzer | 1 |
| **Code Quality** | Knip (dead code), Oxlint (fast linter), jscpd (copy-paste), Ruff (Python), PHPStan, typos, Vale (prose), libyear (dependency freshness) | 8 |
| **CI/CD Security** | Actionlint (GitHub Actions), Poutine (pipeline security), OpenSSF Scorecard, Kubeconform (K8s validation), KubeLinter (K8s security) | 5 |
| **SCA / Compliance** | cargo-audit (Rust), Spectral (OpenAPI linting), dotenv-linter, license-finder, cdxgen (CycloneDX SBOM), ScanCode (license snippets) | 6 |
| **Fuzz Testing** | AFL++ | 1 |
| **Runtime / Chaos** | Falco (runtime rules), Toxiproxy (chaos config) | 2 |
| **Database** | Flyway (migration security) | 1 |
| **Policy / Reporting** | OPA, Allure, Conftest | 3 |
| **Test Generation** | selenium-gen (Selenium test generator) | 1 |

**Removed scanners**: detect-secrets (redundant with Gitleaks), garak (minimal value), pip-audit (redundant with Trivy+Grype), k6 (AGPL-3.0 license incompatible).

### Scan Profiles

13 profiles (12 named + `full`):

| Profile | Scanners | Use Case |
|---------|----------|----------|
| `quick` | 2 | Fast feedback (~30s) -- gitleaks, trivy |
| `standard` | 12 | Regular development (~2-5 min) |
| `comprehensive` | 49 | Releases/audits (~10-15 min) |
| `security` | 16 | Security-focused scan |
| `api` | 8 | API testing focused |
| `performance` | 3 | Load testing -- locust, artillery, gatling |
| `frontend` | 5 | Browser, accessibility, visual testing |
| `supply-chain` | 11 | SBOM, attestation, license, container |
| `ai-security` | 7 | AI/LLM-specific security risks |
| `ai-code-quality` | 22 | Purpose-built for AI-generated codebases |
| `database` | 3 | Database/migration security |
| `chaos` | 4 | Chaos/resilience testing |
| `full` | 62 | All unique scanners (aliases excluded) |

Additionally, the `auto` profile auto-detects languages via `detectLanguages()` and selects appropriate scanners, falling back to `standard` if detection fails.

### DAST Context & Scanner Maximization

Projects can configure DAST context to unlock scanners that would otherwise skip:

| Context Field | Unlocks | Storage |
|---------------|---------|---------|
| `target_url` | ZAP, Nuclei, Pa11y (on DAST profiles) | projects.target_url |
| `container_image` | Dockle (container hardening) | projects.container_image |
| `openapi_spec_path` | Spectral, Schemathesis, RESTler (on DAST profiles) | projects.openapi_spec_path |
| `auth_config` | Authenticated DAST scanning | projects.auth_config (encrypted JSONB) |
| `registry_credentials` | Private registry image pulling | registry_credentials table (encrypted) |

The `buildScanContext()` helper (`services/scan-context.ts`) fetches and decrypts project context for all scan entry points. The `augmentScannersWithContext()` function adds relevant scanners to profiles based on detected context. Scanners that skip due to missing context return structured `skipReason`/`skipHint` fields visible in the Scanner Coverage UI.

## Finding Enrichment Pipeline

Post-scan intelligence layer that reduces false positives. Runs after scanner execution but before score calculation:

```
1. Code Analysis (CA-001 through CA-005)
   |  Languages, frameworks, endpoints, auth patterns, dataflows
   |
2. Framework-Aware Suppressions
   |  Auto-suppress known FPs (e.g., Django ORM -> SQL injection, React JSX -> XSS)
   |
3. Reachability Filtering
   |  File-level import graph tracing from HTTP/CLI entry points
   |  Tags findings as reachable/unreachable
   |
4. Dataflow Cross-Reference
   |  Matches findings against CA-005 dataflow sinks (line proximity = 5)
   |  Auto-suppresses findings where sanitization is confirmed
   |
5. Exploitability Scoring
   |  Classifies each finding: confirmed / likely / theoretical / unlikely
   |  Matrix: reachable + dataflow + auth + external accessibility
   |
6. LLM Verification (Premium)
   |  Claude Haiku adversarial exploit path analysis
   |  Only for confirmed/likely findings, max 10 per scan
   |  Requires ANTHROPIC_API_KEY
```

### Exploitability Matrix

| Classification | Criteria |
|----------------|----------|
| **confirmed** | Reachable + unsanitized dataflow + externally accessible + no auth |
| **likely** | Reachable + unsanitized + auth-protected, OR reachable + no dataflow + external + no auth |
| **theoretical** | Reachable but sanitized, OR reachable with no dataflow match |
| **unlikely** | Unreachable, OR sanitized + behind auth |

### Finding Deduplication

Three-layer dedup prevents duplicate findings:

1. **In-memory Set** in `scan.queue.ts` -- same `scanner:ruleId:title:filePath:lineNumber` within a scan
2. **DB unique index** `idx_findings_unique_per_scan` -- constraint violation catch
3. **Prior status carry-forward** -- batch-fetch dismissed findings from previous scans via `batchGetPriorDismissedStatuses()` (single query, not N+1)

## Quality Score System

**Base score**: 1000 points

### Penalty Calculation

Uses square-root scaling: `penalty = weight * sqrt(count)`, capped per severity.

| Severity | Weight | Cap | Example: 1 finding | Example: 10 findings |
|----------|--------|-----|--------------------|-----------------------|
| Critical | 200 | 450 | -200 pts | -632 (capped at -450) |
| High | 60 | 300 | -60 pts | -190 pts |
| Medium | 18 | 250 | -18 pts | -57 pts |
| Low | 4 | 150 | -4 pts | -13 pts |
| Info | 0 | 0 | 0 | 0 |

### Severity Ceilings

Hard caps regardless of bonuses:

- Any **critical** finding -> max score 600 ("Moderate")
- Any **high** finding -> max score 800 ("Good")

### Quality Bonuses (12 bonuses, 280 points max)

| Bonus | Points | Condition |
|-------|--------|-----------|
| SBOM Generated | 25 | Syft ran successfully |
| Signed Attestation | 30 | Sigstore/Ed25519 signing succeeded |
| Clean Secrets Scan | 20 | Gitleaks ran with 0 findings |
| Clean IaC Scan | 15 | Checkov ran with 0 findings |
| Supply Chain Verified | 25 | Cosign or in-toto ran successfully |
| Defense in Depth | 10 | Project has used 2+ scan profiles historically |
| Strong Mutation Score | 30 | Mutation testing score >= 70% |
| All Packages Verified | 25 | package-validator ran with 0 findings |
| Clean License Scan | 20 | ScanCode ran with 0 findings |
| No Confirmed Exploits | 25 | All enriched findings are theoretical/unlikely |
| All Tests Passing | 30 | Jest/pytest ran with 0 failures |
| High Test Coverage | 25 | Test coverage >= 80% across all runners |

**Total**: 280 possible bonus points

### Quality Levels

| Range | Level |
|-------|-------|
| 900-1000 | Excellent |
| 750-899 | Good |
| 500-749 | Moderate |
| 250-499 | Poor |
| 0-249 | Critical |

### Dual Scoring

Each scan produces two scores:

- **score** (adjusted): Based on open findings only (after suppressions). Displayed in dashboard.
- **score_raw**: Based on all findings regardless of status. Used for diagnostics.

The `findings_count` JSONB stores both: top-level counts are open-only (for dashboard), `.raw` nested object contains all findings (for diagnostics).

## Attestation

Cryptographic attestation follows the in-toto attestation format:

1. **Sigstore** (preferred): Cosign keyless signing via Fulcio CA, logged to Rekor transparency log
2. **Ed25519** (fallback): Local key pair generated at `$SIGNING_KEYS_DIR/attestation-signing.pem`

Attestations include scan metadata (profile, scanners used, timing, findings summary, score) and are stored in the `attestations` table with optional signature, certificate, and Rekor log ID.

## MCP Protocol

Two transport modes for AI coding assistant integration:

| Mode | Transport | Auth | Use Case |
|------|-----------|------|----------|
| **stdio** | Direct process | Single-user (default context) | Local dev with Claude Code |
| **SSE** | `GET /mcp/sse` + `POST /mcp/rpc` | API key or JWT | Cursor, remote agents, multi-user |

MCP tools: `codehardener_scan`, `codehardener_status`, `codehardener_findings`, plus report generation and project management tools.

## Dashboard

Next.js 14 App Router with 26 pages and 13 reusable components.

### Pages

| Route | Purpose |
|-------|---------|
| `/` | Dashboard overview with quality scores and recent scans |
| `/projects`, `/projects/new`, `/projects/[id]` | Project CRUD with DAST context configuration |
| `/scans`, `/scans/new`, `/scans/[id]` | Scan management and detail views with Scanner Coverage UI |
| `/findings`, `/findings/[id]` | Finding browser with exploitability badges and enrichment data |
| `/reports`, `/reports/[id]` | Compliance report generation and viewing |
| `/attestations`, `/attestations/new`, `/attestations/[id]` | Attestation management |
| `/policies`, `/policies/new`, `/policies/new-draft`, `/policies/[id]` | Security policy configuration |
| `/tests` | Test generation and results |
| `/settings` | General settings |
| `/settings/api-keys` | API key management |
| `/settings/billing` | Subscription management |
| `/settings/integrations` | Third-party integrations |
| `/settings/notifications` | Notification preferences |
| `/settings/team` | Team management |
| `/login` | Authentication |

### Components

`DashboardLayout`, `Sidebar`, `Header`, `Logo`, `StatsCard`, `ScoreGauge`, `SeverityBadge`, `StatusBadge`, `ExploitabilityBadge`, `Pagination`, `EmptyState`, `ErrorBoundary`, `Providers`

### Tech Stack

- React Query hooks defined in `useApi.ts` (515 lines)
- Dev mode auth: `dev@codehardener.local` via `X-User-Id` header
- `NEXT_PUBLIC_*` env vars must be build args, not runtime env

## Backend API

Express server with 27 route modules:

`health`, `auth`, `sso`, `projects`, `scans`, `findings`, `reports`, `attestations`, `policies`, `api-keys`, `webhooks`, `notifications`, `integrations`, `team`, `billing`, `badges`, `tools`, `tests`, `test-generator`, `github`, `mcp`, `dashboard`, `prompts`, `gdpr`, `suppressions`, `registry-credentials`, `n8n-hooks`

### Internal API

| Endpoint | Purpose | Auth |
|----------|---------|------|
| `POST /internal/scanners/execute` | Run a specific scanner | X-Internal-API-Key |
| `POST /internal/findings/import` | Bulk import findings | X-Internal-API-Key |
| `POST /internal/policies/evaluate` | Evaluate policies | X-Internal-API-Key |
| `POST /internal/attestations/create` | Create attestation | X-Internal-API-Key |
| `GET /internal/projects/:id/config` | Get project config | X-Internal-API-Key |

## DefectDojo Integration

When `DEFECTDOJO_ENABLED=true`:

- Projects sync to DefectDojo products
- Scan results import as engagements with scan artifacts
- 8 scanners have native DD parsers: Trivy, Bandit, Gitleaks, ZAP, Nuclei, Grype, Checkov, ESLint
- Remaining scanners use Generic Findings Import format

## Policy Engine

Policies contain ordered rules evaluated against scan findings:

| Rule Type | Description | Actions |
|-----------|-------------|---------|
| `severity_threshold` | Max allowed findings per severity | block, warn, ignore |
| `no_secrets` | Block on hardcoded secrets (CWE-798) | block, warn, ignore |
| `max_total_findings` | Cap on total finding count | block, warn, ignore |
| `cwe_blocklist` | Block specific CWE IDs | block, warn, ignore |
| `scanner_required` | Require specific scanner in scan | block, warn, ignore |

## Finding Statuses

| Status | Meaning |
|--------|---------|
| `open` | Active finding requiring attention |
| `fixed` | Remediated by developer |
| `ignored` | Manually dismissed |
| `false_positive` | Confirmed not a real issue (manual or auto-suppressed) |
| `deferred` | Acknowledged but accepted for now |

## Code Analysis Modules

Used for finding enrichment (not standalone scanning):

| Module | Purpose |
|--------|---------|
| CA-001 | Language detection |
| CA-002 | Framework detection |
| CA-003 | Endpoint extraction |
| CA-004 | Authentication pattern detection |
| CA-005 | Dataflow analysis (sources, sinks, sanitization) |

Modules CA-006 through CA-010 exist but are skipped during scan enrichment because existing scanners cover their domain (sensitive data -> Gitleaks, dependencies -> Trivy/Grype, infrastructure -> Checkov).

## Worker Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `SCANNER_TIMEOUT_MS` | 300000 (5 min) | Per-scanner execution timeout |
| `SCANNER_MAX_CONCURRENT` | 5 | Parallel scanner batch size |
| Worker concurrency | 5 | BullMQ concurrent job processing |
| Rate limit | 10/min | BullMQ rate limiter |
| Job retries | 3 | Exponential backoff (5s base) |
| Job priority | 1 (quick), 2 (standard), 3 (other) | BullMQ priority queue |
