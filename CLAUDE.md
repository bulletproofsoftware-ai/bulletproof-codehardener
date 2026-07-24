# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Code Hardener is a security assurance platform for AI-first developers. The platform consists of a **backend** (Node.js/TypeScript), a **dashboard** (Next.js), a **scanner Docker image** (70+ tools), and supporting infrastructure (PostgreSQL, Redis, BullMQ, n8n).

**Product Vision**: Security-as-a-service for developers using AI coding assistants (Cursor, GitHub Copilot, Claude Code) who lack traditional security expertise. The platform integrates 70+ security tools into a unified "Assurance Layer."

## Repository Structure

```
backend/               # Node.js/TypeScript API server (Express, Drizzle ORM, BullMQ)
  src/
    config/            # Environment config (env.ts)
    controllers/       # Route handlers
    db/                # Database client
    routes/            # Express routes
    services/
      assurance/       # Quality score (0-1000), attestation (Sigstore/Ed25519)
      scanners/        # 70+ scanner implementations + pipeline orchestrator
      queue/           # BullMQ scan job processing (scan.queue.ts)
      translator/      # Plain-language finding translation
      test-generator/  # Code analysis modules (CA-001 through CA-010)
      defectdojo/      # DefectDojo integration
      mcp/             # MCP server for Claude/Cursor
      reports/         # PDF/compliance report generation
    types/             # Shared TypeScript types (index.ts)
    utils/             # Logger, helpers
dashboard/             # Next.js 14 (App Router) dashboard
  src/
    app/               # Page routes (/, /projects, /findings, /scans, /reports, /settings)
    components/        # Reusable UI components
    types/             # Dashboard TypeScript types
    lib/               # Utilities
scanner/               # Scanner Docker image (Dockerfile.scanner)
postgres/
  init.sql             # Fresh deployment schema
  migrations/          # Incremental SQL migrations (001-016)
docker-compose.yml     # Local dev stack
```

## Key Architectural Concepts

### The Assurance Layer
Core abstraction providing a single interface (prompt, MCP server, skill, or REST API) for security scanning:
- Zero-configuration language detection and scanner selection
- Plain-language finding translation (converts CVE/CWE jargon to human-readable explanations)
- Cryptographic attestation via Sigstore (Cosign, Fulcio, Rekor) with Ed25519 fallback
- Quality score (0-1000) with sqrt penalty scaling and 12 security bonuses

### Integrated Tool Stack (70+ scanners)
- **SAST**: Bandit, Gosec, ESLint Security, PMD, Opengrep, Semgrep
- **DAST**: OWASP ZAP, Nuclei
- **SCA/Container**: Trivy, Grype
- **Secrets**: Gitleaks CLI
- **IaC**: Checkov
- **Load Testing**: Locust, Artillery Core
- **API Testing**: Newman, Pact, RESTler, Keploy, Schemathesis
- **Browser/Visual**: Playwright, BackstopJS, Pa11y, axe-core
- **DAST/Fuzzing**: sqlmap, dalfox, ffuf
- **Property Testing**: fast-check, Hypothesis
- **Coverage**: c8
- **Link Checking**: lychee
- **Supply Chain**: Syft (SBOM), Cosign/Sigstore, package-validator, ScanCode, Socket.dev
- **Mutation Testing**: Stryker, mutmut, pitest
- **Test Runners**: Jest, pytest
- **AI Code Quality**: DeepEval, code-complexity, dead-code-detector, consistency-checker, duplication-detector, naming-analyzer, error-pattern-detector, type-safety-checker, dependency-analyzer, documentation-coverage
- **Threat Modeling**: STRIDE threat model analyzer
- **Policy/Reporting**: OPA, DefectDojo, Giskard

### LLM Assurance Scanners (defending-code-reference-harness integration)
Four-stage static analysis powered by Claude, gating on opt-in per-project privacy and API key configuration:
- **llm-threatmodel**: Generates/refreshes persistent per-project threat models with THREAT_MODEL.md format (8-section contract). Staleness-detected via file inventory hash. Seeds context from CA-001 through CA-010 code-analysis results. Threat-model info-level findings surface unmitigated critical/high threats in reports.
- **llm-vuln-scan**: Threat-model-scoped static review with focus-area fan-out (Sonnet) + confidence-pass re-ranking (Haiku). Parses `<finding>` XML output, maps to standard Finding schema with CWE categories and metadata. Fallback recon mode if threat model unavailable.
- **llm-triage**: N-vote verification (default 3 independent Haiku votes per finding, majority verdict). Cross-scanner deduplication, test-file FP exclusion, threat-model recalibration. Finds that dispatch to triage bypass the single-shot llm-verifier.
- **llm-patch**: Generates candidate patch diffs for verified findings (Sonnet agent loop). Stored as `proposed` patches, never auto-applied, rendered in reports with unverified disclaimer. Includes rationale + validation notes (build/exploit-path-closed/tests/bypass checklist).

**Configuration**: All four stages gated by `ANTHROPIC_API_KEY` environment variable and per-project `llm_analysis_enabled` boolean (defaults false; source code transmitted to Anthropic API only when both key is set AND project opts in). Registered in `deep` and `full` scan profiles only (not `quick`, `standard`, `comprehensive`).

**Environment variables** (all optional, safe defaults):
- `LLM_SCAN_MODEL` (default: `claude-sonnet-4-5-20250929`)
- `LLM_THREATMODEL_MODEL` (default: `claude-haiku-4-5-20251001`)
- `LLM_SCAN_MAX_FOCUS_AREAS` (default: 8)
- `LLM_SCAN_MAX_TOKENS_PER_AREA` (default: 8000)
- `LLM_SCAN_CONFIDENCE_PASS` (default: true)
- `LLM_TRIAGE_MAX_FINDINGS` (default: 20)
- `LLM_TRIAGE_VOTES` (default: 3)
- `LLM_PATCH_MAX_FINDINGS` (default: 5)
- `LLM_SCAN_MAX_TOTAL_TOKENS` (default: 2000000 — per-scan aggregate circuit-breaker across all stages)
- `LLM_THREATMODEL_MAX_TOKENS` (default: 150000 — per-stage reservation so threat-model generation can't drain the shared budget and starve vuln-scan/triage/patch)

**Security model**: Path-confined read-only tools (`read_file`, `list_files`, `grep`), secret redaction on tool output, untrusted data framing in prompts, markdown injection escaping in reports, no auto-patch application, patches lifecycle (`proposed`/`accepted`/`rejected`) is metadata-only. Premium/Enterprise feature positioning.

### Finding Enrichment Pipeline
Post-scan intelligence layer that reduces false positives:
1. **Code Analysis** — Runs CA modules (languages, frameworks, endpoints, auth, dataflows) on scan target
2. **Framework-Aware Suppressions** — Auto-suppresses known FPs based on framework defaults (Django ORM, React JSX, etc.)
3. **Reachability Filtering** — Tags findings as reachable/unreachable from entry points
4. **Dataflow Cross-Reference** — Matches findings against CA-005 dataflow sinks, auto-suppresses sanitized paths
5. **Exploitability Scoring** — Classifies as confirmed/likely/theoretical/unlikely
6. **LLM Verification** (Premium) — Haiku-powered adversarial exploit verification for confirmed/likely findings

### Quality Score System
- Base score: 1000
- Penalties: sqrt(count) * weight, capped per severity (critical=450, high=300, medium=250, low=150)
- Severity ceilings: any critical → max 600, any high → max 800
- 12 bonuses (280 pts total): SBOM, attestation, clean secrets/IaC, supply chain, defense-in-depth, mutation score, package validation, clean licenses, no confirmed exploits, all tests passing, high test coverage

### Scan Pipeline Flow
```
prepareScanTarget → collectFileInventory → runCodeAnalysis → detectProjectContext → checkTargetHealth → augmentScannersWithContext → runScanners (llm-threatmodel pre-pass → chunked scanners incl. llm-vuln-scan) → enrichFindings → insertFindings → applySuppressions → llm-triage → LLM verification → calculateQualityScore → createAttestation → llm-patch
```

**Key change (LLM Assurance integration)**: Triage now runs *before* quality score and attestation (reorders per adversarial-review finding A1/F1). This ensures the attestation attests to the final, triaged set of findings, not the pre-triage snapshot.

### DAST Context & Scanner Maximization
Projects can configure DAST context (target URL, container image, OpenAPI spec, auth config, registry credentials) to unlock ~20 scanners that were previously always-skipped. The `buildScanContext()` helper (in `services/scan-context.ts`) fetches and decrypts this context for all scan entry points.

Scanners that skip due to missing context return structured `skipReason`/`skipHint` fields visible in the Scanner Coverage UI. The `augmentScannersWithContext()` function automatically adds relevant scanners (ZAP, Nuclei, Spectral, etc.) based on detected context.

## Development

### Local Docker Stack
```bash
docker compose up -d              # postgres=5432, redis=6379, backend=4000, dashboard=3001, n8n=5678
docker compose build backend      # Rebuild backend
docker compose build dashboard    # Rebuild dashboard (NEXT_PUBLIC_* must be build args)
docker compose restart backend    # Restart after rebuild
```

### Database
```bash
# Apply a migration
docker exec -i codehardener-postgres-1 psql -U codehardener -d codehardener < postgres/migrations/NNN_name.sql
```

### Testing
```bash
cd backend && npx vitest run      # Run all tests
cd backend && npx tsc --noEmit    # Type check
```

### Key Conventions
- Backend uses strict TypeScript (`noUnusedLocals`, `noUnusedParameters`)
- Scanner files export `async function runXxx(_jobData: ScanJobData): Promise<ScannerResult>`
- Scanners registered in `SCANNER_MAP` and `PROFILE_SCANNERS` in pipeline.ts
- Use TEXT not VARCHAR for findings/scan data columns
- Dashboard authenticates as `dev@codehardener.local` via X-User-Id header in dev mode
- NEXT_PUBLIC_* env vars must be build args, not runtime env

## Pricing Model

- **Free**: 3 projects, 200 scans/month
- **Pro**: $19/month - 10 projects, unlimited scans
- **Team**: $39/dev/month - SSO, Slack, custom policies
- **Enterprise**: Custom - self-hosted, FedRAMP, SLA, LLM verification
