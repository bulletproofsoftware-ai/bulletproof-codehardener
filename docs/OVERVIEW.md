# Code Hardener — Overview

**bulletproof-codehardener** is a security assurance platform for AI-first
development teams. It wraps a large set of open-source security, quality, and
supply-chain tools behind a single API, dashboard, and Model Context Protocol
(MCP) server, so that AI coding agents (Claude Code, Cursor, GitHub Copilot) and
humans can scan code, score its security posture, and harden it from one place.

## What it does

- **Multi-tool scanning** — orchestrates SAST, DAST, SCA, secrets, IaC, supply
  chain, load, API, and accessibility tools in a single scan run. Each tool's
  output is normalized into a common finding schema.
- **Quality scoring** — every scan produces a deterministic security score from
  0 to 1000 with a quality level (`excellent` / `good` / `moderate` / `poor` /
  `critical`). See [Scoring](#scoring) below.
- **Hardening & fix guidance** — findings carry plain-language risk explanations,
  the exact `file:line` location, and remediation guidance. MCP fix tools return
  actionable patches.
- **Attestation & SBOM** — completed scans can emit an in-toto attestation and a
  CycloneDX Software Bill of Materials for supply-chain provenance.
- **Agent-native (MCP)** — the same capabilities are exposed as MCP tools over
  stdio or SSE, so an AI agent can scan, read findings, and request fixes inline.

## Architecture

```
AI Agents (Claude Code, Cursor)           Humans (Dashboard UI)
        |  MCP (stdio / SSE)                       |  HTTPS
        v                                          v
                Code Hardener Backend API (Express, /api/v1)
        |                    |                         |
        v                    v                         v
   Scanner Worker       Postgres                    Redis
   (BullMQ jobs,        (projects, scans,           (job queue,
    27 tools in a        findings, scores,           cache)
    hardened            attestations)
    container)               |
        |                    v
        |               DefectDojo (optional analytics UI)
        v
   n8n (optional automation backbone: scan orchestration,
        post-scan processing, test execution)
```

Components that actually ship in this repository:

| Component | Path | Description |
|-----------|------|-------------|
| Backend API + MCP server | `backend/` | Express API (`/api/v1`) and the MCP stdio/SSE server. TypeScript. |
| Scanner worker | `backend/src/worker.ts`, `backend/Dockerfile.scanner` | BullMQ worker that runs the tools inside a hardened container. |
| Dashboard | `dashboard/` | Next.js UI for projects, scans, findings, and scores. |
| CLI | `cli/` | Command-line client. |
| SDKs | `sdks/node`, `sdks/python`, `sdks/go` | Official client libraries. |
| n8n workflows / templates | `n8n-workflows/`, `n8n-templates/` | Automation definitions. |
| Scanner configs | `scanner-configs/` | Tool rule sets (gitleaks, semgrep, gosec, PMD, etc.). |
| Postgres init | `postgres/` | Schema and seed SQL. |
| Deploy | `docker-compose*.yml`, `helm/`, `nginx/` | Compose stacks, Helm chart, reverse proxy. |

## Integrated tools

The platform integrates a broad set of open-source tools, grouped by category:

- **SAST**: Opengrep, Bandit, Gosec, ESLint Security, PMD
- **DAST**: Nuclei, OWASP ZAP
- **SCA**: Trivy, Grype
- **Secrets**: Gitleaks, detect-secrets
- **IaC**: Checkov
- **Supply chain**: Syft, in-toto, Cosign
- **Load testing**: Locust, Artillery, k6
- **API testing**: Newman, Pact, RESTler
- **Browser / visual / accessibility**: Playwright, BackstopJS, Pa11y
- **Policy / reporting**: OPA, Allure, Conftest

Not every tool runs in every scan — profiles select an appropriate subset (see
[HOW-TO-USE](HOW-TO-USE.md)).

## Scan profiles

Profiles are defined in `backend/src/controllers/tools.controller.ts`. The most
commonly used are:

| Profile | Purpose | Representative tools |
|---------|---------|----------------------|
| `quick` | Fast essential check | trivy, gitleaks, eslint_security, bandit |
| `standard` | Balanced default | trivy, grype, gitleaks, eslint_security, bandit, gosec, checkov |
| `comprehensive` | Full SAST + SCA + secrets + IaC assessment | all tools in those categories |
| `api` | API-focused testing | zap, nuclei, newman, restler, pact |
| `supply_chain` | Supply-chain analysis | syft, trivy, grype, cosign, gitleaks |
| `compliance` | Compliance scanning | checkov, trivy, syft, opa |
| `pre_commit` | Fast pre-commit checks | eslint_security, gitleaks, bandit, gosec |

> **Note.** The `standard` profile is the recommended default for source-tree
> scans. Profiles such as `comprehensive` that pull in dynamic/runtime tools
> require a live running target to be meaningful.

## Scoring

Scores are computed by `backend/src/services/assurance/quality-score.ts` using a
**square-root penalty** model on a base of 1000:

- Each severity applies `penalty = weight * sqrt(count)`, capped per severity.
  Weights (and per-severity caps): critical 200 (450), high 60 (300),
  medium 18 (250), low 4 (150), info 1 (20). The square-root curve means the
  first finding of a severity costs the most and additional ones cost less.
- **Severity ceilings** enforce hard limits: any open critical caps the score at
  600 ("moderate"); any open high caps it at 800 ("good"). You cannot earn an
  "excellent" score while critical or high findings remain open.
- Quality levels: `excellent` ≥ 900, `good` ≥ 750, `moderate` ≥ 500,
  `poor` ≥ 250, otherwise `critical`.

This repository's own latest `standard` scan scores **767 / 1000 ("good")** with
**0 critical and 0 high** findings — see
[scan/scan-report.md](scan/scan-report.md).

## Where to go next

- [INSTALL.md](INSTALL.md) — stand up the stack with Docker Compose.
- [HOW-TO-USE.md](HOW-TO-USE.md) — scan a project via API, MCP, or dashboard.
- [ADMINISTRATOR.md](ADMINISTRATOR.md) — operations, configuration, and services.
- [SBOM.md](SBOM.md) — the platform's own Software Bill of Materials.
- [scan/scan-report.md](scan/scan-report.md) — the platform's own security scan.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
