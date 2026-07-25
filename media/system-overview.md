# bulletproof-codehardener: Technical Briefing and Architecture Overview

### 1. Platform Introduction and Core Value Proposition
**bulletproof-codehardener** is a centralized security assurance layer architected specifically for the AI-first development lifecycle. It provides a unified orchestration fabric that allows both human operators and AI coding agents to scan, score, and harden complex codebases with zero manual configuration.

**Key Capabilities:**
*   **Multi-tool Scanning:** Orchestrates a comprehensive suite of security, quality, and supply-chain tools, normalizing disparate outputs into a singular, enriched finding schema.
*   **Quality Scoring:** Generates a deterministic security score (0-1000) based on rigorous mathematics to provide an objective metric of project posture.
*   **Hardening and Fix Guidance:** Provides plain-language risk analysis and actionable remediation guidance, including automated, LLM-generated candidate patches.
*   **Attestation and SBOM Generation:** Produces cryptographic in-toto attestations and CycloneDX Software Bill of Materials (SBOM) for verified supply-chain provenance.
*   **Agent-Native MCP Integration:** Exposes all platform capabilities via the Model Context Protocol (MCP), enabling deep integration with AI agents like Claude Code, Cursor, and GitHub Copilot.

**Integrated Tooling:**
The platform integrates **62 unique security tools** (supporting 64 `SCANNER_MAP` entries) into a "zero configuration" layer. By automatically detecting languages and frameworks, it selects the optimal analysis suite for any given repository without requiring per-project setup.

### 2. Service Architecture and Data Management
The platform is deployed as a suite of Docker containers operating within a shared `codehardener` bridge network. 

**Core Services:**
| Service | Role | Internal Port | Default External Port |
| :--- | :--- | :--- | :--- |
| **backend** | Express API server and MCP SSE endpoint | 4000 | 4000 |
| **scanner** | BullMQ worker executing tool pipelines | — | — (Zero Ingress) |
| **dashboard** | Next.js 14 (App Router) web interface | 3000 | 3001 |
| **postgres** | Primary relational datastore (PostgreSQL 16) | 5432 | 5432 |
| **redis** | Job queuing (BullMQ) and state caching | 6379 | 6379 |
| **init** | One-shot migration and workflow importer | — | — |
| **n8n (opt)** | Workflow automation and delegation | 5678 | 5678 |
| **defectdojo (opt)** | Vulnerability management analytics | 8080 | 8083 |

**Database Schema:**
The PostgreSQL instance hosts three distinct databases:
1.  **codehardener:** The primary application database featuring 35 tables (including `projects`, `scans`, `findings`, `attestations`, and `policies`).
2.  **defectdojo:** Managed by the optional DefectDojo analytics service.
3.  **n8n:** Managed by the optional n8n automation engine.

**Architectural Integrity & Migrations:** 
A critical component of the deployment is the **init container**, which executes migrations 002-018 to reach the final `init.sql` state before application services start. 

**Network Logic:**
The architecture maintains a strict separation of concerns. The **backend** manages job queuing via `addScanJob()`, while the **scanner worker** executes the `runScanPipeline()`. From a security perspective, the **scanner worker maintains a zero-ingress posture**; it has no exposed ports and communicates exclusively as a client to Redis and Postgres. This ensures that the environment where untrusted code is analyzed is isolated from external network requests.

### 3. The Multi-Stage Scan Pipeline
The platform utilizes a complex execution flow to identify, verify, and remediate vulnerabilities.

**Orchestration Logic:**
If `N8N_ENABLED` is active, the scanner worker attempts to delegate the scan to n8n via a secured webhook. If the n8n service is unreachable, the system automatically falls back to the local scanner pipeline to ensure continuity.

**The LLM Assurance Layer:**
For `deep` and `full` profiles, the platform executes a four-stage analysis process using Anthropic Claude models:
1.  **llm-threatmodel (Haiku):** Generates a persistent per-project threat model. This stage is **context-seeded by Code Analysis (CA) modules CA-001 through CA-005**, providing the LLM with ground-truth data on language, framework, and dataflow.
2.  **llm-vuln-scan (Sonnet):** Conducts a threat-model-scoped review, fanning out agent calls to identify vulnerabilities within identified focus areas.
3.  **llm-triage (Haiku):** Performs N-vote verification (default 3 votes) to confirm findings and eliminate false positives.
4.  **llm-patch (Sonnet):** Generates candidate patch diffs, rationales, and validation notes for verified findings.

**Security and Cost Controls:**
*   **Token Budget & Circuit Breakers:** The platform enforces a per-scan aggregate limit of **2,000,000 tokens**. The `llm-threatmodel` stage is specifically reserved a slice of 150,000 tokens to prevent starvation of later stages.
*   **Gating:** Requires `ANTHROPIC_API_KEY` and explicit project-level `llm_analysis_enabled` opt-in.
*   **Path Confinement:** Agent tools are strictly confined to the scan target directory using `realpath` validation.
*   **Secret Redaction:** All tool outputs pass through a regex redactor to strip credentials before being processed by LLMs.

### 4. Scanner Registry and Profiles
The registry provides access to 62 unique scanners across multiple domains.

**Scanner Categories:**
| Category | Representative Tools |
| :--- | :--- |
| **SAST** | Opengrep, Bandit, Gosec, ESLint Security, PMD |
| **DAST** | Nuclei, OWASP ZAP |
| **SCA / Container** | Trivy, Grype, Dockle |
| **Secrets** | Gitleaks |
| **IaC** | Checkov |
| **Load Testing** | Locust, Artillery, Gatling |
| **Supply Chain** | Syft, in-toto, Cosign, cdxgen |
| **API Testing** | RESTler, Schemathesis, Newman, Pact |

**Scan Profiles:**
| Profile | Use Case | Est. Execution Time |
| :--- | :--- | :--- |
| **quick** | Fast feedback for pre-commit | ~30s |
| **standard** | Balanced default for daily development | ~2-5 min |
| **comprehensive** | Full assessment for releases/audits | ~10-15 min |
| **deep** | Includes full LLM Assurance Layer | ~15-20 min |
| **security** | Focused strictly on vulnerabilities | ~5-8 min |
| **api** | API-specific testing (ZAP, Nuclei, RESTler) | ~10 min |
| **performance** | Load and stress testing | ~10 min |
| **supply-chain** | SBOM and license analysis | ~5 min |
| **ai-security** | LLM-specific risks and hallucinations | ~8 min |
| **database** | Migration and DB security | ~3 min |
| **chaos** | Resilience and chaos testing | ~10 min |

**DAST Context:**
Specific project fields unlock specialized scanners: `target_url` enables ZAP and Nuclei; `container_image` enables Dockle; `openapi_spec_path` enables Spectral and RESTler.

### 5. Finding Enrichment and Quality Scoring
The post-scan intelligence layer transforms raw data into actionable intelligence.

**Exploitability Matrix:**
| Classification | Criteria |
| :--- | :--- |
| **Confirmed** | Reachable + unsanitized dataflow + externally accessible |
| **Likely** | Reachable and unsanitized, but requires authentication |
| **Theoretical** | Reachable but sanitized, or no clear dataflow match |
| **Unlikely** | Unreachable or fully sanitized |

**Deduplication Strategy:**
Findings are filtered via an in-memory set, a database unique index (`idx_findings_unique_per_scan`), and a prior status carry-forward mechanism to ensure remediation efforts are not duplicated.

**Scoring Mathematics:**
The platform uses a 1000-point base with **square-root scaling** penalties: `penalty = weight * sqrt(count)`.
*   **Critical Findings:** Weight 200 (Cap 450). Any open critical caps the total score at **600**.
*   **High Findings:** Weight 60 (Cap 300). Any open high caps the total score at **800**.
*   **Dual Scoring:** For diagnostic purposes, the platform tracks both **Score** (adjusted for open findings and suppressions) and **Score_Raw** (all findings regardless of status).

**Quality Bonuses (280 Points Max):**
Twelve bonuses are available, including **SBOM Generated** (+25), **Signed Attestation** (+30), **All Tests Passing** (+30), and **High Test Coverage** (+25).

### 6. Interaction Interfaces: API, MCP, and Dashboard
**REST API:**
Base URL: `http://localhost:4000/api/v1`.
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| **POST** | `/api/v1/scans` | Initiate a scan job |
| **GET** | `/api/v1/scans/:id` | Retrieve scan summary and score |
| **GET** | `/api/v1/findings/:id/patches` | Retrieve LLM-generated fixes |
| **POST** | `/api/v1/findings/bulk-status` | Update multiple findings at once |

**Model Context Protocol (MCP):**
The platform supports **stdio** for local development (e.g., Claude Code) and **SSE** for remote agents.
*   **Core Tools:** Basic functions like `codehardener_scan` and `codehardener_findings`.
*   **Orchestrated Tools:** These handle complex, multi-step sequences in a single agent call, such as `codehardener_scan_project` (Project Creation + Scan + Finding Retrieval).

**Dashboard UI:**
A Next.js 14 interface for human operators, featuring a **Scanner Coverage UI**, Exploitability Badges, and score trends.

### 7. Deployment and Administration
**Prerequisites:**
*   **Hardware:** Minimum 6GB of free RAM.
*   **Software:** Docker with Docker Compose v2, Node.js 20.

**Configuration:**
Mandatory variables in `.env` include `DB_PASSWORD` (min 16 chars), `JWT_SECRET` (min 32 chars), and `INTERNAL_API_KEY`.

**Health and Diagnostics:**
*   **Liveness:** `GET /api/v1/health` (200 OK if the process is up).
*   **Readiness:** `GET /api/v1/ready` (Verifies DB connectivity and reports dependency status: healthy/degraded).

**Maintenance:**
The PostgreSQL volume requires regular backups. Scan artifacts (reports and SBOMs) are stored in `reports/` and are regenerated per run, meaning they do not require persistent backup.