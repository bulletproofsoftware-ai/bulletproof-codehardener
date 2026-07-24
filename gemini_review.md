# Code Hardener Architectural Review and Gap Analysis

This document provides a comprehensive architectural review of the Code Hardener codebase and a gap analysis based on the Business Requirements Document (BRD) and Product Requirements Document (PRD).

## Architectural Review Summary

The Code Hardener project is a monorepo composed of three main services: a `backend` API, a `dashboard` frontend, and a `marketing` website.

### Backend

-   **Technology Stack:** Node.js, TypeScript, Fastify, PostgreSQL, BullMQ, Redis.
-   **Architecture:** The backend follows a simple and direct "route-handler-as-controller" pattern. Business logic, validation (using Zod), and raw SQL database queries are co-located within the route handlers. It does not use a separate service layer or an ORM, which keeps the architecture lightweight but may lead to code duplication.
-   **Asynchronous Processing:** A key feature is the `ScanQueue` system, which uses BullMQ and Redis to manage a job queue for security scans. This system is designed with a highly extensible plugin/strategy pattern, allowing for the registration of multiple "scanners".
-   **Scanners:** All 27 scanners listed in the PRD have corresponding implementation files. An inspection of `gitleaks-scanner.ts` and `trivy-scanner.ts` confirms that these are not just stubs but have full implementations for argument building, output parsing, and finding normalization.
-   **API:** The API is well-structured and documented with Swagger.

### Dashboard

-   **Technology Stack:** Next.js, React, TypeScript, Tailwind CSS, @tanstack/react-query, Recharts, Zustand.
-   **Architecture:** The dashboard is a standard Next.js application using the App Router. It has a well-organized page structure that corresponds to the features outlined in the PRD, including pages for attestations, findings, policies, projects, reports, scans, and settings. It uses `@tanstack/react-query` for data fetching from the backend and `recharts` for data visualization.

### Marketing

-   **Technology Stack:** Next.js, React, TypeScript, Tailwind CSS, Framer Motion.
-   **Architecture:** The marketing site is a standard Next.js application. The page structure includes pages for about, blog, contact, docs, features, pricing, and legal information.

## Feature Comparison: PRD vs. Implementation

| Feature                                     | PRD Status | Implemented? | Notes                                                                                                                                                             |
| :------------------------------------------ | :--------- | :----------: | :---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core Platform**                           |            |              |                                                                                                                                                                   |
| K8s Scan Orchestration                      | Defined    |      ❌      | Currently using `docker-compose`, not Kubernetes.                                                                                                                 |
| gVisor Sandbox                              | Defined    |      ❌      | No evidence of gVisor sandboxing in the `docker-compose.yml`.                                                                                                     |
| PostgreSQL Database                         | Defined    |      ✅      | Implemented with `node-postgres`.                                                                                                                                 |
| Web Dashboard                               | Defined    |      ✅      | The `dashboard` Next.js application exists.                                                                                                                       |
| REST API                                    | Defined    |      ✅      | Implemented with Fastify and Swagger.                                                                                                                             |
| **Tool Integrations**                       |            |              |                                                                                                                                                                   |
| 27 Security Tools                           | Listed     |      ✅      | All 27 tools have corresponding scanner files in the backend.                                                                                                     |
| **Assurance Layer**                         |            |              |                                                                                                                                                                   |
| Intelligent Language Detection              | Defined    |      ⚠️      | The `determineScanners` method in `trivy-scanner.ts` is a starting point, but a more sophisticated language detection mechanism is not evident.                      |
| Plain-Language Findings                     | Defined    |      ⚠️      | The `gitleaks-scanner.ts` and `trivy-scanner.ts` show this is being done, but it's not clear how comprehensive this is across all scanners.                        |
| One-Click Auto-Fix                          | Defined    |      ❌      | The `fixAvailable` and `fixDescription` fields exist in the `NormalizedFinding` type, but there's no implementation for applying fixes.                           |
| Risk Score Algorithm                        | Defined    |      ⚠️      | The PRD defines a scoring algorithm, but there's no evidence of its implementation in the backend.                                                                |
| Cryptographic Attestation                   | Defined    |      ⚠️      | The `in-toto` and `cosign` scanners exist, but the full Sigstore integration flow is not fully implemented.                                                       |
| Embeddable Trust Badges                     | Defined    |      ❌      | The `/badge` endpoint is mentioned in the PRD, but there's no implementation for generating SVG badges.                                                          |
| Policy-as-Code                              | Defined    |      ⚠️      | The `opa-scanner.ts` exists, but the full policy evaluation engine is not evident.                                                                                |
| Webhook Notifications                       | Defined    |      ❌      | No evidence of a webhook dispatch system.                                                                                                                         |
| **Developer Experience**                    |            |              |                                                                                                                                                                   |
| AI Coding Tool Integrations                 | Defined    |      ⚠️      | The PRD mentions native support for Cursor, Copilot, and Claude Code. The `@modelcontextprotocol/sdk` is present, but the extent of the integration is unclear. |
| Onboarding (under 2 mins)                   | Goal       |      ❓      | This is a UX goal and cannot be verified from the code alone.                                                                                                     |
| **Compliance**                              |            |              |                                                                                                                                                                   |
| SOC 2, ISO 27001                            | Goal       |      ❌      | No evidence of compliance-related code or documentation.                                                                                                          |
| FedRAMP                                     | Goal       |      ❌      | No evidence of FedRAMP-related code or documentation.                                                                                                             |

## Missing or To-Be-Built Functionality

Based on the analysis, here is a prioritized list of missing or to-be-built functionality:

### High Priority (Core Functionality)

*   **Kubernetes-based Scan Orchestration:** The current `docker-compose` setup is suitable for development but not for a scalable production environment. This needs to be migrated to a Kubernetes-based system for orchestration, scaling, and management of scanner jobs.
*   **gVisor Sandbox Implementation:** This is a critical security feature mentioned in the PRD for isolating scanner execution. There is no evidence of gVisor or any other sandboxing technology in the current `docker-compose` setup.
*   **Risk Score Algorithm Implementation:** The backend needs to implement the scoring algorithm defined in the PRD.
*   **Embeddable Trust Badges:** The backend needs an endpoint and the corresponding logic to generate the SVG trust badges for embedding in READMEs and websites, as described in the PRD.
*   **Webhook Notification System:** The platform is missing a system to dispatch webhook notifications for events like scan completion and policy failures.
*   **One-Click Auto-Fix Implementation:** While the data structures for fixes are present, the backend lacks the implementation to apply these fixes to the user's code.
*   **Comprehensive Plain-Language Findings:** Ensure all 27 scanners have their findings mapped to plain-language explanations.

### Medium Priority (Key Features)

*   **Intelligent Language Detection:** A more robust language detection mechanism is needed to accurately select the right set of scanners for a given project.
*   **Policy-as-Code Engine:** The OPA integration needs to be fully implemented to allow for custom policy evaluation.
*   **Full Sigstore Integration:** The attestation generation and signing flow needs to be completed.
*   **AI Coding Tool Integrations:** The extent of the integration with Cursor, Copilot, and Claude Code is unclear and likely needs more work.

### Low Priority (Future Features & Compliance)

*   **Compliance Automation:** There is no evidence of any code or documentation to support the generation of compliance reports for SOC 2, ISO 27001, or FedRAMP.
*   **Multi-region Deployment:** The current infrastructure is not designed for multi-region deployment, which is a requirement for data residency and enterprise customers.
*   **API Security Testing Suite:** This is mentioned as a future product expansion in the PRD and is not yet implemented.
*   **Runtime Security Monitoring:** The Falco integration for runtime security is not yet implemented.
*   **Developer Security Training:** This is a future product feature and is not yet implemented.
