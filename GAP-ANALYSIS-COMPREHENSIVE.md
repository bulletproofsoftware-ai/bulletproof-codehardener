# Code Hardener - Comprehensive Gap Analysis

**Date**: January 1, 2026
**Analyst**: Claude (Code Review)
**Question**: Will this product work as designed?

---

## Executive Summary

**Verdict: The product WILL NOT work as designed in its current state.**

The codebase contains a solid foundation (~18,000 lines of TypeScript across backend and frontend), but critical functionality gaps prevent the product from delivering on its core value proposition. The existing documentation (BRD-tracker.json and GAP-ANALYSIS-ACCURATE.md) contain significant inaccuracies that misrepresent the actual implementation state.

| Metric | PRD Requirement | Actual Implementation | Coverage |
|--------|-----------------|----------------------|----------|
| Security Scanners | 27 tools | 5 tools | 18.5% |
| MCP Tools | 15 tools (claimed) | 5 tools | 33% |
| Integration Methods | 5 patterns | 2 patterns | 40% |
| OAuth Providers | 5 providers | 0 providers | 0% |
| Attestation/Signing | Full Sigstore | None | 0% |

---

## Section 1: Accurate State of Implementation

### What Actually Exists

#### Backend (`/backend/src/`) - ~4,250 lines TypeScript

**Working Components:**
1. **Scanner Pipeline** (`/services/scanners/pipeline.ts:15-21`)
   - 5 scanners implemented: Trivy, Gitleaks, OpenGrep, Checkov, Nuclei
   - Concurrent execution with timeout handling
   - Profile-based scanner selection (quick, standard, comprehensive)

2. **Risk Scoring** (`/services/assurance/risk-score.ts:44-99`)
   - 0-1000 point scoring system
   - Severity-based penalties with caps (critical=100pts, high=40pts, medium=15pts, low=5pts)
   - Risk level categorization (excellent, good, moderate, poor, critical)
   - Trend calculation from historical data

3. **Plain Language Translation** (`/services/translator/plain-language.ts:11-50`)
   - 15 CWE explanations mapped
   - 10 OWASP Top 10 2021 categories covered
   - Severity-specific action guidance

4. **MCP Server** (`/services/mcp/server.ts:11-100`)
   - 5 tools: scan, status, findings, fix, score
   - Database integration for project/scan management
   - User-scoped data access

5. **Database Schema** (`/postgres/init.sql`)
   - 15 tables with proper relationships
   - Row-level security considerations
   - Audit logging structure

6. **Job Queue** (`/services/queue/scan.queue.ts`)
   - BullMQ integration with Redis
   - Async scan job processing

#### Frontend (`/dashboard/`) - ~13,900 lines TypeScript/TSX

- Next.js 14 with App Router
- React components for dashboard, projects, scans
- TailwindCSS styling
- Basic UI skeleton exists

---

## Section 2: Critical Gaps (Blockers)

### Gap 1: Scanner Coverage (82% Missing)

**PRD Requirement**: 27 integrated security tools
**Implemented**: 5 tools

| Category | Required | Implemented | Missing |
|----------|----------|-------------|---------|
| SAST | Bandit, Gosec, ESLint Security, PMD, OpenGrep | OpenGrep | 4 tools |
| DAST | OWASP ZAP, Nuclei | Nuclei | 1 tool |
| SCA/Container | Trivy, Grype | Trivy | 1 tool |
| Secrets | Gitleaks, detect-secrets | Gitleaks | 1 tool |
| IaC | Checkov | Checkov | None |
| Load Testing | Locust, Gatling, Artillery | None | 3 tools |
| API Testing | Newman, WireMock, Pact, RESTler | None | 4 tools |
| Browser/Visual | Playwright, BackstopJS, Pa11y | None | 3 tools |
| Supply Chain | Syft, in-toto, Cosign | None | 3 tools |
| Policy/Reporting | OPA, DefectDojo, Allure | None | 3 tools |

**Impact**: Users cannot get comprehensive security coverage. The "27 tools in one interface" value proposition fails.

### Gap 2: Authentication System (100% Missing)

**PRD Requirement**: OAuth with Google, GitHub, GitLab, Bitbucket, Microsoft
**Implemented**: None

```typescript
// oauth_accounts table exists in schema but no handlers
// /backend/src/routes/auth.ts does not exist
```

**Impact**: No user authentication = no production deployment possible.

### Gap 3: Cryptographic Attestation (100% Missing)

**PRD Requirement**: Sigstore integration (Cosign, Fulcio, Rekor)
**Implemented**: None

```sql
-- attestations table exists but no signing logic
CREATE TABLE attestations (
  id UUID PRIMARY KEY,
  signature TEXT NOT NULL,  -- Never populated
  certificate TEXT,         -- Never populated
  rekor_log_id TEXT,        -- Never populated
  ...
);
```

**Impact**: Cannot provide cryptographic proof of scan execution. SLSA compliance impossible.

### Gap 4: Policy Engine (100% Missing)

**PRD Requirement**: OPA/Rego policy evaluation, custom rules
**Implemented**: Database tables only

```sql
-- Tables exist but no evaluation engine
CREATE TABLE policies (...);
CREATE TABLE policy_rules (...);
```

**Impact**: No automated compliance gating or custom rule enforcement.

### Gap 5: Webhook System (0% Functional)

**PRD Requirement**: Webhook notifications for scan events
**Implemented**: Tables only, no dispatch logic

**Impact**: No CI/CD integration capability.

---

## Section 3: Moderate Gaps (Degraded Experience)

### Gap 6: Report Generation (0% Implemented)

- PDF/HTML export not implemented
- `reports` table unused
- No Allure integration

### Gap 7: Badge Service (Partial)

- Badge data exists in code (`getRiskBadge()`)
- No dynamic badge endpoint (`/badge/{project}.svg`)
- No embeddable badge for READMEs

### Gap 8: Integration Ecosystem (20% Complete)

| Integration | Status |
|-------------|--------|
| Claude Code MCP | Partial (5/15 tools) |
| REST API | Basic structure |
| GitHub Actions | Not implemented |
| GitLab CI | Not implemented |
| Replit/Lovable/Bolt | Not implemented |
| Slack/Teams | Not implemented |
| VS Code Extension | Not implemented |

### Gap 9: Plain Language Translation (Partial)

- 15 CWEs covered (need 50+ for production)
- No dynamic learning or LLM fallback
- Missing mappings for many vulnerability types

### Gap 10: Billing/Pricing (0% Implemented)

- No Stripe integration
- No usage tracking
- No tier enforcement

---

## Section 4: Documentation Discrepancies

### BRD-tracker.json Claims vs Reality

| Claim | Reality |
|-------|---------|
| "30 scanners integrated" | 5 scanners exist |
| "35/35 requirements complete" | ~30% actually implemented |
| "MCP server with 15 tools" | 5 tools implemented |
| "Full Sigstore integration" | 0% implemented |
| "OAuth with 5 providers" | 0 providers |

### GAP-ANALYSIS-ACCURATE.md Claims vs Reality

| Claim | Reality |
|-------|---------|
| "Backend does not exist" | Backend exists with ~4,250 lines |
| "No database schema" | Complete 15-table schema exists |
| "No scanner code" | 5 working scanners with 652 lines |

---

## Section 5: What Works Today

If deployed as-is, the following would function:

1. **Basic Scanning**: Run Trivy, Gitleaks, OpenGrep, Checkov, or Nuclei against code
2. **Risk Scoring**: Calculate and display 0-1000 security scores
3. **Finding Translation**: Convert some CVEs/CWEs to plain language
4. **MCP Integration**: Basic Claude Code integration with 5 commands
5. **Database**: Store projects, scans, findings with proper schema

---

## Section 6: Recommended Path to MVP

### Phase 1: Authentication (1-2 weeks effort)
1. Implement GitHub OAuth (primary developer audience)
2. Add session management with JWT
3. Connect to existing users table

### Phase 2: Core Scanner Expansion (2-3 weeks effort)
Priority additions to reach 12 scanners:
1. Bandit (Python SAST)
2. ESLint Security (JS/TS SAST)
3. Gosec (Go SAST)
4. OWASP ZAP (DAST)
5. Grype (container SCA)
6. detect-secrets (secrets)
7. Syft (SBOM generation)

### Phase 3: Attestation MVP (1-2 weeks effort)
1. Integrate Cosign for basic signing
2. Store attestations in database
3. Verification endpoint

### Phase 4: Billing & Limits (1 week effort)
1. Stripe integration
2. Usage metering
3. Tier enforcement

### Phase 5: Integration Expansion (ongoing)
1. GitHub Actions workflow template
2. REST API documentation
3. Complete MCP toolset

---

## Section 7: Conclusion

### Will This Product Work as Designed?

**No, not in its current state.**

**Can it work?** Yes. The foundation is solid:
- Well-structured TypeScript codebase
- Working scanner pipeline architecture
- Proper database schema
- Functional risk scoring

**What's needed:**
- 22 more scanners (~80% of core feature)
- Authentication system (blocker)
- Attestation system (differentiator)
- Billing integration (monetization)

**Estimated effort to MVP**: 6-8 weeks of focused development

**Recommendation**: Prioritize authentication and 7 additional high-value scanners to reach a viable beta product. The attestation and full 27-tool integration can follow in subsequent releases.

---

## Appendix: File References

| Component | File Path | Lines |
|-----------|-----------|-------|
| Scanner Pipeline | `backend/src/services/scanners/pipeline.ts` | 99 |
| Trivy Scanner | `backend/src/services/scanners/trivy.ts` | 130 |
| Risk Scoring | `backend/src/services/assurance/risk-score.ts` | 136 |
| MCP Server | `backend/src/services/mcp/server.ts` | 350 |
| Plain Language | `backend/src/services/translator/plain-language.ts` | 169 |
| Database Schema | `postgres/init.sql` | 320 |
| Docker Compose | `docker-compose.yml` | 124 |
