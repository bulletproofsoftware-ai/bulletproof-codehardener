# Security Scan Report — bulletproof-codehardener

Code Hardener scans its own source tree. This report summarizes the **final,
clean** `standard`-profile scan after all critical and high findings were
remediated.

## Result

| Metric | Value |
|--------|-------|
| Profile | `standard` |
| Score | **767 / 1000** — quality level **good** |
| Critical | **0** |
| High | **0** |
| Medium | 65 |
| Low | 416 |
| Info | 33 |
| Secrets (gitleaks) | **PASS** (0) |
| Branch | `main` |
| Scanners executed | 15 (trivy, gitleaks, opengrep, checkov, grype, syft, package-validator, oxlint, ruff, actionlint, jscpd, typos, spectral, newman, file-inventory) |

> Score is the platform's authoritative post-adjustment project score
> (0 critical + 0 high, penalized only by residual medium/low/info under the
> square-root model). The attached full report shows the raw pre-adjustment
> figure; both agree on **0 critical / 0 high**.

## What was fixed (critical + high → 0)

The initial `standard` scan reported **41 high** findings (0 critical). Every one
was fixed and verified by re-scan. Fixes were committed to `main` before the
re-scan, because the scanner evaluates the committed `HEAD`, not the working
tree.

### Code — opengrep `detect-child-process` (8 findings)

Scanner prerequisite checks built shell-string commands and executed them with
`exec` / `execSync`. Each was converted to `execFile` / `execFileSync` with an
**argument array** (no shell), so interpolated paths and container IDs can no
longer be interpreted as shell metacharacters. Pipes to `head` were replaced by
JavaScript-side line slicing.

| File | Fix |
|------|-----|
| `backend/src/services/scanners/stryker.ts` | `execSync(find …)` → `execFileSync('find', [...])` |
| `backend/src/services/scanners/pytest.ts` | 2× `execSync(find …)` → `execFileSync` |
| `backend/src/services/scanners/mutmut.ts` | 2× `execSync(find …)` → `execFileSync` |
| `backend/src/services/scanners/jest.ts` | `execSync(find …)` → `execFileSync` |
| `backend/src/services/scanners/aflpp.ts` | `execSync(find …)` → `execFileSync` |
| `backend/src/services/scanners/container-isolation.ts` | `exec(docker kill …)` / `execAsync(docker …)` → `execFile` / `execFileAsync` arg-array |

### Dependencies — CVE bumps (33 findings, deduplicated across trivy + grype)

| Package | From | To | Advisory |
|---------|------|----|----------|
| multer (backend) | 2.1.1 | 2.2.0 | CVE-2026-5079 (DoS via nested field names) |
| js-yaml (backend) | 4.1.1 → 4.3.0; 3.14.2 → 3.15.0 | patched | CVE-2026-59869 (quadratic CPU on merge-key chains) |
| fast-uri (backend, transitive) | 3.1.2 | 3.1.4 | CVE-2026-16221, CVE-2026-13676 (host confusion) |
| hono (backend, transitive) | 4.12.23 | 4.12.32 | CVE-2026-54290 (CORS wildcard + credentials) |
| brace-expansion (backend, transitive) | 5.0.6 / 2.1.0 / 1.1.14 | 5.0.8 / 2.1.2 / 1.1.16 | CVE-2026-13149 (exponential-time expansion) |
| next (dashboard + marketing) | 15.5.19 | 15.5.21 | CVE-2026-64641, CVE-2026-64645, CVE-2026-64649 (SSRF / DoS in App Router) |
| postcss (dashboard + marketing, transitive) | 8.4.31 | ≥ 8.5.12 | CVE-2026-45623 (arbitrary file read via sourceMappingURL) |
| sharp (dashboard + marketing, transitive) | 0.34.5 | 0.35.x | GHSA-f88m-g3jw-g9cj (libvips CVEs) |

Transitive packages were pinned via npm `overrides`; direct dependencies were
bumped in their `package.json`. The backend TypeScript build (`npm run build`)
passes (exit 0) after these changes.

### License consistency

`backend/package.json`, `sdks/node/package.json`, and
`sdks/python/pyproject.toml` declared `MIT` while the repository's `LICENSE` is
Apache-2.0. All were corrected to **Apache-2.0**.

## What remains (low-risk, not blocking)

Per the platform's own guidance, medium/low findings are not driven to zero;
they are documented honestly. Nothing below is a critical or high.

**Medium (65)** — dominated by opengrep *audit*-tier heuristics that flag
patterns for human review rather than confirmed vulnerabilities:

- `path-join-resolve-traversal` (18) and `detect-non-literal-regexp` (13) —
  audit heuristics on dynamic path/regex construction within trusted,
  internally-derived inputs.
- `express-unvalidated-params` (7), `direct-response-write` / `raw-html-format`
  (2) — audit-tier Express patterns.
- `github-actions-mutable-action-tag` (6) — CI actions referenced by tag rather
  than commit SHA (hardening opportunity, not a code vulnerability).
- `nginx request-host-used` / `possible-h2c-smuggling` (8) — reverse-proxy config
  heuristics.
- `hardcoded-jwt-secret` (2) — placeholder/example secrets in non-production
  config, not live credentials (gitleaks reports **0** real secrets).
- A handful of medium-severity dependency advisories with no released fix or
  low exploitability (`CVE-2026-65898`, `CVE-2026-5078`, `GHSA-frvp-7c67-39w9`).

**Low (416) / Info (33)** — largely trivy informational package metadata,
duplicate-code and style signals, and inventory items.

One scanner (`typos`) reported an internal error and produced no findings; it did
not affect the critical/high result.

## Signed artifacts

| Artifact | File |
|----------|------|
| Rich portal report (PDF, 123 pp, attestation certificate on page 1) | [`bulletproof-codehardener-scan-report.pdf`](bulletproof-codehardener-scan-report.pdf) |
| Full findings report (Markdown) | [`scan-report-full.md`](scan-report-full.md) |
| SARIF 2.1.0 (IDE / CI) | [`scan-report.sarif.json`](scan-report.sarif.json) |
| In-toto attestation | [`attestation.json`](attestation.json) |

Scan-target paths in the SARIF and full Markdown reports have been normalized
(the scanner's internal `/scan-target/` prefix removed); no host filesystem paths
appear in any artifact.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
