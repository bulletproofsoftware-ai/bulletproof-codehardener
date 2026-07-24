# Software Bill of Materials (SBOM)

This document summarizes the Software Bill of Materials for Code Hardener. The
machine-readable CycloneDX 1.5 SBOMs are committed alongside it and are generated
directly from each package's installed dependency tree with:

```bash
npm sbom --sbom-format cyclonedx --omit dev > docs/<package>.cyclonedx.json
```

(`--omit dev` excludes development-only dependencies, so these reflect what ships
at runtime.)

## SBOM files

| Package | SBOM | Runtime components |
|---------|------|--------------------|
| Backend API + MCP server (`backend/`) | [`backend.cyclonedx.json`](backend.cyclonedx.json) | 220 |
| Dashboard (`dashboard/`) | [`dashboard.cyclonedx.json`](dashboard.cyclonedx.json) | 78 |
| CLI (`cli/`) | [`cli.cyclonedx.json`](cli.cyclonedx.json) | 1 |
| Node SDK (`sdks/node/`) | [`sdk-node.cyclonedx.json`](sdk-node.cyclonedx.json) | 0 (dependency-free) |

## License distribution

Aggregated across the runtime dependency trees (declared licenses; a small
number of components declare compound expressions):

### Backend (220 components)

| License | Count |
|---------|-------|
| MIT | 200 |
| ISC | 6 |
| BSD-3-Clause | 5 |
| Apache-2.0 | 5 |
| BSD-2-Clause | 3 |
| 0BSD | 1 |

### Dashboard (78 components)

| License | Count |
|---------|-------|
| MIT | 53 |
| ISC | 13 |
| Apache-2.0 | 4 |
| BSD-3-Clause | 2 |
| LGPL-3.0-or-later | 1 |
| MPL-2.0 OR Apache-2.0 | 1 |
| MIT AND Zlib | 1 |
| Apache-2.0 AND LGPL-3.0-or-later AND MIT | 1 |

All dependency licenses are OSI-approved and compatible with the project's own
**Apache-2.0** license. The `LGPL-3.0-or-later` component in the dashboard tree is
consumed as an unmodified library (dynamic linkage), consistent with LGPL
distribution terms.

## Key runtime dependencies (backend)

| Package | Version | Purpose |
|---------|---------|---------|
| express | ^4.21.0 | HTTP framework |
| @modelcontextprotocol/sdk | ^1.26.0 | MCP server/protocol |
| drizzle-orm | ^0.45.2 | Postgres ORM |
| pg | ^8.12.0 | Postgres driver |
| bullmq | ^5.12.0 | Job queue (scan worker) |
| ioredis | ^5.4.1 | Redis client |
| helmet | ^7.1.0 | HTTP security headers |
| jsonwebtoken | ^9.0.2 | JWT auth |
| argon2 / bcryptjs | ^0.44.0 / ^2.4.3 | Password hashing |
| multer | ^2.2.0 | Multipart upload handling |
| js-yaml | ^4.3.0 | YAML parsing |
| zod | ^3.23.8 | Input validation |
| stripe | ^20.3.1 | Billing |

Several transitive packages are pinned to patched versions via npm `overrides`
in `backend/package.json` (`fast-uri`, `hono`, `brace-expansion`) and in
`dashboard/package.json` / `marketing/package.json` (`postcss`, `sharp`) to
remediate known advisories — see [scan/scan-report.md](scan/scan-report.md).

## Base images

The backend and scanner containers are built on **`node:20-alpine`**
(`backend/Dockerfile`, `backend/Dockerfile.scanner`); the scanner image
additionally installs the security tool binaries. The Next.js dashboard image is
also built on a Node 20 Alpine base. Both application images run as a non-root
user (UID 1001) at runtime.

## Regenerating the SBOM

```bash
cd backend   && npm install && npm sbom --sbom-format cyclonedx --omit dev > ../docs/backend.cyclonedx.json
cd dashboard && npm install && npm sbom --sbom-format cyclonedx --omit dev > ../docs/dashboard.cyclonedx.json
cd cli       && npm install && npm sbom --sbom-format cyclonedx --omit dev > ../docs/cli.cyclonedx.json
```

The platform can also emit an SBOM for any scanned project at runtime via the
`codehardener_sbom` MCP tool or the Syft-backed supply-chain scan profile.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
