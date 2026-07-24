# Administrator Guide

This guide covers operating a Code Hardener deployment: services, configuration,
health, and day-to-day operations. It is scoped to what ships in this
repository — where a capability is optional or environment-specific, that is
called out.

## Services

A default Docker Compose deployment runs:

| Service | Role | Default port |
|---------|------|--------------|
| `backend` | Express API (`/api/v1`) + MCP SSE endpoint | 4000 (`BACKEND_PORT`) |
| Scanner worker | BullMQ worker running the tools in a hardened container | — (internal) |
| `postgres` | Primary datastore (projects, scans, findings, scores, attestations) | 5432 (internal) |
| `redis` | Job queue + cache | 6379 (internal) |
| `n8n` (optional) | Automation backbone | 5678 (`N8N_PORT`) |
| `defectdojo` (optional) | Vulnerability-management analytics UI | 8083 (`DEFECTDOJO_PORT`) |
| Dashboard | Next.js UI | 3001 (dev) |

Reverse-proxy configuration for production lives in `nginx/`; a Helm chart is in
`helm/` for Kubernetes deployments.

## Configuration

All configuration is via environment variables loaded from `.env` (template:
`.env.example`). Key groups:

### Core (required)

| Variable | Notes |
|----------|-------|
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | Postgres connection. Password ≥ 16 chars. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | Postgres container init. |
| `REDIS_HOST`, `REDIS_PORT` | Redis connection. |
| `JWT_SECRET` | JWT signing key ≥ 32 chars. |
| `JWT_EXPIRES_IN`, `JWT_REFRESH_EXPIRES_IN` | Token lifetimes. |
| `INTERNAL_API_KEY` | Shared secret for n8n → backend calls. |
| `NODE_ENV`, `BACKEND_PORT`, `LOG_LEVEL` | Runtime. |

### DefectDojo (optional — `DEFECTDOJO_ENABLED`)

`DEFECTDOJO_URL`, `DEFECTDOJO_PORT`, `DEFECTDOJO_API_KEY`, `DD_ADMIN_USER`,
`DD_ADMIN_PASSWORD`, `DD_DATABASE_URL`, `DD_SECRET_KEY`,
`DD_CREDENTIAL_AES_256_KEY`.

### n8n (optional — `N8N_ENABLED`)

`N8N_URL`, `N8N_PORT`, `N8N_WEBHOOK_BASE`, `N8N_API_KEY`, `N8N_BASIC_AUTH_USER`,
`N8N_BASIC_AUTH_PASSWORD`, and the `N8N_DB_*` Postgres-backing settings.

### SSO / OAuth (optional)

`GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` and
`GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` (plus `GITHUB_CALLBACK_URL`,
`GITHUB_TOKEN_ENCRYPTION_KEY`, `GITHUB_WEBHOOK_BASE_URL`).

> **Rotate every `change-me` / `change-this` placeholder before exposing the
> stack.** The defaults in `.env.example` are for local bring-up only.

## Health and readiness

The backend exposes two probes:

- `GET /api/v1/health` — liveness; returns 200 while the process is up.
- `GET /api/v1/ready` — readiness; verifies the database connection and reports
  `status: healthy | degraded | unhealthy` with per-dependency checks and
  response time.

Wire `GET /api/v1/ready` into your orchestrator's readiness probe and load
balancer health check.

## Running scans as an operator

Scans are created via the API (`POST /api/v1/scans`) or MCP and executed by the
scanner worker as BullMQ jobs. Operationally:

- **Rate limits & quotas.** Scan creation is rate-limited and subject to
  per-account scan/project limits (`scanRateLimiter`, `enforceScanLimit`,
  `enforceProjectLimit` middleware). Adjust for your plan/tier as needed.
- **Cancel / retry.** `POST /api/v1/scans/:id/cancel` and
  `POST /api/v1/scans/:id/retry` manage in-flight or failed scans.
- **Score recalculation.** `POST /api/v1/scans/recalculate-scores` recomputes
  scores across scans (useful after changing scoring weights).

## Scanner container isolation

The scanner worker runs tools inside a dedicated container (built from
`backend/Dockerfile.scanner`) and enforces per-scan container isolation with
timeouts and automatic cleanup of stale containers (see
`backend/src/services/scanners/container-isolation.ts`). Container invocations
use argument-array process spawning (no shell), so scan-target paths and
container IDs cannot be interpreted as shell metacharacters.

Both `backend/Dockerfile` and `backend/Dockerfile.scanner` drop to a non-root
user (`nodejs` / `scanner`, UID 1001) for the runtime stage.

## n8n automation (optional)

When `N8N_ENABLED=true`, n8n hosts the automation workflows in `n8n-workflows/`
and templates in `n8n-templates/`. Import them with `make workflows-import`. The
backend talks to n8n using `INTERNAL_API_KEY`; n8n calls back to the backend's
`/api/v1/n8n-hooks` endpoints. See [n8n-workflows.md](n8n-workflows.md).

## Backups and data

State lives in Postgres (`postgres/` holds the schema/seed SQL). Back up the
Postgres volume on your normal cadence. Redis holds transient queue/cache data
and does not require backup. Scan result artifacts under `reports/` are
regenerated per run and are git-ignored.

## Logs

The backend uses `pino` structured logging; set `LOG_LEVEL` (`debug`, `info`,
`warn`, `error`). Tail container logs with `make logs` or
`docker compose logs -f backend`.

## Reference docs

- [architecture.md](architecture.md) — component and data-flow detail.
- [API-REFERENCE.md](API-REFERENCE.md) — full endpoint reference.
- [deployment.md](deployment.md) — deployment specifics.
- [mcp-tools.md](mcp-tools.md) — MCP tool schemas.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
