# Installation

Code Hardener runs as a set of Docker containers orchestrated by Docker Compose.
The backend API and MCP server are TypeScript (Node 20); the dashboard is
Next.js.

## Prerequisites

- **Docker** and **Docker Compose v2** (`docker compose`, not the legacy
  `docker-compose`).
- **Node.js ≥ 20** — only needed if you want to run the backend, MCP server, or
  SDKs directly outside Docker.
- Roughly 6 GB of free RAM for the full stack (the scanner image bundles many
  tools).

## Quick start (Docker Compose)

```bash
# 1. Clone and configure
git clone https://github.com/bulletproofsoftware-ai/bulletproof-codehardener.git
cd bulletproof-codehardener
cp .env.example .env
# Edit .env — at minimum set strong values for DB_PASSWORD and JWT_SECRET.

# 2. Start the core services
docker compose up -d

# 3. Verify
./scripts/verify-e2e.sh
```

### Compose stacks

| File | Use |
|------|-----|
| `docker-compose.yml` | Core stack (backend, scanner worker, Postgres, Redis, and optional n8n / DefectDojo). |
| `docker-compose.extended.yml` | Adds extended services. Layer with `-f`. |
| `docker-compose.prod.yml` | Production overrides (behind the nginx reverse proxy in `nginx/`). |

To run an extended stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.extended.yml up -d
```

The repository also ships a `Makefile` with convenience targets:

```bash
make up        # start core services
make down      # stop all services
make logs      # tail logs
make status    # show service status
make verify    # run the E2E verification script
```

## Default service endpoints

After `docker compose up -d`, the following are available on the host (ports come
from `.env`):

| Service | Default URL | Env var |
|---------|-------------|---------|
| Backend API | `http://localhost:4000/api/v1` | `BACKEND_PORT` |
| MCP over SSE | `http://localhost:4000/mcp/sse` | — |
| n8n (optional) | `http://localhost:5678` | `N8N_PORT` |
| DefectDojo (optional) | `http://localhost:8083` | `DEFECTDOJO_PORT` |

> The dashboard (`dashboard/`) runs on port 3001 in development
> (`next dev -p 3001`); wire it up behind your reverse proxy for production.

## Required configuration

All configuration is via environment variables. Start from `.env.example`. The
variables you **must** change before any real use:

| Variable | Purpose |
|----------|---------|
| `DB_PASSWORD` / `POSTGRES_PASSWORD` | Postgres password (min 16 chars). |
| `JWT_SECRET` | JWT signing key (min 32 chars). |
| `INTERNAL_API_KEY` | Shared key for n8n → backend calls. |

Optional integrations are toggled by `DEFECTDOJO_ENABLED` and `N8N_ENABLED`, each
with their own URL / credential / secret variables (see `.env.example` for the
full list, including DefectDojo `DD_*` and n8n `N8N_*` settings and OAuth
credentials for GitHub / Google SSO).

## Running the backend directly (development)

```bash
cd backend
npm install
npm run dev        # API on http://localhost:4000 (tsx watch)
npm run build      # compile TypeScript to dist/
npm test           # vitest
npm run typecheck  # tsc --noEmit
```

## Running the MCP server (stdio)

```bash
cd backend
npm run build
npm run mcp-server     # node dist/mcp-server.js
# or for development:
npm run mcp-dev        # tsx src/mcp-server.ts
```

See [HOW-TO-USE.md](HOW-TO-USE.md) for wiring the MCP server into Claude Code and
Cursor.

## SDK installation

```bash
# Node.js
cd sdks/node && npm install && npm run build

# Python
cd sdks/python && pip install -e .

# Go
cd sdks/go && go build ./...
```

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
