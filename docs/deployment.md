# Deployment Guide

## Prerequisites

- Docker and Docker Compose v2
- 4GB RAM minimum (8GB recommended for full stack)
- Node.js 20+ (for local MCP development)

## Docker Compose Deployment

### 1. Configure

```bash
cp .env.example .env
```

Required settings:
- `DB_PASSWORD` / `POSTGRES_PASSWORD` — Match these
- `JWT_SECRET` — Random string, 32+ characters
- `INTERNAL_API_KEY` — Generate with `openssl rand -hex 32`

### 2. Start

```bash
docker compose up -d
```

This starts 7 services:
- postgres, redis — Data layer
- backend — API + MCP SSE
- scanner — Worker with security tools
- n8n — Workflow automation
- defectdojo — Vulnerability management
- init — Runs once to set up databases and import workflows

### 3. Verify

```bash
./scripts/verify-e2e.sh
```

Or check individual services:
```bash
curl http://localhost:4000/health
curl http://localhost:5678/healthz
curl http://localhost:8083/api/v2/
```

### 4. First-time setup

1. **DefectDojo**: Log in at http://localhost:8083 with `admin/defectdojo`. Change the password immediately.
2. **DefectDojo API key**: Generate at DefectDojo > API v2 > Token, then set `DEFECTDOJO_API_KEY` in `.env`.
3. **n8n**: Access at http://localhost:5678 with `admin/codehardener`. Workflows should be pre-imported.

## Service Configuration

### Optional services

The dashboard is available as a Docker Compose profile:

```bash
# Include dashboard
docker compose --profile dashboard up -d
```

### DefectDojo

To disable DefectDojo (reduces resource usage):
```env
DEFECTDOJO_ENABLED=false
```

### n8n

To disable n8n (backend uses local BullMQ worker instead):
```env
N8N_ENABLED=false
```

## Environment Variables

### Core
| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | postgres | Database host |
| `DB_PORT` | 5432 | Database port |
| `DB_USER` | codehardener | Database user |
| `DB_PASSWORD` | — | Database password (required) |
| `DB_NAME` | codehardener | Database name |
| `REDIS_HOST` | redis | Redis host |
| `REDIS_PORT` | 6379 | Redis port |
| `BACKEND_PORT` | 4000 | API server port |
| `NODE_ENV` | development | Environment |
| `LOG_LEVEL` | info | Log level |

### Authentication
| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | — | JWT signing key (required) |
| `JWT_EXPIRES_IN` | 7d | Access token TTL |
| `JWT_REFRESH_EXPIRES_IN` | 30d | Refresh token TTL |

### Integrations
| Variable | Default | Description |
|----------|---------|-------------|
| `DEFECTDOJO_ENABLED` | true | Enable DefectDojo |
| `DEFECTDOJO_URL` | http://defectdojo:8080 | DefectDojo URL |
| `DEFECTDOJO_API_KEY` | — | DefectDojo API token |
| `N8N_ENABLED` | true | Enable n8n delegation |
| `N8N_URL` | http://n8n:5678 | n8n URL |
| `N8N_WEBHOOK_BASE` | http://n8n:5678/webhook | n8n webhook base |
| `INTERNAL_API_KEY` | dev-internal-key-... | n8n ↔ backend auth |

### GitHub
| Variable | Default | Description |
|----------|---------|-------------|
| `GITHUB_CLIENT_ID` | — | OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | — | OAuth app secret |
| `GITHUB_TOKEN_ENCRYPTION_KEY` | — | AES key for token storage |

## Resource Requirements

| Service | CPU | RAM | Disk |
|---------|-----|-----|------|
| postgres | 0.5 | 512MB | 1GB+ |
| redis | 0.1 | 128MB | — |
| backend | 0.5 | 256MB | — |
| scanner | 2.0 | 1GB | 2GB (tools) |
| n8n | 0.5 | 512MB | — |
| defectdojo | 1.0 | 1GB | 500MB |

Total minimum: ~4 cores, 4GB RAM.

## Volumes

| Volume | Purpose |
|--------|---------|
| `postgres_data` | Database files |
| `redis_data` | Redis persistence |
| `n8n_data` | n8n workflows and credentials |
| `defectdojo_media` | DD uploads and reports |
| `scan_results` | Scanner output artifacts |

## Troubleshooting

### Init container fails
Check logs: `docker compose logs init`
Common cause: Postgres not ready. The init container retries, but if it exits too early, run `docker compose restart init`.

### n8n workflows not imported
Run manually: `make workflows-import`

### DefectDojo slow to start
DefectDojo takes 2-3 minutes on first boot (migrations). Check: `docker compose logs defectdojo`

### Scanner container large
The scanner image includes 27 tools and is ~2GB. Build once and cache: `docker compose build scanner`
