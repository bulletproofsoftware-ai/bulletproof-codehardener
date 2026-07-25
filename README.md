# Code Hardener

Security assurance platform for AI-first developers. Integrates 27 open-source security tools into a single interface that AI coding agents (Claude Code, Cursor, GitHub Copilot) can call through MCP.

![bulletproof-codehardener — overview](docs/media/infographic.png)

> **On the numbers:** 27 integrated open-source tools powering 37 analyzers (22 quality + 15 security). The tool count is the number of distinct upstream projects vendored into the scanner image; the analyzer count is the number of named checks those tools expose through the API and dashboard.

> 📚 Full documentation in [`docs/`](docs/) · 🔒 security scan in [`docs/scan/scan-report.md`](docs/scan/scan-report.md) · 🎬 System overview: [briefing](media/system-overview.md) · [video](media/system-overview.mp4).

## Quick Start

```bash
# 1. Clone and configure
git clone https://github.com/bulletproofsoftware-ai/bulletproof-codehardener.git
cd bulletproof-codehardener
cp .env.example .env
# Edit .env — at minimum set DB_PASSWORD and JWT_SECRET

# 2. Start all services
docker compose up -d

# 3. Verify
./scripts/verify-e2e.sh
```

Services will be available at:
- **Backend API**: http://localhost:4000
- **n8n Workflows**: http://localhost:5678
- **DefectDojo**: http://localhost:8083
- **MCP SSE**: http://localhost:4000/mcp/sse

## MCP Setup

### Claude Code (stdio — recommended for local use)

Add to your Claude Code MCP config:

```json
{
  "mcpServers": {
    "codehardener": {
      "command": "node",
      "args": ["./backend/dist/mcp-server.js"],
      "cwd": "/path/to/codehardener",
      "env": {
        "DB_HOST": "localhost",
        "REDIS_HOST": "localhost"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "codehardener": {
      "url": "http://localhost:4000/mcp/sse",
      "transport": "sse"
    }
  }
}
```

## Available MCP Tools

### Scanning
| Tool | Description |
|------|-------------|
| `codehardener_scan_project` | One-shot: create project, scan, return findings |
| `codehardener_scan` | Run a scan on a specific path |
| `codehardener_status` | Check scan status |

### Results
| Tool | Description |
|------|-------------|
| `codehardener_findings` | Get findings from a scan |
| `codehardener_get_findings` | Query findings via DefectDojo |
| `codehardener_fix` | Get fix suggestions for a finding |
| `codehardener_dismiss` | Dismiss a finding |
| `codehardener_compare` | Compare findings between two scans |

### Risk & Compliance
| Tool | Description |
|------|-------------|
| `codehardener_score` | Get project security score (0-1000) |
| `codehardener_get_risk_score` | Get risk score via DefectDojo metrics |
| `codehardener_get_trends` | Historical scan data and trends |
| `codehardener_attestation` | Get Sigstore attestation for a scan |
| `codehardener_sbom` | Generate SBOM |
| `codehardener_history` | Scan history for a project |

### Automation
| Tool | Description |
|------|-------------|
| `codehardener_run_tests` | Trigger test execution via n8n |
| `codehardener_workflow_status` | Check n8n workflow execution status |

## Scan Profiles

- **quick** — Trivy + Gitleaks (~30s)
- **standard** — 7 scanners including SCA and IaC (~2-5 min)
- **comprehensive** — 14 scanners, full coverage (~10-15 min)
- **security** — 9 scanners focused on vulnerabilities
- **api** — Newman + Pact + RESTler + Nuclei
- **deep** — Comprehensive + LLM threat-model + LLM vulnerability scan + triage + patches (requires `ANTHROPIC_API_KEY` + project opt-in)

## Architecture

```
AI Agents (Claude Code, Cursor)
    | MCP Protocol (stdio / SSE)
    v
Code Hardener MCP Server
    | triggers workflows, queries results
    v
n8n (automation backbone)
    |--- Scan Orchestration
    |--- Post-Scan Processing
    |--- Test Execution
    v
Backend API (Express) + Scanner Worker (27 tools)
    |                           |
    v                           v
Postgres (3 DBs)           DefectDojo
+ Redis (queue/cache)      (analytics UI)
```

See [docs/architecture.md](docs/architecture.md) for details.

## Integrated Tools (27)

**SAST**: Opengrep, Bandit, Gosec, ESLint Security, PMD
**DAST**: Nuclei, OWASP ZAP
**SCA**: Trivy, Grype
**Secrets**: Gitleaks, detect-secrets
**IaC**: Checkov
**Load Testing**: Locust, Artillery, k6
**API Testing**: Newman, Pact, RESTler
**Browser/Visual**: Playwright, BackstopJS, Pa11y
**Supply Chain**: Syft, in-toto, Cosign
**Policy/Reporting**: OPA, Allure, Conftest

## Development

```bash
# Backend dev server
cd backend && npm run dev

# Run tests
cd backend && npm test

# Type checking
cd backend && npm run typecheck

# MCP server (dev)
cd backend && npm run mcp-dev
```

## Make Targets

```bash
make up              # Start core services
make down            # Stop all services
make logs            # View logs
make mcp-start       # Run MCP server (stdio)
make mcp-test        # Test MCP tools
make workflows-import # Import n8n workflows
make scan-demo       # Full end-to-end demo
make verify          # Run E2E verification
make status          # Show service status
```

## Configuration

See [.env.example](.env.example) for all configuration options.

Key variables:
- `DB_PASSWORD` — Database password (required)
- `JWT_SECRET` — JWT signing key (required)
- `DEFECTDOJO_ENABLED` — Enable DefectDojo integration
- `N8N_ENABLED` — Enable n8n workflow delegation
- `INTERNAL_API_KEY` — Key for n8n-to-backend communication

## Documentation

- [Architecture](docs/architecture.md)
- [MCP Tools Reference](docs/mcp-tools.md)
- [n8n Workflows](docs/n8n-workflows.md)
- [Deployment Guide](docs/deployment.md)
- [API Reference](docs/API-REFERENCE.md)

## License

Apache-2.0 — see [LICENSE](LICENSE).
