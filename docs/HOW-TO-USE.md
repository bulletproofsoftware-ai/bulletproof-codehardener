# How to use Code Hardener

There are three ways to drive Code Hardener: the **REST API**, the **MCP server**
(for AI agents), and the **dashboard UI**. All three sit on top of the same
backend.

## 1. REST API

The API is served under `/api/v1`. In local/dev mode the backend accepts an
`X-User-Id` header to scope requests to a user; in production, use JWT bearer
auth from `/api/v1/auth`.

### Create a project

```bash
curl -X POST http://localhost:4000/api/v1/projects \
  -H 'Content-Type: application/json' \
  -H 'X-User-Id: you@example.com' \
  -d '{"name":"my-app","repositoryUrl":"https://github.com/org/my-app"}'
# -> { "success": true, "data": { "id": "<projectId>", ... } }
```

### Start a scan

```bash
curl -X POST http://localhost:4000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -H 'X-User-Id: you@example.com' \
  -d '{"projectId":"<projectId>","repositoryUrl":"https://github.com/org/my-app","scanType":"standard","branch":"main"}'
# -> { "success": true, "data": { "id": "<scanId>", "status": "pending", ... } }
```

`scanType` accepts any profile id (`quick`, `standard`, `comprehensive`, `api`,
`supply_chain`, `compliance`, `pre_commit`, …). `standard` is the recommended
default for source trees.

### Poll scan status

```bash
curl http://localhost:4000/api/v1/scans/<scanId> \
  -H 'X-User-Id: you@example.com'
# data.status transitions: pending -> running -> completed
# data.score, data.findingsCount populate on completion
```

### Retrieve findings (paginated)

```bash
curl 'http://localhost:4000/api/v1/scans/<scanId>/findings?status=all&page=1&limit=200' \
  -H 'X-User-Id: you@example.com'
```

Each finding includes `severity`, `title`, `description`, `filePath`,
`lineNumber`, `scanner`, `ruleId`, `cwe`, `owaspCategory`, `fixAvailable`, and
`fixDescription`.

### Reports, attestation, SBOM

```bash
# Markdown / SARIF / JSON report
curl 'http://localhost:4000/api/v1/scans/<scanId>/report?format=markdown' \
  -H 'X-User-Id: you@example.com' -o report.md
curl 'http://localhost:4000/api/v1/scans/<scanId>/report?format=sarif' \
  -H 'X-User-Id: you@example.com' -o report.sarif.json

# In-toto attestation for a completed scan
curl http://localhost:4000/api/v1/scans/<scanId>/attestation \
  -H 'X-User-Id: you@example.com'
```

### Selected endpoints

| Method & path | Description |
|---------------|-------------|
| `GET /api/v1/projects` | List projects |
| `POST /api/v1/projects` | Create a project |
| `GET /api/v1/projects/:id` | Get a project |
| `GET /api/v1/projects/:id/stats` | Project statistics |
| `DELETE /api/v1/projects/:id` | Delete a project |
| `POST /api/v1/scans` | Start a scan |
| `GET /api/v1/scans` | List scans |
| `GET /api/v1/scans/:id` | Scan status / summary |
| `POST /api/v1/scans/:id/cancel` | Cancel a running scan |
| `POST /api/v1/scans/:id/retry` | Retry a scan |
| `GET /api/v1/scans/:id/findings` | Findings for a scan |
| `GET /api/v1/scans/:id/report` | Report (`format=markdown\|sarif\|json`) |
| `GET /api/v1/scans/:id/attestation` | In-toto attestation |
| `GET /api/v1/findings/:id` | A single finding |
| `GET /api/v1/findings/:id/patches` | Suggested patches |
| `POST /api/v1/findings/bulk-status` | Bulk-update finding status |
| `GET /api/v1/attestations/:id/verify` | Verify an attestation |
| `GET /api/v1/health` | Liveness |
| `GET /api/v1/ready` | Readiness (checks DB) |

The full contract is defined in `backend/openapi.yaml`.

## 2. MCP (AI agents)

The MCP server exposes the platform's capabilities as tools an agent can call.

### Claude Code (stdio — recommended for local use)

```json
{
  "mcpServers": {
    "codehardener": {
      "command": "node",
      "args": ["./backend/dist/mcp-server.js"],
      "cwd": "/path/to/bulletproof-codehardener",
      "env": { "DB_HOST": "localhost", "REDIS_HOST": "localhost" }
    }
  }
}
```

### Cursor (SSE)

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

### Available MCP tools

The tool set is assembled in `backend/src/services/mcp/server.ts`
(`getMcpToolDefinitions`). There are 21 tools in total.

**Core tools** (defined in `MCP_TOOLS`):

| Tool | Description |
|------|-------------|
| `codehardener_scan` | Run a security scan on the current project or a path |
| `codehardener_status` | Status of a running or completed scan |
| `codehardener_findings` | Findings from a completed scan |
| `codehardener_fix` | Fix suggestions for a specific finding |
| `codehardener_score` | Security score and risk assessment for a project |
| `codehardener_attestation` | Sigstore/in-toto attestation for a scan |
| `codehardener_sbom` | Generate a CycloneDX SBOM for a project |
| `codehardener_compare` | Diff findings between two scans |
| `codehardener_dismiss` | Dismiss a finding (false positive / accepted risk) |
| `codehardener_history` | Scan history and score trend for a project |
| `codehardener_get_report` | Structured report (markdown / SARIF / JSON) |

**Orchestrated / targeted tools** (in `backend/src/services/mcp/tools/`):

| Tool | Description |
|------|-------------|
| `codehardener_scan_project` | One-shot: create project, scan, return findings |
| `codehardener_scan_file` | Scan a single file |
| `codehardener_scan_diff` | Scan a diff / changed set |
| `codehardener_auto_fix` | Apply an automated fix for a finding |
| `codehardener_bulk_fix` | Apply automated fixes across findings |
| `codehardener_get_findings` | Query findings (DefectDojo or local DB) |
| `codehardener_get_quality_score` | Quality/risk score |
| `codehardener_get_trends` | Historical scan trends |
| `codehardener_run_tests` | Trigger test execution via n8n |
| `codehardener_workflow_status` | Check an n8n workflow execution |

## 3. Dashboard UI

The Next.js dashboard (`dashboard/`) provides projects, scans, findings, and
score views over the same API. Run it with `cd dashboard && npm run dev` (port
3001) or deploy it behind your reverse proxy.

## Typical agent workflow

1. `codehardener_scan_project` (or `POST /projects` + `POST /scans`) to scan.
2. `codehardener_status` / `GET /scans/:id` until `completed`.
3. `codehardener_findings` to read the results, filtered by severity.
4. `codehardener_fix` / `codehardener_auto_fix` to remediate.
5. Re-scan and confirm the score improves and criticals/highs reach zero.
6. `codehardener_attestation` for supply-chain provenance.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
