# Code Hardener — Claude Code Skill

Security scanning skill for Claude Code. Scans your project for vulnerabilities, secrets, misconfigurations, and supply chain risks using 35 integrated open-source security tools.

## Prerequisites

- Code Hardener backend running (local Docker stack or hosted)
- MCP server configured in Claude Code settings

## MCP Server Configuration

Add to your Claude Code MCP settings (`~/.claude/mcp.json`):

```json
{
  "mcpServers": {
    "codehardener": {
      "command": "node",
      "args": ["path/to/codehardener/backend/dist/mcp-server.js"],
      "env": {
        "DATABASE_URL": "postgresql://codehardener:codehardener@localhost:5435/codehardener",
        "REDIS_URL": "redis://localhost:6381"
      }
    }
  }
}
```

Or connect to a running backend:

```json
{
  "mcpServers": {
    "codehardener": {
      "type": "sse",
      "url": "http://localhost:4000/api/v1/mcp/stream"
    }
  }
}
```

## Available Tools

### Scanning
- **codehardener_scan_project** — Full project scan with auto-wait for results
- **codehardener_scan_file** — Scan a single file (fast feedback during dev)
- **codehardener_scan_diff** — Scan git diff for new issues (pre-commit/PR)
- **codehardener_scan** — Low-level scan trigger (use scan_project for most cases)

### Results
- **codehardener_status** — Check scan progress
- **codehardener_findings** — Get findings with plain-language translations
- **codehardener_get_report** — Full markdown/SARIF/JSON report
- **codehardener_score** — Security score (0-1000) with risk badge
- **codehardener_history** — Score trend over time
- **codehardener_compare** — Diff findings between two scans

### Remediation
- **codehardener_auto_fix** — Get fix instructions for a specific finding
- **codehardener_bulk_fix** — Batch fix suggestions grouped by file
- **codehardener_fix** — Detailed fix guidance with code context
- **codehardener_dismiss** — Dismiss false positives with audit trail

### Supply Chain
- **codehardener_attestation** — Sigstore cryptographic attestation
- **codehardener_sbom** — Software Bill of Materials (CycloneDX/SPDX)

## Scan Profiles

| Profile | Scanners | Time | Use Case |
|---------|----------|------|----------|
| quick | 2 | ~30s | Fast feedback |
| standard | 8 | ~2-5m | Regular dev |
| comprehensive | 24 | ~10-15m | Releases/audits |
| security | 9 | ~3-5m | Security focus |
| api | 5 | ~2-3m | API testing |
| performance | 3 | ~5m | Load testing |
| full | 35 | ~15-20m | Everything |
| auto | varies | varies | Language-detected |

## Example Workflows

### Quick Security Check
```
Scan my project with the quick profile and show me any critical findings.
```

### Pre-Release Audit
```
Run a comprehensive scan, generate the SBOM, and create an attestation for this release.
```

### Fix Vulnerabilities
```
Get the bulk fix suggestions for my last scan and apply the critical ones.
```

### Diff Check Before Commit
```
Scan my current git diff for any security issues I'm about to commit.
```
