# MCP Tools Reference

## Base Tools (10)

### codehardener_scan

Run a security scan on the current project or specified path.

```json
{
  "path": ".",
  "profile": "standard",
  "scanners": ["trivy", "gitleaks"]
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| path | string | no | Path to scan (defaults to `.`) |
| profile | string | no | `quick`, `standard`, `comprehensive` |
| scanners | string[] | no | Specific scanners to run |

Returns: `{ scanId, status: "queued", estimatedTime }`.

### codehardener_status

Get scan status.

```json
{ "scanId": "uuid" }
```

Returns: `{ scanId, status, score, riskLevel, findingsCount, startedAt, completedAt }`.

### codehardener_findings

Get findings from a completed scan with plain-language translations.

```json
{ "scanId": "uuid", "severity": "high", "limit": 20 }
```

### codehardener_fix

Get fix suggestions for a specific finding.

```json
{ "findingId": "uuid" }
```

Returns: `{ title, severity, riskExplanation, actionRequired, filePath, lineNumber, codeSnippet }`.

### codehardener_score

Get project security score (0-1000) with risk badge.

```json
{ "projectId": "uuid" }
```

Returns: `{ score, riskLevel, badge, findings: { critical, high, medium, low }, recommendation }`.

### codehardener_attestation

Get Sigstore attestation for a completed scan.

```json
{ "scanId": "uuid" }
```

### codehardener_sbom

Generate SBOM for a project.

```json
{ "projectId": "uuid", "format": "cyclonedx-json" }
```

### codehardener_compare

Compare findings between two scans.

```json
{ "baseScanId": "uuid", "headScanId": "uuid" }
```

Returns: `{ summary: { introduced, resolved, unchanged }, trend: "improving"|"degrading"|"stable" }`.

### codehardener_dismiss

Dismiss a finding.

```json
{ "findingId": "uuid", "reason": "false_positive", "comment": "Not applicable" }
```

### codehardener_history

Get scan history and score trend.

```json
{ "projectId": "uuid", "limit": 10 }
```

---

## High-Level Orchestrated Tools (6)

### codehardener_scan_project

One-shot tool: creates project, runs scan, polls for completion, returns findings summary. Best for agents that want results in a single call.

```json
{
  "name": "my-project",
  "source_url": "https://github.com/org/repo",
  "profile": "standard",
  "wait": true
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| name | string | yes | Project name |
| source_url | string | yes | Repository URL |
| profile | string | no | Scan profile (default: `standard`) |
| wait | boolean | no | Wait for completion (default: true, max 5 min) |

### codehardener_get_findings

Query findings via DefectDojo (if enabled) or local DB.

```json
{
  "project_id": "uuid",
  "severity": "high",
  "active": true,
  "limit": 25
}
```

### codehardener_get_risk_score

Get risk score from DefectDojo metrics or local finding counts.

```json
{ "project_id": "uuid" }
```

Returns: `{ score, level, findings: { critical, high, medium, low }, source: "defectdojo"|"local" }`.

### codehardener_get_trends

Historical scan data with trend calculation.

```json
{ "project_id": "uuid", "limit": 10 }
```

### codehardener_run_tests

Trigger test execution via n8n workflow.

```json
{
  "project_id": "uuid",
  "test_suite": "security",
  "test_ids": ["test-1", "test-2"]
}
```

### codehardener_workflow_status

Check n8n workflow execution status.

```json
{ "execution_id": "123" }
```
