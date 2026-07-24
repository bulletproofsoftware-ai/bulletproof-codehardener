# n8n Workflows

Code Hardener ships with 4 pre-built n8n workflow templates. They are auto-imported on first boot by the init container, or manually via `make workflows-import`.

## Workflows

### 1. Scan Orchestrator (`scan-orchestrator.json`)

Orchestrates the complete scan pipeline when `N8N_ENABLED=true`.

**Trigger**: Webhook `POST /webhook/scan-orchestrator`

**Flow**:
1. Receive scan request (scanId, projectId, profile, scanners)
2. GET project config from `/internal/projects/:id/config`
3. Resolve scanners from profile
4. Execute scanners in parallel batches (5 at a time)
5. Aggregate results
6. POST findings to `/internal/findings/import`
7. Trigger post-scan processor

**Input payload**:
```json
{
  "scanId": "uuid",
  "projectId": "uuid",
  "userId": "uuid",
  "profile": "standard",
  "scanners": ["trivy", "gitleaks", "opengrep"],
  "branch": "main"
}
```

### 2. Post-Scan Processor (`post-scan-processor.json`)

Runs after scan completion to handle policy evaluation, attestation, and notifications.

**Trigger**: Webhook `POST /webhook/post-scan-processor`

**Flow**:
1. Receive scan completion notification
2. POST to `/internal/policies/evaluate` — evaluate all active policies
3. If blocked: mark scan as failed, skip attestation
4. If passed: POST to `/internal/attestations/create`
5. Trigger GitHub issue creator (if critical/high findings exist)

### 3. Test Case Runner (`test-case-runner.json`)

Executes generated test cases and aggregates results.

**Trigger**: Webhook `POST /webhook/test-case-runner`

**Flow**:
1. Receive test execution request
2. Immediately respond with execution ID
3. Fetch test cases for project
4. Execute each test case
5. Aggregate results
6. Import results to DefectDojo (if enabled)

**Input payload**:
```json
{
  "projectId": "uuid",
  "testSuite": "security",
  "testIds": ["test-1", "test-2"]
}
```

### 4. GitHub Issue Creator (`github-issue-creator.json`)

Creates GitHub issues from critical/high severity findings.

**Trigger**: Webhook `POST /webhook/github-issue-creator`

**Flow**:
1. Receive findings array
2. Filter to critical and high severity only
3. Format issue body with finding details
4. Create GitHub issue via API (if GitHub integration configured)
5. Return created issue URLs

## Customization

All workflows are stored as JSON in `n8n-workflows/`. To customize:

1. Edit the JSON file directly, or
2. Access n8n UI at http://localhost:5678 (default: admin/codehardener)
3. Modify workflows visually
4. Export updated workflows: `n8n export:workflow --all > n8n-workflows/`

## Manual Import

```bash
# Via Makefile
make workflows-import

# Via n8n API directly
curl -X POST -u admin:codehardener \
  -H "Content-Type: application/json" \
  -d @n8n-workflows/scan-orchestrator.json \
  http://localhost:5678/api/v1/workflows
```

## Backend Fallback

When `N8N_ENABLED=false` or n8n is unreachable, the backend falls back to its local BullMQ worker for scan execution. The n8n integration is additive — the system works without it.
