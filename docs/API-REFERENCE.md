# Code Hardener API Reference

**Version:** 1.0.0
**Base URL:** `https://api.codehardener.dev` (production) | `http://localhost:4000` (development)
**Last Updated:** December 2025

---

## Table of Contents

1. [Authentication](#authentication)
2. [Common Response Formats](#common-response-formats)
3. [Endpoints](#endpoints)
   - [Health](#health)
   - [Authentication](#authentication-endpoints)
   - [Projects](#projects)
   - [Scans](#scans)
   - [Findings](#findings)
   - [Attestations](#attestations)
   - [API Keys](#api-keys)
   - [Policies](#policies)
   - [Webhooks](#webhooks)
   - [Reports](#reports)
   - [Badges](#badges)
4. [Error Codes](#error-codes)
5. [Rate Limits](#rate-limits)
6. [SDK Examples](#sdk-examples)

---

## Authentication

The API supports two authentication methods:

### JWT Bearer Token

```bash
Authorization: Bearer <access_token>
```

Obtain tokens via the `/auth/login` or `/auth/register` endpoints.

### API Key

```bash
X-API-Key: vs_live_<key>
```

Create API keys via the dashboard or `/api-keys` endpoint.

---

## Common Response Formats

### Success Response

```json
{
  "data": { ... },
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "totalPages": 5
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request body",
    "details": [
      {
        "field": "email",
        "message": "Invalid email address"
      }
    ]
  }
}
```

---

## Endpoints

---

## Health

### Get Health Status

Check API health and readiness.

```
GET /health
```

**Response:**

```json
{
  "status": "ok",
  "timestamp": "2025-12-23T10:00:00.000Z",
  "version": "1.0.0"
}
```

### Get Readiness Status

Check if all dependencies are ready.

```
GET /health/ready
```

**Response:**

```json
{
  "status": "ready",
  "database": "connected",
  "timestamp": "2025-12-23T10:00:00.000Z"
}
```

---

## Authentication Endpoints

### Register User

Create a new user account.

```
POST /auth/register
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Valid email address |
| password | string | Yes | Minimum 8 characters |
| name | string | Yes | User's display name (1-100 chars) |

**Example:**

```bash
curl -X POST https://api.codehardener.dev/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "name": "John Doe"
  }'
```

**Response (201):**

```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe"
  },
  "accessToken": "eyJhbGci...",
  "refreshToken": "eyJhbGci..."
}
```

---

### Login

Authenticate and receive tokens.

```
POST /auth/login
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Registered email |
| password | string | Yes | Account password |

**Example:**

```bash
curl -X POST https://api.codehardener.dev/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

**Response (200):**

```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "John Doe"
  },
  "accessToken": "eyJhbGci...",
  "refreshToken": "eyJhbGci..."
}
```

---

### Refresh Token

Get new access token using refresh token.

```
POST /auth/refresh
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| refreshToken | string | Yes | Valid refresh token |

**Response (200):**

```json
{
  "accessToken": "eyJhbGci...",
  "refreshToken": "eyJhbGci..."
}
```

---

### Forgot Password

Request password reset email.

```
POST /auth/forgot-password
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Registered email |

**Response (200):**

```json
{
  "message": "If an account exists, a reset email has been sent"
}
```

---

### Reset Password

Reset password using token.

```
POST /auth/reset-password
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Reset token from email |
| password | string | Yes | New password (min 8 chars) |

**Response (200):**

```json
{
  "message": "Password has been reset successfully"
}
```

---

### Change Password

Change password for authenticated user.

```
POST /auth/change-password
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| currentPassword | string | Yes | Current password |
| newPassword | string | Yes | New password (min 8 chars) |

**Response (200):**

```json
{
  "message": "Password changed successfully"
}
```

---

### Get Current User

Get authenticated user's profile.

```
GET /auth/me
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Logout

Invalidate current tokens.

```
POST /auth/logout
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "message": "Logged out successfully"
}
```

---

## Projects

### List Projects

Get all projects for the authenticated user.

```
GET /projects
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| search | string | - | Search by name or description |

**Example:**

```bash
curl -X GET "https://api.codehardener.dev/projects?page=1&limit=10" \
  -H "Authorization: Bearer <token>"
```

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "name": "My Project",
      "description": "Project description",
      "repositoryUrl": "https://github.com/user/repo",
      "createdAt": "2025-12-23T10:00:00.000Z",
      "updatedAt": "2025-12-23T10:00:00.000Z",
      "scanCount": 5,
      "lastScanAt": "2025-12-23T09:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 25,
    "totalPages": 3
  }
}
```

---

### Create Project

Create a new project.

```
POST /projects
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Project name (1-100 chars) |
| description | string | No | Description (max 500 chars) |
| repositoryUrl | string | No | Git repository URL |
| settings | object | No | Custom project settings |

**Example:**

```bash
curl -X POST https://api.codehardener.dev/projects \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Project",
    "description": "Backend API for mobile app",
    "repositoryUrl": "https://github.com/user/api"
  }'
```

**Response (201):**

```json
{
  "id": "uuid",
  "name": "My API Project",
  "description": "Backend API for mobile app",
  "repositoryUrl": "https://github.com/user/api",
  "settings": {},
  "createdAt": "2025-12-23T10:00:00.000Z",
  "updatedAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Get Project

Get a specific project by ID.

```
GET /projects/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "name": "My Project",
  "description": "Project description",
  "repositoryUrl": "https://github.com/user/repo",
  "settings": {},
  "createdAt": "2025-12-23T10:00:00.000Z",
  "updatedAt": "2025-12-23T10:00:00.000Z",
  "statistics": {
    "totalScans": 10,
    "lastScanAt": "2025-12-23T09:00:00.000Z",
    "openFindings": 5,
    "securityScore": 85
  }
}
```

---

### Update Project

Update a project's details.

```
PATCH /projects/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | No | Project name (1-100 chars) |
| description | string | No | Description (max 500 chars) |
| repositoryUrl | string | No | Git repository URL (null to remove) |
| settings | object | No | Custom project settings |

**Response (200):**

```json
{
  "id": "uuid",
  "name": "Updated Project",
  "description": "Updated description",
  "repositoryUrl": null,
  "settings": {},
  "updatedAt": "2025-12-23T11:00:00.000Z"
}
```

---

### Delete Project

Delete a project and all associated data.

```
DELETE /projects/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

## Scans

### List Scans

Get all scans for the authenticated user.

```
GET /scans
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| projectId | uuid | - | Filter by project |
| status | string | - | Filter: pending, running, completed, failed |
| scanType | string | - | Filter: sast, dast, sca, secrets, container, iac, custom |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "projectId": "uuid",
      "projectName": "My Project",
      "status": "completed",
      "scanType": "sast",
      "createdAt": "2025-12-23T10:00:00.000Z",
      "startedAt": "2025-12-23T10:00:05.000Z",
      "completedAt": "2025-12-23T10:05:00.000Z",
      "findingsCount": 12
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 50,
    "totalPages": 3
  }
}
```

---

### Create Scan

Start a new security scan.

```
POST /scans
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| projectId | uuid | Yes | Project to scan |
| scanType | string | Yes | Type: sast, dast, sca, secrets, container, iac, custom |
| config | object | No | Scanner-specific configuration |

**Scan Types:**

| Type | Description |
|------|-------------|
| sast | Static Application Security Testing |
| dast | Dynamic Application Security Testing |
| sca | Software Composition Analysis |
| secrets | Secret/credential detection |
| container | Container image scanning |
| iac | Infrastructure as Code scanning |
| custom | Custom scanner configuration |

**Example:**

```bash
curl -X POST https://api.codehardener.dev/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "projectId": "uuid",
    "scanType": "sast",
    "config": {
      "languages": ["python", "javascript"],
      "excludePaths": ["node_modules", "vendor"]
    }
  }'
```

**Response (201):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "status": "pending",
  "scanType": "sast",
  "config": {
    "languages": ["python", "javascript"],
    "excludePaths": ["node_modules", "vendor"]
  },
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Get Scan

Get scan details and results.

```
GET /scans/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "projectName": "My Project",
  "status": "completed",
  "scanType": "sast",
  "config": {},
  "results": {
    "summary": {
      "critical": 2,
      "high": 5,
      "medium": 10,
      "low": 8,
      "info": 3
    },
    "duration": 295000,
    "filesScanned": 150
  },
  "createdAt": "2025-12-23T10:00:00.000Z",
  "startedAt": "2025-12-23T10:00:05.000Z",
  "completedAt": "2025-12-23T10:05:00.000Z"
}
```

---

### Cancel Scan

Cancel a running or pending scan.

```
POST /scans/:id/cancel
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "status": "cancelled",
  "cancelledAt": "2025-12-23T10:02:00.000Z"
}
```

---

## Findings

### List Findings

Get security findings across projects.

```
GET /findings
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| projectId | uuid | - | Filter by project |
| scanId | uuid | - | Filter by scan |
| severity | string | - | Filter: critical, high, medium, low, info |
| status | string | - | Filter: open, acknowledged, resolved, false_positive |
| search | string | - | Search in title/description |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "scanId": "uuid",
      "projectId": "uuid",
      "projectName": "My Project",
      "title": "SQL Injection Vulnerability",
      "description": "User input is concatenated into SQL query...",
      "severity": "critical",
      "status": "open",
      "location": "src/api/users.ts",
      "lineNumber": 42,
      "codeSnippet": "const query = `SELECT * FROM users WHERE id = ${userId}`",
      "cweId": "CWE-89",
      "cveId": null,
      "remediation": "Use parameterized queries instead...",
      "createdAt": "2025-12-23T10:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "totalPages": 5
  }
}
```

---

### Get Finding

Get a specific finding with full details.

```
GET /findings/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "scanId": "uuid",
  "projectId": "uuid",
  "projectName": "My Project",
  "title": "SQL Injection Vulnerability",
  "description": "User input is concatenated into SQL query without proper sanitization.",
  "severity": "critical",
  "status": "open",
  "location": "src/api/users.ts",
  "lineNumber": 42,
  "codeSnippet": "const query = `SELECT * FROM users WHERE id = ${userId}`",
  "cweId": "CWE-89",
  "cveId": null,
  "remediation": "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [userId])",
  "metadata": {
    "scanner": "opengrep",
    "ruleId": "javascript.express.security.audit.db-sqli"
  },
  "notes": null,
  "createdAt": "2025-12-23T10:00:00.000Z",
  "updatedAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Update Finding

Update finding status or add notes.

```
PATCH /findings/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | string | No | Status: open, acknowledged, resolved, false_positive |
| notes | string | No | Notes about the finding (max 2000 chars) |

**Response (200):**

```json
{
  "id": "uuid",
  "status": "acknowledged",
  "notes": "Investigating with security team",
  "updatedAt": "2025-12-23T11:00:00.000Z"
}
```

---

### Bulk Update Findings

Update multiple findings at once.

```
POST /findings/bulk-update
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| findingIds | array | Yes | Array of finding UUIDs (1-100) |
| status | string | Yes | New status for all findings |

**Response (200):**

```json
{
  "updated": 15,
  "status": "resolved"
}
```

---

### Get Finding Patches

Get candidate patch suggestions for a specific finding (LLM-generated patches from deep/full profiles).

```
GET /api/v1/findings/:id/patches
```

**Headers:** `Authorization: Bearer <token>`

**URL Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| id | uuid | Yes | Finding ID (must be a valid UUID) |

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| status | string | - | Filter by patch status: proposed, accepted, rejected |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "findingId": "uuid",
      "scanId": "uuid",
      "patchDiff": "--- a/src/api/users.ts\n+++ b/src/api/users.ts\n@@ -10,7 +10,7 @@...",
      "rationale": "Use parameterized queries to prevent SQL injection. The original code concatenates user input directly into the SQL string.",
      "validationNotes": "Build: verified with `npm run build`. Exploit path: original SQL injection vector now sanitized via parameterized binding. Tests: unit tests pass; no test regressions. Bypass checks: binding is cryptographically enforced by the ORM layer.",
      "modelUsed": "claude-sonnet-4-5-20250929",
      "status": "proposed",
      "createdAt": "2025-12-23T10:00:00.000Z"
    }
  ]
}
```

**Response (404):**

Finding not found or finding has no patches.

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Finding with id 'invalid-uuid' not found"
  }
}
```

**Response (422):**

Invalid UUID format for finding ID.

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid finding ID format",
    "details": [
      {
        "field": "id",
        "message": "Must be a valid UUID"
      }
    ]
  }
}
```

**Security Notes:**
- Requires authentication; findings are scoped to user's projects (cross-tenant requests return 404)
- Patches are LLM-generated suggestions in `proposed` status by default; status lifecycle (`proposed`/`accepted`/`rejected`) is metadata only — server has no code-path to auto-apply patches
- Patch content is rendered in reports and responses inside fenced markdown blocks with embedded-fence neutralization

---

## Attestations

### List Attestations

Get cryptographic attestations.

```
GET /attestations
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| projectId | uuid | - | Filter by project |
| type | string | - | Filter: vex, sbom, slsa, in-toto, custom |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "projectId": "uuid",
      "projectName": "My Project",
      "scanId": "uuid",
      "type": "sbom",
      "format": "spdx",
      "digest": "sha256:abc123...",
      "createdAt": "2025-12-23T10:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 10,
    "totalPages": 1
  }
}
```

---

### Create Attestation

Create a new attestation.

```
POST /attestations
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| projectId | uuid | Yes | Associated project |
| scanId | uuid | No | Associated scan |
| type | string | Yes | Type: vex, sbom, slsa, in-toto, custom |
| format | string | Yes | Format: json, spdx, cyclonedx, predicate |
| content | object | Yes | Attestation content |
| metadata | object | No | Additional metadata |

**Response (201):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "scanId": "uuid",
  "type": "sbom",
  "format": "spdx",
  "digest": "sha256:abc123...",
  "content": { ... },
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Get Attestation

Get attestation with full content.

```
GET /attestations/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "projectName": "My Project",
  "scanId": "uuid",
  "type": "sbom",
  "format": "spdx",
  "digest": "sha256:abc123...",
  "content": {
    "spdxVersion": "SPDX-2.3",
    "packages": [...]
  },
  "metadata": {},
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Delete Attestation

Delete an attestation.

```
DELETE /attestations/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

### Verify Attestation

Verify attestation integrity.

```
POST /attestations/:id/verify
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "valid": true,
  "digest": "sha256:abc123...",
  "verifiedAt": "2025-12-23T10:00:00.000Z"
}
```

---

## API Keys

### List API Keys

Get all API keys for the user.

```
GET /api-keys
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| isActive | boolean | - | Filter by active status |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "name": "CI/CD Pipeline",
      "keyPrefix": "vs_live_abc...",
      "permissions": ["scans:write", "findings:read"],
      "isActive": true,
      "lastUsedAt": "2025-12-23T09:00:00.000Z",
      "expiresAt": null,
      "createdAt": "2025-12-23T08:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 3,
    "totalPages": 1
  }
}
```

---

### Get Available Permissions

Get list of available API key permissions.

```
GET /api-keys/permissions
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "permissions": [
    "projects:read",
    "projects:write",
    "projects:delete",
    "scans:read",
    "scans:write",
    "findings:read",
    "findings:write",
    "attestations:read",
    "attestations:write",
    "attestations:delete",
    "policies:read",
    "policies:write",
    "policies:delete",
    "webhooks:read",
    "webhooks:write",
    "webhooks:delete",
    "reports:read",
    "reports:write",
    "badges:read",
    "admin"
  ]
}
```

---

### Create API Key

Create a new API key.

```
POST /api-keys
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Key name (1-100 chars) |
| permissions | array | Yes | Array of permission strings |
| expiresAt | datetime | No | Expiration date (ISO 8601) |

**Example:**

```bash
curl -X POST https://api.codehardener.dev/api-keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline",
    "permissions": ["scans:write", "findings:read"],
    "expiresAt": "2026-12-31T23:59:59.000Z"
  }'
```

**Response (201):**

```json
{
  "id": "uuid",
  "name": "CI/CD Pipeline",
  "key": "vs_live_a1b2c3d4e5f6...",
  "keyPrefix": "vs_live_a1b2c3...",
  "permissions": ["scans:write", "findings:read"],
  "expiresAt": "2026-12-31T23:59:59.000Z",
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

**Important:** The full `key` is only shown once at creation. Store it securely.

---

### Update API Key

Update API key settings.

```
PATCH /api-keys/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | No | Key name (1-100 chars) |
| permissions | array | No | Updated permissions |
| isActive | boolean | No | Enable/disable key |

**Response (200):**

```json
{
  "id": "uuid",
  "name": "Updated Name",
  "permissions": ["scans:write", "findings:read", "reports:read"],
  "isActive": true,
  "updatedAt": "2025-12-23T11:00:00.000Z"
}
```

---

### Delete API Key

Permanently delete an API key.

```
DELETE /api-keys/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

## Policies

### List Policies

Get security policies.

```
GET /policies
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| projectId | uuid | - | Filter by project |
| isGlobal | boolean | - | Filter global/project policies |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "name": "Block Critical Vulnerabilities",
      "description": "Block deployment if critical vulnerabilities found",
      "projectId": null,
      "isGlobal": true,
      "isActive": true,
      "rulesCount": 3,
      "createdAt": "2025-12-23T10:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 5,
    "totalPages": 1
  }
}
```

---

### Create Policy

Create a security policy with rules.

```
POST /policies
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Policy name (1-100 chars) |
| description | string | No | Description (max 500 chars) |
| projectId | uuid | No | Attach to specific project |
| isGlobal | boolean | No | Apply to all projects (default: false) |
| rules | array | Yes | Array of policy rules |

**Rule Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Rule name |
| condition | object | Yes | Rule condition (JSON logic) |
| action | string | Yes | Action: block, warn, allow |
| severity | string | No | Filter severity |

**Example:**

```bash
curl -X POST https://api.codehardener.dev/policies \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Critical Vulnerabilities",
    "description": "Block if critical findings exist",
    "isGlobal": true,
    "rules": [
      {
        "name": "No Critical",
        "condition": {"findings.critical": {"$eq": 0}},
        "action": "block",
        "severity": "critical"
      }
    ]
  }'
```

**Response (201):**

```json
{
  "id": "uuid",
  "name": "Block Critical Vulnerabilities",
  "description": "Block if critical findings exist",
  "projectId": null,
  "isGlobal": true,
  "isActive": true,
  "rules": [
    {
      "id": "uuid",
      "name": "No Critical",
      "condition": {"findings.critical": {"$eq": 0}},
      "action": "block",
      "severity": "critical"
    }
  ],
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Get Policy

Get policy with all rules.

```
GET /policies/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "name": "Block Critical Vulnerabilities",
  "description": "Block if critical findings exist",
  "projectId": null,
  "isGlobal": true,
  "isActive": true,
  "rules": [...],
  "createdAt": "2025-12-23T10:00:00.000Z",
  "updatedAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Update Policy

Update policy and rules.

```
PATCH /policies/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | No | Policy name |
| description | string | No | Description |
| isActive | boolean | No | Enable/disable policy |
| rules | array | No | Updated rules (replaces all) |

**Response (200):** Updated policy object

---

### Delete Policy

Delete a policy.

```
DELETE /policies/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

## Webhooks

### List Webhooks

Get configured webhooks.

```
GET /webhooks
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| projectId | uuid | - | Filter by project |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "name": "Slack Notifications",
      "url": "https://hooks.slack.com/...",
      "events": ["scan.completed", "finding.critical"],
      "projectId": null,
      "isActive": true,
      "createdAt": "2025-12-23T10:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 2,
    "totalPages": 1
  }
}
```

---

### Create Webhook

Create a new webhook.

```
POST /webhooks
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Webhook name (1-100 chars) |
| url | string | Yes | Endpoint URL |
| events | array | Yes | Events to subscribe to |
| projectId | uuid | No | Limit to specific project |
| headers | object | No | Custom HTTP headers |

**Available Events:**

- `scan.started`
- `scan.completed`
- `scan.failed`
- `finding.new`
- `finding.critical`
- `finding.resolved`
- `attestation.created`
- `policy.violation`

**Response (201):**

```json
{
  "id": "uuid",
  "name": "Slack Notifications",
  "url": "https://hooks.slack.com/...",
  "secret": "whsec_a1b2c3...",
  "events": ["scan.completed", "finding.critical"],
  "headers": {},
  "isActive": true,
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Get Webhook

Get webhook details.

```
GET /webhooks/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "name": "Slack Notifications",
  "url": "https://hooks.slack.com/...",
  "secret": "whsec_a1b2c3...",
  "events": ["scan.completed", "finding.critical"],
  "headers": {},
  "projectId": null,
  "isActive": true,
  "createdAt": "2025-12-23T10:00:00.000Z",
  "updatedAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Update Webhook

Update webhook settings.

```
PATCH /webhooks/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | No | Webhook name |
| url | string | No | Endpoint URL |
| events | array | No | Updated events |
| headers | object | No | Custom headers |
| isActive | boolean | No | Enable/disable |

**Response (200):** Updated webhook object

---

### Delete Webhook

Delete a webhook.

```
DELETE /webhooks/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

### Get Webhook Deliveries

Get delivery history for a webhook.

```
GET /webhooks/:id/deliveries
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "event": "scan.completed",
      "payload": {...},
      "responseStatus": 200,
      "success": true,
      "attempts": 1,
      "createdAt": "2025-12-23T10:00:00.000Z",
      "deliveredAt": "2025-12-23T10:00:01.000Z"
    }
  ],
  "pagination": {...}
}
```

---

### Redeliver Webhook

Retry a failed delivery.

```
POST /webhooks/:id/deliveries/:deliveryId/redeliver
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "status": "redelivered",
  "redeliveredAt": "2025-12-23T10:05:00.000Z"
}
```

---

## Reports

### List Reports

Get generated reports.

```
GET /reports
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page (max 100) |
| projectId | uuid | - | Filter by project |
| type | string | - | Filter: security, compliance, summary, custom |
| status | string | - | Filter: pending, generating, completed, failed |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "projectId": "uuid",
      "projectName": "My Project",
      "name": "Q4 Security Report",
      "type": "security",
      "format": "pdf",
      "status": "completed",
      "fileUrl": "/reports/download/uuid",
      "fileSize": 245760,
      "createdAt": "2025-12-23T10:00:00.000Z",
      "completedAt": "2025-12-23T10:02:00.000Z"
    }
  ],
  "pagination": {...}
}
```

---

### Create Report

Generate a new report.

```
POST /reports
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Report name (1-100 chars) |
| projectId | uuid | Yes | Project to report on |
| type | string | Yes | Type: security, compliance, summary, custom |
| format | string | Yes | Format: pdf, html, json, csv |
| config | object | No | Report configuration |
| scanIds | array | No | Specific scans to include |
| dateRange | object | No | Date range filter |

**Response (201):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "name": "Q4 Security Report",
  "type": "security",
  "format": "pdf",
  "status": "pending",
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Get Report

Get report details.

```
GET /reports/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "projectName": "My Project",
  "name": "Q4 Security Report",
  "type": "security",
  "format": "pdf",
  "status": "completed",
  "config": {},
  "fileUrl": "/reports/download/uuid",
  "fileSize": 245760,
  "createdAt": "2025-12-23T10:00:00.000Z",
  "completedAt": "2025-12-23T10:02:00.000Z"
}
```

---

### Download Report

Download generated report file.

```
GET /reports/:id/download
```

**Headers:** `Authorization: Bearer <token>`

**Response:** Binary file with appropriate Content-Type header

---

### Delete Report

Delete a report.

```
DELETE /reports/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

## Badges

### Public Badge

Get embeddable badge SVG (no authentication required).

```
GET /badges/public/:token
```

**Response:** SVG image

**Example (Markdown):**

```markdown
![Security Score](https://api.codehardener.dev/badges/public/abc123)
```

---

### List Badges

Get configured badges.

```
GET /badges
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| limit | integer | 20 | Items per page |
| projectId | uuid | - | Filter by project |

**Response (200):**

```json
{
  "data": [
    {
      "id": "uuid",
      "projectId": "uuid",
      "projectName": "My Project",
      "type": "security-score",
      "style": "flat",
      "label": "security",
      "token": "abc123...",
      "isPublic": true,
      "url": "https://api.codehardener.dev/badges/public/abc123",
      "createdAt": "2025-12-23T10:00:00.000Z"
    }
  ],
  "pagination": {...}
}
```

---

### Create Badge

Create a new badge.

```
POST /badges
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| projectId | uuid | Yes | Associated project |
| type | string | Yes | Type: security-score, scan-status, findings-count, last-scan, custom |
| style | string | No | Style: flat, flat-square, plastic, for-the-badge (default: flat) |
| label | string | No | Custom label (max 50 chars) |
| config | object | No | Badge-specific configuration |

**Badge Types:**

| Type | Description |
|------|-------------|
| security-score | Overall security score (0-100) |
| scan-status | Latest scan status |
| findings-count | Open findings count |
| last-scan | Time since last scan |
| custom | Custom badge configuration |

**Response (201):**

```json
{
  "id": "uuid",
  "projectId": "uuid",
  "type": "security-score",
  "style": "flat",
  "label": "security",
  "token": "abc123...",
  "isPublic": true,
  "url": "https://api.codehardener.dev/badges/public/abc123",
  "createdAt": "2025-12-23T10:00:00.000Z"
}
```

---

### Update Badge

Update badge settings.

```
PATCH /badges/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| label | string | No | Custom label |
| style | string | No | Badge style |
| config | object | No | Configuration |
| isPublic | boolean | No | Public visibility |

**Response (200):** Updated badge object

---

### Delete Badge

Delete a badge.

```
DELETE /badges/:id
```

**Headers:** `Authorization: Bearer <token>`

**Response (204):** No content

---

### Regenerate Badge Token

Generate new token (invalidates old URL).

```
POST /badges/:id/regenerate-token
```

**Headers:** `Authorization: Bearer <token>`

**Response (200):**

```json
{
  "id": "uuid",
  "token": "newtoken123...",
  "url": "https://api.codehardener.dev/badges/public/newtoken123"
}
```

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| VALIDATION_ERROR | 400 | Invalid request body or parameters |
| UNAUTHORIZED | 401 | Missing or invalid authentication |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource already exists |
| RATE_LIMITED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Server error |

---

## Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Authentication | 5 requests | 15 minutes |
| API (authenticated) | 100 requests | 1 minute |
| Scan submission | 10 scans | 1 hour |
| File upload | 20 uploads | 1 hour |
| Public badges | 1000 requests | 1 minute |

Rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1703332800
```

---

## SDK Examples

### cURL

```bash
# Authenticate
TOKEN=$(curl -s -X POST https://api.codehardener.dev/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password"}' | jq -r '.accessToken')

# Create project
curl -X POST https://api.codehardener.dev/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Project"}'
```

### JavaScript/TypeScript

```typescript
const API_BASE = 'https://api.codehardener.dev';

async function createScan(projectId: string, scanType: string) {
  const response = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ projectId, scanType }),
  });
  return response.json();
}
```

### Python

```python
import requests

API_BASE = "https://api.codehardener.dev"

def list_findings(token: str, project_id: str = None):
    headers = {"Authorization": f"Bearer {token}"}
    params = {"projectId": project_id} if project_id else {}
    response = requests.get(f"{API_BASE}/findings", headers=headers, params=params)
    return response.json()
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | December 2025 | Initial API release |

---

**End of API Reference**
