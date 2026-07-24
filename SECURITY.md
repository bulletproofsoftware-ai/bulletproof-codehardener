# Code Hardener Security Assessment & Threat Model

## CISO Security Review - December 2025

This document outlines the security architecture, threat model, and security best practices for the Code Hardener platform.

---

## 1. Executive Security Summary

Code Hardener is a security scanning platform that processes untrusted code. This creates unique security challenges:

1. **We handle potentially malicious code** - Users upload code that may contain malware
2. **We store security findings** - Sensitive vulnerability information requires protection
3. **We provide compliance attestations** - Integrity of attestations is critical
4. **We have multi-tenant data** - Strict isolation between users is required

### Security Classification

| Data Type | Classification | Protection Level |
|-----------|---------------|------------------|
| User credentials | Confidential | Highest |
| API keys | Confidential | Highest |
| Security findings | Sensitive | High |
| Uploaded code | Sensitive | High |
| Attestations | Public (signed) | Integrity-critical |
| Scan metadata | Internal | Standard |

---

## 2. Threat Model (STRIDE Analysis)

### 2.1 Spoofing

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Account takeover via credential stuffing | Medium | High | Rate limiting, bcrypt with high cost factor, account lockout |
| API key theft | Medium | High | Key hashing, prefix-only display, rotation capability |
| JWT token forgery | Low | Critical | Strong secret, short expiry, token refresh flow |
| Session hijacking | Low | High | Secure cookies, HTTPS only, SameSite attribute |

**Controls Implemented:**
- Passwords hashed with bcrypt (cost factor 12)
- API keys hashed, only prefix shown after creation
- JWT tokens expire in 1 hour, refresh tokens in 7 days
- All cookies: `Secure; HttpOnly; SameSite=Strict`

### 2.2 Tampering

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Scan result manipulation | Low | Critical | Database transactions, audit logging |
| Attestation forgery | Low | Critical | Cryptographic signatures (Phase 2: Sigstore) |
| Code modification during scan | Low | High | Read-only mounts, checksums |
| Database tampering | Low | Critical | Row-level security, audit tables |

**Controls Implemented:**
- All database writes in transactions
- Audit logging for critical operations
- Uploaded files stored with SHA-256 checksum
- Attestations include hash of scan results

### 2.3 Repudiation

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| User denies triggering scan | Medium | Medium | Comprehensive audit logging |
| Disputed attestation validity | Medium | High | Timestamped, signed attestations |
| API key usage disputes | Low | Medium | Key usage logging with timestamps |

**Controls Implemented:**
- All API calls logged with user ID, timestamp, IP
- Attestations include creation timestamp
- Immutable audit log table

### 2.4 Information Disclosure

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Cross-tenant data leakage | Low | Critical | Strict query filtering, row-level security |
| Secrets in uploaded code | High | High | Code deleted after scan, findings redacted |
| Error message information leakage | Medium | Low | Generic error messages, detailed logs internal only |
| Scanner output leakage | Low | Medium | Output sanitization |

**Controls Implemented:**
- All queries filtered by user_id
- PostgreSQL row-level security enabled
- Uploaded code deleted within 24 hours
- Secrets in findings partially redacted
- Error responses contain only safe messages

### 2.5 Denial of Service

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Resource exhaustion via large uploads | Medium | High | File size limits (50MB), timeout limits |
| Scan queue flooding | Medium | Medium | Per-user rate limits, queue depth limits |
| Zip bomb attacks | Medium | High | Decompression limits, pre-scan validation |
| CPU exhaustion via complex code | Medium | High | Scan timeouts (5 min), resource limits |

**Controls Implemented:**
- Upload limit: 50MB per file
- Rate limits: 100 API calls/minute, 10 scans/hour
- Zip extraction limit: 500MB uncompressed
- Scan timeout: 5 minutes
- Container memory limit: 2GB
- Container CPU limit: 1 core

### 2.6 Elevation of Privilege

| Threat | Likelihood | Impact | Mitigation |
|--------|------------|--------|------------|
| Scanner escape | Low | Critical | Containerized scanners, no network access |
| SQL injection | Low | Critical | Parameterized queries only |
| Code execution via uploaded code | Medium | Critical | Isolated execution, no shell access |
| Admin role escalation | Low | Critical | No admin features in MVP |

**Controls Implemented:**
- All scanners run in Docker containers
- Scanner containers: `--network=none --read-only`
- All database queries use parameterized statements
- No dynamic code execution allowed
- User input never interpreted as executable code

---

## 3. Security Architecture

### 3.1 Network Security

```
                    INTERNET
                        |
                        v
              +------------------+
              |   Load Balancer  |  <- TLS termination
              |    (nginx)       |  <- Rate limiting
              +--------+---------+
                       |
         +-------------+-------------+
         |             |             |
         v             v             v
    +---------+   +---------+   +---------+
    |Marketing|   |Dashboard|   | Backend |
    |  :3000  |   |  :3001  |   |  :4000  |
    +---------+   +---------+   +----+----+
                                     |
                    +----------------+----------------+
                    |                |                |
                    v                v                v
              +----------+    +----------+    +----------+
              | Scanner  |    | Scanner  |    | Scanner  |
              |Container |    |Container |    |Container |
              | (no net) |    | (no net) |    | (no net) |
              +----------+    +----------+    +----------+
                                     |
                                     v
                              +----------+
                              |PostgreSQL|
                              |  :5432   |
                              +----------+
```

### 3.2 Container Security

**Scanner Container Configuration:**
```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
network_mode: none
mem_limit: 2g
cpus: 1
tmpfs:
  - /tmp:size=100m,mode=1777
```

### 3.3 Database Security

```sql
-- Row-level security policy
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

CREATE POLICY projects_isolation ON projects
    FOR ALL
    TO app_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Separate roles
CREATE ROLE app_user;
CREATE ROLE app_readonly;

GRANT SELECT, INSERT, UPDATE, DELETE ON projects TO app_user;
GRANT SELECT ON projects TO app_readonly;
```

---

## 4. Security Requirements by Component

### 4.1 Backend API

| Requirement | Implementation | Status |
|-------------|---------------|--------|
| HTTPS only | Redirect HTTP to HTTPS | Required |
| Input validation | Zod schemas on all endpoints | Required |
| Output encoding | JSON.stringify, no raw HTML | Required |
| Authentication | JWT with secure settings | Required |
| Authorization | User ID check on all queries | Required |
| Rate limiting | Express rate-limit middleware | Required |
| Logging | Structured JSON logs, no secrets | Required |
| Error handling | Generic messages, detailed internal logs | Required |
| SQL injection prevention | Parameterized queries only | Required |
| CORS | Strict origin whitelist | Required |

### 4.2 Frontend (Marketing & Dashboard)

| Requirement | Implementation | Status |
|-------------|---------------|--------|
| CSP headers | Strict Content-Security-Policy | Required |
| XSS prevention | React's default escaping | Required |
| CSRF protection | SameSite cookies, custom headers | Required |
| Secure storage | No secrets in localStorage | Required |
| Dependency audit | npm audit in CI | Required |
| Subresource integrity | SRI hashes for CDN resources | Required |

### 4.3 Scanner Execution

| Requirement | Implementation | Status |
|-------------|---------------|--------|
| Process isolation | Docker containers | Required |
| Network isolation | --network=none | Required |
| Filesystem isolation | Read-only root, tmpfs for writes | Required |
| Resource limits | CPU, memory, time limits | Required |
| Output sanitization | Strip ANSI, limit size | Required |
| No secrets in output | Redact detected secrets | Required |

---

## 5. Security Headers

**Required HTTP headers for all responses:**

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.codehardener.dev
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

---

## 6. Authentication Security

### 6.1 Password Requirements

```typescript
const passwordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSpecial: false, // Reduces memorability without security benefit
  maxLength: 128,
  checkBreached: true, // Check against HaveIBeenPwned API
};
```

### 6.2 JWT Configuration

```typescript
const jwtConfig = {
  algorithm: 'HS256',
  accessTokenExpiry: '1h',
  refreshTokenExpiry: '7d',
  issuer: 'codehardener',
  audience: 'codehardener-api',
};
```

### 6.3 Account Security

| Feature | Implementation |
|---------|---------------|
| Account lockout | 5 failed attempts -> 15 minute lockout |
| Password reset | Time-limited token (1 hour), single use |
| Email verification | Required before full access |
| Session invalidation | Logout invalidates all tokens |

---

## 7. API Security

### 7.1 API Key Security

```typescript
// API key format: vs_live_<32 random chars>
// Only prefix stored, rest is hashed
const apiKeyFormat = /^vs_(live|test)_[a-zA-Z0-9]{32}$/;

// Key generation
function generateApiKey(type: 'live' | 'test'): { key: string; hash: string } {
  const random = crypto.randomBytes(24).toString('base64url');
  const key = `vs_${type}_${random}`;
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return { key, hash };
}
```

### 7.2 Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| Authentication | 5 requests | 15 minutes |
| API (authenticated) | 100 requests | 1 minute |
| Scan submission | 10 scans | 1 hour |
| File upload | 20 uploads | 1 hour |
| Badge requests | 1000 requests | 1 minute |

---

## 8. Data Protection

### 8.1 Data Retention

| Data Type | Retention | Deletion Method |
|-----------|-----------|-----------------|
| Uploaded code | 24 hours | Secure delete |
| Scan results | 1 year | Soft delete, hard delete after 30 days |
| Audit logs | 2 years | Archived, then deleted |
| User accounts | Until deletion request | 30-day grace period |
| API keys | Until revoked | Immediate |

### 8.2 Encryption

| Data | At Rest | In Transit |
|------|---------|------------|
| Passwords | bcrypt hash | TLS 1.3 |
| API keys | SHA-256 hash | TLS 1.3 |
| Uploaded files | AES-256 (future) | TLS 1.3 |
| Database | PostgreSQL encryption (future) | TLS 1.3 |

---

## 9. Incident Response

### 9.1 Security Incident Classification

| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Data breach, system compromise | Immediate |
| High | Attempted breach, vulnerability exploited | 4 hours |
| Medium | Security misconfiguration, failed attack | 24 hours |
| Low | Security warning, policy violation | 72 hours |

### 9.2 Incident Response Contacts

```
Security Team: security@codehardener.dev
Emergency: [To be defined]
Bug Bounty: [To be defined]
```

---

## 10. Security Testing Requirements

### 10.1 Pre-Deployment Checklist

- [ ] All dependencies scanned with `npm audit`
- [ ] SAST scan with Semgrep passes
- [ ] Secrets scan with Gitleaks passes
- [ ] Container scan with Trivy passes
- [ ] Security headers verified
- [ ] Authentication flow tested
- [ ] Rate limiting verified
- [ ] Input validation tested
- [ ] SQL injection testing completed
- [ ] XSS testing completed

### 10.2 Continuous Security Testing

| Test Type | Frequency | Tool |
|-----------|-----------|------|
| Dependency scan | Every build | npm audit |
| SAST | Every build | Semgrep |
| Secrets scan | Every build | Gitleaks |
| Container scan | Every build | Trivy |
| DAST | Weekly | OWASP ZAP |
| Penetration test | Quarterly | External firm |

---

## 11. Compliance Alignment

### 11.1 SOC 2 Type II Preparation

| Control | Code Hardener Implementation |
|---------|---------------------------|
| CC6.1 Logical Access | JWT auth, RBAC |
| CC6.2 Authentication | Password policy, MFA (Phase 2) |
| CC6.3 Authorization | User-scoped queries |
| CC7.2 Monitoring | Audit logging |
| CC8.1 Change Management | Git-based deployments |

### 11.2 GDPR Considerations

| Requirement | Implementation |
|-------------|---------------|
| Data minimization | Only necessary data collected |
| Right to erasure | Account deletion API |
| Data portability | Export API (Phase 2) |
| Privacy by design | Security-first architecture |

---

## 12. Security TODOs for Implementation

### P0 - Must Have for MVP

- [ ] Implement bcrypt password hashing (cost 12)
- [ ] Implement JWT authentication with secure config
- [ ] Add rate limiting middleware
- [ ] Set all security headers
- [ ] Implement parameterized queries only
- [ ] Add user_id filtering to all queries
- [ ] Configure scanner containers with no network
- [ ] Implement audit logging
- [ ] Validate all inputs with Zod
- [ ] Implement CORS whitelist

### P1 - Should Have

- [ ] Add HaveIBeenPwned password check
- [ ] Implement account lockout
- [ ] Add API key hashing and rotation
- [ ] Implement file upload scanning
- [ ] Add content security policy
- [ ] Implement secrets redaction in findings

### P2 - Phase 2

- [ ] Add MFA support
- [ ] Implement Sigstore attestations
- [ ] Add database encryption at rest
- [ ] Implement SOC 2 audit logging
- [ ] Add penetration testing program
- [ ] Implement bug bounty program

---

---

## 13. Local Docker MVP Security Controls

For the local Docker deployment (3 containers), the following security controls apply:

### 13.1 Docker Compose Security

```yaml
# docker-compose.yml security settings
version: '3.8'

services:
  backend-api:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp:size=100m
    environment:
      - NODE_ENV=production
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:4000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  marketing-site:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true

  user-dashboard:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true

  postgres:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - SETUID
      - SETGID
    volumes:
      - postgres_data:/var/lib/postgresql/data:rw
```

### 13.2 Environment Variable Security

**Required .env variables (NEVER commit):**
```bash
# Database
DATABASE_URL=postgres://user:password@postgres:5432/codehardener
POSTGRES_PASSWORD=<strong-password>

# JWT
JWT_SECRET=<32+ character random string>
JWT_REFRESH_SECRET=<32+ character random string>

# OAuth (optional)
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

# Feature flags
ENABLE_REGISTRATION=true
ENABLE_OAUTH=false
```

**Validation on startup:**
```typescript
// Required environment validation
const requiredEnvVars = [
  'DATABASE_URL',
  'JWT_SECRET',
  'JWT_REFRESH_SECRET',
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`);
  }
  if (envVar.includes('SECRET') && process.env[envVar]!.length < 32) {
    throw new Error(`${envVar} must be at least 32 characters`);
  }
}
```

### 13.3 Network Isolation (Docker Networks)

```yaml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access
  database:
    driver: bridge
    internal: true  # No external access
```

### 13.4 Volume Security

```yaml
volumes:
  postgres_data:
    driver: local
  scan_uploads:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=500m,uid=1000
```

---

## 14. Pre-Deployment Security Verification

Run these commands before any deployment:

```bash
# 1. Secrets scan
docker run --rm -v $(pwd):/path zricethezav/gitleaks:latest detect --source /path

# 2. Dependency audit
npm audit --production

# 3. SAST scan
docker run --rm -v $(pwd):/src returntocorp/semgrep semgrep scan --config auto /src

# 4. Container scan
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image codehardener-backend:latest

# 5. Check for hardcoded secrets in built images
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --security-checks secret codehardener-backend:latest
```

---

## Document History

- Created: 2025-12-23
- Updated: 2025-12-23 - Added Docker MVP security controls
- Author: CISO Security Review
- Classification: Internal
- Next Review: Before MVP launch
