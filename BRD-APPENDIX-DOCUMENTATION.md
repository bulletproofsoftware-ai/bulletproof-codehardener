# Code Hardener BRD Appendix: User-Facing Documentation Requirements

**Version 1.0**
**December 2025**

---

## Overview

This appendix specifies the user-facing documentation that MUST be accessible within the Code Hardener portal. All documentation is generated during the build process and served from the dashboard application.

---

## Required Documentation Types

### 1. Software Bill of Materials (SBOM)

**Purpose**: Provide transparency into all components, dependencies, and versions used in Code Hardener.

**Location**: Dashboard at `/docs/sbom` or Marketing at `/docs/sbom`

**Format Requirements**:
- CycloneDX 1.5 JSON format (machine-readable)
- SPDX 2.3 format (alternative)
- Human-readable HTML view with search/filter
- Downloadable in JSON, XML, and PDF formats

**Content Requirements**:
| Section | Description |
|---------|-------------|
| Platform Components | All three containers and their base images |
| Runtime Dependencies | Node.js, PostgreSQL versions |
| NPM Packages | All production dependencies with versions |
| Security Tools | All 27 integrated tools with versions |
| Transitive Dependencies | Full dependency tree |
| License Summary | License type for each component |
| Vulnerability Status | Known CVEs at time of generation |

**Generation Method**:
```bash
# Generate SBOM using Syft (already in tool stack)
syft dir:./backend -o cyclonedx-json > sbom-backend.json
syft dir:./marketing -o cyclonedx-json > sbom-marketing.json
syft dir:./dashboard -o cyclonedx-json > sbom-dashboard.json
# Merge into unified SBOM
```

**Update Frequency**: Generated on every release, displayed with generation timestamp.

---

### 2. Administration Guide

**Purpose**: Enable administrators to deploy, configure, maintain, and troubleshoot Code Hardener.

**Location**: Dashboard at `/docs/admin-guide` (accessible to Team/Enterprise admins)

**Sections Required**:

#### 2.1 Installation
| Topic | Content |
|-------|---------|
| System Requirements | CPU, RAM, disk, network requirements |
| Docker Compose Setup | Step-by-step local deployment |
| Kubernetes Deployment | Helm chart installation |
| Environment Variables | All configuration options |
| Initial Setup | First admin user, database initialization |

#### 2.2 Configuration
| Topic | Content |
|-------|---------|
| Authentication | OAuth providers, SAML/SSO setup |
| Database | PostgreSQL connection, backups |
| Storage | Scan results, attestations storage |
| Email | SMTP configuration for notifications |
| Security | TLS, secrets management |
| Rate Limiting | API rate limits configuration |

#### 2.3 Operations
| Topic | Content |
|-------|---------|
| Health Checks | Monitoring endpoints |
| Logging | Log levels, aggregation |
| Backup/Restore | Database, configuration backup |
| Scaling | Horizontal scaling guidance |
| Troubleshooting | Common issues and solutions |

#### 2.4 Security Hardening
| Topic | Content |
|-------|---------|
| Network Security | Firewall rules, network isolation |
| Container Security | Seccomp, AppArmor profiles |
| Secrets Management | Vault integration, key rotation |
| Audit Logging | Security event logging |
| Compliance | SOC 2, ISO 27001 controls |

**Format**:
- Interactive documentation with navigation
- Code blocks with copy buttons
- Expandable troubleshooting sections
- Printable PDF version

---

### 3. API Documentation

**Purpose**: Enable developers to integrate with Code Hardener programmatically.

**Location**: Marketing at `/docs/api` (public) and Dashboard at `/docs/api` (authenticated with try-it-out)

**Format Requirements**:
- OpenAPI 3.1 specification
- Interactive Swagger/Redoc UI
- Code examples in multiple languages (JavaScript, Python, Go, cURL)
- Downloadable OpenAPI spec file

**Content Requirements**:

#### 3.1 Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | Email/password login |
| `/api/v1/auth/register` | POST | New user registration |
| `/api/v1/auth/refresh` | POST | Token refresh |
| `/api/v1/auth/logout` | POST | Session termination |
| `/api/v1/auth/oauth/:provider` | GET | OAuth initiation |

#### 3.2 Projects
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/projects` | GET | List all projects |
| `/api/v1/projects` | POST | Create project |
| `/api/v1/projects/:id` | GET | Get project details |
| `/api/v1/projects/:id` | PUT | Update project |
| `/api/v1/projects/:id` | DELETE | Delete project |

#### 3.3 Scans
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scans` | GET | List all scans |
| `/api/v1/scans` | POST | Initiate new scan |
| `/api/v1/scans/:id` | GET | Get scan results |
| `/api/v1/scans/:id/findings` | GET | Get scan findings |
| `/api/v1/scans/:id/attestation` | GET | Get scan attestation |

#### 3.4 Findings
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/findings` | GET | List all findings |
| `/api/v1/findings/:id` | GET | Get finding details |
| `/api/v1/findings/:id/fix` | POST | Request auto-fix |
| `/api/v1/findings/:id/dismiss` | POST | Dismiss finding |

#### 3.5 Attestations
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/attestations` | GET | List attestations |
| `/api/v1/attestations/:id` | GET | Get attestation |
| `/api/v1/attestations/:id/verify` | GET | Verify attestation |
| `/api/v1/attestations/:id/download` | GET | Download attestation |

#### 3.6 Policies
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/policies` | GET | List policies |
| `/api/v1/policies` | POST | Create policy |
| `/api/v1/policies/:id` | GET | Get policy |
| `/api/v1/policies/:id` | PUT | Update policy |
| `/api/v1/policies/:id` | DELETE | Delete policy |
| `/api/v1/policies/:id/validate` | POST | Validate policy |

#### 3.7 Webhooks
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/webhooks` | GET | List webhooks |
| `/api/v1/webhooks` | POST | Create webhook |
| `/api/v1/webhooks/:id` | DELETE | Delete webhook |
| `/api/v1/webhooks/:id/test` | POST | Test webhook |

#### 3.8 Reports
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/reports` | GET | List reports |
| `/api/v1/reports` | POST | Generate report |
| `/api/v1/reports/:id` | GET | Get report |
| `/api/v1/reports/:id/download` | GET | Download PDF |

#### 3.9 Badges
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/badges/:projectId` | GET | Get SVG badge |
| `/api/v1/badges/:projectId/markdown` | GET | Get markdown embed |

**Code Examples Required**:
Each endpoint must include examples in:
- cURL
- JavaScript (fetch)
- Python (requests)
- Go (net/http)

---

### 4. MCP Server Documentation

**Purpose**: Guide users in setting up Code Hardener as an MCP server for Claude/Cursor.

**Location**: Marketing at `/docs/mcp`

**Content**:
- Installation steps (npx, npm global, Docker)
- Configuration file examples
- Available tools and their parameters
- Example prompts and responses
- Troubleshooting common issues

---

### 5. CLI Documentation

**Purpose**: Document the `codehardener` CLI tool.

**Location**: Marketing at `/docs/cli`

**Content**:
- Installation methods (npm, curl script, homebrew)
- Authentication (`codehardener login`)
- Commands reference (`scan`, `report`, `attest`, `verify`)
- Configuration file format
- CI/CD integration examples

---

### 6. Integration Guides

**Purpose**: Step-by-step guides for platform integrations.

**Location**: Marketing at `/docs/integrations`

**Guides Required**:
| Integration | Content |
|-------------|---------|
| GitHub Actions | Workflow YAML, secrets setup |
| GitLab CI | `.gitlab-ci.yml` configuration |
| Vercel | Build command integration |
| Netlify | `netlify.toml` configuration |
| Replit | Extension installation |
| VS Code | Extension setup |

---

## Documentation Portal Requirements

### Accessibility
- All documentation pages must be accessible from both:
  1. Marketing site (public, no auth required for most)
  2. Dashboard (authenticated, with additional features)

### Features
| Feature | Description |
|---------|-------------|
| Search | Full-text search across all documentation |
| Navigation | Sidebar with collapsible sections |
| Version Selector | View docs for specific versions |
| Code Blocks | Syntax highlighting, copy button |
| Dark Mode | Match site theme |
| PDF Export | Print/export any page |
| Feedback | "Was this helpful?" on each page |

### URLs
| Documentation | Marketing URL | Dashboard URL |
|---------------|---------------|---------------|
| SBOM | `/docs/sbom` | `/docs/sbom` |
| Admin Guide | N/A (restricted) | `/docs/admin-guide` |
| API Reference | `/docs/api` | `/docs/api` (with try-it-out) |
| MCP Guide | `/docs/mcp` | `/docs/mcp` |
| CLI Guide | `/docs/cli` | `/docs/cli` |
| Integrations | `/docs/integrations` | `/docs/integrations` |
| Quickstart | `/docs/quickstart` | `/docs/quickstart` |

---

## Generation Process

Documentation must be generated during the build process:

1. **SBOM Generation**
   ```bash
   # In CI/CD pipeline
   syft . -o cyclonedx-json > public/docs/sbom.json
   grype sbom:./public/docs/sbom.json -o json > public/docs/vulnerabilities.json
   ```

2. **API Documentation**
   ```bash
   # Generate from TypeScript types
   npx @redocly/cli build-docs openapi.yaml -o public/docs/api/index.html
   ```

3. **Static Documentation**
   - Markdown files in `/docs` directory
   - Processed during build with MDX
   - Output to `public/docs/`

---

## Compliance Mapping

| Requirement | Compliance Framework |
|-------------|---------------------|
| SBOM Generation | NIST SSDF PO.3, CISA SBOM Guidance |
| API Documentation | SOC 2 CC2.1, ISO 27001 A.14.2.1 |
| Admin Guide | SOC 2 CC6.1, ISO 27001 A.12.1.1 |
| Audit Logging Docs | SOC 2 CC4.1, ISO 27001 A.12.4.1 |

---

**Document Status**: APPROVED
**Last Updated**: 2025-12-23
**Owner**: Product Team
