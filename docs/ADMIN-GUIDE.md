# Code Hardener Administration Guide

**Version:** 1.0.0
**Last Updated:** December 2025
**Platform:** Code Hardener Security Assurance Platform

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Deployment](#deployment)
6. [Operations](#operations)
7. [Monitoring](#monitoring)
8. [Backup and Recovery](#backup-and-recovery)
9. [Security Hardening](#security-hardening)
10. [Troubleshooting](#troubleshooting)
11. [Maintenance](#maintenance)
12. [Appendix](#appendix)

---

## 1. Overview

Code Hardener is a security assurance platform designed for AI-first developers. It integrates 27 open-source security tools into a unified platform that provides:

- **Security Scanning**: SAST, DAST, SCA, and secrets detection
- **Compliance Evidence**: Cryptographic attestations for audit trails
- **Developer Experience**: Plain-language findings and auto-remediation
- **Multi-Platform Integration**: REST API, MCP Server, CLI, and IDE plugins

### Architecture Overview

```
                    INTERNET
                        |
                        v
              +------------------+
              |   Load Balancer  |  (TLS termination, rate limiting)
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
                    |                                 |
                    v                                 v
              +----------+                    +----------+
              | Scanner  |                    |PostgreSQL|
              |Containers|                    |  :5432   |
              +----------+                    +----------+
```

### Component Summary

| Component | Technology | Port | Purpose |
|-----------|------------|------|---------|
| Marketing Site | Next.js 15 | 3000 | Public website, documentation |
| Dashboard | Next.js 15 | 3001 | User interface for scans/findings |
| Backend API | Node.js/Express | 4000 | REST API, authentication, scan orchestration |
| Database | PostgreSQL 16 | 5432 | Persistent data storage |
| Scanners | Docker containers | - | Isolated security tool execution |

---

## 2. System Requirements

### Minimum Requirements (Development)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 4 GB | 8 GB |
| Storage | 20 GB | 50 GB SSD |
| Docker | 24.0+ | Latest |
| Node.js | 20.x LTS | 22.x LTS |

### Production Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 16 GB | 32 GB |
| Storage | 100 GB SSD | 500 GB NVMe |
| Network | 100 Mbps | 1 Gbps |

### Software Prerequisites

- Docker Engine 24.0+
- Docker Compose v2.20+
- Node.js 20.x or 22.x LTS
- PostgreSQL 16 (or use containerized version)
- Git 2.40+

### Supported Platforms

| Platform | Support Level |
|----------|--------------|
| Ubuntu 22.04+ | Full |
| Debian 12+ | Full |
| macOS 14+ (Sonoma) | Development |
| Windows 11 + WSL2 | Development |
| Amazon Linux 2023 | Full |
| RHEL 9+ | Full |

---

## 3. Installation

### 3.1 Quick Start (Development)

```bash
# Clone the repository
git clone https://github.com/youorg/codehardener.git
cd codehardener

# Copy environment template
cp .env.example .env

# Generate secure secrets
export JWT_SECRET=$(openssl rand -base64 32)
export DB_PASSWORD=$(openssl rand -base64 24)

# Update .env with generated secrets
sed -i "s/your-jwt-secret-min-32-characters-long/$JWT_SECRET/" .env
sed -i "s/your-secure-password-min-16-chars/$DB_PASSWORD/" .env

# Start all services
docker-compose up -d

# Verify services are healthy
docker-compose ps
```

### 3.2 Manual Installation

#### Step 1: Install Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y docker.io docker-compose-v2 nodejs npm git

# Enable Docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

#### Step 2: Clone Repository

```bash
git clone https://github.com/youorg/codehardener.git
cd codehardener
```

#### Step 3: Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
vim .env
```

#### Step 4: Build and Start

```bash
# Build all containers
docker-compose build

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

### 3.3 Verify Installation

```bash
# Check all containers are running
docker-compose ps

# Expected output:
# NAME                 STATUS         PORTS
# codehardener-db        Up (healthy)   0.0.0.0:5432->5432/tcp
# codehardener-api       Up (healthy)   0.0.0.0:4000->4000/tcp
# codehardener-marketing Up             0.0.0.0:3000->3000/tcp
# codehardener-dashboard Up             0.0.0.0:3001->3001/tcp

# Test API health
curl http://localhost:4000/health

# Test marketing site
curl -I http://localhost:3000

# Test dashboard
curl -I http://localhost:3001
```

---

## 4. Configuration

### 4.1 Environment Variables

#### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password | `SecureP@ssw0rd123` |
| `JWT_SECRET` | JWT signing secret (min 32 chars) | `a1b2c3d4...` |
| `NODE_ENV` | Environment mode | `production` |

#### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_EXPIRES_IN` | Access token expiry | `7d` |
| `JWT_REFRESH_EXPIRES_IN` | Refresh token expiry | `30d` |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth secret | - |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth secret | - |
| `SMTP_HOST` | Email server hostname | - |
| `SMTP_PORT` | Email server port | `587` |

#### Production URLs

```bash
NEXT_PUBLIC_API_URL=https://api.yourdomain.com
NEXT_PUBLIC_MARKETING_URL=https://yourdomain.com
NEXT_PUBLIC_DASHBOARD_URL=https://app.yourdomain.com
```

### 4.2 Database Configuration

The platform uses PostgreSQL 16 with the following default settings:

```yaml
# docker-compose.yml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_USER: codehardener
    POSTGRES_PASSWORD: ${DB_PASSWORD}
    POSTGRES_DB: codehardener
```

#### Connection String Format

```
postgresql://codehardener:${DB_PASSWORD}@postgres:5432/codehardener
```

### 4.3 CORS Configuration

Configure allowed origins in the backend environment:

```bash
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### 4.4 Rate Limiting

Default rate limits (configured in backend):

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| Authentication | 5 requests | 15 minutes |
| API (authenticated) | 100 requests | 1 minute |
| Scan submission | 10 scans | 1 hour |
| File upload | 20 uploads | 1 hour |
| Badge requests | 1000 requests | 1 minute |

---

## 5. Deployment

### 5.1 Development Deployment

```bash
# Start with hot-reload
docker-compose up

# Rebuild after code changes
docker-compose up --build
```

### 5.2 Production Deployment

#### Using Docker Compose

```bash
# Set production environment
export NODE_ENV=production

# Pull latest images (if using registry)
docker-compose pull

# Deploy with zero downtime
docker-compose up -d --no-deps --build backend
docker-compose up -d --no-deps --build marketing
docker-compose up -d --no-deps --build dashboard
```

#### Using Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml codehardener
```

### 5.3 Reverse Proxy Configuration (nginx)

```nginx
# /etc/nginx/sites-available/codehardener

upstream marketing {
    server 127.0.0.1:3000;
}

upstream dashboard {
    server 127.0.0.1:3001;
}

upstream api {
    server 127.0.0.1:4000;
}

# Marketing site
server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://marketing;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

# Dashboard
server {
    listen 443 ssl http2;
    server_name app.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://dashboard;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

# API
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    client_max_body_size 50M;

    location / {
        proxy_pass http://api;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

### 5.4 SSL/TLS Configuration

Using Let's Encrypt with Certbot:

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificates
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com -d app.yourdomain.com -d api.yourdomain.com

# Auto-renewal is configured automatically
sudo systemctl status certbot.timer
```

---

## 6. Operations

### 6.1 Starting and Stopping Services

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart specific service
docker-compose restart backend

# View logs
docker-compose logs -f [service_name]

# Scale a service (if needed)
docker-compose up -d --scale backend=3
```

### 6.2 Health Checks

```bash
# Check all services
docker-compose ps

# API health endpoint
curl http://localhost:4000/health

# Database connectivity
docker exec codehardener-db pg_isready -U codehardener
```

### 6.3 User Management

Users are managed through the API. Common operations:

```bash
# Create admin user (via database)
docker exec -it codehardener-db psql -U codehardener -c "
INSERT INTO users (email, password_hash, role, verified)
VALUES ('admin@example.com', '\$2b\$12\$...', 'admin', true);
"

# List users
docker exec -it codehardener-db psql -U codehardener -c "
SELECT id, email, role, created_at FROM users;
"

# Disable user
docker exec -it codehardener-db psql -U codehardener -c "
UPDATE users SET active = false WHERE email = 'user@example.com';
"
```

### 6.4 API Key Management

```bash
# List API keys (prefix only shown)
docker exec -it codehardener-db psql -U codehardener -c "
SELECT id, key_prefix, name, created_at, last_used_at FROM api_keys;
"

# Revoke API key
docker exec -it codehardener-db psql -U codehardener -c "
UPDATE api_keys SET revoked = true WHERE id = 'key-id';
"
```

---

## 7. Monitoring

### 7.1 Container Monitoring

```bash
# Real-time stats
docker stats

# Container resource usage
docker-compose top
```

### 7.2 Log Management

```bash
# View all logs
docker-compose logs

# Follow specific service logs
docker-compose logs -f backend

# Export logs to file
docker-compose logs > logs.txt

# Tail last 100 lines
docker-compose logs --tail=100 backend
```

### 7.3 Application Metrics

The API exposes health and metrics at:

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Basic health check |
| `GET /health/ready` | Readiness check (includes DB) |
| `GET /health/live` | Liveness check |

### 7.4 Database Monitoring

```bash
# Connection count
docker exec codehardener-db psql -U codehardener -c "
SELECT count(*) FROM pg_stat_activity WHERE datname = 'codehardener';
"

# Table sizes
docker exec codehardener-db psql -U codehardener -c "
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
"

# Slow queries (if pg_stat_statements enabled)
docker exec codehardener-db psql -U codehardener -c "
SELECT query, calls, mean_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC LIMIT 10;
"
```

---

## 8. Backup and Recovery

### 8.1 Database Backup

#### Manual Backup

```bash
# Create backup directory
mkdir -p /backups/codehardener

# Full database backup
docker exec codehardener-db pg_dump -U codehardener -Fc codehardener > /backups/codehardener/backup-$(date +%Y%m%d-%H%M%S).dump

# Schema only
docker exec codehardener-db pg_dump -U codehardener --schema-only codehardener > /backups/codehardener/schema.sql
```

#### Automated Backup Script

```bash
#!/bin/bash
# /usr/local/bin/backup-codehardener.sh

BACKUP_DIR="/backups/codehardener"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Create backup
docker exec codehardener-db pg_dump -U codehardener -Fc codehardener > "$BACKUP_DIR/backup-$TIMESTAMP.dump"

# Compress
gzip "$BACKUP_DIR/backup-$TIMESTAMP.dump"

# Clean old backups
find "$BACKUP_DIR" -name "backup-*.dump.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: backup-$TIMESTAMP.dump.gz"
```

Add to crontab:

```bash
# Daily backup at 2 AM
0 2 * * * /usr/local/bin/backup-codehardener.sh >> /var/log/codehardener-backup.log 2>&1
```

### 8.2 Database Recovery

```bash
# Stop application
docker-compose stop backend marketing dashboard

# Restore from backup
docker exec -i codehardener-db pg_restore -U codehardener -d codehardener --clean < /backups/codehardener/backup-YYYYMMDD-HHMMSS.dump

# Restart application
docker-compose up -d
```

### 8.3 Volume Backup

```bash
# Backup Docker volumes
docker run --rm -v codehardener_postgres_data:/data -v /backups:/backup alpine \
  tar czf /backup/postgres-volume-$(date +%Y%m%d).tar.gz /data
```

---

## 9. Security Hardening

### 9.1 Production Checklist

- [ ] Change all default passwords
- [ ] Generate unique JWT secrets (min 32 characters)
- [ ] Enable TLS/SSL on all endpoints
- [ ] Configure firewall rules
- [ ] Enable rate limiting
- [ ] Set up log monitoring
- [ ] Configure backup automation
- [ ] Review CORS settings
- [ ] Disable debug mode (`NODE_ENV=production`)

### 9.2 Firewall Configuration (ufw)

```bash
# Default deny
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable
```

### 9.3 Docker Security

Add security options to docker-compose.yml:

```yaml
services:
  backend:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp:size=100m
```

### 9.4 Database Security

```sql
-- Enable row-level security
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

-- Create security policies
CREATE POLICY user_isolation ON projects
    USING (user_id = current_setting('app.current_user_id')::uuid);
```

### 9.5 Secrets Management

For production, use a secrets manager:

```bash
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id codehardener/production

# HashiCorp Vault
vault kv get secret/codehardener/production
```

---

## 10. Troubleshooting

### 10.1 Common Issues

#### Container Won't Start

```bash
# Check logs
docker-compose logs [service_name]

# Check container status
docker inspect codehardener-[service]

# Common fixes:
# - Verify .env file exists and has correct values
# - Check port conflicts: lsof -i :3000
# - Verify Docker is running: systemctl status docker
```

#### Database Connection Failed

```bash
# Test database connectivity
docker exec codehardener-db pg_isready -U codehardener

# Check DATABASE_URL format
echo $DATABASE_URL

# Verify database exists
docker exec codehardener-db psql -U codehardener -c '\l'
```

#### Authentication Errors

```bash
# Check JWT_SECRET is set
grep JWT_SECRET .env

# Verify token format
# JWT should be: header.payload.signature

# Clear browser cookies and try again
```

#### High Memory Usage

```bash
# Check container memory
docker stats --no-stream

# Limit container memory in docker-compose.yml:
# deploy:
#   resources:
#     limits:
#       memory: 2G
```

### 10.2 Log Analysis

```bash
# Search for errors
docker-compose logs | grep -i error

# Search for specific user activity
docker-compose logs backend | grep "user@example.com"

# Export logs for analysis
docker-compose logs --since 24h > logs-24h.txt
```

### 10.3 Performance Issues

```bash
# Check slow queries
docker exec codehardener-db psql -U codehardener -c "
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state = 'active' AND now() - pg_stat_activity.query_start > interval '5 seconds';
"

# Analyze table performance
docker exec codehardener-db psql -U codehardener -c "
ANALYZE VERBOSE;
"
```

---

## 11. Maintenance

### 11.1 Updates

#### Updating Application

```bash
# Pull latest code
git pull origin main

# Rebuild containers
docker-compose build --no-cache

# Deploy with minimal downtime
docker-compose up -d
```

#### Updating Dependencies

```bash
# Backend
cd backend && npm update && npm audit fix

# Marketing
cd marketing && npm update && npm audit fix

# Dashboard
cd dashboard && npm update && npm audit fix
```

### 11.2 Database Maintenance

```bash
# Vacuum and analyze
docker exec codehardener-db psql -U codehardener -c "VACUUM ANALYZE;"

# Reindex
docker exec codehardener-db psql -U codehardener -c "REINDEX DATABASE codehardener;"

# Check for bloat
docker exec codehardener-db psql -U codehardener -c "
SELECT schemaname, relname, n_dead_tup
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC LIMIT 10;
"
```

### 11.3 Log Rotation

Add log rotation for Docker:

```json
// /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Restart Docker after changes:

```bash
sudo systemctl restart docker
```

### 11.4 Scheduled Maintenance

| Task | Frequency | Command |
|------|-----------|---------|
| Database backup | Daily | `pg_dump` script |
| Log rotation | Automatic | Docker config |
| Security updates | Weekly | `apt update && apt upgrade` |
| Dependency audit | Weekly | `npm audit` |
| Database vacuum | Weekly | `VACUUM ANALYZE` |
| SSL renewal | Automatic | Certbot |

---

## 12. Appendix

### A. File Structure

```
codehardener/
├── backend/              # Node.js/Express API
│   ├── src/
│   │   ├── routes/       # API routes
│   │   ├── middleware/   # Auth, validation
│   │   ├── services/     # Business logic
│   │   └── index.ts      # Entry point
│   ├── Dockerfile
│   └── package.json
├── marketing/            # Next.js marketing site
│   ├── src/app/          # App router pages
│   ├── src/components/   # React components
│   ├── Dockerfile
│   └── package.json
├── dashboard/            # Next.js dashboard
│   ├── src/app/          # App router pages
│   ├── src/components/   # React components
│   ├── Dockerfile
│   └── package.json
├── postgres/             # Database init scripts
│   └── init.sql
├── docs/                 # Documentation
├── reports/              # Security scan reports
├── docker-compose.yml    # Container orchestration
├── .env.example          # Environment template
├── SECURITY.md           # Security documentation
└── CLAUDE.md            # AI assistant instructions
```

### B. API Endpoints Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/register | User registration |
| POST | /auth/login | User login |
| POST | /auth/refresh | Refresh token |
| GET | /projects | List projects |
| POST | /projects | Create project |
| GET | /projects/:id | Get project details |
| POST | /scans | Start new scan |
| GET | /scans/:id | Get scan results |
| GET | /findings | List findings |
| GET | /attestations/:id | Get attestation |

### C. Environment Variable Reference

See `.env.example` for complete list.

### D. Support

- **Documentation**: https://yourdomain.com/docs
- **GitHub Issues**: https://github.com/youorg/codehardener/issues
- **Email**: support@yourdomain.com

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | December 2025 | Code Hardener Team | Initial release |

---

**End of Administration Guide**
