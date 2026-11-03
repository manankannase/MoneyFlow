# MoneyFlow - Secure Banking Application

**Enhanced Money Transfer Platform with Advanced Security Hardening**

## Overview

MoneyFlow is a secure financial transaction platform built with PHP 8.2, MySQL 8.0, and Apache 2.4, containerized with Docker. It features comprehensive security hardening across all layers.

## Features

- Secure Member Authentication (bcrypt, cost factor 12)
- Profile Management (bio, email, avatar uploads)
- Money Transfers with transaction memos
- Member Discovery / Search
- Transfer History with pagination
- Activity Logging / Audit Trail
- Rate Limiting on authentication
- CSRF Protection on all forms
- Content Security Policy headers
- Session binding (IP + User-Agent)

## Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/manankannase/MoneyFlow.git
cd MoneyFlow

# 2. Create your .env file from template
cp .env.example .env
# Edit .env with strong, unique passwords!

# 3. Start services
docker-compose up --build -d

# 4. Wait for DB initialization (~30s), then create test accounts
docker-compose exec web php /var/www/html/create_accounts.php

# 5. Open in browser
# http://localhost:8080
```

### Stopping

```bash
docker-compose down       # Keep data
docker-compose down -v    # Remove everything
```

## Security Hardening Applied

This project has undergone comprehensive security hardening with **41 vulnerabilities fixed**:

| Category | Fixes |
|----------|-------|
| Secrets Management | 5 (externalized to .env) |
| Network Exposure | 3 (MySQL not exposed, network isolation) |
| Apache Hardening | 12 (CSP, HSTS, directory listing, etc.) |
| Docker Hardening | 9 (resource limits, no-new-privileges, etc.) |
| Database Schema | 8 (CHECK constraints, ON DELETE RESTRICT, etc.) |
| Script Security | 4 (env checks, timeouts, etc.) |

See SECURITY_FIX.md for full details.

## Technology Stack

- **Backend**: PHP 8.2 (PDO, no frameworks)
- **Database**: MySQL 8.0 (InnoDB, CHECK constraints)
- **Server**: Apache 2.4 (hardened headers)
- **Container**: Docker + Docker Compose
- **Frontend**: HTML5, CSS3, Vanilla JS

## License

Educational project demonstrating secure banking application architecture.