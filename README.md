# MoneyFlow — Secure Banking Platform

## Team 9

| Roll Number | Name |
|-------------|------|
| CS25MTECH11028 | Manan Kannasey |
| CS25MTECH14005 | Hemang Ranga |
| CS25MTECH14012 | Rohit B |
| CS25MTECH14016 | Yash Vardhan |
| CS25MTECH14017 | Deependra Singh |

**Repository:** [github.com/aashuvardhan/MoneyFlow](https://github.com/aashuvardhan/MoneyFlow.git)

> All five team members have contributed equally to this project and share joint responsibility for its development and all associated activities.

| Member | Domain | Lines of Code |
|--------|--------|------:|
| **member_1** | Authentication & Security | **1,094** |
| **member_2** | DevOps & Core Operations | **1,017** |
| **member_3** | Database, Logging & Docs | **1,089** |
| **member_4** | Frontend & CSS | **1,196** |
| **member_5** | Transactions & JavaScript | **1,113** |

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Security Architecture](#security-architecture)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [Pages & Routes](#pages--routes)
- [API Endpoints](#api-endpoints)
- [Quick Start](#quick-start)
- [Test Accounts](#test-accounts)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Overview

MoneyFlow is a secure peer-to-peer money transfer application. Members can register accounts, send funds to other members, manage their profiles, and review their full transaction history. Every design decision prioritizes security: cryptographically sound authentication, tamper-proof transfers, comprehensive audit logging, and strict input/output handling throughout.

---

## Key Features

### Authentication
- **Argon2id password hashing** — memory-hard (64 MB, 4 iterations, 2 threads), GPU-resistant
- **Timing-safe verification** — `password_verify` + `hash_equals` used throughout
- **Auto-upgrade** — legacy bcrypt hashes upgraded to Argon2id on next login
- **Password strength enforcement** — minimum 8 characters, mixed case, digit, special character
- **Dual-layer rate limiting** — 5 attempts per (IP + account) per 15 minutes; 10 global attempts per account per 6 hours
- **Registration throttling** — max 5 new accounts per IP per 24 hours
- **Generic error messages** — no username enumeration on failed login or registration

### Session Management
- **256-bit session tokens** — generated via `random_bytes(32)`
- **Hash-only storage** — only SHA-256 of token stored in database (no plaintext)
- **Session binding** — tied to IP address and SHA-256 of User-Agent
- **Dual timeouts** — 30-minute inactivity window + 5-hour absolute lifetime
- **Session invalidation** — all sessions destroyed on password change; new session on each login
- **Secure cookies** — `HttpOnly`, `Secure`, `SameSite=Strict`

### Fund Transfers — Two-Step Cryptographic Flow
Transfers use **DB intent binding** to prevent proxy/Burp Suite tampering:

1. **Step 1 — Intent creation**: Client sends recipient ID + amount to `/api_transfer_signature.php`. Server validates inputs, creates a `pending_transfers` row, and returns an **AES-256-GCM encrypted token** (opaque to the client).
2. **Step 2 — Execution**: Client submits the token + optional memo to `/transfer.php`. Server decrypts the token, reads the amount and recipient from the database (ignoring any client-side values), and executes the transfer.

This means:
- Recipient and amount cannot be tampered between steps — they are encrypted and DB-locked
- Replay attacks blocked by one-time nonce (session) + `used` flag (database)
- Cross-account attacks blocked — sender is always taken from the authenticated session

**Velocity controls**: max 10 transfers/day, max ₹5,000 outflow/day per account.

### Transfer Execution
- **Database transactions** with `BEGIN/COMMIT/ROLLBACK` for atomicity
- **Row-level locking** (`SELECT ... FOR UPDATE`) on both accounts, ordered by ID to prevent deadlocks
- Atomic balance deduction + credit + ledger insert — all-or-nothing

### Profile & Avatar Management
- Update bio (max 500 characters) and email address
- **Secure avatar uploads**:
  - MIME type validated via `finfo_file` (not extension/pathinfo)
  - Image structure validated with `getimagesize`
  - Polyglot file detection
  - Re-encoded through PHP GD library (strips embedded payloads and EXIF exploits)
  - Random filename generation (no user input in stored name)
  - `.htaccess` in uploads directory disables PHP execution
  - Upload rate limit: 10 per member per hour

### Member Search
- Search by account ID (exact numeric) or account name (partial match)
- Rate limited: 10 searches per IP per minute
- Results capped at 5 per query (prevents bulk account harvesting)

### Transaction History
- Complete bidirectional ledger (sent and received)
- 20 transactions per page with full pagination
- Memo text displayed (HTML-escaped)
- Sorted newest-first

### Audit Logging
- Every page access recorded to `event_chronicle` table
- Captures: member ID, account name, page path, IP address, User-Agent, timestamp
- Immutable records — no update/delete by application user
- Automatic retention: logs older than 90 days are purged daily

### HTTP Security Headers
| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `X-XSS-Protection` | `1; mode=block` |
| `Content-Security-Policy` | self-only for scripts, styles, images, fonts |
| `Strict-Transport-Security` | `max-age=31536000` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | camera, microphone, geolocation, payment disabled |
| `Cache-Control` | `no-store` (all authenticated pages) |
| `X-Response-Integrity` | HMAC-SHA256 of response body |

### CSRF Protection
- Per-session CSRF tokens (64-char hex), regenerated on every login
- Applied to: login, registration, logout, transfers, profile updates, password changes
- Transmitted via hidden form fields only (never in URLs)
- Validated with `hash_equals` (timing-safe)

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | PHP 8.2 (no frameworks) |
| Database | MySQL 8.0 (InnoDB) |
| Web Server | Apache 2.4 with mod_rewrite, mod_headers, mod_ssl |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Containerization | Docker + Docker Compose |
| Encryption | AES-256-GCM (transfer tokens), Argon2id (passwords), SHA-256 (session tokens) |

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Network Layer      HTTPS-only, HSTS, HTTP→HTTPS redirect       │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer  CSRF tokens, input validation, output        │
│                     encoding, rate limiting on all endpoints     │
├─────────────────────────────────────────────────────────────────┤
│  Cryptography       Argon2id passwords, AES-256-GCM tokens,     │
│                     SHA-256 hashing, random_bytes() everywhere   │
├─────────────────────────────────────────────────────────────────┤
│  Database Layer     Prepared statements (EMULATE_PREPARES=off),  │
│                     transactions, row-level locking, minimal     │
│                     privileges (SELECT/INSERT/UPDATE/DELETE only) │
├─────────────────────────────────────────────────────────────────┤
│  Audit Layer        event_chronicle logs every page access       │
└─────────────────────────────────────────────────────────────────┘
```

**PHP hardening** (php.ini overrides in Dockerfile):
- `display_errors = Off`, `expose_php = Off`
- Dangerous functions disabled: `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`
- Session cookies: `httponly=true`, `secure=true`, `samesite=Strict`

**Apache hardening**:
- `DocumentRoot` set to `/var/www/html/webroot` (parent directory unreachable)
- Directory listing disabled; hidden files (`.*`) blocked
- `ServerTokens Prod`, `ServerSignature Off` (version disclosure suppressed)
- TLS 1.2+ only; weak cipher suites excluded

**Docker hardening**:
- MySQL port not exposed to host (internal Docker network only)
- Application runs as `www-data` (non-root after port bind)
- Health checks on both services; `web` waits for `db` healthy status

---

## Project Structure

```
MoneyFlow/
├── settings/
│   └── db_config.php              # PDO connection with security hardening
├── utilities/
│   ├── auth.php                   # Registration, login, password management
│   ├── session.php                # Custom session management (token-based)
│   ├── operations.php             # Business logic: transfers, profiles, search
│   ├── validation.php             # Input validation & HTML output escaping
│   ├── activity_log.php           # Audit trail (event_chronicle)
│   └── security.php               # Security headers, AES-256-GCM encryption
├── layouts/
│   ├── header.php                 # Navigation & page header template
│   └── footer.php                 # Footer template with JS versioning
├── webroot/                       # Apache DocumentRoot (public)
│   ├── index.php                  # Home/welcome page
│   ├── signin.php                 # Login with CSRF + rate limiting
│   ├── signup.php                 # Registration with CSRF + rate limiting
│   ├── dashboard.php              # Balance, quick actions, recent transfers
│   ├── transfer.php               # Two-step send money flow
│   ├── api_transfer_signature.php # JSON API: creates pending transfer + token
│   ├── search.php                 # Member search with rate limiting
│   ├── transaction_history.php    # Paginated transfer ledger
│   ├── account_settings.php       # Profile, avatar, password management
│   ├── member_profile.php         # Public member profile view
│   ├── logout.php                 # POST-only logout with CSRF
│   ├── css/main.css               # Dark-themed stylesheet
│   ├── js/main.js                 # Transfer flow, form validation, UI
│   └── uploads/avatars/           # Avatar storage (PHP execution disabled)
├── docker-compose.yml             # MySQL + web service orchestration
├── Dockerfile                     # PHP 8.2 + Apache with hardening
├── apache.conf                    # VirtualHost config (HTTP→HTTPS, SSL)
├── init.sql                       # Full database schema + events + privileges
├── migrations.sql                 # Incremental schema additions
├── create_accounts.php            # Test account generator
└── .env                           # Credentials and encryption keys
```

---

## Database Schema

### Core Tables

**`members`** — User accounts
- `id`, `account_name` (UNIQUE), `email_address` (UNIQUE)
- `password_hash` (Argon2id), `account_balance` (DECIMAL 12,2, CHECK ≥ 0)
- `member_bio`, `profile_photo`, `created_at`, `updated_at`

**`member_sessions`** — Session tokens
- `token_hash` (SHA-256, UNIQUE), `csrf_token`
- `agent_hash` (SHA-256 of User-Agent), `ip_address`
- `expires_at` (absolute), `last_activity` (sliding)

**`transfer_ledger`** — Immutable transaction history
- `sender_id` (FK), `recipient_id` (FK), `transfer_amount`, `memo_text`
- Indexed by sender, recipient, and timestamp

**`event_chronicle`** — Audit trail
- `member_id`, `account_name`, `page_path`, `ip_address`, `user_agent`, `access_timestamp`

### Rate Limiting Tables

| Table | Enforces |
|-------|----------|
| `failed_auth_attempts` | Login brute-force (per IP+account, per account globally) |
| `pending_transfers` | Transfer intent creation (10 per user per 5 min) |
| `registration_attempts` | Account creation (5 per IP per 24 hours) |
| `avatar_upload_attempts` | Avatar uploads (10 per member per hour) |
| `search_rate_limit` | Member searches (10 per IP per minute) |

All rate limit tables use **atomic `INSERT...SELECT`** patterns to prevent TOCTOU race conditions.

### Automatic Cleanup (MySQL Events)
Expired rows are deleted automatically:
- Sessions: every hour
- Failed auth attempts: every day
- Pending transfers: every 10 minutes
- Avatar attempts: every 10 minutes
- Search limits: every minute
- Registration attempts: every hour
- Activity logs (`event_chronicle`): every day (rows older than 90 days)

---

## Pages & Routes

### Public (No Authentication Required)
| Path | Description |
|------|-------------|
| `/` | Home/welcome page (redirects authenticated users to dashboard) |
| `/signin.php` | Login form |
| `/signup.php` | Registration form |

### Authenticated (Valid Session Required)
| Path | Description |
|------|-------------|
| `/dashboard.php` | Account balance, recent transfers, quick actions |
| `/transfer.php` | Two-step send money (AES-256-GCM token flow) |
| `/search.php` | Find members by account ID or name |
| `/transaction_history.php` | Full paginated transfer ledger |
| `/account_settings.php` | Bio, email, avatar, password management |
| `/member_profile.php?id=X` | View another member's public profile |
| `/logout.php` | POST-only logout (CSRF protected) |

---

## API Endpoints

### `POST /api_transfer_signature.php`

Creates a pending transfer and returns an encrypted token for the second step.

**Authentication:** Session cookie required

**Request Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `csrf_token` | string | CSRF protection token |
| `recipient_id` | integer | Target member's numeric ID |
| `transfer_amount` | float | Amount to send (positive, ≤ 1,000,000) |

**Success Response:**
```json
{
  "success": true,
  "token": "<base64-encoded AES-256-GCM ciphertext>",
  "recipient_name": "account_name"
}
```

**Error Responses:**
| Code | Reason |
|------|--------|
| 401 | No valid session |
| 403 | Invalid CSRF token |
| 400 | Invalid recipient or amount |
| 422 | Sender = recipient, insufficient balance |
| 429 | Rate limit exceeded (10 pending transfers per 5 minutes) |

---

## Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+

### Start the Application

```bash
# Build and start all services
docker compose up --build -d

# Wait for both containers to be healthy (~30 seconds)
docker compose ps

# Create test accounts
docker compose exec web php /var/www/html/create_accounts.php
```

### Access
- **HTTP**: `http://localhost:8080` (auto-redirects to HTTPS)
- **HTTPS**: `https://localhost:8443` (self-signed certificate — accept browser warning)

### Stop / Reset

```bash
# Stop containers (preserve database)
docker compose down

# Stop and delete all data (full reset)
docker compose down -v
```

### View Logs

```bash
docker compose logs -f web   # Application / Apache logs
docker compose logs -f db    # MySQL logs
```

### Database Access

```bash
docker compose exec db mysql -u moneyflow_admin -p moneyflow_db
```

### Accessing Activity Logs

Activity logs are stored in the `event_chronicle` table. Connect to the database and run SQL queries:

```bash
docker compose exec db mysql -u moneyflow_admin -p moneyflow_db
```

**View all recent activity (newest first):**
```sql
SELECT account_name, page_path, ip_address, access_timestamp
FROM event_chronicle
ORDER BY access_timestamp DESC
LIMIT 100;
```

**Filter by username:**
```sql
SELECT page_path, ip_address, access_timestamp
FROM event_chronicle
WHERE account_name = 'player1'
ORDER BY access_timestamp DESC;
```

**Filter by IP address:**
```sql
SELECT account_name, page_path, access_timestamp
FROM event_chronicle
WHERE ip_address = '192.168.1.1'
ORDER BY access_timestamp DESC;
```

**Filter by page (e.g. all login attempts):**
```sql
SELECT account_name, ip_address, access_timestamp
FROM event_chronicle
WHERE page_path LIKE '%signin%'
ORDER BY access_timestamp DESC;
```

**Filter by date range:**
```sql
SELECT account_name, page_path, ip_address, access_timestamp
FROM event_chronicle
WHERE access_timestamp BETWEEN '2025-01-01' AND '2025-01-31'
ORDER BY access_timestamp DESC;
```

> Logs are retained for **90 days**. Entries older than 90 days are automatically purged daily by a MySQL scheduled event.

---

## Test Accounts

After running `create_accounts.php`, the following accounts are created with ₹100.00 starting balance each:

| Account ID | Password Source |
|-----------|-----------------|
| player1 | `ACCOUNT_PASS_1` env var (or random if unset) |
| player2 | `ACCOUNT_PASS_2` env var (or random if unset) |
| player3 | `ACCOUNT_PASS_3` env var (or random if unset) |
| player4 | `ACCOUNT_PASS_4` env var (or random if unset) |
| player5 | `ACCOUNT_PASS_5` env var (or random if unset) |

Passwords are printed to the console during account creation. If the accounts already exist, the script will report that and skip creation.

---

## Configuration

All sensitive values are read from `.env` — the application will refuse to start if required keys are missing (no hardcoded fallbacks):

```env
# Database credentials
DATABASE_PASS=<password for moneyflow_admin>
MYSQL_ROOT_PASSWORD=<MySQL root password>

# 64 hex chars (256-bit key) for HMAC-SHA256 response integrity
HMAC_SECRET=<hex string>

# 64 hex chars (256-bit key) for AES-256-GCM transfer token encryption
AES_TRANSFER_KEY=<hex string>

# Optional: pre-set passwords for test accounts
ACCOUNT_PASS_1=<password>
ACCOUNT_PASS_2=<password>
ACCOUNT_PASS_3=<password>
ACCOUNT_PASS_4=<password>
ACCOUNT_PASS_5=<password>
```

---

## Troubleshooting

**`Connection refused` or `getaddrinfo for db failed`**

The `db` container isn't ready yet. Run `docker compose ps` and wait for the `db` service to show `(healthy)`, then retry.

```bash
docker compose ps
docker compose exec web php /var/www/html/create_accounts.php
```

**Port already in use**

Change the host port mapping in `docker-compose.yml`:
```yaml
ports:
  - "9080:80"
  - "9443:443"
```

**Permission denied on uploads**

```bash
docker compose exec web chmod -R 755 /var/www/html/webroot/uploads
```

**Full reset after `docker compose down -v`**

The database volume is deleted. Bring everything back up and re-run account creation:
```bash
docker compose up --build -d
# Wait for healthy status, then:
docker compose exec web php /var/www/html/create_accounts.php
```

---

## License

Educational project demonstrating secure banking application architecture.

## Security Disclosure

If you discover security vulnerabilities, please report them responsibly and do not disclose publicly until fixed.
