# MoneyFlow

A PHP money-transfer web application with authenticated accounts, profiles, member search, transfer history and an auditable ledger. Transfers move simulated INR balances between accounts in the same database. There is no bank, UPI, card or withdrawal integration.

This version restores application code that previously existed only on an unmerged branch. It also replaces the unsafe transfer and session behavior with tested controls. PHP 8.4, MySQL 8.4 LTS, Apache 2.4 and Docker Compose are used in the supported deployment.

## Run locally

Install Docker and Docker Compose v2.24.4 or later, and Python 3. Run from this directory:

```sh
python3 scripts/bootstrap.py
docker compose up -d --build --wait
```

Open http://localhost:8080 and register two accounts. Each starts with ₹100 in simulated funds. Transfers require the sender's password. On Macs with the standalone Compose executable, replace `docker compose` with `docker-compose`.

Secrets are generated into `.secrets/`, which is excluded from Git and the image. Existing secrets are never replaced automatically. The application runs as `www-data` with a read-only root filesystem, dropped Linux capabilities and separate writable avatar storage. MySQL has no published port; the local web listener binds to loopback.

## How a transfer works

The server derives the sender from the authenticated session, validates CSRF and the confirmation password, and parses the amount as integer paise. It locks both member rows in ascending ID order, then checks the sender's request ID against the ledger. A repeated request returns its original reference; changing the contents of that request is rejected. Debit, credit, ledger entry and audit event commit in one transaction. An uncertain commit is not automatically retried with a new ID.

Balances stay in MySQL `DECIMAL` columns and are converted to integer paise for arithmetic. No floating point is used to authorize or settle a transfer. An identical amount sent twice with different request IDs is allowed; a second transfer is not mistaken for a retry.

## Security controls

- Bcrypt at cost 12, 12–72 byte password policy, native PDO prepared statements, generic login errors and password-hash revalidation before successful login.
- Random 256-bit session tokens, SHA-256 hashes at rest, IP/User-Agent binding, eight-hour absolute expiry, 30-minute idle expiry and server-side logout revocation.
- CSRF checks on login, registration, transfers, profile changes and logout; password confirmation for transfers; atomic database-backed rate limits.
- Secure/HttpOnly/SameSite=Strict cookies over HTTPS, restrictive CSP, escaped output, bounded requests and generic error references.
- JPEG/PNG decoding and re-encoding with dimension/size limits, random names, storage outside the document root and authenticated image serving.
- Runtime database privileges cannot create/drop tables or update/delete the transfer ledger and audit log. Administrative database access remains a separate trust boundary.

See [security boundaries](SECURITY.md), [deployment and recovery](docs/DEPLOYMENT.md) and [verification evidence](docs/VERIFICATION.md). This repository does not claim an independent penetration test or payment certification.

## Verification

```sh
scripts/verify.sh
scripts/scan-image.sh
```

The command creates a new disposable Compose project, runs syntax checks, unit assertions, runtime database privilege checks and HTTP/MySQL security regressions, then removes only that project's test containers and volumes. Ports 18080 and 18443 must be free. The HTTPS test trusts only the explicit test CA for that test client. Tests cover real transactions, concurrent spending, duplicate retries, injected failures, CSRF, SQL injection, output escaping, uploads, session expiry and forwarding-header spoofing. They use synthetic accounts and a dedicated test database.

## HTTPS deployment

Configure a domain and a Linux host with Docker, then follow [the runbook](docs/DEPLOYMENT.md). The production overlay removes the direct web port and puts Caddy in front of Apache. The fixed proxy peer is the only source trusted for forwarded client addresses and HTTPS metadata.

An existing installation must be backed up and migrated before starting this version. Do not point the new schema initialization at an old volume or run `down -v` against an installation you want to retain. See the migration section of the runbook.
