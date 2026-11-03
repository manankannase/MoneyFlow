# Deployment and recovery

## Fresh installation

Use a supported Linux Docker host, a domain you control, and Compose v2.24.4 or later. Restrict SSH to administrators and expose only HTTPS plus the HTTP port needed by Caddy for certificate issuance/redirects. The runtime database is on an internal Docker network.

1. Check out a reviewed commit. Run `python3 scripts/bootstrap.py` once.
2. Set `DOMAIN=your.actual.domain` in a private `.env` file. Point DNS at the host. Back up `.secrets/` through an encrypted channel.
3. Run `docker compose -f docker-compose.yml -f compose.production.yml up -d --build --wait`.
4. Confirm the public certificate, successful registration/login, Secure/HttpOnly/SameSite cookies, transfer/history behavior and absence of a published app or MySQL port.
5. Retain the deployed commit, image digests and verification logs. Keep the host, Docker, PHP, MySQL and Caddy patched. Restrict access to Docker and the secret directory.

The overlay reserves 172.30.91.0/28. If this conflicts with the host network, change the subnet, both fixed peer addresses, and `deploy/proxy.conf` together. Caddy's usual forwarded-header behavior discards untrusted incoming client values. Do not add broad trusted proxies.

The PHP image supports both amd64 and arm64. Local verification here uses arm64; the GitHub gate exercises the clean Linux runner. Check the published gate for the commit being deployed.

## Existing v1 database

The old repository was incomplete, so the schema and code running on an external host may differ. Inspect `SHOW CREATE TABLE` for the five original tables before applying the supplied migration. Stop the old web service; preserve its image, configuration, database and avatars. Restore a backup into a separate database and test the migration there first.

`deploy/migrate-v1-to-v2.sql` applies only to the original `init.sql` layout. It checks account-name/balance assumptions, revokes old sessions, adds sender-scoped idempotency fields, preserves the old audit log as `event_chronicle_v1`, and creates the new versioned schema. MySQL DDL commits implicitly. Stop on any error; restore the backup rather than rerunning a partial migration.

Create a dedicated `moneyflow_app` user with a new password if the old deployment used another username. Apply `deploy/grants.sql` as administrator. Update secrets to match. Old credentials must lose their privileges when cutover is complete. Legacy avatars are not copied into the public webroot; users should upload them again through the re-encoding path. Users with passwords shorter than 12 bytes need an administrator-assisted reset before transfer confirmation can succeed.

Never use the new fresh-install `init.sql` as a migration. No migration or redeployment of an external installation is performed by checking out this repository.

## Backups

Use a database administrator, not the runtime app user, for a transaction-consistent `mysqldump --single-transaction --routines --triggers --events` backup. Keep the password in an administrator-only MySQL option file, not a command argument. Encrypt backups, retain them separately from the host, and include the private avatar volume and secret material. Define retention and access restrictions before using real user data.

Restore into an isolated host/project. Confirm account balances, ledger rows, audit history, session invalidation and total balances before opening traffic. Test recovery regularly. A failed deployment should roll back to the saved image and database snapshot together; old code must not run against an incompatible schema.

## Maintenance

The operator should remove expired `member_sessions` and `request_limits` rows older than the rate-limit retention window through a privileged scheduled maintenance job. Retain audit records according to the installation's privacy and retention policy. No background job deletes transfer history. Monitor free disk space, container health, HTTP 5xx, denied requests and transfer-unconfirmed events. Investigate uncertain transfers by request ID and ledger reference before asking a user to submit a new request.
