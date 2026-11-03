# Security boundaries

MoneyFlow demonstrates application security around a simulated ledger. Its money is database state with no cash value. A working self-hosted deployment does not establish suitability for handling deposits or regulated payments.

The browser, form fields, uploaded files and model-free client behavior are untrusted. The server derives identity from a hashed bearer session, applies CSRF and transfer-password checks, and performs mutations through prepared SQL. Network-address binding is an additional control, not proof of identity. It can invalidate legitimate mobile sessions.

The database, container host, administrator and TLS reverse proxy are trusted. The runtime database user can change balances through the application's SQL access; a compromised app or database administrator is outside the append-only ledger guarantee. Database administrators can alter historical records. Backups and external log retention are operator responsibilities.

Login failures use the same bcrypt path for unknown users, but no constant-time request latency is claimed. Rate limits count attempts, including successes, in fixed windows. There may be a burst at a window boundary. They use the database and fail closed on database failure. Limits are not a substitute for perimeter DDoS protection.

Production requires HTTPS and the supplied proxy boundary. Direct forwarded headers are ignored. Keep the frontend network dedicated to MoneyFlow; a hostile container on that trusted network can attack the proxy boundary. Do not attach unrelated services to it.

Uploaded images are decoded with GD and re-encoded as PNG outside the webroot. Public registration and profile search are intended for portfolio use. Do not enter real banking or sensitive personal information. Account email verification, MFA, password recovery, account closure and legal/payment workflows are not implemented.

The repository formerly contained example credentials and code/configuration with unverified hardening claims. Rotate any password or secret ever used from a historical example. Removing a value from a file does not revoke it or remove it from Git history. No historical credential was used to access any external system during this update.

To report a problem, contact the repository owner privately using GitHub's available private reporting/contact options. Do not post passwords, session cookies, personal data or exploit traces against a public installation in an issue.
