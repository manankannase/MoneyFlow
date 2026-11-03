# Verification record

Local verification on 3 November 2026 used Apple arm64, Colima, Docker Compose 5.1.4, PHP 8.4, Apache 2.4 and MySQL 8.4. The image bases are pinned by digest in the deployment files. The supported clean-run command is `scripts/verify.sh`.

The final clean run passed PHP syntax checks, validation/arithmetic unit assertions, and runtime database privilege checks. Thirteen HTTP/MySQL regression tests passed, including concurrent overspending, opposing transfers, simultaneous duplicate retries, same-second independent transfers, injected ledger failure rollback, CSRF on anonymous/authenticated forms, SQL injection, cross-account history access, stored HTML escaping, re-encoded avatars, session expiry and rate-limit forwarding spoofing.

A separate disposable v1 database migrated successfully. Existing balances and transfer rows were retained. This checks the supplied original schema; it does not establish compatibility with every external deployment.

The production overlay was tested on loopback HTTPS with a private local CA explicitly trusted by the Python test client. Registration and login worked; cookies had Secure/HttpOnly/SameSite=Strict; hostile origins were rejected; Caddy discarded spoofed forwarding metadata. Direct HTTP requests with forged HTTPS forwarding headers were rejected. The web container had no published port under the production overlay.

The Debian 13 runtime removes build tools, development headers and the unused curl executable. Trivy v0.76.0 scanned the exported application image without Docker socket access. The scan reported **60 high/critical package findings representing 21 distinct CVEs, with no available fixed versions reported**. These are scanner findings, not 60 confirmed application exploits. See `IMAGE_SCAN.json` for IDs and packages. The scan identifies Debian packages; it is not a complete audit of compiled PHP, the host kernel, MySQL, Caddy or application logic. The CI gate retains all findings in the report and fails if any high/critical finding has an available fix. A passing gate is not a zero-vulnerability claim.

GitHub Actions runs the same clean Linux workflow and image gate for pushes and pull requests. Check the run for the exact commit you intend to deploy; this local record does not substitute for that status.

No external hosting account was accessed or redeployed. No live funds, customer records or banking endpoints were used. No independent penetration test, production load test or full disaster-recovery exercise was performed. An existing hosted installation needs the migration and deployment steps in `DEPLOYMENT.md`.
