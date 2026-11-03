MoneyFlow — Secure Money Transfer Application | PHP 8.4, MySQL 8.4, Apache, Docker Compose

- Developed an authenticated money-transfer application with profiles and transaction history, using exact decimal handling, ordered row locks and sender-scoped idempotency to prevent overspending and duplicate transfers of simulated INR balances.
- Implemented bcrypt authentication, hashed database sessions, CSRF validation, password confirmation for transfers and atomic rate limits, with expiry and logout revocation to restrict unauthorized account actions.
- Hardened deployment with a non-root read-only container, least-privilege database grants, HTTPS proxy controls and private image re-encoding; validated the system through concurrent-transfer, failure-injection and access-control regression tests.

The application uses simulated funds. Do not describe it as a live banking integration, independently audited system or vulnerability-free platform. Include only the work you can explain and demonstrate.
