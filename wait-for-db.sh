#!/bin/bash
# =============================================================
# MoneyFlow — Wait for Database Readiness
# =============================================================
# SECURITY: Uses environment variables instead of hardcoded passwords.
# Includes timeout to prevent infinite loops.
# =============================================================

set -euo pipefail

MAX_WAIT=60
ELAPSED=0

echo "Waiting for database to be ready (timeout: ${MAX_WAIT}s)..."

while ! mysqladmin ping -h"db" -u"root" -p"${MYSQL_ROOT_PASSWORD}" --silent 2>/dev/null; do
    ELAPSED=$((ELAPSED + 1))
    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        echo "ERROR: Database did not become ready within ${MAX_WAIT} seconds."
        exit 1
    fi
    echo "Waiting for MySQL... (${ELAPSED}s / ${MAX_WAIT}s)"
    sleep 1
done

echo "Database is ready! (took ${ELAPSED}s)"
exit 0
