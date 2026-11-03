#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
else
  compose() { docker-compose "$@"; }
fi
project="moneyflow-test-$(date +%s)-$$"
mkdir -p runtime
printf '%s\n' "$project" > runtime/verified-project
python3 scripts/bootstrap.py
printf 'APP_ENV=development\nAPP_ORIGIN=http://127.0.0.1:18080\nWEB_PORT=18080\n' > runtime/test.env
cleanup() { DOMAIN=localhost compose -p "$project" --env-file runtime/test.env -f docker-compose.yml -f compose.production.yml -f compose.tls-test.yml down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT INT TERM
compose -p "$project" --env-file runtime/test.env up -d --build --wait
compose -p "$project" exec -T web sh -c 'find settings utilities layouts webroot tests -name "*.php" -print0 | xargs -0 -n1 php -l'
compose -p "$project" exec -T web php tests/unit.php
compose -p "$project" exec -T web php tests/database.php
python3 tests/integration.py --project "$project"
python3 tests/migration.py --project "$project"
DOMAIN=localhost compose -p "$project" --env-file runtime/test.env -f docker-compose.yml -f compose.production.yml -f compose.tls-test.yml up -d --wait
compose -p "$project" cp proxy:/data/caddy/pki/authorities/local/root.crt runtime/test-root.crt
python3 tests/tls.py
compose -p "$project" exec -T web php -r '$s=fsockopen("127.0.0.1",8080); fwrite($s,"GET /login.php HTTP/1.0\r\nHost: localhost\r\nX-Forwarded-Proto: https\r\n\r\n"); if(!str_contains(stream_get_contents($s),"400 Bad Request"))exit(1); echo "Direct HTTP spoof rejected\n";'
