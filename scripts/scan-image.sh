#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
project=$(cat runtime/verified-project)
mkdir -p runtime
trap 'rm -f runtime/image.tar' EXIT
# The scanner sees only an exported image, not the Docker daemon or host secrets.
docker image save "$project-web:latest" -o runtime/image.tar
docker run --rm -v "$PWD/runtime:/scan:ro" -v moneyflow-trivy-cache:/root/.cache/ \
  aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c \
  image --input /scan/image.tar --scanners vuln --severity HIGH,CRITICAL --format json > runtime/image-scan.json
python3 - <<'PY'
import json
report=json.load(open('runtime/image-scan.json'))
findings=[v for r in report.get('Results',[]) for v in r.get('Vulnerabilities',[])]
fixable=[v for v in findings if v.get('FixedVersion')]
print(f'High/critical package findings: {len(findings)}; available fixes: {len(fixable)}')
raise SystemExit(bool(fixable))
PY
