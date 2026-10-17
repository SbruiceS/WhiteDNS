#!/bin/sh
# Build if needed, run an authorized domain audit, require valid JSON.
# Exit codes from the binary: 0 ok, 1 usage, 2 degraded, 3 exposed, 4 warning.
# Also writes Prometheus text for Grafana.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DOMAIN=${1:-${WHITEDNS_DOMAIN:-google.com}}
FAIL_ON=${WHITEDNS_FAIL_ON:-degraded}
BIN=${WHITEDNS_BIN:-$ROOT/build/whitedns}
if [ ! -x "$BIN" ]; then
  cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release -DWHITEDNS_RELEASE=ON
  cmake --build "$ROOT/build"
fi
OUT=${WHITEDNS_REPORT:-$ROOT/build/audit.json}
PROM=${WHITEDNS_PROM:-$ROOT/build/metrics.prom}
mkdir -p "$(dirname "$OUT")"
set +e
"$BIN" audit --format json --color never --fail-on "$FAIL_ON" "$DOMAIN" > "$OUT"
code=$?
"$BIN" audit --format prometheus --color never --fail-on never "$DOMAIN" > "$PROM" || true
set -e
python3 - "$OUT" << 'PY'
import json, sys
path = sys.argv[1]
with open(path) as f:
    data = json.load(f)
if not isinstance(data, dict):
    raise SystemExit("report is not a JSON object")
print("json_ok schema=" + str(data.get("schema","")) + " posture=" + str(data.get("posture","")))
PY
echo "domain=$DOMAIN fail_on=$FAIL_ON exit=$code report=$OUT metrics=$PROM"
exit "$code"