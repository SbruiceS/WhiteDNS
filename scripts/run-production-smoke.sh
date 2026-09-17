#!/usr/bin/env sh
set -eu

BINARY="${1:-./build/whitedns}"
DOMAIN_FILE="${2:-./tests/production_domains.txt}"
SERVER="${3:-8.8.8.8}"
OUTPUT_DIR="${4:-./test-results}"

if [ ! -x "$BINARY" ]; then
  echo "WhiteDNS binary not found or not executable: $BINARY" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

while IFS= read -r domain; do
  case "$domain" in
    ""|\#*) continue ;;
  esac
  echo "== WhiteDNS smoke: $domain =="
  "$BINARY" -j -s "$SERVER" -r -n -w -x -t A,AAAA,NS,MX,TXT "$domain" > "$OUTPUT_DIR/$domain.json"
  echo "artifact=$OUTPUT_DIR/$domain.json"
done < "$DOMAIN_FILE"
