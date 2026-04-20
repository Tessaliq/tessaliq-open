#!/usr/bin/env bash
# Verify a Tessaliq receipt JWT from the command line.
#
# Prereqs:
#   - Build the library: pnpm -F @tessaliq/receipt-verifier build
#   - Node.js >= 20
#
# Usage:
#   ./cli-example.sh path/to/receipt.jwt
#   cat receipt.jwt | ./cli-example.sh --stdin
#
# To point at staging instead of production:
#   ./cli-example.sh receipt.jwt \
#     --jwks-url https://api-staging.tessaliq.com/.well-known/jwks.json \
#     --issuer   https://api-staging.tessaliq.com
#
# Exit codes:
#   0 = receipt is valid
#   1 = receipt is invalid
#   2 = usage error (missing file, etc.)

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cli_js="$here/../../packages/receipt-verifier/dist/cli.js"

if [[ ! -f "$cli_js" ]]; then
  echo "error: $cli_js not found — build the library first:" >&2
  echo "  pnpm -F @tessaliq/receipt-verifier build" >&2
  exit 2
fi

exec node "$cli_js" "$@"
