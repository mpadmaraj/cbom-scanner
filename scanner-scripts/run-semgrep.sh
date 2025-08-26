#!/bin/sh
set -e
WORKSPACE="${1:-/tmp/repo}"
semgrep --config /app/scanner-scripts/rules \
--json --output "$WORKSPACE/semgrep-out.json" \
--exclude node_modules --exclude dist --exclude build \
"$WORKSPACE" >/dev/null 2>&1 || true
cat "$WORKSPACE/semgrep-out.json" 2>/dev/null || echo "{}"
